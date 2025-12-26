#include "memory_lowering.h"
#include "utils/pe_reader.h"

#include <iostream>
#include <map>
#include <set>

#include <llvm/ADT/STLExtras.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>

namespace lifting {

std::pair<llvm::GlobalVariable *, uint64_t>
MemoryBackingInfo::FindGlobalForAddress(uint64_t va) const {
  for (const auto &mapping : sections) {
    if (va >= mapping.start_va && va < mapping.end_va) {
      return {mapping.global, va - mapping.start_va};
    }
  }
  return {nullptr, 0};
}

std::pair<llvm::AllocaInst *, uint64_t>
StackBackingInfo::FindStackOffset(uint64_t va) const {
  // Stack range: [stack_top_va - stack_size, stack_top_va + caller_space)
  // The caller_space bytes are above stack_top_va for main's RET to read
  uint64_t stack_bottom = stack_top_va - stack_size;
  uint64_t stack_end = stack_top_va + caller_space;
  if (va >= stack_bottom && va < stack_end) {
    // Offset from bottom of stack (array index 0 is at lowest address)
    uint64_t offset = va - stack_bottom;
    return {stack_alloca, offset};
  }
  return {nullptr, 0};
}

StackBackingInfo CreateStackAlloca(llvm::Function *func,
                                   uint64_t initial_rsp,
                                   uint64_t stack_size) {
  auto &context = func->getContext();
  llvm::IRBuilder<> builder(&func->getEntryBlock().front());

  // Allocate extra space above initial_rsp for "caller's frame"
  // This handles main's RET reading from [RSP] when RSP == initial_rsp
  constexpr uint64_t caller_space = 8;  // 8 bytes for return address slot
  uint64_t total_size = stack_size + caller_space;

  // Create [total_size x i8] alloca for stack memory
  auto *arr_type = llvm::ArrayType::get(llvm::Type::getInt8Ty(context), total_size);
  auto *alloca = builder.CreateAlloca(arr_type, nullptr, "__stack_local");

  // Zero initialize the stack (use align 1 to match alloca alignment)
  auto *size = llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), total_size);
  builder.CreateMemSet(alloca, builder.getInt8(0), size, llvm::MaybeAlign(1));

  std::cout << "Created stack alloca: " << stack_size << " bytes at VA range 0x"
            << std::hex << (initial_rsp - stack_size) << "-0x" << initial_rsp
            << std::dec << "\n";

  return {alloca, initial_rsp, stack_size, caller_space};
}

MemoryBackingInfo CreateMemoryGlobals(llvm::Module *module,
                                       const utils::PEInfo &pe_info) {
  MemoryBackingInfo info;
  auto &context = module->getContext();

  for (const auto &section : pe_info.sections) {
    if (!section.IsReadable()) {
      continue;
    }

    // Create array type for section data
    auto arr_type =
        llvm::ArrayType::get(llvm::Type::getInt8Ty(context), section.bytes.size());

    // Create constant initializer from section bytes
    auto data = llvm::ConstantDataArray::get(context, section.bytes);

    // Create global variable as constant (initial data)
    // We'll copy to alloca for writable sections in LowerMemoryIntrinsics
    auto global = new llvm::GlobalVariable(
        *module, arr_type, true, llvm::GlobalValue::PrivateLinkage, data,
        "__section_" + section.name);

    // Record mapping
    uint64_t start_va = pe_info.image_base + section.virtual_address;
    uint64_t end_va = start_va + section.bytes.size();
    info.sections.push_back({start_va, end_va, global});

    std::cout << "Created backing global for section " << section.name
              << " at VA range 0x" << std::hex << start_va << "-0x" << end_va
              << std::dec << " (" << section.bytes.size() << " bytes)\n";
  }

  return info;
}

void LowerMemoryIntrinsics(llvm::Module *module,
                           const MemoryBackingInfo &memory_info,
                           const StackBackingInfo *stack_info,
                           llvm::Function *target_func) {
  if (!target_func || target_func->empty()) {
    return;
  }

  auto &context = module->getContext();

  // Create allocas for each section at function entry
  // This allows LLVM's SROA to optimize them as local variables
  std::map<llvm::GlobalVariable*, llvm::AllocaInst*> global_to_alloca;

  llvm::IRBuilder<> entry_builder(&target_func->getEntryBlock().front());

  for (const auto &mapping : memory_info.sections) {
    auto *global = mapping.global;
    auto *arr_type = global->getValueType();

    // Create alloca at function entry
    auto *alloca = entry_builder.CreateAlloca(arr_type, nullptr,
        global->getName().str() + "_local");

    // Copy initial data from global to alloca
    auto *size = llvm::ConstantInt::get(llvm::Type::getInt64Ty(context),
        module->getDataLayout().getTypeAllocSize(arr_type));
    entry_builder.CreateMemCpy(alloca, llvm::MaybeAlign(1),
        global, llvm::MaybeAlign(1), size);

    global_to_alloca[global] = alloca;

    std::cout << "Created local alloca for " << global->getName().str() << "\n";
  }

  // Build a set of memory intrinsic functions to recognize
  std::set<llvm::Function *> read_intrinsics;
  std::set<llvm::Function *> write_intrinsics;

  const char *read_names[] = {
      "__remill_read_memory_8", "__remill_read_memory_16",
      "__remill_read_memory_32", "__remill_read_memory_64"};
  const char *write_names[] = {
      "__remill_write_memory_8", "__remill_write_memory_16",
      "__remill_write_memory_32", "__remill_write_memory_64"};

  for (const char *name : read_names) {
    if (auto *f = module->getFunction(name)) {
      read_intrinsics.insert(f);
    }
  }
  for (const char *name : write_names) {
    if (auto *f = module->getFunction(name)) {
      write_intrinsics.insert(f);
    }
  }

  // Process all instructions in program order to preserve memory semantics
  // This is critical for correctness: stores must happen before subsequent loads
  std::vector<llvm::CallInst *> to_process;
  for (auto &bb : *target_func) {
    for (auto &inst : bb) {
      if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        auto *callee = call->getCalledFunction();
        if (read_intrinsics.count(callee) || write_intrinsics.count(callee)) {
          to_process.push_back(call);
        }
      }
    }
  }

  // Now process in program order
  for (auto *call : to_process) {
    auto *callee = call->getCalledFunction();
    bool is_read = read_intrinsics.count(callee) > 0;

    if (is_read) {
      // Read intrinsic: __remill_read_memory_N(mem, addr) -> value
      if (call->arg_size() < 2) {
        continue;
      }

      llvm::Value *addr_arg = call->getArgOperand(1);
      llvm::Value *replacement = nullptr;

      if (auto *addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_arg)) {
        uint64_t address = addr_const->getZExtValue();

        // Try global sections first
        auto [global, offset] = memory_info.FindGlobalForAddress(address);

        if (global) {
          auto it = global_to_alloca.find(global);
          if (it != global_to_alloca.end()) {
            llvm::IRBuilder<> ir(call);
            auto *alloca = it->second;

            auto *ptr = ir.CreateConstGEP2_64(alloca->getAllocatedType(),
                                              alloca, 0, offset, "mem_ptr");
            auto *val = ir.CreateLoad(call->getType(), ptr, "mem_val");

            replacement = val;
            std::cout << "Lowered read at 0x" << std::hex << address
                      << " -> load from global alloca + " << std::dec << offset << "\n";
          }
        }
        // Try stack if global not found
        else if (stack_info) {
          auto [stack_alloca, stack_offset] = stack_info->FindStackOffset(address);
          if (stack_alloca) {
            llvm::IRBuilder<> ir(call);

            auto *ptr = ir.CreateConstGEP2_64(stack_alloca->getAllocatedType(),
                                              stack_alloca, 0, stack_offset, "stack_ptr");
            auto *val = ir.CreateLoad(call->getType(), ptr, "stack_val");

            replacement = val;
            std::cout << "Lowered read at 0x" << std::hex << address
                      << " -> load from stack alloca + " << std::dec << stack_offset << "\n";
          }
        }
      }

      // Fall back to undef for unknown addresses
      if (!replacement) {
        replacement = llvm::UndefValue::get(call->getType());
      }

      call->replaceAllUsesWith(replacement);
      call->eraseFromParent();

    } else {
      // Write intrinsic: __remill_write_memory_N(mem, addr, val) -> mem
      if (call->arg_size() < 3) {
        continue;
      }

      llvm::Value *addr_arg = call->getArgOperand(1);
      llvm::Value *value_arg = call->getArgOperand(2);
      bool lowered = false;

      if (auto *addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_arg)) {
        uint64_t address = addr_const->getZExtValue();

        // Try global sections first
        auto [global, offset] = memory_info.FindGlobalForAddress(address);

        if (global) {
          auto it = global_to_alloca.find(global);
          if (it != global_to_alloca.end()) {
            llvm::IRBuilder<> ir(call);
            auto *alloca = it->second;

            auto *ptr = ir.CreateConstGEP2_64(alloca->getAllocatedType(),
                                              alloca, 0, offset, "mem_ptr");
            ir.CreateStore(value_arg, ptr);

            lowered = true;
            std::cout << "Lowered write at 0x" << std::hex << address
                      << " -> store to global alloca + " << std::dec << offset << "\n";
          }
        }
        // Try stack if global not found
        else if (stack_info) {
          auto [stack_alloca, stack_offset] = stack_info->FindStackOffset(address);
          if (stack_alloca) {
            llvm::IRBuilder<> ir(call);

            auto *ptr = ir.CreateConstGEP2_64(stack_alloca->getAllocatedType(),
                                              stack_alloca, 0, stack_offset, "stack_ptr");
            ir.CreateStore(value_arg, ptr);

            lowered = true;
            std::cout << "Lowered write at 0x" << std::hex << address
                      << " -> store to stack alloca + " << std::dec << stack_offset << "\n";
          }
        }
      }

      // Write intrinsics return the memory pointer (first argument)
      call->replaceAllUsesWith(call->getArgOperand(0));
      call->eraseFromParent();

      if (!lowered) {
        // Unknown address - write is dropped (becomes no-op)
      }
    }
  }
}

// NOTE: This function is NOT USED. Kept for reference only.
// See MEMORY.md for comparison of approaches.
// Limitations:
// - Does not track instruction ordering (all writes processed before reads)
// - Fails for repeated read/write patterns to same address
// - Only handles constant addresses
void ReplaceMemoryIntrinsics(llvm::Module *module,
                              const utils::PEInfo &pe_info) {
  struct IntrinsicInfo {
    const char *name;
    unsigned size;
  };

  // First pass: collect all written bytes at byte granularity
  // Map from address to byte value (for constant writes only)
  // Also track which addresses have non-constant writes
  std::map<uint64_t, uint8_t> written_bytes;
  std::set<uint64_t> non_constant_write_addresses;

  IntrinsicInfo write_intrinsics[] = {
      {"__remill_write_memory_8", 1},
      {"__remill_write_memory_16", 2},
      {"__remill_write_memory_32", 4},
      {"__remill_write_memory_64", 8},
  };

  for (const auto &info : write_intrinsics) {
    if (auto *func = module->getFunction(info.name)) {
      for (auto &use : func->uses()) {
        auto *call = llvm::dyn_cast<llvm::CallInst>(use.getUser());
        if (!call || call->getCalledFunction() != func) {
          continue;
        }
        if (call->arg_size() < 3) {
          continue;
        }
        // Get the address argument (second parameter: memory*, addr, value)
        llvm::Value *addr_arg = call->getArgOperand(1);
        llvm::Value *value_arg = call->getArgOperand(2);
        if (auto *addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_arg)) {
          uint64_t address = addr_const->getZExtValue();
          if (auto *value_const = llvm::dyn_cast<llvm::ConstantInt>(value_arg)) {
            // Store each byte of the written value
            uint64_t written_value = value_const->getZExtValue();
            for (unsigned i = 0; i < info.size; ++i) {
              written_bytes[address + i] = (written_value >> (i * 8)) & 0xFF;
            }
          } else {
            // Non-constant write - mark these addresses
            for (unsigned i = 0; i < info.size; ++i) {
              non_constant_write_addresses.insert(address + i);
            }
          }
        }
      }
    }
  }

  // Second pass: replace reads by composing from written bytes and/or original binary
  IntrinsicInfo read_intrinsics[] = {
      {"__remill_read_memory_8", 1},
      {"__remill_read_memory_16", 2},
      {"__remill_read_memory_32", 4},
      {"__remill_read_memory_64", 8},
  };

  for (const auto &info : read_intrinsics) {
    if (auto *func = module->getFunction(info.name)) {
      for (auto &use : llvm::make_early_inc_range(func->uses())) {
        auto *call = llvm::dyn_cast<llvm::CallInst>(use.getUser());
        if (!call) {
          continue;
        }

        // Verify this is a call to the function (not another use like a function pointer)
        if (call->getCalledFunction() != func) {
          continue;
        }

        // Verify the call has the expected number of arguments
        if (call->arg_size() < 2) {
          continue;
        }

        // Get the address argument (second parameter: memory*, addr)
        llvm::Value *addr_arg = call->getArgOperand(1);

        llvm::Constant *replacement = nullptr;

        // Try to get constant address
        if (auto *addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_arg)) {
          uint64_t address = addr_const->getZExtValue();

          // Check if any byte in the read range has a non-constant write
          bool has_non_constant_write = false;
          for (unsigned i = 0; i < info.size; ++i) {
            if (non_constant_write_addresses.count(address + i)) {
              has_non_constant_write = true;
              break;
            }
          }

          if (has_non_constant_write) {
            std::cout << "Skipping read at 0x" << std::hex << address
                      << " - has non-constant write\n" << std::dec;
            replacement = llvm::UndefValue::get(call->getType());
          } else {
            // Compose the value from written bytes and/or original binary
            uint64_t composed_value = 0;
            bool all_bytes_available = true;
            bool any_from_write = false;

            for (unsigned i = 0; i < info.size; ++i) {
              auto it = written_bytes.find(address + i);
              if (it != written_bytes.end()) {
                composed_value |= (uint64_t(it->second) << (i * 8));
                any_from_write = true;
              } else {
                // Try from PE info (original binary)
                auto byte_val = pe_info.ReadByte(address + i);
                if (byte_val) {
                  composed_value |= (uint64_t(*byte_val) << (i * 8));
                } else {
                  all_bytes_available = false;
                  break;
                }
              }
            }

            if (all_bytes_available) {
              replacement = llvm::ConstantInt::get(call->getType(), composed_value);
              if (any_from_write) {
                std::cout << "Resolved memory read at 0x" << std::hex << address
                          << " -> 0x" << composed_value << " (composed from writes)\n" << std::dec;
              } else {
                std::cout << "Resolved memory read at 0x" << std::hex << address
                          << " -> 0x" << composed_value << "\n" << std::dec;
              }
            }
          }
        }

        // Fall back to undef for unknown addresses
        if (!replacement) {
          replacement = llvm::UndefValue::get(call->getType());
        }

        call->replaceAllUsesWith(replacement);
        call->eraseFromParent();
      }
    }
  }
}

}  // namespace lifting
