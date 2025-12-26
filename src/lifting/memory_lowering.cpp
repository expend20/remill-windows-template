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

  struct IntrinsicInfo {
    const char *name;
    unsigned size;
  };

  // Process read intrinsics - replace with load from alloca
  IntrinsicInfo read_intrinsics[] = {
      {"__remill_read_memory_8", 1},
      {"__remill_read_memory_16", 2},
      {"__remill_read_memory_32", 4},
      {"__remill_read_memory_64", 8},
  };

  for (const auto &info : read_intrinsics) {
    auto *func = module->getFunction(info.name);
    if (!func) {
      continue;
    }

    for (auto &use : llvm::make_early_inc_range(func->uses())) {
      auto *call = llvm::dyn_cast<llvm::CallInst>(use.getUser());
      if (!call || call->getCalledFunction() != func) {
        continue;
      }

      if (call->arg_size() < 2) {
        continue;
      }

      llvm::Value *addr_arg = call->getArgOperand(1);
      llvm::Value *replacement = nullptr;

      if (auto *addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_arg)) {
        uint64_t address = addr_const->getZExtValue();
        auto [global, offset] = memory_info.FindGlobalForAddress(address);

        if (global) {
          auto it = global_to_alloca.find(global);
          if (it != global_to_alloca.end()) {
            llvm::IRBuilder<> ir(call);
            auto *alloca = it->second;

            // GEP to the offset within the alloca
            auto *ptr = ir.CreateConstGEP2_64(alloca->getAllocatedType(),
                                              alloca, 0, offset, "mem_ptr");

            // Load the value with appropriate type
            auto *val = ir.CreateLoad(call->getType(), ptr, "mem_val");

            replacement = val;
            std::cout << "Lowered read at 0x" << std::hex << address
                      << " -> load from alloca + " << std::dec << offset << "\n";
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

  // Process write intrinsics - replace with store to alloca
  IntrinsicInfo write_intrinsics[] = {
      {"__remill_write_memory_8", 1},
      {"__remill_write_memory_16", 2},
      {"__remill_write_memory_32", 4},
      {"__remill_write_memory_64", 8},
  };

  for (const auto &info : write_intrinsics) {
    auto *func = module->getFunction(info.name);
    if (!func) {
      continue;
    }

    for (auto &use : llvm::make_early_inc_range(func->uses())) {
      auto *call = llvm::dyn_cast<llvm::CallInst>(use.getUser());
      if (!call || call->getCalledFunction() != func) {
        continue;
      }

      if (call->arg_size() < 3) {
        continue;
      }

      llvm::Value *addr_arg = call->getArgOperand(1);
      llvm::Value *value_arg = call->getArgOperand(2);
      bool lowered = false;

      if (auto *addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_arg)) {
        uint64_t address = addr_const->getZExtValue();
        auto [global, offset] = memory_info.FindGlobalForAddress(address);

        if (global) {
          auto it = global_to_alloca.find(global);
          if (it != global_to_alloca.end()) {
            llvm::IRBuilder<> ir(call);
            auto *alloca = it->second;

            // GEP to the offset within the alloca
            auto *ptr = ir.CreateConstGEP2_64(alloca->getAllocatedType(),
                                              alloca, 0, offset, "mem_ptr");

            // Store the value
            ir.CreateStore(value_arg, ptr);

            lowered = true;
            std::cout << "Lowered write at 0x" << std::hex << address
                      << " -> store to alloca + " << std::dec << offset << "\n";
          }
        }
      }

      // Write intrinsics return the memory pointer (first argument)
      // Replace uses with that pointer
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
