#include "memory_lowering.h"
#include "utils/pe_reader.h"

#include <iostream>
#include <map>
#include <set>

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/STLExtras.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>

namespace lifting {

namespace {

// Try to decompose an address as: constant_base + dynamic_offset
// where constant_base falls within a known section.
// Returns {base_va, offset_value} or {0, nullptr} if not decomposable.
// Handles patterns like:
//   - add i64 %base_const, %offset
//   - add i64 %offset, %base_const
//   - or i64 %base_const, %offset (disjoint bits - common for array indexing)
std::pair<uint64_t, llvm::Value*>
DecomposeAddress(llvm::Value *addr, const MemoryBackingInfo &mem_info,
                 const StackBackingInfo *stack_info) {
  // Handle binary operators: add and or
  if (auto *bin_op = llvm::dyn_cast<llvm::BinaryOperator>(addr)) {
    unsigned opcode = bin_op->getOpcode();

    // We handle ADD and OR (disjoint OR is used for array indexing)
    if (opcode == llvm::Instruction::Add || opcode == llvm::Instruction::Or) {
      llvm::Value *op0 = bin_op->getOperand(0);
      llvm::Value *op1 = bin_op->getOperand(1);

      // Check each operand to see if it's a constant within a known section
      for (int i = 0; i < 2; i++) {
        llvm::Value *potential_base = (i == 0) ? op0 : op1;
        llvm::Value *potential_offset = (i == 0) ? op1 : op0;

        if (auto *base_const = llvm::dyn_cast<llvm::ConstantInt>(potential_base)) {
          uint64_t base_va = base_const->getZExtValue();

          // Check if base is within a known global section
          if (mem_info.FindGlobalForAddress(base_va).first) {
            return {base_va, potential_offset};
          }

          // Check if base is within stack range
          if (stack_info && stack_info->FindStackOffset(base_va).first) {
            return {base_va, potential_offset};
          }
        }
      }
    }
  }

  return {0, nullptr};
}

// Recursively try to find a known pointer value, following through phi nodes
// Returns the known pointer value if ALL paths lead to the same value (or undef)
// max_depth prevents infinite recursion on phi cycles
std::optional<uint64_t>
GetKnownPointerRecursive(llvm::Value *val, const PointerTracker &tracker,
                          const MemoryBackingInfo &mem_info,
                          const StackBackingInfo *stack_info,
                          int max_depth = 8,
                          llvm::SmallPtrSet<llvm::Value*, 16> *visited = nullptr) {
  if (max_depth <= 0) {
    return std::nullopt;
  }

  // Create visited set for cycle detection if not provided
  llvm::SmallPtrSet<llvm::Value*, 16> local_visited;
  if (!visited) visited = &local_visited;

  // Cycle detection
  if (visited->count(val)) {
    return std::nullopt;  // Cycle - treat as compatible (will be skipped)
  }
  visited->insert(val);

  // Check if directly tracked
  if (auto known = tracker.GetKnownValue(val)) {
    return *known;
  }

  // Check if it's a constant that's a valid section address
  if (auto *const_int = llvm::dyn_cast<llvm::ConstantInt>(val)) {
    uint64_t ptr_val = const_int->getZExtValue();
    if (mem_info.FindGlobalForAddress(ptr_val).first ||
        (stack_info && stack_info->FindStackOffset(ptr_val).first)) {
      return ptr_val;
    }
  }

  // Undef is compatible with any value
  if (llvm::isa<llvm::UndefValue>(val)) {
    return std::nullopt;  // Return nullopt but don't fail - caller handles this
  }

  // Handle phi nodes - all non-undef incoming values must agree
  if (auto *phi = llvm::dyn_cast<llvm::PHINode>(val)) {
    std::optional<uint64_t> common_ptr;

    for (unsigned i = 0; i < phi->getNumIncomingValues(); i++) {
      auto *incoming = phi->getIncomingValue(i);

      // Skip undef values
      if (llvm::isa<llvm::UndefValue>(incoming)) {
        continue;
      }

      // Skip already-visited (cycle)
      if (visited->count(incoming)) {
        continue;
      }

      auto incoming_ptr = GetKnownPointerRecursive(incoming, tracker, mem_info,
                                                    stack_info, max_depth - 1, visited);
      if (!incoming_ptr) {
        // This incoming value is not a known pointer - can't track this phi
        return std::nullopt;
      }

      if (!common_ptr) {
        common_ptr = *incoming_ptr;
      } else if (*common_ptr != *incoming_ptr) {
        // Different pointer values on different paths - can't track
        return std::nullopt;
      }
    }

    // If all non-undef incoming values agree (or only cycles/undef), return that value
    if (common_ptr) {
      return common_ptr;
    }
  }

  return std::nullopt;
}

// Enhanced version that also checks tracked pointer values (including through phis)
std::pair<uint64_t, llvm::Value*>
DecomposeAddressWithTracking(llvm::Value *addr, const MemoryBackingInfo &mem_info,
                              const StackBackingInfo *stack_info,
                              const PointerTracker &tracker) {
  // First try normal decomposition
  auto result = DecomposeAddress(addr, mem_info, stack_info);
  if (result.first != 0) {
    return result;
  }

  // Check if addr itself is a tracked pointer value (including through phis)
  if (auto known = GetKnownPointerRecursive(addr, tracker, mem_info, stack_info)) {
    uint64_t ptr_val = *known;
    // Verify it points to a known section
    if (mem_info.FindGlobalForAddress(ptr_val).first ||
        (stack_info && stack_info->FindStackOffset(ptr_val).first)) {
      // Return as base with zero offset
      auto *zero = llvm::ConstantInt::get(addr->getType(), 0);
      return {ptr_val, zero};
    }
  }

  // Check for (tracked_pointer + dynamic_offset) or (tracked_pointer | dynamic_offset)
  if (auto *bin_op = llvm::dyn_cast<llvm::BinaryOperator>(addr)) {
    unsigned opcode = bin_op->getOpcode();
    if (opcode == llvm::Instruction::Add || opcode == llvm::Instruction::Or) {
      llvm::Value *op0 = bin_op->getOperand(0);
      llvm::Value *op1 = bin_op->getOperand(1);

      for (int i = 0; i < 2; i++) {
        llvm::Value *potential_base = (i == 0) ? op0 : op1;
        llvm::Value *potential_offset = (i == 0) ? op1 : op0;

        // Use recursive lookup that handles phis
        if (auto known = GetKnownPointerRecursive(potential_base, tracker,
                                                   mem_info, stack_info)) {
          uint64_t ptr_val = *known;
          if (mem_info.FindGlobalForAddress(ptr_val).first ||
              (stack_info && stack_info->FindStackOffset(ptr_val).first)) {
            return {ptr_val, potential_offset};
          }
        }
      }
    }
  }

  return {0, nullptr};
}

}  // anonymous namespace

// PointerTracker implementation
void PointerTracker::TrackStore(uint64_t addr, uint64_t value) {
  memory_contents[addr] = value;
}

void PointerTracker::TrackLoadResult(llvm::Value *result, uint64_t value) {
  known_pointer_values[result] = value;
}

std::optional<uint64_t> PointerTracker::GetKnownValue(llvm::Value *v) const {
  auto it = known_pointer_values.find(v);
  if (it != known_pointer_values.end()) {
    return it->second;
  }
  return std::nullopt;
}

std::optional<uint64_t> PointerTracker::GetStoredValue(uint64_t addr) const {
  auto it = memory_contents.find(addr);
  if (it != memory_contents.end()) {
    return it->second;
  }
  return std::nullopt;
}

// Check if a value is a valid section address (global or stack)
static bool IsValidSectionAddress(uint64_t va, const MemoryBackingInfo &mem_info,
                                   const StackBackingInfo *stack_info) {
  if (mem_info.FindGlobalForAddress(va).first) return true;
  if (stack_info && stack_info->FindStackOffset(va).first) return true;
  return false;
}

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
  std::set<llvm::Function *> read_float_intrinsics;
  std::set<llvm::Function *> write_float_intrinsics;
  llvm::Function *read_64 = nullptr;
  llvm::Function *write_64 = nullptr;

  const char *read_names[] = {
      "__remill_read_memory_8", "__remill_read_memory_16",
      "__remill_read_memory_32", "__remill_read_memory_64"};
  const char *write_names[] = {
      "__remill_write_memory_8", "__remill_write_memory_16",
      "__remill_write_memory_32", "__remill_write_memory_64"};
  const char *read_float_names[] = {
      "__remill_read_memory_f32", "__remill_read_memory_f64",
      "__remill_read_memory_f80"};
  const char *write_float_names[] = {
      "__remill_write_memory_f32", "__remill_write_memory_f64",
      "__remill_write_memory_f80"};

  for (const char *name : read_names) {
    if (auto *f = module->getFunction(name)) {
      read_intrinsics.insert(f);
      if (std::string(name) == "__remill_read_memory_64") {
        read_64 = f;
      }
    }
  }
  for (const char *name : write_names) {
    if (auto *f = module->getFunction(name)) {
      write_intrinsics.insert(f);
      if (std::string(name) == "__remill_write_memory_64") {
        write_64 = f;
      }
    }
  }
  for (const char *name : read_float_names) {
    if (auto *f = module->getFunction(name)) {
      read_float_intrinsics.insert(f);
    }
  }
  for (const char *name : write_float_names) {
    if (auto *f = module->getFunction(name)) {
      write_float_intrinsics.insert(f);
    }
  }

  // Pointer tracker for multi-pass lowering
  PointerTracker tracker;

  // Iterative processing - loop until no more progress
  // This handles cases where pointer tracking enables lowering of previously-stuck accesses
  constexpr int MAX_ITERATIONS = 10;
  int iteration = 0;
  int total_lowered = 0;

  while (iteration < MAX_ITERATIONS) {
    iteration++;

    // Collect remaining memory intrinsics in program order
    std::vector<llvm::CallInst *> to_process;
    for (auto &bb : *target_func) {
      for (auto &inst : bb) {
        if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
          auto *callee = call->getCalledFunction();
          if (read_intrinsics.count(callee) || write_intrinsics.count(callee) ||
              read_float_intrinsics.count(callee) || write_float_intrinsics.count(callee)) {
            to_process.push_back(call);
          }
        }
      }
    }

    if (to_process.empty()) {
      break;  // All done
    }

    int lowered_this_pass = 0;

    // Process in program order
    for (auto *call : to_process) {
    auto *callee = call->getCalledFunction();
    bool is_read = read_intrinsics.count(callee) > 0;
    bool is_float_read = read_float_intrinsics.count(callee) > 0;
    bool is_64bit_read = (callee == read_64);
    bool is_64bit_write = (callee == write_64);

    if (is_read || is_float_read) {
      // Read intrinsic: __remill_read_memory_N(mem, addr) -> value
      if (call->arg_size() < 2) {
        continue;
      }

      llvm::Value *addr_arg = call->getArgOperand(1);
      llvm::Value *replacement = nullptr;
      uint64_t read_address = 0;  // Track for pointer propagation

      if (auto *addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_arg)) {
        uint64_t address = addr_const->getZExtValue();
        read_address = address;

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
      } else {
        // Try dynamic address decomposition with pointer tracking
        auto [base_va, dyn_offset] = DecomposeAddressWithTracking(
            addr_arg, memory_info, stack_info, tracker);
        if (base_va && dyn_offset) {
          // Try global sections
          auto [global, section_offset] = memory_info.FindGlobalForAddress(base_va);
          if (global) {
            auto it = global_to_alloca.find(global);
            if (it != global_to_alloca.end()) {
              llvm::IRBuilder<> ir(call);
              auto *alloca = it->second;

              // Compute total offset: section_offset + dynamic_offset
              llvm::Value *total_offset = dyn_offset;
              if (section_offset != 0) {
                total_offset = ir.CreateAdd(
                    llvm::ConstantInt::get(dyn_offset->getType(), section_offset),
                    dyn_offset, "total_offset");
              }

              // GEP with dynamic index
              auto *ptr = ir.CreateGEP(
                  alloca->getAllocatedType(), alloca,
                  {ir.getInt64(0), total_offset}, "dyn_mem_ptr");
              auto *val = ir.CreateLoad(call->getType(), ptr, "dyn_mem_val");

              replacement = val;
              std::cout << "Lowered dynamic read (base 0x" << std::hex << base_va
                        << " + offset) -> load from global alloca\n" << std::dec;
            }
          }
          // Try stack if global not found
          else if (stack_info) {
            auto [stack_alloca, stack_offset] = stack_info->FindStackOffset(base_va);
            if (stack_alloca) {
              llvm::IRBuilder<> ir(call);

              // Compute total offset: stack_offset + dynamic_offset
              llvm::Value *total_offset = dyn_offset;
              if (stack_offset != 0) {
                total_offset = ir.CreateAdd(
                    llvm::ConstantInt::get(dyn_offset->getType(), stack_offset),
                    dyn_offset, "total_offset");
              }

              auto *ptr = ir.CreateGEP(
                  stack_alloca->getAllocatedType(), stack_alloca,
                  {ir.getInt64(0), total_offset}, "dyn_stack_ptr");
              auto *val = ir.CreateLoad(call->getType(), ptr, "dyn_stack_val");

              replacement = val;
              std::cout << "Lowered dynamic read (base 0x" << std::hex << base_va
                        << " + offset) -> load from stack alloca\n" << std::dec;
            }
          }
        }
      }

      // NOTE: We intentionally do NOT have a fallback for arbitrary dynamic addresses.
      // The previous fallback assumed all dynamic addresses were stack-relative, which
      // caused incorrect behavior when the address pointed to other sections (e.g., .rdata).
      // If we can't decompose the address as base_const + offset where base_const is in
      // a known section, we leave the access as undef.

      // If we successfully lowered the read, replace and erase
      if (replacement) {
        // Track pointer values loaded from known locations (for 64-bit reads)
        if (is_64bit_read && read_address != 0) {
          if (auto stored_ptr = tracker.GetStoredValue(read_address)) {
            tracker.TrackLoadResult(replacement, *stored_ptr);
            std::cout << "Tracked pointer: load from 0x" << std::hex << read_address
                      << " = 0x" << *stored_ptr << std::dec << "\n";
          }
        }
        call->replaceAllUsesWith(replacement);
        call->eraseFromParent();
        lowered_this_pass++;
      }
      // If not lowered, leave the call for next iteration (pointer tracking may help)

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

        // Track pointer stores (for 64-bit writes of section pointers)
        if (is_64bit_write) {
          if (auto *val_const = llvm::dyn_cast<llvm::ConstantInt>(value_arg)) {
            uint64_t ptr_val = val_const->getZExtValue();
            if (IsValidSectionAddress(ptr_val, memory_info, stack_info)) {
              tracker.TrackStore(address, ptr_val);
              std::cout << "Tracked pointer store: [0x" << std::hex << address
                        << "] = 0x" << ptr_val << std::dec << "\n";
            }
          } else if (auto known_ptr = tracker.GetKnownValue(value_arg)) {
            // The value being stored is a tracked pointer
            tracker.TrackStore(address, *known_ptr);
            std::cout << "Tracked pointer store (from tracked): [0x" << std::hex << address
                      << "] = 0x" << *known_ptr << std::dec << "\n";
          }
        }

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
      } else {
        // Try dynamic address decomposition with pointer tracking
        auto [base_va, dyn_offset] = DecomposeAddressWithTracking(
            addr_arg, memory_info, stack_info, tracker);
        if (base_va && dyn_offset) {
          // Try global sections
          auto [global, section_offset] = memory_info.FindGlobalForAddress(base_va);
          if (global) {
            auto it = global_to_alloca.find(global);
            if (it != global_to_alloca.end()) {
              llvm::IRBuilder<> ir(call);
              auto *alloca = it->second;

              // Compute total offset: section_offset + dynamic_offset
              llvm::Value *total_offset = dyn_offset;
              if (section_offset != 0) {
                total_offset = ir.CreateAdd(
                    llvm::ConstantInt::get(dyn_offset->getType(), section_offset),
                    dyn_offset, "total_offset");
              }

              // GEP with dynamic index
              auto *ptr = ir.CreateGEP(
                  alloca->getAllocatedType(), alloca,
                  {ir.getInt64(0), total_offset}, "dyn_mem_ptr");
              ir.CreateStore(value_arg, ptr);

              lowered = true;
              std::cout << "Lowered dynamic write (base 0x" << std::hex << base_va
                        << " + offset) -> store to global alloca\n" << std::dec;
            }
          }
          // Try stack if global not found
          else if (stack_info) {
            auto [stack_alloca, stack_offset] = stack_info->FindStackOffset(base_va);
            if (stack_alloca) {
              llvm::IRBuilder<> ir(call);

              // Compute total offset: stack_offset + dynamic_offset
              llvm::Value *total_offset = dyn_offset;
              if (stack_offset != 0) {
                total_offset = ir.CreateAdd(
                    llvm::ConstantInt::get(dyn_offset->getType(), stack_offset),
                    dyn_offset, "total_offset");
              }

              auto *ptr = ir.CreateGEP(
                  stack_alloca->getAllocatedType(), stack_alloca,
                  {ir.getInt64(0), total_offset}, "dyn_stack_ptr");
              ir.CreateStore(value_arg, ptr);

              lowered = true;
              std::cout << "Lowered dynamic write (base 0x" << std::hex << base_va
                        << " + offset) -> store to stack alloca\n" << std::dec;
            }
          }
        }
      }

      // NOTE: We intentionally do NOT have a fallback for arbitrary dynamic addresses.
      // See the comment in the read handling section above.

      // Only erase if we successfully lowered
      if (lowered) {
        // Write intrinsics return the memory pointer (first argument)
        call->replaceAllUsesWith(call->getArgOperand(0));
        call->eraseFromParent();
        lowered_this_pass++;
      }
      // If not lowered, leave the call for next iteration (pointer tracking may help)
    }
  }

    total_lowered += lowered_this_pass;
    std::cout << "Iteration " << iteration << ": lowered " << lowered_this_pass
              << " memory intrinsics (total: " << total_lowered << ")\n";

    // No progress means we can't lower any more
    if (lowered_this_pass == 0) {
      break;
    }
  }

  // After all iterations, check for remaining intrinsics and warn
  int remaining = 0;
  for (auto &bb : *target_func) {
    for (auto &inst : bb) {
      if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        auto *callee = call->getCalledFunction();
        if (read_intrinsics.count(callee) || write_intrinsics.count(callee) ||
            read_float_intrinsics.count(callee) || write_float_intrinsics.count(callee)) {
          remaining++;
          std::cerr << "WARNING: Could not lower memory intrinsic: ";
          call->print(llvm::errs());
          std::cerr << "\n";

          // Replace with undef/noop so code can still run
          if (read_intrinsics.count(callee) || read_float_intrinsics.count(callee)) {
            call->replaceAllUsesWith(llvm::UndefValue::get(call->getType()));
          } else {
            call->replaceAllUsesWith(call->getArgOperand(0));
          }
        }
      }
    }
  }

  // Erase remaining intrinsics (we already replaced their uses)
  std::vector<llvm::CallInst*> to_erase;
  for (auto &bb : *target_func) {
    for (auto &inst : bb) {
      if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        auto *callee = call->getCalledFunction();
        if (read_intrinsics.count(callee) || write_intrinsics.count(callee) ||
            read_float_intrinsics.count(callee) || write_float_intrinsics.count(callee)) {
          to_erase.push_back(call);
        }
      }
    }
  }
  for (auto *call : to_erase) {
    call->eraseFromParent();
  }

  if (remaining > 0) {
    std::cerr << "WARNING: " << remaining << " memory intrinsics could not be lowered\n";
  }
  std::cout << "Memory lowering complete: " << total_lowered << " intrinsics lowered in "
            << iteration << " iterations\n";
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
