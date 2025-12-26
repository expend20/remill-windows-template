#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

namespace utils {
struct PEInfo;
}

namespace lifting {

// Holds mapping from virtual addresses to LLVM globals
struct MemoryBackingInfo {
  struct SectionMapping {
    uint64_t start_va;             // Virtual address start
    uint64_t end_va;               // Virtual address end (exclusive)
    llvm::GlobalVariable *global;  // Backing global
  };
  std::vector<SectionMapping> sections;

  // Find global and offset for a virtual address
  // Returns {nullptr, 0} if address not found
  std::pair<llvm::GlobalVariable *, uint64_t>
  FindGlobalForAddress(uint64_t va) const;
};

// Create LLVM globals for all PE data sections
// Each readable section becomes an LLVM global array initialized with section data
// Writable sections are marked as non-constant
MemoryBackingInfo CreateMemoryGlobals(llvm::Module *module,
                                       const utils::PEInfo &pe_info);

// Stack memory backing for lifted code
struct StackBackingInfo {
  llvm::AllocaInst *stack_alloca;  // The stack byte array
  uint64_t stack_top_va;           // Initial RSP value (high end)
  uint64_t stack_size;             // Size of stack in bytes

  // Find stack alloca and offset for a virtual address in stack range
  // Stack range is [stack_top_va - stack_size, stack_top_va)
  // Returns {nullptr, 0} if address not in stack range
  std::pair<llvm::AllocaInst *, uint64_t> FindStackOffset(uint64_t va) const;
};

// Create stack alloca at function entry for stack memory operations
// Returns info needed for lowering stack accesses
StackBackingInfo CreateStackAlloca(llvm::Function *func,
                                   uint64_t initial_rsp,
                                   uint64_t stack_size);

// Lower __remill_read/write_memory_* intrinsics to actual load/store operations
// Creates local allocas from the backing globals, allowing LLVM's SROA to optimize
// This approach treats memory as local variables that LLVM can fully optimize
// If stack_info is provided, also handles stack memory accesses
// Unknown addresses are replaced with undef
void LowerMemoryIntrinsics(llvm::Module *module,
                           const MemoryBackingInfo &memory_info,
                           const StackBackingInfo *stack_info,
                           llvm::Function *target_func);

// NOT USED - Kept for reference only. See MEMORY.md for details.
// Replace memory intrinsics with concrete constant values
// Does compile-time constant propagation by:
// 1. Tracking all constant writes at byte granularity
// 2. Composing reads from tracked writes and/or original PE data
// Limitations: No instruction ordering, fails for repeated r/w to same address
void ReplaceMemoryIntrinsics(llvm::Module *module,
                              const utils::PEInfo &pe_info);

}  // namespace lifting
