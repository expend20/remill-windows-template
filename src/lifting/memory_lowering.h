#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

namespace utils {
struct PEInfo;
}

namespace lifting {

// Forward declaration
enum class GlobalMode;

// Holds mapping from virtual addresses to LLVM globals
struct MemoryBackingInfo {
  struct SectionMapping {
    uint64_t start_va;             // Virtual address start
    uint64_t end_va;               // Virtual address end (exclusive)
    llvm::GlobalVariable *global;  // Backing global
    bool is_writable;              // True for .data/.bss, false for .rdata/.text
  };
  std::vector<SectionMapping> sections;

  // Find global and offset for a virtual address
  // Returns {nullptr, 0} if address not found
  std::pair<llvm::GlobalVariable *, uint64_t>
  FindGlobalForAddress(uint64_t va) const;
};

// Create LLVM globals for all PE data sections
// Each readable section becomes an LLVM global array initialized with section data
// global_mode controls memory representation:
// - Constant: Create globals (used with allocas for full optimization)
// - Lifted: Create globals (used directly, pointer data resolved)
// - OriginalVA: Create NO globals (will use inttoptr to original VAs)
MemoryBackingInfo CreateMemoryGlobals(llvm::Module *module,
                                       const utils::PEInfo &pe_info,
                                       GlobalMode global_mode);

// Stack memory backing for lifted code
struct StackBackingInfo {
  llvm::AllocaInst *stack_alloca;  // The stack byte array
  uint64_t stack_top_va;           // Initial RSP value (high end)
  uint64_t stack_size;             // Size of stack in bytes
  uint64_t caller_space;           // Extra bytes above stack_top_va for caller's frame

  // Find stack alloca and offset for a virtual address in stack range
  // Stack range is [stack_top_va - stack_size, stack_top_va + caller_space)
  // Returns {nullptr, 0} if address not in stack range
  std::pair<llvm::AllocaInst *, uint64_t> FindStackOffset(uint64_t va) const;
};

// Create stack alloca at function entry for stack memory operations
// Returns info needed for lowering stack accesses
StackBackingInfo CreateStackAlloca(llvm::Function *func,
                                   uint64_t initial_rsp,
                                   uint64_t stack_size);

// Tracks known pointer values through memory store/load pairs
// Used by multi-pass lowering to handle pointer-through-memory patterns
struct PointerTracker {
  // Map from LLVM Value* to known constant pointer value
  // When we lower a load and know the stored value, we record it here
  std::map<llvm::Value*, uint64_t> known_pointer_values;

  // Map from memory location VA to stored pointer value
  // When we see write_memory_64(mem, addr, const_ptr) where const_ptr
  // points to a known section, we record: addr -> const_ptr
  std::map<uint64_t, uint64_t> memory_contents;

  // Track a store of a pointer value to memory
  void TrackStore(uint64_t addr, uint64_t value);

  // Track the result of a load that returned a known pointer
  void TrackLoadResult(llvm::Value *result, uint64_t value);

  // Get the known pointer value for an LLVM Value, if tracked
  std::optional<uint64_t> GetKnownValue(llvm::Value *v) const;

  // Get the known pointer stored at a memory address, if tracked
  std::optional<uint64_t> GetStoredValue(uint64_t addr) const;
};

// Lower __remill_read/write_memory_* intrinsics to actual load/store operations
// If stack_info is provided, also handles stack memory accesses
// global_mode controls memory representation:
// - Constant: Use allocas (copied from globals) for full SROA optimization
// - Lifted: Use globals directly for all sections
// - OriginalVA: Use inttoptr for all sections (no globals)
// Unknown addresses are replaced with undef
void LowerMemoryIntrinsics(llvm::Module *module,
                           const MemoryBackingInfo &memory_info,
                           const StackBackingInfo *stack_info,
                           llvm::Function *target_func,
                           GlobalMode global_mode);

// NOT USED - Kept for reference only. See MEMORY.md for details.
// Replace memory intrinsics with concrete constant values
// Does compile-time constant propagation by:
// 1. Tracking all constant writes at byte granularity
// 2. Composing reads from tracked writes and/or original PE data
// Limitations: No instruction ordering, fails for repeated r/w to same address
void ReplaceMemoryIntrinsics(llvm::Module *module,
                              const utils::PEInfo &pe_info);

}  // namespace lifting
