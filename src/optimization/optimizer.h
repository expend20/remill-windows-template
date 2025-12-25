#pragma once

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

namespace lifting {
class MemoryProvider;
}

namespace optimization {

// Optimize lifted code for clean IR output
// Runs inlining, SROA, mem2reg, and other passes to simplify State usage
void OptimizeForCleanIR(llvm::Module *module, llvm::Function *target_func);

// Remove calls to memory intrinsics by replacing with undef
// Useful for leaf functions that don't actually use memory
void RemoveMemoryIntrinsics(llvm::Module *module);

// Replace memory intrinsics with concrete values where possible
// Uses memory_provider to look up constant data
// Falls back to undef for unknown addresses
void ReplaceMemoryIntrinsics(llvm::Module *module,
                              const lifting::MemoryProvider *memory_provider);

}  // namespace optimization
