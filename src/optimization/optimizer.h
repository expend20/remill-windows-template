#pragma once

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

namespace optimization {

// Optimize lifted code for clean IR output
// Runs inlining, SROA, mem2reg, and other passes to simplify State usage
// Safe to run on modules with unsized types (like remill semantics module)
void OptimizeForCleanIR(llvm::Module *module, llvm::Function *target_func);

// Run full O3 optimization pipeline including loop unrolling
// Only safe to run on clean modules (extracted functions without unsized types)
void OptimizeAggressive(llvm::Module *module);

// Remove calls to memory intrinsics by replacing with undef
// Useful for leaf functions that don't actually use memory
void RemoveMemoryIntrinsics(llvm::Module *module);

// Remove flag computation intrinsics by replacing with their computed value
// These intrinsics are identity functions used for debugging but block optimization
void RemoveFlagComputationIntrinsics(llvm::Module *module);

}  // namespace optimization
