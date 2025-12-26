#pragma once

#include <string>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

#include "lifting_context.h"

namespace lifting {

// Stack memory constants for lifted code
// Initial RSP value (high address, stack grows down)
constexpr uint64_t INITIAL_RSP = 0x7FFFFF000000ULL;
// Maximum stack size - keep small to enable LLVM's SROA optimization
// Need at least 24 bytes: 8 for call return addr, 8 for padding, 8 for outer RET
constexpr uint64_t STACK_SIZE = 32ULL;

// Builds wrapper functions that call lifted code with native calling convention
class WrapperBuilder {
 public:
  explicit WrapperBuilder(LiftingContext &ctx);

  // Create a wrapper function that:
  // 1. Allocates State on stack
  // 2. Calls the lifted function
  // 3. Extracts the return value from RAX
  // Returns the wrapper function
  llvm::Function *CreateInt32ReturnWrapper(const std::string &wrapper_name,
                                           llvm::Function *lifted_func,
                                           uint64_t start_pc);

  // Mark a lifted function for inlining
  static void PrepareForInlining(llvm::Function *func);

 private:
  LiftingContext &ctx_;
};

}  // namespace lifting
