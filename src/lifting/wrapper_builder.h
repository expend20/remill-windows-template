#pragma once

#include <string>
#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

#include "lifting_context.h"

namespace lifting {

// Stack memory constants for lifted code
// Initial RSP value (high address, stack grows down)
constexpr uint64_t INITIAL_RSP = 0x7FFFFF000000ULL;
// Maximum stack size for lifted code
// Must be large enough for nested function calls and local variables
// and accommodate RSP growth during RET dispatch loops
// XTEA test needs substantial headroom for complex control flow
constexpr uint64_t STACK_SIZE = 4096ULL;

// Configuration for variable (non-constant) registers
struct VariableConfig {
  std::vector<std::string> input_registers;  // e.g., ["RCX", "RDX"]
  std::string return_register = "RAX";
};

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

  // Create a wrapper function with variable register inputs:
  // 1. Takes function parameters for each variable register
  // 2. Allocates State on stack, initializes RSP
  // 3. Stores function parameters into corresponding State register fields
  // 4. Calls the lifted function
  // 5. Extracts return value from specified register
  // Returns the wrapper function with signature: i64(i64, i64, ...)
  llvm::Function *CreateParameterizedWrapper(const std::string &wrapper_name,
                                             llvm::Function *lifted_func,
                                             uint64_t start_pc,
                                             const VariableConfig &config);

  // Mark a lifted function for inlining
  static void PrepareForInlining(llvm::Function *func);

 private:
  LiftingContext &ctx_;
};

}  // namespace lifting
