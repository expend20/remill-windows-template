#include "function_splitter.h"

#include <iostream>
#include <queue>
#include <sstream>

#include <llvm/IR/Attributes.h>

namespace lifting {

void FunctionSplitter::AssignBlocksToFunctions(
    const std::set<uint64_t> &block_starts,
    const std::set<uint64_t> &call_targets,
    const std::map<uint64_t, DecodedInstruction> &instructions,
    uint64_t entry_point,
    uint64_t code_end,
    std::map<uint64_t, uint64_t> &block_owner) {

  // First, assign all blocks to main function (owner = 0)
  for (uint64_t addr : block_starts) {
    block_owner[addr] = 0;
  }

  // Option C: Don't create helper functions
  // All blocks stay in main function (owner = 0)
  // Direct CALLs will branch to target blocks, RET dispatch handles returns
  // This avoids phi nodes from function inlining that break memory lowering
  (void)call_targets;  // Suppress unused parameter warning
  (void)instructions;
  (void)code_end;

  // Debug output
  std::cout << "Block ownership:\n";
  for (const auto &[addr, owner] : block_owner) {
    if (owner == 0) {
      std::cout << "  0x" << std::hex << addr << " -> main\n";
    } else {
      std::cout << "  0x" << std::hex << addr << " -> helper_0x" << owner << "\n";
    }
  }
  std::cout << std::dec;
}

void FunctionSplitter::CreateHelperFunctions(
    llvm::Function *main_func,
    const std::set<uint64_t> &call_targets,
    std::map<uint64_t, llvm::Function *> &helper_functions) {

  // Option C: Don't create helper functions
  // All code stays in main function, CALL becomes direct branch
  // This avoids phi nodes from function inlining that break memory lowering
  (void)main_func;
  (void)call_targets;
  (void)helper_functions;

  std::cout << "Option C: Skipping helper function creation (all blocks in main)\n";
}

}  // namespace lifting
