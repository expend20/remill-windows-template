#pragma once

#include <cstdint>
#include <map>
#include <set>

#include <llvm/IR/Function.h>

#include "control_flow_lifter.h"

namespace lifting {

// Helper class for splitting code into multiple functions (main + helpers)
class FunctionSplitter {
 public:
  // Determine which blocks belong to which native function
  // Uses BFS to determine reachability from entry points
  static void AssignBlocksToFunctions(
      const std::set<uint64_t> &block_starts,
      const std::set<uint64_t> &call_targets,
      const std::map<uint64_t, DecodedInstruction> &instructions,
      uint64_t entry_point,
      uint64_t code_end,
      std::map<uint64_t, uint64_t> &block_owner);

  // Create helper functions for call targets with alwaysinline attribute
  static void CreateHelperFunctions(
      llvm::Function *main_func,
      const std::set<uint64_t> &call_targets,
      std::map<uint64_t, llvm::Function *> &helper_functions);
};

}  // namespace lifting
