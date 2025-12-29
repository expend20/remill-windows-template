#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>

#include "utils/pe_reader.h"

namespace lifting {

// Forward declarations
struct IterativeLiftingState;

// Helper class for resolving indirect jumps via SCCP analysis
class IndirectJumpResolver {
 public:
  explicit IndirectJumpResolver(const utils::PEInfo *pe_info);

  // Resolve indirect jumps by cloning the module and running SCCP
  // Returns set of newly discovered target addresses
  std::set<uint64_t> ResolveIndirectJumps(
      llvm::Function *main_func,
      uint64_t entry_point,
      IterativeLiftingState &iter_state,
      const std::set<uint64_t> &lifted_blocks,
      std::function<uint64_t(uint64_t)> find_block_end,
      std::function<uint64_t(uint64_t)> get_block_owner);

  // Evaluate an LLVM Value assuming program_counter = entry_point
  std::optional<int64_t> EvaluateWithKnownPC(llvm::Value *val,
                                              uint64_t entry_point);

  // Helper for evaluating binary operations
  static std::optional<uint64_t> EvaluateBinaryOp(
      llvm::Instruction::BinaryOps opcode, uint64_t lhs, uint64_t rhs);

  // Read a qword from PE section data at the given masked offset
  std::optional<uint64_t> ReadQwordFromPESections(uint64_t masked_offset) const;

 private:
  const utils::PEInfo *pe_info_;
};

}  // namespace lifting
