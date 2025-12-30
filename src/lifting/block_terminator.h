#pragma once

#include <cstdint>
#include <map>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>

#include "control_flow_lifter.h"

namespace lifting {

// Forward declarations
struct IterativeLiftingState;
class LiftingContext;

// Helper class for finishing basic blocks with appropriate terminators
class BlockTerminator {
 public:
  explicit BlockTerminator(LiftingContext &ctx);

  // Finish a basic block with appropriate terminator
  // Returns the SwitchInst for indirect jumps (nullptr otherwise)
  llvm::SwitchInst *FinishBlock(
      llvm::BasicBlock *block,
      const DecodedInstruction &last_instr,
      uint64_t next_addr,
      uint64_t block_addr,
      const std::map<uint64_t, llvm::BasicBlock *> &blocks,
      const std::map<uint64_t, uint64_t> &block_owner,
      const std::map<uint64_t, llvm::Function *> &helper_functions,
      IterativeLiftingState &iter_state,
      std::map<uint64_t, llvm::BasicBlock *> &dispatch_blocks);

  // Try to extract the memory address from an indirect call/jump instruction
  // Returns the computed effective address, or 0 if not determinable
  // Static so it can be used by ControlFlowLifter for pre-lift detection
  static uint64_t ExtractIndirectCallMemoryAddress(const remill::Instruction &instr);

 private:
  LiftingContext &ctx_;
};

}  // namespace lifting
