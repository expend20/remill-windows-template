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
class ExternalCallHandler;
struct ExternalCallConfig;

// Helper class for finishing basic blocks with appropriate terminators
class BlockTerminator {
 public:
  explicit BlockTerminator(LiftingContext &ctx,
                           ExternalCallHandler *external_handler = nullptr);

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

 private:
  LiftingContext &ctx_;
  ExternalCallHandler *external_handler_;

  // Try to extract the memory address from an indirect call instruction
  // Returns the computed effective address, or 0 if not determinable
  uint64_t ExtractIndirectCallMemoryAddress(const remill::Instruction &instr);

  // Generate an external function call
  // Returns true if external call was generated, false otherwise
  bool GenerateExternalCall(
      llvm::BasicBlock *block,
      const ExternalCallConfig *config,
      uint64_t next_addr,
      const std::map<uint64_t, llvm::BasicBlock *> &blocks,
      const std::map<uint64_t, uint64_t> &block_owner,
      uint64_t current_owner);
};

}  // namespace lifting
