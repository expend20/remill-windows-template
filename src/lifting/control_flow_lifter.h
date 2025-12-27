#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include <remill/Arch/Instruction.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>

#include "lifting_context.h"

namespace lifting {

// Information about a decoded instruction
struct DecodedInstruction {
  uint64_t address;
  size_t size;
  remill::Instruction instr;
};

// Control flow-aware lifter that handles jumps and conditional branches
class ControlFlowLifter {
 public:
  explicit ControlFlowLifter(LiftingContext &ctx);

  // Decode and analyze control flow, then lift all instructions
  // code_base: start of the code region (for scanning all instructions)
  // entry_point: the function's entry point address
  // Returns true on success
  bool LiftFunction(uint64_t code_base, uint64_t entry_point,
                    const uint8_t *bytes, size_t size,
                    llvm::Function *func);

 private:
  // First pass: decode all instructions and discover basic block boundaries
  bool DiscoverBasicBlocks(uint64_t start_address, const uint8_t *bytes,
                           size_t size);

  // Create LLVM basic blocks for each discovered block
  void CreateBasicBlocks(llvm::Function *func);

  // Lift instructions into their respective basic blocks
  bool LiftBlocks(const uint8_t *bytes, size_t size, uint64_t code_base);

  // Finish a basic block with appropriate terminator
  void FinishBlock(llvm::BasicBlock *block, const DecodedInstruction &last_instr,
                   uint64_t next_addr, uint64_t block_addr);

  LiftingContext &ctx_;
  remill::DecodingContext decoding_context_;

  // All decoded instructions indexed by address
  std::map<uint64_t, DecodedInstruction> instructions_;

  // Set of addresses that start a basic block
  std::set<uint64_t> block_starts_;

  // LLVM basic blocks indexed by start address
  std::map<uint64_t, llvm::BasicBlock *> blocks_;

  // Range of valid code addresses
  uint64_t code_start_ = 0;
  uint64_t code_end_ = 0;

  // Entry point address (may differ from code_start_)
  uint64_t entry_point_ = 0;

  // Call return addresses mapped to their continuation blocks
  // Used by RET to dispatch back to the correct call site
  std::map<uint64_t, llvm::BasicBlock *> return_blocks_;

  // Set of block addresses that are call targets (i.e., helper functions)
  // RETs in these blocks should dispatch back to callers
  std::set<uint64_t> call_targets_;

  // Shadow return stack for proper LIFO call dispatch
  // Maps call site return address to a unique index
  std::map<uint64_t, uint32_t> call_site_indices_;

  // Allocas for the shadow return stack (created in entry block)
  llvm::AllocaInst *shadow_stack_ = nullptr;     // [MAX_CALL_DEPTH x i32]
  llvm::AllocaInst *shadow_stack_sp_ = nullptr;  // i32 stack pointer

  static constexpr unsigned kMaxCallDepth = 64;
};

}  // namespace lifting
