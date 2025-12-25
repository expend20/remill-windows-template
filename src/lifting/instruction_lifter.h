#pragma once

#include <cstdint>
#include <string_view>

#include <remill/Arch/Instruction.h>

#include <llvm/IR/BasicBlock.h>

#include "lifting_context.h"

namespace lifting {

// Lifts individual instructions into LLVM IR
class InstructionLifter {
 public:
  explicit InstructionLifter(LiftingContext &ctx);

  // Decode and lift a single instruction at the given address
  // Returns the number of bytes consumed, or 0 on failure
  size_t LiftInstruction(uint64_t address, const uint8_t *bytes, size_t size,
                         llvm::BasicBlock *block);

  // Lift multiple instructions sequentially
  // Returns true if all instructions were lifted successfully
  template <size_t N>
  bool LiftInstructions(uint64_t start_address, const uint8_t (&bytes)[N],
                        llvm::BasicBlock *block) {
    return LiftInstructionsImpl(start_address, bytes, N, block);
  }

  bool LiftInstructionsImpl(uint64_t start_address, const uint8_t *bytes,
                            size_t size, llvm::BasicBlock *block);

 private:
  LiftingContext &ctx_;
  remill::DecodingContext decoding_context_;
};

}  // namespace lifting
