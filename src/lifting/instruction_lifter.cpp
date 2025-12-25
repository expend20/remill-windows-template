#include "instruction_lifter.h"

#include <iostream>

namespace lifting {

InstructionLifter::InstructionLifter(LiftingContext &ctx)
    : ctx_(ctx), decoding_context_(ctx.GetArch()->CreateInitialContext()) {}

size_t InstructionLifter::LiftInstruction(uint64_t address,
                                          const uint8_t *bytes, size_t size,
                                          llvm::BasicBlock *block) {
  std::string_view bytes_view(reinterpret_cast<const char *>(bytes), size);

  remill::Instruction instr;
  if (!ctx_.GetArch()->DecodeInstruction(address, bytes_view, instr,
                                         decoding_context_)) {
    std::cerr << "Failed to decode instruction at 0x" << std::hex << address
              << std::dec << "\n";
    return 0;
  }

  auto lifter = instr.GetLifter();
  auto status = lifter->LiftIntoBlock(instr, block);
  if (status != remill::kLiftedInstruction) {
    std::cerr << "Failed to lift instruction: " << instr.Serialize() << "\n";
    return 0;
  }

  return instr.bytes.size();
}

bool InstructionLifter::LiftInstructionsImpl(uint64_t start_address,
                                             const uint8_t *bytes, size_t size,
                                             llvm::BasicBlock *block) {
  uint64_t address = start_address;
  size_t offset = 0;

  while (offset < size) {
    size_t consumed =
        LiftInstruction(address, bytes + offset, size - offset, block);
    if (consumed == 0) {
      return false;
    }
    offset += consumed;
    address += consumed;
  }

  return true;
}

}  // namespace lifting
