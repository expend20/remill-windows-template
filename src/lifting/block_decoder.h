#pragma once

#include <cstdint>
#include <map>
#include <set>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>

#include "control_flow_lifter.h"

namespace lifting {

// Forward declarations
struct IterativeLiftingState;
class LiftingContext;

// Helper class for decoding instructions and discovering basic blocks
class BlockDecoder {
 public:
  explicit BlockDecoder(LiftingContext &ctx);

  // Set the code region for decoding
  void SetCodeRegion(const uint8_t *bytes, size_t size,
                     uint64_t code_start, uint64_t code_end);

  // Check if an address is valid for decoding
  bool IsValidCodeAddress(uint64_t addr) const;

  // Find the end address of a block (next block start or code_end)
  uint64_t FindBlockEnd(uint64_t block_addr,
                        const std::set<uint64_t> &block_starts) const;

  // Get the address of the last instruction in a block
  uint64_t GetLastInstrAddr(uint64_t block_start, uint64_t block_end,
                            const std::map<uint64_t, DecodedInstruction> &instructions) const;

  // Decode a single block at the given address
  // Returns false if decoding fails or address is invalid
  bool DecodeBlockAt(uint64_t addr,
                     std::map<uint64_t, DecodedInstruction> &instructions,
                     const std::set<uint64_t> &block_starts);

  // BFS-based block discovery from a starting address
  // Only follows direct control flow; marks indirect jumps as unresolved
  void DiscoverBlocksFromEntry(uint64_t start_addr, int iteration,
                               std::map<uint64_t, DecodedInstruction> &instructions,
                               std::set<uint64_t> &block_starts,
                               std::set<uint64_t> &call_targets,
                               std::map<uint64_t, uint64_t> &call_return_addrs,
                               IterativeLiftingState &iter_state);

  // Legacy: First pass decode all instructions and discover basic blocks
  bool DiscoverBasicBlocks(uint64_t start_address,
                           const uint8_t *bytes, size_t size,
                           std::map<uint64_t, DecodedInstruction> &instructions,
                           std::set<uint64_t> &block_starts);

 private:
  LiftingContext &ctx_;
  remill::DecodingContext decoding_context_;

  const uint8_t *code_bytes_ = nullptr;
  size_t code_size_ = 0;
  uint64_t code_start_ = 0;
  uint64_t code_end_ = 0;
};

}  // namespace lifting
