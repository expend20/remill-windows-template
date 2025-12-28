#include "block_decoder.h"

#include <iostream>
#include <queue>

#include <llvm/Support/Format.h>

#include "lifting_context.h"
#include "utils/debug_flag.h"

namespace lifting {

BlockDecoder::BlockDecoder(LiftingContext &ctx,
                           const IterativeLiftingConfig &config)
    : ctx_(ctx),
      config_(config),
      decoding_context_(ctx.GetArch()->CreateInitialContext()) {}

void BlockDecoder::SetCodeRegion(const uint8_t *bytes, size_t size,
                                 uint64_t code_start, uint64_t code_end) {
  code_bytes_ = bytes;
  code_size_ = size;
  code_start_ = code_start;
  code_end_ = code_end;
}

bool BlockDecoder::IsValidCodeAddress(uint64_t addr) const {
  return addr >= code_start_ && addr < code_end_;
}

uint64_t BlockDecoder::FindBlockEnd(uint64_t block_addr,
                                    const std::set<uint64_t> &block_starts) const {
  auto it = block_starts.find(block_addr);
  if (it == block_starts.end()) {
    return code_end_;
  }
  auto next_it = std::next(it);
  return (next_it != block_starts.end()) ? *next_it : code_end_;
}

uint64_t BlockDecoder::GetLastInstrAddr(
    uint64_t block_start, uint64_t block_end,
    const std::map<uint64_t, DecodedInstruction> &instructions) const {
  uint64_t last_addr = block_start;
  for (const auto &[addr, decoded] : instructions) {
    if (addr >= block_start && addr < block_end) {
      if (decoded.instr.IsControlFlow()) {
        return addr;
      }
      last_addr = addr;
    }
  }
  return last_addr;
}

bool BlockDecoder::DecodeBlockAt(uint64_t addr,
                                 std::map<uint64_t, DecodedInstruction> &instructions,
                                 const std::set<uint64_t> &block_starts) {
  if (!IsValidCodeAddress(addr)) {
    return false;
  }

  // Already decoded?
  if (instructions.count(addr)) {
    return true;
  }

  // Decode instructions starting from addr until we hit a control flow instruction
  size_t offset = addr - code_start_;

  while (offset < code_size_) {
    uint64_t current_addr = code_start_ + offset;

    // Check if we've hit another block start (already decoded region)
    if (current_addr != addr && block_starts.count(current_addr)) {
      break;
    }

    std::string_view bytes_view(
        reinterpret_cast<const char *>(code_bytes_ + offset),
        code_size_ - offset);

    DecodedInstruction decoded;
    decoded.address = current_addr;

    if (!ctx_.GetArch()->DecodeInstruction(current_addr, bytes_view,
                                           decoded.instr, decoding_context_)) {
      utils::dbg() << "Failed to decode instruction at " << llvm::format_hex(current_addr, 0) << "\n";
      return false;
    }

    decoded.size = decoded.instr.bytes.size();
    instructions[current_addr] = decoded;

    offset += decoded.size;

    // Stop at control flow instructions
    if (decoded.instr.IsControlFlow()) {
      break;
    }
  }

  return true;
}

void BlockDecoder::DiscoverBlocksFromEntry(
    uint64_t start_addr, int iteration,
    std::map<uint64_t, DecodedInstruction> &instructions,
    std::set<uint64_t> &block_starts,
    std::set<uint64_t> &call_targets,
    std::map<uint64_t, uint64_t> &call_return_addrs,
    IterativeLiftingState &iter_state) {

  if (iter_state.lifted_blocks.count(start_addr)) {
    return;  // Already lifted
  }

  std::queue<uint64_t> worklist;
  std::set<uint64_t> visited;

  worklist.push(start_addr);
  visited.insert(start_addr);

  while (!worklist.empty()) {
    uint64_t addr = worklist.front();
    worklist.pop();

    // Skip if already lifted in previous iteration
    if (iter_state.lifted_blocks.count(addr)) {
      continue;
    }

    // Decode this block if not already decoded
    if (!instructions.count(addr)) {
      if (!DecodeBlockAt(addr, instructions, block_starts)) {
        continue;  // Failed to decode
      }
    }

    // Mark as a block start
    block_starts.insert(addr);
    iter_state.block_discovery_iteration[addr] = iteration;

    // Find last instruction of block to determine successors
    uint64_t block_end = FindBlockEnd(addr, block_starts);
    uint64_t last_addr = GetLastInstrAddr(addr, block_end, instructions);
    auto instr_it = instructions.find(last_addr);
    if (instr_it == instructions.end()) {
      continue;
    }

    const auto &decoded = instr_it->second;
    uint64_t next_addr = last_addr + decoded.size;

    // Add direct successors to worklist
    switch (decoded.instr.category) {
      case remill::Instruction::kCategoryConditionalBranch: {
        // Add both targets: taken branch and fall-through
        if (auto *cond = std::get_if<remill::Instruction::ConditionalInstruction>(
                &decoded.instr.flows)) {
          if (auto *direct = std::get_if<remill::Instruction::DirectJump>(
                  &cond->taken_branch)) {
            uint64_t target = direct->taken_flow.known_target;
            if (IsValidCodeAddress(target) && !visited.count(target) &&
                !iter_state.lifted_blocks.count(target)) {
              worklist.push(target);
              visited.insert(target);
            }
          }
        }
        // Fall-through
        if (IsValidCodeAddress(next_addr) && !visited.count(next_addr) &&
            !iter_state.lifted_blocks.count(next_addr)) {
          worklist.push(next_addr);
          visited.insert(next_addr);
        }
        break;
      }

      case remill::Instruction::kCategoryDirectJump: {
        if (auto *jump = std::get_if<remill::Instruction::DirectJump>(
                &decoded.instr.flows)) {
          uint64_t target = jump->taken_flow.known_target;
          if (IsValidCodeAddress(target) && !visited.count(target) &&
              !iter_state.lifted_blocks.count(target)) {
            worklist.push(target);
            visited.insert(target);
          }
        }
        break;
      }

      case remill::Instruction::kCategoryDirectFunctionCall: {
        // Add call target and return address
        uint64_t target = decoded.instr.branch_taken_pc;
        if (IsValidCodeAddress(target) && !visited.count(target) &&
            !iter_state.lifted_blocks.count(target)) {
          worklist.push(target);
          visited.insert(target);
          call_targets.insert(target);
        }
        if (IsValidCodeAddress(next_addr) && !visited.count(next_addr) &&
            !iter_state.lifted_blocks.count(next_addr)) {
          worklist.push(next_addr);
          visited.insert(next_addr);
        }
        // Track call return address
        call_return_addrs[last_addr] = next_addr;
        break;
      }

      case remill::Instruction::kCategoryIndirectJump:
        // DO NOT follow - will be handled by switch resolution
        utils::dbg() << "Found indirect jump at " << llvm::format_hex(last_addr, 0)
                     << " (will be resolved by SCCP)\n";
        break;

      case remill::Instruction::kCategoryFunctionReturn:
        // End of function, no successors
        break;

      default:
        // Fall through to next instruction/block
        if (IsValidCodeAddress(next_addr) && !visited.count(next_addr) &&
            !iter_state.lifted_blocks.count(next_addr)) {
          worklist.push(next_addr);
          visited.insert(next_addr);
        }
        break;
    }
  }
}

bool BlockDecoder::DiscoverBasicBlocks(
    uint64_t start_address, const uint8_t *bytes, size_t size,
    std::map<uint64_t, DecodedInstruction> &instructions,
    std::set<uint64_t> &block_starts) {

  // Function entry is always a block start
  block_starts.insert(start_address);

  uint64_t address = start_address;
  size_t offset = 0;

  while (offset < size) {
    std::string_view bytes_view(reinterpret_cast<const char *>(bytes + offset),
                                size - offset);

    DecodedInstruction decoded;
    decoded.address = address;

    if (!ctx_.GetArch()->DecodeInstruction(address, bytes_view, decoded.instr,
                                           decoding_context_)) {
      std::cerr << "Failed to decode instruction at 0x" << std::hex << address
                << std::dec << "\n";
      return false;
    }

    decoded.size = decoded.instr.bytes.size();
    instructions[address] = decoded;

    uint64_t next_addr = address + decoded.size;

    // Analyze control flow
    switch (decoded.instr.category) {
      case remill::Instruction::kCategoryConditionalBranch: {
        // Conditional branch: both target and fall-through are block starts
        if (auto *cond = std::get_if<remill::Instruction::ConditionalInstruction>(
                &decoded.instr.flows)) {
          if (auto *direct = std::get_if<remill::Instruction::DirectJump>(
                  &cond->taken_branch)) {
            uint64_t target = direct->taken_flow.known_target;
            if (target >= code_start_ && target < code_end_) {
              block_starts.insert(target);
            }
          }
          if (next_addr < code_end_) {
            block_starts.insert(next_addr);
          }
        }
        break;
      }

      case remill::Instruction::kCategoryDirectJump: {
        if (auto *jump = std::get_if<remill::Instruction::DirectJump>(
                &decoded.instr.flows)) {
          uint64_t target = jump->taken_flow.known_target;
          if (target >= code_start_ && target < code_end_) {
            block_starts.insert(target);
          }
        }
        break;
      }

      case remill::Instruction::kCategoryDirectFunctionCall: {
        uint64_t target = decoded.instr.branch_taken_pc;
        if (target >= code_start_ && target < code_end_) {
          block_starts.insert(target);
        }
        if (next_addr < code_end_) {
          block_starts.insert(next_addr);
        }
        break;
      }

      case remill::Instruction::kCategoryFunctionReturn:
        if (next_addr < code_end_) {
          block_starts.insert(next_addr);
        }
        break;

      default:
        break;
    }

    offset += decoded.size;
    address = next_addr;
  }

  std::cout << "Discovered " << block_starts.size() << " basic blocks\n";
  for (uint64_t addr : block_starts) {
    std::cout << "  Block at 0x" << std::hex << addr << std::dec << "\n";
  }

  return true;
}

}  // namespace lifting
