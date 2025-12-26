#include "control_flow_lifter.h"

#include <iostream>
#include <variant>

#include <llvm/IR/IRBuilder.h>
#include <remill/BC/Util.h>

namespace lifting {

ControlFlowLifter::ControlFlowLifter(LiftingContext &ctx)
    : ctx_(ctx), decoding_context_(ctx.GetArch()->CreateInitialContext()) {}

bool ControlFlowLifter::LiftFunction(uint64_t code_base, uint64_t entry_point,
                                      const uint8_t *bytes, size_t size,
                                      llvm::Function *func) {
  // Clear state from any previous lifts
  instructions_.clear();
  block_starts_.clear();
  blocks_.clear();
  return_blocks_.clear();
  call_targets_.clear();

  code_start_ = code_base;
  code_end_ = code_base + size;
  entry_point_ = entry_point;

  // First pass: decode all instructions and discover basic block boundaries
  if (!DiscoverBasicBlocks(code_base, bytes, size)) {
    return false;
  }

  // Ensure entry point is a block start
  block_starts_.insert(entry_point);

  // Create LLVM basic blocks
  CreateBasicBlocks(func);

  // Pre-create return continuation blocks for all internal calls
  // This needs to happen before LiftBlocks so RET can use them
  for (const auto &[addr, decoded] : instructions_) {
    if (decoded.instr.category == remill::Instruction::kCategoryDirectFunctionCall) {
      uint64_t target = decoded.instr.branch_taken_pc;
      uint64_t return_addr = addr + decoded.size;
      if (blocks_.count(target) && blocks_.count(return_addr)) {
        // Internal call - create return continuation block
        auto &context = ctx_.GetContext();
        std::string name = "ret_" + std::to_string(return_addr);
        auto *ret_block = llvm::BasicBlock::Create(context, name, func);
        return_blocks_[return_addr] = ret_block;

        // Mark the target as a call target (its RET should dispatch)
        call_targets_.insert(target);
      }
    }
  }

  // Lift instructions into their respective blocks
  if (!LiftBlocks(bytes, size, code_base)) {
    return false;
  }

  return true;
}

bool ControlFlowLifter::DiscoverBasicBlocks(uint64_t start_address,
                                             const uint8_t *bytes,
                                             size_t size) {
  // Function entry is always a block start
  block_starts_.insert(start_address);

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
    instructions_[address] = decoded;

    uint64_t next_addr = address + decoded.size;

    // Analyze control flow
    switch (decoded.instr.category) {
      case remill::Instruction::kCategoryConditionalBranch: {
        // Conditional branch: both target and fall-through are block starts
        if (auto *cond = std::get_if<remill::Instruction::ConditionalInstruction>(
                &decoded.instr.flows)) {
          // Get the taken branch target
          if (auto *direct = std::get_if<remill::Instruction::DirectJump>(
                  &cond->taken_branch)) {
            uint64_t target = direct->taken_flow.known_target;
            if (target >= code_start_ && target < code_end_) {
              block_starts_.insert(target);
            }
          }
          // Fall-through is also a block start
          if (next_addr < code_end_) {
            block_starts_.insert(next_addr);
          }
        }
        break;
      }

      case remill::Instruction::kCategoryDirectJump: {
        // Unconditional jump: target is a block start
        if (auto *jump = std::get_if<remill::Instruction::DirectJump>(
                &decoded.instr.flows)) {
          uint64_t target = jump->taken_flow.known_target;
          if (target >= code_start_ && target < code_end_) {
            block_starts_.insert(target);
          }
        }
        break;
      }

      case remill::Instruction::kCategoryDirectFunctionCall: {
        // Direct function call: target and return address are block starts
        uint64_t target = decoded.instr.branch_taken_pc;
        if (target >= code_start_ && target < code_end_) {
          block_starts_.insert(target);
        }
        // Fall-through (return address) is also a block start
        if (next_addr < code_end_) {
          block_starts_.insert(next_addr);
        }
        break;
      }

      case remill::Instruction::kCategoryFunctionReturn:
        // Return ends the block, next instruction (if any) starts a new block
        if (next_addr < code_end_) {
          block_starts_.insert(next_addr);
        }
        break;

      default:
        break;
    }

    offset += decoded.size;
    address = next_addr;
  }

  std::cout << "Discovered " << block_starts_.size() << " basic blocks\n";
  for (uint64_t addr : block_starts_) {
    std::cout << "  Block at 0x" << std::hex << addr << std::dec << "\n";
  }

  return true;
}

void ControlFlowLifter::CreateBasicBlocks(llvm::Function *func) {
  auto &context = ctx_.GetContext();

  // The function already has an entry block with allocas from DefineLiftedFunction
  // Use it for the entry point block
  for (uint64_t addr : block_starts_) {
    if (addr == entry_point_) {
      // Use the existing entry block for the entry point
      auto *entry = &func->getEntryBlock();
      entry->setName("bb_" + std::to_string(addr));
      blocks_[addr] = entry;
    } else {
      std::string name = "bb_" + std::to_string(addr);
      auto *block = llvm::BasicBlock::Create(context, name, func);
      blocks_[addr] = block;
    }
  }
}

bool ControlFlowLifter::LiftBlocks(const uint8_t *bytes, size_t size,
                                    uint64_t code_base) {
  // Iterate through each basic block
  for (auto it = block_starts_.begin(); it != block_starts_.end(); ++it) {
    uint64_t block_addr = *it;
    llvm::BasicBlock *block = blocks_[block_addr];

    // Find the end of this block (start of next block or end of code)
    auto next_it = std::next(it);
    uint64_t block_end = (next_it != block_starts_.end()) ? *next_it : code_end_;

    // Lift all instructions in this block
    uint64_t addr = block_addr;
    DecodedInstruction *last_instr = nullptr;

    while (addr < block_end) {
      auto instr_it = instructions_.find(addr);
      if (instr_it == instructions_.end()) {
        std::cerr << "Missing instruction at 0x" << std::hex << addr
                  << std::dec << "\n";
        return false;
      }

      auto &decoded = instr_it->second;
      last_instr = &decoded;

      // Lift the instruction
      auto lifter = decoded.instr.GetLifter();
      auto status = lifter->LiftIntoBlock(decoded.instr, block);
      if (status != remill::kLiftedInstruction) {
        std::cerr << "Failed to lift instruction: " << decoded.instr.Serialize()
                  << "\n";
        return false;
      }

      addr += decoded.size;

      // Check if this instruction ends the block early (control flow)
      if (decoded.instr.IsControlFlow()) {
        break;
      }
    }

    // Finish the block with appropriate terminator
    if (last_instr) {
      FinishBlock(block, *last_instr, addr, block_addr);
    }
  }

  return true;
}

void ControlFlowLifter::FinishBlock(llvm::BasicBlock *block,
                                     const DecodedInstruction &last_instr,
                                     uint64_t next_addr, uint64_t block_addr) {
  llvm::IRBuilder<> builder(block);
  auto *intrinsics = ctx_.GetIntrinsics();

  switch (last_instr.instr.category) {
    case remill::Instruction::kCategoryConditionalBranch: {
      // Get the condition from BRANCH_TAKEN
      // After lifting, the lifted code sets a BRANCH_TAKEN variable
      // We need to read the condition and create a conditional branch

      if (auto *cond = std::get_if<remill::Instruction::ConditionalInstruction>(
              &last_instr.instr.flows)) {
        uint64_t taken_addr = 0;
        if (auto *direct = std::get_if<remill::Instruction::DirectJump>(
                &cond->taken_branch)) {
          taken_addr = direct->taken_flow.known_target;
        }

        // Find the BRANCH_TAKEN alloca in the function
        llvm::AllocaInst *branch_taken = nullptr;
        for (auto &inst : block->getParent()->getEntryBlock()) {
          if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
            if (alloca->getName() == "BRANCH_TAKEN") {
              branch_taken = alloca;
              break;
            }
          }
        }

        if (branch_taken && blocks_.count(taken_addr) && blocks_.count(next_addr)) {
          // Load the condition and create conditional branch
          auto *cond_val = builder.CreateLoad(builder.getInt8Ty(), branch_taken);
          auto *cond_bool = builder.CreateICmpNE(
              cond_val, llvm::ConstantInt::get(builder.getInt8Ty(), 0));
          builder.CreateCondBr(cond_bool, blocks_[taken_addr], blocks_[next_addr]);
        } else {
          // Fallback: just return
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    case remill::Instruction::kCategoryDirectJump: {
      // Unconditional jump
      if (auto *jump = std::get_if<remill::Instruction::DirectJump>(
              &last_instr.instr.flows)) {
        uint64_t target = jump->taken_flow.known_target;
        if (blocks_.count(target)) {
          builder.CreateBr(blocks_[target]);
        } else {
          // Jump outside the function - return
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    case remill::Instruction::kCategoryDirectFunctionCall: {
      // Direct function call - branch to target and set up return
      uint64_t target = last_instr.instr.branch_taken_pc;

      if (blocks_.count(target) && return_blocks_.count(next_addr)) {
        // Internal call - branch to target block
        // Use the pre-created continuation block
        auto *ret_block = return_blocks_[next_addr];

        // Branch to call target
        builder.CreateBr(blocks_[target]);

        // Fill in the continuation block - branch to the code after the call
        llvm::IRBuilder<> ret_builder(ret_block);
        if (blocks_.count(next_addr)) {
          ret_builder.CreateBr(blocks_[next_addr]);
        } else {
          ret_builder.CreateRet(remill::LoadMemoryPointer(ret_block, *intrinsics));
        }
      } else {
        // External call - just continue to next instruction
        if (blocks_.count(next_addr)) {
          builder.CreateBr(blocks_[next_addr]);
        } else {
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    case remill::Instruction::kCategoryFunctionReturn: {
      // Return from function
      // Only dispatch if this block is part of a called helper function
      // A block is a helper if:
      // 1. It's a call target entry point, OR
      // 2. It's before the main entry point (helpers typically come first)
      bool is_helper = call_targets_.count(block_addr) || block_addr < entry_point_;

      if (return_blocks_.empty() || !is_helper) {
        // No internal callers OR this is main's RET - just return from LLVM function
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      } else {
        // Dispatch based on return address stored in NEXT_PC by RET semantic
        // Find the NEXT_PC alloca
        llvm::AllocaInst *next_pc = nullptr;
        for (auto &inst : block->getParent()->getEntryBlock()) {
          if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
            if (alloca->getName() == "NEXT_PC") {
              next_pc = alloca;
              break;
            }
          }
        }

        if (next_pc) {
          // Load the return address from NEXT_PC (set by RET semantic)
          auto *ret_addr = builder.CreateLoad(builder.getInt64Ty(), next_pc);

          // Create default block that returns from LLVM function
          // This handles main function's RET (with invalid return address)
          auto &context = ctx_.GetContext();
          auto *default_block = llvm::BasicBlock::Create(
              context, "ret_default", block->getParent());
          llvm::IRBuilder<> default_builder(default_block);
          default_builder.CreateRet(remill::LoadMemoryPointer(default_block, *intrinsics));

          // Create switch to dispatch to known return addresses
          auto *switch_inst = builder.CreateSwitch(
              ret_addr, default_block, return_blocks_.size());

          for (const auto &[addr, ret_block] : return_blocks_) {
            switch_inst->addCase(
                llvm::ConstantInt::get(builder.getInt64Ty(), addr),
                ret_block);
          }
        } else {
          // Fallback - just return
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    default:
      // Normal instruction - fall through to next block or return
      if (blocks_.count(next_addr)) {
        builder.CreateBr(blocks_[next_addr]);
      } else {
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      }
      break;
  }
}

}  // namespace lifting
