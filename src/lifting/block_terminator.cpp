#include "block_terminator.h"

#include <iostream>

#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/Format.h>
#include <remill/BC/Util.h>

#include "lifting_context.h"
#include "utils/debug_flag.h"

namespace lifting {

BlockTerminator::BlockTerminator(LiftingContext &ctx,
                                 const IterativeLiftingConfig &config)
    : ctx_(ctx), config_(config) {}

llvm::SwitchInst *BlockTerminator::FinishBlock(
    llvm::BasicBlock *block,
    const DecodedInstruction &last_instr,
    uint64_t next_addr,
    uint64_t block_addr,
    const std::map<uint64_t, llvm::BasicBlock *> &blocks,
    const std::map<uint64_t, uint64_t> &block_owner,
    const std::map<uint64_t, llvm::Function *> &helper_functions,
    IterativeLiftingState &iter_state,
    std::map<uint64_t, llvm::BasicBlock *> &dispatch_blocks) {

  llvm::IRBuilder<> builder(block);
  auto *intrinsics = ctx_.GetIntrinsics();

  // Get current owner
  uint64_t current_owner = 0;
  auto owner_it = block_owner.find(block_addr);
  if (owner_it != block_owner.end()) {
    current_owner = owner_it->second;
  }

  llvm::SwitchInst *result_switch = nullptr;

  // Helper to check if a target block is in the same function
  auto sameFunction = [&blocks, &block_owner, current_owner](uint64_t target_addr) -> bool {
    if (!blocks.count(target_addr)) return false;
    auto it = block_owner.find(target_addr);
    uint64_t target_owner = (it != block_owner.end()) ? it->second : 0;
    return target_owner == current_owner;
  };

  // Helper to get block at address
  auto getBlock = [&blocks](uint64_t addr) -> llvm::BasicBlock* {
    auto it = blocks.find(addr);
    return (it != blocks.end()) ? it->second : nullptr;
  };

  switch (last_instr.instr.category) {
    case remill::Instruction::kCategoryConditionalBranch: {
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

        // Only branch to blocks in the same function
        if (branch_taken && sameFunction(taken_addr) && sameFunction(next_addr)) {
          auto *cond_val = builder.CreateLoad(builder.getInt8Ty(), branch_taken);
          auto *cond_bool = builder.CreateICmpNE(
              cond_val, llvm::ConstantInt::get(builder.getInt8Ty(), 0));
          builder.CreateCondBr(cond_bool, getBlock(taken_addr), getBlock(next_addr));
        } else {
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    case remill::Instruction::kCategoryDirectJump: {
      if (auto *jump = std::get_if<remill::Instruction::DirectJump>(
              &last_instr.instr.flows)) {
        uint64_t target = jump->taken_flow.known_target;
        if (sameFunction(target)) {
          builder.CreateBr(getBlock(target));
        } else {
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    case remill::Instruction::kCategoryDirectFunctionCall: {
      uint64_t target = last_instr.instr.branch_taken_pc;

      auto helper_it = helper_functions.find(target);
      if (helper_it != helper_functions.end()) {
        auto *helper_func = helper_it->second;

        // Get current state and memory
        llvm::Value *state = nullptr;
        llvm::Value *memory = nullptr;
        llvm::AllocaInst *memory_alloca = nullptr;
        for (auto &inst : block->getParent()->getEntryBlock()) {
          if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
            if (alloca->getName() == "STATE") {
              state = builder.CreateLoad(builder.getPtrTy(), alloca);
            } else if (alloca->getName() == "MEMORY") {
              memory_alloca = alloca;
              memory = builder.CreateLoad(builder.getPtrTy(), alloca);
            }
          }
        }

        if (state && memory && memory_alloca) {
          auto *target_pc = builder.getInt64(target);
          auto *result = builder.CreateCall(helper_func, {state, target_pc, memory});
          builder.CreateStore(result, memory_alloca);

          if (sameFunction(next_addr)) {
            builder.CreateBr(getBlock(next_addr));
          } else {
            builder.CreateRet(result);
          }
        } else {
          if (sameFunction(next_addr)) {
            builder.CreateBr(getBlock(next_addr));
          } else {
            builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
          }
        }
      } else {
        if (sameFunction(next_addr)) {
          builder.CreateBr(getBlock(next_addr));
        } else {
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    case remill::Instruction::kCategoryFunctionReturn: {
      llvm::Value *target_pc = remill::LoadProgramCounter(block, *intrinsics);

      if (target_pc) {
        auto *dispatch_block = llvm::BasicBlock::Create(
            ctx_.GetContext(), "ret_dispatch", block->getParent());
        builder.CreateBr(dispatch_block);

        llvm::IRBuilder<> dispatch_builder(dispatch_block);

        auto *default_block = llvm::BasicBlock::Create(
            ctx_.GetContext(), "ret_default", block->getParent());
        llvm::IRBuilder<> default_builder(default_block);
        default_builder.CreateRet(remill::LoadMemoryPointer(default_block, *intrinsics));

        auto *sw = dispatch_builder.CreateSwitch(target_pc, default_block, 0);

        iter_state.unresolved_indirect_jumps[block_addr] = sw;

        utils::dbg() << "Created RET switch at " << llvm::format_hex(block_addr, 0)
                     << " (will be resolved by SCCP)\n";
      } else {
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      }
      break;
    }

    case remill::Instruction::kCategoryIndirectJump: {
      llvm::Value *target_pc = remill::LoadProgramCounter(block, *intrinsics);

      if (target_pc) {
        auto *entry_block = &block->getParent()->getEntryBlock();
        std::vector<std::pair<uint64_t, llvm::BasicBlock *>> targets;
        for (const auto &[addr, bb] : blocks) {
          if (sameFunction(addr) && bb != entry_block) {
            targets.push_back({addr, bb});
          }
        }

        llvm::AllocaInst *memory_alloca = nullptr;
        for (auto &inst : block->getParent()->getEntryBlock()) {
          if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
            if (alloca->getName() == "MEMORY") {
              memory_alloca = alloca;
              break;
            }
          }
        }

        if (memory_alloca) {
          auto *dispatch_block = llvm::BasicBlock::Create(
              ctx_.GetContext(), "indirect_jmp_dispatch", block->getParent());
          builder.CreateBr(dispatch_block);

          llvm::IRBuilder<> dispatch_builder(dispatch_block);

          auto *default_block = llvm::BasicBlock::Create(
              ctx_.GetContext(), "indirect_jmp_default", block->getParent());
          llvm::IRBuilder<> default_builder(default_block);
          auto *mem_ptr = default_builder.CreateLoad(default_builder.getPtrTy(), memory_alloca);
          default_builder.CreateRet(mem_ptr);

          auto *sw = dispatch_builder.CreateSwitch(target_pc, default_block, targets.size());
          for (const auto &[addr, bb] : targets) {
            sw->addCase(dispatch_builder.getInt64(addr), bb);
          }

          result_switch = sw;
          iter_state.unresolved_indirect_jumps[block_addr] = sw;
          dispatch_blocks[block_addr] = dispatch_block;

          utils::dbg() << "Created indirect jump switch with " << targets.size()
                       << " known targets\n";
        } else {
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      } else {
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      }
      break;
    }

    default:
      if (sameFunction(next_addr)) {
        builder.CreateBr(getBlock(next_addr));
      } else {
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      }
      break;
  }

  return result_switch;
}

}  // namespace lifting
