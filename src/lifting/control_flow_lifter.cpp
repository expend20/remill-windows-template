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
  call_site_indices_.clear();
  shadow_stack_ = nullptr;
  shadow_stack_sp_ = nullptr;

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
  uint32_t call_site_index = 0;
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

        // Assign a unique index to this call site for shadow stack dispatch
        call_site_indices_[return_addr] = call_site_index++;

        // Mark the target as a call target (its RET should dispatch)
        call_targets_.insert(target);
      }
    }
  }

  // Create shadow return stack allocas if we have internal calls
  if (!return_blocks_.empty()) {
    auto &context = ctx_.GetContext();
    llvm::IRBuilder<> builder(&func->getEntryBlock(),
                               func->getEntryBlock().begin());

    // Allocate shadow stack array [kMaxCallDepth x i32]
    auto *array_type = llvm::ArrayType::get(builder.getInt32Ty(), kMaxCallDepth);
    shadow_stack_ = builder.CreateAlloca(array_type, nullptr, "shadow_ret_stack");

    // Allocate stack pointer, initialize to 0
    shadow_stack_sp_ = builder.CreateAlloca(builder.getInt32Ty(), nullptr,
                                             "shadow_ret_sp");
    builder.CreateStore(builder.getInt32(0), shadow_stack_sp_);
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

      if (blocks_.count(target) && return_blocks_.count(next_addr) &&
          shadow_stack_ && shadow_stack_sp_) {
        // Internal call - push index to shadow stack before branching
        auto *ret_block = return_blocks_[next_addr];
        uint32_t call_idx = call_site_indices_[next_addr];

        // Push call site index to shadow stack:
        // sp = load shadow_stack_sp
        // shadow_stack[sp] = call_idx
        // shadow_stack_sp = sp + 1
        auto *sp = builder.CreateLoad(builder.getInt32Ty(), shadow_stack_sp_,
                                       "shadow_sp");
        auto *slot = builder.CreateInBoundsGEP(
            shadow_stack_->getAllocatedType(), shadow_stack_,
            {builder.getInt32(0), sp}, "shadow_slot");
        builder.CreateStore(builder.getInt32(call_idx), slot);
        auto *new_sp = builder.CreateAdd(sp, builder.getInt32(1), "shadow_sp_inc");
        builder.CreateStore(new_sp, shadow_stack_sp_);

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
      // Return from function using shadow stack dispatch
      // The shadow stack contains indices that map to continuation blocks.
      // This ensures proper LIFO call semantics even after LLVM optimization.

      if (return_blocks_.empty() || !shadow_stack_ || !shadow_stack_sp_) {
        // No internal callers - just return from LLVM function
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      } else {
        // Pop from shadow stack and dispatch:
        // sp = load shadow_stack_sp
        // new_sp = sp - 1
        // idx = load shadow_stack[new_sp]
        // shadow_stack_sp = new_sp
        // switch(idx) { ... }

        auto *sp = builder.CreateLoad(builder.getInt32Ty(), shadow_stack_sp_,
                                       "shadow_sp_ret");

        // Check if stack is empty (sp == 0) -> this is main's RET
        auto *is_empty = builder.CreateICmpEQ(sp, builder.getInt32(0),
                                               "shadow_stack_empty");

        // Create blocks for the conditional dispatch
        auto &context = ctx_.GetContext();
        auto *main_ret_block = llvm::BasicBlock::Create(
            context, "main_ret", block->getParent());
        auto *helper_ret_block = llvm::BasicBlock::Create(
            context, "helper_ret", block->getParent());

        builder.CreateCondBr(is_empty, main_ret_block, helper_ret_block);

        // Main return - return from LLVM function
        {
          llvm::IRBuilder<> main_builder(main_ret_block);
          main_builder.CreateRet(remill::LoadMemoryPointer(main_ret_block, *intrinsics));
        }

        // Helper return - pop index and dispatch
        {
          llvm::IRBuilder<> helper_builder(helper_ret_block);

          // Decrement stack pointer
          auto *new_sp = helper_builder.CreateSub(sp, helper_builder.getInt32(1),
                                                   "shadow_sp_dec");
          helper_builder.CreateStore(new_sp, shadow_stack_sp_);

          // Load the call site index
          auto *slot = helper_builder.CreateInBoundsGEP(
              shadow_stack_->getAllocatedType(), shadow_stack_,
              {helper_builder.getInt32(0), new_sp}, "shadow_slot_ret");
          auto *call_idx = helper_builder.CreateLoad(helper_builder.getInt32Ty(),
                                                      slot, "call_site_idx");

          // Create default block (shouldn't happen, but needed for switch)
          auto *unreachable_block = llvm::BasicBlock::Create(
              context, "unreachable_ret", block->getParent());
          llvm::IRBuilder<> unreachable_builder(unreachable_block);
          unreachable_builder.CreateUnreachable();

          // Create switch to dispatch based on call site index
          auto *switch_inst = helper_builder.CreateSwitch(
              call_idx, unreachable_block, return_blocks_.size());

          for (const auto &[addr, ret_block] : return_blocks_) {
            uint32_t idx = call_site_indices_[addr];
            switch_inst->addCase(helper_builder.getInt32(idx), ret_block);
          }
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
