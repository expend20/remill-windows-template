#include "block_terminator.h"

#include <iostream>

#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/Format.h>
#include <remill/BC/Util.h>

#include "external_call_handler.h"
#include "lifting_context.h"
#include "utils/debug_flag.h"

namespace lifting {

BlockTerminator::BlockTerminator(LiftingContext &ctx,
                                 ExternalCallHandler *external_handler)
    : ctx_(ctx), external_handler_(external_handler) {}

uint64_t BlockTerminator::ExtractIndirectCallMemoryAddress(
    const remill::Instruction &instr) {
  // Look for an address operand that is a memory read (for indirect calls/jumps)
  for (const auto &op : instr.operands) {
    if (op.type == remill::Operand::kTypeAddress &&
        (op.addr.kind == remill::Operand::Address::kControlFlowTarget ||
         op.addr.kind == remill::Operand::Address::kMemoryRead)) {
      // For RIP-relative addressing: effective_addr = next_pc + displacement
      // For absolute addressing or register-based: can't compute statically
      // Remill uses NEXT_PC as the base register for RIP-relative addressing
      if (op.addr.base_reg.name == "RIP" || op.addr.base_reg.name == "PC" ||
          op.addr.base_reg.name == "NEXT_PC") {
        // RIP-relative: next_pc + displacement
        return instr.next_pc + op.addr.displacement;
      } else if (op.addr.base_reg.name.empty() &&
                 op.addr.index_reg.name.empty()) {
        // Absolute address (just displacement)
        return static_cast<uint64_t>(op.addr.displacement);
      }
      // Otherwise it's register-based and we can't compute statically
    }
  }
  return 0;
}

bool BlockTerminator::GenerateExternalCall(
    llvm::BasicBlock *block,
    const ExternalCallConfig *config,
    uint64_t next_addr,
    const std::map<uint64_t, llvm::BasicBlock *> &blocks,
    const std::map<uint64_t, uint64_t> &block_owner,
    uint64_t current_owner) {

  llvm::IRBuilder<> builder(block);
  auto *intrinsics = ctx_.GetIntrinsics();

  // Get the external function
  auto *ext_func = external_handler_->GetExternalFunction(config->name);
  if (!ext_func) {
    utils::dbg() << "External function not found: " << config->name << "\n";
    return false;
  }

  // Find STATE pointer in entry block
  llvm::Value *state_ptr = nullptr;
  for (auto &inst : block->getParent()->getEntryBlock()) {
    if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
      if (alloca->getName() == "STATE") {
        state_ptr = builder.CreateLoad(builder.getPtrTy(), alloca);
        break;
      }
    }
  }

  if (!state_ptr) {
    utils::dbg() << "STATE pointer not found for external call\n";
    return false;
  }

  // Load arguments from State registers (Win64: RCX, RDX, R8, R9)
  std::vector<llvm::Value *> args;

  // Win64 calling convention argument registers
  static const char *arg_regs[] = {"RCX", "RDX", "R8", "R9"};
  size_t num_args = std::min(config->arg_types.size(), size_t(4));

  for (size_t i = 0; i < num_args; ++i) {
    auto *reg = ctx_.GetRegister(arg_regs[i]);
    if (!reg) {
      utils::dbg() << "Register " << arg_regs[i] << " not found\n";
      continue;
    }

    // Get the register value from State
    auto reg_ptr = reg->AddressOf(state_ptr, block);
    auto *reg_val = builder.CreateLoad(builder.getInt64Ty(), reg_ptr);

    // Convert to the expected type
    const std::string &arg_type = config->arg_types[i];
    if (arg_type == "ptr") {
      // Convert i64 to ptr
      args.push_back(builder.CreateIntToPtr(reg_val, builder.getPtrTy()));
    } else if (arg_type == "i32") {
      args.push_back(builder.CreateTrunc(reg_val, builder.getInt32Ty()));
    } else {
      // Default: pass as i64
      args.push_back(reg_val);
    }
  }

  // Create the call
  auto *result = builder.CreateCall(ext_func, args);

  // Store result to RAX
  auto *rax_reg = ctx_.GetRegister("RAX");
  if (rax_reg) {
    auto rax_ptr = rax_reg->AddressOf(state_ptr, block);
    builder.CreateStore(result, rax_ptr);
  }

  // Continue to next block or return
  auto sameFunction = [&blocks, &block_owner, current_owner](uint64_t target_addr) -> bool {
    if (!blocks.count(target_addr)) return false;
    auto it = block_owner.find(target_addr);
    uint64_t target_owner = (it != block_owner.end()) ? it->second : 0;
    return target_owner == current_owner;
  };

  if (sameFunction(next_addr)) {
    builder.CreateBr(blocks.at(next_addr));
  } else {
    builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
  }

  utils::dbg() << "Generated external call to " << config->name
               << " with " << args.size() << " args\n";

  return true;
}

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
      // First, check if this is an external call (jmp through IAT - tail call)
      if (external_handler_) {
        uint64_t mem_addr = ExtractIndirectCallMemoryAddress(last_instr.instr);
        if (mem_addr != 0) {
          auto *ext_config = external_handler_->GetConfigByIATAddress(mem_addr);
          if (ext_config) {
            utils::dbg() << "Detected external tail call to " << ext_config->name
                         << " via IAT at " << llvm::format_hex(mem_addr, 0) << "\n";

            // For tail call, we generate the external call but return instead of continuing
            auto *ext_func = external_handler_->GetExternalFunction(ext_config->name);
            if (ext_func) {
              // Find STATE pointer
              llvm::Value *state_ptr = nullptr;
              for (auto &inst : block->getParent()->getEntryBlock()) {
                if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
                  if (alloca->getName() == "STATE") {
                    state_ptr = builder.CreateLoad(builder.getPtrTy(), alloca);
                    break;
                  }
                }
              }

              if (state_ptr) {
                // Load arguments from Win64 registers
                static const char *arg_regs[] = {"RCX", "RDX", "R8", "R9"};
                std::vector<llvm::Value *> args;
                size_t num_args = std::min(ext_config->arg_types.size(), size_t(4));

                for (size_t i = 0; i < num_args; ++i) {
                  auto *reg = ctx_.GetRegister(arg_regs[i]);
                  if (reg) {
                    auto reg_ptr = reg->AddressOf(state_ptr, block);
                    auto *reg_val = builder.CreateLoad(builder.getInt64Ty(), reg_ptr);
                    if (ext_config->arg_types[i] == "ptr") {
                      args.push_back(builder.CreateIntToPtr(reg_val, builder.getPtrTy()));
                    } else if (ext_config->arg_types[i] == "i32") {
                      args.push_back(builder.CreateTrunc(reg_val, builder.getInt32Ty()));
                    } else {
                      args.push_back(reg_val);
                    }
                  }
                }

                // Call external function
                auto *result = builder.CreateCall(ext_func, args);

                // Store result to RAX
                auto *rax_reg = ctx_.GetRegister("RAX");
                if (rax_reg) {
                  auto rax_ptr = rax_reg->AddressOf(state_ptr, block);
                  builder.CreateStore(result, rax_ptr);
                }

                // Tail call returns - load memory pointer from alloca
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
                  auto *mem_ptr = builder.CreateLoad(builder.getPtrTy(), memory_alloca);
                  builder.CreateRet(mem_ptr);
                } else {
                  builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
                }

                utils::dbg() << "Generated external tail call to " << ext_config->name
                             << " with " << args.size() << " args\n";
                break;  // Exit the switch
              }
            }
          }
        }
      }

      // Not an external call - use regular dispatch
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

    case remill::Instruction::kCategoryIndirectFunctionCall: {
      // Indirect function call: call *%rax or call *[mem]
      // First, check if this is an external call (call through IAT)
      if (external_handler_) {
        uint64_t mem_addr = ExtractIndirectCallMemoryAddress(last_instr.instr);
        if (mem_addr != 0) {
          auto *ext_config = external_handler_->GetConfigByIATAddress(mem_addr);
          if (ext_config) {
            utils::dbg() << "Detected external call to " << ext_config->name
                         << " via IAT at " << llvm::format_hex(mem_addr, 0) << "\n";
            if (GenerateExternalCall(block, ext_config, next_addr, blocks,
                                     block_owner, current_owner)) {
              break;  // External call generated successfully
            }
          }
        }
      }

      // Not an external call - use regular dispatch
      // The call semantics have already pushed the return address (next_addr) onto the stack
      // and set PC to the target. We need to dispatch to the target and handle returns.
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
              ctx_.GetContext(), "indirect_call_dispatch", block->getParent());
          builder.CreateBr(dispatch_block);

          llvm::IRBuilder<> dispatch_builder(dispatch_block);

          auto *default_block = llvm::BasicBlock::Create(
              ctx_.GetContext(), "indirect_call_default", block->getParent());
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

          utils::dbg() << "Created indirect call switch with " << targets.size()
                       << " known targets at " << llvm::format_hex(block_addr, 0)
                       << ", return to " << llvm::format_hex(next_addr, 0) << "\n";
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
