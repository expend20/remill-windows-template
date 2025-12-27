#include "control_flow_lifter.h"

#include <iostream>
#include <queue>
#include <sstream>
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
  call_targets_.clear();
  helper_functions_.clear();
  block_owner_.clear();
  call_return_addrs_.clear();
  main_func_ = func;

  code_start_ = code_base;
  code_end_ = code_base + size;
  entry_point_ = entry_point;

  // First pass: decode all instructions and discover basic block boundaries
  if (!DiscoverBasicBlocks(code_base, bytes, size)) {
    return false;
  }

  // Ensure entry point is a block start
  block_starts_.insert(entry_point);

  // Identify call targets from the decoded instructions
  for (const auto &[addr, decoded] : instructions_) {
    if (decoded.instr.category == remill::Instruction::kCategoryDirectFunctionCall) {
      uint64_t target = decoded.instr.branch_taken_pc;
      uint64_t return_addr = addr + decoded.size;
      if (block_starts_.count(target) && block_starts_.count(return_addr)) {
        // Internal call - mark target as a helper function entry
        call_targets_.insert(target);
        call_return_addrs_[addr] = return_addr;
      }
    }
  }

  // Determine which blocks belong to which native function
  AssignBlocksToFunctions();

  // Create helper functions for call targets
  CreateHelperFunctions(func);

  // Create LLVM basic blocks for main function
  CreateBasicBlocks(func);

  // Lift instructions into their respective blocks
  if (!LiftBlocks(bytes, size, code_base)) {
    return false;
  }

  return true;
}

void ControlFlowLifter::AssignBlocksToFunctions() {
  // Use BFS to determine which blocks belong to which function
  // Main function: blocks reachable from entry_point_ without entering call_targets_
  // Helper function: blocks reachable from a call_target_ entry

  // First, assign all blocks to main function (owner = 0)
  for (uint64_t addr : block_starts_) {
    block_owner_[addr] = 0;
  }

  // For each call target, find blocks reachable from it
  for (uint64_t helper_entry : call_targets_) {
    std::queue<uint64_t> worklist;
    std::set<uint64_t> visited;

    worklist.push(helper_entry);
    visited.insert(helper_entry);

    while (!worklist.empty()) {
      uint64_t block_addr = worklist.front();
      worklist.pop();

      // This block belongs to the helper function
      block_owner_[block_addr] = helper_entry;

      // Find successors of this block
      // Look at the last instruction to determine control flow
      auto it = block_starts_.find(block_addr);
      auto next_it = std::next(it);
      uint64_t block_end = (next_it != block_starts_.end()) ? *next_it : code_end_;

      // Find the last instruction in this block
      uint64_t last_addr = block_addr;
      for (auto &[addr, decoded] : instructions_) {
        if (addr >= block_addr && addr < block_end) {
          if (decoded.instr.IsControlFlow()) {
            last_addr = addr;
            break;
          }
          last_addr = addr;
        }
      }

      auto instr_it = instructions_.find(last_addr);
      if (instr_it == instructions_.end()) continue;

      const auto &decoded = instr_it->second;
      uint64_t next_addr = last_addr + decoded.size;

      switch (decoded.instr.category) {
        case remill::Instruction::kCategoryConditionalBranch: {
          // Add both targets
          if (auto *cond = std::get_if<remill::Instruction::ConditionalInstruction>(
                  &decoded.instr.flows)) {
            if (auto *direct = std::get_if<remill::Instruction::DirectJump>(
                    &cond->taken_branch)) {
              uint64_t target = direct->taken_flow.known_target;
              if (block_starts_.count(target) && !visited.count(target) &&
                  !call_targets_.count(target)) {
                worklist.push(target);
                visited.insert(target);
              }
            }
          }
          if (block_starts_.count(next_addr) && !visited.count(next_addr) &&
              !call_targets_.count(next_addr)) {
            worklist.push(next_addr);
            visited.insert(next_addr);
          }
          break;
        }

        case remill::Instruction::kCategoryDirectJump: {
          if (auto *jump = std::get_if<remill::Instruction::DirectJump>(
                  &decoded.instr.flows)) {
            uint64_t target = jump->taken_flow.known_target;
            if (block_starts_.count(target) && !visited.count(target) &&
                !call_targets_.count(target)) {
              worklist.push(target);
              visited.insert(target);
            }
          }
          break;
        }

        case remill::Instruction::kCategoryDirectFunctionCall: {
          // Don't follow calls - they go to other functions
          // But the return address continues in this function
          if (block_starts_.count(next_addr) && !visited.count(next_addr) &&
              !call_targets_.count(next_addr)) {
            worklist.push(next_addr);
            visited.insert(next_addr);
          }
          break;
        }

        case remill::Instruction::kCategoryFunctionReturn:
          // RET ends the function, don't follow
          break;

        default:
          // Fall through to next block
          if (block_starts_.count(next_addr) && !visited.count(next_addr) &&
              !call_targets_.count(next_addr)) {
            worklist.push(next_addr);
            visited.insert(next_addr);
          }
          break;
      }
    }
  }

  // Debug output
  std::cout << "Block ownership:\n";
  for (const auto &[addr, owner] : block_owner_) {
    if (owner == 0) {
      std::cout << "  0x" << std::hex << addr << " -> main\n";
    } else {
      std::cout << "  0x" << std::hex << addr << " -> helper_0x" << owner << "\n";
    }
  }
  std::cout << std::dec;
}

void ControlFlowLifter::CreateHelperFunctions(llvm::Function *main_func) {
  auto *module = main_func->getParent();

  // Helper functions have the same signature as the main lifted function:
  // ptr @helper(ptr %state, i64 %pc, ptr %memory)
  auto *func_type = main_func->getFunctionType();

  for (uint64_t helper_entry : call_targets_) {
    std::stringstream ss;
    ss << "helper_" << std::hex << helper_entry;
    std::string name = ss.str();
    auto *helper_func = llvm::Function::Create(
        func_type,
        llvm::GlobalValue::InternalLinkage,
        name,
        module);

    // Copy argument names from main function
    auto main_args = main_func->arg_begin();
    auto helper_args = helper_func->arg_begin();
    for (; main_args != main_func->arg_end(); ++main_args, ++helper_args) {
      helper_args->setName(main_args->getName());
    }

    // Set attributes for inlining
    helper_func->addFnAttr(llvm::Attribute::AlwaysInline);
    helper_func->addFnAttr(llvm::Attribute::NoUnwind);
    helper_func->removeFnAttr(llvm::Attribute::NoInline);

    helper_functions_[helper_entry] = helper_func;

    std::cout << "Created helper function: " << name << " (alwaysinline)\n";
  }
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

  // Create blocks for main function and helper functions
  for (uint64_t addr : block_starts_) {
    uint64_t owner = block_owner_[addr];
    llvm::Function *target_func = (owner == 0) ? func : helper_functions_[owner];

    if (!target_func) {
      std::cerr << "Warning: no function for block 0x" << std::hex << addr
                << " (owner 0x" << owner << ")\n" << std::dec;
      continue;
    }

    std::string name = "bb_" + std::to_string(addr);

    // Check if this is the entry point of the function
    bool is_entry = (owner == 0 && addr == entry_point_) ||
                    (owner != 0 && addr == owner);

    if (is_entry && !target_func->empty()) {
      // Use existing entry block
      auto *entry = &target_func->getEntryBlock();
      entry->setName(name);
      blocks_[addr] = entry;
    } else if (is_entry) {
      // Create entry block
      auto *block = llvm::BasicBlock::Create(context, name, target_func);
      blocks_[addr] = block;
    } else {
      auto *block = llvm::BasicBlock::Create(context, name, target_func);
      blocks_[addr] = block;
    }
  }

  // Initialize helper functions with required allocas
  for (auto &[helper_entry, helper_func] : helper_functions_) {
    if (helper_func->empty()) {
      // Create entry block if it doesn't exist
      auto *entry = llvm::BasicBlock::Create(context, "entry", helper_func);
      blocks_[helper_entry] = entry;
    }

    // Add required allocas to helper function entry
    llvm::IRBuilder<> builder(&helper_func->getEntryBlock(),
                               helper_func->getEntryBlock().begin());

    // BRANCH_TAKEN
    builder.CreateAlloca(builder.getInt8Ty(), nullptr, "BRANCH_TAKEN");

    // RETURN_PC
    builder.CreateAlloca(builder.getInt64Ty(), nullptr, "RETURN_PC");

    // MONITOR
    auto *monitor = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "MONITOR");
    builder.CreateStore(builder.getInt64(0), monitor);

    // STATE - store the state pointer argument
    auto *state_alloca = builder.CreateAlloca(builder.getPtrTy(), nullptr, "STATE");
    builder.CreateStore(helper_func->getArg(0), state_alloca);

    // MEMORY - store the memory pointer argument
    auto *memory_alloca = builder.CreateAlloca(builder.getPtrTy(), nullptr, "MEMORY");
    builder.CreateStore(helper_func->getArg(2), memory_alloca);

    // NEXT_PC - store the PC argument
    auto *next_pc = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "NEXT_PC");
    builder.CreateStore(helper_func->getArg(1), next_pc);

    // PC register is updated by instruction lifter

    // Segment bases (required by some instructions)
    auto *csbase = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "CSBASE");
    builder.CreateStore(builder.getInt64(0), csbase);
    auto *ssbase = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "SSBASE");
    builder.CreateStore(builder.getInt64(0), ssbase);
    auto *esbase = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "ESBASE");
    builder.CreateStore(builder.getInt64(0), esbase);
    auto *dsbase = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "DSBASE");
    builder.CreateStore(builder.getInt64(0), dsbase);
  }
}

bool ControlFlowLifter::LiftBlocks(const uint8_t *bytes, size_t size,
                                    uint64_t code_base) {
  // Iterate through each basic block
  for (auto it = block_starts_.begin(); it != block_starts_.end(); ++it) {
    uint64_t block_addr = *it;

    if (!blocks_.count(block_addr)) {
      std::cerr << "Warning: no LLVM block for address 0x" << std::hex
                << block_addr << std::dec << "\n";
      continue;
    }

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
  uint64_t current_owner = block_owner_[block_addr];

  // Helper to check if a target block is in the same function
  auto sameFunction = [this, current_owner](uint64_t target_addr) -> bool {
    if (!blocks_.count(target_addr)) return false;
    return block_owner_[target_addr] == current_owner;
  };

  switch (last_instr.instr.category) {
    case remill::Instruction::kCategoryConditionalBranch: {
      // Get the condition from BRANCH_TAKEN
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
        // Only branch to blocks in the same function
        if (sameFunction(target)) {
          builder.CreateBr(blocks_[target]);
        } else {
          // Jump outside the function - return
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    case remill::Instruction::kCategoryDirectFunctionCall: {
      // Direct function call - use LLVM call to helper function
      uint64_t target = last_instr.instr.branch_taken_pc;

      if (helper_functions_.count(target)) {
        // Internal call to helper function
        auto *helper_func = helper_functions_[target];

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
          // Call the helper function with target PC
          auto *target_pc = builder.getInt64(target);
          auto *result = builder.CreateCall(helper_func, {state, target_pc, memory});

          // Store the returned memory pointer
          builder.CreateStore(result, memory_alloca);

          // Continue to the return address block (must be in same function)
          if (sameFunction(next_addr)) {
            builder.CreateBr(blocks_[next_addr]);
          } else {
            builder.CreateRet(result);
          }
        } else {
          // Fallback
          if (sameFunction(next_addr)) {
            builder.CreateBr(blocks_[next_addr]);
          } else {
            builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
          }
        }
      } else {
        // External call - just continue to next instruction
        if (sameFunction(next_addr)) {
          builder.CreateBr(blocks_[next_addr]);
        } else {
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      }
      break;
    }

    case remill::Instruction::kCategoryFunctionReturn: {
      // Return from function - use LLVM ret
      // This returns the memory pointer
      builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      break;
    }

    case remill::Instruction::kCategoryIndirectJump: {
      // Indirect jump (e.g., jmp rax) - emit a switch over all possible targets
      // After SCCP runs, the switch selector becomes a constant and SimplifyCFG
      // will eliminate dead cases, leaving a direct branch.

      // Get NEXT_PC which contains the jump target (set by the JMP instruction)
      llvm::AllocaInst *next_pc_alloca = nullptr;
      for (auto &inst : block->getParent()->getEntryBlock()) {
        if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
          if (alloca->getName() == "NEXT_PC") {
            next_pc_alloca = alloca;
            break;
          }
        }
      }

      if (next_pc_alloca) {
        auto *target_pc = builder.CreateLoad(builder.getInt64Ty(), next_pc_alloca);

        // Collect all blocks in the same function, excluding the entry block
        // (to avoid creating back edges that confuse LLVM's loop analysis)
        auto *entry_block = &block->getParent()->getEntryBlock();
        std::vector<std::pair<uint64_t, llvm::BasicBlock *>> targets;
        for (const auto &[addr, bb] : blocks_) {
          if (sameFunction(addr) && bb != entry_block) {
            targets.push_back({addr, bb});
          }
        }

        // Find the MEMORY alloca for the return value
        llvm::AllocaInst *memory_alloca = nullptr;
        for (auto &inst : block->getParent()->getEntryBlock()) {
          if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
            if (alloca->getName() == "MEMORY") {
              memory_alloca = alloca;
              break;
            }
          }
        }

        if (!targets.empty() && memory_alloca) {
          // Create a dispatch block to hold the switch
          // This avoids issues with back edges to the entry block
          auto *dispatch_block = llvm::BasicBlock::Create(
              ctx_.GetContext(), "indirect_jmp_dispatch", block->getParent());
          builder.CreateBr(dispatch_block);

          llvm::IRBuilder<> dispatch_builder(dispatch_block);

          // Create switch with default case returning (for truly unknown targets)
          auto *default_block = llvm::BasicBlock::Create(
              ctx_.GetContext(), "indirect_jmp_default", block->getParent());
          llvm::IRBuilder<> default_builder(default_block);
          auto *mem_ptr = default_builder.CreateLoad(default_builder.getPtrTy(), memory_alloca);
          default_builder.CreateRet(mem_ptr);

          auto *sw = dispatch_builder.CreateSwitch(target_pc, default_block, targets.size());
          for (const auto &[addr, bb] : targets) {
            sw->addCase(dispatch_builder.getInt64(addr), bb);
          }

          std::cout << "Created indirect jump switch with " << targets.size()
                    << " possible targets\n";
        } else {
          // No known targets or missing MEMORY alloca, just return
          builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
        }
      } else {
        // Fallback: just return
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      }
      break;
    }

    default:
      // Normal instruction - fall through to next block or return
      if (sameFunction(next_addr)) {
        builder.CreateBr(blocks_[next_addr]);
      } else {
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      }
      break;
  }
}

}  // namespace lifting
