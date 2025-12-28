#include "function_splitter.h"

#include <iostream>
#include <queue>
#include <sstream>

#include <llvm/IR/Attributes.h>

namespace lifting {

void FunctionSplitter::AssignBlocksToFunctions(
    const std::set<uint64_t> &block_starts,
    const std::set<uint64_t> &call_targets,
    const std::map<uint64_t, DecodedInstruction> &instructions,
    uint64_t entry_point,
    uint64_t code_end,
    std::map<uint64_t, uint64_t> &block_owner) {

  // First, assign all blocks to main function (owner = 0)
  for (uint64_t addr : block_starts) {
    block_owner[addr] = 0;
  }

  // For each call target, find blocks reachable from it
  for (uint64_t helper_entry : call_targets) {
    std::queue<uint64_t> worklist;
    std::set<uint64_t> visited;

    worklist.push(helper_entry);
    visited.insert(helper_entry);

    while (!worklist.empty()) {
      uint64_t block_addr = worklist.front();
      worklist.pop();

      // This block belongs to the helper function
      block_owner[block_addr] = helper_entry;

      // Find successors of this block
      auto it = block_starts.find(block_addr);
      auto next_it = std::next(it);
      uint64_t block_end = (next_it != block_starts.end()) ? *next_it : code_end;

      // Find the last instruction in this block
      uint64_t last_addr = block_addr;
      for (auto &[addr, decoded] : instructions) {
        if (addr >= block_addr && addr < block_end) {
          if (decoded.instr.IsControlFlow()) {
            last_addr = addr;
            break;
          }
          last_addr = addr;
        }
      }

      auto instr_it = instructions.find(last_addr);
      if (instr_it == instructions.end()) continue;

      const auto &decoded = instr_it->second;
      uint64_t next_addr = last_addr + decoded.size;

      switch (decoded.instr.category) {
        case remill::Instruction::kCategoryConditionalBranch: {
          if (auto *cond = std::get_if<remill::Instruction::ConditionalInstruction>(
                  &decoded.instr.flows)) {
            if (auto *direct = std::get_if<remill::Instruction::DirectJump>(
                    &cond->taken_branch)) {
              uint64_t target = direct->taken_flow.known_target;
              if (block_starts.count(target) && !visited.count(target) &&
                  !call_targets.count(target)) {
                worklist.push(target);
                visited.insert(target);
              }
            }
          }
          if (block_starts.count(next_addr) && !visited.count(next_addr) &&
              !call_targets.count(next_addr)) {
            worklist.push(next_addr);
            visited.insert(next_addr);
          }
          break;
        }

        case remill::Instruction::kCategoryDirectJump: {
          if (auto *jump = std::get_if<remill::Instruction::DirectJump>(
                  &decoded.instr.flows)) {
            uint64_t target = jump->taken_flow.known_target;
            if (block_starts.count(target) && !visited.count(target) &&
                !call_targets.count(target)) {
              worklist.push(target);
              visited.insert(target);
            }
          }
          break;
        }

        case remill::Instruction::kCategoryDirectFunctionCall: {
          // Don't follow calls - they go to other functions
          // But the return address continues in this function
          if (block_starts.count(next_addr) && !visited.count(next_addr) &&
              !call_targets.count(next_addr)) {
            worklist.push(next_addr);
            visited.insert(next_addr);
          }
          break;
        }

        case remill::Instruction::kCategoryFunctionReturn:
          // RET ends the function, don't follow
          break;

        default:
          if (block_starts.count(next_addr) && !visited.count(next_addr) &&
              !call_targets.count(next_addr)) {
            worklist.push(next_addr);
            visited.insert(next_addr);
          }
          break;
      }
    }
  }

  // Debug output
  std::cout << "Block ownership:\n";
  for (const auto &[addr, owner] : block_owner) {
    if (owner == 0) {
      std::cout << "  0x" << std::hex << addr << " -> main\n";
    } else {
      std::cout << "  0x" << std::hex << addr << " -> helper_0x" << owner << "\n";
    }
  }
  std::cout << std::dec;
}

void FunctionSplitter::CreateHelperFunctions(
    llvm::Function *main_func,
    const std::set<uint64_t> &call_targets,
    std::map<uint64_t, llvm::Function *> &helper_functions) {

  auto *module = main_func->getParent();
  auto *func_type = main_func->getFunctionType();

  for (uint64_t helper_entry : call_targets) {
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

    helper_functions[helper_entry] = helper_func;

    std::cout << "Created helper function: " << name << " (alwaysinline)\n";
  }
}

}  // namespace lifting
