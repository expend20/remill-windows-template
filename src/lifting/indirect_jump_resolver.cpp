#include "indirect_jump_resolver.h"

#include <iostream>

#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Format.h>
#include <llvm/Transforms/IPO/ModuleInliner.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include "control_flow_lifter.h"
#include "optimization/optimizer.h"
#include "utils/debug_flag.h"

namespace lifting {

IndirectJumpResolver::IndirectJumpResolver(const IterativeLiftingConfig &config,
                                           const utils::PEInfo *pe_info)
    : config_(config), pe_info_(pe_info) {}

std::optional<uint64_t> IndirectJumpResolver::EvaluateBinaryOp(
    llvm::Instruction::BinaryOps opcode, uint64_t lhs, uint64_t rhs) {
  switch (opcode) {
    case llvm::Instruction::Add:
      return lhs + rhs;
    case llvm::Instruction::Sub:
      return lhs - rhs;
    case llvm::Instruction::Mul:
      return lhs * rhs;
    case llvm::Instruction::And:
      return lhs & rhs;
    case llvm::Instruction::Or:
      return lhs | rhs;
    case llvm::Instruction::Xor:
      return lhs ^ rhs;
    case llvm::Instruction::Shl:
      return lhs << rhs;
    case llvm::Instruction::LShr:
      return lhs >> rhs;
    default:
      return std::nullopt;
  }
}

std::optional<uint64_t> IndirectJumpResolver::ReadQwordFromPESections(
    uint64_t masked_offset) const {
  if (!pe_info_) {
    return std::nullopt;
  }

  for (const auto &section : pe_info_->sections) {
    uint64_t section_va = pe_info_->image_base + section.virtual_address;
    uint64_t masked_base = section_va & 0xFFFFF;

    if (masked_offset >= masked_base &&
        masked_offset < masked_base + section.bytes.size()) {
      size_t section_offset = masked_offset - masked_base;
      if (section_offset + 8 <= section.bytes.size()) {
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
          value |= static_cast<uint64_t>(section.bytes[section_offset + i])
                   << (i * 8);
        }
        return value;
      }
    }
  }
  return std::nullopt;
}

std::optional<int64_t> IndirectJumpResolver::EvaluateWithKnownPC(
    llvm::Value *val, uint64_t entry_point) {
  // Base case: constant integer
  if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(val)) {
    return ci->getSExtValue();
  }

  // Base case: program_counter argument (arg 1)
  if (auto *arg = llvm::dyn_cast<llvm::Argument>(val)) {
    if (arg->getArgNo() == 1) {
      return static_cast<int64_t>(entry_point);
    }
    return std::nullopt;
  }

  // Binary operation: try to evaluate both operands
  if (auto *binop = llvm::dyn_cast<llvm::BinaryOperator>(val)) {
    auto lhs = EvaluateWithKnownPC(binop->getOperand(0), entry_point);
    auto rhs = EvaluateWithKnownPC(binop->getOperand(1), entry_point);
    if (!lhs || !rhs) {
      return std::nullopt;
    }

    switch (binop->getOpcode()) {
      case llvm::Instruction::Add:
        return *lhs + *rhs;
      case llvm::Instruction::Sub:
        return *lhs - *rhs;
      case llvm::Instruction::Mul:
        return *lhs * *rhs;
      default:
        return std::nullopt;
    }
  }

  // Load from alloca: try to find the stored value
  if (auto *load = llvm::dyn_cast<llvm::LoadInst>(val)) {
    auto *ptr = load->getPointerOperand();

    // Look for the most recent store to this pointer before the load
    llvm::BasicBlock *bb = load->getParent();
    llvm::Value *stored_val = nullptr;

    // Scan backwards from the load to find the store
    for (auto it = llvm::BasicBlock::reverse_iterator(load->getIterator());
         it != bb->rend(); ++it) {
      if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&*it)) {
        if (store->getPointerOperand() == ptr) {
          stored_val = store->getValueOperand();
          break;
        }
      }
    }

    if (stored_val) {
      return EvaluateWithKnownPC(stored_val, entry_point);
    }
    return std::nullopt;
  }

  return std::nullopt;
}

std::set<uint64_t> IndirectJumpResolver::ResolveIndirectJumps(
    llvm::Function *main_func,
    uint64_t entry_point,
    IterativeLiftingState &iter_state,
    const std::set<uint64_t> &lifted_blocks,
    std::function<uint64_t(uint64_t)> find_block_end,
    std::function<uint64_t(uint64_t)> get_block_owner) {
  std::set<uint64_t> new_targets;

  if (iter_state.unresolved_indirect_jumps.empty()) {
    return new_targets;
  }

  // Strategy: Clone the function, run SCCP on the clone to fold computations,
  // then extract constant switch selectors from the optimized clone.
  // This preserves the original function's allocas for continued lifting.

  // Build a map from dispatch block name to original block address
  std::map<std::string, uint64_t> dispatch_name_to_addr;
  for (auto &[block_addr, sw] : iter_state.unresolved_indirect_jumps) {
    if (!sw) continue;
    auto *dispatch_block = sw->getParent();
    dispatch_name_to_addr[dispatch_block->getName().str()] = block_addr;
  }

  // Clone the module for SCCP analysis
  auto *original_module = main_func->getParent();
  auto cloned_module = llvm::CloneModule(*original_module);
  if (!cloned_module) {
    utils::dbg() << "Failed to clone module for SCCP resolution\n";
    return new_targets;
  }

  // Find the cloned main function
  auto *cloned_func = cloned_module->getFunction(main_func->getName());
  if (!cloned_func) {
    utils::dbg() << "Failed to find cloned function\n";
    return new_targets;
  }

  // First, inline all helper functions so memory operations are visible
  {
    // Mark all internal functions as always_inline
    for (auto &func : *cloned_module) {
      if (func.isDeclaration()) continue;
      if (&func == cloned_func) continue;
      func.addFnAttr(llvm::Attribute::AlwaysInline);
    }

    // Run inlining pass using new pass manager
    llvm::LoopAnalysisManager lam;
    llvm::FunctionAnalysisManager fam;
    llvm::CGSCCAnalysisManager cgam;
    llvm::ModuleAnalysisManager mam;

    llvm::PassBuilder pb;
    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerFunctionAnalyses(fam);
    pb.registerLoopAnalyses(lam);
    pb.crossRegisterProxies(lam, fam, cgam, mam);

    llvm::ModulePassManager mpm;
    mpm.addPass(llvm::ModuleInlinerPass(llvm::getInlineParams(10000)));
    mpm.run(*cloned_module, mam);

    utils::dbg() << "Inlined helper functions for SCCP resolution\n";
  }

  // Replace memory intrinsics with actual load/store to a global memory array
  {
    constexpr size_t SYMBOLIC_MEMORY_SIZE = 0x100000;  // 1MB
    auto *mem_type = llvm::ArrayType::get(
        llvm::Type::getInt8Ty(cloned_module->getContext()), SYMBOLIC_MEMORY_SIZE);

    // Initialize memory with PE section data if available
    std::vector<uint8_t> mem_init(SYMBOLIC_MEMORY_SIZE, 0);

    if (pe_info_) {
      for (const auto &section : pe_info_->sections) {
        uint64_t section_va = pe_info_->image_base + section.virtual_address;
        uint64_t masked_base = section_va & 0xFFFFF;

        utils::dbg() << "Initializing symbolic memory for section " << section.name
                     << " at VA " << llvm::format_hex(section_va, 0)
                     << " (masked: " << llvm::format_hex(masked_base, 0) << ")\n";

        for (size_t i = 0; i < section.bytes.size() && (masked_base + i) < SYMBOLIC_MEMORY_SIZE; ++i) {
          mem_init[masked_base + i] = section.bytes[i];
        }
      }
    }

    auto *init_data = llvm::ConstantDataArray::get(
        cloned_module->getContext(), llvm::ArrayRef<uint8_t>(mem_init));
    auto *mem_global = new llvm::GlobalVariable(
        *cloned_module, mem_type, false, llvm::GlobalValue::InternalLinkage,
        init_data, "symbolic_memory");

    // Collect memory intrinsic calls
    std::vector<llvm::CallInst*> write_calls;
    std::vector<llvm::CallInst*> read_calls;

    for (auto &func : *cloned_module) {
      for (auto &bb : func) {
        for (auto &inst : bb) {
          if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
            auto *callee = call->getCalledFunction();
            if (!callee) continue;
            std::string name = callee->getName().str();
            if (name.find("__remill_write_memory_64") != std::string::npos) {
              write_calls.push_back(call);
            } else if (name.find("__remill_read_memory_64") != std::string::npos) {
              read_calls.push_back(call);
            }
          }
        }
      }
    }

    // Replace write_memory_64 calls
    for (auto *call : write_calls) {
      if (call->arg_size() < 3) continue;
      llvm::Value *addr = call->getArgOperand(1);
      llvm::Value *value = call->getArgOperand(2);

      llvm::IRBuilder<> builder(call);
      auto *masked = builder.CreateAnd(addr, builder.getInt64(0xFFFFF));
      auto *ptr = builder.CreateGEP(mem_type, mem_global,
                                    {builder.getInt64(0), masked});
      auto *typed_ptr = builder.CreateBitCast(ptr, builder.getInt64Ty()->getPointerTo());
      builder.CreateStore(value, typed_ptr);

      call->replaceAllUsesWith(call->getArgOperand(0));
    }

    // Replace read_memory_64 calls
    for (auto *call : read_calls) {
      if (call->arg_size() < 2) continue;
      llvm::Value *addr = call->getArgOperand(1);

      llvm::IRBuilder<> builder(call);
      auto *masked = builder.CreateAnd(addr, builder.getInt64(0xFFFFF));
      auto *ptr = builder.CreateGEP(mem_type, mem_global,
                                    {builder.getInt64(0), masked});
      auto *typed_ptr = builder.CreateBitCast(ptr, builder.getInt64Ty()->getPointerTo());
      auto *loaded = builder.CreateLoad(builder.getInt64Ty(), typed_ptr);

      call->replaceAllUsesWith(loaded);
    }

    // Remove the original calls
    for (auto *call : write_calls) {
      call->eraseFromParent();
    }
    for (auto *call : read_calls) {
      call->eraseFromParent();
    }

    utils::dbg() << "Replaced " << write_calls.size() << " memory writes and "
                 << read_calls.size() << " memory reads\n";
  }

  // Run SCCP on the cloned module
  utils::dbg() << "Running SCCP on cloned function to resolve indirect jumps...\n";
  utils::dbg() << "  Dispatch blocks to check: ";
  for (auto &[name, addr] : dispatch_name_to_addr) {
    utils::dbg() << name << "->" << llvm::format_hex(addr, 0) << " ";
  }
  utils::dbg() << "\n";

  optimization::OptimizeForResolution(cloned_module.get(), cloned_func);

  // Helper to extract the offset from a symbolic memory load instruction
  auto getSymbolicMemoryOffset = [](llvm::LoadInst *load) -> llvm::Value* {
    auto *ptr = load->getPointerOperand();

    if (auto *bitcast = llvm::dyn_cast<llvm::BitCastInst>(ptr)) {
      ptr = bitcast->getOperand(0);
    }

    auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(ptr);
    if (!gep || gep->getNumIndices() != 2) return nullptr;

    auto *base = gep->getPointerOperand();
    auto *global = llvm::dyn_cast<llvm::GlobalVariable>(base);
    if (!global || global->getName() != "symbolic_memory") return nullptr;

    return gep->getOperand(2);
  };

  // Helper to evaluate a value, substituting program_counter with entry_point
  std::function<std::optional<uint64_t>(llvm::Value*)> evaluateValue;
  evaluateValue = [&](llvm::Value *val) -> std::optional<uint64_t> {
    if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(val)) {
      return ci->getZExtValue();
    }

    if (auto *arg = llvm::dyn_cast<llvm::Argument>(val)) {
      return (arg->getArgNo() == 1) ? std::optional<uint64_t>(entry_point)
                                    : std::nullopt;
    }

    if (auto *binop = llvm::dyn_cast<llvm::BinaryOperator>(val)) {
      auto lhs = evaluateValue(binop->getOperand(0));
      auto rhs = evaluateValue(binop->getOperand(1));
      if (!lhs || !rhs) return std::nullopt;
      return EvaluateBinaryOp(binop->getOpcode(), *lhs, *rhs);
    }

    if (auto *cast = llvm::dyn_cast<llvm::CastInst>(val)) {
      if (llvm::isa<llvm::TruncInst>(val) || llvm::isa<llvm::ZExtInst>(val) ||
          llvm::isa<llvm::SExtInst>(val)) {
        return evaluateValue(cast->getOperand(0));
      }
    }

    if (auto *load = llvm::dyn_cast<llvm::LoadInst>(val)) {
      if (auto *offset_val = getSymbolicMemoryOffset(load)) {
        std::optional<uint64_t> offset;
        if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(offset_val)) {
          offset = ci->getZExtValue();
        } else {
          offset = evaluateValue(offset_val);
        }

        if (offset) {
          auto value = ReadQwordFromPESections(*offset);
          if (value) {
            utils::dbg() << "  Evaluated load from symbolic_memory offset "
                         << llvm::format_hex(*offset, 0) << " = " << llvm::format_hex(*value, 0) << "\n";
          }
          return value;
        }
      }
    }

    return std::nullopt;
  };

  // Find stores to PC (offset 2472 in state) and evaluate the stored value
  for (auto &bb : *cloned_func) {
    for (auto &inst : bb) {
      auto *store = llvm::dyn_cast<llvm::StoreInst>(&inst);
      if (!store) continue;

      auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(store->getPointerOperand());
      if (!gep) continue;

      if (gep->getNumIndices() == 1) {
        if (auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
          if (idx->getZExtValue() != 2472) continue;

          auto computed = evaluateValue(store->getValueOperand());
          if (computed) {
            uint64_t target = *computed;

            // Filter out targets inside existing blocks
            bool is_inside_existing_block = false;
            for (uint64_t block_addr : lifted_blocks) {
              uint64_t block_end = find_block_end(block_addr);
              if (target > block_addr && target < block_end) {
                is_inside_existing_block = true;
                break;
              }
            }

            if (!is_inside_existing_block &&
                !lifted_blocks.count(target) &&
                !new_targets.count(target)) {

              utils::dbg() << "Discovered target " << llvm::format_hex(target, 0)
                           << " from PC store\n";

              new_targets.insert(target);
            }
          }
        }
      }
    }
  }

  return new_targets;
}

}  // namespace lifting
