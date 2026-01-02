#include "indirect_jump_resolver.h"

#include <iostream>

#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Format.h>
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/IPO/ModuleInliner.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/IR/Verifier.h>

#include "control_flow_lifter.h"
#include "optimization/optimizer.h"
#include "utils/debug_flag.h"

namespace lifting {

IndirectJumpResolver::IndirectJumpResolver(const utils::PEInfo *pe_info)
    : pe_info_(pe_info) {}

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

IndirectJumpResolution IndirectJumpResolver::ResolveIndirectJumps(
    llvm::Function *main_func,
    uint64_t entry_point,
    IterativeLiftingState &iter_state,
    const std::set<uint64_t> &lifted_blocks,
    std::function<uint64_t(uint64_t)> find_block_end,
    std::function<uint64_t(uint64_t)> get_block_owner) {
  IndirectJumpResolution result;

  if (iter_state.unresolved_indirect_jumps.empty()) {
    return result;
  }

  // Check if we have any CALL return dispatches (not just RET dispatches)
  // RET dispatches can only be resolved if there's a corresponding CALL that pushed
  // the return address. If there are only RET dispatches, SCCP can't resolve anything
  // because the return address comes from the caller.
  bool has_call_dispatch = false;
  for (auto &[block_addr, sw] : iter_state.unresolved_indirect_jumps) {
    if (!sw) continue;
    auto *dispatch_block = sw->getParent();
    std::string name = dispatch_block->getName().str();
    if (name.find("call_ret_dispatch") != std::string::npos) {
      has_call_dispatch = true;
      break;
    }
  }

  // Count instructions to avoid expensive optimization on huge functions
  int instr_count = 0;
  for (auto &bb : *main_func) {
    instr_count += bb.size();
  }

  // Skip SCCP resolution for pure RET dispatches (no CALLs) AND huge functions
  constexpr int MAX_INSTRUCTIONS_FOR_SCCP = 50000;
  if (!has_call_dispatch && instr_count > MAX_INSTRUCTIONS_FOR_SCCP) {
    utils::dbg() << "Skipping SCCP resolution: no CALL dispatches and function too large ("
                 << instr_count << " instructions)\n";
    return result;
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

  // Debug: count definitions vs declarations
  int def_count = 0, decl_count = 0;
  for (auto &func : *original_module) {
    if (func.isDeclaration()) decl_count++;
    else def_count++;
  }
  utils::dbg() << "Original module: " << def_count << " definitions, "
               << decl_count << " declarations\n";

  // Check if RET semantic is a definition
  if (auto *ret_func = original_module->getFunction("_ZN12_GLOBAL__N_13RETEP6MemoryR5State3RnWImE")) {
    utils::dbg() << "RET semantic is " << (ret_func->isDeclaration() ? "DECLARATION" : "DEFINITION") << "\n";
  }

  // Verify module before cloning to check for issues
  std::string verify_error;
  llvm::raw_string_ostream verify_os(verify_error);
  if (llvm::verifyModule(*original_module, &verify_os)) {
    utils::dbg() << "Module verification FAILED before clone:\n" << verify_error << "\n";
  } else {
    utils::dbg() << "Module verification passed before clone\n";
  }

  auto cloned_module = llvm::CloneModule(*original_module);
  if (!cloned_module) {
    utils::dbg() << "Failed to clone module for SCCP resolution\n";
    return result;
  }

  // Find the cloned main function
  auto *cloned_func = cloned_module->getFunction(main_func->getName());
  if (!cloned_func) {
    utils::dbg() << "Failed to find cloned function\n";
    return result;
  }

  // First, inline all helper functions so memory operations are visible
  {
    // Mark all internal functions as always_inline
    for (auto &func : *cloned_module) {
      if (func.isDeclaration()) continue;
      if (&func == cloned_func) continue;
      func.addFnAttr(llvm::Attribute::AlwaysInline);
    }

    // Run AlwaysInliner pass (handles alwaysinline attribute)
    // Run it multiple times to handle nested calls
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
    // Run AlwaysInliner multiple times for nested inlining
    for (int i = 0; i < 5; ++i) {
      mpm.addPass(llvm::AlwaysInlinerPass());
    }
    mpm.run(*cloned_module, mam);

    utils::dbg() << "Inlined helper functions for SCCP resolution\n";
  }

  // Phase 0.5: Replace %program_counter argument with constant entry point
  // IPSCCP doesn't always propagate this correctly, so we do it manually
  {
    // Find the program_counter argument (arg 1)
    auto arg_it = cloned_func->arg_begin();
    ++arg_it;  // Skip state argument
    llvm::Argument *pc_arg = &*arg_it;

    // Replace all uses with the constant entry point
    auto *entry_const = llvm::ConstantInt::get(
        llvm::Type::getInt64Ty(cloned_module->getContext()), entry_point);
    pc_arg->replaceAllUsesWith(entry_const);

    utils::dbg() << "Replaced %program_counter with constant "
                 << llvm::format_hex(entry_point, 0) << "\n";
  }

  // Phase 1: Create RSP alloca and stack alloca in cloned function
  // This allows LLVM to track RSP value and stack contents through allocas
  // Use a FIXED constant for stack base so SCCP can evaluate is_stack checks
  llvm::AllocaInst *rsp_alloca = nullptr;
  llvm::AllocaInst *stack_alloca = nullptr;
  constexpr size_t STACK_SIZE = 4096;
  constexpr uint64_t RSP_OFFSET = 2312;
  constexpr uint64_t STACK_BASE = 0x7FFFFF000000ULL;  // Fixed constant for SCCP
  constexpr uint64_t STACK_TOP = STACK_BASE + STACK_SIZE;
  llvm::ConstantInt *stack_base_int = nullptr;
  {
    auto *entry = &cloned_func->getEntryBlock();
    auto *first_inst = entry->getFirstNonPHI();
    llvm::IRBuilder<> builder(first_inst);

    // Create RSP value alloca (stores the current RSP as i64)
    rsp_alloca = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "rsp_val");

    // Create stack alloca (array of i64 for proper alignment)
    auto *stack_type = llvm::ArrayType::get(builder.getInt64Ty(), STACK_SIZE / 8);
    stack_alloca = builder.CreateAlloca(stack_type, nullptr, "sccp_stack");

    // Use fixed constant for stack base (so SCCP can fold comparisons)
    stack_base_int = builder.getInt64(STACK_BASE);

    // Initialize RSP to top of stack
    builder.CreateStore(builder.getInt64(STACK_TOP), rsp_alloca);

    utils::dbg() << "Created RSP alloca and stack alloca for SCCP analysis\n";
    utils::dbg() << "  Stack base: " << llvm::format_hex(STACK_BASE, 0)
                 << ", top: " << llvm::format_hex(STACK_TOP, 0) << "\n";
  }

  // Phase 2: Replace loads/stores to State.RSP with loads/stores to rsp_alloca
  {
    std::vector<llvm::LoadInst*> rsp_loads;
    std::vector<llvm::StoreInst*> rsp_stores;

    for (auto &bb : *cloned_func) {
      for (auto &inst : bb) {
        if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
          if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(load->getPointerOperand())) {
            // Check for byte-offset GEP to RSP (offset 2312)
            if (gep->getNumIndices() == 1) {
              if (auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
                if (idx->getZExtValue() == RSP_OFFSET) {
                  rsp_loads.push_back(load);
                }
              }
            }
            // Check for struct GEP pattern [0,0,6,13,0,0] for RSP
            if (gep->getNumIndices() == 6) {
              std::vector<int64_t> indices;
              for (unsigned i = 1; i <= 6; ++i) {
                if (auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(i))) {
                  indices.push_back(idx->getSExtValue());
                }
              }
              if (indices.size() == 6 && indices[0] == 0 && indices[1] == 0 &&
                  indices[2] == 6 && indices[3] == 13 && indices[4] == 0 && indices[5] == 0) {
                rsp_loads.push_back(load);
              }
            }
          }
        }
        if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
          if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(store->getPointerOperand())) {
            if (gep->getNumIndices() == 1) {
              if (auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
                if (idx->getZExtValue() == RSP_OFFSET) {
                  rsp_stores.push_back(store);
                }
              }
            }
            if (gep->getNumIndices() == 6) {
              std::vector<int64_t> indices;
              for (unsigned i = 1; i <= 6; ++i) {
                if (auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(i))) {
                  indices.push_back(idx->getSExtValue());
                }
              }
              if (indices.size() == 6 && indices[0] == 0 && indices[1] == 0 &&
                  indices[2] == 6 && indices[3] == 13 && indices[4] == 0 && indices[5] == 0) {
                rsp_stores.push_back(store);
              }
            }
          }
        }
      }
    }

    // Replace RSP loads
    for (auto *load : rsp_loads) {
      llvm::IRBuilder<> builder(load);
      auto *new_load = builder.CreateLoad(builder.getInt64Ty(), rsp_alloca, "rsp_val");
      load->replaceAllUsesWith(new_load);
      load->eraseFromParent();
    }

    // Replace RSP stores
    for (auto *store : rsp_stores) {
      llvm::IRBuilder<> builder(store);
      builder.CreateStore(store->getValueOperand(), rsp_alloca);
      store->eraseFromParent();
    }

    utils::dbg() << "Replaced " << rsp_loads.size() << " RSP loads and "
                 << rsp_stores.size() << " RSP stores with alloca ops\n";
  }

  // Phase 3: Replace memory intrinsics
  // - Stack addresses (derived from RSP) use the stack alloca
  // - Other addresses use symbolic_memory global
  {
    constexpr size_t SYMBOLIC_MEMORY_SIZE = 0x100000;  // 1MB
    auto *mem_type = llvm::ArrayType::get(
        llvm::Type::getInt8Ty(cloned_module->getContext()), SYMBOLIC_MEMORY_SIZE);

    // Initialize symbolic memory with PE section data
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

    // Collect memory intrinsic calls - ONLY in cloned_func
    // (stack_base_int and stack_alloca are only defined in cloned_func)
    std::vector<llvm::CallInst*> write_calls;
    std::vector<llvm::CallInst*> read_calls;

    for (auto &bb : *cloned_func) {
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

    // Helper to check if an address is stack-relative
    // Stack addresses are: stack_base <= addr < stack_base + STACK_SIZE
    auto createStackCheck = [&](llvm::IRBuilder<> &builder, llvm::Value *addr) -> llvm::Value* {
      auto *ge_base = builder.CreateICmpUGE(addr, stack_base_int);
      auto *stack_end = builder.CreateAdd(stack_base_int, builder.getInt64(STACK_SIZE));
      auto *lt_end = builder.CreateICmpULT(addr, stack_end);
      return builder.CreateAnd(ge_base, lt_end, "is_stack");
    };

    // Helper to compute stack alloca pointer from address
    auto createStackPtr = [&](llvm::IRBuilder<> &builder, llvm::Value *addr) -> llvm::Value* {
      auto *offset = builder.CreateSub(addr, stack_base_int, "stack_offset");
      // Divide by 8 to get i64 array index
      auto *idx = builder.CreateLShr(offset, 3, "stack_idx");
      auto *stack_type = llvm::ArrayType::get(builder.getInt64Ty(), STACK_SIZE / 8);
      return builder.CreateGEP(stack_type, stack_alloca, {builder.getInt64(0), idx}, "stack_ptr");
    };

    // Replace write_memory_64 calls
    for (auto *call : write_calls) {
      if (call->arg_size() < 3) continue;
      llvm::Value *addr = call->getArgOperand(1);
      llvm::Value *value = call->getArgOperand(2);

      llvm::IRBuilder<> builder(call);

      // Check if address is in stack range
      auto *is_stack = createStackCheck(builder, addr);

      // Create stack store
      auto *stack_ptr = createStackPtr(builder, addr);

      // Create symbolic memory store
      auto *masked = builder.CreateAnd(addr, builder.getInt64(0xFFFFF));
      auto *sym_ptr = builder.CreateGEP(mem_type, mem_global, {builder.getInt64(0), masked});
      auto *sym_typed = builder.CreateBitCast(sym_ptr, builder.getInt64Ty()->getPointerTo());

      // Select which pointer to use
      auto *ptr = builder.CreateSelect(is_stack, stack_ptr, sym_typed, "mem_ptr");
      builder.CreateStore(value, ptr);

      call->replaceAllUsesWith(call->getArgOperand(0));
    }

    // Replace read_memory_64 calls
    for (auto *call : read_calls) {
      if (call->arg_size() < 2) continue;
      llvm::Value *addr = call->getArgOperand(1);

      llvm::IRBuilder<> builder(call);

      // Check if address is in stack range
      auto *is_stack = createStackCheck(builder, addr);

      // Create stack load
      auto *stack_ptr = createStackPtr(builder, addr);
      auto *stack_val = builder.CreateLoad(builder.getInt64Ty(), stack_ptr, "stack_val");

      // Create symbolic memory load
      auto *masked = builder.CreateAnd(addr, builder.getInt64(0xFFFFF));
      auto *sym_ptr = builder.CreateGEP(mem_type, mem_global, {builder.getInt64(0), masked});
      auto *sym_typed = builder.CreateBitCast(sym_ptr, builder.getInt64Ty()->getPointerTo());
      auto *sym_val = builder.CreateLoad(builder.getInt64Ty(), sym_typed, "sym_val");

      // Select which value to use
      auto *loaded = builder.CreateSelect(is_stack, stack_val, sym_val, "mem_val");

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
  utils::dbg() << "  Entry point for evaluation: " << llvm::format_hex(entry_point, 0) << "\n";
  utils::dbg() << "  Dispatch blocks to check: ";
  for (auto &[name, addr] : dispatch_name_to_addr) {
    utils::dbg() << name << "->" << llvm::format_hex(addr, 0) << " ";
  }
  utils::dbg() << "\n";

  // Debug: count instructions before optimization
  int instr_before = 0;
  for (auto &bb : *cloned_func) {
    instr_before += bb.size();
  }
  utils::dbg() << "  Instructions before optimization: " << instr_before << "\n";

  // Debug: print key instructions before optimization
  utils::dbg() << "  Stack-related ops before optimization:\n";
  for (auto &bb : *cloned_func) {
    for (auto &inst : bb) {
      std::string s;
      llvm::raw_string_ostream os(s);
      inst.print(os);
      // Look for stack_alloca, rsp_alloca, or select instructions
      if (s.find("stack") != std::string::npos ||
          s.find("rsp") != std::string::npos ||
          s.find("select") != std::string::npos ||
          s.find("is_stack") != std::string::npos) {
        utils::dbg() << "    " << s << "\n";
      }
    }
  }

  optimization::OptimizeForResolution(cloned_module.get(), cloned_func);

  // Debug: count instructions after optimization
  int instr_after = 0;
  for (auto &bb : *cloned_func) {
    instr_after += bb.size();
  }
  utils::dbg() << "  Instructions after optimization: " << instr_after << "\n";

  // Debug: print the optimized function
  utils::dbg() << "  Optimized cloned_func:\n";
  for (auto &bb : *cloned_func) {
    utils::dbg() << "    " << bb.getName().str() << ":\n";
    for (auto &inst : bb) {
      std::string s;
      llvm::raw_string_ostream os(s);
      inst.print(os);
      utils::dbg() << "      " << s << "\n";
    }
  }

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

  // Helper to check if a GEP points to the PC register (offset 2472 in State)
  auto isPCStore = [&](llvm::GetElementPtrInst *gep) -> bool {
    if (!gep) return false;

    // Method 1: Single-index byte-offset GEP
    if (gep->getNumIndices() == 1) {
      if (auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
        return idx->getZExtValue() == 2472;
      }
    }

    // Method 2: Multi-index struct GEP (remill pattern: 0, 0, 6, 33, 0, 0)
    // PC is at State.gpr.rip which is index path [0][0][6][33][0][0]
    if (gep->getNumIndices() == 6) {
      auto indices = std::vector<int64_t>();
      for (unsigned i = 1; i <= 6; ++i) {
        if (auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(i))) {
          indices.push_back(idx->getSExtValue());
        } else {
          return false;
        }
      }
      // Check for the specific index pattern for PC/RIP register
      // [0, 0, 6, 33, 0, 0] is the path to PC in State struct
      if (indices.size() == 6 &&
          indices[0] == 0 && indices[1] == 0 &&
          indices[2] == 6 && indices[3] == 33 &&
          indices[4] == 0 && indices[5] == 0) {
        return true;
      }
    }

    return false;
  };

  // Find stores to PC and evaluate the stored value
  int store_count = 0;
  int pc_store_count = 0;
  for (auto &bb : *cloned_func) {
    // Get source block address from name
    // Try bb_XXXXXX format first (original block names)
    // Then try dispatch block name lookup (ret_dispatch, etc.)
    uint64_t source_block_addr = 0;
    llvm::StringRef bb_name = bb.getName();
    if (bb_name.starts_with("bb_")) {
      bb_name.substr(3).getAsInteger(16, source_block_addr);
    } else {
      // Try dispatch block name lookup
      auto it = dispatch_name_to_addr.find(bb_name.str());
      if (it != dispatch_name_to_addr.end()) {
        source_block_addr = it->second;
      }
    }

    for (auto &inst : bb) {
      auto *store = llvm::dyn_cast<llvm::StoreInst>(&inst);
      if (!store) continue;
      store_count++;

      auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(store->getPointerOperand());
      if (!isPCStore(gep)) continue;
      pc_store_count++;

      auto *stored_value = store->getValueOperand();
      utils::dbg() << "  PC store found in bb " << llvm::format_hex(source_block_addr, 0)
                   << ", value: ";
      stored_value->print(llvm::errs());
      utils::dbg() << "\n";

      auto computed = evaluateValue(stored_value);
      if (computed) {
        utils::dbg() << "    Evaluated to: " << llvm::format_hex(*computed, 0) << "\n";
      } else {
        utils::dbg() << "    Could not evaluate\n";
      }
      if (computed) {
        uint64_t target = *computed;

        // Filter out targets inside existing blocks
        bool is_inside_existing_block = false;
        for (uint64_t block_addr : lifted_blocks) {
          uint64_t block_end = find_block_end(block_addr);
          if (target > block_addr && target < block_end) {
            is_inside_existing_block = true;
            utils::dbg() << "    Target " << llvm::format_hex(target, 0)
                         << " is inside block " << llvm::format_hex(block_addr, 0)
                         << "-" << llvm::format_hex(block_end, 0) << "\n";
            break;
          }
        }

        bool already_lifted = lifted_blocks.count(target) > 0;
        bool already_found = result.new_targets.count(target) > 0;

        utils::dbg() << "    Target " << llvm::format_hex(target, 0)
                     << ": inside_existing=" << is_inside_existing_block
                     << ", already_lifted=" << already_lifted
                     << ", already_found=" << already_found << "\n";

        if (!is_inside_existing_block && !already_lifted && !already_found) {
          utils::dbg() << "    -> Adding as new target!\n";
          result.new_targets.insert(target);

          // Check if source block has a RET dispatch switch
          // If so, add this target as a case for that RET dispatch
          if (source_block_addr != 0) {
            auto sw_it = iter_state.unresolved_indirect_jumps.find(source_block_addr);
            if (sw_it != iter_state.unresolved_indirect_jumps.end() && sw_it->second) {
              auto *sw = sw_it->second;
              std::string dispatch_name = sw->getParent()->getName().str();
              if (dispatch_name.find("ret_dispatch") != std::string::npos) {
                result.ret_dispatch_cases[source_block_addr].insert(target);
                utils::dbg() << "    -> RET dispatch case for block "
                             << llvm::format_hex(source_block_addr, 0) << "\n";
              }
            }
          }
        }
      }
    }
  }

  utils::dbg() << "  Total stores in cloned func: " << store_count
               << ", PC stores found: " << pc_store_count << "\n";

  return result;
}

}  // namespace lifting
