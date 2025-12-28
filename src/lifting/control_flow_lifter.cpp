#include "control_flow_lifter.h"

#include <iostream>
#include <queue>
#include <sstream>
#include <variant>

#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/IPO/ModuleInliner.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/BC/Util.h>

#include "optimization/optimizer.h"

namespace lifting {

ControlFlowLifter::ControlFlowLifter(LiftingContext &ctx)
    : ctx_(ctx), decoding_context_(ctx.GetArch()->CreateInitialContext()) {}

void ControlFlowLifter::SetIterativeConfig(const IterativeLiftingConfig &config) {
  config_ = config;
}

void ControlFlowLifter::SetPEInfo(const utils::PEInfo *pe_info) {
  pe_info_ = pe_info;
}

std::optional<uint64_t> ControlFlowLifter::EvaluateBinaryOp(
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

std::optional<uint64_t> ControlFlowLifter::ReadQwordFromPESections(
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

const IterativeLiftingState &ControlFlowLifter::GetIterationState() const {
  return iter_state_;
}

void ControlFlowLifter::ClearState() {
  instructions_.clear();
  block_starts_.clear();
  blocks_.clear();
  call_targets_.clear();
  helper_functions_.clear();
  block_owner_.clear();
  call_return_addrs_.clear();
  main_func_ = nullptr;
  dispatch_blocks_.clear();

  // Reset iteration state
  iter_state_.lifted_blocks.clear();
  iter_state_.pending_blocks.clear();
  iter_state_.unresolved_indirect_jumps.clear();
  iter_state_.block_discovery_iteration.clear();

}

bool ControlFlowLifter::IsValidCodeAddress(uint64_t addr) const {
  return addr >= code_start_ && addr < code_end_;
}

uint64_t ControlFlowLifter::FindBlockEnd(uint64_t block_addr) const {
  auto it = block_starts_.find(block_addr);
  if (it == block_starts_.end()) {
    return code_end_;
  }
  auto next_it = std::next(it);
  return (next_it != block_starts_.end()) ? *next_it : code_end_;
}

uint64_t ControlFlowLifter::GetLastInstrAddr(uint64_t block_start,
                                              uint64_t block_end) const {
  uint64_t last_addr = block_start;
  for (const auto &[addr, decoded] : instructions_) {
    if (addr >= block_start && addr < block_end) {
      if (decoded.instr.IsControlFlow()) {
        return addr;
      }
      last_addr = addr;
    }
  }
  return last_addr;
}

bool ControlFlowLifter::DecodeBlockAt(uint64_t addr) {
  if (!IsValidCodeAddress(addr)) {
    return false;
  }

  // Already decoded?
  if (instructions_.count(addr)) {
    return true;
  }

  // Decode instructions starting from addr until we hit a control flow instruction
  size_t offset = addr - code_start_;

  while (offset < code_size_) {
    uint64_t current_addr = code_start_ + offset;

    // Check if we've hit another block start (already decoded region)
    if (current_addr != addr && block_starts_.count(current_addr)) {
      break;
    }

    std::string_view bytes_view(
        reinterpret_cast<const char *>(code_bytes_ + offset),
        code_size_ - offset);

    DecodedInstruction decoded;
    decoded.address = current_addr;

    if (!ctx_.GetArch()->DecodeInstruction(current_addr, bytes_view,
                                           decoded.instr, decoding_context_)) {
      if (config_.verbose) {
        std::cerr << "Failed to decode instruction at 0x" << std::hex
                  << current_addr << std::dec << "\n";
      }
      return false;
    }

    decoded.size = decoded.instr.bytes.size();
    instructions_[current_addr] = decoded;

    offset += decoded.size;

    // Stop at control flow instructions
    if (decoded.instr.IsControlFlow()) {
      break;
    }
  }

  return true;
}

void ControlFlowLifter::DiscoverBlocksFromEntry(uint64_t start_addr,
                                                 int iteration) {
  if (iter_state_.lifted_blocks.count(start_addr)) {
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
    if (iter_state_.lifted_blocks.count(addr)) {
      continue;
    }

    // Decode this block if not already decoded
    if (!instructions_.count(addr)) {
      if (!DecodeBlockAt(addr)) {
        continue;  // Failed to decode
      }
    }

    // Mark as a block start
    block_starts_.insert(addr);
    iter_state_.block_discovery_iteration[addr] = iteration;

    // Find last instruction of block to determine successors
    uint64_t block_end = FindBlockEnd(addr);
    uint64_t last_addr = GetLastInstrAddr(addr, block_end);
    auto instr_it = instructions_.find(last_addr);
    if (instr_it == instructions_.end()) {
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
                !iter_state_.lifted_blocks.count(target)) {
              worklist.push(target);
              visited.insert(target);
            }
          }
        }
        // Fall-through
        if (IsValidCodeAddress(next_addr) && !visited.count(next_addr) &&
            !iter_state_.lifted_blocks.count(next_addr)) {
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
              !iter_state_.lifted_blocks.count(target)) {
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
            !iter_state_.lifted_blocks.count(target)) {
          worklist.push(target);
          visited.insert(target);
          call_targets_.insert(target);
        }
        if (IsValidCodeAddress(next_addr) && !visited.count(next_addr) &&
            !iter_state_.lifted_blocks.count(next_addr)) {
          worklist.push(next_addr);
          visited.insert(next_addr);
        }
        // Track call return address
        call_return_addrs_[last_addr] = next_addr;
        break;
      }

      case remill::Instruction::kCategoryIndirectJump:
        // DO NOT follow - will be handled by switch resolution
        if (config_.verbose) {
          std::cout << "Found indirect jump at 0x" << std::hex << last_addr
                    << std::dec << " (will be resolved by SCCP)\n";
        }
        break;

      case remill::Instruction::kCategoryFunctionReturn:
        // End of function, no successors
        break;

      default:
        // Fall through to next instruction/block
        if (IsValidCodeAddress(next_addr) && !visited.count(next_addr) &&
            !iter_state_.lifted_blocks.count(next_addr)) {
          worklist.push(next_addr);
          visited.insert(next_addr);
        }
        break;
    }
  }
}

void ControlFlowLifter::CreateBasicBlocksIncremental() {
  auto &context = ctx_.GetContext();

  // Initialize main function entry block with required allocas if needed
  if (main_func_ && !blocks_.count(entry_point_)) {
    auto *entry = &main_func_->getEntryBlock();
    blocks_[entry_point_] = entry;

    // Check if NEXT_PC alloca already exists
    llvm::AllocaInst *existing_next_pc = nullptr;
    for (auto &inst : *entry) {
      if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
        if (alloca->getName() == "NEXT_PC") {
          existing_next_pc = alloca;
          break;
        }
      }
    }

    // Add NEXT_PC alloca if not present
    if (!existing_next_pc) {
      llvm::IRBuilder<> builder(entry, entry->begin());

      // NEXT_PC - store the PC argument
      auto *next_pc =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "NEXT_PC");
      builder.CreateStore(main_func_->getArg(1), next_pc);
    }
  }

  // First, initialize any new helper functions with required allocas
  for (auto &[helper_entry, helper_func] : helper_functions_) {
    if (helper_func->empty()) {
      // Create entry block if it doesn't exist
      auto *entry = llvm::BasicBlock::Create(context, "entry", helper_func);
      blocks_[helper_entry] = entry;

      // Add required allocas to helper function entry
      llvm::IRBuilder<> builder(entry, entry->begin());

      // BRANCH_TAKEN
      builder.CreateAlloca(builder.getInt8Ty(), nullptr, "BRANCH_TAKEN");

      // RETURN_PC
      builder.CreateAlloca(builder.getInt64Ty(), nullptr, "RETURN_PC");

      // MONITOR
      auto *monitor =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "MONITOR");
      builder.CreateStore(builder.getInt64(0), monitor);

      // STATE - store the state pointer argument
      auto *state_alloca =
          builder.CreateAlloca(builder.getPtrTy(), nullptr, "STATE");
      builder.CreateStore(helper_func->getArg(0), state_alloca);

      // MEMORY - store the memory pointer argument
      auto *memory_alloca =
          builder.CreateAlloca(builder.getPtrTy(), nullptr, "MEMORY");
      builder.CreateStore(helper_func->getArg(2), memory_alloca);

      // NEXT_PC - store the PC argument
      auto *next_pc =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "NEXT_PC");
      builder.CreateStore(helper_func->getArg(1), next_pc);

      // Segment bases (required by some instructions)
      auto *csbase =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "CSBASE");
      builder.CreateStore(builder.getInt64(0), csbase);
      auto *ssbase =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "SSBASE");
      builder.CreateStore(builder.getInt64(0), ssbase);
      auto *esbase =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "ESBASE");
      builder.CreateStore(builder.getInt64(0), esbase);
      auto *dsbase =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "DSBASE");
      builder.CreateStore(builder.getInt64(0), dsbase);
    }
  }

  // Create blocks only for addresses not yet in blocks_ map
  for (uint64_t addr : block_starts_) {
    if (blocks_.count(addr)) {
      continue;  // Already created
    }

    // Determine owner (for now, use main function; helpers handled separately)
    uint64_t owner = block_owner_.count(addr) ? block_owner_[addr] : 0;
    llvm::Function *target_func =
        (owner == 0) ? main_func_ : helper_functions_[owner];

    if (!target_func) {
      // May be discovered later as a helper function
      continue;
    }

    std::ostringstream oss;
    oss << "bb_" << std::hex << addr;
    std::string name = oss.str();

    // Check if this is the entry point of the function
    bool is_entry =
        (owner == 0 && addr == entry_point_) || (owner != 0 && addr == owner);

    if (is_entry && !target_func->empty()) {
      // Use existing entry block
      auto *entry = &target_func->getEntryBlock();
      entry->setName(name);
      blocks_[addr] = entry;
    } else {
      auto *block = llvm::BasicBlock::Create(context, name, target_func);
      blocks_[addr] = block;
    }
  }
}

bool ControlFlowLifter::LiftPendingBlocks() {
  // Lift only blocks that haven't been lifted yet
  for (uint64_t block_addr : block_starts_) {
    if (iter_state_.lifted_blocks.count(block_addr)) {
      continue;  // Already lifted
    }

    if (!blocks_.count(block_addr)) {
      if (config_.verbose) {
        std::cerr << "Warning: no LLVM block for address 0x" << std::hex
                  << block_addr << std::dec << "\n";
      }
      continue;
    }

    llvm::BasicBlock *block = blocks_[block_addr];

    // Find the end of this block
    uint64_t block_end = FindBlockEnd(block_addr);

    // Lift all instructions in this block
    uint64_t addr = block_addr;
    DecodedInstruction *last_instr = nullptr;

    while (addr < block_end) {
      auto instr_it = instructions_.find(addr);
      if (instr_it == instructions_.end()) {
        // Instruction not decoded - this can happen if the block is
        // partially decoded. Try to decode it.
        if (!DecodeBlockAt(addr)) {
          std::cerr << "Missing instruction at 0x" << std::hex << addr
                    << std::dec << "\n";
          return false;
        }
        instr_it = instructions_.find(addr);
        if (instr_it == instructions_.end()) {
          return false;
        }
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

    // Mark as lifted
    iter_state_.lifted_blocks.insert(block_addr);
  }

  return true;
}

// Helper to evaluate a Value assuming program_counter = entry_point_
// Returns the computed value, or std::nullopt if it can't be evaluated
std::optional<int64_t> ControlFlowLifter::EvaluateWithKnownPC(llvm::Value *val) {
  // Base case: constant integer
  if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(val)) {
    return ci->getSExtValue();
  }

  // Base case: program_counter argument (arg 1)
  if (auto *arg = llvm::dyn_cast<llvm::Argument>(val)) {
    if (arg->getArgNo() == 1) {
      return static_cast<int64_t>(entry_point_);
    }
    return std::nullopt;
  }

  // Binary operation: try to evaluate both operands
  if (auto *binop = llvm::dyn_cast<llvm::BinaryOperator>(val)) {
    auto lhs = EvaluateWithKnownPC(binop->getOperand(0));
    auto rhs = EvaluateWithKnownPC(binop->getOperand(1));
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
      return EvaluateWithKnownPC(stored_val);
    }
    return std::nullopt;
  }

  return std::nullopt;
}

std::set<uint64_t> ControlFlowLifter::ResolveIndirectJumps() {
  std::set<uint64_t> new_targets;

  if (iter_state_.unresolved_indirect_jumps.empty()) {
    return new_targets;
  }

  // Strategy: Clone the function, run SCCP on the clone to fold computations,
  // then extract constant switch selectors from the optimized clone.
  // This preserves the original function's allocas for continued lifting.

  // Build a map from dispatch block name to original block address
  // so we can find the corresponding switch in the clone
  std::map<std::string, uint64_t> dispatch_name_to_addr;
  for (auto &[block_addr, sw] : iter_state_.unresolved_indirect_jumps) {
    if (!sw) continue;
    auto *dispatch_block = sw->getParent();
    dispatch_name_to_addr[dispatch_block->getName().str()] = block_addr;
  }

  // Clone the module for SCCP analysis
  auto *original_module = main_func_->getParent();
  auto cloned_module = llvm::CloneModule(*original_module);
  if (!cloned_module) {
    if (config_.verbose) {
      std::cerr << "Failed to clone module for SCCP resolution\n";
    }
    return new_targets;
  }

  // Find the cloned main function
  auto *cloned_func = cloned_module->getFunction(main_func_->getName());
  if (!cloned_func) {
    if (config_.verbose) {
      std::cerr << "Failed to find cloned function\n";
    }
    return new_targets;
  }

  // First, inline all helper functions so memory operations are visible
  // This is needed because PUSH/RET semantics are in separate functions
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

    if (config_.verbose) {
      std::cout << "Inlined helper functions for SCCP resolution\n";
    }
  }

  // Replace memory intrinsics with actual load/store to a global memory array
  // This allows SCCP to propagate constants through stack operations
  {
    // Create a global array to represent memory
    // Size needs to accommodate both stack operations (low addresses masked to 0xFFFF)
    // and PE section data (if available)
    constexpr size_t SYMBOLIC_MEMORY_SIZE = 0x100000;  // 1MB should be enough
    auto *mem_type = llvm::ArrayType::get(
        llvm::Type::getInt8Ty(cloned_module->getContext()), SYMBOLIC_MEMORY_SIZE);

    // Initialize memory with zeros, then overlay PE section data if available
    std::vector<uint8_t> mem_init(SYMBOLIC_MEMORY_SIZE, 0);

    // If we have PE info, populate the symbolic memory with actual section data
    // This allows SCCP to resolve jump targets stored in global variables
    if (pe_info_) {
      for (const auto &section : pe_info_->sections) {
        uint64_t section_va = pe_info_->image_base + section.virtual_address;
        // Map to lower addresses by masking - same as the read/write replacement below
        uint64_t masked_base = section_va & 0xFFFFF;  // Mask to 1MB range

        if (config_.verbose) {
          std::cout << "Initializing symbolic memory for section " << section.name
                    << " at VA 0x" << std::hex << section_va
                    << " (masked: 0x" << masked_base << ")" << std::dec << "\n";
        }

        for (size_t i = 0; i < section.bytes.size() && (masked_base + i) < SYMBOLIC_MEMORY_SIZE; ++i) {
          mem_init[masked_base + i] = section.bytes[i];
        }
      }
    }

    // Create constant initializer from the byte array
    auto *init_data = llvm::ConstantDataArray::get(
        cloned_module->getContext(), llvm::ArrayRef<uint8_t>(mem_init));
    // Note: Can't mark as constant because we also write to it for stack ops
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

    // Replace write_memory_64 calls: (memory, addr, value) -> store value
    for (auto *call : write_calls) {
      if (call->arg_size() < 3) continue;
      llvm::Value *addr = call->getArgOperand(1);
      llvm::Value *value = call->getArgOperand(2);

      llvm::IRBuilder<> builder(call);
      // Mask address to fit in our array (1MB = 0xFFFFF)
      auto *masked = builder.CreateAnd(addr, builder.getInt64(0xFFFFF));
      auto *ptr = builder.CreateGEP(mem_type, mem_global,
                                    {builder.getInt64(0), masked});
      auto *typed_ptr = builder.CreateBitCast(ptr, builder.getInt64Ty()->getPointerTo());
      builder.CreateStore(value, typed_ptr);

      // Replace uses with original memory pointer
      call->replaceAllUsesWith(call->getArgOperand(0));
    }

    // Replace read_memory_64 calls: (memory, addr) -> load
    for (auto *call : read_calls) {
      if (call->arg_size() < 2) continue;
      llvm::Value *addr = call->getArgOperand(1);

      llvm::IRBuilder<> builder(call);
      // Mask address to fit in our array (1MB = 0xFFFFF)
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

    if (config_.verbose) {
      std::cout << "Replaced " << write_calls.size() << " memory writes and "
                << read_calls.size() << " memory reads\n";
    }
  }

  // Run SCCP on the cloned module to fold computations
  if (config_.verbose) {
    std::cout << "Running SCCP on cloned function to resolve indirect jumps...\n";
    std::cout << "  Dispatch blocks to check: ";
    for (auto &[name, addr] : dispatch_name_to_addr) {
      std::cout << name << "->0x" << std::hex << addr << " " << std::dec;
    }
    std::cout << "\n";
  }

  optimization::OptimizeForResolution(cloned_module.get(), cloned_func);

  // After optimization, we look for stores to the PC register at the end of the function.
  // The switch may have been optimized away, but the final PC value should be computable.
  // Find stores to PC (state->rip at offset 2472) and trace back the value.

  // Helper to extract the offset from a symbolic memory load instruction
  auto getSymbolicMemoryOffset = [](llvm::LoadInst *load) -> llvm::Value* {
    auto *ptr = load->getPointerOperand();

    // Check for bitcast of GEP into symbolic_memory
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

  // Helper to evaluate a value, substituting program_counter argument with entry_point
  std::function<std::optional<uint64_t>(llvm::Value*)> evaluateValue;
  evaluateValue = [&](llvm::Value *val) -> std::optional<uint64_t> {
    // Constant integer
    if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(val)) {
      return ci->getZExtValue();
    }

    // Function argument - check if it's program_counter (arg 1)
    if (auto *arg = llvm::dyn_cast<llvm::Argument>(val)) {
      return (arg->getArgNo() == 1) ? std::optional<uint64_t>(entry_point_)
                                    : std::nullopt;
    }

    // Binary operation
    if (auto *binop = llvm::dyn_cast<llvm::BinaryOperator>(val)) {
      auto lhs = evaluateValue(binop->getOperand(0));
      auto rhs = evaluateValue(binop->getOperand(1));
      if (!lhs || !rhs) return std::nullopt;
      return EvaluateBinaryOp(binop->getOpcode(), *lhs, *rhs);
    }

    // Cast operations - evaluate operand
    if (auto *cast = llvm::dyn_cast<llvm::CastInst>(val)) {
      if (llvm::isa<llvm::TruncInst>(val) || llvm::isa<llvm::ZExtInst>(val) ||
          llvm::isa<llvm::SExtInst>(val)) {
        return evaluateValue(cast->getOperand(0));
      }
    }

    // Load from symbolic_memory - evaluate the address and look up the value
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
          if (value && config_.verbose) {
            std::cout << "  Evaluated load from symbolic_memory offset 0x"
                      << std::hex << *offset << " = 0x" << *value << std::dec << "\n";
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

      // Check if this stores to PC (offset 2472)
      auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(store->getPointerOperand());
      if (!gep) continue;

      // Check for byte-offset GEP with offset 2472 (PC register)
      if (gep->getNumIndices() == 1) {
        if (auto *idx = llvm::dyn_cast<llvm::ConstantInt>(gep->getOperand(1))) {
          if (idx->getZExtValue() != 2472) continue;

          // This is a store to PC! Evaluate the stored value.
          auto computed = evaluateValue(store->getValueOperand());
          if (computed) {
            uint64_t target = *computed;

            // Only add if it's a valid target we haven't lifted yet
            // Also filter out targets that fall within the range of an existing block
            // (these are intermediate PC values, not actual jump targets)
            bool is_inside_existing_block = false;
            for (uint64_t block_addr : iter_state_.lifted_blocks) {
              uint64_t block_end = FindBlockEnd(block_addr);
              if (target > block_addr && target < block_end) {
                is_inside_existing_block = true;
                break;
              }
            }

            if (IsValidCodeAddress(target) &&
                !iter_state_.lifted_blocks.count(target) &&
                !new_targets.count(target) &&
                !is_inside_existing_block) {

              if (config_.verbose) {
                std::cout << "Discovered target 0x" << std::hex << target
                          << " from PC store\n" << std::dec;
              }

              // Find which block this came from
              for (auto &[block_addr, _] : iter_state_.unresolved_indirect_jumps) {
                // Assign ownership
                if (!block_owner_.count(target)) {
                  uint64_t owner = block_owner_.count(block_addr) ? block_owner_[block_addr] : 0;
                  block_owner_[target] = owner;
                }
                break;  // Use first unresolved jump's owner
              }

              new_targets.insert(target);
            }
          }
        }
      }
    }
  }

  // The cloned module is automatically deleted when cloned_module goes out of scope

  return new_targets;
}

bool ControlFlowLifter::LiftFunction(uint64_t code_base, uint64_t entry_point,
                                      const uint8_t *bytes, size_t size,
                                      llvm::Function *func) {
  // Clear all state for a fresh lift
  ClearState();

  // Store code bytes for incremental decoding
  code_bytes_ = bytes;
  code_size_ = size;
  code_start_ = code_base;
  code_end_ = code_base + size;
  entry_point_ = entry_point;
  main_func_ = func;

  // Initialize iteration state with entry point
  iter_state_.pending_blocks.insert(entry_point);
  iter_state_.block_discovery_iteration[entry_point] = 0;

  int iteration = 0;
  while (!iter_state_.pending_blocks.empty() &&
         iteration < config_.max_iterations) {
    if (config_.verbose) {
      std::cout << "\n=== Iteration " << iteration << " ===" << std::endl;
      std::cout << "Pending blocks: " << iter_state_.pending_blocks.size()
                << std::endl;
    }

    // Phase 1: Discover blocks reachable from pending (BFS, direct flow only)
    std::set<uint64_t> to_process = iter_state_.pending_blocks;
    iter_state_.pending_blocks.clear();

    for (uint64_t addr : to_process) {
      DiscoverBlocksFromEntry(addr, iteration);
    }

    if (config_.verbose) {
      std::cout << "Discovered " << block_starts_.size()
                << " total blocks so far" << std::endl;
    }

    // Phase 2: Determine which blocks belong to which native function
    AssignBlocksToFunctions();

    // Phase 3: Create helper functions for newly discovered call targets
    CreateHelperFunctions(func);

    // Phase 4: Create LLVM basic blocks for newly discovered addresses
    CreateBasicBlocksIncremental();

    // Phase 4b: Update switches with newly discovered targets
    // After creating blocks, add them as cases to existing switches
    for (auto &[jump_block_addr, sw] : iter_state_.unresolved_indirect_jumps) {
      if (!sw) continue;

      // Find the function owner for this switch
      uint64_t owner = block_owner_.count(jump_block_addr) ? block_owner_[jump_block_addr] : 0;

      // Get the function's entry block - we must not add it as a case (creates loop header)
      auto *sw_func = sw->getFunction();
      auto *entry_block = &sw_func->getEntryBlock();

      // Add cases for all blocks in the same function
      for (auto &[target_addr, target_bb] : blocks_) {
        if (!target_bb) continue;

        // Skip entry block to avoid creating back edges
        if (target_bb == entry_block) continue;

        // Check if this target is in the same function
        uint64_t target_owner = block_owner_.count(target_addr) ? block_owner_[target_addr] : 0;
        if (target_owner != owner) continue;

        // Skip if case already exists
        bool case_exists = false;
        for (auto case_it : sw->cases()) {
          if (case_it.getCaseValue()->getZExtValue() == target_addr) {
            case_exists = true;
            break;
          }
        }

        if (!case_exists) {
          auto &ctx = sw->getContext();
          sw->addCase(llvm::ConstantInt::get(llvm::Type::getInt64Ty(ctx), target_addr), target_bb);
        }
      }
    }

    // Phase 5: Lift pending blocks
    if (!LiftPendingBlocks()) {
      return false;
    }

    // Phase 5b: Dump iteration IR if requested
    if (!config_.dump_iterations_dir.empty()) {
      std::string filename = config_.dump_iterations_dir + "/iteration_" +
                             std::to_string(iteration) + ".ll";
      std::error_code ec;
      llvm::raw_fd_ostream os(filename, ec);
      if (!ec) {
        // Print a header comment with iteration info
        os << "; Iteration " << iteration << "\n";
        os << "; Blocks lifted this iteration:\n";
        for (uint64_t addr : iter_state_.lifted_blocks) {
          if (iter_state_.block_discovery_iteration.count(addr) &&
              iter_state_.block_discovery_iteration[addr] == iteration) {
            os << ";   " << llvm::format_hex(addr, 10) << "\n";
          }
        }
        os << "; Total blocks so far: " << iter_state_.lifted_blocks.size() << "\n";
        os << "; Unresolved indirect jumps: "
           << iter_state_.unresolved_indirect_jumps.size() << "\n";
        os << "\n";

        // Print only the lifted function (not the whole semantics module)
        main_func_->print(os, nullptr);

        // Also print helper functions
        for (auto &[addr, helper_func] : helper_functions_) {
          os << "\n";
          helper_func->print(os, nullptr);
        }

        os.close();
        std::cout << "Written: " << filename << "\n";
      }
    }

    // Phase 6: Check switches for constant selectors
    // We skip optimization during iterative lifting because it destroys
    // allocas (MEMORY, NEXT_PC) that Remill needs for lifting new blocks.
    // Instead, we rely on statically computed targets from LEA analysis.
    std::set<uint64_t> new_targets = ResolveIndirectJumps();

    if (config_.verbose) {
      std::cout << "Found " << new_targets.size() << " new targets from "
                << "resolved indirect jumps" << std::endl;
    }

    // Add new targets to pending for next iteration
    for (uint64_t target : new_targets) {
      if (!iter_state_.lifted_blocks.count(target)) {
        iter_state_.pending_blocks.insert(target);
        iter_state_.block_discovery_iteration[target] = iteration + 1;
      }
    }

    iteration++;
  }

  // Check for max iteration limit
  if (iteration >= config_.max_iterations &&
      !iter_state_.pending_blocks.empty()) {
    std::cerr << "Warning: Maximum iteration limit (" << config_.max_iterations
              << ") reached with " << iter_state_.pending_blocks.size()
              << " pending blocks\n";
    std::cerr << "Unresolved indirect jumps: "
              << iter_state_.unresolved_indirect_jumps.size() << "\n";
  }

  // Always print iteration summary
  std::cout << "Lifting completed: " << iteration << " iterations, "
            << iter_state_.lifted_blocks.size() << " blocks\n";

  if (config_.verbose) {
    std::cout << "Unresolved indirect jumps: "
              << iter_state_.unresolved_indirect_jumps.size() << std::endl;
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

    std::ostringstream oss;
    oss << "bb_" << std::hex << addr;
    std::string name = oss.str();

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

llvm::SwitchInst *ControlFlowLifter::FinishBlock(llvm::BasicBlock *block,
                                                  const DecodedInstruction &last_instr,
                                                  uint64_t next_addr,
                                                  uint64_t block_addr) {
  llvm::IRBuilder<> builder(block);
  auto *intrinsics = ctx_.GetIntrinsics();
  uint64_t current_owner = block_owner_[block_addr];
  llvm::SwitchInst *result_switch = nullptr;

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
      // Treat RET like an indirect jump - create a switch over PC
      // SCCP will resolve the target by propagating constants through memory operations
      llvm::Value *target_pc = remill::LoadProgramCounter(block, *intrinsics);

      if (target_pc) {
        // Create dispatch block for the switch
        auto *dispatch_block = llvm::BasicBlock::Create(
            ctx_.GetContext(), "ret_dispatch", block->getParent());
        builder.CreateBr(dispatch_block);

        llvm::IRBuilder<> dispatch_builder(dispatch_block);

        // Create default block that returns (for truly external returns)
        auto *default_block = llvm::BasicBlock::Create(
            ctx_.GetContext(), "ret_default", block->getParent());
        llvm::IRBuilder<> default_builder(default_block);
        default_builder.CreateRet(remill::LoadMemoryPointer(default_block, *intrinsics));

        // Create switch - cases will be added incrementally as targets are discovered
        auto *sw = dispatch_builder.CreateSwitch(target_pc, default_block, 0);

        // Track this switch for resolution (same as indirect jumps)
        iter_state_.unresolved_indirect_jumps[block_addr] = sw;

        if (config_.verbose) {
          std::cout << "Created RET switch at 0x" << std::hex << block_addr
                    << std::dec << " (will be resolved by SCCP)\n";
        }
      } else {
        // Fallback: just return
        builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
      }
      break;
    }

    case remill::Instruction::kCategoryIndirectJump: {
      // Indirect jump (e.g., jmp rax) - emit a switch over all possible targets.
      // After SCCP runs on a cloned module, the switch selector becomes a constant
      // and we discover the target. Then we lift the newly discovered block and
      // repeat until no more targets are found.

      // Use LoadProgramCounter to get the jump target.
      // The actual target resolution happens via SCCP on a cloned function,
      // which can fold arbitrary computations (lea + inc + jmp, etc.) into constants.
      llvm::Value *target_pc = remill::LoadProgramCounter(block, *intrinsics);

      if (target_pc) {

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

        if (memory_alloca) {
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

          // Always create a switch, even if targets is empty
          // The switch selector value will be checked after SCCP
          // and new targets will be discovered if it becomes constant
          auto *sw = dispatch_builder.CreateSwitch(target_pc, default_block, targets.size());
          for (const auto &[addr, bb] : targets) {
            sw->addCase(dispatch_builder.getInt64(addr), bb);
          }

          // Track this switch for resolution in iterative lifting
          result_switch = sw;
          iter_state_.unresolved_indirect_jumps[block_addr] = sw;
          dispatch_blocks_[block_addr] = dispatch_block;

          if (config_.verbose) {
            std::cout << "Created indirect jump switch with " << targets.size()
                      << " known targets\n";
          }
        } else {
          // Missing MEMORY alloca, just return
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

  return result_switch;
}

}  // namespace lifting
