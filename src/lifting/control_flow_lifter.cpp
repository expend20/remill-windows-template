#include "control_flow_lifter.h"

#include <iostream>
#include <sstream>

#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/Util.h>

#include "block_decoder.h"
#include "block_terminator.h"
#include "function_splitter.h"
#include "indirect_jump_resolver.h"
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
      auto *next_pc =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "NEXT_PC");
      builder.CreateStore(main_func_->getArg(1), next_pc);
    }
  }

  // Initialize helper functions with required allocas
  for (auto &[helper_entry, helper_func] : helper_functions_) {
    if (helper_func->empty()) {
      auto *entry = llvm::BasicBlock::Create(context, "entry", helper_func);
      blocks_[helper_entry] = entry;

      llvm::IRBuilder<> builder(entry, entry->begin());

      builder.CreateAlloca(builder.getInt8Ty(), nullptr, "BRANCH_TAKEN");
      builder.CreateAlloca(builder.getInt64Ty(), nullptr, "RETURN_PC");

      auto *monitor =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "MONITOR");
      builder.CreateStore(builder.getInt64(0), monitor);

      auto *state_alloca =
          builder.CreateAlloca(builder.getPtrTy(), nullptr, "STATE");
      builder.CreateStore(helper_func->getArg(0), state_alloca);

      auto *memory_alloca =
          builder.CreateAlloca(builder.getPtrTy(), nullptr, "MEMORY");
      builder.CreateStore(helper_func->getArg(2), memory_alloca);

      auto *next_pc =
          builder.CreateAlloca(builder.getInt64Ty(), nullptr, "NEXT_PC");
      builder.CreateStore(helper_func->getArg(1), next_pc);

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
      continue;
    }

    uint64_t owner = block_owner_.count(addr) ? block_owner_[addr] : 0;
    llvm::Function *target_func =
        (owner == 0) ? main_func_ : helper_functions_[owner];

    if (!target_func) {
      continue;
    }

    std::ostringstream oss;
    oss << "bb_" << std::hex << addr;
    std::string name = oss.str();

    bool is_entry =
        (owner == 0 && addr == entry_point_) || (owner != 0 && addr == owner);

    if (is_entry && !target_func->empty()) {
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
  BlockTerminator terminator(ctx_, config_);

  for (uint64_t block_addr : block_starts_) {
    if (iter_state_.lifted_blocks.count(block_addr)) {
      continue;
    }

    if (!blocks_.count(block_addr)) {
      if (config_.verbose) {
        std::cerr << "Warning: no LLVM block for address 0x" << std::hex
                  << block_addr << std::dec << "\n";
      }
      continue;
    }

    llvm::BasicBlock *block = blocks_[block_addr];
    uint64_t block_end = FindBlockEnd(block_addr);

    uint64_t addr = block_addr;
    DecodedInstruction *last_instr = nullptr;

    while (addr < block_end) {
      auto instr_it = instructions_.find(addr);
      if (instr_it == instructions_.end()) {
        BlockDecoder decoder(ctx_, config_);
        decoder.SetCodeRegion(code_bytes_, code_size_, code_start_, code_end_);
        if (!decoder.DecodeBlockAt(addr, instructions_, block_starts_)) {
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

      auto lifter = decoded.instr.GetLifter();
      auto status = lifter->LiftIntoBlock(decoded.instr, block);
      if (status != remill::kLiftedInstruction) {
        std::cerr << "Failed to lift instruction: " << decoded.instr.Serialize()
                  << "\n";
        return false;
      }

      addr += decoded.size;

      if (decoded.instr.IsControlFlow()) {
        break;
      }
    }

    if (last_instr) {
      terminator.FinishBlock(block, *last_instr, addr, block_addr,
                             blocks_, block_owner_, helper_functions_,
                             iter_state_, dispatch_blocks_);
    }

    iter_state_.lifted_blocks.insert(block_addr);
  }

  return true;
}

std::set<uint64_t> ControlFlowLifter::ResolveIndirectJumps() {
  IndirectJumpResolver resolver(config_, pe_info_);

  auto find_block_end = [this](uint64_t addr) { return FindBlockEnd(addr); };
  auto get_block_owner = [this](uint64_t addr) -> uint64_t {
    auto it = block_owner_.find(addr);
    return (it != block_owner_.end()) ? it->second : 0;
  };

  return resolver.ResolveIndirectJumps(
      main_func_, entry_point_, iter_state_,
      iter_state_.lifted_blocks, find_block_end, get_block_owner);
}

bool ControlFlowLifter::LiftFunction(uint64_t code_base, uint64_t entry_point,
                                      const uint8_t *bytes, size_t size,
                                      llvm::Function *func) {
  ClearState();

  code_bytes_ = bytes;
  code_size_ = size;
  code_start_ = code_base;
  code_end_ = code_base + size;
  entry_point_ = entry_point;
  main_func_ = func;

  iter_state_.pending_blocks.insert(entry_point);
  iter_state_.block_discovery_iteration[entry_point] = 0;

  BlockDecoder decoder(ctx_, config_);
  decoder.SetCodeRegion(code_bytes_, code_size_, code_start_, code_end_);

  int iteration = 0;
  while (!iter_state_.pending_blocks.empty() &&
         iteration < config_.max_iterations) {
    if (config_.verbose) {
      std::cout << "\n=== Iteration " << iteration << " ===" << std::endl;
      std::cout << "Pending blocks: " << iter_state_.pending_blocks.size()
                << std::endl;
    }

    // Phase 1: Discover blocks reachable from pending
    std::set<uint64_t> to_process = iter_state_.pending_blocks;
    iter_state_.pending_blocks.clear();

    for (uint64_t addr : to_process) {
      decoder.DiscoverBlocksFromEntry(addr, iteration, instructions_,
                                      block_starts_, call_targets_,
                                      call_return_addrs_, iter_state_);
    }

    if (config_.verbose) {
      std::cout << "Discovered " << block_starts_.size()
                << " total blocks so far" << std::endl;
    }

    // Phase 2: Assign blocks to functions
    FunctionSplitter::AssignBlocksToFunctions(
        block_starts_, call_targets_, instructions_,
        entry_point_, code_end_, block_owner_);

    // Phase 3: Create helper functions
    FunctionSplitter::CreateHelperFunctions(
        func, call_targets_, helper_functions_);

    // Phase 4: Create LLVM basic blocks
    CreateBasicBlocksIncremental();

    // Phase 4b: Update switches with newly discovered targets
    for (auto &[jump_block_addr, sw] : iter_state_.unresolved_indirect_jumps) {
      if (!sw) continue;

      uint64_t owner = block_owner_.count(jump_block_addr) ? block_owner_[jump_block_addr] : 0;
      auto *sw_func = sw->getFunction();
      auto *entry_block = &sw_func->getEntryBlock();

      for (auto &[target_addr, target_bb] : blocks_) {
        if (!target_bb) continue;
        if (target_bb == entry_block) continue;

        uint64_t target_owner = block_owner_.count(target_addr) ? block_owner_[target_addr] : 0;
        if (target_owner != owner) continue;

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

        main_func_->print(os, nullptr);

        for (auto &[addr, helper_func] : helper_functions_) {
          os << "\n";
          helper_func->print(os, nullptr);
        }

        os.close();
        std::cout << "Written: " << filename << "\n";
      }
    }

    // Phase 6: Resolve indirect jumps
    std::set<uint64_t> new_targets = ResolveIndirectJumps();

    if (config_.verbose) {
      std::cout << "Found " << new_targets.size() << " new targets from "
                << "resolved indirect jumps" << std::endl;
    }

    for (uint64_t target : new_targets) {
      if (!iter_state_.lifted_blocks.count(target)) {
        iter_state_.pending_blocks.insert(target);
        iter_state_.block_discovery_iteration[target] = iteration + 1;
      }
    }

    iteration++;
  }

  if (iteration >= config_.max_iterations &&
      !iter_state_.pending_blocks.empty()) {
    std::cerr << "Warning: Maximum iteration limit (" << config_.max_iterations
              << ") reached with " << iter_state_.pending_blocks.size()
              << " pending blocks\n";
    std::cerr << "Unresolved indirect jumps: "
              << iter_state_.unresolved_indirect_jumps.size() << "\n";
  }

  std::cout << "Lifting completed: " << iteration << " iterations, "
            << iter_state_.lifted_blocks.size() << " blocks\n";

  if (config_.verbose) {
    std::cout << "Unresolved indirect jumps: "
              << iter_state_.unresolved_indirect_jumps.size() << std::endl;
  }

  return true;
}

// ============================================================================
// Legacy methods (kept for backwards compatibility)
// ============================================================================

bool ControlFlowLifter::DecodeBlockAt(uint64_t addr) {
  BlockDecoder decoder(ctx_, config_);
  decoder.SetCodeRegion(code_bytes_, code_size_, code_start_, code_end_);
  return decoder.DecodeBlockAt(addr, instructions_, block_starts_);
}

void ControlFlowLifter::DiscoverBlocksFromEntry(uint64_t start_addr,
                                                 int iteration) {
  BlockDecoder decoder(ctx_, config_);
  decoder.SetCodeRegion(code_bytes_, code_size_, code_start_, code_end_);
  decoder.DiscoverBlocksFromEntry(start_addr, iteration, instructions_,
                                  block_starts_, call_targets_,
                                  call_return_addrs_, iter_state_);
}

void ControlFlowLifter::AssignBlocksToFunctions() {
  FunctionSplitter::AssignBlocksToFunctions(
      block_starts_, call_targets_, instructions_,
      entry_point_, code_end_, block_owner_);
}

void ControlFlowLifter::CreateHelperFunctions(llvm::Function *main_func) {
  FunctionSplitter::CreateHelperFunctions(
      main_func, call_targets_, helper_functions_);
}

bool ControlFlowLifter::DiscoverBasicBlocks(uint64_t start_address,
                                             const uint8_t *bytes,
                                             size_t size) {
  BlockDecoder decoder(ctx_, config_);
  decoder.SetCodeRegion(bytes, size, start_address, start_address + size);
  return decoder.DiscoverBasicBlocks(start_address, bytes, size,
                                     instructions_, block_starts_);
}

void ControlFlowLifter::CreateBasicBlocks(llvm::Function *func) {
  auto &context = ctx_.GetContext();

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

    bool is_entry = (owner == 0 && addr == entry_point_) ||
                    (owner != 0 && addr == owner);

    if (is_entry && !target_func->empty()) {
      auto *entry = &target_func->getEntryBlock();
      entry->setName(name);
      blocks_[addr] = entry;
    } else if (is_entry) {
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
      auto *entry = llvm::BasicBlock::Create(context, "entry", helper_func);
      blocks_[helper_entry] = entry;
    }

    llvm::IRBuilder<> builder(&helper_func->getEntryBlock(),
                               helper_func->getEntryBlock().begin());

    builder.CreateAlloca(builder.getInt8Ty(), nullptr, "BRANCH_TAKEN");
    builder.CreateAlloca(builder.getInt64Ty(), nullptr, "RETURN_PC");

    auto *monitor = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "MONITOR");
    builder.CreateStore(builder.getInt64(0), monitor);

    auto *state_alloca = builder.CreateAlloca(builder.getPtrTy(), nullptr, "STATE");
    builder.CreateStore(helper_func->getArg(0), state_alloca);

    auto *memory_alloca = builder.CreateAlloca(builder.getPtrTy(), nullptr, "MEMORY");
    builder.CreateStore(helper_func->getArg(2), memory_alloca);

    auto *next_pc = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "NEXT_PC");
    builder.CreateStore(helper_func->getArg(1), next_pc);

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
  BlockTerminator terminator(ctx_, config_);

  for (auto it = block_starts_.begin(); it != block_starts_.end(); ++it) {
    uint64_t block_addr = *it;

    if (!blocks_.count(block_addr)) {
      std::cerr << "Warning: no LLVM block for address 0x" << std::hex
                << block_addr << std::dec << "\n";
      continue;
    }

    llvm::BasicBlock *block = blocks_[block_addr];

    auto next_it = std::next(it);
    uint64_t block_end = (next_it != block_starts_.end()) ? *next_it : code_end_;

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

      auto lifter = decoded.instr.GetLifter();
      auto status = lifter->LiftIntoBlock(decoded.instr, block);
      if (status != remill::kLiftedInstruction) {
        std::cerr << "Failed to lift instruction: " << decoded.instr.Serialize()
                  << "\n";
        return false;
      }

      addr += decoded.size;

      if (decoded.instr.IsControlFlow()) {
        break;
      }
    }

    if (last_instr) {
      terminator.FinishBlock(block, *last_instr, addr, block_addr,
                             blocks_, block_owner_, helper_functions_,
                             iter_state_, dispatch_blocks_);
    }
  }

  return true;
}

llvm::SwitchInst *ControlFlowLifter::FinishBlock(llvm::BasicBlock *block,
                                                  const DecodedInstruction &last_instr,
                                                  uint64_t next_addr,
                                                  uint64_t block_addr) {
  BlockTerminator terminator(ctx_, config_);
  return terminator.FinishBlock(block, last_instr, next_addr, block_addr,
                                blocks_, block_owner_, helper_functions_,
                                iter_state_, dispatch_blocks_);
}

// Static method kept for backwards compatibility
std::optional<uint64_t> ControlFlowLifter::EvaluateBinaryOp(
    llvm::Instruction::BinaryOps opcode, uint64_t lhs, uint64_t rhs) {
  return IndirectJumpResolver::EvaluateBinaryOp(opcode, lhs, rhs);
}

std::optional<uint64_t> ControlFlowLifter::ReadQwordFromPESections(
    uint64_t masked_offset) const {
  IndirectJumpResolver resolver(config_, pe_info_);
  return resolver.ReadQwordFromPESections(masked_offset);
}

std::optional<int64_t> ControlFlowLifter::EvaluateWithKnownPC(llvm::Value *val) {
  IndirectJumpResolver resolver(config_, pe_info_);
  return resolver.EvaluateWithKnownPC(val, entry_point_);
}

}  // namespace lifting
