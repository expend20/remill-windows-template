#include "control_flow_lifter.h"

#include <iostream>
#include <sstream>

#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/Util.h>

#include "block_decoder.h"
#include "block_terminator.h"
#include "external_call_handler.h"
#include "function_splitter.h"
#include "indirect_jump_resolver.h"
#include "optimization/optimizer.h"
#include "utils/debug_flag.h"

namespace lifting {

ControlFlowLifter::ControlFlowLifter(LiftingContext &ctx)
    : ctx_(ctx), decoding_context_(ctx.GetArch()->CreateInitialContext()) {}

void ControlFlowLifter::SetIterativeConfig(const IterativeLiftingConfig &config) {
  config_ = config;
}

void ControlFlowLifter::SetPEInfo(const utils::PEInfo *pe_info) {
  pe_info_ = pe_info;
}

void ControlFlowLifter::SetExternalCallHandler(ExternalCallHandler *handler) {
  external_handler_ = handler;
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
  external_only_helper_configs_.clear();

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
  BlockTerminator terminator(ctx_);

  for (uint64_t block_addr : block_starts_) {
    if (iter_state_.lifted_blocks.count(block_addr)) {
      continue;
    }

    if (!blocks_.count(block_addr)) {
      utils::dbg() << "Warning: no LLVM block for address 0x"
                   << llvm::format_hex(block_addr, 0) << "\n";
      continue;
    }

    llvm::BasicBlock *block = blocks_[block_addr];
    uint64_t block_end = FindBlockEnd(block_addr);

    uint64_t addr = block_addr;
    DecodedInstruction *last_instr = nullptr;

    while (addr < block_end) {
      auto instr_it = instructions_.find(addr);
      if (instr_it == instructions_.end()) {
        BlockDecoder decoder(ctx_);
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

      // Check for external indirect call/jump BEFORE lifting to avoid dead return address store
      // This covers both:
      // - kCategoryIndirectFunctionCall: call qword ptr [IAT_addr]
      // - kCategoryIndirectJump: jmp qword ptr [IAT_addr] (tail call)
      if ((decoded.instr.category == remill::Instruction::kCategoryIndirectFunctionCall ||
           decoded.instr.category == remill::Instruction::kCategoryIndirectJump) &&
          external_handler_) {
        uint64_t mem_addr = BlockTerminator::ExtractIndirectCallMemoryAddress(decoded.instr);
        if (mem_addr != 0) {
          auto *ext_config = external_handler_->GetConfigByIATAddress(mem_addr);
          if (ext_config) {
            // Generate external call WITHOUT lifting (no return address push)
            uint64_t next_addr = addr + decoded.size;
            bool is_tail_call = (decoded.instr.category == remill::Instruction::kCategoryIndirectJump);
            GenerateExternalCallDirect(block, ext_config, next_addr, block_addr, is_tail_call);
            // Clear last_instr so FinishBlock isn't called (we already terminated the block)
            last_instr = nullptr;
            // Mark block as lifted and continue to next block
            break;
          }
        }
      }

      // Check for direct function call to an external-only helper BEFORE lifting
      // This handles: call helper_addr where helper only contains jmp [IAT_addr]
      // Without this, remill's CALL semantics would push return address creating dead store
      if (decoded.instr.category == remill::Instruction::kCategoryDirectFunctionCall) {
        uint64_t target = decoded.instr.branch_taken_pc;
        auto ext_it = external_only_helper_configs_.find(target);
        if (ext_it != external_only_helper_configs_.end()) {
          // Generate external call WITHOUT lifting (no return address push)
          uint64_t next_addr = addr + decoded.size;
          GenerateExternalCallDirect(block, ext_it->second, next_addr, block_addr, false);
          // Clear last_instr so FinishBlock isn't called (we already terminated the block)
          last_instr = nullptr;
          utils::dbg() << "Handled direct call to external-only helper at 0x"
                       << llvm::format_hex(target, 0) << " -> " << ext_it->second->name << "\n";
          // Mark block as lifted and continue to next block
          break;
        }
      }

      auto lifter = decoded.instr.GetLifter();
      auto status = lifter->LiftIntoBlock(decoded.instr, block);
      if (status != remill::kLiftedInstruction) {
        // Unsupported instruction - likely junk bytes after a noreturn call
        // Terminate the block as unreachable and continue with other blocks
        utils::dbg() << "Unsupported instruction at " << llvm::format_hex(addr, 0)
                     << ": " << decoded.instr.Serialize() << " - treating as unreachable\n";
        std::cerr << "Warning: Unsupported instruction at 0x" << std::hex << addr << std::dec
                  << ": " << decoded.instr.Serialize() << " - treating as unreachable\n";

        llvm::IRBuilder<> builder(block);
        builder.CreateUnreachable();
        last_instr = nullptr;  // Don't call FinishBlock
        break;
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

IndirectJumpResolution ControlFlowLifter::ResolveIndirectJumps() {
  IndirectJumpResolver resolver(pe_info_);

  // Return the actual instruction end, not just the next block start
  auto find_block_end = [this](uint64_t block_addr) -> uint64_t {
    uint64_t region_end = FindBlockEnd(block_addr);
    uint64_t last_addr = GetLastInstrAddr(block_addr, region_end);
    auto instr_it = instructions_.find(last_addr);
    if (instr_it != instructions_.end()) {
      return last_addr + instr_it->second.size;
    }
    return region_end;
  };
  auto get_block_owner = [this](uint64_t addr) -> uint64_t {
    auto it = block_owner_.find(addr);
    return (it != block_owner_.end()) ? it->second : 0;
  };

  return resolver.ResolveIndirectJumps(
      main_func_, entry_point_, iter_state_,
      iter_state_.lifted_blocks, find_block_end, get_block_owner);
}

void ControlFlowLifter::IdentifyExternalOnlyHelpers() {
  if (!external_handler_) {
    return;
  }

  // Check each call target to see if it's an external-only helper
  // An external-only helper is a block that contains only a single indirect jump to IAT
  for (uint64_t helper_addr : call_targets_) {
    // Find the first instruction at this address
    auto instr_it = instructions_.find(helper_addr);
    if (instr_it == instructions_.end()) {
      continue;
    }

    const auto &decoded = instr_it->second;

    // Check if this is an indirect jump (jmp qword ptr [addr])
    if (decoded.instr.category != remill::Instruction::kCategoryIndirectJump) {
      continue;
    }

    // Extract the memory address from the indirect jump
    uint64_t mem_addr = BlockTerminator::ExtractIndirectCallMemoryAddress(decoded.instr);
    if (mem_addr == 0) {
      continue;
    }

    // Check if this address is in the IAT (external function)
    auto *ext_config = external_handler_->GetConfigByIATAddress(mem_addr);
    if (ext_config) {
      external_only_helper_configs_[helper_addr] = ext_config;
      utils::dbg() << "Identified external-only helper at 0x"
                   << llvm::format_hex(helper_addr, 0)
                   << " -> " << ext_config->name << "\n";
    }
  }

  utils::dbg() << "Found " << external_only_helper_configs_.size()
               << " external-only helpers\n";
}

void ControlFlowLifter::GenerateExternalCallDirect(
    llvm::BasicBlock *block,
    const ExternalCallConfig *config,
    uint64_t next_addr,
    uint64_t block_addr,
    bool is_tail_call) {

  llvm::IRBuilder<> builder(block);
  auto *intrinsics = ctx_.GetIntrinsics();

  // Get the external function
  auto *ext_func = external_handler_->GetExternalFunction(config->name);
  if (!ext_func) {
    utils::dbg() << "External function not found: " << config->name << "\n";
    return;
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
    return;
  }

  // NOTE: Unlike GenerateExternalCall in BlockTerminator, we do NOT need to
  // undo RSP here because we skipped lifting the CALL instruction entirely.
  // No return address was pushed, so no dead store to worry about.

  // Load arguments from State registers (Win64: RCX, RDX, R8, R9)
  std::vector<llvm::Value *> args;
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
      args.push_back(builder.CreateIntToPtr(reg_val, builder.getPtrTy()));
    } else if (arg_type == "i32") {
      args.push_back(builder.CreateTrunc(reg_val, builder.getInt32Ty()));
    } else {
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

  // Get current block owner
  uint64_t current_owner = 0;
  auto owner_it = block_owner_.find(block_addr);
  if (owner_it != block_owner_.end()) {
    current_owner = owner_it->second;
  }

  // Helper to check if a target block is in the same function
  auto sameFunction = [this, current_owner](uint64_t target_addr) -> bool {
    if (!blocks_.count(target_addr)) return false;
    auto it = block_owner_.find(target_addr);
    uint64_t target_owner = (it != block_owner_.end()) ? it->second : 0;
    return target_owner == current_owner;
  };

  // Continue to next block or return
  // For tail calls (jmp [IAT]), always return after the call
  if (is_tail_call) {
    builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
    utils::dbg() << "Generated direct external tail call to " << config->name
                 << " with " << args.size() << " args (no JMP semantics)\n";
  } else if (sameFunction(next_addr)) {
    builder.CreateBr(blocks_.at(next_addr));
    utils::dbg() << "Generated direct external call to " << config->name
                 << " with " << args.size() << " args (no CALL semantics)\n";
  } else {
    builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
    utils::dbg() << "Generated direct external call to " << config->name
                 << " with " << args.size() << " args (no CALL semantics, returning)\n";
  }
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

  BlockDecoder decoder(ctx_);
  decoder.SetCodeRegion(code_bytes_, code_size_, code_start_, code_end_);

  int iteration = 0;
  while (!iter_state_.pending_blocks.empty() &&
         iteration < config_.max_iterations) {
    utils::dbg() << "\n=== Iteration " << iteration << " ===\n";
    utils::dbg() << "Pending blocks: " << iter_state_.pending_blocks.size() << "\n";

    // Phase 1: Discover blocks reachable from pending
    std::set<uint64_t> to_process = iter_state_.pending_blocks;
    iter_state_.pending_blocks.clear();

    for (uint64_t addr : to_process) {
      decoder.DiscoverBlocksFromEntry(addr, iteration, instructions_,
                                      block_starts_, call_targets_,
                                      call_return_addrs_, iter_state_);
    }

    utils::dbg() << "Discovered " << block_starts_.size()
                 << " total blocks so far\n";

    // Phase 1b: Identify external-only helpers (call targets that only contain jmp [IAT])
    IdentifyExternalOnlyHelpers();

    // Phase 1c: Queue return addresses for calls to external-only helpers
    // External calls are known to return, so their return addresses must be lifted
    for (const auto &[call_addr, ret_addr] : call_return_addrs_) {
      // Find what function this call targets
      auto instr_it = instructions_.find(call_addr);
      if (instr_it == instructions_.end()) continue;

      const auto &decoded = instr_it->second;
      if (decoded.instr.category != remill::Instruction::kCategoryDirectFunctionCall) continue;

      uint64_t target = decoded.instr.branch_taken_pc;

      // Check if this call targets an external-only helper
      if (external_only_helper_configs_.count(target)) {
        // External calls always return - queue the return address
        if (IsValidCodeAddress(ret_addr) &&
            !iter_state_.lifted_blocks.count(ret_addr) &&
            !block_starts_.count(ret_addr)) {
          block_starts_.insert(ret_addr);
          iter_state_.block_discovery_iteration[ret_addr] = iteration;
          utils::dbg() << "Queued return address " << llvm::format_hex(ret_addr, 0)
                       << " for external call to " << external_only_helper_configs_[target]->name << "\n";
        }
      }
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

    // Phase 5: Lift pending blocks (creates RET switches during lifting)
    if (!LiftPendingBlocks()) {
      return false;
    }

    // Phase 5b: Update switches with discovered targets
    // Must run AFTER LiftPendingBlocks since that's where switches are created
    //
    // For RET dispatch switches: only add CALL return addresses (from call_return_addrs_)
    // For indirect jump/call switches: add all blocks in the same function
    for (auto &[jump_block_addr, sw] : iter_state_.unresolved_indirect_jumps) {
      if (!sw) continue;

      auto *dispatch_block = sw->getParent();
      std::string dispatch_name = dispatch_block->getName().str();
      bool is_ret_dispatch = (dispatch_name.find("ret_dispatch") != std::string::npos);

      uint64_t owner = block_owner_.count(jump_block_addr) ? block_owner_[jump_block_addr] : 0;
      auto *sw_func = sw->getFunction();
      auto *entry_block = &sw_func->getEntryBlock();

      if (is_ret_dispatch) {
        // For RET dispatch, only add return address for the CALL that targets
        // the function containing this RET.
        //
        // Find the "virtual function" containing jump_block_addr:
        // - If jump_block_addr >= some call_target, it's in that function
        // - The return address for that CALL should be added as a case
        //
        // For nested calls, we find the innermost function containing the RET.
        uint64_t containing_func = 0;  // 0 means entry function
        for (uint64_t call_target : call_targets_) {
          if (call_target <= jump_block_addr && call_target > containing_func) {
            containing_func = call_target;
          }
        }

        // Find all CALLs that target this function
        for (const auto &[call_addr, ret_addr] : call_return_addrs_) {
          auto call_instr_it = instructions_.find(call_addr);
          if (call_instr_it == instructions_.end()) continue;
          uint64_t call_target = call_instr_it->second.instr.branch_taken_pc;

          // Only add case if this CALL targets the function containing the RET
          if (call_target != containing_func) continue;

          if (!blocks_.count(ret_addr)) continue;
          auto *target_bb = blocks_[ret_addr];
          if (!target_bb) continue;
          if (target_bb == entry_block) continue;

          // Don't add a case for the same block as the RET - this creates a self-loop
          if (ret_addr == jump_block_addr) continue;

          bool case_exists = false;
          for (auto case_it : sw->cases()) {
            if (case_it.getCaseValue()->getZExtValue() == ret_addr) {
              case_exists = true;
              break;
            }
          }

          if (!case_exists) {
            auto &ctx = sw->getContext();
            sw->addCase(llvm::ConstantInt::get(llvm::Type::getInt64Ty(ctx), ret_addr), target_bb);
            utils::dbg() << "Added RET case " << llvm::format_hex(ret_addr, 0)
                         << " to dispatch at " << llvm::format_hex(jump_block_addr, 0)
                         << " (in func " << llvm::format_hex(containing_func, 0) << ")\n";
          }
        }
      } else {
        // For indirect jump/call dispatch, add all blocks in same function
        for (auto &[target_addr, target_bb] : blocks_) {
          if (!target_bb) continue;
          if (target_bb == entry_block) continue;
          if (target_addr == jump_block_addr) continue;

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
            utils::dbg() << "Added case " << llvm::format_hex(target_addr, 0)
                         << " to dispatch at " << llvm::format_hex(jump_block_addr, 0) << "\n";
          }
        }
      }
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
    auto resolution = ResolveIndirectJumps();

    utils::dbg() << "Found " << resolution.new_targets.size() << " new targets from "
                 << "resolved indirect jumps\n";

    // Phase 6b: Merge new RET dispatch cases into pending list
    for (const auto &[ret_block_addr, targets] : resolution.ret_dispatch_cases) {
      for (uint64_t target : targets) {
        iter_state_.pending_ret_dispatch_cases[ret_block_addr].insert(target);
      }
    }

    // Phase 6c: Try to add all pending RET dispatch cases
    // (target blocks may have been lifted in this iteration)
    for (auto &[ret_block_addr, targets] : iter_state_.pending_ret_dispatch_cases) {
      auto sw_it = iter_state_.unresolved_indirect_jumps.find(ret_block_addr);
      if (sw_it == iter_state_.unresolved_indirect_jumps.end() || !sw_it->second)
        continue;

      auto *sw = sw_it->second;
      std::set<uint64_t> added_targets;

      for (uint64_t target : targets) {
        if (!blocks_.count(target)) continue;
        auto *target_bb = blocks_[target];
        if (!target_bb) continue;

        // Check if case already exists
        bool exists = false;
        for (auto case_it : sw->cases()) {
          if (case_it.getCaseValue()->getZExtValue() == target) {
            exists = true;
            break;
          }
        }

        if (!exists) {
          auto &ctx = sw->getContext();
          sw->addCase(llvm::ConstantInt::get(llvm::Type::getInt64Ty(ctx), target),
                      target_bb);
          utils::dbg() << "Added SCCP case " << llvm::format_hex(target, 0)
                       << " to RET dispatch at " << llvm::format_hex(ret_block_addr, 0)
                       << "\n";
        }
        added_targets.insert(target);
      }

      // Remove successfully added targets from pending list
      for (uint64_t added : added_targets) {
        targets.erase(added);
      }
    }

    for (uint64_t target : resolution.new_targets) {
      // Filter out targets outside the code section
      if (target < code_start_ || target >= code_end_) {
        utils::dbg() << "Skipping out-of-bounds target " << llvm::format_hex(target, 0)
                     << " (code range: " << llvm::format_hex(code_start_, 0)
                     << " - " << llvm::format_hex(code_end_, 0) << ")\n";
        continue;
      }
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

  utils::dbg() << "Unresolved indirect jumps: "
               << iter_state_.unresolved_indirect_jumps.size() << "\n";

  return true;
}

// ============================================================================
// Legacy methods (kept for backwards compatibility)
// ============================================================================

bool ControlFlowLifter::DecodeBlockAt(uint64_t addr) {
  BlockDecoder decoder(ctx_);
  decoder.SetCodeRegion(code_bytes_, code_size_, code_start_, code_end_);
  return decoder.DecodeBlockAt(addr, instructions_, block_starts_);
}

void ControlFlowLifter::DiscoverBlocksFromEntry(uint64_t start_addr,
                                                 int iteration) {
  BlockDecoder decoder(ctx_);
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
  BlockDecoder decoder(ctx_);
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
  BlockTerminator terminator(ctx_);

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
        // Unsupported instruction - likely junk bytes after a noreturn call
        utils::dbg() << "Unsupported instruction in helper at " << llvm::format_hex(addr, 0)
                     << ": " << decoded.instr.Serialize() << " - treating as unreachable\n";
        std::cerr << "Warning: Unsupported instruction at 0x" << std::hex << addr << std::dec
                  << ": " << decoded.instr.Serialize() << " - treating as unreachable\n";

        llvm::IRBuilder<> builder(block);
        builder.CreateUnreachable();
        last_instr = nullptr;
        break;
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
  BlockTerminator terminator(ctx_);
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
  IndirectJumpResolver resolver(pe_info_);
  return resolver.ReadQwordFromPESections(masked_offset);
}

std::optional<int64_t> ControlFlowLifter::EvaluateWithKnownPC(llvm::Value *val) {
  IndirectJumpResolver resolver(pe_info_);
  return resolver.EvaluateWithKnownPC(val, entry_point_);
}

}  // namespace lifting
