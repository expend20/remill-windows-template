#include "optimizer.h"
#include "stack_slot_splitter.h"

#include <algorithm>
#include <climits>
#include <cstdint>
#include <map>
#include <optional>
#include <set>

#include <llvm/ADT/STLExtras.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Error.h>
#include <llvm/Transforms/IPO/GlobalDCE.h>
#include <llvm/Transforms/IPO/GlobalOpt.h>
#include <llvm/Transforms/IPO/ModuleInliner.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/ADCE.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/DeadStoreElimination.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/LoopUnrollPass.h>
#include <llvm/Transforms/Scalar/MemCpyOptimizer.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/Scalar/SCCP.h>
#include <llvm/Transforms/IPO/SCCP.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>
#include <llvm/Transforms/Utils/LowerSwitch.h>
#include <llvm/Transforms/Utils/LoopSimplify.h>
#include <llvm/Transforms/Utils/LCSSA.h>

namespace optimization {

namespace {

// Pass to mark all loops with llvm.loop.unroll.full metadata.
// This forces the loop unroller to fully unroll regardless of cost.
class ForceFullUnrollPass : public llvm::PassInfoMixin<ForceFullUnrollPass> {
public:
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &AM) {
    auto &LI = AM.getResult<llvm::LoopAnalysis>(F);
    if (LI.empty())
      return llvm::PreservedAnalyses::all();

    llvm::MDBuilder MDB(F.getContext());
    bool changed = false;

    for (llvm::Loop *L : LI) {
      markLoopForFullUnroll(L, MDB, changed);
    }

    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
  }

private:
  void markLoopForFullUnroll(llvm::Loop *L, llvm::MDBuilder &MDB,
                              bool &changed) {
    // Process nested loops first
    for (llvm::Loop *SubLoop : *L) {
      markLoopForFullUnroll(SubLoop, MDB, changed);
    }

    // Get the loop latch's terminator to attach metadata
    if (llvm::BasicBlock *Latch = L->getLoopLatch()) {
      if (llvm::Instruction *Term = Latch->getTerminator()) {
        // Create llvm.loop.unroll.full metadata
        llvm::LLVMContext &Ctx = Term->getContext();
        llvm::MDNode *FullUnroll = llvm::MDNode::get(
            Ctx, llvm::MDString::get(Ctx, "llvm.loop.unroll.full"));

        // Create loop ID with the unroll metadata
        llvm::SmallVector<llvm::Metadata *, 4> MDs;
        MDs.push_back(nullptr);  // Placeholder for self-reference
        MDs.push_back(FullUnroll);

        llvm::MDNode *LoopID = llvm::MDNode::get(Ctx, MDs);
        LoopID->replaceOperandWith(0, LoopID);  // Self-reference

        Term->setMetadata(llvm::LLVMContext::MD_loop, LoopID);
        changed = true;
      }
    }
  }
};

}  // namespace

void OptimizeForCleanIR(llvm::Module *module, llvm::Function *target_func) {
  // Initial optimization pass - inline and simplify
  // Safe to run on modules with unsized types (like remill semantics module)
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

  // Module-level passes
  llvm::ModulePassManager mpm;

  // Inline first - this inlines the lifted function into the wrapper
  mpm.addPass(llvm::ModuleInlinerPass(llvm::getInlineParams(500)));

  mpm.run(*module, mam);

  // Function-level optimization on the target function
  llvm::FunctionPassManager fpm;

  // SROA: Break up the State alloca into individual scalar allocas
  fpm.addPass(llvm::SROAPass(llvm::SROAOptions::ModifyCFG));

  // Promote allocas to SSA registers
  fpm.addPass(llvm::PromotePass());

  // SCCP: Sparse Conditional Constant Propagation
  // Critical for resolving indirect jump targets
  fpm.addPass(llvm::SCCPPass());

  // Simplify instructions
  fpm.addPass(llvm::InstCombinePass());

  // Simplify CFG (remove dead blocks, etc.)
  fpm.addPass(llvm::SimplifyCFGPass());

  // Dead code elimination
  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::ADCEPass());

  // Common subexpression elimination
  fpm.addPass(llvm::EarlyCSEPass(true));

  // GVN - can forward stores to loads through memory
  fpm.addPass(llvm::GVNPass());

  // MemCpyOpt - can forward from memset/stores to loads
  fpm.addPass(llvm::MemCpyOptPass());

  // DSE - dead store elimination
  fpm.addPass(llvm::DSEPass());

  // Another round of SROA after GVN
  fpm.addPass(llvm::SROAPass(llvm::SROAOptions::ModifyCFG));

  // Another round of simplification
  fpm.addPass(llvm::InstCombinePass());
  fpm.addPass(llvm::SimplifyCFGPass());

  // Dead code elimination
  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::ADCEPass());

  // Final SCCP + SimplifyCFG to resolve indirect jumps
  // After all inlining and optimization, switch selectors should be constants
  fpm.addPass(llvm::SCCPPass());
  fpm.addPass(llvm::SimplifyCFGPass());

  fpm.run(*target_func, fam);
}

// Helper to run O3 pipeline with fresh analysis managers
// Each phase needs fresh managers because cached analyses become stale after transforms
static void runO3Pipeline(llvm::Module *module) {
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

  llvm::ModulePassManager mpm = pb.buildPerModuleDefaultPipeline(
      llvm::OptimizationLevel::O3);
  mpm.run(*module, mam);
}

// Forward declaration
void CleanupDeadStackStores(llvm::Module *module);

void OptimizeAggressive(llvm::Module *module) {
  // Aggressive optimization pipeline for deobfuscation.
  // Structure: 2x O3 -> force unroll -> O3 -> cleanup
  // IMPORTANT: Each phase needs fresh analysis managers - shared managers
  // cause stale cached analyses that break loop unrolling.
  // The 2x O3 before unrolling is needed to propagate constants from .rdata
  // through complex control flow before the loop can be analyzed for unrolling.

  // Phase 1: First O3 - propagates constants from .rdata into computations
  runO3Pipeline(module);

  // Phase 2: Second O3 - cascades constant propagation for loop analysis
  runO3Pipeline(module);

  // Phase 3: Force full unroll on all loops
  {
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

    llvm::FunctionPassManager fpm;
    fpm.addPass(ForceFullUnrollPass());

    llvm::ModulePassManager mpm;
    mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
    mpm.run(*module, mam);
  }

  // Phase 4: Third O3 - unrolls with forced metadata and constant folds
  runO3Pipeline(module);

  // Phase 5: Clean up dead stores that DSE missed
  // DSE can't eliminate stores to stack alloca when external calls like puts
  // have memory(argmem: read) - it doesn't know how many bytes they read.
  // We clean up stores that are clearly xorstr bookkeeping (storing stack addresses
  // or XOR key data that's not part of the actual string).
  CleanupDeadStackStores(module);
}

// Describes how a function reads from a pointer argument
enum class ReadSemantics {
  NullTerminated,  // Read until null byte (puts, printf, strlen, etc.)
  SizedBuffer,     // Read N bytes from size argument
  Unknown          // Unknown - be conservative, keep all stores forward
};

struct FunctionReadInfo {
  ReadSemantics semantics;
  unsigned ptr_arg_index;    // Which argument is the pointer
  unsigned size_arg_index;   // Which argument is the size (for SizedBuffer)
  unsigned size_arg_index2;  // Second size arg for fwrite (size * nmemb), -1 if unused
};

// Get read semantics for known functions
static std::optional<FunctionReadInfo> getFunctionReadInfo(llvm::StringRef name, unsigned arg_index) {
  // Null-terminated string functions (read until null)
  static const std::set<std::string> null_term_funcs = {
    "puts", "printf", "sprintf", "snprintf", "fprintf",
    "strlen", "strcpy", "strncpy", "strcat", "strncat",
    "strcmp", "strncmp", "strchr", "strrchr", "strstr",
    "atoi", "atol", "atoll", "atof", "strtol", "strtoll", "strtod",
    "fputs", "puts_s", "printf_s", "wprintf",
    // Windows variants
    "_putws", "wprintf", "fputws"
  };

  // Sized buffer functions: {ptr_arg, size_arg, size_arg2 (-1 if none)}
  struct SizedInfo { unsigned ptr_arg; unsigned size_arg; unsigned size_arg2; };
  static const std::map<std::string, SizedInfo> sized_funcs = {
    {"memcpy",   {1, 2, UINT_MAX}},  // memcpy(dst, src, n) - src is arg 1
    {"memmove",  {1, 2, UINT_MAX}},  // memmove(dst, src, n)
    {"memcmp",   {0, 2, UINT_MAX}},  // memcmp(s1, s2, n) - both args read
    {"memchr",   {0, 2, UINT_MAX}},  // memchr(s, c, n)
    {"write",    {1, 2, UINT_MAX}},  // write(fd, buf, n)
    {"_write",   {1, 2, UINT_MAX}},  // Windows _write
    {"fwrite",   {0, 1, 2}},         // fwrite(ptr, size, nmemb, stream) - size*nmemb
    {"send",     {1, 2, UINT_MAX}},  // send(sock, buf, len, flags)
    {"sendto",   {1, 2, UINT_MAX}},  // sendto(sock, buf, len, ...)
  };

  std::string func_name = name.str();

  // Check null-terminated functions
  if (null_term_funcs.count(func_name)) {
    // For most string functions, arg 0 is the string
    // Special cases handled below
    unsigned expected_ptr_arg = 0;

    // printf family: format string is arg 0
    // strcpy/strcat: src is arg 1
    if (func_name == "strcpy" || func_name == "strncpy" ||
        func_name == "strcat" || func_name == "strncat") {
      expected_ptr_arg = 1;  // src argument
    }

    if (arg_index == expected_ptr_arg) {
      return FunctionReadInfo{ReadSemantics::NullTerminated, expected_ptr_arg, 0, UINT_MAX};
    }
    // Also mark arg 0 as null-terminated for strcmp (both args are strings)
    if ((func_name == "strcmp" || func_name == "strncmp") && arg_index <= 1) {
      return FunctionReadInfo{ReadSemantics::NullTerminated, arg_index, 0, UINT_MAX};
    }
  }

  // Check sized buffer functions
  auto it = sized_funcs.find(func_name);
  if (it != sized_funcs.end()) {
    const auto& info = it->second;
    if (arg_index == info.ptr_arg) {
      return FunctionReadInfo{ReadSemantics::SizedBuffer, info.ptr_arg, info.size_arg, info.size_arg2};
    }
    // memcmp reads from both args
    if (func_name == "memcmp" && arg_index == 1) {
      return FunctionReadInfo{ReadSemantics::SizedBuffer, 1, 2, UINT_MAX};
    }
  }

  // Unknown function - return unknown semantics
  return FunctionReadInfo{ReadSemantics::Unknown, arg_index, 0, UINT_MAX};
}

void CleanupDeadStackStores(llvm::Module *module) {
  // Generic dead store elimination for stack allocas.
  // DSE can't eliminate stores when external calls have memory(argmem: read)
  // because it doesn't know how many bytes they read.
  //
  // Our approach:
  // 1. For null-terminated string functions (puts, printf): scan for null terminator
  // 2. For sized buffer functions (memcpy, write): use size argument
  // 3. For unknown functions: keep all stores from pointer offset forward (conservative)

  for (auto &F : *module) {
    if (F.isDeclaration()) continue;

    // Find the stack alloca
    llvm::AllocaInst *stack_alloca = nullptr;
    for (auto &I : F.getEntryBlock()) {
      if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
        if (alloca->getName() == "__stack_local") {
          stack_alloca = alloca;
          break;
        }
      }
    }
    if (!stack_alloca) continue;

    auto &DL = module->getDataLayout();

    // Collect info about each pointer argument to external calls
    struct LiveRange {
      int64_t start;
      int64_t end;        // -1 means "until null terminator"
      bool scan_for_null; // If true, scan for null; if false, use fixed end
    };
    std::vector<LiveRange> live_ranges;

    for (auto &BB : F) {
      for (auto &I : BB) {
        auto *call = llvm::dyn_cast<llvm::CallInst>(&I);
        if (!call) continue;

        auto *callee = call->getCalledFunction();
        llvm::StringRef func_name = callee ? callee->getName() : "";

        // Check each argument
        for (unsigned i = 0; i < call->arg_size(); ++i) {
          auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(call->getArgOperand(i));
          if (!gep || gep->getPointerOperand() != stack_alloca) continue;

          // Get the constant offset
          llvm::APInt offset_ap(64, 0);
          if (!gep->accumulateConstantOffset(DL, offset_ap)) continue;
          int64_t offset = offset_ap.getSExtValue();

          // Get function semantics
          auto info = getFunctionReadInfo(func_name, i);
          if (!info) continue;

          switch (info->semantics) {
            case ReadSemantics::NullTerminated:
              live_ranges.push_back({offset, -1, true});
              break;

            case ReadSemantics::SizedBuffer: {
              // Try to get size from the size argument
              int64_t size = -1;
              if (info->size_arg_index < call->arg_size()) {
                if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(info->size_arg_index))) {
                  size = ci->getSExtValue();
                  // Handle fwrite(ptr, size, nmemb, stream) - multiply size * nmemb
                  if (info->size_arg_index2 != UINT_MAX && info->size_arg_index2 < call->arg_size()) {
                    if (auto *ci2 = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(info->size_arg_index2))) {
                      size *= ci2->getSExtValue();
                    } else {
                      size = -1;  // Non-constant, be conservative
                    }
                  }
                }
              }
              if (size > 0) {
                live_ranges.push_back({offset, offset + size, false});
              } else {
                // Couldn't determine size, keep all forward
                live_ranges.push_back({offset, INT64_MAX, false});
              }
              break;
            }

            case ReadSemantics::Unknown:
              // Unknown function - keep all stores from this offset forward
              live_ranges.push_back({offset, INT64_MAX, false});
              break;
          }
        }
      }
    }

    // If no live ranges found, don't remove anything
    if (live_ranges.empty()) continue;

    // Collect all stores with their offsets
    struct StoreInfo {
      llvm::StoreInst *store;
      int64_t offset;
      int64_t size;
      bool contains_null;
    };
    std::vector<StoreInfo> stores;

    for (auto &BB : F) {
      for (auto &I : BB) {
        auto *store = llvm::dyn_cast<llvm::StoreInst>(&I);
        if (!store) continue;

        auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(store->getPointerOperand());
        if (!gep || gep->getPointerOperand() != stack_alloca) continue;

        llvm::APInt offset_ap(64, 0);
        if (!gep->accumulateConstantOffset(DL, offset_ap)) continue;

        int64_t offset = offset_ap.getSExtValue();
        int64_t size = DL.getTypeStoreSize(store->getValueOperand()->getType());

        // Check if the stored value contains a null byte
        bool contains_null = false;
        if (auto *ci = llvm::dyn_cast<llvm::ConstantInt>(store->getValueOperand())) {
          uint64_t val = ci->getZExtValue();
          for (int64_t j = 0; j < size; j++) {
            if (((val >> (j * 8)) & 0xFF) == 0) {
              contains_null = true;
              break;
            }
          }
        }

        stores.push_back({store, offset, size, contains_null});
      }
    }

    // Sort stores by offset
    std::sort(stores.begin(), stores.end(), [](const StoreInfo &a, const StoreInfo &b) {
      return a.offset < b.offset;
    });

    // For each live range, mark stores as live
    std::set<llvm::StoreInst *> live_stores;
    for (const auto &range : live_ranges) {
      bool found_null = false;
      for (const auto &si : stores) {
        // Skip stores entirely before this range
        if (si.offset + si.size <= range.start) continue;

        // For null-terminated: stop after finding null
        if (range.scan_for_null && found_null) break;

        // For fixed-size: stop when we're past the end
        if (!range.scan_for_null && si.offset >= range.end) break;

        // Keep this store if it overlaps with the range
        int64_t range_end = range.scan_for_null ? INT64_MAX : range.end;
        if (si.offset < range_end && si.offset + si.size > range.start) {
          live_stores.insert(si.store);

          if (range.scan_for_null && si.contains_null) {
            found_null = true;
          }
        }
      }
    }

    // Remove stores not in live_stores
    std::vector<llvm::Instruction *> to_remove;
    for (const auto &si : stores) {
      if (live_stores.find(si.store) == live_stores.end()) {
        to_remove.push_back(si.store);
      }
    }

    for (auto *I : to_remove) {
      I->eraseFromParent();
    }
  }

  // Run DCE to clean up unused GEPs
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

  llvm::FunctionPassManager fpm;
  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::ADCEPass());

  llvm::ModulePassManager mpm;
  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
  mpm.run(*module, mam);
}

void OptimizeWithoutDSE(llvm::Module *module) {
  // Minimal optimization to fold XOR/loop computations while keeping stores alive.
  // CRITICAL: We only run SCCP + InstCombine. No GVN/EarlyCSE which forward loads
  // through stores (making stores appear dead) and no SimplifyCFG which can
  // eliminate useless code including allocas.

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

  // Minimal constant folding - just SCCP and InstCombine
  auto runMinimalFolding = [&]() {
    llvm::FunctionPassManager fpm;
    fpm.addPass(llvm::SCCPPass());
    fpm.addPass(llvm::InstCombinePass());

    llvm::ModulePassManager mpm;
    mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
    mpm.run(*module, mam);
  };

  // Phase 1: Force full unroll on all loops first
  {
    llvm::FunctionPassManager fpm;
    fpm.addPass(llvm::LoopSimplifyPass());
    fpm.addPass(llvm::LCSSAPass());
    fpm.addPass(ForceFullUnrollPass());
    fpm.addPass(llvm::LoopUnrollPass());

    llvm::ModulePassManager mpm;
    mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
    mpm.run(*module, mam);
  }

  // Phase 2: Multiple rounds of constant folding
  for (int i = 0; i < 4; ++i) {
    runMinimalFolding();
  }
}

void RemoveMemoryIntrinsics(llvm::Module *module) {
  // List of memory intrinsics to remove
  const char *intrinsic_names[] = {
      "__remill_read_memory_8",  "__remill_read_memory_16",
      "__remill_read_memory_32", "__remill_read_memory_64",
  };

  for (const char *name : intrinsic_names) {
    if (auto *func = module->getFunction(name)) {
      for (auto &use : llvm::make_early_inc_range(func->uses())) {
        if (auto *call = llvm::dyn_cast<llvm::CallInst>(use.getUser())) {
          call->replaceAllUsesWith(llvm::UndefValue::get(call->getType()));
          call->eraseFromParent();
        }
      }
    }
  }
}

void OptimizeForResolution(llvm::Module *module, llvm::Function *target_func) {
  // Optimization for switch resolution during iterative lifting
  // Goal: propagate constants through the CFG to resolve switch selectors
  // Key challenge: loops (like xtea's 32 iterations) create phi nodes that
  // prevent SCCP from tracing RSP/stack values. We need loop unrolling.

  // Single analysis manager for all phases (avoid recreation overhead)
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

  // Phase 1: Inline + IPSCCP to propagate entry point constant
  {
    llvm::ModulePassManager mpm;
    mpm.addPass(llvm::ModuleInlinerPass(llvm::getInlineParams(500)));
    mpm.addPass(llvm::IPSCCPPass());
    mpm.run(*module, mam);
  }

  // Phase 2: Force full unroll metadata + O2 pipeline
  // O2 includes SROA, GVN, InstCombine, loop unrolling - no need for separate phases
  {
    // Mark loops for full unroll
    llvm::FunctionPassManager fpm;
    fpm.addPass(ForceFullUnrollPass());
    llvm::ModulePassManager mpm;
    mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
    mpm.run(*module, mam);
  }

  // Phase 3: Run O2 (handles SROA, GVN, InstCombine, loop unroll, etc.)
  {
    llvm::ModulePassManager mpm = pb.buildPerModuleDefaultPipeline(
        llvm::OptimizationLevel::O2);
    mpm.run(*module, mam);
  }
}

void RemoveFlagComputationIntrinsics(llvm::Module *module) {
  // Flag computation intrinsics that return their first argument
  // These are used for debugging but block optimization
  const char *identity_intrinsics[] = {
      "__remill_flag_computation_zero",
      "__remill_flag_computation_sign",
      "__remill_flag_computation_carry",
      "__remill_flag_computation_overflow",
      // Comparison intrinsics - all return their argument unchanged
      "__remill_compare_sle",
      "__remill_compare_slt",
      "__remill_compare_sge",
      "__remill_compare_sgt",
      "__remill_compare_ule",
      "__remill_compare_ult",
      "__remill_compare_ugt",
      "__remill_compare_uge",
      "__remill_compare_eq",
      "__remill_compare_neq",
  };

  std::vector<llvm::Function *> to_delete;

  for (const char *name : identity_intrinsics) {
    if (auto *func = module->getFunction(name)) {
      for (auto &use : llvm::make_early_inc_range(func->uses())) {
        if (auto *call = llvm::dyn_cast<llvm::CallInst>(use.getUser())) {
          // Replace call with first argument (the computed flag value)
          if (call->arg_size() >= 1) {
            call->replaceAllUsesWith(call->getArgOperand(0));
            call->eraseFromParent();
          }
        }
      }
      to_delete.push_back(func);
    }
  }

  // Remove __remill_undefined_8 - replace with undef
  if (auto *func = module->getFunction("__remill_undefined_8")) {
    for (auto &use : llvm::make_early_inc_range(func->uses())) {
      if (auto *call = llvm::dyn_cast<llvm::CallInst>(use.getUser())) {
        call->replaceAllUsesWith(llvm::UndefValue::get(call->getType()));
        call->eraseFromParent();
      }
    }
    to_delete.push_back(func);
  }

  // Delete the unused declarations
  for (auto *func : to_delete) {
    if (func->use_empty()) {
      func->eraseFromParent();
    }
  }
}

void PropagateConstants(llvm::Module *module) {
  // Run SCCP and basic simplification
  // This propagates constant values while keeping stores that feed into
  // external call arguments alive
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

  llvm::FunctionPassManager fpm;

  // SCCP: Sparse conditional constant propagation
  fpm.addPass(llvm::SCCPPass());

  // InstCombine: Fold constant expressions
  fpm.addPass(llvm::InstCombinePass());

  // SimplifyCFG: Clean up unreachable blocks
  fpm.addPass(llvm::SimplifyCFGPass());

  llvm::ModulePassManager mpm;
  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
  mpm.run(*module, mam);
}

}  // namespace optimization
