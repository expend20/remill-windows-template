#include "optimizer.h"

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

void OptimizeAggressive(llvm::Module *module) {
  // Run aggressive optimization pipeline for deobfuscation.
  // Uses llvm.loop.unroll.full metadata to force full loop unrolling
  // regardless of cost threshold.

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

  // Run O3 first for general optimization
  llvm::ModulePassManager mpm = pb.buildPerModuleDefaultPipeline(
      llvm::OptimizationLevel::O3);
  mpm.run(*module, mam);

  // Mark all loops with llvm.loop.unroll.full metadata and run unroller.
  // This bypasses the cost threshold and forces full unrolling.
  // Run multiple rounds to handle nested loops and propagate constants.
  llvm::LoopUnrollOptions unroll_opts;
  unroll_opts.setOptLevel(3);
  unroll_opts.setFullUnrollMaxCount(256);

  for (int round = 0; round < 3; ++round) {
    llvm::FunctionPassManager fpm;

    // Mark loops for forced full unrolling
    fpm.addPass(ForceFullUnrollPass());

    // Run loop unroller (will respect the metadata)
    fpm.addPass(llvm::LoopUnrollPass(unroll_opts));

    // Simplification passes to fold constants after unrolling
    fpm.addPass(llvm::SROAPass(llvm::SROAOptions::ModifyCFG));
    fpm.addPass(llvm::GVNPass());
    fpm.addPass(llvm::SCCPPass());
    fpm.addPass(llvm::InstCombinePass());
    fpm.addPass(llvm::SimplifyCFGPass());
    fpm.addPass(llvm::ADCEPass());

    llvm::ModulePassManager round_mpm;
    round_mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
    round_mpm.run(*module, mam);
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
  // Minimal optimization for switch resolution during iterative lifting
  // Goal: propagate constants through the CFG to resolve switch selectors
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

  // Module-level: inline helper functions
  llvm::ModulePassManager mpm;
  mpm.addPass(llvm::ModuleInlinerPass(llvm::getInlineParams(500)));
  mpm.run(*module, mam);

  // First, run function-level optimization on the target function
  llvm::FunctionPassManager fpm;

  // SROA: Break up State alloca into scalars
  fpm.addPass(llvm::SROAPass(llvm::SROAOptions::ModifyCFG));

  // Promote allocas to SSA
  fpm.addPass(llvm::PromotePass());

  // GVN: Forward stores to loads through memory aliasing
  // Critical for resolving PC loads where store is through different GEP
  fpm.addPass(llvm::GVNPass());

  // Fold constant expressions
  fpm.addPass(llvm::InstCombinePass());

  fpm.run(*target_func, fam);

  // Now run IPSCCP (interprocedural SCCP) to propagate constants across function calls
  // This is needed because the lifted function is called with a constant entry point
  // from the test() wrapper function
  llvm::ModulePassManager mpm2;
  mpm2.addPass(llvm::IPSCCPPass());
  mpm2.run(*module, mam);

  // Run another round of function-level optimization after IPSCCP
  llvm::FunctionPassManager fpm2;
  fpm2.addPass(llvm::GVNPass());
  fpm2.addPass(llvm::InstCombinePass());
  fpm2.run(*target_func, fam);
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

}  // namespace optimization
