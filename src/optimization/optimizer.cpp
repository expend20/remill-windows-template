#include "optimizer.h"

#include <llvm/ADT/STLExtras.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO/GlobalDCE.h>
#include <llvm/Transforms/IPO/GlobalOpt.h>
#include <llvm/Transforms/IPO/ModuleInliner.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/ADCE.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/DeadStoreElimination.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/MemCpyOptimizer.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/Scalar/SCCP.h>
#include <llvm/Transforms/IPO/SCCP.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>

namespace optimization {

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

  fpm.run(*target_func, fam);
}

void OptimizeAggressive(llvm::Module *module) {
  // Run full O3 pipeline - includes loop unrolling and constant folding
  // Only safe to run on clean modules (extracted functions without unsized types)
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

void RemoveFlagComputationIntrinsics(llvm::Module *module) {
  // Flag computation intrinsics that return their first argument
  // These are used for debugging but block optimization
  const char *identity_intrinsics[] = {
      "__remill_flag_computation_zero",
      "__remill_flag_computation_sign",
      "__remill_flag_computation_carry",
      "__remill_flag_computation_overflow",
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
