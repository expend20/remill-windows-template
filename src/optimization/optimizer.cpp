#include "optimizer.h"
#include "lifting/memory_provider.h"

#include <iostream>

#include <llvm/ADT/STLExtras.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO/ModuleInliner.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/ADCE.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>

namespace optimization {

void OptimizeForCleanIR(llvm::Module *module, llvm::Function *target_func) {
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

  // Inline first - this inlines the lifted function into the wrapper
  llvm::ModulePassManager mpm;
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

  // Another round of simplification
  fpm.addPass(llvm::InstCombinePass());
  fpm.addPass(llvm::SimplifyCFGPass());

  fpm.run(*target_func, fam);
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

void ReplaceMemoryIntrinsics(llvm::Module *module,
                              const lifting::MemoryProvider *memory_provider) {
  struct IntrinsicInfo {
    const char *name;
    unsigned size;
  };

  IntrinsicInfo intrinsics[] = {
      {"__remill_read_memory_8", 1},
      {"__remill_read_memory_16", 2},
      {"__remill_read_memory_32", 4},
      {"__remill_read_memory_64", 8},
  };

  for (const auto &info : intrinsics) {
    if (auto *func = module->getFunction(info.name)) {
      for (auto &use : llvm::make_early_inc_range(func->uses())) {
        auto *call = llvm::dyn_cast<llvm::CallInst>(use.getUser());
        if (!call) {
          continue;
        }

        // Verify this is a call to the function (not another use like a function pointer)
        if (call->getCalledFunction() != func) {
          continue;
        }

        // Verify the call has the expected number of arguments
        if (call->arg_size() < 2) {
          continue;
        }

        // Get the address argument (second parameter: memory*, addr)
        llvm::Value *addr_arg = call->getArgOperand(1);

        llvm::Constant *replacement = nullptr;

        // Try to get constant address
        if (auto *addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_arg)) {
          uint64_t address = addr_const->getZExtValue();

          // Look up value in memory provider
          auto value = memory_provider->ReadMemory(address, info.size);
          if (value) {
            replacement = llvm::ConstantInt::get(call->getType(), *value);
            std::cout << "Resolved memory read at 0x" << std::hex << address
                      << " -> 0x" << *value << std::dec << "\n";
          }
        }

        // Fall back to undef for unknown addresses
        if (!replacement) {
          replacement = llvm::UndefValue::get(call->getType());
        }

        call->replaceAllUsesWith(replacement);
        call->eraseFromParent();
      }
    }
  }
}

}  // namespace optimization
