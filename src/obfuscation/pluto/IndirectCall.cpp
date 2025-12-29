// Credits: https://github.com/bluesadi/Pluto/
//
// TODO(IndirectCall): INDEX IS NOT ACTUALLY USED - MBA OBFUSCATION WON'T WORK!
// ================================================================================
//
// The original Pluto implementation stored function pointers in a ConstantArray and used
// an index to GEP into it. The index computation pattern (alloca -> store 0 -> load -> add)
// was designed to be obfuscated by MBAObfuscation pass.
//
// PROBLEM: LLVM 19's opaque pointers and constant uniquing cause crashes when:
//   1. We create a ConstantArray containing Function* pointers
//   2. Then modify CallInsts that call those functions (setCalledOperand or eraseFromParent)
//   3. LLVM's constant table gets corrupted: "Constant not found in constant table!"
//
// CURRENT WORKAROUND: Use individual GlobalVariables for each function pointer instead of
// a ConstantArray. This avoids the crash but means:
//   - The computed index is DEAD CODE and gets optimized away
//   - MBAObfuscation has nothing meaningful to transform
//   - The indirect calls still work, but without index obfuscation
//
// TO PROPERLY FIX THIS, one of these approaches is needed:
//
//   1. SWITCH-BASED DISPATCH: Use the index in a switch statement to select which
//      GlobalVariable to load from. The switch cases would be:
//        switch(obfuscated_index) {
//          case 0: funcPtr = load @global0; break;
//          case 1: funcPtr = load @global1; break;
//          ...
//        }
//      This preserves the index for MBA obfuscation.
//
//   2. RUNTIME INITIALIZATION: Create a zero-initialized array and fill it at runtime
//      using a constructor function (.init_array / llvm.global_ctors). This avoids
//      the ConstantArray issue entirely since Function* are only used in store
//      instructions, not in constant initializers.
//
//   3. INTEGER ADDRESSES: Store ptrtoint(Function*) as i64 in the array instead of
//      raw Function* pointers. Then inttoptr when loading. However, ConstantExpr::getPtrToInt
//      still references the Function* and causes the same crash.
//
//   4. FIX LLVM INTERACTION: Understand why setCalledOperand/eraseFromParent triggers
//      constant table corruption when Function* exists in a ConstantArray. May need to
//      clone/recreate the array after modifications, or use RAUW differently.
//
// ================================================================================

#include "Pluto/IndirectCall.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <algorithm>
#include <random>
#include <vector>
#include <map>

namespace Pluto {

PreservedAnalyses Pluto::IndirectCall::run(Module &M, ModuleAnalysisManager &AM) {
    LLVMContext &context = M.getContext();

    // Step 1: Collect all internal/private functions
    std::vector<Function *> functions;
    for (Function &F : M) {
        if (F.size() && (F.hasInternalLinkage() || F.hasPrivateLinkage())) {
            functions.push_back(&F);
        }
    }

    if (functions.empty()) {
        return PreservedAnalyses::all();
    }

    // Step 2: Collect all call sites that need to be modified (before creating the table)
    struct CallSiteInfo {
        CallInst *CI;
        Function *Callee;
        Function *Caller;
    };
    std::vector<CallSiteInfo> callSites;

    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                    Function *callee = CI->getCalledFunction();
                    if (callee && std::find(functions.begin(), functions.end(), callee) != functions.end()) {
                        callSites.push_back({CI, callee, &F});
                    }
                }
            }
        }
    }

    if (callSites.empty()) {
        return PreservedAnalyses::all();
    }

    // Step 3: Shuffle the function order
    std::random_device rd;
    std::default_random_engine rng(rd());
    std::shuffle(functions.begin(), functions.end(), rng);

    // Create index map
    std::map<Function *, int> funcToIndex;
    for (size_t i = 0; i < functions.size(); ++i) {
        funcToIndex[functions[i]] = i;
    }

    // Step 4: Create individual global variables for each function pointer
    // This avoids LLVM constant uniquing issues that occur with ConstantArray
    PointerType *ptrTy = PointerType::get(context, 0);
    Type *i32Ty = Type::getInt32Ty(context);
    std::vector<GlobalVariable *> funcPtrGlobals;

    for (Function *F : functions) {
        // Create a mutable global variable holding the function pointer
        GlobalVariable *GV = new GlobalVariable(
            M, ptrTy, false, GlobalVariable::PrivateLinkage, F,
            ".indcall." + F->getName().str());
        funcPtrGlobals.push_back(GV);
    }

    // Step 5: Modify all collected call sites
    IRBuilder<> builder(context);
    for (auto &info : callSites) {
        CallInst *CI = info.CI;
        Function *callee = info.Callee;
        Function *caller = info.Caller;

        // Find the correct index of current callee and corresponding global
        int calleeIndex = funcToIndex[callee];
        GlobalVariable *funcPtrGV = funcPtrGlobals[calleeIndex];

        // TODO: This index computation is DEAD CODE - see TODO at top of file!
        // It was meant for MBAObfuscation but doesn't work with the current
        // individual-globals workaround. Keeping it here as a placeholder for
        // when a proper fix is implemented.
        builder.SetInsertPoint(&caller->getEntryBlock().front());
        AllocaInst *indexPtr = builder.CreateAlloca(i32Ty, nullptr, "indcall.idx");
        builder.CreateStore(ConstantInt::get(i32Ty, 0), indexPtr);
        Value *loadedZero = builder.CreateLoad(i32Ty, indexPtr);
        Value *index = builder.CreateAdd(loadedZero, ConstantInt::get(i32Ty, calleeIndex));
        (void)index;  // Unused - will be optimized away

        // Insert before the call instruction itself
        builder.SetInsertPoint(CI);

        // Load the function pointer from the global variable
        Value *loadedPtr = builder.CreateLoad(ptrTy, funcPtrGV);
        CI->setCalledOperand(loadedPtr);
    }

    PreservedAnalyses PA;
    PA.preserveSet<CFGAnalyses>();
    return PA;
}

}; // namespace Pluto