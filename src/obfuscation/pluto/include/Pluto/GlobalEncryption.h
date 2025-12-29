// Credits: https://github.com/bluesadi/Pluto/
#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"

using namespace llvm;

namespace Pluto {

struct GlobalEncryption : PassInfoMixin<GlobalEncryption> {
    Function *createArrayDecryptFunction(Module &M, GlobalVariable *GV, uint64_t key, uint64_t eleNum);
    Function *createIntDecryptFunction(Module &M, GlobalVariable *GV, uint64_t key);

    void insertArrayDecryption(Module &M, GlobalVariable *GV, uint64_t key, uint64_t eleNum);
    void insertIntDecryption(Module &M, GlobalVariable *GV, uint64_t key);

    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

    static bool isRequired() { return true; }
};

}; // namespace Pluto