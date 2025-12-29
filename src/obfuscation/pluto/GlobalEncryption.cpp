// Credits: https://github.com/bluesadi/Pluto/
#include "Pluto/GlobalEncryption.h"

#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/FormatVariadic.h"
#include "Pluto/CryptoUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <vector>

namespace Pluto {

bool shouldSkip(GlobalVariable &GV) {
    // Do not encrypt LLVM-generated GV like llvm.global_ctors
    if (GV.getName().starts_with("llvm.")) {
        return true;
    }
    // Only encrypt GV with internal or private linkage
    // Other linkages may cause problem. For example, if a GV has LinkOnce linkage, two global variables in two modules
    // with the same name will be merged into one GV at link-time and the merged GV will be decrypted twice (the two
    // decrypt functions are not merged).
    // Reference: https://llvm.org/docs/LangRef.html#linkage-types
    if (!GV.hasInternalLinkage() && !GV.hasPrivateLinkage()) {
        return true;
    }
    // Encrypt the GV only if it's an integer or integer array
    if (!GV.getValueType()->isIntegerTy() &&
        (!GV.getValueType()->isArrayTy() || !cast<ArrayType>(GV.getValueType())->getElementType()->isIntegerTy())) {
        return true;
    }
    // Make sure the GV has an initializer
    if (!GV.hasInitializer() || !GV.getInitializer()) {
        return true;
    }
    // Make sure the GV doesn't belong to any custom section (which means it belongs .data section by default)
    // We conservatively skip data in custom section to avoid unexpected behaviors after obfuscation
    if (GV.hasSection()) {
        return true;
    }
    return false;
}

PreservedAnalyses GlobalEncryption::run(Module &M, ModuleAnalysisManager &AM) {
    std::vector<GlobalVariable *> GVs;
    for (auto &GV : M.globals()) {
        if (!shouldSkip(GV)) {
            GVs.push_back(&GV);
        }
    }

    // Collect all modifications first to avoid issues with constant uniquing
    struct IntMod {
        GlobalVariable *GV;
        uint64_t encValue;
        uint64_t key;
    };
    struct ArrayMod {
        GlobalVariable *GV;
        std::vector<char> encData;
        uint64_t key;
        uint64_t eleNum;
        Type *eleType;
    };
    std::vector<IntMod> intMods;
    std::vector<ArrayMod> arrayMods;

    for (auto *GV : GVs) {
        if (ConstantInt *dataInt = dyn_cast<ConstantInt>(GV->getInitializer())) {
            IntMod mod;
            mod.GV = GV;
            mod.key = cryptoutils->get_uint64_t();
            mod.encValue = mod.key ^ dataInt->getZExtValue();
            intMods.push_back(mod);
        } else if (ConstantDataArray *dataArr = dyn_cast<ConstantDataArray>(GV->getInitializer())) {
            ArrayMod mod;
            mod.GV = GV;
            mod.eleType = dataArr->getElementType();
            mod.eleNum = dataArr->getNumElements();
            mod.key = cryptoutils->get_uint64_t();

            // Store encrypted values for each element (to be stored as code constants)
            StringRef rawData = dataArr->getRawDataValues();
            uint64_t eleByteSize = mod.eleType->getPrimitiveSizeInBits() / 8;
            mod.encData.resize(rawData.size());
            for (uint64_t i = 0; i < mod.eleNum; i++) {
                uint64_t val = 0;
                memcpy(&val, rawData.data() + i * eleByteSize, eleByteSize);
                uint64_t encVal = val ^ mod.key;
                memcpy(mod.encData.data() + i * eleByteSize, &encVal, eleByteSize);
            }
            arrayMods.push_back(mod);
        }
    }

    if (intMods.empty() && arrayMods.empty()) {
        return PreservedAnalyses::all();
    }

    // ============================================================================
    // WARNING: NAIVE ENTRY POINT DETECTION - THIS IS FUNDAMENTALLY FLAWED!
    // ============================================================================
    // This code simply picks the FIRST non-declaration function in the module
    // and assumes it's the entry point. This is incorrect for several reasons:
    //
    // 1. The first function in IR order is NOT necessarily the program entry point
    // 2. The first function may not even use any of the encrypted globals
    // 3. If any code (e.g., global constructors, other TUs) accesses the global
    //    BEFORE this function runs, it will read encrypted garbage data
    // 4. In multi-TU programs, link order determines which function comes first
    //
    // TODO: Use appendToGlobalCtors() instead! There are already helper functions
    //       at the bottom of this file (insertArrayDecryption, insertIntDecryption)
    //       that correctly use appendToGlobalCtors to register decrypt functions
    //       as global constructors. These run BEFORE main() and are the proper
    //       way to ensure decryption happens before any code accesses the globals.
    //
    // TODO: Alternatively, analyze the module to find actual uses of each global
    //       and insert decryption at each use site (more complex but more robust).
    // ============================================================================
    Function *EntryFunc = nullptr;
    for (Function &F : M) {
        if (!F.isDeclaration()) {
            EntryFunc = &F;
            break;
        }
    }

    if (!EntryFunc) {
        return PreservedAnalyses::all();
    }

    // Get insertion point at start of entry function
    BasicBlock &Entry = EntryFunc->getEntryBlock();
    Instruction *FirstInst = &*Entry.getFirstInsertionPt();
    IRBuilder<> builder(FirstInst);

    // Apply array modifications - create new global with encrypted initializer
    for (auto &mod : arrayMods) {
        Type *eleType = mod.eleType;
        uint64_t eleByteSize = eleType->getPrimitiveSizeInBits() / 8;
        ArrayType *arrayType = ArrayType::get(eleType, mod.eleNum);

        // Build encrypted initializer elements
        std::vector<Constant *> encElements;
        for (uint64_t i = 0; i < mod.eleNum; i++) {
            uint64_t encVal = 0;
            memcpy(&encVal, mod.encData.data() + i * eleByteSize, eleByteSize);
            encElements.push_back(ConstantInt::get(eleType, encVal));
        }
        Constant *encInit = ConstantArray::get(arrayType, encElements);

        // Rename old global and create new one with encrypted data
        std::string origName = mod.GV->getName().str();
        mod.GV->setName(origName + ".orig");

        GlobalVariable *newGV = new GlobalVariable(
            M, arrayType, false, mod.GV->getLinkage(), encInit,
            origName, mod.GV, mod.GV->getThreadLocalMode(),
            mod.GV->getAddressSpace());
        newGV->setAlignment(mod.GV->getAlign());
        newGV->setExternallyInitialized(true);  // Prevent constant folding of reads

        // Replace uses and remove old global
        mod.GV->replaceAllUsesWith(newGV);
        mod.GV->eraseFromParent();

        // Generate decrypt code using alloca indirection
        Type *ptrType = PointerType::getUnqual(eleType);
        AllocaInst *ptrAlloca = builder.CreateAlloca(ptrType);
        builder.CreateStore(newGV, ptrAlloca);
        Value *basePtr = builder.CreateLoad(ptrType, ptrAlloca);

        for (uint64_t i = 0; i < mod.eleNum; i++) {
            Value *elePtr = builder.CreateGEP(eleType, basePtr,
                ConstantInt::get(Type::getInt64Ty(M.getContext()), i));
            Value *val = builder.CreateLoad(eleType, elePtr);
            Value *decrypted = builder.CreateXor(val, ConstantInt::get(eleType, mod.key));
            builder.CreateStore(decrypted, elePtr);
        }
    }

    // Apply int modifications and generate inline decrypt
    for (auto &mod : intMods) {
        Constant *enc = ConstantInt::get(mod.GV->getValueType(), mod.encValue);
        mod.GV->setInitializer(enc);
        mod.GV->setConstant(false);

        // Generate inline int decryption (load, xor, store)
        Value *val = builder.CreateLoad(mod.GV->getValueType(), mod.GV);
        Value *decrypted = builder.CreateXor(val, ConstantInt::get(mod.GV->getValueType(), mod.key));
        builder.CreateStore(decrypted, mod.GV);
    }

    return PreservedAnalyses::none();
}

Function *GlobalEncryption::createArrayDecryptFunction(Module &M, GlobalVariable *GV, uint64_t key, uint64_t eleNum) {
    static uint64_t cnt = 0;
    LLVMContext &context = M.getContext();
    FunctionType *funcType = FunctionType::get(Type::getVoidTy(context), false);
    std::string funcName = formatv("decrypt.arr.{0:d}", cnt++);
    FunctionCallee callee = M.getOrInsertFunction(funcName, funcType);
    Function *func = cast<Function>(callee.getCallee());
    func->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
    BasicBlock *head = BasicBlock::Create(context, "head", func);
    BasicBlock *forCond = BasicBlock::Create(context, "for.cond", func);
    BasicBlock *forBody = BasicBlock::Create(context, "for.body", func);
    BasicBlock *forInc = BasicBlock::Create(context, "for.inc", func);
    BasicBlock *forEnd = BasicBlock::Create(context, "for.end", func);

    IRBuilder<> builder(context);

    builder.SetInsertPoint(head);
    AllocaInst *indexPtr = builder.CreateAlloca(Type::getInt32Ty(context));
    builder.CreateStore(ConstantInt::get(Type::getInt32Ty(context), 0), indexPtr);
    builder.CreateBr(forCond);

    builder.SetInsertPoint(forCond);
    LoadInst *index = builder.CreateLoad(Type::getInt32Ty(context), indexPtr);
    Value *cond = builder.CreateICmpSLT(index, ConstantInt::get(Type::getInt32Ty(context), eleNum));
    builder.CreateCondBr(cond, forBody, forEnd);

    builder.SetInsertPoint(forBody);

    Value *elePtr = builder.CreateGEP(GV->getValueType(), GV, {ConstantInt::get(Type::getInt32Ty(context), 0), index});
    Type *eleType = cast<ArrayType>(GV->getValueType())->getElementType();
    builder.CreateStore(builder.CreateXor(builder.CreateLoad(eleType, elePtr), ConstantInt::get(eleType, key)), elePtr);
    builder.CreateBr(forInc);

    builder.SetInsertPoint(forInc);
    builder.CreateStore(builder.CreateAdd(index, ConstantInt::get(Type::getInt32Ty(context), 1)), indexPtr);
    builder.CreateBr(forCond);

    builder.SetInsertPoint(forEnd);
    builder.CreateRetVoid();

    return func;
}

Function *GlobalEncryption::createIntDecryptFunction(Module &M, GlobalVariable *GV, uint64_t key) {
    static uint64_t cnt = 0;
    LLVMContext &context = M.getContext();
    FunctionType *funcType = FunctionType::get(Type::getVoidTy(context), false);
    std::string funcName = formatv("decrypt.int.{0:d}", cnt++);
    FunctionCallee callee = M.getOrInsertFunction(funcName, funcType);
    Function *func = cast<Function>(callee.getCallee());
    func->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);

    BasicBlock *BB = BasicBlock::Create(context, "BB", func);

    IRBuilder<> builder(context);
    builder.SetInsertPoint(BB);
    LoadInst *val = builder.CreateLoad(GV->getValueType(), GV);
    builder.CreateStore(builder.CreateXor(val, ConstantInt::get(GV->getValueType(), key)), GV);
    builder.CreateRetVoid();

    return func;
}

void GlobalEncryption::insertArrayDecryption(Module &M, GlobalVariable *GV, uint64_t key, uint64_t eleNum) {
    Function *func = createArrayDecryptFunction(M, GV, key, eleNum);
    appendToGlobalCtors(M, func, 0);
}

void GlobalEncryption::insertIntDecryption(Module &M, GlobalVariable *GV, uint64_t key) {
    Function *func = createIntDecryptFunction(M, GV, key);
    appendToGlobalCtors(M, func, 0);
}
}; // namespace Pluto