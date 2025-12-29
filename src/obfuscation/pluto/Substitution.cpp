// Credits to https://github.com/bluesadi/Pluto

#include "Pluto/Substitution.h"
#include "Pluto/CryptoUtils.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/ADT/SmallVector.h"

using namespace llvm;

// Use NoFolder to avoid constant folding, which can trigger DenseMap corruption
// in LLVM's constant uniquing when the pass DLL has separate static data from opt.exe
using BuilderTy = IRBuilder<NoFolder>;

// Thread-local builder to avoid issues with multiple pass invocations
static thread_local BuilderTy *builder = nullptr;

PreservedAnalyses Pluto::Substitution::run(Function &F, FunctionAnalysisManager &AM) {
    BuilderTy localBuilder(F.getContext());
    builder = &localBuilder;

    for (BasicBlock &BB : F) {
        // Collect only BinaryOperators directly to avoid unnecessary casts
        SmallVector<BinaryOperator *, 16> binOps;
        for (Instruction &I : BB) {
            if (auto *BI = dyn_cast<BinaryOperator>(&I)) {
                binOps.push_back(BI);
            }
        }
        for (BinaryOperator *BI : binOps) {
            builder->SetInsertPoint(BI);
            if (substitute(BI)) {
                BI->eraseFromParent();
            }
        }
    }

    builder = nullptr;
    return PreservedAnalyses::none();
}

bool Pluto::Substitution::substitute(BinaryOperator *BI) {
    switch (BI->getOpcode()) {
    case BinaryOperator::Add:
        substituteAdd(BI);
        return true;
    case BinaryOperator::Sub:
        substituteSub(BI);
        return true;
    case BinaryOperator::And:
        substituteAnd(BI);
        return true;
    case BinaryOperator::Or:
        substituteOr(BI);
        return true;
    case BinaryOperator::Xor:
        substituteXor(BI);
        return true;
    default:
        return false;
    }
}

void Pluto::Substitution::substituteAdd(BinaryOperator *BI) {
    switch (cryptoutils->get_range(4)) {
    case 0:
        addNeg(BI);
        break;
    case 1:
        addDoubleNeg(BI);
        break;
    case 2:
        addRand(BI);
        break;
    case 3:
        addRand2(BI);
        break;
    default:
        break;
    }
}

void Pluto::Substitution::addNeg(BinaryOperator *BI) {
    Value *op;
    op = builder->CreateNeg(BI->getOperand(1));
    op = builder->CreateSub(BI->getOperand(0), op);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::addDoubleNeg(BinaryOperator *BI) {
    Value *op, *op1, *op2;
    op1 = builder->CreateNeg(BI->getOperand(0));
    op2 = builder->CreateNeg(BI->getOperand(1));
    op = builder->CreateAdd(op1, op2);
    op = builder->CreateNeg(op);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::addRand(BinaryOperator *BI) {
    Constant *r = ConstantInt::get(BI->getType(), cryptoutils->get_uint32_t());
    Value *op;
    op = builder->CreateAdd(BI->getOperand(0), r);
    op = builder->CreateAdd(op, BI->getOperand(1));
    op = builder->CreateSub(op, r);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::addRand2(BinaryOperator *BI) {
    Constant *r = ConstantInt::get(BI->getType(), cryptoutils->get_uint32_t());
    Value *op;
    op = builder->CreateSub(BI->getOperand(0), r);
    op = builder->CreateAdd(op, BI->getOperand(1));
    op = builder->CreateAdd(op, r);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::substituteSub(BinaryOperator *BI) {
    switch (cryptoutils->get_range(3)) {
    case 0:
        subNeg(BI);
        break;
    case 1:
        subRand(BI);
        break;
    case 2:
        subRand2(BI);
        break;
    default:
        break;
    }
}

void Pluto::Substitution::subNeg(BinaryOperator *BI) {
    Value *op;
    op = builder->CreateNeg(BI->getOperand(1));
    op = builder->CreateAdd(BI->getOperand(0), op);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::subRand(BinaryOperator *BI) {
    Constant *r = ConstantInt::get(BI->getType(), cryptoutils->get_uint32_t());
    Value *op;
    op = builder->CreateAdd(BI->getOperand(0), r);
    op = builder->CreateSub(op, BI->getOperand(1));
    op = builder->CreateSub(op, r);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::subRand2(BinaryOperator *BI) {
    Constant *r = ConstantInt::get(BI->getType(), cryptoutils->get_uint32_t());
    Value *op;
    op = builder->CreateSub(BI->getOperand(0), r);
    op = builder->CreateSub(op, BI->getOperand(1));
    op = builder->CreateAdd(op, r);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::substituteXor(BinaryOperator *BI) {
    int choice = cryptoutils->get_uint32_t() % NUMBER_XOR_SUBST;
    switch (choice) {
    case 0:
        xorSubstitute(BI);
        break;
    case 1:
        xorSubstituteRand(BI);
        break;
    default:
        break;
    }
}

void Pluto::Substitution::xorSubstitute(BinaryOperator *BI) {
    Value *op, *op1, *op2;
    op1 = builder->CreateNot(BI->getOperand(0));
    op1 = builder->CreateAnd(op1, BI->getOperand(1));
    op2 = builder->CreateNot(BI->getOperand(1));
    op2 = builder->CreateAnd(BI->getOperand(0), op2);
    op = builder->CreateOr(op1, op2);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::xorSubstituteRand(BinaryOperator *BI) {
    Constant *r = ConstantInt::get(BI->getType(), cryptoutils->get_uint32_t());
    // Pre-compute ~r to avoid repeated constant folding through IRBuilder
    Constant *notR = ConstantExpr::getNot(r);
    Value *op, *op1, *op2, *op3;
    op1 = builder->CreateNot(BI->getOperand(0));
    op1 = builder->CreateAnd(op1, r);
    op2 = builder->CreateAnd(BI->getOperand(0), notR);
    op = builder->CreateOr(op1, op2);
    op1 = builder->CreateNot(BI->getOperand(1));
    op1 = builder->CreateAnd(op1, r);
    op2 = builder->CreateAnd(BI->getOperand(1), notR);
    op3 = builder->CreateOr(op1, op2);
    op = builder->CreateXor(op, op3);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::substituteAnd(BinaryOperator *BI) {
    int choice = cryptoutils->get_uint32_t() % NUMBER_AND_SUBST;
    switch (choice) {
    case 0:
        andSubstitute(BI);
        break;
    case 1:
        andSubstituteRand(BI);
        break;
    default:
        break;
    }
}

void Pluto::Substitution::andSubstitute(BinaryOperator *BI) {
    Value *op;
    op = builder->CreateNot(BI->getOperand(1));
    op = builder->CreateXor(BI->getOperand(0), op);
    op = builder->CreateAnd(op, BI->getOperand(0));
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::andSubstituteRand(BinaryOperator *BI) {
    Constant *r = ConstantInt::get(BI->getType(), cryptoutils->get_uint32_t());
    // Pre-compute ~r to avoid constant folding issues
    Constant *notR = ConstantExpr::getNot(r);
    Value *op, *op1;
    op = builder->CreateNot(BI->getOperand(0));
    op1 = builder->CreateNot(BI->getOperand(1));
    op = builder->CreateOr(op, op1);
    op = builder->CreateNot(op);
    // r | ~r is always -1 (all ones), so this is just masking with -1
    // But we keep the pattern for obfuscation purposes
    op1 = builder->CreateOr(r, notR);
    op = builder->CreateAnd(op, op1);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::substituteOr(BinaryOperator *BI) {
    switch (cryptoutils->get_range(2)) {
    case 0:
        orSubstitute(BI);
        break;
    case 1:
        orSubstituteRand(BI);
        break;
    default:
        break;
    }
}

void Pluto::Substitution::orSubstitute(BinaryOperator *BI) {
    Value *op, *op1;
    op = builder->CreateAnd(BI->getOperand(0), BI->getOperand(1));
    op1 = builder->CreateXor(BI->getOperand(0), BI->getOperand(1));
    op = builder->CreateOr(op, op1);
    BI->replaceAllUsesWith(op);
}

void Pluto::Substitution::orSubstituteRand(BinaryOperator *BI) {
    Constant *r = ConstantInt::get(BI->getType(), cryptoutils->get_uint32_t());
    // Pre-compute ~r to avoid constant folding issues
    Constant *notR = ConstantExpr::getNot(r);
    Value *op, *op1;
    op = builder->CreateNot(BI->getOperand(0));
    op1 = builder->CreateNot(BI->getOperand(1));
    op = builder->CreateAnd(op, op1);
    op = builder->CreateNot(op);
    // r | ~r is always -1 (all ones), so this is just masking with -1
    // But we keep the pattern for obfuscation purposes
    op1 = builder->CreateOr(r, notR);
    op = builder->CreateAnd(op, op1);
    BI->replaceAllUsesWith(op);
}