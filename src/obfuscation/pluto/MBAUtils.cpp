// Credits to https://github.com/bluesadi/Pluto
#include "Pluto/MBAUtils.h"
#include "Pluto/CryptoUtils.h"

#include "z3++.h"
#include "llvm/ADT/APInt.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/FormatVariadic.h"
#include <algorithm>
#include <cstdint>
#include <queue>
#include <string>

#define USE_CACHE

//using namespace z3;
using namespace llvm;

static int8_t truthTables[15][4] = {
    {0, 0, 0, 1}, // x & y
    {0, 0, 1, 0}, // x & ~y
    {0, 0, 1, 1}, // x
    {0, 1, 0, 0}, // ~x & y
    {0, 1, 0, 1}, // y
    {0, 1, 1, 0}, // x ^ y
    {0, 1, 1, 1}, // x | y
    {1, 0, 0, 0}, // ~(x | y)
    {1, 0, 0, 1}, // ~(x ^ y)
    {1, 0, 1, 0}, // ~y
    {1, 0, 1, 1}, // x | ~y
    {1, 1, 0, 0}, // ~x
    {1, 1, 0, 1}, // ~x | y
    {1, 1, 1, 0}, // ~(x & y)
    {1, 1, 1, 1}, // -1
};

int64_t *Pluto::MBAUtils::generateLinearMBA(int numExprs) {
#ifdef USE_CACHE
    static std::queue<int64_t *> cached_coeffs;
    if (cached_coeffs.size() >= 100) {
        int64_t *coeffs = cached_coeffs.front();
        cached_coeffs.pop();
        int64_t *coeffs_copy = new int64_t[15];
        std::copy(coeffs, coeffs + 15, coeffs_copy);
        cached_coeffs.push(coeffs_copy);
        return coeffs;
    }
#endif
    int *exprs = new int[numExprs];
    int64_t *coeffs = new int64_t[15];
    while (true) {
        z3::context c;
        std::vector<z3::expr> X;
        z3::solver s(c);
        std::fill_n(coeffs, 15, 0);
        for (int i = 0; i < numExprs; i++) {
            std::string name = formatv("a{0:d}", i);
            X.push_back(c.int_const(name.c_str()));
        }
        for (int i = 0; i < numExprs; i++) {
            exprs[i] = cryptoutils->get_range(15);
        }
        for (int i = 0; i < 4; i++) {
            z3::expr equ = c.int_val(0);
            for (int j = 0; j < numExprs; j++) {
                equ = equ + X[j] * truthTables[exprs[j]][i];
            }
            s.add(equ == 0);
        }
        z3::expr notZeroCond = c.bool_val(false);
        // a1 != 0 || a2 != 0 || ... || an != 0
        for (int i = 0; i < numExprs; i++) {
            notZeroCond = notZeroCond || (X[i] != 0);
        }
        s.add(notZeroCond);
        if (s.check() != z3::sat) {
            continue;
        }
        z3::model m = s.get_model();
        for (int i = 0; i < numExprs; i++) {
            coeffs[exprs[i]] += m.eval(X[i]).get_numeral_int64();
        }
        delete[] exprs;
#ifdef USE_CACHE
        int64_t *coeffs_copy = new int64_t[15];
        std::copy(coeffs, coeffs + 15, coeffs_copy);
        cached_coeffs.push(coeffs_copy);
#endif
        return coeffs;
    }
}

Value *Pluto::MBAUtils::insertLinearMBA(int64_t *coeffs, Instruction *insertBefore) {
    // Use NoFolder to avoid constant folding, which can trigger DenseMap corruption
    // in LLVM's constant uniquing when the pass DLL has separate static data from opt.exe
    IRBuilder<NoFolder> builder(insertBefore->getContext());
    builder.SetInsertPoint(insertBefore);
    Value *x, *y;
    Type *type;

    if (isa<BinaryOperator>(insertBefore) && insertBefore->getNumOperands() == 2) {
        x = insertBefore->getOperand(0);
        y = insertBefore->getOperand(1);
        type = x->getType();
    } else {
        Module &M = *insertBefore->getModule();
        type = insertBefore->getOperand(0)->getType();
        // Use get_uint32_t() to avoid issues with large values being truncated
        uint64_t randX = cryptoutils->get_uint32_t();
        uint64_t randY = cryptoutils->get_uint32_t();
        GlobalVariable *xPtr =
            new GlobalVariable(M, type, false, GlobalValue::PrivateLinkage,
                               ConstantInt::get(type, randX), "x");
        GlobalVariable *yPtr =
            new GlobalVariable(M, type, false, GlobalValue::PrivateLinkage,
                               ConstantInt::get(type, randY), "y");
        x = builder.CreateLoad(type, xPtr);
        y = builder.CreateLoad(type, yPtr);
    }

    Value *mbaExpr = ConstantInt::get(type, 0);
    Value *boolExpr, *term;

    for (int i = 0; i < 15; i++) {
        if (!coeffs[i])
            continue;
        // x & y
        if (i == 0)
            boolExpr = builder.CreateAnd(x, y);
        // x & ~y
        else if (i == 1)
            boolExpr = builder.CreateAnd(x, builder.CreateNot(y));
        // x
        else if (i == 2)
            boolExpr = x;
        // ~x & y
        else if (i == 3)
            boolExpr = builder.CreateAnd(builder.CreateNot(x), y);
        // y
        else if (i == 4)
            boolExpr = y;
        // x ^ y
        else if (i == 5)
            boolExpr = builder.CreateXor(x, y);
        // x | y
        else if (i == 6)
            boolExpr = builder.CreateOr(x, y);
        // ~(x | y)
        else if (i == 7)
            boolExpr = builder.CreateNot(builder.CreateOr(x, y));
        // ~(x ^ y)
        else if (i == 8)
            boolExpr = builder.CreateNot(builder.CreateXor(x, y));
        // ~y
        else if (i == 9)
            boolExpr = builder.CreateNot(y);
        // x | ~y
        else if (i == 10)
            boolExpr = builder.CreateOr(x, builder.CreateNot(y));
        // ~x
        else if (i == 11)
            boolExpr = builder.CreateNot(x);
        // ~x | y
        else if (i == 12)
            boolExpr = builder.CreateOr(builder.CreateNot(x), y);
        // ~(x & y)
        else if (i == 13)
            boolExpr = builder.CreateNot(builder.CreateAnd(x, y));
        // -1 (all bits set)
        else if (i == 14)
            boolExpr = ConstantInt::getSigned(type, -1);
        // Create constant - coefficients are small values from z3 solver
        auto *coeffConst = ConstantInt::getSigned(type, coeffs[i]);
        term = builder.CreateMul(coeffConst, boolExpr);
        mbaExpr = builder.CreateAdd(mbaExpr, term);
    }
    return mbaExpr;
}

// Extended Euclid's Theorem function.
uint64_t exgcd(uint64_t a, uint64_t b, uint64_t &x, uint64_t &y) {
    if (b == 0) {
        x = 1, y = 0;
        return a;
    }
    uint64_t g = exgcd(b, a % b, y, x);
    y -= a / b * x;
    return g;
}

uint64_t inv(uint64_t a, uint64_t p) {
    uint64_t x, y;
    exgcd(a, p, x, y);
    // get the inverse element
    return (x % p + p) % p;
}

uint64_t inverse(uint64_t n, uint32_t bitWidth) {
    assert(bitWidth <= 32);
    return inv(n, 1LL << bitWidth);
}

void generateUnivariatePoly(uint64_t *a, uint64_t *b, uint32_t bitWidth) {
    // Mask for the target bit width (e.g., 0xFFFFFFFF for 32-bit)
    uint64_t mask = (bitWidth == 64) ? ~0ULL : ((1ULL << bitWidth) - 1);

    uint64_t a0, a1, b0, b1, a1_inv;

    // Generate random values and mask to target bit width
    a0 = Pluto::cryptoutils->get_uint64_t() & mask;
    a1 = (Pluto::cryptoutils->get_uint64_t() | 1) & mask;  // Ensure odd for invertibility

    // Calculate a1_inv (modular inverse of a1 mod 2^bitWidth)
    a1_inv = inverse(a1, bitWidth) & mask;

    // Calculate b1 = a1_inv
    b1 = a1_inv;

    // Calculate b0 = -(b1 * a0) mod 2^bitWidth
    b0 = (-(b1 * a0)) & mask;

    a[0] = a0, a[1] = a1, b[0] = b0, b[1] = b1;
}

Value *Pluto::MBAUtils::insertPolynomialMBA(Value *linearMBAExpr, Instruction *insertBefore) {
    // Use NoFolder to avoid constant folding, which can trigger DenseMap corruption
    IRBuilder<NoFolder> builder(insertBefore->getContext());
    builder.SetInsertPoint(insertBefore);
    Type *operandType = insertBefore->getOperand(0)->getType();
    uint32_t bitWidth = operandType->getIntegerBitWidth();
    uint64_t a[2], b[2];
    generateUnivariatePoly(a, b, bitWidth);

    // Use Type* based ConstantInt::get to use host's constant uniquing
    auto *b1Const = ConstantInt::get(operandType, b[1]);
    auto *b0Const = ConstantInt::get(operandType, b[0]);
    auto *a1Const = ConstantInt::get(operandType, a[1]);
    auto *a0Const = ConstantInt::get(operandType, a[0]);

    Value *expr;
    expr = builder.CreateMul(b1Const, linearMBAExpr);
    expr = builder.CreateAdd(expr, b0Const);
    expr = builder.CreateMul(a1Const, expr);
    expr = builder.CreateAdd(expr, a0Const);
    return expr;
}