// IR Checker Tool
// Verifies that the optimized IR contains only "ret i32 <expected>" instruction
// Usage: ir_checker <bitcode_file> <expected_return_value>

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

#include <cstdlib>
#include <string>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        llvm::errs() << "Usage: " << argv[0] << " <bitcode_file> <expected_return_value>\n";
        return 1;
    }

    const char *filename = argv[1];
    int expected_value = std::atoi(argv[2]);

    llvm::LLVMContext context;
    llvm::SMDiagnostic error;

    // Load the module (works with both .bc and .ll files)
    auto module = llvm::parseIRFile(filename, error, context);
    if (!module) {
        llvm::errs() << "Error: Failed to load " << filename << "\n";
        error.print(argv[0], llvm::errs());
        return 1;
    }

    // Find the @test function
    llvm::Function *test_func = module->getFunction("test");
    if (!test_func) {
        llvm::errs() << "Error: No @test function found in " << filename << "\n";
        return 1;
    }

    if (test_func->isDeclaration()) {
        llvm::errs() << "Error: @test function is a declaration, not a definition\n";
        return 1;
    }

    // Count instructions (excluding terminators that are ret)
    int instruction_count = 0;
    llvm::ReturnInst *ret_inst = nullptr;

    for (auto &bb : *test_func) {
        for (auto &inst : bb) {
            // Skip debug intrinsics and lifetime markers
            if (llvm::isa<llvm::DbgInfoIntrinsic>(&inst)) {
                continue;
            }

            if (auto *ret = llvm::dyn_cast<llvm::ReturnInst>(&inst)) {
                ret_inst = ret;
            }
            instruction_count++;
        }
    }

    // Check we have exactly one basic block with one instruction
    if (test_func->size() != 1) {
        llvm::errs() << "Error: Expected 1 basic block, found " << test_func->size() << "\n";
        llvm::errs() << "Function body:\n";
        test_func->print(llvm::errs());
        return 1;
    }

    if (instruction_count != 1) {
        llvm::errs() << "Error: Expected 1 instruction (ret i32 " << expected_value
                     << "), found " << instruction_count << " instructions\n";
        llvm::errs() << "Function body:\n";
        test_func->print(llvm::errs());
        return 1;
    }

    if (!ret_inst) {
        llvm::errs() << "Error: No return instruction found\n";
        llvm::errs() << "Function body:\n";
        test_func->print(llvm::errs());
        return 1;
    }

    // Check the return value
    llvm::Value *ret_val = ret_inst->getReturnValue();
    if (!ret_val) {
        llvm::errs() << "Error: Return instruction has no value (void return)\n";
        return 1;
    }

    auto *const_int = llvm::dyn_cast<llvm::ConstantInt>(ret_val);
    if (!const_int) {
        llvm::errs() << "Error: Return value is not a constant integer\n";
        llvm::errs() << "Return instruction: ";
        ret_inst->print(llvm::errs());
        llvm::errs() << "\n";
        return 1;
    }

    int actual_value = static_cast<int>(const_int->getSExtValue());
    if (actual_value != expected_value) {
        llvm::errs() << "Error: Expected return value " << expected_value
                     << ", got " << actual_value << "\n";
        return 1;
    }

    llvm::outs() << "SUCCESS: Optimized IR contains only 'ret i32 " << expected_value << "'\n";
    return 0;
}
