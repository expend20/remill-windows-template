#include "module_utils.h"

#include <iostream>

#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>

namespace utils {

std::unique_ptr<llvm::Module> CreateCleanModule(
    llvm::LLVMContext &context, llvm::Function *source_func,
    const std::string &module_name, const std::string &target_triple,
    const llvm::DataLayout &data_layout) {
  auto clean_module = std::make_unique<llvm::Module>(module_name, context);
  clean_module->setTargetTriple(target_triple);
  clean_module->setDataLayout(data_layout);

  // Create the function with the same signature
  auto *func_type = source_func->getFunctionType();
  auto *clean_func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, source_func->getName(),
      clean_module.get());
  clean_func->setCallingConv(source_func->getCallingConv());

  // Create entry block
  auto *entry = llvm::BasicBlock::Create(context, "entry", clean_func);
  llvm::IRBuilder<> builder(entry);

  // Find the return instruction and extract the constant value
  llvm::ConstantInt *return_value = nullptr;
  for (auto &BB : *source_func) {
    for (auto &I : BB) {
      if (auto *ret = llvm::dyn_cast<llvm::ReturnInst>(&I)) {
        if (auto *val = ret->getReturnValue()) {
          return_value = llvm::dyn_cast<llvm::ConstantInt>(val);
        }
        break;
      }
    }
    if (return_value)
      break;
  }

  if (return_value) {
    builder.CreateRet(
        llvm::ConstantInt::get(func_type->getReturnType(), return_value->getValue()));
  } else {
    // Return 0 as fallback
    builder.CreateRet(llvm::ConstantInt::get(func_type->getReturnType(), 0));
  }

  return clean_module;
}

bool WriteModule(llvm::Module *module, const std::string &base_name) {
  return WriteLLFile(module, base_name + ".ll") &&
         WriteBCFile(module, base_name + ".bc");
}

bool WriteLLFile(llvm::Module *module, const std::string &filename) {
  std::error_code EC;
  llvm::raw_fd_ostream file(filename, EC);
  if (EC) {
    std::cerr << "Failed to open " << filename << ": " << EC.message() << "\n";
    return false;
  }
  module->print(file, nullptr);
  file.close();
  std::cout << "Written: " << filename << "\n";
  return true;
}

bool WriteBCFile(llvm::Module *module, const std::string &filename) {
  std::error_code EC;
  llvm::raw_fd_ostream file(filename, EC);
  if (EC) {
    std::cerr << "Failed to open " << filename << ": " << EC.message() << "\n";
    return false;
  }
  llvm::WriteBitcodeToFile(*module, file);
  file.close();
  std::cout << "Written: " << filename << "\n";
  return true;
}

}  // namespace utils
