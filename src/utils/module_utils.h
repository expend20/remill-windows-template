#pragma once

#include <memory>
#include <string>
#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

namespace utils {

// Create a clean module containing only the specified function
// Extracts the constant return value from an optimized function
std::unique_ptr<llvm::Module> CreateCleanModule(llvm::LLVMContext &context,
                                                 llvm::Function *source_func,
                                                 const std::string &module_name,
                                                 const std::string &target_triple,
                                                 const llvm::DataLayout &data_layout);

// Extract specified functions and their dependencies into a new module
// This is useful for extracting just the lifted code from the semantics module
std::unique_ptr<llvm::Module> ExtractFunctions(
    llvm::Module *source_module,
    const std::vector<std::string> &function_names,
    const std::string &module_name);

// Write a module to .ll and .bc files
// Returns true on success
bool WriteModule(llvm::Module *module, const std::string &base_name);

// Write just the .ll file
bool WriteLLFile(llvm::Module *module, const std::string &filename);

// Write just the .bc file
bool WriteBCFile(llvm::Module *module, const std::string &filename);

}  // namespace utils
