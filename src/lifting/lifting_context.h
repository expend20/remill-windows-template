#pragma once

#include <memory>
#include <string_view>

#include <remill/Arch/Arch.h>
#include <remill/BC/IntrinsicTable.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

namespace lifting {

// Context for lifting operations - wraps architecture, semantics, and intrinsics
class LiftingContext {
 public:
  LiftingContext(const std::string &os_name, const std::string &arch_name);

  bool IsValid() const;

  llvm::LLVMContext &GetContext() { return *context_; }
  const remill::Arch *GetArch() const { return arch_.get(); }
  llvm::Module *GetSemanticsModule() { return semantics_.get(); }
  const remill::IntrinsicTable *GetIntrinsics() const { return intrinsics_; }

  // Create a new lifted function in the semantics module
  llvm::Function *DefineLiftedFunction(const std::string &name);

  // Get register accessor
  const remill::Register *GetRegister(std::string_view name) const;

  // Get state structure type
  llvm::StructType *GetStateType() const;

 private:
  std::unique_ptr<llvm::LLVMContext> context_;
  std::unique_ptr<const remill::Arch> arch_;
  std::unique_ptr<llvm::Module> semantics_;
  const remill::IntrinsicTable *intrinsics_ = nullptr;
};

}  // namespace lifting
