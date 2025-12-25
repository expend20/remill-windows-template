#include "lifting_context.h"

#include <iostream>

#include <remill/BC/Util.h>

namespace lifting {

LiftingContext::LiftingContext(const std::string &os_name,
                               const std::string &arch_name)
    : context_(std::make_unique<llvm::LLVMContext>()) {
  arch_ = remill::Arch::Get(*context_, os_name, arch_name);
  if (!arch_) {
    std::cerr << "Failed to get architecture: " << os_name << "/" << arch_name
              << "\n";
    return;
  }

  semantics_ = remill::LoadArchSemantics(arch_.get());
  if (!semantics_) {
    std::cerr << "Failed to load architecture semantics\n";
    return;
  }

  intrinsics_ = arch_->GetInstrinsicTable();
  if (!intrinsics_) {
    std::cerr << "Failed to get intrinsic table\n";
    return;
  }
}

bool LiftingContext::IsValid() const {
  return arch_ && semantics_ && intrinsics_;
}

llvm::Function *LiftingContext::DefineLiftedFunction(const std::string &name) {
  return arch_->DefineLiftedFunction(name, semantics_.get());
}

const remill::Register *LiftingContext::GetRegister(
    std::string_view name) const {
  return arch_->RegisterByName(name);
}

llvm::StructType *LiftingContext::GetStateType() const {
  return arch_->StateStructType();
}

}  // namespace lifting
