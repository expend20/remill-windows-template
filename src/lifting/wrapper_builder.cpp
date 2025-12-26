#include "wrapper_builder.h"

#include <llvm/IR/IRBuilder.h>

namespace lifting {

WrapperBuilder::WrapperBuilder(LiftingContext &ctx) : ctx_(ctx) {}

llvm::Function *WrapperBuilder::CreateInt32ReturnWrapper(
    const std::string &wrapper_name, llvm::Function *lifted_func,
    uint64_t start_pc) {
  auto &context = ctx_.GetContext();
  auto *module = ctx_.GetSemanticsModule();
  auto *intrinsics = ctx_.GetIntrinsics();

  auto *i32_type = llvm::Type::getInt32Ty(context);
  auto *wrapper_type = llvm::FunctionType::get(i32_type, {}, false);
  auto *wrapper = llvm::Function::Create(
      wrapper_type, llvm::GlobalValue::ExternalLinkage, wrapper_name, module);

  auto *entry = llvm::BasicBlock::Create(context, "entry", wrapper);
  llvm::IRBuilder<> builder(entry);

  // Allocate State on stack
  auto *state_type = ctx_.GetStateType();
  auto *state_ptr = builder.CreateAlloca(state_type, nullptr, "state");

  // Initialize RSP with a known constant for stack address tracking
  // Using constant enables memory lowering to recognize stack accesses
  auto *rsp_reg = ctx_.GetRegister("RSP");
  auto *rsp_ptr = rsp_reg->AddressOf(state_ptr, builder);
  builder.CreateStore(
      llvm::ConstantInt::get(builder.getInt64Ty(), INITIAL_RSP), rsp_ptr);

  // Call lifted function
  llvm::Value *args[] = {
      state_ptr, llvm::ConstantInt::get(builder.getInt64Ty(), start_pc),
      llvm::UndefValue::get(intrinsics->mem_ptr_type)};
  builder.CreateCall(lifted_func, args);

  // Extract EAX (lower 32 bits of RAX) and return
  auto *rax_reg = ctx_.GetRegister("RAX");
  auto *rax_ptr = rax_reg->AddressOf(state_ptr, builder);
  auto *rax_val = builder.CreateLoad(builder.getInt64Ty(), rax_ptr);
  auto *eax_val = builder.CreateTrunc(rax_val, i32_type);
  builder.CreateRet(eax_val);

  return wrapper;
}

void WrapperBuilder::PrepareForInlining(llvm::Function *func) {
  func->setLinkage(llvm::GlobalValue::InternalLinkage);
  func->removeFnAttr(llvm::Attribute::NoInline);
  func->addFnAttr(llvm::Attribute::AlwaysInline);
}

}  // namespace lifting
