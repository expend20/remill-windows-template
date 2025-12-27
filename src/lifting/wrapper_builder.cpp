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
  // We set RSP = INITIAL_RSP - 8 to simulate a caller having pushed a
  // return address. The stack location at RSP will contain 0 (sentinel).
  // When the lifted function returns, its RET will pop this 0 value,
  // which won't match any internal return address, causing the switch
  // to take the default branch and properly exit the LLVM function.
  auto *rsp_reg = ctx_.GetRegister("RSP");
  auto *rsp_ptr = rsp_reg->AddressOf(state_ptr, builder);
  uint64_t initial_rsp = INITIAL_RSP - 8;  // Point to "return address" slot
  builder.CreateStore(
      llvm::ConstantInt::get(builder.getInt64Ty(), initial_rsp), rsp_ptr);

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
