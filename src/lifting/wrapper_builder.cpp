#include "wrapper_builder.h"

#include <algorithm>
#include <cctype>

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

llvm::Function *WrapperBuilder::CreateParameterizedWrapper(
    const std::string &wrapper_name, llvm::Function *lifted_func,
    uint64_t start_pc, const VariableConfig &config) {
  auto &context = ctx_.GetContext();
  auto *module = ctx_.GetSemanticsModule();
  auto *intrinsics = ctx_.GetIntrinsics();

  // Build function type with i64 parameters for each variable register
  auto *i64_type = llvm::Type::getInt64Ty(context);
  std::vector<llvm::Type *> param_types(config.input_registers.size(), i64_type);
  auto *wrapper_type = llvm::FunctionType::get(i64_type, param_types, false);
  auto *wrapper = llvm::Function::Create(
      wrapper_type, llvm::GlobalValue::ExternalLinkage, wrapper_name, module);

  // Name the parameters for readability
  unsigned idx = 0;
  for (auto &arg : wrapper->args()) {
    std::string param_name = config.input_registers[idx];
    // Convert to lowercase for parameter name
    std::transform(param_name.begin(), param_name.end(), param_name.begin(),
                   ::tolower);
    arg.setName(param_name + "_input");
    idx++;
  }

  auto *entry = llvm::BasicBlock::Create(context, "entry", wrapper);
  llvm::IRBuilder<> builder(entry);

  // Allocate State on stack
  auto *state_type = ctx_.GetStateType();
  auto *state_ptr = builder.CreateAlloca(state_type, nullptr, "state");

  // Initialize RSP with a known constant for stack address tracking
  auto *rsp_reg = ctx_.GetRegister("RSP");
  auto *rsp_ptr = rsp_reg->AddressOf(state_ptr, builder);
  uint64_t initial_rsp = INITIAL_RSP - 8;
  builder.CreateStore(
      llvm::ConstantInt::get(builder.getInt64Ty(), initial_rsp), rsp_ptr);

  // Store function parameters into corresponding State register fields
  idx = 0;
  for (auto &arg : wrapper->args()) {
    std::string reg_name = config.input_registers[idx];
    // Convert to uppercase for register lookup
    std::transform(reg_name.begin(), reg_name.end(), reg_name.begin(),
                   ::toupper);
    auto *reg = ctx_.GetRegister(reg_name);
    auto *reg_ptr = reg->AddressOf(state_ptr, builder);
    builder.CreateStore(&arg, reg_ptr);
    idx++;
  }

  // Call lifted function
  llvm::Value *args[] = {
      state_ptr, llvm::ConstantInt::get(builder.getInt64Ty(), start_pc),
      llvm::UndefValue::get(intrinsics->mem_ptr_type)};
  builder.CreateCall(lifted_func, args);

  // Extract return value from specified register
  std::string ret_reg_name = config.return_register;
  std::transform(ret_reg_name.begin(), ret_reg_name.end(), ret_reg_name.begin(),
                 ::toupper);
  auto *ret_reg = ctx_.GetRegister(ret_reg_name);
  auto *ret_ptr = ret_reg->AddressOf(state_ptr, builder);
  auto *ret_val = builder.CreateLoad(i64_type, ret_ptr);
  builder.CreateRet(ret_val);

  return wrapper;
}

void WrapperBuilder::PrepareForInlining(llvm::Function *func) {
  func->setLinkage(llvm::GlobalValue::InternalLinkage);
  func->removeFnAttr(llvm::Attribute::NoInline);
  func->addFnAttr(llvm::Attribute::AlwaysInline);
}

}  // namespace lifting
