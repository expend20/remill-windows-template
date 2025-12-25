// Test: ret_with_code
// Lifts a simple function that returns a constant value: mov eax, 0x1337; ret
// Verifies that the lifted and optimized code produces: ret i32 4919

#include <cstdlib>
#include <iostream>

#include <glog/logging.h>
#include <remill/BC/Util.h>

#include <llvm/IR/IRBuilder.h>

#include "lifting/lifting_context.h"
#include "lifting/instruction_lifter.h"
#include "lifting/wrapper_builder.h"
#include "optimization/optimizer.h"
#include "utils/module_utils.h"
#include "utils/pe_reader.h"

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);

  // Get shellcode path from command line
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <shellcode.exe>\n";
    return EXIT_FAILURE;
  }
  const char *shellcode_path = argv[1];

  // Read .text section from compiled shellcode
  auto text_info = utils::ReadTextSection(shellcode_path);
  if (!text_info) {
    std::cerr << "Failed to read shellcode from: " << shellcode_path << "\n";
    return EXIT_FAILURE;
  }

  std::cout << "Loaded " << text_info->bytes.size()
            << " bytes from .text section\n";

  // Initialize lifting context
  lifting::LiftingContext ctx("windows", "amd64");
  if (!ctx.IsValid()) {
    return EXIT_FAILURE;
  }

  // Calculate start address: ImageBase + .text RVA
  uint64_t start_address = text_info->image_base + text_info->virtual_address;

  // Create lifted function
  auto *lifted_func = ctx.DefineLiftedFunction("lifted_ret_with_code");
  auto *block = &lifted_func->getEntryBlock();

  // Lift all instructions
  lifting::InstructionLifter lifter(ctx);
  if (!lifter.LiftInstructionsImpl(start_address, text_info->bytes.data(),
                                   text_info->bytes.size(), block)) {
    std::cerr << "Failed to lift instructions\n";
    return EXIT_FAILURE;
  }

  // Finish the lifted block
  llvm::IRBuilder<> ir(block);
  ir.CreateRet(remill::LoadMemoryPointer(block, *ctx.GetIntrinsics()));

  // Prepare lifted function for inlining
  lifting::WrapperBuilder::PrepareForInlining(lifted_func);

  // Create wrapper function
  lifting::WrapperBuilder wrapper_builder(ctx);
  auto *wrapper = wrapper_builder.CreateInt32ReturnWrapper(
      "test", lifted_func, start_address);

  // Remove memory intrinsics (safe for leaf functions)
  optimization::RemoveMemoryIntrinsics(ctx.GetSemanticsModule());

  // Optimize
  optimization::OptimizeForCleanIR(ctx.GetSemanticsModule(), wrapper);

  // Print result
  std::cout << "[Optimized IR]\n";
  wrapper->print(llvm::outs());
  std::cout << "\n";

  // Write clean optimized module
  auto clean_module = utils::CreateCleanModule(
      ctx.GetContext(), wrapper, "test_optimized",
      ctx.GetSemanticsModule()->getTargetTriple(),
      ctx.GetSemanticsModule()->getDataLayout());
  utils::WriteModule(clean_module.get(), "test_optimized");

  // Also write full semantics module (for reference)
  utils::WriteModule(ctx.GetSemanticsModule(), "lifted");

  return EXIT_SUCCESS;
}
