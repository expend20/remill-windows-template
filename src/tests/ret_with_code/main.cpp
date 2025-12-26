// Test: ret_with_code
// Lifts a simple function that returns a constant value: mov eax, 0x1337; ret
// Verifies that the lifted and optimized code produces: ret i32 4919

#include <cstdlib>
#include <iostream>

#include <glog/logging.h>
#include <remill/BC/Util.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/raw_ostream.h>

#include "lifting/lifting_context.h"
#include "lifting/instruction_lifter.h"
#include "lifting/memory_lowering.h"
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

  // Read full PE file (all sections)
  auto pe_info = utils::ReadPE(shellcode_path);
  if (!pe_info) {
    std::cerr << "Failed to read PE from: " << shellcode_path << "\n";
    return EXIT_FAILURE;
  }

  // Find .text section
  const auto *text_section = pe_info->FindSection(".text");
  if (!text_section) {
    std::cerr << ".text section not found\n";
    return EXIT_FAILURE;
  }

  std::cout << "Loaded PE with " << pe_info->sections.size() << " sections\n";
  for (const auto &sec : pe_info->sections) {
    std::cout << "  " << sec.name << ": " << sec.bytes.size() << " bytes at RVA 0x"
              << std::hex << sec.virtual_address << std::dec << "\n";
  }

  // Initialize lifting context
  lifting::LiftingContext ctx("windows", "amd64");
  if (!ctx.IsValid()) {
    return EXIT_FAILURE;
  }

  // Calculate start address: ImageBase + .text RVA
  uint64_t start_address = pe_info->image_base + text_section->virtual_address;

  // Create lifted function in semantics module (required by remill's instruction lifter)
  auto *lifted_func = ctx.DefineLiftedFunction("lifted_ret_with_code");
  auto *block = &lifted_func->getEntryBlock();

  // Lift all instructions
  lifting::InstructionLifter lifter(ctx);
  if (!lifter.LiftInstructionsImpl(start_address, text_section->bytes.data(),
                                   text_section->bytes.size(), block)) {
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

  // Create backing globals from PE sections
  auto memory_info = lifting::CreateMemoryGlobals(ctx.GetSemanticsModule(), *pe_info);

  // Extract just the lifted functions to a separate module (for debugging)
  // This gives us a small "lifted.ll" without the full 7MB runtime
  auto extracted_module = utils::ExtractFunctions(
      ctx.GetSemanticsModule(),
      {"test", "lifted_ret_with_code"},
      "lifted_code");
  utils::WriteModule(extracted_module.get(), "lifted");

  // First optimization pass to fold addresses and inline
  optimization::OptimizeForCleanIR(ctx.GetSemanticsModule(), wrapper);

  // Create stack alloca for stack memory operations
  auto stack_info = lifting::CreateStackAlloca(
      wrapper, lifting::INITIAL_RSP, lifting::STACK_SIZE);

  // Lower memory intrinsics to load/store from local allocas
  // This allows LLVM's SROA to optimize them as local variables
  lifting::LowerMemoryIntrinsics(ctx.GetSemanticsModule(), memory_info,
                                 &stack_info, wrapper);

  // Debug: dump wrapper function after lowering but before second optimization
  {
    std::error_code EC;
    llvm::raw_fd_ostream file("after_lowering_wrapper.ll", EC);
    if (!EC) {
      wrapper->print(file);
      file.close();
      std::cout << "Written: after_lowering_wrapper.ll\n";
    }
  }

  // Extract to a clean module for optimization (with full function body)
  // This avoids interference from other functions in the semantics module
  auto opt_module = utils::ExtractFunctions(
      ctx.GetSemanticsModule(), {"test"}, "test_optimized");

  // Second optimization pass on the extracted module
  auto *opt_func = opt_module->getFunction("test");
  optimization::OptimizeForCleanIR(opt_module.get(), opt_func);

  // Create final clean module with just the constant return
  auto clean_module = utils::CreateCleanModule(
      ctx.GetContext(), opt_func, "test_optimized",
      ctx.GetSemanticsModule()->getTargetTriple(),
      ctx.GetSemanticsModule()->getDataLayout());
  utils::WriteModule(clean_module.get(), "test_optimized");

  return EXIT_SUCCESS;
}
