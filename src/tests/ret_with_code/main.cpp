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
#include "lifting/memory_provider.h"
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

  // Create lifted function
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

  // Create memory provider for data section lookups
  lifting::PEMemoryProvider memory_provider(*pe_info);

  // First optimization pass to fold addresses
  optimization::OptimizeForCleanIR(ctx.GetSemanticsModule(), wrapper);

  // Replace memory intrinsics with concrete values where possible
  optimization::ReplaceMemoryIntrinsics(ctx.GetSemanticsModule(), &memory_provider);

  // Second optimization pass to fold the resolved constants
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
