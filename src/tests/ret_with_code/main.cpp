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
#include "lifting/control_flow_lifter.h"
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

  // Calculate addresses
  uint64_t code_base = pe_info->image_base + text_section->virtual_address;
  uint64_t entry_point = pe_info->image_base + pe_info->entry_point_rva;

  // Create lifted function in semantics module (required by remill's instruction lifter)
  auto *lifted_func = ctx.DefineLiftedFunction("lifted_ret_with_code");

  // Use control flow-aware lifter to handle jumps and loops
  lifting::ControlFlowLifter lifter(ctx);

  // Set PE info for resolving indirect jumps through global variables
  lifter.SetPEInfo(&(*pe_info));

  // Configure iterative lifting with debug output
  lifting::IterativeLiftingConfig lift_config;
  lift_config.max_iterations = 10;
  lift_config.verbose = true;

  // Derive output directory from input path for iteration dumps
  std::string input_path = shellcode_path;
  size_t last_sep = input_path.find_last_of("/\\");
  if (last_sep != std::string::npos) {
    lift_config.dump_iterations_dir = input_path.substr(0, last_sep);
  } else {
    lift_config.dump_iterations_dir = ".";
  }
  lifter.SetIterativeConfig(lift_config);

  if (!lifter.LiftFunction(code_base, entry_point, text_section->bytes.data(),
                           text_section->bytes.size(), lifted_func)) {
    std::cerr << "Failed to lift instructions\n";
    return EXIT_FAILURE;
  }

  // Prepare lifted function for inlining
  lifting::WrapperBuilder::PrepareForInlining(lifted_func);

  // Create wrapper function
  lifting::WrapperBuilder wrapper_builder(ctx);
  auto *wrapper = wrapper_builder.CreateInt32ReturnWrapper(
      "test", lifted_func, entry_point);

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

  // Remove flag computation intrinsics that block loop optimization
  // These are identity functions used for debugging
  optimization::RemoveFlagComputationIntrinsics(opt_module.get());

  // Debug: dump module after intrinsic removal
  utils::WriteLLFile(opt_module.get(), "after_intrinsic_removal.ll");

  // Run full O3 optimization to fold loops and constant propagation
  optimization::OptimizeAggressive(opt_module.get());

  // Write the optimized module
  utils::WriteModule(opt_module.get(), "test_optimized");

  return EXIT_SUCCESS;
}
