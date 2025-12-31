// Variable lifting test
// Lifts code with variable (non-constant) register inputs
// Also supports external function calls (imports like puts)
// Produces an executable that takes input values and returns the computed result

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

#include <glog/logging.h>
#include <remill/BC/Util.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/raw_ostream.h>

#include "lifting/lifting_context.h"
#include "lifting/control_flow_lifter.h"
#include "lifting/memory_lowering.h"
#include "lifting/wrapper_builder.h"
#include "lifting/variable_config.h"
#include "lifting/external_call_handler.h"
#include "optimization/optimizer.h"
#include "utils/debug_flag.h"
#include "utils/module_utils.h"
#include "utils/pe_reader.h"

// Generate main function that parses args and calls test function
void GenerateMainFunction(llvm::Module *module, llvm::Function *test_func,
                          const std::vector<std::string> &param_names) {
  auto &context = module->getContext();
  llvm::IRBuilder<> builder(context);

  auto *i32_type = builder.getInt32Ty();
  auto *i64_type = builder.getInt64Ty();
  auto *ptr_type = builder.getPtrTy();

  // Declare strtoll
  auto *strtoll_type = llvm::FunctionType::get(i64_type, {ptr_type, ptr_type, i32_type}, false);
  auto *strtoll_func = llvm::Function::Create(
      strtoll_type, llvm::GlobalValue::ExternalLinkage, "strtoll", module);

  // Create main(int argc, char **argv) -> int
  auto *main_type = llvm::FunctionType::get(i32_type, {i32_type, ptr_type}, false);
  auto *main_func = llvm::Function::Create(
      main_type, llvm::GlobalValue::ExternalLinkage, "main", module);

  auto *entry = llvm::BasicBlock::Create(context, "entry", main_func);
  builder.SetInsertPoint(entry);

  auto args_it = main_func->arg_begin();
  llvm::Value *argc = &*args_it++;
  llvm::Value *argv = &*args_it;
  argc->setName("argc");
  argv->setName("argv");

  // Parse arguments: argv[1], argv[2], ...
  std::vector<llvm::Value *> call_args;
  for (size_t i = 0; i < param_names.size(); ++i) {
    // Get argv[i+1]
    auto *argv_ptr = builder.CreateGEP(ptr_type, argv,
        builder.getInt64(i + 1), "argv_ptr_" + std::to_string(i));
    auto *arg_str = builder.CreateLoad(ptr_type, argv_ptr, "arg_str_" + std::to_string(i));

    // Parse as i64 using strtoll
    auto *null_ptr = llvm::ConstantPointerNull::get(ptr_type);
    auto *parsed = builder.CreateCall(strtoll_func,
        {arg_str, null_ptr, builder.getInt32(10)}, param_names[i] + "_val");
    call_args.push_back(parsed);
  }

  // Call test function
  auto *result = builder.CreateCall(test_func, call_args, "result");

  // Return lower 32 bits as exit code
  auto *exit_code = builder.CreateTrunc(result, i32_type, "exit_code");
  builder.CreateRet(exit_code);
}

void PrintUsage(const char *prog) {
  std::cerr << "Usage: " << prog << " <shellcode.exe> <config.json> [--debug]\n";
}

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);

  if (argc < 3) {
    PrintUsage(argv[0]);
    return EXIT_FAILURE;
  }

  const char *shellcode_path = argv[1];
  const char *config_path = argv[2];

  // Parse --debug flag
  for (int i = 3; i < argc; ++i) {
    if (std::string(argv[i]) == "--debug") {
      utils::g_debug = true;
    }
  }

  // Parse config
  auto config = lifting::ParseVariableConfig(config_path);
  if (!config) {
    return EXIT_FAILURE;
  }

  if (config->HasVariableInputs()) {
    std::cout << "Variable registers: ";
    for (const auto &var : config->input_registers) {
      std::cout << var << " ";
    }
    std::cout << "\n";
  }
  std::cout << "Return register: " << config->return_register << "\n";

  if (config->external_calls.HasExternalCalls()) {
    std::cout << "External calls configured: ";
    for (const auto &[name, cfg] : config->external_calls.GetAllConfigs()) {
      std::cout << name << "(" << cfg.arg_types.size() << " args) ";
    }
    std::cout << "\n";
  }

  // Read full PE file
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
  std::cout << "Found " << pe_info->imports.size() << " imports\n";

  // Print imports for debugging
  for (const auto &import : pe_info->imports) {
    utils::dbg() << "Import: " << import.dll_name << "::" << import.function_name
                 << " at IAT VA " << llvm::format_hex(import.iat_va, 0) << "\n";
  }

  // Link external call config with PE imports
  config->external_calls.LinkWithImports(pe_info->imports);

  // Initialize lifting context
  lifting::LiftingContext ctx("windows", "amd64");
  if (!ctx.IsValid()) {
    return EXIT_FAILURE;
  }

  // Create external call handler (may be empty if no external calls configured)
  lifting::ExternalCallHandler external_handler(ctx, config->external_calls);

  // Configure handler with PE info for pointer resolution
  external_handler.SetPEInfo(&(*pe_info));
  external_handler.SetResolvePointerData(config->resolve_pointer_data);

  if (config->resolve_pointer_data) {
    std::cout << "Pointer data resolution: enabled\n";
  }

  // Create external function declarations BEFORE lifting
  // so they're available when generating external calls
  if (config->external_calls.HasExternalCalls()) {
    external_handler.CreateDeclarations(ctx.GetSemanticsModule());
  }

  // Calculate addresses
  uint64_t code_base = pe_info->image_base + text_section->virtual_address;
  uint64_t entry_point = pe_info->image_base + pe_info->entry_point_rva;

  // Create lifted function
  auto *lifted_func = ctx.DefineLiftedFunction("lifted_variable");

  // Use control flow-aware lifter
  lifting::ControlFlowLifter lifter(ctx);
  lifter.SetPEInfo(&(*pe_info));

  // Set external call handler if we have external calls
  if (config->external_calls.HasExternalCalls()) {
    lifter.SetExternalCallHandler(&external_handler);
  }

  // Configure iterative lifting
  lifting::IterativeLiftingConfig lift_config;
  lift_config.max_iterations = 15;
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

  // Create wrapper (with or without variable registers)
  llvm::Function *wrapper = nullptr;
  lifting::WrapperBuilder wrapper_builder(ctx);

  if (!config->HasVariableInputs()) {
    // No variable inputs - create constant wrapper
    wrapper = wrapper_builder.CreateInt32ReturnWrapper("test", lifted_func, entry_point);
  } else {
    // Variable inputs - create parameterized wrapper
    wrapper = wrapper_builder.CreateParameterizedWrapper(
        "test", lifted_func, entry_point, *config);
  }

  // Create backing globals from PE sections
  auto memory_info = lifting::CreateMemoryGlobals(ctx.GetSemanticsModule(), *pe_info);

  // Extract lifted functions for debugging
  auto extracted_module = utils::ExtractFunctions(
      ctx.GetSemanticsModule(),
      {"test", "lifted_variable"},
      "lifted_code");
  utils::WriteModule(extracted_module.get(), "lifted");

  // First optimization pass
  optimization::OptimizeForCleanIR(ctx.GetSemanticsModule(), wrapper);

  // Create stack alloca
  auto stack_info = lifting::CreateStackAlloca(
      wrapper, lifting::INITIAL_RSP, lifting::STACK_SIZE);

  // Pass stack info to external handler for stack pointer resolution
  external_handler.SetStackInfo(lifting::INITIAL_RSP, lifting::STACK_SIZE);

  // Lower memory intrinsics
  lifting::LowerMemoryIntrinsics(ctx.GetSemanticsModule(), memory_info,
                                 &stack_info, wrapper);

  // Extract to clean module for optimization
  // Include external function declarations if present
  std::vector<std::string> funcs_to_extract = {"test"};
  for (const auto &[name, cfg] : config->external_calls.GetAllConfigs()) {
    funcs_to_extract.push_back(name);
  }
  auto opt_module = utils::ExtractFunctions(
      ctx.GetSemanticsModule(), funcs_to_extract, "test_optimized");

  // Debug: dump IR right after extraction
  utils::WriteModule(opt_module.get(), "after_extraction");
  std::cout << "Written: after_extraction.ll (for debugging)\n";

  // Remove flag computation intrinsics
  optimization::RemoveFlagComputationIntrinsics(opt_module.get());

  // Phase 1: Resolve constant pointers BEFORE optimization
  // This converts inttoptr(constant) to GEP, keeping the alloca alive
  // For puts_stack: pointer is already constant, resolves immediately
  // For xorstr: pointer is dynamic, will be resolved after XOR folding
  size_t resolved_phase1 = 0;
  if (config->resolve_pointer_data) {
    resolved_phase1 = external_handler.ResolveConstantPointers(opt_module.get());
    if (resolved_phase1 > 0) {
      std::cout << "Resolved " << resolved_phase1 << " pointer argument(s) in phase 1\n";
    }
  }

  // Phase 2: Fold XOR/loop operations without eliminating stores
  // This runs O3-like optimization but skips Dead Store Elimination
  // so that stores to stack memory remain alive until pointer resolution
  optimization::OptimizeWithoutDSE(opt_module.get());

  // Debug: dump IR after OptimizeWithoutDSE
  utils::WriteModule(opt_module.get(), "after_no_dse");
  std::cout << "Written: after_no_dse.ll (for debugging)\n";

  // Phase 3: Resolve constant pointers again (for xorstr case)
  // After OptimizeWithoutDSE, XOR operations are folded, making pointers constant
  if (config->resolve_pointer_data && resolved_phase1 == 0) {
    size_t resolved_phase2 = external_handler.ResolveConstantPointers(opt_module.get());
    if (resolved_phase2 > 0) {
      std::cout << "Resolved " << resolved_phase2 << " pointer argument(s) in phase 2\n";
    }
  }

  // Phase 3: Full optimization including Dead Store Elimination
  // The GEPs created above keep the stores alive
  optimization::OptimizeAggressive(opt_module.get());

  // Write the optimized module
  utils::WriteModule(opt_module.get(), "test_optimized");

  // Verify external calls are present (if configured)
  bool found_external_call = false;
  if (auto *test_func = opt_module->getFunction("test")) {
    for (auto &BB : *test_func) {
      for (auto &I : BB) {
        if (auto *call = llvm::dyn_cast<llvm::CallInst>(&I)) {
          if (auto *callee = call->getCalledFunction()) {
            if (config->external_calls.FindByName(callee->getName().str())) {
              std::cout << "External call preserved: " << callee->getName().str() << "\n";
              found_external_call = true;
            }
          }
        }
      }
    }
  }

  if (config->external_calls.HasExternalCalls() && !found_external_call) {
    std::cerr << "WARNING: Expected external calls were not found in optimized IR\n";
  }

  // Generate main function for variable test runner (only if we have variables)
  if (config->HasVariableInputs()) {
    auto *test_func = opt_module->getFunction("test");
    if (!test_func) {
      std::cerr << "Test function not found after optimization\n";
      return EXIT_FAILURE;
    }

    GenerateMainFunction(opt_module.get(), test_func, config->input_registers);

    // Write module with main function
    utils::WriteModule(opt_module.get(), "test_runner");
    std::cout << "Written: test_runner.ll, test_runner.bc\n";
  }

  std::cout << "Written: test_optimized.ll, test_optimized.bc\n";
  std::cout << "Written: lifted.ll, lifted.bc\n";

  return EXIT_SUCCESS;
}
