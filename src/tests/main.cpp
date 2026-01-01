// Unified lifter for binary deobfuscation
// Lifts x86-64 PE binaries to LLVM IR and optimizes aggressively
// Unresolved variables and external calls are preserved as-is
//
// Usage:
//   lifter <shellcode.exe> [config.json] [--debug]

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
  std::cerr << "Usage: " << prog << " <shellcode.exe> [config.json] [--debug]\n";
}

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);

  if (argc < 2) {
    PrintUsage(argv[0]);
    return EXIT_FAILURE;
  }

  const char *shellcode_path = argv[1];
  const char *config_path = nullptr;

  // Parse arguments: config file (if .json) and --debug flag
  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--debug") {
      utils::g_debug = true;
    } else if (arg.size() > 5 && arg.substr(arg.size() - 5) == ".json") {
      config_path = argv[i];
    }
  }

  // Parse config (use default if not provided)
  lifting::VariableConfig config;
  if (config_path) {
    auto parsed = lifting::ParseVariableConfig(config_path);
    if (!parsed) {
      return EXIT_FAILURE;
    }
    config = std::move(*parsed);

    if (config.HasVariableInputs()) {
      std::cout << "Variable registers: ";
      for (const auto &var : config.input_registers) {
        std::cout << var << " ";
      }
      std::cout << "\n";
    }
    std::cout << "Return register: " << config.return_register << "\n";

    if (config.external_calls.HasExternalCalls()) {
      std::cout << "External calls configured: ";
      for (const auto &[name, cfg] : config.external_calls.GetAllConfigs()) {
        std::cout << name << "(" << cfg.arg_types.size() << " args) ";
      }
      std::cout << "\n";
    }
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
  for (const auto &sec : pe_info->sections) {
    std::cout << "  " << sec.name << ": " << sec.bytes.size() << " bytes at RVA 0x"
              << std::hex << sec.virtual_address << std::dec << "\n";
  }

  std::cout << "Found " << pe_info->imports.size() << " imports\n";
  for (const auto &import : pe_info->imports) {
    utils::dbg() << "Import: " << import.dll_name << "::" << import.function_name
                 << " at IAT VA " << llvm::format_hex(import.iat_va, 0) << "\n";
  }

  // Link external call config with PE imports
  config.external_calls.LinkWithImports(pe_info->imports);

  // Initialize lifting context
  lifting::LiftingContext ctx("windows", "amd64");
  if (!ctx.IsValid()) {
    return EXIT_FAILURE;
  }

  // Create external call handler
  lifting::ExternalCallHandler external_handler(ctx, config.external_calls);
  external_handler.SetPEInfo(&(*pe_info));
  external_handler.SetResolvePointerData(config.resolve_pointer_data);

  if (config.resolve_pointer_data) {
    std::cout << "Pointer data resolution: enabled\n";
  }

  // Create external function declarations BEFORE lifting
  if (config.external_calls.HasExternalCalls()) {
    external_handler.CreateDeclarations(ctx.GetSemanticsModule());
  }

  // Calculate addresses
  uint64_t code_base = pe_info->image_base + text_section->virtual_address;
  uint64_t entry_point = pe_info->image_base + pe_info->entry_point_rva;

  // Create lifted function
  auto *lifted_func = ctx.DefineLiftedFunction("lifted_func");

  // Use control flow-aware lifter
  lifting::ControlFlowLifter lifter(ctx);
  lifter.SetPEInfo(&(*pe_info));

  // Set external call handler if we have external calls
  if (config.external_calls.HasExternalCalls()) {
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

  // Create wrapper
  llvm::Function *wrapper = nullptr;
  lifting::WrapperBuilder wrapper_builder(ctx);

  if (!config.HasVariableInputs()) {
    // No variable inputs - create constant wrapper
    wrapper = wrapper_builder.CreateInt32ReturnWrapper("test", lifted_func, entry_point);
  } else {
    // Variable inputs - create parameterized wrapper
    wrapper = wrapper_builder.CreateParameterizedWrapper(
        "test", lifted_func, entry_point, config);
  }

  // Create backing globals from PE sections
  auto memory_info = lifting::CreateMemoryGlobals(ctx.GetSemanticsModule(), *pe_info);

  // Extract lifted functions for debugging
  auto extracted_module = utils::ExtractFunctions(
      ctx.GetSemanticsModule(),
      {"test", "lifted_func"},
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
  for (const auto &[name, cfg] : config.external_calls.GetAllConfigs()) {
    funcs_to_extract.push_back(name);
  }
  auto opt_module = utils::ExtractFunctions(
      ctx.GetSemanticsModule(), funcs_to_extract, "test_optimized");

  // Remove flag computation intrinsics
  optimization::RemoveFlagComputationIntrinsics(opt_module.get());

  // Phase optimization for pointer resolution
  size_t resolved_phase1 = 0;
  if (config.resolve_pointer_data) {
    resolved_phase1 = external_handler.ResolveConstantPointers(opt_module.get());
    if (resolved_phase1 > 0) {
      std::cout << "Resolved " << resolved_phase1 << " pointer argument(s) in phase 1\n";
    }

    // Phase 2: Fold XOR/loop operations without eliminating stores
    optimization::OptimizeWithoutDSE(opt_module.get());

    // Phase 3: Resolve constant pointers again (for xorstr case)
    if (resolved_phase1 == 0) {
      size_t resolved_phase2 = external_handler.ResolveConstantPointers(opt_module.get());
      if (resolved_phase2 > 0) {
        std::cout << "Resolved " << resolved_phase2 << " pointer argument(s) in phase 2\n";
      }
    }
  }

  // Run full O3 optimization to fold loops and constant propagation
  optimization::OptimizeAggressive(opt_module.get());

  // Write the optimized module
  utils::WriteModule(opt_module.get(), "test_optimized");

  // Report external calls if present
  if (config.external_calls.HasExternalCalls()) {
    bool found_external_call = false;
    if (auto *test_func = opt_module->getFunction("test")) {
      for (auto &BB : *test_func) {
        for (auto &I : BB) {
          if (auto *call = llvm::dyn_cast<llvm::CallInst>(&I)) {
            if (auto *callee = call->getCalledFunction()) {
              if (config.external_calls.FindByName(callee->getName().str())) {
                std::cout << "External call preserved: " << callee->getName().str() << "\n";
                found_external_call = true;
              }
            }
          }
        }
      }
    }

    if (!found_external_call) {
      std::cerr << "WARNING: Expected external calls were not found in optimized IR\n";
    }
  }

  // Generate main function for test runner (only if we have variable inputs)
  if (config.HasVariableInputs()) {
    auto *test_func = opt_module->getFunction("test");
    if (!test_func) {
      std::cerr << "Test function not found after optimization\n";
      return EXIT_FAILURE;
    }

    GenerateMainFunction(opt_module.get(), test_func, config.input_registers);

    // Write module with main function
    utils::WriteModule(opt_module.get(), "test_runner");
    std::cout << "Written: test_runner.ll, test_runner.bc\n";
  }

  std::cout << "Written: test_optimized.ll, test_optimized.bc\n";
  std::cout << "Written: lifted.ll, lifted.bc\n";

  return EXIT_SUCCESS;
}
