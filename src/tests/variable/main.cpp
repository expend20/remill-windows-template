// Variable lifting test
// Lifts code with variable (non-constant) register inputs
// Produces an executable that takes input values and returns the computed result

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

#include <glog/logging.h>
#include <remill/BC/Util.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include "lifting/lifting_context.h"
#include "lifting/control_flow_lifter.h"
#include "lifting/memory_lowering.h"
#include "lifting/wrapper_builder.h"
#include "optimization/optimizer.h"
#include "utils/debug_flag.h"
#include "utils/module_utils.h"
#include "utils/pe_reader.h"

// Config structure parsed from JSON
struct VariableTestConfig {
  std::vector<std::string> variables;
  std::string return_register = "rax";
};

// Parse config from JSON file using LLVM's JSON parser
std::optional<VariableTestConfig> ParseConfig(const std::string &config_path) {
  auto buffer = llvm::MemoryBuffer::getFile(config_path);
  if (!buffer) {
    std::cerr << "Failed to read config file: " << config_path << "\n";
    return std::nullopt;
  }

  auto json = llvm::json::parse(buffer.get()->getBuffer());
  if (!json) {
    std::cerr << "Failed to parse JSON: " << llvm::toString(json.takeError()) << "\n";
    return std::nullopt;
  }

  auto *root = json->getAsObject();
  if (!root) {
    std::cerr << "Config must be a JSON object\n";
    return std::nullopt;
  }

  VariableTestConfig config;

  // Parse "variables": ["rcx", "rdx", ...]
  if (auto *vars = root->getArray("variables")) {
    for (const auto &var : *vars) {
      if (auto str = var.getAsString()) {
        config.variables.push_back(str->str());
      }
    }
  }

  // Parse "return_register": "rax"
  if (auto ret = root->getString("return_register")) {
    config.return_register = ret->str();
  }

  if (config.variables.empty()) {
    std::cerr << "No variables found in config\n";
    return std::nullopt;
  }

  return config;
}

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
  auto config = ParseConfig(config_path);
  if (!config) {
    return EXIT_FAILURE;
  }

  std::cout << "Variable registers: ";
  for (const auto &var : config->variables) {
    std::cout << var << " ";
  }
  std::cout << "\n";
  std::cout << "Return register: " << config->return_register << "\n";

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

  // Initialize lifting context
  lifting::LiftingContext ctx("windows", "amd64");
  if (!ctx.IsValid()) {
    return EXIT_FAILURE;
  }

  // Calculate addresses
  uint64_t code_base = pe_info->image_base + text_section->virtual_address;
  uint64_t entry_point = pe_info->image_base + pe_info->entry_point_rva;

  // Create lifted function
  auto *lifted_func = ctx.DefineLiftedFunction("lifted_variable");

  // Use control flow-aware lifter
  lifting::ControlFlowLifter lifter(ctx);
  lifter.SetPEInfo(&(*pe_info));

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

  // Create parameterized wrapper with variable registers
  lifting::VariableConfig var_config;
  var_config.input_registers = config->variables;
  var_config.return_register = config->return_register;

  lifting::WrapperBuilder wrapper_builder(ctx);
  auto *wrapper = wrapper_builder.CreateParameterizedWrapper(
      "test", lifted_func, entry_point, var_config);

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

  // Lower memory intrinsics
  lifting::LowerMemoryIntrinsics(ctx.GetSemanticsModule(), memory_info,
                                 &stack_info, wrapper);

  // Extract to clean module for optimization
  auto opt_module = utils::ExtractFunctions(
      ctx.GetSemanticsModule(), {"test"}, "test_optimized");

  // Remove flag computation intrinsics
  optimization::RemoveFlagComputationIntrinsics(opt_module.get());

  // Run aggressive optimization
  optimization::OptimizeAggressive(opt_module.get());

  // Write the optimized module
  utils::WriteModule(opt_module.get(), "test_optimized");

  // Generate main function for test runner
  auto *test_func = opt_module->getFunction("test");
  if (!test_func) {
    std::cerr << "Test function not found after optimization\n";
    return EXIT_FAILURE;
  }

  GenerateMainFunction(opt_module.get(), test_func, config->variables);

  // Write module with main function
  utils::WriteModule(opt_module.get(), "test_runner");

  std::cout << "Written: test_optimized.ll, test_optimized.bc\n";
  std::cout << "Written: test_runner.ll, test_runner.bc\n";

  return EXIT_SUCCESS;
}
