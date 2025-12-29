// obfuscator.exe - Applies Pluto obfuscation passes to LLVM IR
// Usage: obfuscator <input.ll> <output.ll> --passes="<passes>"
//
// This is a standalone tool that links Pluto passes statically,
// eliminating ODR violations that occur when loading passes.dll as a plugin.

#include <iostream>
#include <string>

#include <llvm/IR/Module.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/Utils/LowerSwitch.h>

// Pluto obfuscation passes
#include "Pluto/BogusControlFlowPass.h"
#include "Pluto/Flattening.h"
#include "Pluto/GlobalEncryption.h"
#include "Pluto/IndirectCall.h"
#include "Pluto/MBAObfuscation.h"
#include "Pluto/Substitution.h"

using namespace llvm;

// Command line options
static cl::opt<std::string> InputFilename(
    cl::Positional, cl::desc("<input .ll file>"), cl::Required);

static cl::opt<std::string> OutputFilename(
    cl::Positional, cl::desc("<output .ll file>"), cl::Required);

static cl::opt<std::string> PassPipeline(
    "passes", cl::desc("Pass pipeline to run"), cl::Required);

// Register Pluto passes with PassBuilder
static void registerPlutoPasses(PassBuilder &PB) {
  // Register module passes
  PB.registerPipelineParsingCallback(
      [](StringRef Name, ModulePassManager &MPM,
         ArrayRef<PassBuilder::PipelineElement>) {
        if (Name == "pluto-global-encryption") {
          MPM.addPass(Pluto::GlobalEncryption());
          return true;
        }
        if (Name == "pluto-indirect-call") {
          MPM.addPass(Pluto::IndirectCall());
          return true;
        }
        return false;
      });

  // Register function passes
  PB.registerPipelineParsingCallback(
      [](StringRef Name, FunctionPassManager &FPM,
         ArrayRef<PassBuilder::PipelineElement>) {
        if (Name == "pluto-bogus-control-flow") {
          FPM.addPass(Pluto::BogusControlFlowPass());
          return true;
        }
        if (Name == "pluto-flattening") {
          // LowerSwitch is a mandatory prerequisite for Flattening
          FPM.addPass(LowerSwitchPass());
          FPM.addPass(Pluto::Flattening());
          return true;
        }
        if (Name == "pluto-mba-obfuscation") {
          FPM.addPass(Pluto::MbaObfuscation());
          return true;
        }
        if (Name == "pluto-substitution") {
          FPM.addPass(Pluto::Substitution());
          return true;
        }
        return false;
      });
}

int main(int argc, char **argv) {
  InitLLVM X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "Pluto obfuscation tool\n");

  // Create LLVM context and load input module
  LLVMContext Context;
  SMDiagnostic Err;

  std::unique_ptr<Module> M = parseIRFile(InputFilename, Err, Context);
  if (!M) {
    Err.print(argv[0], errs());
    return 1;
  }

  // Verify input module
  if (verifyModule(*M, &errs())) {
    errs() << "Input module is broken!\n";
    return 1;
  }

  // Create pass builder and register Pluto passes
  LoopAnalysisManager LAM;
  FunctionAnalysisManager FAM;
  CGSCCAnalysisManager CGAM;
  ModuleAnalysisManager MAM;

  PassBuilder PB;
  registerPlutoPasses(PB);

  // Register analysis passes
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  // Parse and run the pass pipeline
  ModulePassManager MPM;
  if (auto Err = PB.parsePassPipeline(MPM, PassPipeline)) {
    errs() << "Failed to parse pass pipeline: " << toString(std::move(Err)) << "\n";
    return 1;
  }

  // Run the passes
  MPM.run(*M, MAM);

  // Verify output module
  if (verifyModule(*M, &errs())) {
    errs() << "Output module is broken after obfuscation!\n";
    return 1;
  }

  // Write output module
  std::error_code EC;
  raw_fd_ostream OS(OutputFilename, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "Could not open output file: " << EC.message() << "\n";
    return 1;
  }

  M->print(OS, nullptr);
  return 0;
}
