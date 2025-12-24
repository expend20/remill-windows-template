#include <cstdlib>
#include <fstream>
#include <iostream>

#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/raw_ostream.h>

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);

  auto context = std::make_unique<llvm::LLVMContext>();
  auto arch = remill::Arch::Get(*context, "windows", "amd64");
  if (!arch) {
    std::cerr << "Failed to get architecture\n";
    return EXIT_FAILURE;
  }

  auto semantics = remill::LoadArchSemantics(arch.get());
  if (!semantics) {
    std::cerr << "Failed to load architecture semantics\n";
    return EXIT_FAILURE;
  }

  auto intrinsics = arch->GetInstrinsicTable();
  if (!intrinsics) {
    std::cerr << "Failed to get intrinsic table\n";
    return EXIT_FAILURE;
  }

  // mov rcx, 1337
  uint8_t instr_bytes[] = {0x48, 0xc7, 0xc1, 0x39, 0x05, 0x00, 0x00};
  std::string_view instr_view(reinterpret_cast<char *>(instr_bytes),
                              sizeof(instr_bytes));
  remill::Instruction instruction;
  remill::DecodingContext decoding_context = arch->CreateInitialContext();
  if (!arch->DecodeInstruction(0x1000, instr_view, instruction,
                               decoding_context)) {
    std::cerr << "Failed to decode instruction\n";
    return EXIT_FAILURE;
  }

  auto function =
      arch->DefineLiftedFunction("lifted_mov_rcx", semantics.get());
  auto block = &function->getEntryBlock();
  auto lifter = instruction.GetLifter();
  auto status = lifter->LiftIntoBlock(instruction, block);
  if (status != remill::kLiftedInstruction) {
    std::cerr << "Failed to lift instruction\n";
    return EXIT_FAILURE;
  }

  // Finish the lifted block by returning the memory pointer
  llvm::IRBuilder<> ir(block);
  ir.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));

  // Optimize the module
  remill::OptimizeModule(arch.get(), semantics.get(), {function});

  // Print optimized IR to stdout
  std::cout << "[Optimized IR]\n";
  function->print(llvm::outs());
  std::cout << "\n";

  // Write bitcode to file
  std::error_code EC;
  llvm::raw_fd_ostream bc_file("lifted.bc", EC);
  if (EC) {
    std::cerr << "Failed to open lifted.bc: " << EC.message() << "\n";
    return EXIT_FAILURE;
  }
  llvm::WriteBitcodeToFile(*semantics, bc_file);
  bc_file.close();
  std::cout << "Written: lifted.bc\n";

  // Also write human-readable IR
  llvm::raw_fd_ostream ll_file("lifted.ll", EC);
  if (EC) {
    std::cerr << "Failed to open lifted.ll: " << EC.message() << "\n";
    return EXIT_FAILURE;
  }
  semantics->print(ll_file, nullptr);
  ll_file.close();
  std::cout << "Written: lifted.ll\n";

  return EXIT_SUCCESS;
}
