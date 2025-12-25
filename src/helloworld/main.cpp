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

  // mov eax, 0x1337; ret
  uint8_t instr_bytes[] = {0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3};
  std::string_view instr_view(reinterpret_cast<char *>(instr_bytes),
                              sizeof(instr_bytes));
  remill::DecodingContext decoding_context = arch->CreateInitialContext();

  auto function =
      arch->DefineLiftedFunction("lifted_mov_eax_ret", semantics.get());
  auto block = &function->getEntryBlock();

  // Decode and lift: mov eax, 0x1337
  remill::Instruction mov_instr;
  if (!arch->DecodeInstruction(0x1000, instr_view, mov_instr,
                               decoding_context)) {
    std::cerr << "Failed to decode mov instruction\n";
    return EXIT_FAILURE;
  }
  auto mov_lifter = mov_instr.GetLifter();
  auto mov_status = mov_lifter->LiftIntoBlock(mov_instr, block);
  if (mov_status != remill::kLiftedInstruction) {
    std::cerr << "Failed to lift mov instruction\n";
    return EXIT_FAILURE;
  }

  // Decode and lift: ret
  std::string_view ret_view(reinterpret_cast<char *>(instr_bytes) + 5, 1);
  remill::Instruction ret_instr;
  if (!arch->DecodeInstruction(0x1005, ret_view, ret_instr,
                               decoding_context)) {
    std::cerr << "Failed to decode ret instruction\n";
    return EXIT_FAILURE;
  }
  auto ret_lifter = ret_instr.GetLifter();
  auto ret_status = ret_lifter->LiftIntoBlock(ret_instr, block);
  if (ret_status != remill::kLiftedInstruction) {
    std::cerr << "Failed to lift ret instruction\n";
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
