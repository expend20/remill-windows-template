#include <cstdint>
#include <cstring>
#include <iostream>

#include <remill/Arch/X86/Runtime/State.h>

// Declare the lifted function (defined in lifted.ll)
extern "C" void* lifted_mov_eax_ret(State* state, uint64_t pc, void* memory);

int main() {
  // Create and initialize state
  alignas(16) State state = {};
  memset(&state, 0, sizeof(state));

  // Set up a small stack for the ret instruction
  alignas(16) uint8_t stack[4096] = {};
  // Point RSP to the middle of the stack, leaving room for pushes/pops
  state.gpr.rsp.qword = reinterpret_cast<uint64_t>(stack + 2048);

  // Set initial RAX to 0
  state.gpr.rax.qword = 0;

  std::cout << "RAX before: 0x" << std::hex << state.gpr.rax.qword << "\n";

  // Execute the lifted function
  void* memory = nullptr;
  lifted_mov_eax_ret(&state, 0x1000, memory);

  std::cout << "RAX after:  0x" << std::hex << state.gpr.rax.qword << "\n";

  // Verify result (mov eax, 0x1337 should set RAX to 0x1337)
  if (state.gpr.rax.qword == 0x1337) {
    std::cout << "\n[SUCCESS] RAX == 0x1337\n";
    return 0;
  } else {
    std::cerr << "\n[FAILURE] Expected RAX=0x1337, got 0x" << std::hex << state.gpr.rax.qword << "\n";
    return 1;
  }
}
