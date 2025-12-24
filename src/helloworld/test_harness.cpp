#include <cstdint>
#include <cstring>
#include <iostream>

#include <remill/Arch/X86/Runtime/State.h>

// Declare the lifted function (defined in lifted.ll)
extern "C" void* lifted_mov_rcx(State* state, uint64_t pc, void* memory);

int main() {
  // Create and initialize state
  alignas(16) State state = {};
  memset(&state, 0, sizeof(state));

  // Set initial RCX to 0
  state.gpr.rcx.qword = 0;

  std::cout << "RCX before: " << state.gpr.rcx.qword << "\n";

  // Execute the lifted function
  void* memory = nullptr;
  lifted_mov_rcx(&state, 0x1000, memory);

  std::cout << "RCX after:  " << state.gpr.rcx.qword << "\n";

  // Verify result
  if (state.gpr.rcx.qword == 1337) {
    std::cout << "\n[SUCCESS] RCX == 1337\n";
    return 0;
  } else {
    std::cerr << "\n[FAILURE] Expected RCX=1337, got " << state.gpr.rcx.qword << "\n";
    return 1;
  }
}
