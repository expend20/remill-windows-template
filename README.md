# Remill Windows Template

A template project demonstrating how to use [remill](https://github.com/lifting-bits/remill) on Windows to lift x86 machine code to LLVM IR.

## Prerequisites

- Visual Studio 2022 with C++ and Clang toolchain
- CMake 3.15+
- Ninja build system

## Building Dependencies

First, build the dependencies (LLVM, remill, etc.):

```bash
cd dependencies
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang-cl \
    -DCMAKE_CXX_COMPILER=clang-cl
cmake --build build
```

This will take a while as it builds LLVM from source.

## Building the Project

```bash
cmake -B build -G Ninja \
    -DCMAKE_PREFIX_PATH=dependencies/install \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang-cl \
    -DCMAKE_CXX_COMPILER=clang-cl
cmake --build build
```

## HelloWorld

The HelloWorld example demonstrates lifting a simple x86 instruction (`mov rcx, 1337`) to LLVM IR, compiling it, and executing it.

### Running the Test

Build and run the test:

```bash
cmake --build build --target test_lifted
./build/test_lifted.exe
```

Expected output:

```
RCX before: 0
RCX after:  1337

[SUCCESS] RCX == 1337
```

Or run via CTest:

```bash
cd build
ctest -V
```

### How It Works

1. **hello_world.exe** - Lifts the x86 instruction to LLVM IR:
   ```bash
   cd build
   ./hello_world.exe
   ```
   This generates:
   - `lifted.bc` - LLVM bitcode
   - `lifted.ll` - Human-readable LLVM IR

2. **runtime.ll** - Provides stub implementations for remill intrinsics (memory access, flags, etc.)

3. **test_lifted.exe** - Links the lifted code with a test harness that:
   - Creates an x86 State structure
   - Calls the lifted function
   - Verifies RCX == 1337

### Inspecting the Lifted IR

After running `hello_world.exe`, inspect the generated `lifted.ll`:

```bash
# View the lifted function (in build directory)
cat build/lifted.ll | grep -A 30 "define.*@lifted_mov_rcx"
```

The optimized lifted function looks like:

```llvm
define ptr @lifted_mov_rcx(ptr noalias %state, i64 %program_counter, ptr noalias %memory) {
  %RCX = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 5, i32 0, i32 0
  ; ... stack allocations for temporaries ...
  store i64 1337, ptr %RCX, align 8    ; <-- This is the mov rcx, 1337
  ; ...
  ret ptr %4
}
```

Key observations:
- The function takes `State*`, `program_counter`, and `memory` pointer
- It computes the address of RCX in the State struct via GEP
- The `store i64 1337` is the actual `mov rcx, 1337` operation
- Returns the memory pointer (for chaining instructions)

### Disassembling the Lifted Code

You can also disassemble the compiled object file:

```bash
llvm-objdump -d build/lifted_combined.o | grep -A 20 "lifted_mov_rcx"
```

## Project Structure

```
.
├── CMakeLists.txt              # Main build configuration
├── cmake/
│   └── FindLLVM-Wrapper.cmake  # LLVM CMake helper
├── dependencies/
│   ├── CMakeLists.txt          # Dependencies build
│   ├── superbuild.cmake        # ExternalProject helpers
│   ├── llvm.cmake              # LLVM build config
│   └── xed.cmake               # XED build config
└── src/
    └── helloworld/
        ├── main.cpp            # Lifter - generates IR
        ├── runtime.ll          # Remill intrinsic stubs
        └── test_harness.cpp    # Test executable
```

## License

See individual component licenses (LLVM, remill, etc.)
