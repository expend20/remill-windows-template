# Project

This project is a binari deobfuscator leveraging remill (@src/deps/remill) for binary lifting to llvm and massaging code after it to extract original program logic.

There are obfuscation passes (@src/deps/llvm-ob-passes) which are used for obfuscating code to produce a binary which is then lifted in tests.

## Testing

If you discover edge case which blocks lifter/optimizer to propagate the constant values - create an isolated .asm test for it. When building a new test, make sure that final .ll file (test_optimized.ll) containst only one instruction "ret i32 4919", everything else should be propaged/folded.

## Debugging

When you need to debug code for understanding how it works, leverage debug output guarded by a setting.

## Build

Assume `vcvarsall.bat x64` was already run in the environment before launching Claude (provides ml64, link, mt.exe in PATH).

Always use clang-cl as a compiler! Remill uses GCC/Clang-specific attributes like __attribute__((packed)) which MSVC doesn't support.

Build dependencies for the first time: cmake -B dependencies/build -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl && cmake --build dependencies/build

Then build main project: cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=$(PWD)/dependencies/install -DCMAKE_CXX_COMPILER=$(PWD)/dependencies/install/bin/clang-cl.exe -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_MT=mt.exe && cmake --build build

Run the tests with: ctest --test-dir build -V

## References

Warning! Never references the code frome @NOT_INTEGRATED directory, only use it peer inside to understand how it works.

@NOT_INTEGRATED\mcsema is McSema is an executable lifter. It translates ("lifts") executable binaries from native machine code to LLVM bitcode. Discontinued, but good for inspiration or understanding how to lift the whole binary.

