# Build

Always use clang-cl as a compiler! Remill uses GCC/Clang-specific attributes like __attribute__((packed)) which MSVC doesn't support.

Build dependencies for the first time: cmake -B dependencies/build -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl && cmake --build dependencies/build

Then build main project: cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=$(PWD)/dependencies/install -DCMAKE_CXX_COMPILER=$(PWD)/dependencies/install/bin/clang-cl.exe -DCMAKE_BUILD_TYPE=Release -DCMAKE_MT=mt.exe -DZ3_ROOT=C:\z3 && cmake --build build

Run the tests with: ctest --test-dir build -V

# Environment Notes

- Run `vcvarsall.bat x64` before launching Claude (provides ml64, link, mt.exe in PATH)
- Use Release build type (remill is built with `_ITERATOR_DEBUG_LEVEL=0`)
- Use clang-cl from dependencies/install/bin to avoid picking up system clang

# Z3 Installation (Windows)

Z3 is required for the llvm-ob-passes MBAObfuscation pass.

## Option 2: Pre-built binaries
1. Download from https://github.com/Z3Prover/z3/releases (get z3-x.x.x-x64-win.zip)
2. Extract to e.g. `C:\z3`
3. Add to cmake: `-DZ3_ROOT=C:\z3`

# References

Warning! Never references the code frome @NOT_INTEGRATED directory, only use it peer inside to understand how it works.

@NOT_INTEGRATED\mcsema is McSema is an executable lifter. It translates ("lifts") executable binaries from native machine code to LLVM bitcode. Discontinued, but good for inspiration or understanding how to lift the whole binary.

