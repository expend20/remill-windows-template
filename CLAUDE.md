# Build

Always use clang-cl as a compiler! Remill uses GCC/Clang-specific attributes like __attribute__((packed)) which MSVC doesn't support.

Build dependencies for the first time: cmake -B dependencies/build -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl && cmake --build dependencies/build

Then build main project: cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=dependencies/install -DCMAKE_CXX_COMPILER=clang-cl && cmake --build build