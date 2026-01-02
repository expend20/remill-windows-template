# Project

This project is a binary deobfuscator leveraging remill (@src/deps/remill) for binary lifting to llvm and massaging code after it to extract original program logic.

Core idea of the deobfuscator is extremely simple: make everything constant and apply LLVM optimisation to propagate constants and fold the code as much as possible.

There are obfuscation passes (@src/deps/llvm-ob-passes) which are used for obfuscating code to produce a binary which is then lifted in tests.

## Testing

If you discover edge case which blocks lifter/optimizer to propagate the constant values - create an isolated .asm test for it. When building a new test, make sure that final .ll file (test_optimized.ll) containst only one instruction "ret i32 4919", everything else should be propaged/folded.

## Debugging

Run lifter with `--debug` flag to enable verbose output: `./build/lifter.exe <shellcode.exe> --debug`

When adding new debug output, use `utils::dbg() << ...` which is guarded by the debug flag.

## Build

Assume `vcvarsall.bat x64` was already run in the environment before launching Claude (provides ml64, link, mt.exe in PATH).

Always use clang-cl as a compiler! Remill uses GCC/Clang-specific attributes like __attribute__((packed)) which MSVC doesn't support.

Build dependencies for the first time: cmake -B dependencies/build -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl && cmake --build dependencies/build

Then build main project: cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=$(PWD)/dependencies/install -DCMAKE_CXX_COMPILER=$(PWD)/dependencies/install/bin/clang-cl.exe -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_MT=mt.exe && cmake --build build

Run the tests with: ctest --test-dir build -V

## Before starting work

* Always in plan mode to make a plan
* After getting the plan, make sure you write the plan to `$(pwd)/.claude/tasks/MEANINGFUL_TASK_NAME.md`.
* The plan should be a detailed implementation plan and the reasoning behind it, as well as tasks broken down.
* If the task requires external knowledge or certain packages, also research to get the latest knowledge (use Task tool for research).
* Don’t over-plan it; always think MVP.
* Once you write the plan, first ask me to review it. Do not continue until I approve the plan.

## While implementing

* You should update the plan as you work.
* After you complete tasks in the plan, you should update and append detailed descriptions of the changes you made, so following tasks can be easily handed over to other engineers.

## References

Warning! Never references the code frome @NOT_INTEGRATED directory, only use it to peer inside to understand how it works.

@NOT_INTEGRATED\mcsema is McSema is an executable lifter. It translates ("lifts") executable binaries from native machine code to LLVM bitcode. Discontinued, but good for inspiration or understanding how to lift the whole binary.
