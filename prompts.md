My goal in helloworld is to lift the whole function (currently it's mov eax, x; ret) back into native IL and simplify as much as possible. Remill lifts the instructions one by one, however I need to optimize that and handle situations like ret. How would I do that?

My goal is have something like that:

define dso_local noundef i32 @test()() #0 !dbg !10 {
  ret i32 4919, !dbg !15
}

clever-herding-flurry.md

---

I want you to update the test pipeline for helloword.

- Test should compile & run final optimized code and verify it's result.
- Final optimized code should be in a separate .ll file and in a clean binary executable, e.g. make main() return test() result and make sure exit status is 0x1337

---

Refactor hello world test:

- there's more tests like that to come, I need you to move all reusable code one directory up, refactor it into small reusable components
- optimization code should be in a separate directory
- rename hello world test into ret_with_code test

---

refactor ret_with_code test, I need shellcode to be compiled from assembly, use masm (ml64.exe from env) to compile the assembly, then write very siplistic pe64 reader to get the shellcode bytes from .exe file, then lift it

scalable-foraging-boot.md

---

add another shellcode to tests corpus, let's see if this gets omptimized into a proper constant

main PROC
    mov eax, 1300h
    or eax, 37h
    ret
main ENDP

---

I need a test similar to or_const.asm, but the test source should be provided as a standalone .cpp file, e.g.:

```
int test_me()
{
  return 0x1337;
}
```

This code should be compiled into .exe, then processed by pe64 reader...

---

add extra step for the last test, before compiling .cpp it to .exe, compile input into .ll file so user could see it. Also add flag to disable optimization for it.

---

Create new .cpp test:

```
int v = 0x37;

extern "C" int test_me()
{
    return 0x1300 ^ v;
}
```

this will probably break multiple things:
- pe64 reader will not be able to read shellcode properly because it's not spread across multiple sections
  - update pe64 reader to cover this case
- lifter should be able to read the instruction as well as the constant memory it references, so in the end it should be optimized to exactly the same output as existing .cpp test (just returning 0x1337 value)

federated-meandering-wind.md

---

add this project as a submodule https://github.com/expend20/llvm-ob-passes get a grasp of it. 
It has obfuscation passes for .ll files. 
Add a new .cpp test based off global_var.cpp, but now use Pluto substitution pass before .ll gets compiled into .exe.
let's see if it works, it should get optimized into the same result (0x1337 value)

---

Z3 is now required to be externally installed, but remill uses superbuild to handle dependencies, can you also use superbuild for z3?

---



---

Xtea test. Create a new test similar to global_var_pluto_sub_5x.cpp. Take the source from src\deps\llvm-ob-passes\tests\test.c, but adapt it (remove printf, etc), encrypt and decrypt 0x1337 int and return it. Don't apply obfuscation passes just yet, let's see if xtea with constat values gets optimized away.

---

create new test like mov_const.asm, I need there a write to a global variable be tested