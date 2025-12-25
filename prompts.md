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