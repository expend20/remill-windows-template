# Iterative Lifting for Indirect Jump Resolution

## The Problem

When lifting binary code to LLVM IR, indirect jumps pose a fundamental challenge: the target address is computed at runtime, not statically known.

```asm
lea rax, some_function    ; Load function address
add rax, 5                 ; Skip first 5 bytes
jmp rax                    ; Where does this go?
```

Static analysis alone cannot determine the target. But here's the insight: **if all inputs are constants, LLVM's optimization passes can compute the target for us**.

## Core Concept

Iterative lifting uses LLVM itself as a symbolic execution engine:

1. **Lift what we can** - Start with known entry points, follow direct jumps
2. **Hit a wall** - Stop at indirect jumps where target is unknown
3. **Optimize a clone** - Run SCCP/GVN on a copy of the module
4. **Extract targets** - Find constant values being stored to the program counter
5. **Repeat** - Add discovered targets, lift them, optimize again

```
┌─────────────────────────────────────────────────────────┐
│  1. Initial Lifting                                     │
│     - Start from entry point                            │
│     - Follow direct jumps/calls/branches                │
│     - Stop at indirect jumps (mark as unresolved)       │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  2. Emit Placeholder Switches                           │
│     - For each indirect jump, emit:                     │
│       switch i64 %computed_pc, label %unknown []        │
│     - Cases will be added as targets are discovered     │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  3. Clone & Optimize                                    │
│     - Clone the module (preserve original for lifting)  │
│     - Run GVN + SCCP on clone to fold computations      │
│     - Find stores to PC register                        │
│     - Extract constant target addresses                 │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
                 ┌────┴────┐
                 │ New     │ Yes ──► Add to worklist, repeat
                 │ targets?│
                 └────┬────┘
                      │ No
                      ▼
              Done - all targets resolved
```

## Why Clone Before Optimizing?

Running aggressive optimizations (SCCP, SROA, Mem2Reg) **destroys the IR structure** needed for further lifting:

- Allocas get promoted to SSA and disappear
- Memory operations get eliminated
- The lifting framework needs consistent memory layout

**Solution**: Clone the module, optimize the clone to discover targets, but continue lifting in the original unoptimized module.

```
Original Module          Cloned Module
     │                        │
     │                   [Optimize]
     │                        │
     │                   [Extract PC stores]
     │                        │
     │◄──── discovered ───────┘
     │      targets
     │
[Add new blocks]
     │
     ▼
   Repeat
```

## IR Representation of Indirect Jumps

When an indirect jump is encountered, emit a switch on the computed PC value:

```llvm
; Before any targets discovered
%pc = load i64, ptr %PC_register
switch i64 %pc, label %unresolved_indirect [
  ; Empty - no known targets yet
]

unresolved_indirect:
  ; Trap or return error
  unreachable
```

As targets are discovered, cases are added:

```llvm
; After discovering target 0x140001050
%pc = load i64, ptr %PC_register
switch i64 %pc, label %unresolved_indirect [
  i64 5368713296, label %bb_140001050
]

bb_140001050:
  ; Lifted code for target block
  ; ...
```

## Target Discovery via SCCP

After optimization, look for stores to the PC register that are now constants:

**Before SCCP:**
```llvm
%addr = load i64, ptr @function_table
%offset = add i64 %addr, 16
store i64 %offset, ptr %PC_register
```

**After SCCP (if function_table is constant):**
```llvm
store i64 5368713296, ptr %PC_register  ; Constant!
```

The optimizer folded `load + add` into a single constant. We extract `5368713296` (0x140001050) as a new target.

## Example: Arithmetic on Code Pointer

```asm
target:
    nop                      ; 1 byte at 0x140001000
    mov eax, 1337h           ; Actual code at 0x140001001
    ret

main:
    lea rax, target          ; rax = 0x140001000
    inc rax                  ; rax = 0x140001001 (skip nop)
    jmp rax                  ; Indirect jump
```

**Iteration 0** - Lift entry point, hit indirect jump:
```llvm
define void @lifted() {
entry:
  ; lea rax, target
  %addr = add i64 %image_base, 4096  ; 0x140001000

  ; inc rax
  %target = add i64 %addr, 1         ; 0x140001001

  ; jmp rax - indirect, unknown target
  store i64 %target, ptr %PC
  switch i64 %target, label %unknown []
}
```

**After SCCP on clone:**
```llvm
  store i64 5368713217, ptr %PC  ; Folded to constant!
```

**Iteration 1** - Target 0x140001001 discovered and lifted:
```llvm
define void @lifted() {
entry:
  %target = add i64 %image_base, 4097
  switch i64 %target, label %unknown [
    i64 5368713217, label %bb_140001001  ; New case!
  ]

bb_140001001:
  ; mov eax, 1337h
  store i32 4919, ptr %EAX
  ; ret
  ret void
}
```

## Handling Jump Tables

Jump tables require special treatment because targets come from memory:

```asm
; Jump table pattern
mov eax, [input]
cmp eax, 4
ja default
lea rcx, jump_table
mov rax, [rcx + rax*8]    ; Load from table
jmp rax
```

For jump tables, iterative SCCP alone isn't enough. Additional techniques:

1. **Pattern recognition** - Detect the `cmp + ja + table load` pattern
2. **Table enumeration** - Read all entries from the constant table
3. **Bounds analysis** - Use the comparison to limit valid indices

```llvm
; Recognized jump table with 5 entries
switch i32 %index, label %default [
  i32 0, label %case_0
  i32 1, label %case_1
  i32 2, label %case_2
  i32 3, label %case_3
  i32 4, label %case_4
]
```

## Convergence

The algorithm terminates when no new targets are discovered:

- **Converges** when all reachable code has constant control flow
- **Fails to converge** when targets depend on runtime input
- **Max iterations** prevent infinite loops from cycles or bugs

Typical convergence:
- Simple functions: 1-2 iterations
- Functions with computed jumps: 2-5 iterations
- Complex obfuscated code: 5-10+ iterations

## Debug Output

Dumping intermediate IR helps debug resolution failures:

```llvm
; === Iteration 0 ===
; Blocks lifted: 1
; Unresolved indirect jumps: 1
; New targets discovered: 0

; === Iteration 1 ===
; Blocks lifted: 2
; Unresolved indirect jumps: 0
; New targets discovered: 1
;   0x140001001 (from store in bb_entry)
```

## Limitations

| Scenario | Status | Notes |
|----------|--------|-------|
| Direct jumps/calls | Works | Trivially resolved |
| `lea + jmp` | Works | SCCP folds address |
| `lea + add/inc + jmp` | Works | SCCP folds arithmetic |
| Constant jump tables | Partial | Requires pattern matching |
| Input-dependent jumps | Fails | Target not constant |
| Self-modifying code | Fails | Code changes at runtime |
| Virtual dispatch (vtables) | Partial | Needs type analysis |

## Key Insight

LLVM's optimizer is effectively a **partial evaluator**. By providing constant inputs (entry point, image base, section contents), we let SCCP compute what would normally be runtime values. The indirect jump target is "runtime" from the CPU's perspective, but "compile-time" from LLVM's perspective when all inputs are known.
