# Issue: Helper Functions with Loops Cause Unreachable

## Summary

Direct CALL instructions to functions containing loops with stack-based counters result in `unreachable` in the optimized IR. This affects tests like `call_with_loop`, `xtea_substitution`, `xtea_flattening`, `xtea_mba`, and `xtea_global_encryption`.

## Isolated Test Case

**File:** `src/tests/const/call_with_loop.asm`

```asm
; Entry point calls helper with loop
call_with_loop PROC
    call helper_with_loop
    add eax, 1127h      ; Adjust result to get 0x1337
    ret
call_with_loop ENDP

; Helper with stack-based loop counter
helper_with_loop PROC
    sub rsp, 16
    mov dword ptr [rsp], 32      ; counter
    mov dword ptr [rsp+4], 0     ; sum

loop_start:
    mov ecx, dword ptr [rsp]     ; load counter
    test ecx, ecx
    jz loop_done

    mov eax, dword ptr [rsp+4]   ; load sum
    add eax, ecx                 ; sum += counter
    mov dword ptr [rsp+4], eax   ; store sum

    dec ecx
    mov dword ptr [rsp], ecx     ; store counter
    jmp loop_start

loop_done:
    mov eax, dword ptr [rsp+4]
    add rsp, 16
    ret
helper_with_loop ENDP
```

**Expected:** `ret i32 4919`
**Actual:** `unreachable`

## Root Cause

### 1. Helper Function Creation

When the lifter encounters a direct CALL instruction, it creates a separate helper function:

```
call helper_with_loop  -->  Creates helper_140001000(state, pc, memory)
```

The helper function is marked with `alwaysinline` for later inlining.

### 2. Loop Structure in Helper

The helper function contains a loop with stack memory accesses:

```llvm
; In helper_140001000:
bb_loop:                                    ; preds = %bb_loop, %entry
  %counter = call i32 @__remill_read_memory_32(ptr %mem, i64 %stack_addr)
  ...
  call ptr @__remill_write_memory_32(ptr %mem, i64 %stack_addr, i32 %new_counter)
  br i1 %cond, label %bb_loop, label %bb_done
```

### 3. Inlining Creates Phi Nodes

`OptimizeForCleanIR` runs `ModuleInlinerPass` which inlines the helper:

```llvm
; After inlining into test():
bb_loop.i:                                  ; preds = %bb_loop.i, %entry
  %MEMORY.i.0 = phi ptr [ %mem_init, %entry ], [ %mem_updated, %bb_loop.i ]
  %addr.i = phi i64 [ %addr1, %entry ], [ %addr2, %bb_loop.i ]
  %counter = call i32 @__remill_read_memory_32(ptr %MEMORY.i.0, i64 %addr.i)
  ...
```

The memory pointer and addresses become phi nodes due to the loop back-edge.

### 4. Memory Lowering Fails

`LowerMemoryIntrinsics` runs AFTER inlining. It tries to resolve addresses to stack/global accesses:

```cpp
// memory_lowering.cpp - tries to find constant addresses
if (auto *const_int = llvm::dyn_cast<llvm::ConstantInt>(addr)) {
    // Can lower - address is constant
}
// But phi nodes are NOT ConstantInt!
```

**Result:** 80+ memory intrinsics cannot be lowered because their addresses are phi nodes.

### 5. LLVM Marks Function as NoReturn

With opaque memory intrinsics, LLVM's O3 optimization:
1. Cannot determine the loop trip count
2. Cannot prove the loop terminates
3. Adds `llvm.assume(counter != 0)` on the loop path
4. Eliminates the loop exit path
5. Marks function as `noreturn`
6. Replaces body with `unreachable`

## Affected Tests

| Test | Status | Reason |
|------|--------|--------|
| `call_with_loop` | FAIL | Direct CALL + loop |
| `xtea_substitution` | FAIL | Direct CALL + XTEA loop |
| `xtea_flattening` | FAIL | Direct CALL + XTEA loop |
| `xtea_mba` | FAIL | Direct CALL + XTEA loop |
| `xtea_global_encryption` | FAIL | Direct CALL + XTEA loop |
| `xtea_noinline` | FAIL | Explicit noinline + loop |
| `xtea_indirect_call` | PASS | No helper functions (indirect jumps) |
| `xtea_all_pluto` | PASS | Uses pluto-indirect-call |

## Why Some Tests Pass

`xtea_all_pluto` and `xtea_indirect_call` pass because they use `pluto-indirect-call` obfuscation which converts CALL instructions to indirect jumps via a table:

```asm
; Before pluto-indirect-call:
call helper_func

; After pluto-indirect-call:
mov rax, [jump_table + index*8]
jmp rax
```

This eliminates helper function creation - all code stays in `lifted_func` where:
- No phi nodes from function inlining
- Memory lowering sees constant addresses
- Loops can be properly unrolled

## Potential Fixes

### Option A: Lower Memory Before Inlining

Run `LowerMemoryIntrinsics` on each helper function BEFORE `OptimizeForCleanIR` inlines them.

**Challenge:** Helper functions don't have their own stack alloca - they use the state struct passed as argument.

### Option B: Improve Phi Node Handling

Enhance memory lowering to handle phi nodes:
- If all incoming values are within stack range, lower the access
- Track phi node values through the CFG

**Challenge:** Complex implementation, may miss edge cases.

### Option C: Don't Create Helper Functions

Handle CALL like indirect jumps - use dispatch switches instead of helper functions.

**Challenge:** Significant refactoring of control flow lifter architecture.

### Option D: Add pluto-indirect-call to Tests (Workaround)

Modify failing tests to include `pluto-indirect-call` pass.

**Drawback:** Defeats purpose of testing individual obfuscation passes.

## Code Flow

```
lifter.cpp:
  1. LiftCode()                    # Creates helper functions for CALLs
  2. OptimizeForCleanIR()          # Inlines helpers -> creates phi nodes
  3. CreateStackAlloca()           # Creates stack alloca in wrapper
  4. LowerMemoryIntrinsics()       # FAILS - phi addresses can't be resolved
  5. ExtractFunctions()            # Extract test function
  6. OptimizeAggressive()          # O3 marks function noreturn
```

## Files Involved

- `src/lifting/function_splitter.cpp` - Creates helper functions
- `src/lifting/control_flow_lifter.cpp` - Orchestrates lifting
- `src/optimization/optimizer.cpp` - Runs inlining and O3
- `src/lifting/memory_lowering.cpp` - Lowers memory intrinsics
- `src/tests/const/call_with_loop.asm` - Isolated test case
