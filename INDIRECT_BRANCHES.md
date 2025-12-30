# Indirect Branch Handling

## Problem Statement

The lifter currently cannot handle indirect jumps (e.g., `jmp rax`) because it lacks value tracking/constant propagation capabilities.

## Test Case

`src/tests/const/indirect_jmp.asm`:
```asm
.code

target_label PROC
    mov eax, 1337h
    ret
target_label ENDP

main PROC
    lea rax, target_label    ; Load address of target into rax
    jmp rax                  ; Indirect jump through register
main ENDP

END
```

## Current Behavior

1. **Block Discovery**: The lifter correctly discovers both basic blocks:
   - `0x140001000` (target_label)
   - `0x140001006` (main)

2. **Instruction Categories**: Remill categorizes:
   - `lea rax, target_label` as a normal instruction
   - `jmp rax` as `kCategoryIndirectJump`

3. **Control Flow Lifting**: In `control_flow_lifter.cpp`, `FinishBlock()` handles:
   - `kCategoryConditionalBranch`
   - `kCategoryDirectJump`
   - `kCategoryDirectFunctionCall`
   - `kCategoryFunctionReturn`

   But **not** `kCategoryIndirectJump`, which falls through to `default` and returns.

4. **Result**: The lifted IR returns the address (`0x40001000`) instead of following the jump:
   ```llvm
   define i32 @test() {
   entry:
     ret i32 1073745920  ; = 0x40001000, the address loaded by lea
   }
   ```

## Why This Happens

The `lea rax, target_label` instruction computes `target_label`'s address at lift-time (it's a RIP-relative address calculation). The value `0x140001000` is stored in RAX.

When `jmp rax` executes, the lifter:
1. Updates RIP to the value in RAX (correctly)
2. But doesn't know that RAX contains a **known constant** pointing to `target_label`
3. Falls through to `default` case and returns

The block `bb_5368713216` (target_label) exists in the lifted IR but has `; No predecessors!` - nothing jumps to it.

## Solution Approaches

### 1. Simple Constant Propagation (Recommended First Step)

Track register values when they're loaded with constants:
- `lea rax, [rip + offset]` -> RAX = known_address
- `mov rax, imm64` -> RAX = known_value

When encountering `jmp reg`:
1. Look up if `reg` holds a known constant
2. If yes, and the constant is a valid block address, emit a direct branch
3. If no, either:
   - Emit a switch over all possible targets
   - Return (current behavior)

### 2. Leverage LLVM's Analysis Infrastructure (Recommended)

LLVM already has powerful data flow analysis. After lifting and inlining, the IR contains all the information needed:

```llvm
; In @test(), we call with constant PC:
call ptr @lifted_const(ptr %state, i64 5368713222, ptr undef)

; Inside lifted function, LEA computes:
%0 = load i64, ptr %NEXT_PC           ; = 0x140001006 (from constant arg)
%1 = add i64 %0, 7                    ; = 0x14000100D
%3 = sub i64 %1, 13                   ; = 0x140001000 (target_label!)
; stored to RAX, then loaded for JMP
```

**LLVM passes that can resolve this:**

1. **SCCP (Sparse Conditional Constant Propagation)** - Propagates constants through the CFG
2. **Inlining + InstCombine** - After inlining, arithmetic on constants gets folded
3. **GVN (Global Value Numbering)** - Identifies equivalent values

**Implementation approach:**

```cpp
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Analysis/ConstantFolding.h>

// After lifting, run a custom pass:
// 1. Find stores to RIP (indirect jump targets)
// 2. Use SimplifyInstruction() or computeKnownBits() to resolve
// 3. If constant and matches a known block, rewrite to direct branch

llvm::Value *target = /* value stored to RIP */;
if (auto *CI = llvm::dyn_cast<llvm::ConstantInt>(target)) {
    uint64_t addr = CI->getZExtValue();
    if (blocks_.count(addr)) {
        // Replace return with: br label %bb_<addr>
    }
}
```

**When to run the analysis:**

Option A: During lifting (before `FinishBlock`)
- Run `llvm::SimplifyInstruction()` on the jump target value
- Requires the constant PC to be available

Option B: Post-processing pass (after full module is lifted)
- Run SCCP/InstCombine first
- Then scan for indirect jumps and resolve them
- More powerful but adds a pass

Option C: Two-phase lifting
- Phase 1: Lift all code, emit indirect jumps as switches over all possible targets
- Phase 2: Run LLVM optimizations, which will eliminate dead switch cases

### 3. Runtime Dispatch

For truly dynamic jumps (jump tables, computed gotos):
- Create a dispatcher that switches on the target address
- Map each known block address to its LLVM BasicBlock

## Implementation Location

Changes needed in `src/lifting/control_flow_lifter.cpp`:

1. Add tracking for register values in `ControlFlowLifter` class
2. Update instruction lifting to record constant assignments
3. Add `kCategoryIndirectJump` case in `FinishBlock()`
4. Resolve indirect jump targets using tracked values

## Related Work

- McSema handles this via CFG recovery with IDA/Binary Ninja providing jump targets
- RetDec uses data flow analysis to resolve indirect branches
- Binary lifting often relies on external disassemblers for this information

## Implementation Status

**IMPLEMENTED** using Option B (Leverage LLVM's Analysis Infrastructure).

The implementation:
1. `control_flow_lifter.cpp` now handles `kCategoryIndirectJump` by emitting a switch over all known block addresses
2. `optimizer.cpp` runs SCCP (Sparse Conditional Constant Propagation) followed by SimplifyCFG
3. After inlining and constant propagation, the switch selector becomes a constant
4. SimplifyCFG eliminates dead switch cases, leaving a direct branch

The `indirect_jmp` test now passes - the final optimized IR is simply:
```llvm
define i32 @test() {
entry:
  ret i32 4919  ; 0x1337
}
```
