# Non-Returning Call Problem

## Issue

The lifter assumes CALL instructions return to the fall-through address. For obfuscated code with return address manipulation (VMProtect-style), this leads to lifting junk bytes after non-returning calls.

## Test Cases

Created 3 failing tests in `src/tests/const/non_returning_call.asm`:

| Test | Pattern | Result |
|------|---------|--------|
| `non_ret_call_retf` | CALL + pop ret addr + JMP elsewhere | `unreachable` |
| `non_ret_call_modify_ret` | CALL + modify ret addr on stack | `unreachable` |
| `non_ret_tail_jump` | CALL + pop + tail JMP | `unreachable` |

All should return `ret i32 4919` but produce `unreachable` because junk code (RETF) after the CALL gets lifted.

## Root Cause

From `iteration_0.ll`:
```llvm
; Entry calls trampoline, then falls through to junk
call helper_140001006      ; trampoline pops ret addr and jumps away
br label %bb_140001011     ; lifter incorrectly follows fall-through

bb_140001011:              ; junk code (RETF = 0xCB)
  call HandleUnsupported   ; RETF is unsupported
  unreachable              ; kills the function
```

The trampoline actually does:
```asm
add rsp, 8           ; pop return address (discard it)
jmp compute_result   ; jump to real code, never returns to caller
```

## Failed Solution Attempts

### Attempt 1: Switch dispatch after CALL

Tried using switch dispatch after CALL (like RET does):
```cpp
// After helper call, use switch instead of direct branch
switch(PC) {
  case next_addr: goto fall_through_block;
  default: return;
}
```

This broke 4 xtea obfuscation tests because SCCP couldn't optimize through the switch structure. PC is in memory (State struct), not SSA, so constant propagation fails.

### Attempt 2: LowerSwitch + icmp/br

Tried lowering the switch to `icmp + br` chains (either via `LowerSwitchPass` or manually):
```cpp
// After helper call, use icmp+br instead of switch
%cmp = icmp eq i64 %pc, next_addr
br i1 %cmp, label %fall_through, label %return
```

**Results:**
- `non_ret_call_retf`: PASSES - simple helper, SCCP proves PC != next_addr
- `non_ret_tail_jump`: PASSES - simple helper, SCCP proves PC != next_addr
- `non_ret_call_modify_ret`: FAILS - returns `undef` (different problem)
- **xtea tests**: ALL FAIL - complex helpers, SCCP can't prove PC == next_addr

**Why it partially works:**
For simple non-returning helpers (`add rsp,8; jmp`), after inlining:
- PC is set to a constant (the jmp target)
- SCCP evaluates `icmp eq <constant>, next_addr` → false
- SimplifyCFG removes dead fall-through branch

**Why xtea breaks:**
For complex helpers with loops/control flow:
- SCCP can't trace PC through all paths to prove PC == next_addr at exit
- Both branches remain, causing incorrect optimization

### Attempt 3: Detect unsupported fall-through instructions

Idea: Only add dispatch when fall-through starts with unsupported instruction (RETF).

**Why it won't work:**
Random junk bytes may accidentally decode to valid instructions. The fall-through shouldn't be taken regardless of what it decodes to.

## Root Problem Analysis

The fundamental issue is **asymmetric SCCP behavior**:
- For non-returning calls: SCCP CAN prove PC != next_addr (simple control flow)
- For normal calls: SCCP CANNOT prove PC == next_addr (complex control flow)

Any dispatch mechanism that relies on SCCP will break normal calls while fixing non-returning ones.

## Remaining Potential Solutions

1. **Callee analysis**: Detect if callee ends with JMP (not RET) before lifting
   - Analyze helper's last instruction category
   - If ends with `kCategoryDirectJump` instead of `kCategoryFunctionReturn`, it's non-returning

2. **Pattern matching**: Detect `add rsp, 8` followed by `jmp` in callee
   - Explicit return address discard pattern

3. **Lazy fall-through discovery**: Don't add fall-through to worklist during block discovery
   - Only lift fall-through when RET dispatch resolves to that address
   - Requires significant architectural change

4. **Two-pass lifting**:
   - First pass: lift with direct branch, detect unreachable
   - Second pass: for calls leading to unreachable, re-lift with dispatch

5. **Selective dispatch based on callee characteristics**:
   - Only add dispatch for helpers that don't contain RET
   - Requires analyzing helper blocks before terminating caller
