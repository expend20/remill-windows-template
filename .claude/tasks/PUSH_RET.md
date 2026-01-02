# Issue: indirect_push_ret Test Failure (RESOLVED)

## Problem

The `indirect_push_ret` test uses a VMProtect-style indirect jump pattern:

```asm
lea rax, [rip + target]
push rax
ret
```

This is semantically equivalent to `jmp target`, but implemented by:
1. Loading target address into RAX
2. Pushing RAX onto the stack
3. RET pops the address and jumps to it

## Why Option C Doesn't Fix This

Option C tracks CALL/RET pairs by recording return addresses at CALL sites:
- CALL pushes a known return address
- RET dispatch routes to that known address

But `push rax; ret` has no corresponding CALL:
- The address comes from a register, not a CALL instruction
- `call_return_addrs_` has no entry for this RET
- RET dispatch has no cases to route to

## Current Behavior

```
push rax    → Stores RAX value on stack
ret         → Pops address, jumps to it
            → RET dispatch switch has no cases
            → Falls through to ret_default
            → Returns from function (wrong behavior)
```

## Solution Options

### Option A: SCCP Tracing for RET Targets
During SCCP, trace the value popped by RET:
- If it's a constant address, add it as a new block to discover
- Add case to RET dispatch for this address

### Option B: Pattern Recognition
Detect `push reg; ret` or `push imm; ret` patterns:
- Treat as indirect jump instead of function return
- Resolve target using existing indirect jump resolver

### Option C: Stack Value Tracking
Track what values are pushed onto the stack:
- When RET executes, check if top-of-stack came from a push (not CALL)
- If so, treat as indirect jump

## Complexity

This is fundamentally harder than CALL/RET because:
- Target address is computed at runtime (in original binary)
- Requires value tracking through registers and stack
- Similar complexity to resolving any indirect jump

## Test Case

Location: `src/tests/asm/indirect_branch/indirect_push_ret/`

Expected: `ret i32 4919` (0x1337)
Actual: Now passes!

---

## Resolution: Option A Implemented

### Solution
Extended SCCP tracing to discover targets for ALL RET instructions, not just CALL returns:

1. When SCCP finds a PC store, check if the source block has a RET dispatch switch
2. If so, add the discovered target to a persistent `pending_ret_dispatch_cases` map
3. In each iteration, try to add pending cases to RET dispatch switches
4. Cases are added once the target block is lifted

### Changes Made

**`src/lifting/indirect_jump_resolver.h`:**
- Added `IndirectJumpResolution` struct with `new_targets` and `ret_dispatch_cases`

**`src/lifting/indirect_jump_resolver.cpp`:**
- Changed return type to `IndirectJumpResolution`
- Parse source block address from BB name (both `bb_XXXXXX` and dispatch block names)
- When PC store found in RET dispatch block, add to `ret_dispatch_cases`

**`src/lifting/control_flow_lifter.h`:**
- Added `pending_ret_dispatch_cases` to `IterativeLiftingState`
- Updated `ResolveIndirectJumps()` return type

**`src/lifting/control_flow_lifter.cpp`:**
- Merge new RET dispatch cases into pending list
- Try to add all pending cases each iteration
- Remove successfully added cases from pending list

### Test Results
All 68 tests pass (100%), including the previously failing `indirect_push_ret`.
