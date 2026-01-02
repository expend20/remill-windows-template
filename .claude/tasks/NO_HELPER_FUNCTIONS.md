# Implementation Plan: Option C - Don't Create Helper Functions

## Problem Summary

When direct CALLs create helper functions containing loops with stack-based counters:
1. Helper functions are created with `alwaysinline` attribute
2. After inlining, loop back-edges create **phi nodes** for memory addresses
3. Memory lowering fails because phi addresses aren't `ConstantInt`
4. LLVM marks function as `noreturn` → `unreachable`

**Test case:** `call_with_loop` - Expected `ret i32 4919`, Actual `unreachable`

## Solution Overview

Treat direct CALL like indirect jumps - keep all code in one function:
1. Don't create separate helper functions for CALL targets
2. Lift CALL targets as blocks in the **same function** (owner = 0)
3. CALL instruction: remill semantics push return address, then branch to target block
4. RET instruction: existing dispatch switch routes to correct caller
5. Memory lowering sees **constant addresses** (no phi from function inlining)

---

## Files to Modify

### 1. `src/lifting/function_splitter.cpp`

**AssignBlocksToFunctions() - lines 24-121:**
- Remove/skip the entire for loop that assigns `block_owner[block_addr] = helper_entry`
- Keep initial assignment loop (lines 19-22) that sets all blocks to owner = 0

```cpp
// OLD: For each call target, BFS to assign ownership
for (uint64_t helper_entry : call_targets) { ... }

// NEW: Skip entirely - all blocks stay in main (owner = 0)
// Just keep debug output if desired
```

**CreateHelperFunctions() - lines 143-173:**
- Skip all function creation - make function body empty

```cpp
void FunctionSplitter::CreateHelperFunctions(...) {
  // Option C: Don't create helper functions
  // All code stays in main function
}
```

### 2. `src/lifting/block_terminator.cpp`

**kCategoryDirectFunctionCall case - lines 127-196:**
- Remove helper function lookup and call
- Branch directly to target block (like a direct jump)
- RET dispatch will handle returning to correct caller

```cpp
case remill::Instruction::kCategoryDirectFunctionCall: {
  uint64_t target = last_instr.instr.branch_taken_pc;

  // Remill semantics already pushed return address to stack
  // Just branch to target block
  if (sameFunction(target)) {
    builder.CreateBr(getBlock(target));
  } else {
    // Target not discovered yet - will be handled in next iteration
    builder.CreateRet(remill::LoadMemoryPointer(block, *intrinsics));
  }
  break;
}
```

### 3. `src/lifting/block_decoder.cpp`

**kCategoryDirectFunctionCall case - lines 191-206:**
- **Also queue return address** for discovery (since code after CALL is now reachable)

```cpp
case remill::Instruction::kCategoryDirectFunctionCall: {
  uint64_t target = decoded.instr.branch_taken_pc;
  // ... existing code to add target to worklist ...

  // NEW: Also add return address to worklist
  if (IsValidCodeAddress(next_addr) && !visited.count(next_addr) &&
      !iter_state.lifted_blocks.count(next_addr)) {
    worklist.push(next_addr);
    visited.insert(next_addr);
  }
  call_return_addrs[last_addr] = next_addr;
  break;
}
```

### 4. `src/lifting/control_flow_lifter.cpp`

**CreateBasicBlocksIncremental():**
- Simplify/remove helper function block creation (lines 114-154)
- All blocks now go into main function

**Phase 3 - CreateHelperFunctions call:**
- Skip or remove (helper_functions_ will be empty)

---

## How It Works

### Before (with helper functions):
```
CALL helper  → CreateCall(helper_func, {state, pc, memory})
             → Inlining creates phi nodes in loops
             → Memory lowering fails → unreachable
```

### After (Option C):
```
CALL target  → Branch to target block (same function)
             → Loop stays in same function, no inlining
             → Memory lowering sees constant addresses
             → SCCP folds everything → ret i32 4919
```

### RET dispatch (unchanged):
```
RET          → Load PC (popped from stack by remill)
             → Switch on PC value
             → Cases added for all discovered return addresses
             → Routes to correct continuation block
```

---

## Edge Cases Handled

| Scenario | How Handled |
|----------|-------------|
| Multiple call sites to same function | RET dispatch has case for each return address |
| Recursive calls | Stack naturally tracks nested return addresses |
| Nested calls (A→B→C) | Each CALL pushes, each RET pops from stack |
| Non-returning calls | Junk code after CALL never discovered (existing SCCP logic) |

---

## Implementation Order

1. **function_splitter.cpp**: Disable ownership assignment and helper creation
2. **block_terminator.cpp**: Change CALL to branch instead of function call
3. **block_decoder.cpp**: Queue return addresses for discovery
4. **control_flow_lifter.cpp**: Remove helper function handling

---

## Testing

- Primary: `call_with_loop` should produce `ret i32 4919`
- Regression: All existing tests should pass
- XTEA tests with direct CALL should now work

---

## Implementation Status: COMPLETE

### Final Test Results: 67/68 (99% pass rate)

All tests pass except `indirect_push_ret_ir_check` which uses a VMProtect-style `push rax; ret` pattern that requires SCCP tracing (not covered by Option C).

### Changes Made

#### 1. `src/lifting/function_splitter.cpp`
- **AssignBlocksToFunctions()**: Disabled helper function ownership assignment. All blocks stay with owner = 0 (main function).
- **CreateHelperFunctions()**: Made empty - no helper functions created.

#### 2. `src/lifting/block_terminator.cpp`
- **kCategoryDirectFunctionCall**: Changed from creating a function call to a direct branch to the target block. Remill semantics already push the return address to the stack.

#### 3. `src/lifting/block_decoder.cpp`
- **kCategoryDirectFunctionCall**: Added return address queueing for discovery. Since we don't create helper functions, code after CALL is now reachable and must be discovered.

#### 4. `src/lifting/control_flow_lifter.cpp`
- **Phase ordering**: Moved switch population (Phase 4b → Phase 5b) to after LiftPendingBlocks, ensuring switches exist before populating.
- **Smart RET dispatch**: Implemented "virtual function" tracking - each RET dispatch only gets the return address for the CALL that invoked its containing function, avoiding O(n²) edges in nested call scenarios.

### Key Bug Fixes During Implementation

1. **Switch population timing**: Switches were being populated before they were created. Fixed by moving population after LiftPendingBlocks.

2. **Self-loop prevention**: RET dispatch was adding its own address as a case (infinite loop). Fixed by checking `if (ret_addr == jump_block_addr) continue;`

3. **Virtual function scoping**: For nested calls (A→B→C), each RET was getting all return addresses. Fixed by tracking which "virtual function" contains each RET and only adding cases for CALLs that target that function.

### Verified Test Cases

| Test | Status | Notes |
|------|--------|-------|
| call_with_loop | PASS | Original failing test - now returns `ret i32 4919` |
| call_chain | PASS | 10 nested calls |
| xtea_* | PASS | All XTEA variants (substitution, flattening, mba, etc.) |
| indirect_push_ret | FAIL | VMProtect-style push+ret pattern (known limitation) |
