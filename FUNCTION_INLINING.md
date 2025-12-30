# Function Inlining Approach for Constant Propagation

## Background: The Shadow Stack Approach (Old)

When lifting code with function calls, we need to handle the call/return semantics. The original approach used a **shadow stack** - an auxiliary data structure that tracks return addresses within a single LLVM function.

### How the Shadow Stack Worked

All code (main + helpers) was lifted into ONE LLVM function with multiple basic blocks. Function calls and returns were modeled as branches between blocks:

```
lifted_const():
  ; Main's code
  bb_main:
    ... setup ...
    ; CALL encrypt: push return index, branch to callee
    %sp = load i32, ptr %shadow_stack_sp
    %slot = gep %shadow_stack, 0, %sp
    store i32 0, ptr %slot              ; 0 = return to bb_after_encrypt
    %new_sp = add %sp, 1
    store i32 %new_sp, ptr %shadow_stack_sp
    br label %bb_encrypt                ; branch to callee (not a real call!)

  bb_after_encrypt:
    ... continue after call ...

  ; Encrypt's code (in same function!)
  bb_encrypt:
    ... encrypt logic ...
    br label %bb_encrypt_ret

  bb_encrypt_ret:
    ; RET: pop from shadow stack, switch to correct return block
    %sp = load i32, ptr %shadow_stack_sp
    %new_sp = sub %sp, 1
    store i32 %new_sp, ptr %shadow_stack_sp
    %slot = gep %shadow_stack, 0, %new_sp
    %idx = load i32, ptr %slot
    switch i32 %idx, label %unreachable [
      i32 0, label %bb_after_encrypt    ; return from first call site
      i32 1, label %bb_after_decrypt    ; return from second call site
    ]
```

### Why the Shadow Stack Broke Constant Propagation

The switch statement uses a **runtime value** (`%idx`) loaded from memory. Even though we just stored a known constant (0 or 1) at the call site, LLVM's alias analysis cannot prove that the load reads the same value:

1. The shadow stack is an array indexed by a variable (`%sp`)
2. LLVM can't connect `store to stack[sp]` with `load from stack[sp-1]` through the increment/decrement
3. LLVM sees ALL switch cases as potentially reachable
4. PHI nodes in return blocks get `undef` from "impossible" edges
5. This cascades: RSP becomes undef → stack addresses become undef → memory loads return undef

## Problem

When native functions use `__attribute__((noinline))`, the lifted code uses shadow stack dispatch:

```llvm
; At RET - switch on runtime value breaks constant propagation
%idx = load from shadow_stack
switch i32 %idx, label %unreachable [
  i32 0, label %ret_to_caller_A
  i32 1, label %ret_to_caller_B
]
```

LLVM can't simplify this switch, so PHI nodes get `undef` from "impossible" edges, cascading to `undef` stack addresses and memory values.

## Solution: Function Inlining

Lift each call target as a **separate LLVM function** with `alwaysinline` attribute.

### Old (shadow stack - broken):
```
lifted_main():
  bb_main:     push shadow, br to bb_encrypt
  bb_encrypt:  ... work ... switch on shadow → ret blocks
  ret_block:   continue...
```

### New (separate functions - working):
```
lifted_main():
  call @helper_140001040(state, pc, mem)
  ...

@helper_140001040() alwaysinline internal:
  ...
  ret mem
```

When LLVM inlines the helper functions, the result is flat code with no switches - identical to the case where native functions are inlined at compile time.

## Implementation

### Step 1: Create separate functions for call targets

In `ControlFlowLifter::LiftFunction()`:
- For each address in `call_targets_`, create a new LLVM function
- Signature: `ptr @lifted_helper(ptr %state, ptr %mem)` (same as main lifted function)
- Attributes: `internal`, `alwaysinline`

### Step 2: Use LLVM call/ret instead of shadow stack

At `kCategoryDirectFunctionCall`:
```cpp
// Old: br to target, push shadow stack
// New: call @lifted_helper, continue to next block
auto *helper_func = helper_functions_[target];
auto *mem = builder.CreateLoad(mem_ptr_type, MEMORY);
auto *new_mem = builder.CreateCall(helper_func, {state, mem});
builder.CreateStore(new_mem, MEMORY);
builder.CreateBr(blocks_[next_addr]);
```

At `kCategoryFunctionReturn` (in helper):
```cpp
// Old: pop shadow, switch dispatch
// New: return memory pointer
builder.CreateRet(LoadMemoryPointer(block, *intrinsics));
```

### Step 3: Lift helper function bodies

Each helper function contains only its own basic blocks (from entry to all RETs).

### Step 4: Main function contains only main's blocks

The entry function contains blocks that aren't part of any helper.

## Files to Modify

| File | Change |
|------|--------|
| `control_flow_lifter.h` | Add `helper_functions_` map, method to create helpers |
| `control_flow_lifter.cpp` | Split lifting into main + helpers, use call/ret |

## Edge Cases

1. **Recursive functions**: `alwaysinline` may fail; keep shadow stack as fallback
2. **Indirect calls**: Not affected (already use different mechanism)
3. **Multiple call sites to same helper**: Works fine, LLVM inlines at each site

## Expected Result

The `xtea_noinline` test should produce `ret i32 4919` (same as `xtea_roundtrip`) after LLVM inlines the helper functions and constant propagation succeeds.
