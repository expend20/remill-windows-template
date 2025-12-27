# RET Dispatch Bug in Control Flow Lifter

## Status: FIXED

The RET dispatch bug has been fixed using a **shadow return stack** approach. See "The Fix" section below.

## Summary

When lifting code with internal function calls (e.g., XTEA with `noinline` encrypt/decrypt functions), the original RET dispatch mechanism in `control_flow_lifter.cpp` caused incorrect control flow, leading to:
- Infinite loops or excessive loop iterations
- RSP growing beyond stack bounds
- Crashes with `0xc0000409` (STATUS_STACK_BUFFER_OVERRUN)

## How RET Dispatch Originally Worked

When the lifter encountered a RET instruction, it created a switch statement that dispatched based on the return address read from the simulated x86 stack:

```cpp
// ORIGINAL (buggy) implementation
case remill::Instruction::kCategoryFunctionReturn: {
  // Load return address from NEXT_PC (set by RET semantic)
  auto *ret_addr = builder.CreateLoad(builder.getInt64Ty(), next_pc);

  // Create switch to dispatch to known return addresses
  auto *switch_inst = builder.CreateSwitch(ret_addr, default_block, return_blocks_.size());

  for (const auto &[addr, ret_block] : return_blocks_) {
    switch_inst->addCase(
        llvm::ConstantInt::get(builder.getInt64Ty(), addr),
        ret_block);
  }
}
```

## The Bug

### Root Cause

The flat switch on return address values didn't respect the proper LIFO call stack semantics:

1. Multiple RET sites shared the same dispatch targets
2. After LLVM optimization merged phi nodes, incorrect values could match switch cases
3. This caused loops that added 64 to RSP each iteration
4. Eventually RSP exceeded stack bounds → access violation

### Example (after optimization)

```llvm
ret_5368713265.i:
  %state.sroa.335.1 = phi i64 [ %add.i.i67.i, %ret_5368713265.i ], [ ... ]
  ...
  %add.i.i67.i = add i64 %state.sroa.335.1, 64  ; RSP keeps growing!
  switch i64 %dyn_stack_val394, label %exit [
    i64 5368713254, label %ret_5368713254.i.loopexit
    i64 5368713265, label %ret_5368713265.i      ; Can loop back!
  ]
```

## The Fix

We implemented **Option 2: Call Stack Simulation** using a shadow return stack:

### Implementation

1. **Shadow stack allocas** are created at function entry:
   ```cpp
   // In control_flow_lifter.cpp
   shadow_stack_ = builder.CreateAlloca(array_type, nullptr, "shadow_ret_stack");
   shadow_stack_sp_ = builder.CreateAlloca(builder.getInt32Ty(), nullptr, "shadow_ret_sp");
   ```

2. **CALL instructions push a call site index** (not return address):
   ```cpp
   // Push call site index to shadow stack
   auto *sp = builder.CreateLoad(builder.getInt32Ty(), shadow_stack_sp_);
   auto *slot = builder.CreateInBoundsGEP(..., shadow_stack_, {0, sp});
   builder.CreateStore(builder.getInt32(call_idx), slot);
   auto *new_sp = builder.CreateAdd(sp, builder.getInt32(1));
   builder.CreateStore(new_sp, shadow_stack_sp_);
   ```

3. **RET instructions pop and dispatch on the index**:
   ```cpp
   // Check if shadow stack is empty (sp == 0) -> main's RET
   auto *is_empty = builder.CreateICmpEQ(sp, builder.getInt32(0));
   builder.CreateCondBr(is_empty, main_ret_block, helper_ret_block);

   // In helper_ret_block: pop index and switch
   auto *new_sp = builder.CreateSub(sp, builder.getInt32(1));
   auto *slot = builder.CreateGEP(...);
   auto *call_idx = builder.CreateLoad(builder.getInt32Ty(), slot);
   auto *switch_inst = builder.CreateSwitch(call_idx, unreachable_block, ...);
   ```

### Why This Works

- Each CALL site has a unique index (0, 1, 2, ...)
- The shadow stack ensures proper LIFO order
- Dispatch is based on a clean index, not memory values that can alias
- LLVM optimization can't corrupt the control flow

## Remaining Limitation: Pointer Indirection

While the RET dispatch bug is fixed, there's a separate issue with memory lowering:

**Pointer-through-stack patterns aren't fully supported.** When a pointer value (like the key array address) is:
1. Stored to the stack as a function argument
2. Later loaded and used to access memory

The memory lowering loses track of what the pointer points to. This causes unresolved memory accesses that become `undef`.

### Example

In XTEA with `noinline`:
- Encryption accesses `key[i]` with address `0x140002000 + i*4` → lowered correctly
- Decryption accesses `key[i]` with address `ptr + i*4` where `ptr` was loaded from stack → becomes `undef`

### Workaround

Use inlined functions with `volatile` data:

```cpp
extern "C" int test_me() {
    volatile uint32_t v[2] = {0x1337, 0};  // volatile prevents constant folding
    xtea_encrypt(v, key, 32);   // gets inlined
    xtea_decrypt(v, key, 32);   // gets inlined
    return v[0];
}
```

### Future Work

To fully support `noinline` functions with pointer arguments, we would need:
1. Pointer provenance tracking through loads/stores
2. Or runtime dispatch based on address ranges
