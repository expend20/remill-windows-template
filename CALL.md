# Lifting CALL Instructions

This document explains how `CALL` instructions are lifted to LLVM IR in this project.

## The Problem

Unlike jumps, `CALL` instructions expect to **return** to the instruction after the call. Consider:

```asm
get_value PROC
    mov eax, 37h
    ret
get_value ENDP

main PROC
    call get_value    ; should return here after get_value's RET
    or eax, 1300h     ; eax = 0x37 | 0x1300 = 0x1337
    ret
main ENDP
```

Challenges:
1. `CALL` pushes a return address onto the stack and jumps to target
2. `RET` pops that address and jumps back
3. When lifting to LLVM IR, we don't have a real stack - the "stack" is simulated
4. We need to route control flow back to the correct call site

## The Solution: Return Continuation Blocks

The `ControlFlowLifter` handles CALL/RET with **return continuation blocks** and a **dispatch switch**:

### Step 1: Discover Block Boundaries

During CFG discovery, CALL instructions create TWO block boundaries:

```cpp
case remill::Instruction::kCategoryDirectFunctionCall: {
    uint64_t target = decoded.instr.branch_taken_pc;
    if (target >= code_start_ && target < code_end_) {
        block_starts_.insert(target);      // Call target (get_value entry)
    }
    if (next_addr < code_end_) {
        block_starts_.insert(next_addr);   // Return address (instruction after call)
    }
    break;
}
```

For the example, this discovers:
```
Block 0x140001000:  mov eax, 37h; ret           (get_value)
Block 0x140001006:  call get_value              (main entry)
Block 0x14000100B:  or eax, 1300h; ret          (after call returns)
```

### Step 2: Pre-Create Return Continuation Blocks

Before lifting, we create special blocks for each internal call's return address:

```cpp
// Pre-create return continuation blocks for all internal calls
for (const auto &[addr, decoded] : instructions_) {
    if (decoded.instr.category == kCategoryDirectFunctionCall) {
        uint64_t target = decoded.instr.branch_taken_pc;
        uint64_t return_addr = addr + decoded.size;

        if (blocks_.count(target) && blocks_.count(return_addr)) {
            // Internal call - create return continuation block
            auto *ret_block = BasicBlock::Create(context, "ret_" + std::to_string(return_addr), func);
            return_blocks_[return_addr] = ret_block;

            // Track that target is a helper function (its RET should dispatch)
            call_targets_.insert(target);
        }
    }
}
```

This creates:
- `ret_5368713227` - continuation block for return address 0x14000100B
- Marks `get_value` (0x140001000) as a call target

### Step 3: Lift CALL Instructions

When finishing a block that ends with CALL:

```cpp
case remill::Instruction::kCategoryDirectFunctionCall: {
    uint64_t target = last_instr.instr.branch_taken_pc;

    if (blocks_.count(target) && return_blocks_.count(next_addr)) {
        // Internal call - branch to target
        builder.CreateBr(blocks_[target]);

        // Fill in the continuation block - branches to code after the call
        llvm::IRBuilder<> ret_builder(return_blocks_[next_addr]);
        ret_builder.CreateBr(blocks_[next_addr]);
    } else {
        // External call - just continue to next block
        builder.CreateBr(blocks_[next_addr]);
    }
    break;
}
```

### Step 4: Lift RET with Dispatch

The key insight: **only helper function RETs dispatch back to callers**. Main's RET should exit the LLVM function.

```cpp
case remill::Instruction::kCategoryFunctionReturn: {
    // Determine if this RET is in a helper function
    bool is_helper = call_targets_.count(block_addr) || block_addr < entry_point_;

    if (return_blocks_.empty() || !is_helper) {
        // Main's RET - just exit the LLVM function
        builder.CreateRet(LoadMemoryPointer(block, *intrinsics));
    } else {
        // Helper's RET - dispatch based on return address
        auto *ret_addr = builder.CreateLoad(i64, next_pc_alloca);

        // Default: exit function (handles unknown return addresses)
        auto *default_block = BasicBlock::Create(context, "ret_default", func);
        IRBuilder<> default_builder(default_block);
        default_builder.CreateRet(LoadMemoryPointer(default_block, *intrinsics));

        // Switch dispatch to known return addresses
        auto *switch_inst = builder.CreateSwitch(ret_addr, default_block, return_blocks_.size());
        for (const auto &[addr, ret_block] : return_blocks_) {
            switch_inst->addCase(ConstantInt::get(i64, addr), ret_block);
        }
    }
    break;
}
```

## The NEXT_PC Mechanism

Remill's `RET` semantic:
1. Pops the return address from the simulated stack (RSP)
2. Stores it in `NEXT_PC`

The lifter reads `NEXT_PC` after the RET semantic executes and uses it to dispatch:

```llvm
; After lifting "ret" in get_value:
%next_pc = load i64, ptr %NEXT_PC           ; Return address popped by RET
switch i64 %next_pc, label %ret_default [
    i64 5368713227, label %ret_5368713227   ; Known return address -> continuation
]

ret_5368713227:
    br label %bb_5368713227                  ; Continue to "or eax, 1300h"
```

## Control Flow Diagram

```
Entry (main)
    │
    ▼
┌─────────────────────┐
│ call get_value      │ ──────────┐
│ (CALL semantic:     │           │
│  push return_addr)  │           │
└─────────────────────┘           │
                                  ▼
                    ┌─────────────────────┐
                    │ get_value:          │
                    │   mov eax, 37h      │
                    │   ret               │
                    │ (RET semantic:      │
                    │  pop -> NEXT_PC)    │
                    └─────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────┐
                    │ switch(NEXT_PC)     │
                    │   case return_addr: │──────┐
                    │   default: exit     │      │
                    └─────────────────────┘      │
                                                 │
    ┌────────────────────────────────────────────┘
    ▼
┌─────────────────────┐
│ ret_continuation:   │
│   br %after_call    │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│ after_call:         │
│   or eax, 1300h     │
│   ret               │ ──▶ Exit (main's RET, no dispatch)
└─────────────────────┘
```

## Distinguishing Helper RETs from Main's RET

Not all RETs should dispatch. The heuristic:

```cpp
bool is_helper = call_targets_.count(block_addr) || block_addr < entry_point_;
```

1. **call_targets_**: Contains entry points of called functions
2. **block_addr < entry_point_**: Helper functions typically appear before main in the binary

| Function | block_addr | entry_point_ | is_helper | Action |
|----------|------------|--------------|-----------|--------|
| get_value | 0x140001000 | 0x140001006 | true | Dispatch via switch |
| main | 0x14000100B | 0x140001006 | false | Exit LLVM function |

## Stack Considerations

The CALL/RET semantics manipulate RSP and stack memory:

1. **CALL**: Decrements RSP, writes return address to `[RSP]`
2. **RET**: Reads return address from `[RSP]`, increments RSP

The memory lowering pass must handle these stack accesses. The stack alloca needs extra space for the caller's frame:

```cpp
// Allocate stack with extra space above initial RSP
constexpr uint64_t caller_space = 8;  // Space for return address
uint64_t total_size = stack_size + caller_space;
```

## Result

After lifting and optimization:

```llvm
define i32 @test() {
entry:
    ; ... setup ...
    %stack_val = load i64, ptr %stack_ptr      ; Load return address
    %cond = icmp eq i64 %stack_val, 5368713227 ; Check if matches
    br i1 %cond, label %ret_continuation, label %exit

ret_continuation:
    br label %exit

exit:
    %result = phi i32 [ 4919, %ret_continuation ], [ 55, %entry ]
    ret i32 %result
}
```

LLVM's optimizer:
- Inlines the entire call sequence
- Recognizes the return address matches
- Propagates the final value (0x1337 = 4919)

## Pre-requirements

1. **Entry point must be known**: The lifter needs to distinguish main from helpers
2. **Full CFG exploration**: Must discover all CALLs before lifting to pre-create return blocks
3. **Stack space**: The stack alloca must include space for return addresses
4. **Remill's NEXT_PC**: The lifted function must have `NEXT_PC` alloca for RET dispatch

## Key Files

- `src/lifting/control_flow_lifter.h` - Class with `return_blocks_` and `call_targets_`
- `src/lifting/control_flow_lifter.cpp` - CALL/RET handling implementation
- `src/tests/ret_with_code/call_func.asm` - Test case with internal call

---

## Comparison with McSema

### How McSema Handles CALL/RET

McSema treats internal calls differently - it **doesn't inline** them by default:

```cpp
// McSema's approach (BC/Function.cpp)
case remill::Instruction::kCategoryDirectFunctionCall: {
    // Call the lifted function directly
    auto callee = GetOrDeclareFunction(target_ea);
    auto new_state = builder.CreateCall(callee, {state, mem});
    // Continue with returned state
    break;
}
```

Each lifted function is a separate LLVM function, and CALLs become actual LLVM calls.

### Comparison

| Aspect | This Project | McSema |
|--------|--------------|--------|
| Internal calls | Inlined with dispatch | Separate LLVM functions |
| RET handling | Switch dispatch | LLVM function return |
| Optimization | Full inlining possible | Cross-function optimization needed |
| Complexity | Simpler (single function) | More complex (whole binary) |

### Trade-offs

**This project's approach (inlining)**:
- Pro: Better optimization - LLVM sees everything
- Pro: No function call overhead
- Con: Doesn't scale to large call graphs
- Con: Recursion would cause infinite IR

**McSema's approach (separate functions)**:
- Pro: Handles recursion naturally
- Pro: Scales to large binaries
- Con: Requires link-time optimization for cross-function optimization
- Con: More complex state passing

### When to Use Each

- **This project**: Single functions or small call trees with no recursion
- **McSema**: Whole-binary lifting with arbitrary call graphs
