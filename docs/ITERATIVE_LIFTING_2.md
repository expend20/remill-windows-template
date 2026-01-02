# Deferred Return Address Discovery

## The Problem

Standard lifting assumes code after CALL is reachable:

```asm
call some_func    ; Callee returns normally
mov eax, 1337h    ; This executes after return
ret
```

But obfuscation patterns like VMProtect use non-returning calls:

```asm
call non_ret_trampoline   ; Callee pops return addr, jumps elsewhere
db 0CBh                   ; RETF - junk code, never executed
```

Lifting the junk code corrupts the IR and prevents optimization.

## Solution: Defer Until SCCP Proves Reachability

Instead of immediately following CALL return addresses, defer their discovery until SCCP proves they're reachable through stack analysis:

1. **CALL pushes return address** to stack (via remill semantics)
2. **RET pops and jumps** to the address on stack
3. **SCCP traces** the push/pop through symbolic memory
4. **If matched**, the return address is proven reachable

```
┌──────────────────────────────────────────────────────────┐
│  Block Discovery (Iteration 0)                           │
│  - Entry point calls helper function                     │
│  - DON'T add return address to worklist                  │
│  - Create dispatch switch for deferred resolution        │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│  SCCP Resolution                                         │
│  - Clone module, inline helpers                          │
│  - Create RSP alloca with fixed constant                 │
│  - Create stack alloca for stack memory                  │
│  - Replace memory intrinsics with stack/symbolic select  │
│  - Run SCCP to fold push/pop pairs                       │
│  - Extract PC stores → discovered return addresses       │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│  Iteration 1+                                            │
│  - Discovered return addresses added to worklist         │
│  - Lift return blocks, connect to dispatch switches      │
│  - Junk code after non-returning calls is NEVER lifted   │
└──────────────────────────────────────────────────────────┘
```

## CALL Return Dispatch Mechanism

When a CALL's return address isn't known yet, create a dispatch switch:

**Iteration 0 (before return address discovered):**
```llvm
entry:
  ; CALL semantic pushes return address
  call @_CALL_semantic(...)

  ; Call helper function
  %result = call ptr @helper_func(...)

  ; Dispatch switch - cases added when return block discovered
  br label %call_ret_dispatch

call_ret_dispatch:
  switch i64 0x14000100b, label %call_ret_default [
    ; Empty - return block not yet discovered
  ]

call_ret_default:
  ret ptr %result
```

**Iteration 1 (after SCCP discovers return address):**
```llvm
call_ret_dispatch:
  switch i64 0x14000100b, label %call_ret_default [
    i64 5368713227, label %bb_14000100b  ; Case added!
  ]

bb_14000100b:
  ; OR eax, 1300h - the actual return code
  call @_OR_semantic(...)
  ; ...
```

## SCCP Stack Tracing

To trace return addresses through the stack, SCCP needs:

### 1. Fixed RSP Constant
```cpp
constexpr uint64_t STACK_BASE = 0x7FFFFF000000ULL;
constexpr uint64_t STACK_TOP = STACK_BASE + STACK_SIZE;

// Create RSP alloca initialized to known constant
rsp_alloca = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "rsp_val");
builder.CreateStore(builder.getInt64(STACK_TOP), rsp_alloca);
```

### 2. Stack Memory Alloca
```cpp
// Local stack array that SCCP can analyze
auto *stack_type = llvm::ArrayType::get(builder.getInt64Ty(), 512);
stack_alloca = builder.CreateAlloca(stack_type, nullptr, "sccp_stack");
```

### 3. Memory Intrinsic Replacement
Replace remill memory operations with stack/symbolic memory select:

```llvm
; Original (from remill):
call @__remill_write_memory_64(mem, %rsp, %return_addr)

; Replaced:
%is_stack = icmp uge i64 %rsp, STACK_BASE
%is_stack2 = icmp ult i64 %rsp, STACK_TOP
%in_stack = and i1 %is_stack, %is_stack2
%stack_idx = lshr i64 (sub i64 %rsp, STACK_BASE), 3
%stack_ptr = getelementptr [512 x i64], ptr %sccp_stack, i64 0, i64 %stack_idx
%mem_ptr = select i1 %in_stack, ptr %stack_ptr, ptr %symbolic_mem_ptr
store i64 %return_addr, ptr %mem_ptr
```

### 4. SCCP Evaluation
After optimization, SCCP folds the push/pop pair:

```llvm
; Before SCCP:
store i64 %return_addr, ptr %stack_ptr  ; CALL pushes
%loaded = load i64, ptr %stack_ptr      ; RET pops
store i64 %loaded, ptr %PC              ; RET jumps

; After SCCP:
store i64 5368713227, ptr %PC  ; Constant! (0x14000100b)
```

## Non-Returning Call Example

```asm
; Entry point
non_ret_call_retf:
    call non_ret_trampoline   ; Callee doesn't return here
    retf                      ; Junk - never executed

; Trampoline that manipulates return address
non_ret_trampoline:
    pop rax                   ; Pop return address
    lea rax, [rax + 5]        ; Skip the RETF
    push rax
    ret                       ; "Returns" to compute_result

compute_result:
    mov eax, 1337h
    ret
```

**What gets lifted:**
- `non_ret_call_retf` - entry block with CALL
- `non_ret_trampoline` - pops, modifies, pushes back
- `compute_result` - discovered via SCCP

**What is NOT lifted:**
- The `retf` (0xCB) junk byte - SCCP never discovers it as a target

**Final optimized output:**
```llvm
define i32 @test() {
entry:
  ret i32 4919  ; 0x1337
}
```

## Implementation Details

### Files Modified

| File | Changes |
|------|---------|
| `block_decoder.cpp` | Don't add return address after CALL to worklist |
| `block_terminator.cpp` | Create dispatch switch for deferred CALL returns |
| `function_splitter.cpp` | Skip creating duplicate helper functions |
| `indirect_jump_resolver.cpp` | RSP/stack alloca creation, memory replacement |

### Key Code: CALL Return Dispatch

```cpp
// block_terminator.cpp - DirectFunctionCall case
if (sameFunction(next_addr)) {
  builder.CreateBr(getBlock(next_addr));
} else {
  // Return address not yet discovered - create dispatch switch
  auto *dispatch_block = llvm::BasicBlock::Create(
      ctx_.GetContext(), "call_ret_dispatch", block->getParent());
  builder.CreateBr(dispatch_block);

  llvm::IRBuilder<> dispatch_builder(dispatch_block);
  auto *default_block = llvm::BasicBlock::Create(...);

  // Switch on constant next_addr - will match when case is added
  auto *sw = dispatch_builder.CreateSwitch(
      builder.getInt64(next_addr), default_block, 0);

  // Store for later population
  iter_state.unresolved_indirect_jumps[block_addr] = sw;
}
```

### Key Code: RSP Alloca for SCCP

```cpp
// indirect_jump_resolver.cpp - ResolveIndirectJumps
constexpr uint64_t STACK_BASE = 0x7FFFFF000000ULL;
constexpr uint64_t STACK_TOP = STACK_BASE + STACK_SIZE;

// RSP as alloca with known initial value
rsp_alloca = builder.CreateAlloca(builder.getInt64Ty(), nullptr, "rsp_val");
builder.CreateStore(builder.getInt64(STACK_TOP), rsp_alloca);

// Stack memory as local array
auto *stack_type = llvm::ArrayType::get(builder.getInt64Ty(), 512);
stack_alloca = builder.CreateAlloca(stack_type, nullptr, "sccp_stack");
```

## Test Results

| Test | Status | Description |
|------|--------|-------------|
| `call_direct` | PASS | Basic CALL/RET with return value |
| `call_chain` | PASS | 10 nested function calls |
| `non_ret_call_retf` | PASS | Non-returning call with junk after |
| `indirect_call_*` | PASS | All indirect call variants |
| `xtea_indirect_call` | PASS | XTEA with indirect call obfuscation |

## Limitations

| Scenario | Status | Notes |
|----------|--------|-------|
| Normal CALL/RET | Works | SCCP traces through stack |
| Non-returning calls | Works | Junk code not lifted |
| Nested calls (10 deep) | Works | Each has unique RSP |
| Variable stack depth | Partial | Fixed stack size (4KB) |
| Complex xtea patterns | Partial | May exceed SCCP capabilities |
| Runtime-dependent returns | Fails | Can't fold non-constant values |

## Debug Output

```
=== Iteration 0 ===
Pending blocks: 1
Discovered 2 total blocks so far
Created CALL return dispatch at 0x140001006 for return addr 0x14000100b
Created RSP alloca and stack alloca for SCCP analysis
  Stack base: 0x7fffff000000, top: 0x7fffff001000
Replaced 3 RSP loads and 2 RSP stores with alloca ops
PC store found, value:   %1 = add i64 %program_counter, 5
  Evaluated to: 0x14000100b
  -> Adding as new target!

=== Iteration 1 ===
Pending blocks: 1
Discovered 3 total blocks so far
Lifting completed: 2 iterations, 3 blocks
```
