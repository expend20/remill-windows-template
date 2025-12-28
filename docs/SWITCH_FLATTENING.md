# Deobfuscating Control Flow Flattening

## What is Control Flow Flattening?

Control flow flattening is an obfuscation technique that transforms structured control flow (loops, if/else) into a switch-based state machine. The original program's logic is hidden behind a dispatcher that jumps between "states" based on a state variable.

**Original code:**
```c
int result = 0;
for (int i = 0; i < 32; i++) {
    result += data[i];
}
return result;
```

**After flattening:**
```c
int state = INITIAL_STATE;
while (true) {
    switch (state) {
        case 0x12345678: state = init_loop(); break;
        case 0x23456789: state = check_condition(); break;
        case 0x3456789A: state = loop_body(); break;
        case 0x456789AB: state = increment(); break;
        case 0x56789ABC: return result;
    }
}
```

## The Challenge for Optimizers

Standard LLVM optimizations fail to simplify flattened code because:

1. **State variable lives in memory** - The state is stored in a stack byte array, not in SSA registers
2. **SROA can't help** - Scalar Replacement of Aggregates can't split a monolithic `[N x i8]` array
3. **SCCP is blind** - Sparse Conditional Constant Propagation can't track values through memory

## IR Structure of Flattened Code

Here's what flattened code looks like in LLVM IR:

```llvm
define i32 @flattened_function() {
entry:
  ; Stack is a byte array (simulating the native stack)
  %stack = alloca [4096 x i8], align 1
  call void @llvm.memset.p0.i64(ptr %stack, i8 0, i64 4096, i1 false)

  ; Initialize state variable at offset 120
  %state_ptr = getelementptr [4096 x i8], ptr %stack, i64 0, i64 120
  store i32 -1377842561, ptr %state_ptr    ; Initial state constant
  br label %dispatcher

dispatcher:
  %state_ptr1 = getelementptr [4096 x i8], ptr %stack, i64 0, i64 120
  %state = load i32, ptr %state_ptr1
  switch i32 %state, label %default [
    i32 -1377842561, label %block_A    ; 0xADDFCA7F
    i32 1008562837,  label %block_B    ; 0x3C1D7295
    i32 1539481310,  label %block_C    ; 0x5BC29EDE
    i32 2031438978,  label %block_D    ; 0x79154C82
  ]

block_A:
  ; ... do some work ...
  ; Set next state
  %state_ptr2 = getelementptr [4096 x i8], ptr %stack, i64 0, i64 120
  store i32 1008562837, ptr %state_ptr2   ; Transition to block_B
  br label %dispatcher

block_B:
  ; ... more work ...
  store i32 1539481310, ptr %state_ptr2   ; Transition to block_C
  br label %dispatcher

; ... etc ...
}
```

**Key insight**: All state values ARE constants! The obfuscator just uses random-looking numbers, but they're all statically known at compile time.

## The Solution: Stack Slot Splitting

The core technique is to split the byte array into individual typed allocas. This enables Mem2Reg to promote them to SSA form, after which SCCP can propagate the constant state values.

### Before Splitting

```llvm
; Monolithic byte array - optimizer can't reason about it
%stack = alloca [4096 x i8]

; State stored at offset 120
%ptr = getelementptr [4096 x i8], ptr %stack, i64 0, i64 120
store i32 -1377842561, ptr %ptr

; Load for switch
%ptr2 = getelementptr [4096 x i8], ptr %stack, i64 0, i64 120
%state = load i32, ptr %ptr2
switch i32 %state, label %default [ ... ]
```

### After Splitting

```llvm
; Individual scalar alloca for state at offset 120
%slot_120 = alloca i32

; Direct store to scalar
store i32 -1377842561, ptr %slot_120

; Direct load from scalar
%state = load i32, ptr %slot_120
switch i32 %state, label %default [ ... ]
```

### After Mem2Reg (SSA Promotion)

```llvm
; No more alloca! State is now an SSA value
%state = phi i32 [ -1377842561, %entry ], [ 1008562837, %block_A ], ...
switch i32 %state, label %default [ ... ]
```

### After SCCP (Constant Propagation)

```llvm
; SCCP traces the phi and realizes:
; - From %entry, state is -1377842561 -> goes to block_A
; - From %block_A, state is 1008562837 -> goes to block_B
; - etc.

; The switch becomes a known sequence of jumps
br label %block_A   ; Entry always goes here

block_A:
  ; ...
  br label %block_B   ; Always goes here next
```

### After SimplifyCFG

```llvm
; Blocks are now directly connected, switch is eliminated
; The original loop structure may be recoverable
block_A:
  ; ...
  ; fall through
block_B:
  ; ...
```

## Algorithm for Stack Slot Splitting

1. **Find byte array allocas**: Look for `alloca [N x i8]` patterns
2. **Collect constant-offset accesses**: Find all `getelementptr` with constant indices
3. **Determine access types**: For each offset, track what type is loaded/stored (i32, i64, etc.)
4. **Skip dynamic accesses**: If an offset is accessed with a variable index, don't split it
5. **Skip overlapping accesses**: If offset 100 is accessed as i64 and offset 104 as i32, they overlap
6. **Create individual allocas**: For each safe offset, create `%slot_N = alloca <type>`
7. **Rewrite accesses**: Replace GEP+load/store with direct load/store to the new alloca

## Handling Dynamic Array Access

Some data must remain in the original array. For example, encryption key arrays accessed with computed indices:

```llvm
; Key array at offsets 200-215 (4 x i32)
; Accessed with: key[round & 3]

%idx = and i32 %round, 3           ; Dynamic index 0-3
%offset = add i64 200, %idx_ext    ; Offset 200 + (0,4,8,12)
%ptr = getelementptr [4096 x i8], ptr %stack, i64 0, i64 %offset
%key_word = load i32, ptr %ptr
```

This pattern must NOT be split because:
- The access offset is computed at runtime
- Splitting would create 4 separate allocas that the dynamic GEP can't address

**Solution**: Detect dynamic offset patterns like `add i64 <const>, <variable>` and mark those ranges as "do not split".

## Handling Memcpy Initialization

When an alloca is initialized via `memcpy` from a global constant:

```llvm
%rdata = alloca [256 x i8]
call void @llvm.memcpy.p0.p0.i64(ptr %rdata, ptr @constant_data, i64 256, i1 false)
```

This alloca should NOT be split because:
- The memcpy writes to the original alloca
- Split slots would remain uninitialized
- The constant data would be lost

**Solution**: Skip allocas that have memcpy from global constants as users.

## Complete Optimization Pipeline

For effective deobfuscation, run these passes in order:

1. **Stack Slot Splitter** - Convert byte array to individual allocas
2. **SROA** - Further scalar replacement
3. **Mem2Reg** - Promote allocas to SSA phi nodes
4. **SCCP** - Propagate constant state values through phis
5. **SimplifyCFG** - Fold resolved switch cases into direct branches
6. **ADCE** - Remove dead code from eliminated branches
7. **Loop Unrolling** - Unroll the dispatcher loop (now that trip count is known)
8. **Repeat SCCP + SimplifyCFG** - Clean up after unrolling

## Example: Full Deobfuscation

**Input** (flattened XTEA encryption):
```llvm
define i32 @test() {
  %stack = alloca [4096 x i8]
  ; ... 600+ lines of switch-based state machine ...
  ; ... stores state constants, loads them, switches ...
  switch i32 %state, label %default [
    i32 -1377842561, label %bb1
    i32 1008562837,  label %bb2
    ; ... 8 more cases ...
  ]
  ; ... complex interleaved blocks ...
}
```

**Output** (after optimization):
```llvm
define i32 @test() {
entry:
  ret i32 4919   ; The constant result!
}
```

The entire XTEA encrypt/decrypt roundtrip was computed at compile time because all inputs (key, plaintext) were constants embedded in the binary.

## Limitations

This technique works when:
- State values are constants (not computed from external input)
- State transitions are deterministic
- The byte array is only accessed via constant or analyzable offsets

It may not fully work when:
- State depends on runtime input
- Complex pointer aliasing obscures the state variable
- The obfuscator uses additional techniques (opaque predicates, MBA, etc.)
