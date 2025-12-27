# Pointer-Through-Memory Tracking Plan

## Problem Statement

The memory lowering in `memory_lowering.cpp` fails when a pointer value is:
1. Stored to memory (stack or global)
2. Later loaded back
3. Used to compute an address for another memory access

**Example**: In XTEA with `noinline`, the key pointer (`0x140002000`) is passed as an argument:
```
; Store key pointer to stack
call __remill_write_memory_64(mem, 0x7FFE00, 0x140002000)

; ... later in decrypt function ...
; Load pointer from stack
%ptr = call __remill_read_memory_64(mem, 0x7FFE00)  ; returns 0x140002000 but we don't know

; Use pointer to access key[i]
%addr = add %ptr, %idx_times_4
%val = call __remill_read_memory_32(mem, %addr)    ; FAILS: addr is dynamic, not const + offset
```

**Current limitation**: `DecomposeAddress` only handles:
- Constant addresses: `load from 0x140002000`
- `constant_base + dynamic_offset`: `load from 0x140002000 + idx`

It cannot handle `(loaded_value) + offset` because `loaded_value` is not a constant.

## Solution: Pointer Value Tracking

Track known pointer values through store/load pairs during lowering. This works in multiple passes until no more progress is made.

### Key Data Structures

```cpp
// Tracks known pointer values that flow through memory
struct PointerTracker {
  // Map from LLVM Value* to known constant pointer value
  // When we see a load from stack/global and we know what's stored there,
  // we record: load_result -> known_value
  std::map<llvm::Value*, uint64_t> known_pointer_values;

  // Map from (memory_location_VA) to stored pointer value
  // When we see: write_memory_64(mem, 0x7FFE00, 0x140002000)
  // We record: 0x7FFE00 -> 0x140002000
  std::map<uint64_t, uint64_t> memory_contents;
};
```

### Algorithm

```
function LowerMemoryWithPointerTracking:
    tracker = PointerTracker()
    changed = true
    iteration = 0

    while changed and iteration < MAX_ITERATIONS:
        changed = false
        iteration++

        for each memory intrinsic call (in program order):
            if is_write:
                # Track pointer stores
                if addr is constant:
                    if value is constant AND points to known section:
                        tracker.memory_contents[addr] = value
                    elif value is in tracker.known_pointer_values:
                        tracker.memory_contents[addr] = tracker.known_pointer_values[value]

                # Lower the write as before
                lower_write(call)

            elif is_read:
                decomposed = false

                # First try normal decomposition
                (base, offset) = DecomposeAddress(addr)
                if base:
                    decomposed = true
                else:
                    # Try with known pointer values
                    (base, offset) = DecomposeAddressWithTracking(addr, tracker)
                    if base:
                        decomposed = true
                        changed = true  # Made progress!

                if decomposed:
                    lower_read(call, base, offset)

                    # Track loaded pointers
                    if read_size == 64:
                        if addr is constant:
                            if addr in tracker.memory_contents:
                                tracker.known_pointer_values[result] = tracker.memory_contents[addr]
                        elif base is constant:
                            # Can track from known base + constant offset
                            ...
```

### Enhanced DecomposeAddress

```cpp
// New version that checks tracked pointer values
std::pair<uint64_t, llvm::Value*>
DecomposeAddressWithTracking(
    llvm::Value *addr,
    const MemoryBackingInfo &mem_info,
    const StackBackingInfo *stack_info,
    const PointerTracker &tracker)
{
  // Try existing decomposition first
  auto result = DecomposeAddress(addr, mem_info, stack_info);
  if (result.first != 0) return result;

  // Check if addr itself is a tracked pointer
  if (auto it = tracker.known_pointer_values.find(addr);
      it != tracker.known_pointer_values.end()) {
    uint64_t known_ptr = it->second;
    if (mem_info.FindGlobalForAddress(known_ptr).first ||
        (stack_info && stack_info->FindStackOffset(known_ptr).first)) {
      // Return as base with zero offset
      return {known_ptr, ConstantInt::get(addr->getType(), 0)};
    }
  }

  // Check for (tracked_pointer + dynamic_offset) pattern
  if (auto *bin_op = dyn_cast<BinaryOperator>(addr)) {
    if (bin_op->getOpcode() == Instruction::Add ||
        bin_op->getOpcode() == Instruction::Or) {
      Value *op0 = bin_op->getOperand(0);
      Value *op1 = bin_op->getOperand(1);

      // Check each operand
      for (int i = 0; i < 2; i++) {
        Value *potential_base = (i == 0) ? op0 : op1;
        Value *potential_offset = (i == 0) ? op1 : op0;

        if (auto it = tracker.known_pointer_values.find(potential_base);
            it != tracker.known_pointer_values.end()) {
          uint64_t known_ptr = it->second;
          if (mem_info.FindGlobalForAddress(known_ptr).first ||
              (stack_info && stack_info->FindStackOffset(known_ptr).first)) {
            return {known_ptr, potential_offset};
          }
        }
      }
    }
  }

  return {0, nullptr};
}
```

### Handling Stack Pointer Stores

When we see a store of a known section address to stack:
```
write_memory_64(mem, stack_addr, 0x140002000)
```

We record `memory_contents[stack_addr] = 0x140002000`.

When we later see a load from that stack location:
```
%ptr = read_memory_64(mem, stack_addr)
```

After lowering, we track `known_pointer_values[%ptr] = 0x140002000`.

Then when that loaded value is used:
```
%addr = add %ptr, %offset
%val = read_memory_32(mem, %addr)
```

`DecomposeAddressWithTracking` finds `%ptr` in `known_pointer_values` and returns `{0x140002000, %offset}`.

## Implementation Steps

### Step 1: Add PointerTracker struct to memory_lowering.h

```cpp
struct PointerTracker {
  std::map<llvm::Value*, uint64_t> known_pointer_values;
  std::map<uint64_t, uint64_t> memory_contents;

  void TrackStore(uint64_t addr, uint64_t value,
                  const MemoryBackingInfo &mem_info);
  void TrackLoadResult(llvm::Value *result, uint64_t loaded_from);
  std::optional<uint64_t> GetKnownValue(llvm::Value *v) const;
};
```

### Step 2: Add DecomposeAddressWithTracking to memory_lowering.cpp

Create enhanced version that checks `tracker.known_pointer_values`.

### Step 3: Modify LowerMemoryIntrinsics

1. Create PointerTracker at start
2. Process in a loop until no changes
3. Track stores of section addresses
4. Track loads from tracked locations
5. Use DecomposeAddressWithTracking for dynamic addresses

### Step 4: Test with XTEA noinline

Create a test case with `__attribute__((noinline))` encrypt/decrypt functions that pass the key pointer through the stack.

## Files to Modify

| File | Changes |
|------|---------|
| `src/lifting/memory_lowering.h` | Add `PointerTracker` struct |
| `src/lifting/memory_lowering.cpp` | Add tracking, multi-pass lowering |

## Edge Cases

1. **Multiple stores to same location**: Last store wins (tracked in iteration order)
2. **Conditional stores**: Cannot track (different values on different paths)
3. **Loop-carried pointers**: Multi-pass handles up to MAX_ITERATIONS levels
4. **Aliasing via different addresses**: Only exact address matches tracked
5. **Stack addresses computed dynamically**: Only constant stack addresses tracked

## Current Implementation Status

The pointer tracking infrastructure has been implemented with the following capabilities:

**Works for:**
- Constant pointer stores to constant memory addresses
- Loads from tracked memory locations (result is tracked)
- Direct uses of tracked Values (e.g., `load tracked_ptr` or `add tracked_ptr, offset`)
- PHI nodes where all non-undef incoming values resolve to the SAME known pointer
- Iterative multi-pass lowering with progress tracking

**Known limitations:**
- **Inter-procedural pointer flow**: When a pointer is passed as a function argument through the stack, it crosses stack frame boundaries. The caller stores to address A, but the callee reads from address B (its own frame). Our tracking only works for same-address store/load pairs.
- **PHI nodes with unlowered call results**: When a phi has an incoming value from an unlowered memory read call, we can't resolve that phi, creating a circular dependency.
- Cannot track pointers that are computed (e.g., pointer arithmetic results stored and reloaded)
- Maximum iteration limit prevents infinite loops but may miss deep chains

### XTEA Noinline Case Study

With `__attribute__((noinline))` functions, the key pointer (0x140002000) flows through multiple stack frames:

1. **Main's stack frame**:
   - Stores key pointer at 0x7ffffeffffb0 (we track this!)
   - Stores return address at 0x7ffffeffffb8

2. **Encrypt/Decrypt's stack frame** (after helper call):
   - Has different stack addresses (e.g., 0x7ffffefffe40)
   - Reads key parameter from ITS frame, not main's
   - This read address is computed via phi nodes from frame pointer evolution

3. **The circular dependency**:
   ```
   key_ptr_read (unlowered) --> result used in phi --> phi used to compute addresses
       ^                                                        |
       +--------------------------------------------------------+
   ```

   We can't lower the key_ptr_read because its address comes from a phi.
   We can't resolve the phi because it has an unlowered call as incoming value.

### Inlined Functions Work

When encrypt/decrypt are inlined (default XTEA test), everything works because:
- Single stack frame, no frame pointer phis
- Key pointer stored and loaded from same addresses
- All memory accesses use constant base + dynamic offset pattern

### Future Work for Inter-procedural Tracking

Options to address noinline function calls:
1. **Parameter correlation**: Match caller's argument pushes with callee's parameter reads
2. **Stack frame analysis**: Track how RSP evolves through calls and map addresses
3. **Demand-driven resolution**: When a read address is a phi of stack addresses, speculatively resolve assuming they're the same logical location
4. **LLVM Alias Analysis**: Use LLVM's built-in analysis for more sophisticated tracking

## Future Enhancements

1. LLVM Alias Analysis integration for more precise tracking
2. SSA-based pointer tracking for phi-aware analysis
3. Integration with external xref information (IDA Pro, etc.)
4. Inter-procedural dataflow for function call boundaries

# Expret hints

## Hint 1

Load/Store prop is already hard enough going cross block, going cross function would require a bit of wizardry I wouldn’t want to do
Is there anything preventing you from inlining the callee?

## Hint 2

Do you mean that you want to propagate past the function call where the stack pointer is passed as an argument?

If that's the case you need to come up with proper annotations for the function calls you are lifting, enabling LLVM's Alias Analysis to do its job. I'm specifically talking about the LLVM memory attributes that you can assign to the function and function arguments to specify if the function is reading/writing/reading-and-writing/not-accessing memory and in addition if it does that via arguments and/or other pointers.
Look for readnone, readonly, writeonly, argmemonly and especially the new fine grained memory(..) attributes in the LLVM language documentation: https://llvm.org/docs/LangRef.html
This can help you in some cases, but the Alias Analysis will still stop because it doesn't know about the size of the pointed objects or if the pointer you are passing to a function can be used to access/manipulate other objects on the stack. To do that you enter decompilation territory where you would need to have structure definitions (like IDA) to assist the AA in doing its job and determining to which extent some pointer on the stack aliases or not with another pointer passed to a function call.

Depending on the code you are lifting and how well the function behaves, you might be able to make stronger assumptions without violating the soundness of the analysis.