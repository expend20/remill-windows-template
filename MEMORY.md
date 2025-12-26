# Memory Handling Approaches

This document describes the different approaches for lowering Remill's memory intrinsics (`__remill_read_memory_*`, `__remill_write_memory_*`) to optimizable LLVM IR.

## Background

Remill represents memory operations as intrinsic function calls:
```llvm
%val = call i32 @__remill_read_memory_32(ptr %memory, i64 %address)
call ptr @__remill_write_memory_8(ptr %memory, i64 %address, i8 %value)
```

These intrinsics must be lowered to concrete operations for LLVM to optimize the lifted code.

---

## Approach 1: Custom Byte-Level Tracking

**Implementation**: `ReplaceMemoryIntrinsics()` in `memory_lowering.cpp`

### How It Works

1. **First pass**: Scan all write intrinsics, record written bytes at byte granularity
   - Constant writes: store `address -> byte_value` mapping
   - Non-constant writes: mark addresses as "tainted"

2. **Second pass**: Replace read intrinsics by composing values
   - For each byte in the read range, check:
     - Was it written? Use the written value
     - Not written? Read from original PE data
   - Assemble bytes into the final value

3. **Replace intrinsic call** with the composed constant

### Example

```asm
mov byte ptr [data], 0x37      ; write byte at offset 0
mov byte ptr [data+1], 0x13    ; write byte at offset 1
mov eax, dword ptr [data]      ; read dword (4 bytes)
```

The pass tracks:
- `written_bytes[data+0] = 0x37`
- `written_bytes[data+1] = 0x13`

For the dword read, it composes:
- Byte 0: 0x37 (from write)
- Byte 1: 0x13 (from write)
- Byte 2: 0x00 (from PE data)
- Byte 3: 0x00 (from PE data)
- Result: `0x00001337` = 4919

### Pros

| Advantage | Description |
|-----------|-------------|
| Direct constant folding | Produces immediate constants in IR without relying on LLVM passes |
| Handles type punning | Naturally composes bytes regardless of access sizes |
| Handles unaligned access | Cross-boundary reads work automatically |
| Predictable output | Always produces constants for known addresses |
| No LLVM pass dependencies | Works independently of LLVM optimization quality |

### Cons

| Disadvantage | Description |
|--------------|-------------|
| Custom implementation | Reimplements what LLVM optimizers already do |
| Limited to constants | Only works when addresses and values are compile-time constants |
| No runtime support | Cannot handle dynamic addresses or values |
| Maintenance burden | Must be updated if new memory intrinsics are added |
| Single-function scope | Doesn't handle cross-function memory effects |

---

## Approach 2: Alloca-Based Lowering (McSema-inspired)

**Implementation**: `LowerMemoryIntrinsics()` in `memory_lowering.cpp`

### How It Works

1. **Create backing globals**: Each PE section becomes an LLVM global array
   ```llvm
   @__section_data = private constant [100 x i8] c"..."
   ```

2. **Create local allocas**: At function entry, allocate local copies
   ```llvm
   %data_local = alloca [100 x i8]
   call void @llvm.memcpy(%data_local, @__section_data, i64 100)
   ```

3. **Lower intrinsics to load/store**:
   ```llvm
   ; Before: call i32 @__remill_read_memory_32(ptr %mem, i64 0x140001000)
   ; After:  %ptr = getelementptr [100 x i8], ptr %data_local, i64 0, i64 0
   ;         %val = load i32, ptr %ptr
   ```

4. **Let LLVM optimize**: SROA breaks up allocas, mem2reg promotes to SSA

### Example

```asm
mov byte ptr [data], 0x37
mov byte ptr [data+1], 0x13
mov eax, dword ptr [data]
```

After lowering:
```llvm
%data_local = alloca [100 x i8]
call void @llvm.memcpy(%data_local, @__section_data, 100)

%ptr0 = getelementptr [100 x i8], ptr %data_local, i64 0, i64 0
store i8 55, ptr %ptr0    ; 0x37

%ptr1 = getelementptr [100 x i8], ptr %data_local, i64 0, i64 1
store i8 19, ptr %ptr1    ; 0x13

%ptr2 = getelementptr [100 x i8], ptr %data_local, i64 0, i64 0
%val = load i32, ptr %ptr2
```

After LLVM optimization (SROA + mem2reg + GVN):
```llvm
ret i32 4919
```

### Pros

| Advantage | Description |
|-----------|-------------|
| Leverages LLVM | Uses battle-tested LLVM optimization passes |
| Runtime capable | Can generate real load/store for dynamic addresses |
| Type-aware | LLVM understands memory semantics |
| Extensible | Easy to add new section types or access patterns |
| McSema-compatible | Follows proven approach from McSema |

### Cons

| Disadvantage | Description |
|--------------|-------------|
| LLVM pass dependent | Requires specific passes (SROA, mem2reg, GVN) in right order |
| Alloca overhead | Creates allocas even when not needed |
| memcpy at entry | Copies all section data even if mostly unused |
| Pass ordering sensitive | Wrong pass order can leave unoptimized IR |
| Harder to debug | Optimization happens inside LLVM black box |

---

## Approach 3: Global-Based Lowering (Not Used)

This was attempted but abandoned.

### How It Works

Same as Approach 2, but uses globals directly without allocas:
```llvm
@__section_data = private global [100 x i8] c"..."
store i8 55, ptr getelementptr(@__section_data, 0, 0)
%val = load i32, ptr @__section_data
```

### Why It Failed

LLVM treats globals conservatively - they can be accessed from anywhere, so:
- Stores to globals are not eliminated (might be observed externally)
- Loads from globals are not forwarded from stores (might be modified externally)
- GlobalOpt pass can help but causes crashes when run before all uses are resolved

---

## Comparison Matrix

| Feature | Byte Tracking | Alloca-Based | Global-Based |
|---------|---------------|--------------|--------------|
| Compile-time constants | Excellent | Good | Poor |
| Runtime execution | No | Yes | Yes |
| Type punning | Excellent | Good | Good |
| Unaligned access | Excellent | Good | Good |
| LLVM integration | None | High | Medium |
| Code complexity | Medium | Low | Low |
| Maintenance | Higher | Lower | Lower |
| Debug visibility | High | Low | Low |

---

## Current Implementation

The codebase uses **Approach 2 (Alloca-Based)** as the primary method:

```cpp
// Create backing globals from PE sections
auto memory_info = lifting::CreateMemoryGlobals(module, pe_info);

// First optimization pass (inline, fold addresses)
optimization::OptimizeForCleanIR(module, wrapper);

// Lower intrinsics to load/store from allocas
lifting::LowerMemoryIntrinsics(module, memory_info, wrapper);

// Second optimization pass (SROA, mem2reg, GVN)
optimization::OptimizeForCleanIR(module, wrapper);
```

**Approach 1 (Byte Tracking)** is still available as `ReplaceMemoryIntrinsics()` but is not used.

---

## When to Use Each

| Use Case | Recommended Approach |
|----------|---------------------|
| Shellcode lifting (constants only) | Either works |
| Full binary lifting | Alloca-based |
| Maximum optimization control | Byte tracking |
| Runtime execution needed | Alloca-based |
| Debugging optimization issues | Byte tracking |
