# Stack Memory Handling

This document describes how stack memory is handled in the lifter.

## Approach

Stack memory uses the same alloca-based lowering as global memory (see `MEMORY.md`), with a **constant initial RSP value** to enable compile-time address resolution.

## How It Works

### 1. Constant RSP Initialization

Instead of storing a runtime pointer in RSP, we use a known constant:

```cpp
// wrapper_builder.h
constexpr uint64_t INITIAL_RSP = 0x7FFFFF000000ULL;  // Stack base (high address)
constexpr uint64_t STACK_SIZE = 16ULL;               // Small for SROA optimization
```

The wrapper stores this constant into the State's RSP register:
```cpp
builder.CreateStore(ConstantInt::get(i64, INITIAL_RSP), rsp_ptr);
```

### 2. Stack Alloca Creation

Before memory lowering, a stack alloca is created at function entry:

```cpp
// memory_lowering.cpp
StackBackingInfo CreateStackAlloca(Function *func, uint64_t initial_rsp, uint64_t stack_size) {
  // Create [stack_size x i8] alloca
  auto *alloca = builder.CreateAlloca(ArrayType::get(i8, stack_size), nullptr, "__stack_local");
  // Zero initialize
  builder.CreateMemSet(alloca, builder.getInt8(0), stack_size, MaybeAlign(1));
  return {alloca, initial_rsp, stack_size};
}
```

### 3. Address Resolution

When remill lifts `sub rsp, 8` followed by `mov [rsp], eax`, the addresses become constants:
- RSP after `sub rsp, 8` = `0x7FFFFF000000 - 8` = `0x7FFFFEFFF8`
- Memory access address = `0x7FFFFEFFF8`

The lowering pass checks if addresses fall in the stack range:

```cpp
// Stack range: [initial_rsp - stack_size, initial_rsp)
uint64_t stack_bottom = stack_top_va - stack_size;
if (va >= stack_bottom && va < stack_top_va) {
  uint64_t offset = va - stack_bottom;
  return {stack_alloca, offset};
}
```

### 4. Lowering to Load/Store

Memory intrinsics with stack addresses are converted to GEP + load/store:

```llvm
; Before lowering
%val = call i32 @__remill_read_memory_32(ptr %mem, i64 140737471578104)

; After lowering (address 0x7FFFFEFFF8 -> offset 8 in stack alloca)
%ptr = getelementptr [16 x i8], ptr %__stack_local, i64 0, i64 8
%val = load i32, ptr %ptr
```

### 5. Optimization

LLVM's optimization passes (SROA, GVN, MemCpyOpt, DSE) fold the stores and loads:

```llvm
; Before optimization
%__stack_local = alloca [16 x i8]
call void @llvm.memset(%__stack_local, i8 0, i64 16)
store i32 322371584, ptr %__stack_local        ; 0x13370000 at offset 0
store i32 0, ptr (gep %__stack_local, 4)       ; 0x00000000 at offset 4
%val = load i32, ptr (gep %__stack_local, 2)   ; load from offset 2

; After optimization
ret i32 4919  ; 0x1337 - correctly composed from overlapping stores
```

## Key Files

| File | Purpose |
|------|---------|
| `src/lifting/wrapper_builder.h` | Defines `INITIAL_RSP` and `STACK_SIZE` constants |
| `src/lifting/wrapper_builder.cpp` | Stores constant RSP in State |
| `src/lifting/memory_lowering.h` | Declares `StackBackingInfo` and `CreateStackAlloca` |
| `src/lifting/memory_lowering.cpp` | Implements stack address detection and lowering |
| `src/optimization/optimizer.cpp` | Runs passes including MemCpyOpt, DSE for store-to-load forwarding |

## Tests

- `stack_var_write.asm` - Byte writes to stack + dword read
- `unaligned_stack_read.asm` - Unaligned dword read spanning two stores

## Limitations

- Stack size is fixed at compile time (16 bytes currently)
- Only handles constant stack addresses (dynamic indexing not supported)
- Stack grows down from `INITIAL_RSP`
