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

---

## Comparison with McSema

McSema (in `NOT_INTEGRATED/mcsema`) uses a different approach designed for runtime execution rather than compile-time optimization.

### McSema's Approach

**1. Thread-Local Stack Buffer**

McSema allocates a global thread-local stack array at runtime:

```cpp
// mcsema/BC/Callback.cpp - InitialStackPointerValue()
auto stack_type = llvm::ArrayType::get(llvm::Type::getInt8Ty(*gContext), num_bytes);
__mcsema_stack = new llvm::GlobalVariable(
    *gModule, stack_type, false, llvm::GlobalValue::InternalLinkage,
    llvm::ConstantAggregateZero::get(stack_type), "__mcsema_stack",
    nullptr, llvm::GlobalValue::InitialExecTLSModel);
```

- Size: ~1 MiB (configurable via `explicit_args_stack_size` flag)
- Thread-local storage (TLS) for multi-threaded support
- RSP points near the end with 512-byte minimum frame

**2. ABI-Aligned Stack Pointer**

```cpp
// Platform-specific alignment
// AMD64: rsp & ~15 (16-byte aligned)
// SysV x86: (esp & ~15) - 4
```

**3. Lazy Initialization**

Stack pointer is only initialized if null:
```cpp
auto comparison = ir.CreateICmpEQ(rsp_val, GetConstantInt(ptr_size, 0));
// If null, store InitialStackPointerValue()
```

**4. Memory Access Through Remill**

Stack accesses go through remill's `__remill_read/write_memory_*` intrinsics, same as other memory. No special lowering.

### Key Differences

| Aspect | Our Implementation | McSema |
|--------|-------------------|--------|
| **Goal** | Compile-time constant folding | Runtime execution |
| **RSP Value** | Constant (`0x7FFFFF000000`) | Runtime pointer to TLS buffer |
| **Stack Size** | Small (16 bytes) for SROA | Large (~1 MiB) for real programs |
| **Memory Lowering** | Intrinsics → load/store at known offsets | Intrinsics remain for runtime |
| **Optimization** | Full constant propagation | Limited (addresses not constant) |
| **Multi-threading** | N/A (single function) | TLS stack per thread |
| **ABI Compliance** | Not needed | 16-byte alignment enforced |

### Why We Differ

McSema lifts entire executables for **re-execution**, so it needs:
- Real stack memory that grows dynamically
- Thread-safety via TLS
- ABI compliance for calling native functions

Our lifter targets **analysis/optimization** of small code snippets, so we use:
- Constant RSP to enable LLVM's constant propagation
- Small fixed-size alloca for SROA optimization
- Compile-time lowering to eliminate memory intrinsics

### What We Could Adopt

If we needed runtime execution support:
1. **TLS stack buffer** - For multi-threaded lifted code
2. **Lazy initialization** - Check if RSP is null before initializing
3. **ABI alignment** - For interop with native functions
