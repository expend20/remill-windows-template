# Iterative Lifting

Iterative lifting discovers indirect jump targets by running LLVM optimization passes on a cloned module, extracting constant PC values, and repeating until no new targets are found.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│  1. BFS Block Discovery                                 │
│     - Start from entry point                            │
│     - Follow direct jumps/calls/branches                │
│     - Stop at indirect jumps (mark as unresolved)       │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  2. Create & Lift Blocks                                │
│     - Create LLVM basic blocks (named bb_<hex_addr>)    │
│     - Lift instructions via Remill                      │
│     - For indirect jumps: emit switch with PC selector  │
│     - Update switches with cases for known blocks       │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│  3. Resolve Indirect Jumps                              │
│     - Clone the module (preserves original allocas)     │
│     - Run GVN + SCCP on clone to fold computations      │
│     - Find stores to PC register (offset 2472)          │
│     - Evaluate stored value with known entry point      │
│     - Filter out mid-block false positives              │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
                 ┌────┴────┐
                 │ New     │ Yes ──► Add to worklist, repeat
                 │ targets?│
                 └────┬────┘
                      │ No
                      ▼
              Done - run final optimization
```

## Key Insight: Clone Before Optimize

Running SCCP destroys allocas (MEMORY, NEXT_PC) that Remill needs. Solution: clone the module, optimize the clone to discover targets, continue lifting in the original.

```cpp
// Clone module - optimization runs on clone, not original
auto cloned_module = llvm::CloneModule(*original_module);
optimization::OptimizeForResolution(cloned_module.get(), cloned_func);

// Find stores to PC and evaluate with known entry_point
for (auto &inst : ...) {
  if (auto *store = dyn_cast<StoreInst>(&inst)) {
    if (storesTo PC register) {
      auto target = evaluateValue(store->getValueOperand());
      // evaluateValue substitutes program_counter arg with entry_point_
    }
  }
}
```

## Configuration

```cpp
struct IterativeLiftingConfig {
  int max_iterations = 10;
  bool verbose = false;
  std::string dump_iterations_dir;  // If set, dumps iteration_N.ll files
};

// Usage
lifting::ControlFlowLifter lifter(ctx);
lifting::IterativeLiftingConfig config;
config.dump_iterations_dir = "/path/to/output";
lifter.SetIterativeConfig(config);
```

## Debug Output

When `dump_iterations_dir` is set, produces `iteration_N.ll` files showing lifted code after each iteration:

```llvm
; Iteration 0
; Blocks lifted this iteration:
;   0x140001007
; Total blocks so far: 1
; Unresolved indirect jumps: 1

define ptr @lifted_ret_with_code(...) {
  ; ... entry block with indirect jump ...
  switch i64 %pc, label %default []  ; no cases yet
}
```

```llvm
; Iteration 1
; Blocks lifted this iteration:
;   0x140001001
; Total blocks so far: 2
; Unresolved indirect jumps: 1

define ptr @lifted_ret_with_code(...) {
  ; ... entry block ...
  switch i64 %pc, label %default [
    i64 5368713217, label %bb_140001001  ; target discovered!
  ]

bb_140001001:
  ; ... target block code ...
}
```

## Test Case: Indirect Jump with Arithmetic

```asm
target_label PROC
    nop                      ; 1 byte - skipped by inc
    mov eax, 1337h
    ret
target_label ENDP

main PROC
    lea rax, target_label    ; Load address
    inc rax                  ; Skip the nop
    jmp rax                  ; Indirect jump
main ENDP
```

**Result**: 2 iterations, target `0x140001001` discovered via SCCP folding `lea + inc`.

## Files

| File | Purpose |
|------|---------|
| `src/lifting/control_flow_lifter.h` | `IterativeLiftingConfig`, `IterativeLiftingState`, iteration methods |
| `src/lifting/control_flow_lifter.cpp` | BFS discovery, block lifting, SCCP-based resolution, iteration dumps |
| `src/optimization/optimizer.cpp` | `OptimizeForResolution()` - GVN + SCCP pipeline for target discovery |

## Limitations

| Scenario | Status |
|----------|--------|
| Direct jumps/calls | ✅ Works |
| `lea + jmp` | ✅ Works |
| `lea + inc + jmp` (arithmetic) | ✅ Works |
| Jump tables (memory loads) | ❌ Not supported |
| Self-modifying code | ❌ Not supported |
