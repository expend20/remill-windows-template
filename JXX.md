# Lifting Conditional Jumps (JXX Instructions)

This document explains how conditional jumps (`JZ`, `JNZ`, `JG`, etc.) are lifted to LLVM IR in this project.

## The Problem

The original `InstructionLifter` lifted instructions **linearly** - one after another in sequence. This approach fails for code with control flow:

```asm
    xor eax, eax        ; eax = 0
    mov ecx, 37         ; counter
loop_start:
    add eax, ecx        ; eax += ecx
    dec ecx             ; ecx--
    jnz loop_start      ; if ecx != 0, jump back  <-- PROBLEM!
    add eax, 1078h
    ret
```

With linear lifting:
1. Instructions are lifted in order until `ret`
2. The `jnz loop_start` is lifted, but there's no LLVM branch - execution just falls through
3. The loop body executes only once, producing wrong results

## The Solution: Control Flow Graph Discovery

The `ControlFlowLifter` solves this with a **two-pass approach**:

### Pass 1: Discover Basic Blocks

Before lifting any code, we decode ALL instructions and identify **basic block boundaries**:

```cpp
bool ControlFlowLifter::DiscoverBasicBlocks(uint64_t start_address, ...) {
  // Function entry is always a block start
  block_starts_.insert(start_address);

  while (offset < size) {
    // Decode instruction
    DecodeInstruction(address, bytes_view, decoded.instr, ...);

    switch (decoded.instr.category) {
      case kCategoryConditionalBranch:
        // Both jump target AND fall-through start new blocks
        block_starts_.insert(target);      // e.g., loop_start
        block_starts_.insert(next_addr);   // instruction after jnz
        break;

      case kCategoryDirectJump:
        block_starts_.insert(target);
        break;

      case kCategoryFunctionReturn:
        block_starts_.insert(next_addr);   // next instruction (if any)
        break;
    }
  }
}
```

For the loop example, this discovers 3 basic blocks:
```
Block 0x140001000:  xor eax, eax; mov ecx, 37
Block 0x140001007:  add eax, ecx; dec ecx; jnz loop_start  (loop body)
Block 0x14000100D:  add eax, 1078h; ret  (loop exit)
```

### Pass 2: Create LLVM Basic Blocks

Create an LLVM `BasicBlock` for each discovered address:

```cpp
void ControlFlowLifter::CreateBasicBlocks(llvm::Function *func) {
  for (uint64_t addr : block_starts_) {
    auto *block = BasicBlock::Create(context, "bb_" + std::to_string(addr), func);
    blocks_[addr] = block;
  }
}
```

### Pass 3: Lift Instructions with Proper Terminators

Lift instructions into their blocks, and finish each block with the correct LLVM terminator:

```cpp
void ControlFlowLifter::FinishBlock(BasicBlock *block, const DecodedInstruction &last_instr, ...) {
  switch (last_instr.instr.category) {
    case kCategoryConditionalBranch:
      // Load BRANCH_TAKEN flag set by remill's lifted code
      auto *cond_val = builder.CreateLoad(i8, branch_taken_alloca);
      auto *cond_bool = builder.CreateICmpNE(cond_val, 0);
      // Create conditional branch: if taken -> loop, else -> exit
      builder.CreateCondBr(cond_bool, blocks_[taken_addr], blocks_[next_addr]);
      break;

    case kCategoryDirectJump:
      builder.CreateBr(blocks_[target]);
      break;

    case kCategoryFunctionReturn:
      builder.CreateRet(...);
      break;
  }
}
```

## The BRANCH_TAKEN Mechanism

Remill's instruction semantics don't directly produce LLVM branches. Instead, they:

1. Compute the branch condition (e.g., `ZF == 0` for `JNZ`)
2. Store the result in a `BRANCH_TAKEN` variable in the State structure

The `ControlFlowLifter` reads this variable after lifting and uses it to create the actual LLVM `br` instruction:

```llvm
; After lifting "jnz loop_start":
%branch_taken = load i8, ptr %BRANCH_TAKEN
%cond = icmp ne i8 %branch_taken, 0
br i1 %cond, label %bb_loop_start, label %bb_loop_exit
```

## Pre-requirements

1. **Full CFG exploration first**: You MUST decode all instructions before lifting. The lifter needs to know ALL basic block boundaries upfront to create the LLVM structure.

2. **Valid code range**: Jump targets must be within the code being lifted. External jumps result in function returns.

3. **Remill's BRANCH_TAKEN**: The lifted function must have the `BRANCH_TAKEN` alloca created by `DefineLiftedFunction()`.

## Result

After lifting and optimization, the loop is fully analyzed by LLVM:

```llvm
; Before optimization - loop with phi nodes
bb_loop:
  %counter = phi i32 [ 37, %entry ], [ %next, %bb_loop ]
  %sum = phi i32 [ 0, %entry ], [ %new_sum, %bb_loop ]
  %new_sum = add i32 %sum, %counter
  %next = add i32 %counter, -1
  %done = icmp eq i32 %next, 0
  br i1 %done, label %bb_exit, label %bb_loop

; After O3 optimization - loop fully folded!
define i32 @test() {
  ret i32 4919
}
```

The loop computing `1+2+...+37 + 0x1078 = 0x1337` is completely eliminated at compile time.

## Key Files

- `src/lifting/control_flow_lifter.h` - Class declaration
- `src/lifting/control_flow_lifter.cpp` - Implementation
- `src/tests/ret_with_code/loop_sum.asm` - Test case with conditional jump

---

## Comparison with McSema

McSema (discontinued, but a good reference) takes a more sophisticated approach to CFG recovery.

### Architecture Comparison

| Aspect | This Project | McSema |
|--------|--------------|--------|
| CFG Recovery | Inline (same pass as lifting) | Separate tool (mcsema-disass) |
| Analysis Engine | Remill's decoder | Dyninst ParseAPI |
| CFG Format | In-memory maps | Protobuf serialization |
| Scope | Single function | Whole binary |

### McSema's Two-Phase Architecture

```
┌─────────────────┐     protobuf      ┌─────────────────┐
│  mcsema-disass  │ ───────────────▶  │   mcsema-lift   │
│  (CFG Recovery) │                   │  (LLVM Lifting) │
│                 │                   │                 │
│  Uses Dyninst   │                   │  Uses Remill    │
└─────────────────┘                   └─────────────────┘
```

**Phase 1 - CFG Recovery** (dyninst/CFGWriter.cpp):
```cpp
// McSema uses Dyninst's ParseAPI for sophisticated CFG analysis
for (auto edge : block->targets()) {
  auto target = edge->trg()->start();
  cfg_block->add_successor_eas(target);  // Record in protobuf
}
```

**Phase 2 - Lifting** (BC/Function.cpp):
```cpp
// Later, when lifting, it reads the pre-computed successors
case remill::Instruction::kCategoryConditionalBranch: {
  const auto cond = remill::LoadBranchTaken(block);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);

  // Uses CFG to get targets - no decoding needed here
  llvm::BranchInst::Create(GetOrCreateBlock(ctx, ctx.inst.branch_taken_pc), taken_block);
  break;
}
```

### Key Differences

**1. CFG Storage**

McSema serializes CFG to protobuf with explicit successor lists:
```cpp
struct NativeBlock {
  uint64_t ea;
  llvm::SmallVector<uint64_t, 2> successor_eas;  // Pre-computed!
};
```

This project computes successors on-the-fly during decoding:
```cpp
std::set<uint64_t> block_starts_;  // Discovered during decode pass
```

**2. Indirect Jumps**

McSema handles jump tables with LLVM switch statements:
```cpp
auto switch_inst = llvm::SwitchInst::Create(switch_index, fallback, num_blocks, block);
for (auto [ea, target_block] : block_map) {
  switch_inst->addCase(llvm::ConstantInt::get(gWordType, ea), target_block);
}
```

This project currently only handles direct jumps within the function.

**3. BRANCH_TAKEN Usage**

Both use remill's `BRANCH_TAKEN` mechanism identically - remill's semantic functions compute the condition, and the lifter reads it to create LLVM branches.

### What McSema Does Better

1. **Whole-binary analysis**: Dyninst can discover functions, resolve indirect calls, and handle complex CFG patterns (exception handling, computed gotos)

2. **Jump table recovery**: Analyzes data sections to find switch statement targets

3. **Cross-function references**: Tracks which functions call which, enabling whole-program lifting

4. **Delay slot handling**: Supports SPARC/MIPS architectures with branch delay slots

### What This Project Does Differently

1. **Simpler, single-pass**: No external tools or serialization - decode and lift in one process

2. **Function-scoped**: Focuses on lifting individual functions, not whole binaries

3. **Optimization focus**: Designed to produce optimizable IR (loops fold to constants)

### Insights for Future Work

From McSema's approach, potential improvements:

1. **Separate CFG pass**: Could use IDA Pro, Ghidra, or Binary Ninja for CFG recovery instead of inline decoding

2. **Indirect jump handling**: Add switch-based lifting for jump tables

3. **Protobuf CFG format**: Would allow using different disassemblers as frontends

4. **Cross-reference tracking**: Know which addresses are code vs data targets
