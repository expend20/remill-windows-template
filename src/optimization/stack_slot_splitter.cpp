#include "stack_slot_splitter.h"

#include <llvm/IR/Function.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

#include <map>
#include <set>

#include "utils/debug_flag.h"

using namespace llvm;

namespace optimization {

namespace {

// Check if an alloca has a memcpy that initializes it from a global
// These allocas should NOT be split because the memcpy writes to the original
// alloca and the split slots would remain uninitialized.
bool hasMemcpyInitializer(AllocaInst *Alloca) {
  for (User *U : Alloca->users()) {
    // Direct memcpy use
    if (auto *MI = dyn_cast<MemCpyInst>(U)) {
      if (MI->getDest() == Alloca) {
        // Check if source is a global constant
        if (isa<GlobalVariable>(MI->getSource()->stripPointerCasts())) {
          utils::dbg() << "StackSlotSplitter: Skipping alloca - initialized by memcpy from global\n";
          return true;
        }
      }
    }
    // GEP that leads to memcpy (memcpy at offset 0 with GEP)
    if (auto *GEP = dyn_cast<GetElementPtrInst>(U)) {
      if (GEP->hasAllZeroIndices()) {
        for (User *GU : GEP->users()) {
          if (auto *MI = dyn_cast<MemCpyInst>(GU)) {
            if (MI->getDest() == GEP) {
              if (isa<GlobalVariable>(MI->getSource()->stripPointerCasts())) {
                utils::dbg() << "StackSlotSplitter: Skipping alloca - initialized by memcpy from global (via GEP)\n";
                return true;
              }
            }
          }
        }
      }
    }
  }
  return false;
}

struct SlotInfo {
  Type *AccessType = nullptr;
  unsigned AccessSize = 0;
  std::vector<Instruction *> Users;
};

// Check if a GEP has constant indices and compute the byte offset
bool getConstantOffset(GetElementPtrInst *GEP, const DataLayout &DL,
                       int64_t &Offset) {
  APInt OffsetAP(DL.getPointerSizeInBits(), 0);
  if (!GEP->accumulateConstantOffset(DL, OffsetAP)) {
    return false;
  }
  Offset = OffsetAP.getSExtValue();
  return true;
}

// Compute the range of offsets that a dynamic GEP might access
// Returns true if we can determine a range, false if unknown
bool getDynamicOffsetRange(GetElementPtrInst *GEP, const DataLayout &DL,
                           int64_t &MinOffset, int64_t &MaxOffset) {
  // Look for pattern: add i64 <constant_base>, <variable>
  // where variable is computed from and/or operations that bound its range

  // Check if we have a pattern like gep [N x i8], ptr, 0, %dyn_offset
  if (GEP->getNumIndices() == 2) {
    auto *Idx0 = dyn_cast<ConstantInt>(GEP->getOperand(1));
    if (Idx0 && Idx0->isZero()) {
      // First index is 0, second is the byte offset
      Value *Idx1 = GEP->getOperand(2);

      // Check if idx1 is: add <const_base>, <variable>
      if (auto *Add = dyn_cast<BinaryOperator>(Idx1)) {
        if (Add->getOpcode() == Instruction::Add) {
          Value *Op0 = Add->getOperand(0);
          Value *Op1 = Add->getOperand(1);

          ConstantInt *BaseConst = nullptr;
          if (auto *C = dyn_cast<ConstantInt>(Op0))
            BaseConst = C;
          else if (auto *C = dyn_cast<ConstantInt>(Op1))
            BaseConst = C;

          if (BaseConst) {
            int64_t Base = BaseConst->getSExtValue();
            MinOffset = Base;
            MaxOffset = Base + 16;
            utils::dbg() << "StackSlotSplitter: Found dynamic range [" << MinOffset
                         << ", " << MaxOffset << "] from add pattern\n";
            return true;
          }
        }
        // Also check for 'or' pattern (LLVM sometimes uses or instead of add)
        if (Add->getOpcode() == Instruction::Or) {
          Value *Op0 = Add->getOperand(0);
          Value *Op1 = Add->getOperand(1);

          ConstantInt *BaseConst = nullptr;
          if (auto *C = dyn_cast<ConstantInt>(Op0))
            BaseConst = C;
          else if (auto *C = dyn_cast<ConstantInt>(Op1))
            BaseConst = C;

          if (BaseConst) {
            int64_t Base = BaseConst->getSExtValue();
            MinOffset = Base;
            MaxOffset = Base + 16;
            utils::dbg() << "StackSlotSplitter: Found dynamic range [" << MinOffset
                         << ", " << MaxOffset << "] from or pattern\n";
            return true;
          }
        }
      }

      // Check for zext pattern: zext (add/or <const_base>, <variable>)
      if (auto *ZExt = dyn_cast<ZExtInst>(Idx1)) {
        if (auto *BinOp = dyn_cast<BinaryOperator>(ZExt->getOperand(0))) {
          unsigned Opcode = BinOp->getOpcode();
          if (Opcode == Instruction::Add || Opcode == Instruction::Or) {
            Value *Op0 = BinOp->getOperand(0);
            Value *Op1 = BinOp->getOperand(1);

            ConstantInt *BaseConst = nullptr;
            if (auto *C = dyn_cast<ConstantInt>(Op0))
              BaseConst = C;
            else if (auto *C = dyn_cast<ConstantInt>(Op1))
              BaseConst = C;

            if (BaseConst) {
              int64_t Base = BaseConst->getSExtValue();
              MinOffset = Base;
              MaxOffset = Base + 16;
              utils::dbg() << "StackSlotSplitter: Found dynamic range [" << MinOffset
                           << ", " << MaxOffset << "] from zext pattern\n";
              return true;
            }
          }
        }
      }
    }
  }

  return false;
}

// Find all constant-offset accesses to a byte array alloca
// Also detect ranges that have dynamic accesses
void collectSlotAccesses(AllocaInst *Alloca, const DataLayout &DL,
                         std::map<int64_t, SlotInfo> &Slots,
                         std::vector<std::pair<int64_t, int64_t>> &DynamicRanges) {
  for (User *U : Alloca->users()) {
    auto *GEP = dyn_cast<GetElementPtrInst>(U);
    if (!GEP)
      continue;

    int64_t Offset;
    if (!getConstantOffset(GEP, DL, Offset)) {
      // This is a dynamic offset GEP - try to determine its range
      int64_t MinOffset, MaxOffset;
      if (getDynamicOffsetRange(GEP, DL, MinOffset, MaxOffset)) {
        DynamicRanges.push_back({MinOffset, MaxOffset});
        utils::dbg() << "StackSlotSplitter: Found dynamic range ["
                     << MinOffset << ", " << MaxOffset << "]\n";
      }
      continue;
    }

    // Collect load/store users of this GEP
    for (User *GEPUser : GEP->users()) {
      Type *AccessType = nullptr;
      unsigned AccessSize = 0;

      if (auto *Load = dyn_cast<LoadInst>(GEPUser)) {
        AccessType = Load->getType();
        AccessSize = DL.getTypeStoreSize(AccessType);
      } else if (auto *Store = dyn_cast<StoreInst>(GEPUser)) {
        if (Store->getPointerOperand() == GEP) {
          AccessType = Store->getValueOperand()->getType();
          AccessSize = DL.getTypeStoreSize(AccessType);
        }
      }

      if (!AccessType)
        continue;

      auto &Slot = Slots[Offset];
      if (!Slot.AccessType) {
        Slot.AccessType = AccessType;
        Slot.AccessSize = AccessSize;
      } else if (Slot.AccessType != AccessType) {
        // Different types at same offset - use the larger one
        if (AccessSize > Slot.AccessSize) {
          Slot.AccessType = AccessType;
          Slot.AccessSize = AccessSize;
        }
      }
      Slot.Users.push_back(cast<Instruction>(GEPUser));
    }
  }
}

// Check if two slots overlap
bool slotsOverlap(int64_t Offset1, unsigned Size1, int64_t Offset2,
                  unsigned Size2) {
  return !(Offset1 + Size1 <= Offset2 || Offset2 + Size2 <= Offset1);
}

// Remove overlapping slots - keep only non-overlapping ones
void removeOverlappingSlots(std::map<int64_t, SlotInfo> &Slots,
                            const std::vector<std::pair<int64_t, int64_t>> &DynamicRanges) {
  std::set<int64_t> ToRemove;

  // Remove slots that overlap with each other
  for (auto &[Offset1, Info1] : Slots) {
    for (auto &[Offset2, Info2] : Slots) {
      if (Offset1 >= Offset2)
        continue;
      if (slotsOverlap(Offset1, Info1.AccessSize, Offset2, Info2.AccessSize)) {
        ToRemove.insert(Offset1);
        ToRemove.insert(Offset2);
      }
    }
  }

  // Remove slots that overlap with dynamic access ranges
  for (auto &[Offset, Info] : Slots) {
    for (auto &[DynMin, DynMax] : DynamicRanges) {
      if (slotsOverlap(Offset, Info.AccessSize, DynMin, DynMax - DynMin)) {
        utils::dbg() << "StackSlotSplitter: Removing slot at " << Offset
                     << " due to overlap with dynamic range [" << DynMin
                     << ", " << DynMax << "]\n";
        ToRemove.insert(Offset);
        break;
      }
    }
  }

  for (int64_t Offset : ToRemove) {
    Slots.erase(Offset);
  }
}

bool splitByteArrayAlloca(AllocaInst *Alloca, const DataLayout &DL) {
  auto *ArrayTy = dyn_cast<ArrayType>(Alloca->getAllocatedType());
  if (!ArrayTy)
    return false;

  // Only handle [N x i8] arrays
  if (!ArrayTy->getElementType()->isIntegerTy(8))
    return false;

  utils::dbg() << "StackSlotSplitter: Processing byte array alloca ["
               << ArrayTy->getNumElements() << " x i8]\n";

  // Skip allocas that are initialized via memcpy from a global
  // These can't be split because the memcpy would still write to the
  // original alloca, leaving the split slots uninitialized
  if (hasMemcpyInitializer(Alloca)) {
    return false;
  }

  // Collect constant-offset accesses and dynamic access ranges
  std::map<int64_t, SlotInfo> Slots;
  std::vector<std::pair<int64_t, int64_t>> DynamicRanges;
  collectSlotAccesses(Alloca, DL, Slots, DynamicRanges);

  utils::dbg() << "StackSlotSplitter: Found " << Slots.size() << " constant-offset slots, "
               << DynamicRanges.size() << " dynamic ranges\n";

  if (Slots.empty())
    return false;

  // Remove overlapping slots (including those overlapping with dynamic ranges)
  removeOverlappingSlots(Slots, DynamicRanges);

  utils::dbg() << "StackSlotSplitter: After removing overlaps: " << Slots.size() << " slots\n";

  if (Slots.empty())
    return false;

  utils::dbg() << "StackSlotSplitter: Found " << Slots.size()
               << " non-overlapping slots\n";

  // Create individual allocas for each slot
  IRBuilder<> Builder(Alloca->getNextNode());
  std::map<int64_t, AllocaInst *> SlotAllocas;

  for (auto &[Offset, Info] : Slots) {
    auto *NewAlloca =
        Builder.CreateAlloca(Info.AccessType, nullptr,
                             "slot_" + std::to_string(Offset));
    NewAlloca->setAlignment(Alloca->getAlign());
    SlotAllocas[Offset] = NewAlloca;

    utils::dbg() << "StackSlotSplitter: Created alloca for offset "
                 << Offset << ": " << *NewAlloca << "\n";
  }

  // Replace accesses
  bool Changed = false;
  for (auto &[Offset, Info] : Slots) {
    AllocaInst *NewAlloca = SlotAllocas[Offset];

    for (Instruction *User : Info.Users) {
      if (auto *Load = dyn_cast<LoadInst>(User)) {
        // Get the GEP that this load uses
        auto *GEP = cast<GetElementPtrInst>(Load->getPointerOperand());

        // Create new load from the slot alloca
        IRBuilder<> B(Load);
        Value *NewPtr = NewAlloca;

        // Handle type mismatch (e.g., loading i32 from i64 slot)
        if (Load->getType() != Info.AccessType) {
          NewPtr = B.CreateBitCast(NewAlloca, Load->getType()->getPointerTo());
        }

        auto *NewLoad = B.CreateLoad(Load->getType(), NewPtr, Load->getName());
        NewLoad->setAlignment(Load->getAlign());
        Load->replaceAllUsesWith(NewLoad);
        Load->eraseFromParent();

        // Remove GEP if it has no more users
        if (GEP->use_empty())
          GEP->eraseFromParent();

        Changed = true;
      } else if (auto *Store = dyn_cast<StoreInst>(User)) {
        // Get the GEP that this store uses
        auto *GEP = cast<GetElementPtrInst>(Store->getPointerOperand());

        // Create new store to the slot alloca
        IRBuilder<> B(Store);
        Value *NewPtr = NewAlloca;
        Value *Val = Store->getValueOperand();

        // Handle type mismatch
        if (Val->getType() != Info.AccessType) {
          NewPtr = B.CreateBitCast(NewAlloca, Val->getType()->getPointerTo());
        }

        auto *NewStore = B.CreateStore(Val, NewPtr);
        NewStore->setAlignment(Store->getAlign());
        Store->eraseFromParent();

        // Remove GEP if it has no more users
        if (GEP->use_empty())
          GEP->eraseFromParent();

        Changed = true;
      }
    }
  }

  return Changed;
}

} // anonymous namespace

PreservedAnalyses StackSlotSplitter::run(Function &F,
                                          FunctionAnalysisManager &AM) {
  const DataLayout &DL = F.getParent()->getDataLayout();
  bool Changed = false;

  // Collect allocas first to avoid iterator invalidation
  SmallVector<AllocaInst *, 8> Allocas;
  for (auto &I : F.getEntryBlock()) {
    if (auto *AI = dyn_cast<AllocaInst>(&I)) {
      Allocas.push_back(AI);
    }
  }

  for (AllocaInst *AI : Allocas) {
    Changed |= splitByteArrayAlloca(AI, DL);
  }

  if (!Changed)
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}

} // namespace optimization
