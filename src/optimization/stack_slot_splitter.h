#pragma once

#include <llvm/IR/PassManager.h>

namespace optimization {

/// StackSlotSplitter - Splits byte-array allocas into individual typed allocas.
///
/// This pass is designed to enable SSA promotion for lifted code where:
/// - Stack simulation uses a single `[N x i8]` byte array
/// - State variables are stored at constant offsets within this array
/// - SROA cannot split the monolithic array, blocking Mem2Reg promotion
///
/// After splitting, Mem2Reg can promote individual allocas to SSA form,
/// enabling SCCP to propagate constants through control flow flattening.
class StackSlotSplitter : public llvm::PassInfoMixin<StackSlotSplitter> {
public:
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &AM);

  static bool isRequired() { return true; }
};

} // namespace optimization
