#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <remill/Arch/Instruction.h>

#include <llvm/IR/BasicBlock.h>

#include "utils/pe_reader.h"
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>

#include "lifting_context.h"

namespace lifting {

// Information about a decoded instruction
struct DecodedInstruction {
  uint64_t address;
  size_t size;
  remill::Instruction instr;
};

// Configuration for iterative lifting
struct IterativeLiftingConfig {
  int max_iterations = 10;
  bool verbose = false;  // Debug output
  std::string dump_iterations_dir;  // If non-empty, dump IR after each iteration to this directory
};

// State tracking for iterative lifting process
struct IterativeLiftingState {
  // Blocks that have been fully lifted
  std::set<uint64_t> lifted_blocks;

  // Blocks discovered but not yet lifted (worklist)
  std::set<uint64_t> pending_blocks;

  // Indirect jumps that need resolution
  // Maps: block address where indirect jump occurs -> SwitchInst*
  std::map<uint64_t, llvm::SwitchInst *> unresolved_indirect_jumps;

  // Track which iteration discovered each block (for debugging)
  std::map<uint64_t, int> block_discovery_iteration;
};

// Control flow-aware lifter that handles jumps and conditional branches
class ControlFlowLifter {
 public:
  explicit ControlFlowLifter(LiftingContext &ctx);

  // Configure iterative lifting behavior
  void SetIterativeConfig(const IterativeLiftingConfig &config);

  // Set PE info for resolving indirect jumps through global variables
  void SetPEInfo(const utils::PEInfo *pe_info);

  // Get iteration statistics (for debugging)
  const IterativeLiftingState &GetIterationState() const;

  // Decode and analyze control flow, then lift all instructions
  // code_base: start of the code region (for scanning all instructions)
  // entry_point: the function's entry point address
  // Returns true on success
  bool LiftFunction(uint64_t code_base, uint64_t entry_point,
                    const uint8_t *bytes, size_t size,
                    llvm::Function *func);

 private:
  // First pass: decode all instructions and discover basic block boundaries
  bool DiscoverBasicBlocks(uint64_t start_address, const uint8_t *bytes,
                           size_t size);

  // Determine which blocks belong to which native function
  void AssignBlocksToFunctions();

  // Create helper functions for call targets with alwaysinline attribute
  void CreateHelperFunctions(llvm::Function *main_func);

  // Create LLVM basic blocks for each discovered block
  void CreateBasicBlocks(llvm::Function *func);

  // Lift instructions into their respective basic blocks
  bool LiftBlocks(const uint8_t *bytes, size_t size, uint64_t code_base);

  // Finish a basic block with appropriate terminator
  // Returns the SwitchInst for indirect jumps (nullptr otherwise)
  llvm::SwitchInst *FinishBlock(llvm::BasicBlock *block,
                                const DecodedInstruction &last_instr,
                                uint64_t next_addr, uint64_t block_addr);

  // === Iterative Lifting Methods ===

  // BFS-based block discovery from a starting address
  // Only follows direct control flow; marks indirect jumps as unresolved
  void DiscoverBlocksFromEntry(uint64_t start_addr, int iteration);

  // Decode a single block at the given address
  // Returns false if decoding fails or address is invalid
  bool DecodeBlockAt(uint64_t addr);

  // Create LLVM basic blocks for newly discovered addresses
  void CreateBasicBlocksIncremental();

  // Lift only blocks that haven't been lifted yet
  bool LiftPendingBlocks();

  // Check switches for constant selectors and return newly discovered targets
  std::set<uint64_t> ResolveIndirectJumps();

  // Evaluate an LLVM Value assuming program_counter = entry_point_
  // Used to resolve switch selectors before inlining
  std::optional<int64_t> EvaluateWithKnownPC(llvm::Value *val);

  // Helper for evaluating binary operations
  static std::optional<uint64_t> EvaluateBinaryOp(
      llvm::Instruction::BinaryOps opcode, uint64_t lhs, uint64_t rhs);

  // Read a qword from PE section data at the given masked offset
  std::optional<uint64_t> ReadQwordFromPESections(uint64_t masked_offset) const;

  // Check if an address is valid for decoding
  bool IsValidCodeAddress(uint64_t addr) const;

  // Find the end address of a block (next block start or code_end_)
  uint64_t FindBlockEnd(uint64_t block_addr) const;

  // Get the address of the last instruction in a block
  uint64_t GetLastInstrAddr(uint64_t block_start, uint64_t block_end) const;

  // Clear all state for a fresh lift
  void ClearState();

  LiftingContext &ctx_;
  remill::DecodingContext decoding_context_;

  // All decoded instructions indexed by address
  std::map<uint64_t, DecodedInstruction> instructions_;

  // Set of addresses that start a basic block
  std::set<uint64_t> block_starts_;

  // LLVM basic blocks indexed by start address
  std::map<uint64_t, llvm::BasicBlock *> blocks_;

  // Range of valid code addresses
  uint64_t code_start_ = 0;
  uint64_t code_end_ = 0;

  // Entry point address (may differ from code_start_)
  uint64_t entry_point_ = 0;

  // Set of block addresses that are call targets (i.e., helper functions)
  std::set<uint64_t> call_targets_;

  // Helper functions for each call target (marked alwaysinline)
  // Maps call target address -> LLVM function
  std::map<uint64_t, llvm::Function *> helper_functions_;

  // Which native function owns each block address
  // 0 = main function, non-zero = helper function entry address
  std::map<uint64_t, uint64_t> block_owner_;

  // The main function being lifted
  llvm::Function *main_func_ = nullptr;

  // Return address for each call site (used to continue after call)
  std::map<uint64_t, uint64_t> call_return_addrs_;

  // === Iterative Lifting State ===

  // Configuration for iterative lifting
  IterativeLiftingConfig config_;

  // State tracking for iteration
  IterativeLiftingState iter_state_;

  // Raw bytes storage for incremental decoding
  const uint8_t *code_bytes_ = nullptr;
  size_t code_size_ = 0;

  // Track dispatch blocks created for indirect jumps
  std::map<uint64_t, llvm::BasicBlock *> dispatch_blocks_;

  // PE info for reading global variables during indirect jump resolution
  const utils::PEInfo *pe_info_ = nullptr;
};

}  // namespace lifting
