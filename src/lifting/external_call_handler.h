#pragma once

#include <map>
#include <string>
#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>

#include "lifting/variable_config.h"
#include "lifting/lifting_context.h"
#include "utils/pe_reader.h"

namespace lifting {

// Handles creation and retrieval of LLVM declarations for external calls
class ExternalCallHandler {
public:
    ExternalCallHandler(LiftingContext& ctx, const ExternalCallRegistry& registry);

    // Set PE info for pointer resolution (call before CreateDeclarations)
    void SetPEInfo(const utils::PEInfo* pe_info) { pe_info_ = pe_info; }

    // Set stack info for stack pointer resolution
    void SetStackInfo(uint64_t stack_top_va, uint64_t stack_size) {
        stack_top_va_ = stack_top_va;
        stack_size_ = stack_size;
    }

    // Enable/disable pointer data resolution
    void SetResolvePointerData(bool resolve) { resolve_pointer_data_ = resolve; }

    // Check if pointer resolution is enabled
    bool ShouldResolvePointerData() const { return resolve_pointer_data_ && pe_info_; }

    // Create LLVM function declarations for all registered external calls
    void CreateDeclarations(llvm::Module* module);

    // Get external function declaration by name (nullptr if not found)
    llvm::Function* GetExternalFunction(const std::string& name) const;

    // Get the config for an external call by IAT address
    const ExternalCallConfig* GetConfigByIATAddress(uint64_t iat_address) const;

    // Post-optimization pass: resolve inttoptr constants in external call arguments
    // to LLVM globals. This should be called after SCCP has propagated constant values.
    // Returns the number of resolved pointers.
    size_t ResolveConstantPointers(llvm::Module* module);

private:
    const ExternalCallRegistry& registry_;
    std::map<std::string, llvm::Function*> declarations_;

    // PE info for pointer resolution
    const utils::PEInfo* pe_info_ = nullptr;
    bool resolve_pointer_data_ = false;

    // Stack info for stack pointer resolution
    uint64_t stack_top_va_ = 0;
    uint64_t stack_size_ = 0;

    // Cache of resolved pointer globals (address -> global)
    std::map<uint64_t, llvm::GlobalVariable*> resolved_globals_;

    // Parse type string to LLVM type
    llvm::Type* ParseType(const std::string& type_str, llvm::LLVMContext& ctx);

    // Get Win64 calling convention
    llvm::CallingConv::ID GetCallingConv() const;

    // Read a null-terminated string from PE section at given address
    // Returns empty string if address is not in any section
    std::string ReadStringFromPE(uint64_t address) const;

    // Find section containing the given address
    const utils::SectionInfo* FindSectionForAddress(uint64_t address) const;

    // Check if address is in stack range and return offset from stack base
    // Returns {true, offset} if in range, {false, 0} otherwise
    std::pair<bool, uint64_t> FindStackOffset(uint64_t address) const;

    // Find the stack alloca in a function (looks for alloca named "stack")
    llvm::AllocaInst* FindStackAlloca(llvm::Function* func) const;
};

}  // namespace lifting
