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

    // Enable/disable pointer data resolution
    void SetResolvePointerData(bool resolve) { resolve_pointer_data_ = resolve; }

    // Check if pointer resolution is enabled
    bool ShouldResolvePointerData() const { return resolve_pointer_data_ && pe_info_; }

    // Create LLVM function declarations for all registered external calls
    void CreateDeclarations(llvm::Module* module);

    // Get external function declaration by name (nullptr if not found)
    llvm::Function* GetExternalFunction(const std::string& name) const;

    // Check if an IAT address corresponds to an external call
    bool IsExternalCall(uint64_t iat_address) const;

    // Get the config for an external call by IAT address
    const ExternalCallConfig* GetConfigByIATAddress(uint64_t iat_address) const;

    // Get argument count for external function
    size_t GetArgCount(const std::string& name) const;

    // Resolve a pointer address to an LLVM value
    // If the address points to data in a known PE section and resolution is enabled,
    // creates an LLVM global constant and returns a pointer to it.
    // Otherwise returns nullptr (caller should use inttoptr).
    llvm::Value* ResolvePointerArgument(uint64_t address, llvm::IRBuilder<>& builder);

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
};

}  // namespace lifting
