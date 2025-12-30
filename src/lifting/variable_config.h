#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <llvm/Support/JSON.h>

#include "utils/pe_reader.h"

namespace lifting {

// Configuration for a single external function call
struct ExternalCallConfig {
    std::string name;
    std::vector<std::string> arg_types;  // "ptr", "i32", "i64"
    // Note: return type defaults to i64 (Win64 always returns in RAX)
};

// Registry that maps function names and IAT addresses to external call configs
class ExternalCallRegistry {
public:
    ExternalCallRegistry() = default;

    // Parse external_calls array from JSON config
    bool RegisterFromJSON(const llvm::json::Object& config);

    // Link registered configs with PE imports to populate IAT address mappings
    void LinkWithImports(const std::vector<utils::ImportEntry>& imports);

    // Find external call config by function name
    const ExternalCallConfig* FindByName(const std::string& name) const;

    // Find external call config by IAT virtual address
    const ExternalCallConfig* FindByIATAddress(uint64_t va) const;

    // Get all registered configs
    const std::map<std::string, ExternalCallConfig>& GetAllConfigs() const {
        return by_name_;
    }

    // Check if any external calls are configured
    bool HasExternalCalls() const { return !by_name_.empty(); }

private:
    std::map<std::string, ExternalCallConfig> by_name_;
    std::map<uint64_t, const ExternalCallConfig*> by_iat_address_;
};

// Main configuration structure for variable lifting tests
// Supports both variable register inputs and external function calls
struct VariableConfig {
    std::vector<std::string> input_registers;  // e.g., ["rcx", "rdx"]
    std::string return_register = "rax";
    ExternalCallRegistry external_calls;

    // When true, pointer arguments to external calls are resolved:
    // - If the pointer points to data in a known PE section, the data is
    //   copied into an LLVM global constant and the pointer is replaced
    //   with a reference to that global.
    // - For string pointers, reads until null terminator.
    bool resolve_pointer_data = false;

    // Check if this config has variable inputs
    bool HasVariableInputs() const { return !input_registers.empty(); }
};

// Parse configuration from a JSON file
// Returns nullopt on parse error
std::optional<VariableConfig> ParseVariableConfig(const std::string& config_path);

}  // namespace lifting
