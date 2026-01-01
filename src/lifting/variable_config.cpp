#include "lifting/variable_config.h"

#include <iostream>

#include <llvm/Support/MemoryBuffer.h>

namespace lifting {

bool ExternalCallRegistry::RegisterFromJSON(const llvm::json::Object& config) {
    auto* external_calls = config.getArray("external_calls");
    if (!external_calls) {
        // No external_calls array - that's fine, just means no external calls
        return true;
    }

    for (const auto& call_value : *external_calls) {
        auto* call_obj = call_value.getAsObject();
        if (!call_obj) {
            std::cerr << "Invalid external_call entry (not an object)\n";
            return false;
        }

        ExternalCallConfig cfg;

        // Parse name (required)
        auto name = call_obj->getString("name");
        if (!name) {
            std::cerr << "External call missing 'name' field\n";
            return false;
        }
        cfg.name = name->str();

        // Parse args (required)
        auto* args = call_obj->getArray("args");
        if (!args) {
            std::cerr << "External call '" << cfg.name << "' missing 'args' field\n";
            return false;
        }

        for (const auto& arg : *args) {
            auto arg_str = arg.getAsString();
            if (!arg_str) {
                std::cerr << "External call '" << cfg.name << "' has invalid arg type\n";
                return false;
            }
            cfg.arg_types.push_back(arg_str->str());
        }

        by_name_[cfg.name] = std::move(cfg);
    }

    return true;
}

void ExternalCallRegistry::LinkWithImports(const std::vector<utils::ImportEntry>& imports) {
    for (const auto& import : imports) {
        if (import.is_ordinal) {
            continue;  // Skip ordinal imports for now
        }

        auto it = by_name_.find(import.function_name);
        if (it != by_name_.end()) {
            by_iat_address_[import.iat_va] = &it->second;
        }
    }
}

const ExternalCallConfig* ExternalCallRegistry::FindByName(const std::string& name) const {
    auto it = by_name_.find(name);
    return (it != by_name_.end()) ? &it->second : nullptr;
}

const ExternalCallConfig* ExternalCallRegistry::FindByIATAddress(uint64_t va) const {
    auto it = by_iat_address_.find(va);
    return (it != by_iat_address_.end()) ? it->second : nullptr;
}

std::optional<VariableConfig> ParseVariableConfig(const std::string& config_path) {
    auto buffer = llvm::MemoryBuffer::getFile(config_path);
    if (!buffer) {
        std::cerr << "Failed to read config file: " << config_path << "\n";
        return std::nullopt;
    }

    auto json = llvm::json::parse(buffer.get()->getBuffer());
    if (!json) {
        std::cerr << "Failed to parse JSON: " << llvm::toString(json.takeError()) << "\n";
        return std::nullopt;
    }

    auto* root = json->getAsObject();
    if (!root) {
        std::cerr << "Config must be a JSON object\n";
        return std::nullopt;
    }

    VariableConfig config;

    // Parse "variables": ["rcx", "rdx", ...]
    if (auto* vars = root->getArray("variables")) {
        for (const auto& var : *vars) {
            if (auto str = var.getAsString()) {
                config.input_registers.push_back(str->str());
            }
        }
    }

    // Parse "return_register": "rax"
    if (auto ret = root->getString("return_register")) {
        config.return_register = ret->str();
    }

    // Parse "external_calls" array (optional)
    if (!config.external_calls.RegisterFromJSON(*root)) {
        return std::nullopt;
    }

    // Parse "global_mode": "constant" | "lifted" | "original_va"
    if (auto mode = root->getString("global_mode")) {
        std::string mode_str = mode->str();
        if (mode_str == "constant") {
            config.global_mode = GlobalMode::Constant;
        } else if (mode_str == "lifted") {
            config.global_mode = GlobalMode::Lifted;
        } else if (mode_str == "original_va") {
            config.global_mode = GlobalMode::OriginalVA;
        } else {
            std::cerr << "Unknown global_mode: " << mode_str << "\n";
            std::cerr << "Valid values: constant, lifted, original_va\n";
            return std::nullopt;
        }
    }

    return config;
}

}  // namespace lifting
