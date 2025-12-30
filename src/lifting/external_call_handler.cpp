#include "lifting/external_call_handler.h"

#include <llvm/IR/Attributes.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/Support/FormatVariadic.h>

#include "utils/debug_flag.h"

namespace lifting {

ExternalCallHandler::ExternalCallHandler(LiftingContext& /* ctx */,
                                         const ExternalCallRegistry& registry)
    : registry_(registry) {}

llvm::Type* ExternalCallHandler::ParseType(const std::string& type_str,
                                            llvm::LLVMContext& ctx) {
    if (type_str == "ptr") {
        return llvm::PointerType::get(ctx, 0);
    } else if (type_str == "i8") {
        return llvm::Type::getInt8Ty(ctx);
    } else if (type_str == "i16") {
        return llvm::Type::getInt16Ty(ctx);
    } else if (type_str == "i32") {
        return llvm::Type::getInt32Ty(ctx);
    } else if (type_str == "i64") {
        return llvm::Type::getInt64Ty(ctx);
    } else if (type_str == "void") {
        return llvm::Type::getVoidTy(ctx);
    } else {
        // Default to i64 for unknown types
        return llvm::Type::getInt64Ty(ctx);
    }
}

llvm::CallingConv::ID ExternalCallHandler::GetCallingConv() const {
    // Win64 calling convention
    return llvm::CallingConv::Win64;
}

void ExternalCallHandler::CreateDeclarations(llvm::Module* module) {
    llvm::LLVMContext& llvm_ctx = module->getContext();

    for (const auto& [name, config] : registry_.GetAllConfigs()) {
        // Build parameter types
        std::vector<llvm::Type*> param_types;
        for (const auto& arg_type : config.arg_types) {
            param_types.push_back(ParseType(arg_type, llvm_ctx));
        }

        // Return type is always i64 for Win64 (RAX)
        llvm::Type* ret_type = llvm::Type::getInt64Ty(llvm_ctx);

        // Create function type
        auto* func_type = llvm::FunctionType::get(ret_type, param_types, false);

        // Check if function already exists
        auto* existing = module->getFunction(name);
        if (existing) {
            declarations_[name] = existing;
            continue;
        }

        // Create function declaration with external linkage
        auto* func = llvm::Function::Create(
            func_type,
            llvm::GlobalValue::ExternalLinkage,
            name,
            module
        );

        // Set calling convention
        func->setCallingConv(GetCallingConv());

        // Add attributes to prevent optimization from eliminating the call
        // NoBuiltin: prevents LLVM from treating it as a builtin (e.g., printf -> puts)
        func->addFnAttr(llvm::Attribute::NoBuiltin);

        // The function may read/write memory through its pointer arguments
        // This prevents dead store elimination before the call
        func->setDoesNotThrow();

        declarations_[name] = func;

        utils::dbg() << "Created external function declaration: " << name
                     << " with " << param_types.size() << " args\n";
    }
}

llvm::Function* ExternalCallHandler::GetExternalFunction(const std::string& name) const {
    auto it = declarations_.find(name);
    return (it != declarations_.end()) ? it->second : nullptr;
}

bool ExternalCallHandler::IsExternalCall(uint64_t iat_address) const {
    return registry_.FindByIATAddress(iat_address) != nullptr;
}

const ExternalCallConfig* ExternalCallHandler::GetConfigByIATAddress(uint64_t iat_address) const {
    return registry_.FindByIATAddress(iat_address);
}

size_t ExternalCallHandler::GetArgCount(const std::string& name) const {
    auto* config = registry_.FindByName(name);
    return config ? config->arg_types.size() : 0;
}

const utils::SectionInfo* ExternalCallHandler::FindSectionForAddress(uint64_t address) const {
    if (!pe_info_) return nullptr;

    for (const auto& section : pe_info_->sections) {
        uint64_t section_start = pe_info_->image_base + section.virtual_address;
        uint64_t section_end = section_start + section.bytes.size();
        if (address >= section_start && address < section_end) {
            return &section;
        }
    }
    return nullptr;
}

std::string ExternalCallHandler::ReadStringFromPE(uint64_t address) const {
    const auto* section = FindSectionForAddress(address);
    if (!section) return "";

    uint64_t section_start = pe_info_->image_base + section->virtual_address;
    uint64_t offset = address - section_start;

    std::string result;
    while (offset < section->bytes.size()) {
        char c = static_cast<char>(section->bytes[offset]);
        if (c == '\0') break;
        result += c;
        ++offset;
    }
    return result;
}

size_t ExternalCallHandler::ResolveConstantPointers(llvm::Module* module) {
    if (!ShouldResolvePointerData()) {
        return 0;
    }

    size_t resolved_count = 0;
    llvm::LLVMContext& llvm_ctx = module->getContext();

    // Iterate all external functions we know about
    for (const auto& [name, config] : registry_.GetAllConfigs()) {
        // Look up the function in this module (may be different from cached declarations)
        auto* func = module->getFunction(name);
        if (!func) continue;

        // Find all calls to this function
        for (auto* user : func->users()) {
            auto* call = llvm::dyn_cast<llvm::CallInst>(user);
            if (!call) continue;

            // Check each argument
            for (size_t i = 0; i < call->arg_size() && i < config.arg_types.size(); ++i) {
                // Only resolve pointer arguments
                if (config.arg_types[i] != "ptr") continue;

                llvm::Value* arg = call->getArgOperand(i);

                // Check if it's an inttoptr of a constant
                auto* inttoptr = llvm::dyn_cast<llvm::IntToPtrInst>(arg);
                llvm::ConstantInt* const_int = nullptr;

                if (inttoptr) {
                    const_int = llvm::dyn_cast<llvm::ConstantInt>(inttoptr->getOperand(0));
                } else if (auto* const_expr = llvm::dyn_cast<llvm::ConstantExpr>(arg)) {
                    if (const_expr->getOpcode() == llvm::Instruction::IntToPtr) {
                        const_int = llvm::dyn_cast<llvm::ConstantInt>(const_expr->getOperand(0));
                    }
                }

                if (!const_int) continue;

                uint64_t address = const_int->getZExtValue();

                // Try to resolve the address to a string global
                const auto* section = FindSectionForAddress(address);
                if (!section) continue;

                std::string str_data = ReadStringFromPE(address);
                if (str_data.empty()) continue;

                // Check if we already have a global for this address
                llvm::GlobalVariable* global = nullptr;
                auto it = resolved_globals_.find(address);
                if (it != resolved_globals_.end()) {
                    global = it->second;
                } else {
                    // Create string constant
                    auto* str_constant = llvm::ConstantDataArray::getString(llvm_ctx, str_data, true);

                    // Generate unique name
                    std::string global_name = llvm::formatv(".str_{0:x}", address);

                    // Create global variable
                    global = new llvm::GlobalVariable(
                        *module,
                        str_constant->getType(),
                        true,  // isConstant
                        llvm::GlobalValue::PrivateLinkage,
                        str_constant,
                        global_name
                    );
                    global->setAlignment(llvm::Align(1));
                    resolved_globals_[address] = global;

                    utils::dbg() << "Resolved pointer " << llvm::format_hex(address, 0)
                                 << " to string \"" << str_data << "\" -> @" << global_name << "\n";
                }

                // Replace the argument with the global
                call->setArgOperand(i, global);
                ++resolved_count;
            }
        }
    }

    // Clean up dead inttoptr instructions
    for (auto& F : *module) {
        std::vector<llvm::Instruction*> to_erase;
        for (auto& BB : F) {
            for (auto& I : BB) {
                if (auto* inttoptr = llvm::dyn_cast<llvm::IntToPtrInst>(&I)) {
                    if (inttoptr->use_empty()) {
                        to_erase.push_back(inttoptr);
                    }
                }
            }
        }
        for (auto* I : to_erase) {
            I->eraseFromParent();
        }
    }

    return resolved_count;
}

llvm::Value* ExternalCallHandler::ResolvePointerArgument(uint64_t address,
                                                          llvm::IRBuilder<>& builder) {
    // Check if resolution is enabled
    if (!ShouldResolvePointerData()) {
        return nullptr;
    }

    // Check if we already have a global for this address
    auto it = resolved_globals_.find(address);
    if (it != resolved_globals_.end()) {
        return it->second;
    }

    // Find section containing this address
    const auto* section = FindSectionForAddress(address);
    if (!section) {
        utils::dbg() << "Address " << llvm::format_hex(address, 0)
                     << " not in any PE section\n";
        return nullptr;
    }

    // Read string data from PE
    std::string str_data = ReadStringFromPE(address);
    if (str_data.empty()) {
        utils::dbg() << "No string data at address " << llvm::format_hex(address, 0) << "\n";
        return nullptr;
    }

    // Create LLVM global constant for the string
    llvm::Module* module = builder.GetInsertBlock()->getParent()->getParent();
    llvm::LLVMContext& llvm_ctx = module->getContext();

    // Create string constant (including null terminator)
    auto* str_constant = llvm::ConstantDataArray::getString(llvm_ctx, str_data, true);

    // Generate unique name for the global
    std::string global_name = llvm::formatv(".str_{0:x}", address);

    // Create global variable
    auto* global = new llvm::GlobalVariable(
        *module,
        str_constant->getType(),
        true,  // isConstant
        llvm::GlobalValue::PrivateLinkage,
        str_constant,
        global_name
    );

    // Set alignment
    global->setAlignment(llvm::Align(1));

    // Cache the global
    resolved_globals_[address] = global;

    utils::dbg() << "Resolved pointer " << llvm::format_hex(address, 0)
                 << " to string \"" << str_data << "\" -> @" << global_name << "\n";

    return global;
}

}  // namespace lifting
