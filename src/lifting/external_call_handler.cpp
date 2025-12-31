#include "lifting/external_call_handler.h"

#include <llvm/IR/Attributes.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/ModRef.h>

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
        func->setDoesNotThrow();

        // Mark the function as reading memory through arguments (not writing)
        // This preserves stores that feed into pointer arguments while allowing
        // DCE to eliminate unrelated stores to the same alloca
        func->setMemoryEffects(llvm::MemoryEffects::argMemOnly(llvm::ModRefInfo::Ref));

        // Add attributes to pointer parameters to help alias analysis
        for (size_t i = 0; i < config.arg_types.size(); ++i) {
            if (config.arg_types[i] == "ptr") {
                // nocapture: function doesn't store the pointer
                // readonly: function only reads through the pointer
                // nonnull: pointer is never null
                func->addParamAttr(i, llvm::Attribute::NoCapture);
                func->addParamAttr(i, llvm::Attribute::ReadOnly);
                func->addParamAttr(i, llvm::Attribute::NonNull);
            }
        }

        declarations_[name] = func;

        utils::dbg() << "Created external function declaration: " << name
                     << " with " << param_types.size() << " args\n";
    }
}

llvm::Function* ExternalCallHandler::GetExternalFunction(const std::string& name) const {
    auto it = declarations_.find(name);
    return (it != declarations_.end()) ? it->second : nullptr;
}

const ExternalCallConfig* ExternalCallHandler::GetConfigByIATAddress(uint64_t iat_address) const {
    return registry_.FindByIATAddress(iat_address);
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
        utils::dbg() << "ResolveConstantPointers: pointer resolution disabled\n";
        return 0;
    }

    utils::dbg() << "ResolveConstantPointers: starting on module " << module->getName().str() << "\n";

    size_t resolved_count = 0;
    llvm::LLVMContext& llvm_ctx = module->getContext();

    // Cache of stack allocas per function
    std::map<llvm::Function*, llvm::AllocaInst*> stack_alloca_cache;

    // Iterate all external functions we know about
    for (const auto& [name, config] : registry_.GetAllConfigs()) {
        utils::dbg() << "ResolveConstantPointers: looking for function '" << name << "'\n";
        // Look up the function in this module (may be different from cached declarations)
        auto* func = module->getFunction(name);
        if (!func) {
            utils::dbg() << "  Function not found in module\n";
            continue;
        }
        utils::dbg() << "  Found function with " << func->getNumUses() << " uses\n";

        // Find all calls to this function
        for (auto* user : func->users()) {
            auto* call = llvm::dyn_cast<llvm::CallInst>(user);
            if (!call) continue;

            // Get the parent function for stack alloca lookup
            llvm::Function* parent_func = call->getParent()->getParent();

            // Check each argument
            for (size_t i = 0; i < call->arg_size() && i < config.arg_types.size(); ++i) {
                // Only resolve pointer arguments
                if (config.arg_types[i] != "ptr") continue;

                llvm::Value* arg = call->getArgOperand(i);
                utils::dbg() << "    Arg " << i << " type: ";
                if (auto* inttoptr = llvm::dyn_cast<llvm::IntToPtrInst>(arg)) {
                    utils::dbg() << "IntToPtrInst\n";
                } else if (auto* ce = llvm::dyn_cast<llvm::ConstantExpr>(arg)) {
                    utils::dbg() << "ConstantExpr (opcode " << ce->getOpcode() << ")\n";
                } else {
                    utils::dbg() << arg->getValueID() << "\n";
                }

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

                if (!const_int) {
                    utils::dbg() << "    Not a constant inttoptr, skipping\n";
                    continue;
                }
                utils::dbg() << "    Found constant inttoptr\n";

                uint64_t address = const_int->getZExtValue();
                utils::dbg() << "    Address: " << llvm::format_hex(address, 0) << "\n";

                // First, check if it's a stack address
                auto [is_stack, stack_offset] = FindStackOffset(address);
                utils::dbg() << "    Is stack address: " << (is_stack ? "yes" : "no")
                             << ", offset: " << stack_offset << "\n";
                if (is_stack) {
                    // Find or cache the stack alloca for this function
                    llvm::AllocaInst* stack_alloca = nullptr;
                    auto cache_it = stack_alloca_cache.find(parent_func);
                    if (cache_it != stack_alloca_cache.end()) {
                        stack_alloca = cache_it->second;
                    } else {
                        stack_alloca = FindStackAlloca(parent_func);
                        stack_alloca_cache[parent_func] = stack_alloca;
                        utils::dbg() << "    Stack alloca: "
                                     << (stack_alloca ? "found" : "NOT FOUND") << "\n";
                    }

                    if (stack_alloca) {
                        // Create a GEP to the stack location
                        llvm::IRBuilder<> builder(call);
                        auto* gep = builder.CreateGEP(
                            builder.getInt8Ty(),
                            stack_alloca,
                            builder.getInt64(stack_offset),
                            "stack_ptr"
                        );

                        // Replace the argument with the GEP
                        call->setArgOperand(i, gep);
                        ++resolved_count;

                        utils::dbg() << "Resolved stack pointer " << llvm::format_hex(address, 0)
                                     << " to stack offset " << stack_offset << "\n";
                        continue;
                    }
                }

                // Try to resolve the address to a string global (for .rdata etc)
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

std::pair<bool, uint64_t> ExternalCallHandler::FindStackOffset(uint64_t address) const {
    if (stack_size_ == 0) {
        return {false, 0};
    }

    // Stack range: [stack_top_va - stack_size, stack_top_va)
    uint64_t stack_bottom = stack_top_va_ - stack_size_;
    if (address >= stack_bottom && address < stack_top_va_) {
        // Offset from the bottom of the stack (where alloca starts)
        uint64_t offset = address - stack_bottom;
        return {true, offset};
    }
    return {false, 0};
}

llvm::AllocaInst* ExternalCallHandler::FindStackAlloca(llvm::Function* func) const {
    // Look for alloca named "__stack_local" in the entry block
    // (this is the name used by memory_lowering.cpp)
    auto& entry = func->getEntryBlock();
    for (auto& inst : entry) {
        if (auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
            if (alloca->getName() == "__stack_local") {
                return alloca;
            }
        }
    }
    return nullptr;
}

}  // namespace lifting
