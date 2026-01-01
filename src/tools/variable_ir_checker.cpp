// IR Checker Tool
// Verifies that optimized IR meets cleanliness requirements.
//
// Usage:
//   variable_ir_checker <bitcode_file> <config.json>   - Config-based verification
//   variable_ir_checker <bitcode_file> <expected_int>  - Strict mode (1 BB, 1 ret instruction)
//
// Config "verify" section options:
// - "max_instructions": N (fail if instruction count exceeds N)
// - "required_calls": ["puts", ...] (fail if call not present)
// - "required_immediates": [72, 101, ...] (fail if constant not found)
// - "required_string": "Hello" (auto-converts to required_immediates)
// - "required_globals": ["__section_.data", ...] (fail if global not present)
// - "require_inttoptr": true (fail if no inttoptr instruction found)
// - "forbid_globals": true (fail if any global variables exist)
//
// If config has no "verify" section, defaults to strict mode.

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/JSON.h>

#include <cstdlib>
#include <string>
#include <vector>
#include <set>

struct VerifyConfig {
    bool strict_mode = false;           // Strict mode: 1 BB, 1 instruction (ret)
    int expected_return_value = 0;      // For strict mode
    int max_instructions = -1;          // -1 means no limit
    std::vector<std::string> required_calls;
    std::set<int64_t> required_immediates;
    std::vector<std::string> required_globals;
    bool require_inttoptr = false;      // Require at least one inttoptr instruction
    bool forbid_globals = false;        // Forbid any global variables (except external decls)
};

// Check if string is a valid integer
bool isInteger(const std::string& s) {
    if (s.empty()) return false;
    size_t start = (s[0] == '-') ? 1 : 0;
    if (start == s.size()) return false;
    for (size_t i = start; i < s.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) return false;
    }
    return true;
}

bool parseVerifyConfig(const std::string& config_path, VerifyConfig& verify) {
    auto buffer = llvm::MemoryBuffer::getFile(config_path);
    if (!buffer) {
        llvm::errs() << "Failed to read config file: " << config_path << "\n";
        return false;
    }

    auto json = llvm::json::parse(buffer.get()->getBuffer());
    if (!json) {
        llvm::errs() << "Failed to parse JSON: " << llvm::toString(json.takeError()) << "\n";
        return false;
    }

    auto* root = json->getAsObject();
    if (!root) {
        llvm::errs() << "Config must be a JSON object\n";
        return false;
    }

    // Look for "verify" section
    auto* verify_obj = root->getObject("verify");
    if (!verify_obj) {
        // No verify section - use strict mode (1 BB, 1 instruction)
        verify.strict_mode = true;
        return true;
    }

    // Parse max_instructions
    if (auto max_instr = verify_obj->getInteger("max_instructions")) {
        verify.max_instructions = static_cast<int>(*max_instr);
    }

    // Parse required_calls
    if (auto* calls = verify_obj->getArray("required_calls")) {
        for (const auto& call : *calls) {
            if (auto str = call.getAsString()) {
                verify.required_calls.push_back(str->str());
            }
        }
    }

    // Parse required_string (auto-converts to required_immediates)
    if (auto str = verify_obj->getString("required_string")) {
        for (char c : str->str()) {
            verify.required_immediates.insert(static_cast<int64_t>(static_cast<unsigned char>(c)));
        }
    }

    // Parse required_immediates (integers)
    if (auto* imms = verify_obj->getArray("required_immediates")) {
        for (const auto& imm : *imms) {
            if (auto val = imm.getAsInteger()) {
                verify.required_immediates.insert(*val);
            }
        }
    }

    // Parse required_globals (global variable names)
    if (auto* globals = verify_obj->getArray("required_globals")) {
        for (const auto& g : *globals) {
            if (auto str = g.getAsString()) {
                verify.required_globals.push_back(str->str());
            }
        }
    }

    // Parse require_inttoptr
    if (auto val = verify_obj->getBoolean("require_inttoptr")) {
        verify.require_inttoptr = *val;
    }

    // Parse forbid_globals
    if (auto val = verify_obj->getBoolean("forbid_globals")) {
        verify.forbid_globals = *val;
    }

    return true;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        llvm::errs() << "Usage: " << argv[0] << " <bitcode_file> <config.json|expected_int>\n";
        return 1;
    }

    const char *bc_filename = argv[1];
    const std::string second_arg = argv[2];

    // Parse config - detect if it's a JSON file or an integer
    VerifyConfig verify;
    if (isInteger(second_arg)) {
        // Strict mode: expect exactly 1 BB, 1 instruction (ret <value>)
        verify.strict_mode = true;
        verify.expected_return_value = std::atoi(second_arg.c_str());
    } else {
        // Config file mode
        if (!parseVerifyConfig(second_arg, verify)) {
            return 1;
        }
    }

    // Check if there's anything to verify
    if (!verify.strict_mode &&
        verify.max_instructions < 0 &&
        verify.required_calls.empty() &&
        verify.required_immediates.empty() &&
        verify.required_globals.empty() &&
        !verify.require_inttoptr &&
        !verify.forbid_globals) {
        llvm::outs() << "No verification rules in config, skipping checks\n";
        return 0;
    }

    // Load the module
    llvm::LLVMContext context;
    llvm::SMDiagnostic error;

    auto module = llvm::parseIRFile(bc_filename, error, context);
    if (!module) {
        llvm::errs() << "Error: Failed to load " << bc_filename << "\n";
        error.print(argv[0], llvm::errs());
        return 1;
    }

    // Find the @test function
    llvm::Function *test_func = module->getFunction("test");
    if (!test_func) {
        llvm::errs() << "Error: No @test function found in " << bc_filename << "\n";
        return 1;
    }

    if (test_func->isDeclaration()) {
        llvm::errs() << "Error: @test function is a declaration, not a definition\n";
        return 1;
    }

    // Collect statistics
    int instruction_count = 0;
    std::set<std::string> found_calls;
    std::set<int64_t> found_immediates;
    llvm::ReturnInst *ret_inst = nullptr;
    bool found_inttoptr = false;

    // Also scan global variables for string constants
    for (auto &gv : module->globals()) {
        if (gv.hasInitializer()) {
            if (auto *cda = llvm::dyn_cast<llvm::ConstantDataArray>(gv.getInitializer())) {
                if (cda->isString()) {
                    // Extract bytes from string constant
                    for (unsigned i = 0; i < cda->getNumElements(); ++i) {
                        int64_t byte_val = cda->getElementAsInteger(i);
                        if (byte_val != 0) {
                            found_immediates.insert(byte_val);
                        }
                    }
                }
            }
        }
    }

    for (auto &bb : *test_func) {
        for (auto &inst : bb) {
            // Skip debug intrinsics
            if (llvm::isa<llvm::DbgInfoIntrinsic>(&inst)) {
                continue;
            }

            instruction_count++;

            // Track return instruction
            if (auto *ret = llvm::dyn_cast<llvm::ReturnInst>(&inst)) {
                ret_inst = ret;
            }

            // Track call instructions
            if (auto *call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                if (auto *callee = call->getCalledFunction()) {
                    found_calls.insert(callee->getName().str());
                }
            }

            // Track constant integers in operands (including inttoptr constants)
            for (auto &op : inst.operands()) {
                if (auto *const_int = llvm::dyn_cast<llvm::ConstantInt>(op.get())) {
                    int64_t val = const_int->getSExtValue();
                    found_immediates.insert(val);

                    // Also extract individual bytes from the constant
                    // This handles packed string constants (e.g., "Hello" as i64)
                    uint64_t uval = static_cast<uint64_t>(val);
                    unsigned bit_width = const_int->getBitWidth();
                    for (unsigned i = 0; i < bit_width / 8; ++i) {
                        int64_t byte_val = (uval >> (i * 8)) & 0xFF;
                        if (byte_val != 0) {  // Skip null bytes
                            found_immediates.insert(byte_val);
                        }
                    }
                }

                // Check for inttoptr constant expressions in operands
                if (auto *ce = llvm::dyn_cast<llvm::ConstantExpr>(op.get())) {
                    if (ce->getOpcode() == llvm::Instruction::IntToPtr) {
                        found_inttoptr = true;
                    }
                }
            }
        }
    }

    bool success = true;

    // Strict mode checks (for constant-folding tests)
    if (verify.strict_mode) {
        // Check: exactly 1 basic block
        if (test_func->size() != 1) {
            llvm::errs() << "FAIL: Expected 1 basic block, found " << test_func->size() << "\n";
            llvm::errs() << "Function body:\n";
            test_func->print(llvm::errs());
            return 1;
        }

        // Check: exactly 1 instruction
        if (instruction_count != 1) {
            llvm::errs() << "FAIL: Expected 1 instruction (ret i32 " << verify.expected_return_value
                         << "), found " << instruction_count << " instructions\n";
            llvm::errs() << "Function body:\n";
            test_func->print(llvm::errs());
            return 1;
        }

        // Check: must be a return instruction
        if (!ret_inst) {
            llvm::errs() << "FAIL: No return instruction found\n";
            llvm::errs() << "Function body:\n";
            test_func->print(llvm::errs());
            return 1;
        }

        // Check: return value must be constant integer matching expected
        llvm::Value *ret_val = ret_inst->getReturnValue();
        if (!ret_val) {
            llvm::errs() << "FAIL: Return instruction has no value (void return)\n";
            return 1;
        }

        auto *const_int = llvm::dyn_cast<llvm::ConstantInt>(ret_val);
        if (!const_int) {
            llvm::errs() << "FAIL: Return value is not a constant integer\n";
            llvm::errs() << "Return instruction: ";
            ret_inst->print(llvm::errs());
            llvm::errs() << "\n";
            return 1;
        }

        int actual_value = static_cast<int>(const_int->getSExtValue());
        if (actual_value != verify.expected_return_value) {
            llvm::errs() << "FAIL: Expected return value " << verify.expected_return_value
                         << ", got " << actual_value << "\n";
            return 1;
        }

        llvm::outs() << "SUCCESS: Optimized IR contains only 'ret i32 "
                     << verify.expected_return_value << "'\n";
        return 0;
    }

    // Check 1: Max instruction count
    if (verify.max_instructions >= 0 && instruction_count > verify.max_instructions) {
        llvm::errs() << "FAIL: Instruction count " << instruction_count
                     << " exceeds max " << verify.max_instructions << "\n";
        llvm::errs() << "Function body:\n";
        test_func->print(llvm::errs());
        success = false;
    }

    // Check 2: Required calls
    for (const auto& required_call : verify.required_calls) {
        if (found_calls.find(required_call) == found_calls.end()) {
            llvm::errs() << "FAIL: Required call '@" << required_call << "' not found\n";
            llvm::errs() << "Found calls: ";
            for (const auto& c : found_calls) {
                llvm::errs() << "@" << c << " ";
            }
            llvm::errs() << "\n";
            success = false;
        }
    }

    // Check 3: Required immediates
    for (int64_t required_imm : verify.required_immediates) {
        if (found_immediates.find(required_imm) == found_immediates.end()) {
            llvm::errs() << "FAIL: Required immediate " << required_imm;
            if (required_imm >= 32 && required_imm <= 126) {
                llvm::errs() << " ('" << static_cast<char>(required_imm) << "')";
            }
            llvm::errs() << " not found\n";
            success = false;
        }
    }

    // Check 4: Required globals
    for (const auto& required_global : verify.required_globals) {
        auto *gv = module->getGlobalVariable(required_global);
        if (!gv) {
            llvm::errs() << "FAIL: Required global '@" << required_global << "' not found\n";
            success = false;
        }
    }

    // Check 5: Require inttoptr
    if (verify.require_inttoptr && !found_inttoptr) {
        llvm::errs() << "FAIL: Required inttoptr instruction not found\n";
        llvm::errs() << "Function body:\n";
        test_func->print(llvm::errs());
        success = false;
    }

    // Check 6: Forbid globals
    if (verify.forbid_globals) {
        for (auto &gv : module->globals()) {
            // Skip external declarations (like function declarations)
            if (!gv.hasInitializer()) {
                continue;
            }
            llvm::errs() << "FAIL: Global variable '@" << gv.getName().str()
                         << "' found but globals are forbidden\n";
            success = false;
        }
    }

    if (success) {
        llvm::outs() << "SUCCESS: All verification checks passed\n";
        if (verify.max_instructions >= 0) {
            llvm::outs() << "  - Instructions: " << instruction_count
                         << " (max: " << verify.max_instructions << ")\n";
        }
        if (!verify.required_calls.empty()) {
            llvm::outs() << "  - Required calls: all found\n";
        }
        if (!verify.required_immediates.empty()) {
            llvm::outs() << "  - Required immediates: all found\n";
        }
        if (!verify.required_globals.empty()) {
            llvm::outs() << "  - Required globals: all found\n";
        }
        if (verify.require_inttoptr) {
            llvm::outs() << "  - Required inttoptr: found\n";
        }
        if (verify.forbid_globals) {
            llvm::outs() << "  - No globals: verified\n";
        }
        return 0;
    }

    return 1;
}
