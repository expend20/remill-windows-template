#include "module_utils.h"

#include <iostream>
#include <set>

#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

namespace utils {

namespace {

// Recursively collect all functions and globals referenced by a value
void CollectReferences(llvm::Value *v, std::set<llvm::Function *> &funcs,
                       std::set<llvm::GlobalVariable *> &globals,
                       std::set<llvm::Value *> &visited) {
  if (!v || visited.count(v))
    return;
  visited.insert(v);

  if (auto *f = llvm::dyn_cast<llvm::Function>(v)) {
    if (funcs.insert(f).second) {
      // Collect references from the function body
      for (auto &bb : *f) {
        for (auto &inst : bb) {
          for (auto &op : inst.operands()) {
            CollectReferences(op.get(), funcs, globals, visited);
          }
        }
      }
    }
  } else if (auto *gv = llvm::dyn_cast<llvm::GlobalVariable>(v)) {
    if (globals.insert(gv).second && gv->hasInitializer()) {
      CollectReferences(gv->getInitializer(), funcs, globals, visited);
    }
  } else if (auto *c = llvm::dyn_cast<llvm::Constant>(v)) {
    for (unsigned i = 0; i < c->getNumOperands(); ++i) {
      CollectReferences(c->getOperand(i), funcs, globals, visited);
    }
  }
}

}  // namespace

std::unique_ptr<llvm::Module> ExtractFunctions(
    llvm::Module *source_module,
    const std::vector<std::string> &function_names,
    const std::string &module_name) {
  auto &context = source_module->getContext();
  auto dest_module = std::make_unique<llvm::Module>(module_name, context);
  dest_module->setTargetTriple(source_module->getTargetTriple());
  dest_module->setDataLayout(source_module->getDataLayout());

  // Collect all functions and their transitive dependencies
  std::set<llvm::Function *> funcs_to_copy;
  std::set<llvm::GlobalVariable *> globals_to_copy;
  std::set<llvm::Value *> visited;

  for (const auto &name : function_names) {
    if (auto *f = source_module->getFunction(name)) {
      CollectReferences(f, funcs_to_copy, globals_to_copy, visited);
    }
  }

  // Map from source to destination
  llvm::ValueToValueMapTy vmap;

  // First pass: create declarations for all globals
  for (auto *gv : globals_to_copy) {
    auto *new_gv = new llvm::GlobalVariable(
        *dest_module, gv->getValueType(), gv->isConstant(), gv->getLinkage(),
        nullptr, gv->getName(), nullptr, gv->getThreadLocalMode(),
        gv->getAddressSpace());
    new_gv->copyAttributesFrom(gv);
    vmap[gv] = new_gv;
  }

  // Create declarations for all functions first (for forward references)
  for (auto *f : funcs_to_copy) {
    auto *new_f = llvm::Function::Create(f->getFunctionType(), f->getLinkage(),
                                         f->getName(), dest_module.get());
    new_f->copyAttributesFrom(f);
    vmap[f] = new_f;
  }

  // Second pass: copy global initializers
  for (auto *gv : globals_to_copy) {
    if (gv->hasInitializer()) {
      auto *new_gv = llvm::cast<llvm::GlobalVariable>(vmap[gv]);
      auto *init = llvm::MapValue(gv->getInitializer(), vmap);
      new_gv->setInitializer(llvm::cast<llvm::Constant>(init));
    }
  }

  // Copy function bodies by manually cloning basic blocks and instructions
  for (auto *f : funcs_to_copy) {
    if (f->isDeclaration())
      continue;

    auto *new_f = llvm::cast<llvm::Function>(vmap[f]);

    // Map function arguments
    auto src_arg = f->arg_begin();
    auto dst_arg = new_f->arg_begin();
    for (; src_arg != f->arg_end(); ++src_arg, ++dst_arg) {
      dst_arg->setName(src_arg->getName());
      vmap[&*src_arg] = &*dst_arg;
    }

    // Create all basic blocks first (for forward branch references)
    for (auto &bb : *f) {
      auto *new_bb = llvm::BasicBlock::Create(context, bb.getName(), new_f);
      vmap[&bb] = new_bb;
    }

    // Clone instructions
    for (auto &bb : *f) {
      auto *new_bb = llvm::cast<llvm::BasicBlock>(vmap[&bb]);
      for (auto &inst : bb) {
        auto *new_inst = inst.clone();
        new_inst->insertInto(new_bb, new_bb->end());
        vmap[&inst] = new_inst;
        new_inst->setName(inst.getName());
      }
    }

    // Remap operands in all instructions
    for (auto &bb : *new_f) {
      for (auto &inst : bb) {
        llvm::RemapInstruction(&inst, vmap,
                               llvm::RF_NoModuleLevelChanges |
                                   llvm::RF_IgnoreMissingLocals);
      }
    }
  }

  return dest_module;
}

std::unique_ptr<llvm::Module> CreateCleanModule(
    llvm::LLVMContext &context, llvm::Function *source_func,
    const std::string &module_name, const std::string &target_triple,
    const llvm::DataLayout &data_layout) {
  auto clean_module = std::make_unique<llvm::Module>(module_name, context);
  clean_module->setTargetTriple(target_triple);
  clean_module->setDataLayout(data_layout);

  // Create the function with the same signature
  auto *func_type = source_func->getFunctionType();
  auto *clean_func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, source_func->getName(),
      clean_module.get());
  clean_func->setCallingConv(source_func->getCallingConv());

  // Create entry block
  auto *entry = llvm::BasicBlock::Create(context, "entry", clean_func);
  llvm::IRBuilder<> builder(entry);

  // Find the return instruction and extract the constant value
  llvm::ConstantInt *return_value = nullptr;
  for (auto &BB : *source_func) {
    for (auto &I : BB) {
      if (auto *ret = llvm::dyn_cast<llvm::ReturnInst>(&I)) {
        if (auto *val = ret->getReturnValue()) {
          return_value = llvm::dyn_cast<llvm::ConstantInt>(val);
        }
        break;
      }
    }
    if (return_value)
      break;
  }

  if (return_value) {
    builder.CreateRet(
        llvm::ConstantInt::get(func_type->getReturnType(), return_value->getValue()));
  } else {
    // Return 0 as fallback - for non-constant cases, the caller should
    // use the extracted module directly instead of CreateCleanModule
    builder.CreateRet(llvm::ConstantInt::get(func_type->getReturnType(), 0));
  }

  return clean_module;
}

bool WriteModule(llvm::Module *module, const std::string &base_name) {
  return WriteLLFile(module, base_name + ".ll") &&
         WriteBCFile(module, base_name + ".bc");
}

bool WriteLLFile(llvm::Module *module, const std::string &filename) {
  std::error_code EC;
  llvm::raw_fd_ostream file(filename, EC);
  if (EC) {
    std::cerr << "Failed to open " << filename << ": " << EC.message() << "\n";
    return false;
  }
  module->print(file, nullptr);
  file.close();
  std::cout << "Written: " << filename << "\n";
  return true;
}

bool WriteBCFile(llvm::Module *module, const std::string &filename) {
  std::error_code EC;
  llvm::raw_fd_ostream file(filename, EC);
  if (EC) {
    std::cerr << "Failed to open " << filename << ": " << EC.message() << "\n";
    return false;
  }
  llvm::WriteBitcodeToFile(*module, file);
  file.close();
  std::cout << "Written: " << filename << "\n";
  return true;
}

}  // namespace utils
