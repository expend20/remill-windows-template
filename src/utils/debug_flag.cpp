#include "debug_flag.h"

namespace utils {

bool g_debug = false;

llvm::raw_ostream &dbg() {
  if (g_debug) {
    return llvm::errs();
  }
  return llvm::nulls();
}

}
