#pragma once

#include <llvm/Support/raw_ostream.h>

namespace utils {

extern bool g_debug;

/// Returns errs() if debug is enabled, otherwise a null stream that discards output.
llvm::raw_ostream &dbg();

}
