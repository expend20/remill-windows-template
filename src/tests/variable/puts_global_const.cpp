// Test program that calls puts()
// This will be compiled, linked with msvcrt.lib, and lifted
// The external call to puts should be preserved after optimization

#include <stdio.h>

extern "C" int test_proc() {
    puts("Hello");
    return 4919;
}
