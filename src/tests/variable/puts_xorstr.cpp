// Test program that calls puts() with xorstr-encrypted string
// String is XOR-encrypted at compile time and decrypted at runtime
// Tests how the lifter handles obfuscated string arguments

#include <stdio.h>
#include "xorstr.hpp"

extern "C" int test_proc() {
    puts(xorstr_("Hello world!"));
    return 4919;
}
