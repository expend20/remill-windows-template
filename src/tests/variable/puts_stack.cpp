// Test program that calls puts() with stack-allocated string
// String is initialized character by character on the stack
// Tests how the lifter handles stack-based string arguments

#include <stdio.h>

extern "C" int test_proc() {
    char str[6];
    str[0] = 'H';
    str[1] = 'e';
    str[2] = 'l';
    str[3] = 'l';
    str[4] = 'o';
    str[5] = '\0';
    puts(str);
    return 4919;
}
