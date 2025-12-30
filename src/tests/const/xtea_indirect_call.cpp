#include <stdint.h>

// Static functions with internal linkage - IndirectCall pass will convert
// direct calls to these functions into indirect calls via a function pointer table

static uint32_t add_values(uint32_t a, uint32_t b) {
    return a + b;
}

static uint32_t xor_values(uint32_t a, uint32_t b) {
    return a ^ b;
}

static uint32_t shift_left(uint32_t val, uint32_t amount) {
    return val << amount;
}

static uint32_t shift_right(uint32_t val, uint32_t amount) {
    return val >> amount;
}

// XTEA-like round function using the static helpers
static uint32_t xtea_round(uint32_t v0, uint32_t v1, uint32_t key, uint32_t sum) {
    uint32_t shifted_left = shift_left(v1, 4);
    uint32_t shifted_right = shift_right(v1, 5);
    uint32_t xored = xor_values(shifted_left, shifted_right);
    uint32_t added = add_values(xored, v1);
    uint32_t key_sum = xor_values(sum, key);
    return xor_values(added, key_sum);
}

// XTEA encrypt using helper functions - inlined, uses volatile
static void xtea_encrypt(volatile uint32_t v[2], const uint32_t key[4], uint32_t num_rounds) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (uint32_t i = 0; i < num_rounds; i++) {
        v0 = add_values(v0, xtea_round(v0, v1, key[sum & 3], sum));
        sum = add_values(sum, delta);
        v1 = add_values(v1, xtea_round(v1, v0, key[(sum >> 11) & 3], sum));
    }
    v[0] = v0; v[1] = v1;
}

// XTEA decrypt using helper functions - inlined, uses volatile
static void xtea_decrypt(volatile uint32_t v[2], const uint32_t key[4], uint32_t num_rounds) {
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9;
    uint32_t sum = delta * num_rounds;
    for (uint32_t i = 0; i < num_rounds; i++) {
        v1 = v1 - xtea_round(v1, v0, key[(sum >> 11) & 3], sum);
        sum = sum - delta;
        v0 = v0 - xtea_round(v0, v1, key[sum & 3], sum);
    }
    v[0] = v0; v[1] = v1;
}

extern "C" int test_me() {
    uint32_t key[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
    // Use volatile to prevent constant folding at compile time
    volatile uint32_t v[2] = {0x1337, 0};
    uint32_t num_rounds = 32;

    xtea_encrypt(v, key, num_rounds);
    xtea_decrypt(v, key, num_rounds);

    return v[0];
}
