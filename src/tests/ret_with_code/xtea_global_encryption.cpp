#include <stdint.h>

// Static globals with internal linkage - will be encrypted by pluto-global-encryption
static uint32_t key[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
static uint32_t delta = 0x9E3779B9;
static uint32_t num_rounds = 32;

// XTEA encrypt - inlined, uses volatile to prevent constant folding
static void xtea_encrypt(volatile uint32_t v[2]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    for (uint32_t i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}

// XTEA decrypt - inlined, uses volatile to prevent constant folding
static void xtea_decrypt(volatile uint32_t v[2]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = delta * num_rounds;
    for (uint32_t i = 0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

extern "C" int test_me() {
    // Use volatile to prevent constant folding at compile time
    volatile uint32_t v[2];
    v[0] = 0x1337;
    v[1] = 0;

    xtea_encrypt(v);
    xtea_decrypt(v);

    return v[0];
}
