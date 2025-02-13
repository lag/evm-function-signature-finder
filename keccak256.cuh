#ifndef KECCAK256_CUH
#define KECCAK256_CUH

#define KECCAK_ROUNDS 24
#define KECCAK_STATE_SIZE 25
#define KECCAK_256_RATE 136

// Keccak-f[1600] constants
__constant__ const int keccak_rotc[24] = {
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

__constant__ const int keccak_piln[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

__constant__ const uint64_t keccak_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

__device__ __forceinline__ uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

__device__ void keccak_f1600(uint64_t* state) {
    uint64_t C0, C1, C2, C3, C4, D;
    uint64_t temp;

    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta step
        C0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        C1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        C2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        C3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        C4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        D = C4 ^ rotl64(C1, 1);
        state[0] ^= D;
        state[5] ^= D;
        state[10] ^= D;
        state[15] ^= D;
        state[20] ^= D;

        D = C0 ^ rotl64(C2, 1);
        state[1] ^= D;
        state[6] ^= D;
        state[11] ^= D;
        state[16] ^= D;
        state[21] ^= D;

        D = C1 ^ rotl64(C3, 1);
        state[2] ^= D;
        state[7] ^= D;
        state[12] ^= D;
        state[17] ^= D;
        state[22] ^= D;

        D = C2 ^ rotl64(C4, 1);
        state[3] ^= D;
        state[8] ^= D;
        state[13] ^= D;
        state[18] ^= D;
        state[23] ^= D;

        D = C3 ^ rotl64(C0, 1);
        state[4] ^= D;
        state[9] ^= D;
        state[14] ^= D;
        state[19] ^= D;
        state[24] ^= D;

        // Rho and Pi steps
        temp = state[1];
        for (int x = 0; x < 24; x++) {
            uint64_t tmp = state[keccak_piln[x]];
            state[keccak_piln[x]] = rotl64(temp, keccak_rotc[x]);
            temp = tmp;
        }

        // Chi step
        for (int y = 0; y < 5; y++) {
            uint64_t Cx0 = state[y * 5 + 0];
            uint64_t Cx1 = state[y * 5 + 1];
            uint64_t Cx2 = state[y * 5 + 2];
            uint64_t Cx3 = state[y * 5 + 3];
            uint64_t Cx4 = state[y * 5 + 4];

            state[y * 5 + 0] ^= (~Cx1) & Cx2;
            state[y * 5 + 1] ^= (~Cx2) & Cx3;
            state[y * 5 + 2] ^= (~Cx3) & Cx4;
            state[y * 5 + 3] ^= (~Cx4) & Cx0;
            state[y * 5 + 4] ^= (~Cx0) & Cx1;
        }

        // Iota step
        state[0] ^= keccak_rndc[round];
    }
}

__device__ void keccak256(const uint8_t* input, size_t input_length, uint8_t* output) {
    uint64_t state[KECCAK_STATE_SIZE] = {0};
    const uint64_t* input_ptr = (const uint64_t*)input;
    size_t input_size = input_length / 8;
    size_t remaining = input_length % 8;

    // Absorb input
    for (size_t i = 0; i < input_size; i++) {
        state[i % 17] ^= input_ptr[i];
        if ((i + 1) % 17 == 0) {
            keccak_f1600(state);
        }
    }

    // Handle remaining bytes and padding
    uint64_t last_block = 0;
    for (size_t i = 0; i < remaining; i++) {
        last_block |= (uint64_t)input[input_length - remaining + i] << (i * 8);
    }
    state[input_size % 17] ^= last_block;
    state[input_size % 17] ^= 0x01ULL << (remaining * 8);
    state[16] ^= 0x8000000000000000ULL;

    // Final permutation
    keccak_f1600(state);

    // Output
    for (int i = 0; i < 4; i++) {
        ((uint64_t*)output)[i] = state[i];
    }
}

#endif // KECCAK256_CUH