#include "sha3.h"

#include <cstring>

// SHA3-256 (FIPS 202): Keccak-f[1600] permutation + sponge construction

namespace {

using u64 = uint64_t;

inline u64 rotl64(u64 x, int n) { return (x << n) | (x >> (64 - n)); }

constexpr int KECCAK_ROUNDS = 24;

constexpr u64 keccakf_rndc[24] =
{
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

constexpr int keccakf_rotc[24] = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };
constexpr int keccakf_piln[24] = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

// Keccak-f[1600]: permutes a 25-lane (5x5x64-bit = 1600-bit) state in place
void keccakf(u64 st[SHA3_STATE_LANES])
{
    for (int round = 0; round < KECCAK_ROUNDS; round++)
    {
        u64 bc[5];

        // Theta
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (int i = 0; i < 5; i++)
        {
            u64 t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho + Pi
        u64 t = st[1];
        for (int i = 0; i < 24; i++)
        {
            int j = keccakf_piln[i];
            u64 tmp = st[j];
            st[j] = rotl64(t, keccakf_rotc[i]);
            t = tmp;
        }

        // Chi
        for (int j = 0; j < 25; j += 5)
        {
            u64 row[5];
            for (int i = 0; i < 5; i++) row[i] = st[j + i];
            for (int i = 0; i < 5; i++) st[j + i] ^= (~row[(i + 1) % 5]) & row[(i + 2) % 5];
        }

        // Iota
        st[0] ^= keccakf_rndc[round];
    }
}

void absorb_block(u64 state[SHA3_STATE_LANES], const u8 block[SHA3_256_RATE_BYTES])
{
    for (int i = 0; i < SHA3_256_RATE_BYTES / 8; i++)
    {
        u64 lane = 0;
        for (int b = 0; b < 8; b++)
            lane |= static_cast<u64>(block[i * 8 + b]) << (8 * b);
        state[i] ^= lane;
    }
    keccakf(state);
}

} // namespace

int sha3_256_compute(const u8* message, size_t length, u8 hash_o[SHA3_256_HASH_BYTES])
{
    if (length > SHA3_MAX_MESSAGE_BYTES)
    {
        memset(hash_o, 0, SHA3_256_HASH_BYTES);
        return -1;
    }

    constexpr size_t rate = SHA3_256_RATE_BYTES;

    size_t padded_length = length + 1;
    if (padded_length % rate != 0)
        padded_length += rate - (padded_length % rate);

    u8 padded[SHA3_MAX_MESSAGE_BYTES + SHA3_256_RATE_BYTES] = {0};
    memcpy(padded, message, length);
    padded[length] = 0x06;
    padded[padded_length - 1] |= 0x80;

    u64 state[SHA3_STATE_LANES] = {0};
    size_t num_blocks = padded_length / rate;
    for (size_t blk = 0; blk < num_blocks; blk++) {
#pragma HLS LOOP_TRIPCOUNT min=1 max=2
        absorb_block(state, padded + blk * rate);
    }

    for (int i = 0; i < SHA3_256_HASH_BYTES; i++)
        hash_o[i] = static_cast<u8>(state[i / 8] >> (8 * (i % 8)));

    return 0;
}
