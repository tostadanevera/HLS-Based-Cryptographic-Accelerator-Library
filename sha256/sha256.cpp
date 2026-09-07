#include "sha256.h"

#include <cstring>

namespace {

constexpr int SHA256_SCHEDULE_WORDS = 64; // message schedule w[0..63]

// Initial hash values: fractional parts of the square roots of the first eight primes
constexpr u32 INIT_HASH[SHA256_HASH_WORDS] =
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Round constants K: first thirty-two bits of the fractional parts of the
// cube roots of the first sixty-four primes
constexpr u32 K[SHA256_SCHEDULE_WORDS] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Right rotation by n bits
inline u32 rotr(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
// Right shift by n bits
inline u32 shr(u32 x, int n) { return x >> n; }

inline u32 ch(u32 x, u32 y, u32 z) { return (x & y) ^ (~x & z); }
inline u32 maj(u32 x, u32 y, u32 z) { return (x & y) ^ (x & z) ^ (y & z); }

inline u32 SIGMA0(u32 x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline u32 SIGMA1(u32 x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline u32 sigma0(u32 x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }
inline u32 sigma1(u32 x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }

void sha256_block(u32 hash[SHA256_HASH_WORDS], const u8 block[SHA256_BLOCK_BYTES])
{
    u32 a = hash[0], b = hash[1], c = hash[2], d = hash[3];
    u32 e = hash[4], f = hash[5], g = hash[6], h = hash[7];
    u32 w[SHA256_SCHEDULE_WORDS];
#pragma HLS ARRAY_PARTITION variable=w complete dim=1

    // Fixed trip count of 16: cheap to fully unroll.
    for (int i = 0; i < 16; i++)
    {
#pragma HLS UNROLL
        w[i] = (static_cast<u32>(block[i * 4])     << 24) |
               (static_cast<u32>(block[i * 4 + 1]) << 16) |
               (static_cast<u32>(block[i * 4 + 2]) << 8)  |
                static_cast<u32>(block[i * 4 + 3]);
    }

    // Message schedule expansion
    for (int i = 16; i < SHA256_SCHEDULE_WORDS; i++)
    {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }

    for (int i = 0; i < SHA256_SCHEDULE_WORDS; i++)
    {
#pragma HLS PIPELINE off
        u32 t1 = h + SIGMA1(e) + ch(e, f, g) + K[i] + w[i];
        u32 t2 = SIGMA0(a) + maj(a, b, c);

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
    hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
}

} // namespace

int sha256_compute(const u8* message, size_t length, u32 hash_o[SHA256_HASH_WORDS])
{
    // Padding: message || 0x80 || zeros || 64-bit big-endian bit length
    size_t padded_length = ((length + 9 + SHA256_BLOCK_BYTES - 1) / SHA256_BLOCK_BYTES) * SHA256_BLOCK_BYTES;

    if (padded_length > SHA256_MAX_MESSAGE_BYTES)
    {
        for (int i = 0; i < SHA256_HASH_WORDS; i++) hash_o[i] = 0;
        return -1;
    }

    u8 padded[SHA256_MAX_MESSAGE_BYTES] = {0};

    for (size_t i = 0; i < length; i++)
    {
#pragma HLS LOOP_TRIPCOUNT min=0 max=256
        padded[i] = message[i];
    }
    padded[length] = 0x80;

    u64 bit_length = static_cast<u64>(length) * 8;
    for (int i = 0; i < 8; i++)
    {
        padded[padded_length - 1 - i] = static_cast<u8>(bit_length & 0xFF);
        bit_length >>= 8;
    }

    u32 hash[SHA256_HASH_WORDS];
    for (int i = 0; i < SHA256_HASH_WORDS; i++) hash[i] = INIT_HASH[i];

    size_t num_blocks = padded_length / SHA256_BLOCK_BYTES;

    for (size_t block = 0; block < num_blocks; block++)
    {
#pragma HLS LOOP_TRIPCOUNT min=1 max=4
        sha256_block(hash, padded + block * SHA256_BLOCK_BYTES);
    }

    for (int i = 0; i < SHA256_HASH_WORDS; i++) hash_o[i] = hash[i];

    return 0;
}