#ifndef SHA3_H
#define SHA3_H

#include "../common/types.h"

// SHA3-256, Built on the Keccak-f[1600] permutation with a sponge construction

constexpr int SHA3_256_HASH_BYTES = 32;  // 256-bit digest
constexpr int SHA3_STATE_LANES    = 25;  // 5x5 lanes of 64 bits = 1600-bit state
constexpr int SHA3_256_RATE_BYTES = 136; // 1088-bit rate for SHA3-256

// Upper bound on the message size this core will accept, in bytes
constexpr size_t SHA3_MAX_MESSAGE_BYTES = 256;

// Computes the SHA3-256 digest of `length` bytes at `message`
// Returns 0 on success, -1 if length > SHA3_MAX_MESSAGE_BYTES
int sha3_256_compute(const u8* message, size_t length, u8 hash_o[SHA3_256_HASH_BYTES]);

#endif // SHA3_H
