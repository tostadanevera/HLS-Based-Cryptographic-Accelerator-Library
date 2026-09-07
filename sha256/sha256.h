#ifndef SHA256_H
#define SHA256_H

#include "../common/types.h"

/*
SHA-256, takes an input of any size and deterministically transforms it into
a unique, fixed-length 256-bit (32-byte) output
*/

constexpr int SHA256_HASH_WORDS  = 8;   // 256-bit digest, 8 32-bit words
constexpr int SHA256_BLOCK_BYTES = 64;  // 512-bit compression block, 64 bytes

// Upper bound on the message size this core will accept (bytes)
constexpr size_t SHA256_MAX_MESSAGE_BYTES = 256;

// Returns 0 on success, -1 if length > SHA256_MAX_MESSAGE_BYTES
int sha256_compute(const u8* message, size_t length, u32 hash_o[SHA256_HASH_WORDS]);

#endif // SHA256_H
