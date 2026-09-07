#ifndef SERPENT_H
#define SERPENT_H

#include "../common/types.h"

// 128-bit block, 32 rounds, key length 128/192/256 bits
constexpr int SERPENT_BLOCK_WORDS   = 4; // 128 bits / 32
constexpr int SERPENT_MAX_KEY_WORDS = 8; // 256 bits / 32 (max key size in words)
constexpr int SERPENT_ROUNDS        = 32;

// key_length is in BYTES and must be <= 32
void serpent_encrypt(const u8 plaintext[16], const u8 key[], size_t key_length, u8 ciphertext[16]);
void serpent_decrypt(const u8 ciphertext[16], const u8 key[], size_t key_length, u8 plaintext[16]);

#endif // SERPENT_H
