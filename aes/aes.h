#ifndef AES_H
#define AES_H

#include <array>
#include "../common/types.h"

// AES-128
// Block size and key size are both 128 bits (16 bytes), 10 rounds
constexpr int AES_STATE_SIZE        = 16;
constexpr int AES_KEY_SIZE          = 16;
constexpr int AES_EXPANDED_KEY_SIZE = 176; // 11 round keys * 16 bytes
constexpr int AES_ROUNDS            = 10;

// Encrypts one 128-bit block under a 128-bit key.
void aes_encrypt(const std::array<u8, AES_STATE_SIZE>& plaintext,
                 const std::array<u8, AES_KEY_SIZE>&   key,
                 std::array<u8, AES_STATE_SIZE>&       ciphertext);

// Decrypts one 128-bit block under a 128-bit key.
void aes_decrypt(const std::array<u8, AES_STATE_SIZE>& ciphertext,
                 const std::array<u8, AES_KEY_SIZE>&   key,
                 std::array<u8, AES_STATE_SIZE>&       plaintext);

#endif // AES_H