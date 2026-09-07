#ifndef CHACHA20_H
#define CHACHA20_H

#include "../common/types.h"

// ChaCha20 stream cipher
enum
{
    CHACHA_KEY_WORDS   = 8,  // 256-bit key, 8 32-bit words
    CHACHA_NONCE_WORDS = 3,  // 96-bit nonce (number used once), 3 32-bit words
    CHACHA_STATE_WORDS = 16, // 64-byte state, 16 32-bit words
    CHACHA_BLOCK_BYTES = 64
};

// Produces one 64-byte keystream block (16 32-bit words) for the given key/counter/nonce
void chacha20_block(const u32 key[CHACHA_KEY_WORDS],
                    u32 counter,
                    const u32 nonce[CHACHA_NONCE_WORDS],
                    u32 state[CHACHA_STATE_WORDS]);

// Encrypts (or decrypts, the cipher is symmetric)
void chacha20_encrypt(const u32 key[CHACHA_KEY_WORDS],
                      u32 counter,
                      const u32 nonce[CHACHA_NONCE_WORDS],
                      const u8 plaintext[],
                      u8 ciphertext[],
                      size_t length);

#endif // CHACHA20_H