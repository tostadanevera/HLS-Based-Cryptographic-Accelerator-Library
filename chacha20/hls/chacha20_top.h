#ifndef CHACHA20_TOP_H
#define CHACHA20_TOP_H

#include "../chacha20.h"

// Upper bound on the message size this wrapper accepts
// Only needed for the m_axi interface's depth pragma
constexpr u32 CHACHA_MAX_MESSAGE_BYTES = 1024;

int chacha20_top(const u32 key[CHACHA_KEY_WORDS],
                 u32 counter,
                 const u32 nonce[CHACHA_NONCE_WORDS],
                 const u8 plaintext[CHACHA_MAX_MESSAGE_BYTES],
                 u8 ciphertext[CHACHA_MAX_MESSAGE_BYTES],
                 u32 length);

#endif // CHACHA20_TOP_H