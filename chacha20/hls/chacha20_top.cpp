#include "chacha20_top.h"

int chacha20_top(const u32 key[CHACHA_KEY_WORDS],
                 u32 counter,
                 const u32 nonce[CHACHA_NONCE_WORDS],
                 const u8 plaintext[CHACHA_MAX_MESSAGE_BYTES],
                 u8 ciphertext[CHACHA_MAX_MESSAGE_BYTES],
                 u32 length)
{
#pragma HLS INTERFACE s_axilite port=return  bundle=CTRL
#pragma HLS INTERFACE s_axilite port=counter bundle=CTRL
#pragma HLS INTERFACE s_axilite port=length  bundle=CTRL

#pragma HLS INTERFACE m_axi port=key        offset=slave bundle=DATA depth=CHACHA_KEY_WORDS
#pragma HLS INTERFACE m_axi port=nonce      offset=slave bundle=DATA depth=CHACHA_NONCE_WORDS
#pragma HLS INTERFACE m_axi port=plaintext  offset=slave bundle=DATA depth=CHACHA_MAX_MESSAGE_BYTES
#pragma HLS INTERFACE m_axi port=ciphertext offset=slave bundle=DATA depth=CHACHA_MAX_MESSAGE_BYTES

#pragma HLS INTERFACE s_axilite port=key        bundle=CTRL
#pragma HLS INTERFACE s_axilite port=nonce      bundle=CTRL
#pragma HLS INTERFACE s_axilite port=plaintext  bundle=CTRL
#pragma HLS INTERFACE s_axilite port=ciphertext bundle=CTRL

    // The validated core is called unmodified
    chacha20_encrypt(key, counter, nonce, plaintext, ciphertext, static_cast<size_t>(length));

    return 0;
}