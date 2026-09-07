#include "chacha20.h"

// ChaCha20 core

namespace {

constexpr u32 constants[4] =
{
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

inline u32 rotl(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

void words_to_bytes(const u32 words[CHACHA_STATE_WORDS], u8 bytes[CHACHA_BLOCK_BYTES])
{
    for (int i = 0; i < CHACHA_STATE_WORDS; i++)
    {
        bytes[4 * i]     = static_cast<u8>( words[i]        & 0xff);
        bytes[4 * i + 1] = static_cast<u8>((words[i] >> 8)  & 0xff);
        bytes[4 * i + 2] = static_cast<u8>((words[i] >> 16) & 0xff);
        bytes[4 * i + 3] = static_cast<u8>((words[i] >> 24) & 0xff);
    }
}

void quarter_round(u32 state[CHACHA_STATE_WORDS], int a, int b, int c, int d)
{
    state[a] += state[b]; state[d] ^= state[a]; state[d] = rotl(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = rotl(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = rotl(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = rotl(state[b], 7);
}

void column_round(u32 state[CHACHA_STATE_WORDS])
{
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
}

void diagonal_round(u32 state[CHACHA_STATE_WORDS])
{
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

} // namespace

void chacha20_block(const u32 key[CHACHA_KEY_WORDS], u32 counter, const u32 nonce[CHACHA_NONCE_WORDS], u32 state[CHACHA_STATE_WORDS])
{
    u32 init_state[CHACHA_STATE_WORDS];

    for (int i = 0; i < 4; i++)
        state[i] = constants[i];

    for (int i = 0; i < CHACHA_KEY_WORDS; i++)
        state[i + 4] = key[i];

    state[12] = counter;

    for (int i = 0; i < CHACHA_NONCE_WORDS; i++)
        state[i + 13] = nonce[i];

    for (int i = 0; i < CHACHA_STATE_WORDS; i++)
        init_state[i] = state[i];

    // 20 rounds = 10 column + diagonal pairs
    for (int i = 0; i < 10; i++)
    {
#pragma HLS PIPELINE off
        column_round(state);
        diagonal_round(state);
    }

    // Add original state
    for (int i = 0; i < CHACHA_STATE_WORDS; i++)
        state[i] += init_state[i];
}

void chacha20_encrypt(const u32 key[CHACHA_KEY_WORDS], u32 counter, const u32 nonce[CHACHA_NONCE_WORDS],
                      const u8 plaintext[], u8 ciphertext[], size_t length)
{
    u32 keystream_words[CHACHA_STATE_WORDS];
    u8  keystream_bytes[CHACHA_BLOCK_BYTES];

    size_t num_blocks = (length + CHACHA_BLOCK_BYTES - 1) / CHACHA_BLOCK_BYTES;

    for (size_t block = 0; block < num_blocks; block++)
    {
#pragma HLS loop_tripcount min=1 max=16 // max = CHACHA_MAX_MESSAGE_BYTES / CHACHA_BLOCK_BYTES
        size_t offset = block * CHACHA_BLOCK_BYTES;
        size_t block_size = CHACHA_BLOCK_BYTES;
        if (offset + CHACHA_BLOCK_BYTES > length)
            block_size = length - offset;

        chacha20_block(key, counter, nonce, keystream_words);
        words_to_bytes(keystream_words, keystream_bytes);

        for (size_t i = 0; i < block_size; i++)
#pragma HLS loop_tripcount min=1 max=64 // max = CHACHA_BLOCK_BYTES
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream_bytes[i];

        counter++;
    }
}
