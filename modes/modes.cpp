#include "modes.h"

#include <cstring>

namespace {

void xor_block(u8 out[MODES_BLOCK_BYTES], const u8 a[MODES_BLOCK_BYTES], const u8 b[MODES_BLOCK_BYTES])
{
    for (int i = 0; i < MODES_BLOCK_BYTES; i++)
        out[i] = a[i] ^ b[i];
}

// 128-bit big-endian increment-by-one, with carry propagation.
void increment_counter(u8 counter[MODES_BLOCK_BYTES])
{
    for (int i = MODES_BLOCK_BYTES - 1; i >= 0; i--)
    {
        if (++counter[i] != 0)
            break; // no carry
    }
}

} // namespace

size_t ecb_encrypt_pkcs7(block_op_fn encrypt_block, const u8* key, size_t key_len,
                          const u8* plaintext, size_t length, u8* ciphertext)
{
    size_t num_full_blocks = length / MODES_BLOCK_BYTES;
    size_t remainder = length % MODES_BLOCK_BYTES;
    u8 pad_len = static_cast<u8>(MODES_BLOCK_BYTES - remainder); // 1..16, PKCS#7

    for (size_t b = 0; b < num_full_blocks; b++)
        encrypt_block(plaintext + b * MODES_BLOCK_BYTES, key, key_len, ciphertext + b * MODES_BLOCK_BYTES);

    u8 last_block[MODES_BLOCK_BYTES];
    memcpy(last_block, plaintext + num_full_blocks * MODES_BLOCK_BYTES, remainder);
    memset(last_block + remainder, pad_len, pad_len);
    encrypt_block(last_block, key, key_len, ciphertext + num_full_blocks * MODES_BLOCK_BYTES);

    return (num_full_blocks + 1) * MODES_BLOCK_BYTES;
}

size_t ecb_decrypt_pkcs7(block_op_fn decrypt_block, const u8* key, size_t key_len,
                          const u8* ciphertext, size_t length, u8* plaintext)
{
    if (length == 0 || length % MODES_BLOCK_BYTES != 0)
        return 0;

    size_t num_blocks = length / MODES_BLOCK_BYTES;
    for (size_t b = 0; b < num_blocks; b++)
        decrypt_block(ciphertext + b * MODES_BLOCK_BYTES, key, key_len, plaintext + b * MODES_BLOCK_BYTES);

    u8 pad_len = plaintext[length - 1];
    if (pad_len == 0 || pad_len > MODES_BLOCK_BYTES || pad_len > length)
        return 0; // malformed padding

    return length - pad_len;
}

size_t cbc_encrypt_pkcs7(block_op_fn encrypt_block, const u8* key, size_t key_len,
                          const u8 iv[MODES_BLOCK_BYTES],
                          const u8* plaintext, size_t length, u8* ciphertext)
{
    size_t num_full_blocks = length / MODES_BLOCK_BYTES;
    size_t remainder = length % MODES_BLOCK_BYTES;
    u8 pad_len = static_cast<u8>(MODES_BLOCK_BYTES - remainder);

    u8 prev[MODES_BLOCK_BYTES];
    memcpy(prev, iv, MODES_BLOCK_BYTES);

    u8 xored[MODES_BLOCK_BYTES];
    for (size_t b = 0; b < num_full_blocks; b++)
    {
        xor_block(xored, plaintext + b * MODES_BLOCK_BYTES, prev);
        encrypt_block(xored, key, key_len, ciphertext + b * MODES_BLOCK_BYTES);
        memcpy(prev, ciphertext + b * MODES_BLOCK_BYTES, MODES_BLOCK_BYTES);
    }

    u8 last_block[MODES_BLOCK_BYTES];
    memcpy(last_block, plaintext + num_full_blocks * MODES_BLOCK_BYTES, remainder);
    memset(last_block + remainder, pad_len, pad_len);
    xor_block(xored, last_block, prev);
    encrypt_block(xored, key, key_len, ciphertext + num_full_blocks * MODES_BLOCK_BYTES);

    return (num_full_blocks + 1) * MODES_BLOCK_BYTES;
}

size_t cbc_decrypt_pkcs7(block_op_fn decrypt_block, const u8* key, size_t key_len,
                          const u8 iv[MODES_BLOCK_BYTES],
                          const u8* ciphertext, size_t length, u8* plaintext)
{
    if (length == 0 || length % MODES_BLOCK_BYTES != 0)
        return 0;

    size_t num_blocks = length / MODES_BLOCK_BYTES;
    u8 prev[MODES_BLOCK_BYTES];
    memcpy(prev, iv, MODES_BLOCK_BYTES);

    u8 decrypted[MODES_BLOCK_BYTES];
    for (size_t b = 0; b < num_blocks; b++)
    {
        const u8* block_in = ciphertext + b * MODES_BLOCK_BYTES;
        decrypt_block(block_in, key, key_len, decrypted);
        xor_block(plaintext + b * MODES_BLOCK_BYTES, decrypted, prev);
        memcpy(prev, block_in, MODES_BLOCK_BYTES);
    }

    u8 pad_len = plaintext[length - 1];
    if (pad_len == 0 || pad_len > MODES_BLOCK_BYTES || pad_len > length)
        return 0;

    return length - pad_len;
}

void ctr_crypt(block_op_fn encrypt_block, const u8* key, size_t key_len,
                const u8 counter[MODES_BLOCK_BYTES],
                const u8* input, size_t length, u8* output)
{
    u8 ctr[MODES_BLOCK_BYTES];
    memcpy(ctr, counter, MODES_BLOCK_BYTES);

    u8 keystream[MODES_BLOCK_BYTES];
    size_t num_blocks = (length + MODES_BLOCK_BYTES - 1) / MODES_BLOCK_BYTES;

    for (size_t b = 0; b < num_blocks; b++)
    {
        size_t offset = b * MODES_BLOCK_BYTES;
        size_t block_size = MODES_BLOCK_BYTES;
        if (offset + MODES_BLOCK_BYTES > length)
            block_size = length - offset;

        encrypt_block(ctr, key, key_len, keystream);
        for (size_t i = 0; i < block_size; i++)
            output[offset + i] = input[offset + i] ^ keystream[i];

        increment_counter(ctr);
    }
}
