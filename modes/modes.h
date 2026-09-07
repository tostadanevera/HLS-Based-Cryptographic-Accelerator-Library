#ifndef MODES_H
#define MODES_H

#include "../common/types.h"

// Generic modes of operation for any 16-byte-block cipher (AES, Serpent,
// ...). The core algorithm is plugged in via a function pointer so this
// file has no dependency on any specific cipher header.
//
// Throughput/parallelism note for the FPGA characterization:
//   - ECB and CTR have no dependency between blocks -> every block's
//     core invocation can be pipelined/parallelized in hardware.
//   - CBC *encryption* is serial: block i needs ciphertext i-1, so on
//     an FPGA you cannot pipeline across blocks for CBC encryption
//     (only within a single block's internal rounds). CBC *decryption*
//     has no such dependency and can be parallelized like ECB/CTR.
//
// These wrappers use simple PKCS#7 padding for ECB/CBC and are meant
// for library completeness / behavioral testing, not as a hardened
// production padding implementation (no constant-time padding check).

constexpr int MODES_BLOCK_BYTES = 16;

// Signature every wrapped block cipher must match. `key`/`key_len` are
// passed straight through to whichever cipher-specific adapter you wire
// up (see e.g. test_modes.cpp for AES/Serpent adapters).
typedef void (*block_op_fn)(const u8 in[MODES_BLOCK_BYTES], const u8* key, size_t key_len, u8 out[MODES_BLOCK_BYTES]);

// ECB with PKCS#7 padding.
// `ciphertext` must have room for length rounded up to the next multiple
// of 16, plus 16 bytes (worst case: input already block-aligned still
// gets a full padding block, per PKCS#7). Returns the ciphertext length.
size_t ecb_encrypt_pkcs7(block_op_fn encrypt_block, const u8* key, size_t key_len,
                          const u8* plaintext, size_t length, u8* ciphertext);

// `plaintext` must have room for `length` bytes. Returns the plaintext
// length after stripping padding, or 0 if the padding is malformed.
size_t ecb_decrypt_pkcs7(block_op_fn decrypt_block, const u8* key, size_t key_len,
                          const u8* ciphertext, size_t length, u8* plaintext);

// CBC with PKCS#7 padding. Same buffer-sizing rules as ECB above, plus a
// 16-byte IV that must be unpredictable per encryption in real use.
size_t cbc_encrypt_pkcs7(block_op_fn encrypt_block, const u8* key, size_t key_len,
                          const u8 iv[MODES_BLOCK_BYTES],
                          const u8* plaintext, size_t length, u8* ciphertext);

size_t cbc_decrypt_pkcs7(block_op_fn decrypt_block, const u8* key, size_t key_len,
                          const u8 iv[MODES_BLOCK_BYTES],
                          const u8* ciphertext, size_t length, u8* plaintext);

// CTR mode: turns the block cipher into a stream cipher (like ChaCha20),
// so encryption and decryption are the same operation (XOR with the
// keystream) and no padding is needed. `counter` is treated as a
// 128-bit big-endian integer and incremented by 1 per 16-byte block.
void ctr_crypt(block_op_fn encrypt_block, const u8* key, size_t key_len,
                const u8 counter[MODES_BLOCK_BYTES],
                const u8* input, size_t length, u8* output);

#endif // MODES_H
