#ifndef AES_TOP_H
#define AES_TOP_H

#include "../aes.h"

// AES-128 HLS top-level wrapper
// mode = 0: encrypt, mode = 1: decrypt
// Returns 0
int aes128_top(const u8 key[AES_KEY_SIZE],
               const u8 input[AES_STATE_SIZE],
               u8 output[AES_STATE_SIZE],
               u8 mode);

#endif // AES_TOP_H