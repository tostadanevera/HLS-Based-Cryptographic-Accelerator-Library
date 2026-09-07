#ifndef SHA256_TOP_H
#define SHA256_TOP_H

#include "../sha256.h"

// Top-level function for Vitis HLS synthesis
int sha256_top(const u8 msg[SHA256_MAX_MESSAGE_BYTES], u32 len, u32 hash[SHA256_HASH_WORDS]);

#endif // SHA256_TOP_H