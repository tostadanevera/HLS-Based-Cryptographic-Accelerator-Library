#ifndef SHA3_TOP_H
#define SHA3_TOP_H

#include "../sha3.h"

// Returns 0 on success, -1 if length > SHA3_MAX_MESSAGE_BYTES
int sha3_top(const u8 message[SHA3_MAX_MESSAGE_BYTES],
            u32 length,
            u8 hash_o[SHA3_256_HASH_BYTES]);

#endif // SHA3_TOP_H