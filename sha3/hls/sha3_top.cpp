#include "sha3_top.h"

int sha3_top(const u8 message[SHA3_MAX_MESSAGE_BYTES],
             u32 length,
             u8 hash_o[SHA3_256_HASH_BYTES])
{
#pragma HLS INTERFACE s_axilite port=return bundle=CTRL
#pragma HLS INTERFACE s_axilite port=length bundle=CTRL

#pragma HLS INTERFACE m_axi port=message offset=slave bundle=DATA depth=SHA3_MAX_MESSAGE_BYTES
#pragma HLS INTERFACE m_axi port=hash_o  offset=slave bundle=DATA depth=SHA3_256_HASH_BYTES

#pragma HLS INTERFACE s_axilite port=message bundle=CTRL
#pragma HLS INTERFACE s_axilite port=hash_o  bundle=CTRL

    // The validated core is called unmodified
    return sha3_256_compute(message, static_cast<size_t>(length), hash_o);
}