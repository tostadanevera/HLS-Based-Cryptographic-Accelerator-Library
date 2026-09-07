#include "serpent_top.h"

int serpent_top(const u8 key[SERPENT_MAX_KEY_WORDS * 4],
                u32 key_length,
                const u8 input[16],
                u8 output[16],
                u32 mode)
{
#pragma HLS INTERFACE s_axilite port=return      bundle=CTRL
#pragma HLS INTERFACE s_axilite port=key_length  bundle=CTRL
#pragma HLS INTERFACE s_axilite port=mode        bundle=CTRL

#pragma HLS INTERFACE m_axi port=key    offset=slave bundle=DATA depth=32
#pragma HLS INTERFACE m_axi port=input  offset=slave bundle=DATA depth=16
#pragma HLS INTERFACE m_axi port=output offset=slave bundle=DATA depth=16

#pragma HLS INTERFACE s_axilite port=key    bundle=CTRL
#pragma HLS INTERFACE s_axilite port=input  bundle=CTRL
#pragma HLS INTERFACE s_axilite port=output bundle=CTRL

    // The core is called unmodified
    if (mode == 0)
        serpent_encrypt(input, key, static_cast<size_t>(key_length), output);
    else
        serpent_decrypt(input, key, static_cast<size_t>(key_length), output);

    return 0;
}