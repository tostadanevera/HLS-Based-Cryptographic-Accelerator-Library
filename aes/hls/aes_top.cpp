#include "aes_top.h"

#include <array>

// mode = 0: encrypt, mode = 1: decrypt
int aes128_top(const u8 key[AES_KEY_SIZE],
               const u8 input[AES_STATE_SIZE],
               u8 output[AES_STATE_SIZE],
               u8 mode)
{
#pragma HLS INTERFACE s_axilite port=return bundle=CTRL
#pragma HLS INTERFACE s_axilite port=mode   bundle=CTRL

#pragma HLS INTERFACE m_axi port=key    offset=slave bundle=DATA depth=AES_KEY_SIZE
#pragma HLS INTERFACE m_axi port=input  offset=slave bundle=DATA depth=AES_STATE_SIZE
#pragma HLS INTERFACE m_axi port=output offset=slave bundle=DATA depth=AES_STATE_SIZE

#pragma HLS INTERFACE s_axilite port=key    bundle=CTRL
#pragma HLS INTERFACE s_axilite port=input  bundle=CTRL
#pragma HLS INTERFACE s_axilite port=output bundle=CTRL

    std::array<u8, AES_KEY_SIZE> key_arr;
    std::array<u8, AES_STATE_SIZE> in_arr, out_arr;

    for (int i = 0; i < AES_KEY_SIZE; i++) key_arr[i] = key[i];
    for (int i = 0; i < AES_STATE_SIZE; i++) in_arr[i] = input[i];

    if (mode == 0)
        aes_encrypt(in_arr, key_arr, out_arr);
    else
        aes_decrypt(in_arr, key_arr, out_arr);

    for (int i = 0; i < AES_STATE_SIZE; i++) output[i] = out_arr[i];

    return 0;
}