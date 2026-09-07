#include "serpent.h"

#include <cstring>

// Serpent core encrypt/decrypt
// The eight S-boxes are implemented as "bitslice" boolean formulas 
// (standard high-performance formulation of Serpent)

namespace {

constexpr u32 PHI = 0x9e3779b9; // fractional part of the golden ratio

// S-box 0
#define SBOX0(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r3 ^= r0; r4 = r1; \
   r1 &= r3; r4 ^= r2; \
   r1 ^= r0; r0 |= r3; \
   r0 ^= r4; r4 ^= r3; \
   r3 ^= r2; r2 |= r1; \
   r2 ^= r4; r4 = ~r4; \
   r4 |= r1; r1 ^= r3; \
   r1 ^= r4; r3 |= r0; \
   r1 ^= r3; r4 ^= r3; \
   r3 = r0; r0 = r1; r1 = r4; \
}

// S-box 0 inverse
#define SBOX0_INV(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r2 = ~r2; r4 = r1; \
   r1 |= r0; r4 = ~r4; \
   r1 ^= r2; r2 |= r4; \
   r1 ^= r3; r0 ^= r4; \
   r2 ^= r0; r0 &= r3; \
   r4 ^= r0; r0 |= r1; \
   r0 ^= r2; r3 ^= r4; \
   r2 ^= r1; r3 ^= r0; \
   r3 ^= r1; \
   r2 &= r3; \
   r4 ^= r2; \
   r2 = r1; r1 = r4; \
}

// S-box 1
#define SBOX1(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r0 = ~r0; r2 = ~r2; \
   r4 = r0; r0 &= r1; \
   r2 ^= r0; r0 |= r3; \
   r3 ^= r2; r1 ^= r0; \
   r0 ^= r4; r4 |= r1; \
   r1 ^= r3; r2 |= r0; \
   r2 &= r4; r0 ^= r1; \
   r1 &= r2; \
   r1 ^= r0; r0 &= r2; \
   r0 ^= r4; \
   r4 = r0; r0 = r2; r2 = r3; r3 = r1; r1 = r4; \
}

// S-box 1 inverse
#define SBOX1_INV(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r4 = r1; r1 ^= r3; \
   r3 &= r1; r4 ^= r2; \
   r3 ^= r0; r0 |= r1; \
   r2 ^= r3; r0 ^= r4; \
   r0 |= r2; r1 ^= r3; \
   r0 ^= r1; r1 |= r3; \
   r1 ^= r0; r4 = ~r4; \
   r4 ^= r1; r1 |= r0; \
   r1 ^= r0; \
   r1 |= r4; \
   r3 ^= r1; \
   r1 = r0; r0 = r4; r4 = r2; r2 = r3; r3 = r4; \
}

// S-box 2
#define SBOX2(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r4 = r0; r0 &= r2; \
   r0 ^= r3; r2 ^= r1; \
   r2 ^= r0; r3 |= r4; \
   r3 ^= r1; r4 ^= r2; \
   r1 = r3; r3 |= r4; \
   r3 ^= r0; r0 &= r1; \
   r4 ^= r0; r1 ^= r3; \
   r1 ^= r4; r4 = ~r4; \
   r0 = r2; r2 = r1; r1 = r3; r3 = r4; \
}

// S-box 2 inverse
#define SBOX2_INV(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r2 ^= r3; r3 ^= r0; \
   r4 = r3; r3 &= r2; \
   r3 ^= r1; r1 |= r2; \
   r1 ^= r4; r4 &= r3; \
   r2 ^= r3; r4 &= r0; \
   r4 ^= r2; r2 &= r1; \
   r2 |= r0; r3 = ~r3; \
   r2 ^= r3; r0 ^= r3; \
   r0 &= r1; r3 ^= r4; \
   r3 ^= r0; \
   r0 = r1; r1 = r4; \
}

// S-box 3
#define SBOX3(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r4 = r0; r0 |= r3; \
   r3 ^= r1; r1 &= r4; \
   r4 ^= r2; r2 ^= r3; \
   r3 &= r0; r4 |= r1; \
   r3 ^= r4; r0 ^= r1; \
   r4 &= r0; r1 ^= r3; \
   r4 ^= r2; r1 |= r0; \
   r1 ^= r2; r0 ^= r3; \
   r2 = r1; r1 |= r3; \
   r1 ^= r0; \
   r0 = r1; r1 = r2; r2 = r3; r3 = r4; \
}

// S-box 3 inverse
#define SBOX3_INV(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r4 = r2; r2 ^= r1; \
   r0 ^= r2; r4 &= r2; \
   r4 ^= r0; r0 &= r1; \
   r1 ^= r3; r3 |= r4; \
   r2 ^= r3; r0 ^= r3; \
   r1 ^= r4; r3 &= r2; \
   r3 ^= r1; r1 ^= r0; \
   r1 |= r2; r0 ^= r3; \
   r1 ^= r4; \
   r0 ^= r1; \
   r4 = r0; r0 = r2; r2 = r3; r3 = r4; \
}

// S-box 4
#define SBOX4(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r1 ^= r3; r3 = ~r3; \
   r2 ^= r3; r3 ^= r0; \
   r4 = r1; r1 &= r3; \
   r1 ^= r2; r4 ^= r3; \
   r0 ^= r4; r2 &= r4; \
   r2 ^= r0; r0 &= r1; \
   r3 ^= r0; r4 |= r1; \
   r4 ^= r0; r0 |= r3; \
   r0 ^= r2; r2 &= r3; \
   r0 = ~r0; r4 ^= r2; \
   r2 = r0; r0 = r1; r1 = r4; \
}

// S-box 4 inverse
#define SBOX4_INV(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r4 = r2; r2 &= r3; \
   r2 ^= r1; r1 |= r3; \
   r1 &= r0; r4 ^= r2; \
   r4 ^= r1; r1 &= r2; \
   r0 = ~r0; r3 ^= r4; \
   r1 ^= r3; r3 &= r0; \
   r3 ^= r2; r0 ^= r1; \
   r2 &= r0; r3 ^= r0; \
   r2 ^= r4; \
   r2 |= r3; r3 ^= r0; \
   r2 ^= r1; \
   r1 = r3; r3 = r4; \
}

// S-box 5
#define SBOX5(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r0 ^= r1; r1 ^= r3; \
   r3 = ~r3; r4 = r1; \
   r1 &= r0; r2 ^= r3; \
   r1 ^= r2; r2 |= r4; \
   r4 ^= r3; r3 &= r1; \
   r3 ^= r0; r4 ^= r1; \
   r4 ^= r2; r2 ^= r0; \
   r0 &= r3; r2 = ~r2; \
   r0 ^= r4; r4 |= r3; \
   r2 ^= r4; \
   r4 = r0; r0 = r1; r1 = r3; r3 = r2; r2 = r4; \
}

// S-box 5 inverse
#define SBOX5_INV(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r1 = ~r1; r4 = r3; \
   r2 ^= r1; r3 |= r0; \
   r3 ^= r2; r2 |= r1; \
   r2 &= r0; r4 ^= r3; \
   r2 ^= r4; r4 |= r0; \
   r4 ^= r1; r1 &= r2; \
   r1 ^= r3; r4 ^= r2; \
   r3 &= r4; r4 ^= r1; \
   r3 ^= r4; r4 = ~r4; \
   r3 ^= r0; \
   r0 = r1; r1 = r4; r4 = r2; r2 = r3; r3 = r4; \
}

// S-box 6
#define SBOX6(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r2 = ~r2; r4 = r3; \
   r3 &= r0; r0 ^= r4; \
   r3 ^= r2; r2 |= r4; \
   r1 ^= r3; r2 ^= r0; \
   r0 |= r1; r2 ^= r1; \
   r4 ^= r0; r0 |= r3; \
   r0 ^= r2; r4 ^= r3; \
   r4 ^= r0; r3 = ~r3; \
   r2 &= r4; \
   r2 ^= r3; \
   r3 = r2; r2 = r4; \
}

// S-box 6 inverse
#define SBOX6_INV(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r0 ^= r2; r4 = r2; \
   r2 &= r0; r4 ^= r3; \
   r2 = ~r2; r3 ^= r1; \
   r2 ^= r3; r4 |= r0; \
   r0 ^= r2; r3 ^= r4; \
   r4 ^= r1; r1 &= r3; \
   r1 ^= r0; r0 ^= r3; \
   r0 |= r2; r3 ^= r1; \
   r4 ^= r0; \
   r0 = r1; r1 = r2; r2 = r4; \
}

// S-box 7
#define SBOX7(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r4 = r1; r1 |= r2; \
   r1 ^= r3; r4 ^= r2; \
   r2 ^= r1; r3 |= r4; \
   r3 &= r0; r4 ^= r2; \
   r3 ^= r1; r1 |= r4; \
   r1 ^= r0; r0 |= r4; \
   r0 ^= r2; r1 ^= r4; \
   r2 ^= r1; r1 &= r0; \
   r1 ^= r4; r2 = ~r2; \
   r2 |= r0; \
   r4 ^= r2; \
   r2 = r1; r1 = r3; r3 = r0; r0 = r4; \
}

// S-box 7 inverse
#define SBOX7_INV(r0, r1, r2, r3) \
{ \
   u32 r4; \
   r4 = r2; r2 ^= r0; \
   r0 &= r3; r4 |= r3; \
   r2 = ~r2; r3 ^= r1; \
   r1 |= r0; r0 ^= r2; \
   r2 &= r4; r3 &= r4; \
   r1 ^= r2; r2 ^= r0; \
   r0 |= r2; r4 ^= r1; \
   r0 ^= r3; r3 ^= r4; \
   r4 |= r0; r3 ^= r2; \
   r4 ^= r2; \
   r2 = r1; r1 = r0; r0 = r3; r3 = r4; \
}

inline void sbox0_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX0(*r0, *r1, *r2, *r3); }
inline void sbox1_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX1(*r0, *r1, *r2, *r3); }
inline void sbox2_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX2(*r0, *r1, *r2, *r3); }
inline void sbox3_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX3(*r0, *r1, *r2, *r3); }
inline void sbox4_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX4(*r0, *r1, *r2, *r3); }
inline void sbox5_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX5(*r0, *r1, *r2, *r3); }
inline void sbox6_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX6(*r0, *r1, *r2, *r3); }
inline void sbox7_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX7(*r0, *r1, *r2, *r3); }

inline void sbox0_inv_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX0_INV(*r0, *r1, *r2, *r3); }
inline void sbox1_inv_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX1_INV(*r0, *r1, *r2, *r3); }
inline void sbox2_inv_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX2_INV(*r0, *r1, *r2, *r3); }
inline void sbox3_inv_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX3_INV(*r0, *r1, *r2, *r3); }
inline void sbox4_inv_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX4_INV(*r0, *r1, *r2, *r3); }
inline void sbox5_inv_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX5_INV(*r0, *r1, *r2, *r3); }
inline void sbox6_inv_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX6_INV(*r0, *r1, *r2, *r3); }
inline void sbox7_inv_bitslice(u32 *r0, u32 *r1, u32 *r2, u32 *r3) { SBOX7_INV(*r0, *r1, *r2, *r3); }

inline u32 rotl(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

void linear_transform(u32 *state)
{
    u32 x0 = state[0], x1 = state[1], x2 = state[2], x3 = state[3];

    x0 = rotl(x0, 13);
    x2 = rotl(x2, 3);
    x1 = x1 ^ x0 ^ x2;
    x3 = x3 ^ x2 ^ (x0 << 3);
    x1 = rotl(x1, 1);
    x3 = rotl(x3, 7);
    x0 = x0 ^ x1 ^ x3;
    x2 = x2 ^ x3 ^ (x1 << 7);
    x0 = rotl(x0, 5);
    x2 = rotl(x2, 22);

    state[0] = x0; state[1] = x1; state[2] = x2; state[3] = x3;
}

void linear_transform_inverse(u32 *state)
{
    u32 x0 = state[0], x1 = state[1], x2 = state[2], x3 = state[3];

    x2 = rotl(x2, 32 - 22);
    x0 = rotl(x0, 32 - 5);
    x2 = x2 ^ x3 ^ (x1 << 7);
    x0 = x0 ^ x1 ^ x3;
    x3 = rotl(x3, 32 - 7);
    x1 = rotl(x1, 32 - 1);
    x3 = x3 ^ x2 ^ (x0 << 3);
    x1 = x1 ^ x0 ^ x2;
    x2 = rotl(x2, 32 - 3);
    x0 = rotl(x0, 32 - 13);

    state[0] = x0; state[1] = x1; state[2] = x2; state[3] = x3;
}

// Expands the user key into 33 128-bit round keys
// Shared by both serpent_encrypt() and serpent_decrypt()
void generate_round_keys(const u8 key[], size_t key_length, u32 round_keys[33][4])
{
    // Pad the key out to 256 bits: append a single 1 bit then zeros
    u8 padded_key[32] = {0};
    for (size_t i = 0; i < key_length; i++)
    {
    #pragma HLS loop_tripcount min=16 max=32
        padded_key[i] = key[i];
    }
    if (key_length < 32)
        padded_key[key_length] = 0x01;

    // Map the padded key into 8 words (little-endian byte order)
    u32 mapped_key[SERPENT_MAX_KEY_WORDS] = {0};
    for (int i = 0; i < SERPENT_MAX_KEY_WORDS; i++)
    {
        mapped_key[i] = (static_cast<u32>(padded_key[i * 4]))       |
                        (static_cast<u32>(padded_key[i * 4 + 1]) << 8)  |
                        (static_cast<u32>(padded_key[i * 4 + 2]) << 16) |
                        (static_cast<u32>(padded_key[i * 4 + 3]) << 24);
    }

    // Generate the 132 prekey words
    u32 prekey[132] = {0};

    prekey[0] = rotl(mapped_key[0] ^ mapped_key[3] ^ mapped_key[5] ^ mapped_key[7] ^ PHI ^ 0, 11);
    prekey[1] = rotl(mapped_key[1] ^ mapped_key[4] ^ mapped_key[6] ^ prekey[0] ^ PHI ^ 1, 11);
    prekey[2] = rotl(mapped_key[2] ^ mapped_key[5] ^ mapped_key[7] ^ prekey[1] ^ PHI ^ 2, 11);
    prekey[3] = rotl(mapped_key[3] ^ mapped_key[6] ^ prekey[0] ^ prekey[2] ^ PHI ^ 3, 11);
    prekey[4] = rotl(mapped_key[4] ^ mapped_key[7] ^ prekey[1] ^ prekey[3] ^ PHI ^ 4, 11);
    prekey[5] = rotl(mapped_key[5] ^ prekey[0] ^ prekey[2] ^ prekey[4] ^ PHI ^ 5, 11);
    prekey[6] = rotl(mapped_key[6] ^ prekey[1] ^ prekey[3] ^ prekey[5] ^ PHI ^ 6, 11);
    prekey[7] = rotl(mapped_key[7] ^ prekey[2] ^ prekey[4] ^ prekey[6] ^ PHI ^ 7, 11);

    for (int i = 8; i < 132; i++)
        prekey[i] = rotl(prekey[i - 8] ^ prekey[i - 5] ^ prekey[i - 3] ^ prekey[i - 1] ^ PHI ^ i, 11);

    // Derive the 33 round keys from the prekeys, S-box order S3,S2,S1,S0,S7,S6,S5,S4
    static const int key_sbox_order[8] = {3, 2, 1, 0, 7, 6, 5, 4};

    for (int i = 0; i < 33; i++)
    {
        round_keys[i][0] = prekey[4 * i];
        round_keys[i][1] = prekey[4 * i + 1];
        round_keys[i][2] = prekey[4 * i + 2];
        round_keys[i][3] = prekey[4 * i + 3];

        switch (key_sbox_order[i % 8])
        {
            case 0: sbox0_bitslice(&round_keys[i][0], &round_keys[i][1], &round_keys[i][2], &round_keys[i][3]); break;
            case 1: sbox1_bitslice(&round_keys[i][0], &round_keys[i][1], &round_keys[i][2], &round_keys[i][3]); break;
            case 2: sbox2_bitslice(&round_keys[i][0], &round_keys[i][1], &round_keys[i][2], &round_keys[i][3]); break;
            case 3: sbox3_bitslice(&round_keys[i][0], &round_keys[i][1], &round_keys[i][2], &round_keys[i][3]); break;
            case 4: sbox4_bitslice(&round_keys[i][0], &round_keys[i][1], &round_keys[i][2], &round_keys[i][3]); break;
            case 5: sbox5_bitslice(&round_keys[i][0], &round_keys[i][1], &round_keys[i][2], &round_keys[i][3]); break;
            case 6: sbox6_bitslice(&round_keys[i][0], &round_keys[i][1], &round_keys[i][2], &round_keys[i][3]); break;
            case 7: sbox7_bitslice(&round_keys[i][0], &round_keys[i][1], &round_keys[i][2], &round_keys[i][3]); break;
        }
    }
}

} // namespace

void serpent_encrypt(const u8 plaintext[16], const u8 key[], size_t key_length, u8 ciphertext[16])
{
    u32 round_keys[33][4] = {{0}};
    generate_round_keys(key, key_length, round_keys);

    u32 state[SERPENT_BLOCK_WORDS] = {0};
    for (int i = 0; i < SERPENT_BLOCK_WORDS; i++)
    {
    #pragma HLS UNROLL
        state[i] = (static_cast<u32>(plaintext[i * 4]))       |
                   (static_cast<u32>(plaintext[i * 4 + 1]) << 8)  |
                   (static_cast<u32>(plaintext[i * 4 + 2]) << 16) |
                   (static_cast<u32>(plaintext[i * 4 + 3]) << 24);
    }

    for (int round = 0; round < SERPENT_ROUNDS; round++)
    {
    #pragma HLS PIPELINE II=2
        state[0] ^= round_keys[round][0];
        state[1] ^= round_keys[round][1];
        state[2] ^= round_keys[round][2];
        state[3] ^= round_keys[round][3];

        // S-boxes cycle S0, S1, ..., S7, S0, ...
        switch (round % 8)
        {
            case 0: sbox0_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 1: sbox1_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 2: sbox2_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 3: sbox3_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 4: sbox4_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 5: sbox5_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 6: sbox6_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 7: sbox7_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
        }

        if (round < SERPENT_ROUNDS - 1)
            linear_transform(state);
    }

    state[0] ^= round_keys[32][0];
    state[1] ^= round_keys[32][1];
    state[2] ^= round_keys[32][2];
    state[3] ^= round_keys[32][3];

    for (int i = 0; i < SERPENT_BLOCK_WORDS; i++)
    {
    #pragma HLS UNROLL
        ciphertext[i * 4]     =  state[i]        & 0xFF;
        ciphertext[i * 4 + 1] = (state[i] >> 8)  & 0xFF;
        ciphertext[i * 4 + 2] = (state[i] >> 16) & 0xFF;
        ciphertext[i * 4 + 3] = (state[i] >> 24) & 0xFF;
    }
}

void serpent_decrypt(const u8 ciphertext[16], const u8 key[], size_t key_length, u8 plaintext[16])
{
    u32 round_keys[33][4] = {{0}};
    generate_round_keys(key, key_length, round_keys);

    u32 state[SERPENT_BLOCK_WORDS] = {0};
    for (int i = 0; i < SERPENT_BLOCK_WORDS; i++)
    {
    #pragma HLS UNROLL
        state[i] = (static_cast<u32>(ciphertext[i * 4]))       |
                   (static_cast<u32>(ciphertext[i * 4 + 1]) << 8)  |
                   (static_cast<u32>(ciphertext[i * 4 + 2]) << 16) |
                   (static_cast<u32>(ciphertext[i * 4 + 3]) << 24);
    }

    state[0] ^= round_keys[32][0];
    state[1] ^= round_keys[32][1];
    state[2] ^= round_keys[32][2];
    state[3] ^= round_keys[32][3];

    for (int round = SERPENT_ROUNDS - 1; round >= 0; round--)
    {
    #pragma HLS PIPELINE II=3
        if (round < SERPENT_ROUNDS - 1)
            linear_transform_inverse(state);

        switch (round % 8)
        {
            case 0: sbox0_inv_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 1: sbox1_inv_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 2: sbox2_inv_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 3: sbox3_inv_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 4: sbox4_inv_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 5: sbox5_inv_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 6: sbox6_inv_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
            case 7: sbox7_inv_bitslice(&state[0], &state[1], &state[2], &state[3]); break;
        }

        state[0] ^= round_keys[round][0];
        state[1] ^= round_keys[round][1];
        state[2] ^= round_keys[round][2];
        state[3] ^= round_keys[round][3];
    }

    for (int i = 0; i < SERPENT_BLOCK_WORDS; i++)
    {
    #pragma HLS UNROLL
        plaintext[i * 4]     =  state[i]        & 0xFF;
        plaintext[i * 4 + 1] = (state[i] >> 8)  & 0xFF;
        plaintext[i * 4 + 2] = (state[i] >> 16) & 0xFF;
        plaintext[i * 4 + 3] = (state[i] >> 24) & 0xFF;
    }
}