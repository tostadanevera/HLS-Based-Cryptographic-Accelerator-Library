#ifndef SERPENT_TOP_H
#define SERPENT_TOP_H

#include "../serpent.h"

// mode: 0 = encrypt, 1 = decrypt
// key_length is in BYTES (16, 24, or 32), the core handles padding internally
int serpent_top(const u8 key[SERPENT_MAX_KEY_WORDS * 4],
                u32 key_length,
                const u8 input[16],
                u8 output[16],
                u32 mode);

#endif // SERPENT_TOP_H