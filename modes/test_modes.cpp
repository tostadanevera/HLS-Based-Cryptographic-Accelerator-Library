#include "modes.h"
#include "../aes/aes.h"
#include "../serpent/serpent.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <array>

namespace {

// --- Adapters: make each cipher's native API match block_op_fn ---

void aes_encrypt_adapter(const u8 in[MODES_BLOCK_BYTES], const u8* key, size_t /*key_len*/, u8 out[MODES_BLOCK_BYTES])
{
    std::array<u8, AES_STATE_SIZE> pt, ct;
    std::array<u8, AES_KEY_SIZE> k;
    memcpy(pt.data(), in, AES_STATE_SIZE);
    memcpy(k.data(), key, AES_KEY_SIZE);
    aes_encrypt(pt, k, ct);
    memcpy(out, ct.data(), AES_STATE_SIZE);
}

void aes_decrypt_adapter(const u8 in[MODES_BLOCK_BYTES], const u8* key, size_t /*key_len*/, u8 out[MODES_BLOCK_BYTES])
{
    std::array<u8, AES_STATE_SIZE> ct, pt;
    std::array<u8, AES_KEY_SIZE> k;
    memcpy(ct.data(), in, AES_STATE_SIZE);
    memcpy(k.data(), key, AES_KEY_SIZE);
    aes_decrypt(ct, k, pt);
    memcpy(out, pt.data(), AES_STATE_SIZE);
}

// Serpent's signature matches block_op_fn, can be passed straight through with no adapter

std::string to_hex(const u8* data, size_t len)
{
    static const char* digits = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (size_t i = 0; i < len; i++)
    {
        out[2 * i]     = digits[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = digits[data[i] & 0xF];
    }
    return out;
}

int total = 0, passed = 0;

void check(const std::string& name, bool ok)
{
    total++;
    if (ok) passed++;
    printf("  %-32s %s\n", name.c_str(), ok ? "[OK]" : "[FAIL]");
}

} // namespace

int main()
{
    // Reference vectors generated with Python's `cryptography` library
    const u8 key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    const u8 iv[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    u8 pt[32];
    for (int i = 0; i < 32; i++) pt[i] = static_cast<u8>(i);

    const std::string expected_ecb = "50fe67cc996d32b6da0937e99bafec60c84af0b613435d5d9182801a9bd9320b";
    const std::string expected_cbc = "7df76b0c1ab899b33e42f047b91b546f1caa8018c80b15b8e7aea82794adcb00";
    const std::string expected_ctr = "50ff65cf9d6834b1d2003de297a2e26fbf309c5d93f685bdc22851ff67eabd40";

    printf("AES modes-of-operation:\n");

    // ECB
    {
        u8 ct[48] = {0};
        size_t ct_len = ecb_encrypt_pkcs7(aes_encrypt_adapter, key, 16, pt, 32, ct);
        check("ECB encrypt matches reference (first 2 blocks)", to_hex(ct, 32) == expected_ecb);
        check("ECB encrypt appended a pad block", ct_len == 48);

        u8 dec[48] = {0};
        size_t dec_len = ecb_decrypt_pkcs7(aes_decrypt_adapter, key, 16, ct, ct_len, dec);
        check("ECB decrypt round-trip", dec_len == 32 && memcmp(dec, pt, 32) == 0);
    }

    // CBC
    {
        u8 ct[48] = {0};
        size_t ct_len = cbc_encrypt_pkcs7(aes_encrypt_adapter, key, 16, iv, pt, 32, ct);
        check("CBC encrypt matches reference (first 2 blocks)", to_hex(ct, 32) == expected_cbc);
        check("CBC encrypt appended a pad block", ct_len == 48);

        u8 dec[48] = {0};
        size_t dec_len = cbc_decrypt_pkcs7(aes_decrypt_adapter, key, 16, iv, ct, ct_len, dec);
        check("CBC decrypt round-trip", dec_len == 32 && memcmp(dec, pt, 32) == 0);
    }

    // CTR
    {
        u8 ct[32] = {0};
        ctr_crypt(aes_encrypt_adapter, key, 16, iv, pt, 32, ct);
        check("CTR matches reference", to_hex(ct, 32) == expected_ctr);

        u8 dec[32] = {0};
        ctr_crypt(aes_encrypt_adapter, key, 16, iv, ct, 32, dec);
        check("CTR round-trip", memcmp(dec, pt, 32) == 0);
    }

    // Edge cases: empty message, and a message that is an exact multiple of the block size
    {
        u8 ct[16] = {0}, dec[16] = {0};
        size_t ct_len = ecb_encrypt_pkcs7(aes_encrypt_adapter, key, 16, pt, 0, ct);
        size_t dec_len = ecb_decrypt_pkcs7(aes_decrypt_adapter, key, 16, ct, ct_len, dec);
        check("ECB empty-message round-trip", ct_len == 16 && dec_len == 0);

        u8 ct2[48] = {0}, dec2[32] = {0};
        size_t ct2_len = ecb_encrypt_pkcs7(aes_encrypt_adapter, key, 16, pt, 32, ct2);
        size_t dec2_len = ecb_decrypt_pkcs7(aes_decrypt_adapter, key, 16, ct2, ct2_len, dec2);
        check("ECB block-aligned message gets full pad block", ct2_len == 48);
        check("ECB block-aligned round-trip", dec2_len == 32 && memcmp(dec2, pt, 32) == 0);
    }

    // Serpent, wired straight into the same generic modes
    // No external Serpent KAT is available, checks round-trip self-consistency
    printf("\nSerpent through the same generic modes (round-trip only, see Serpent caveat):\n");
    {
        const u8 skey[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        u8 sct[48] = {0}, sdec[32] = {0};

        size_t ct_len = ecb_encrypt_pkcs7(serpent_encrypt, skey, 16, pt, 32, sct);
        size_t dec_len = ecb_decrypt_pkcs7(serpent_decrypt, skey, 16, sct, ct_len, sdec);
        check("Serpent ECB round-trip", dec_len == 32 && memcmp(sdec, pt, 32) == 0);

        memset(sct, 0, sizeof(sct)); memset(sdec, 0, sizeof(sdec));
        ct_len = cbc_encrypt_pkcs7(serpent_encrypt, skey, 16, iv, pt, 32, sct);
        dec_len = cbc_decrypt_pkcs7(serpent_decrypt, skey, 16, iv, sct, ct_len, sdec);
        check("Serpent CBC round-trip", dec_len == 32 && memcmp(sdec, pt, 32) == 0);

        u8 sct_ctr[32] = {0}, sdec_ctr[32] = {0};
        ctr_crypt(serpent_encrypt, skey, 16, iv, pt, 32, sct_ctr);
        ctr_crypt(serpent_encrypt, skey, 16, iv, sct_ctr, 32, sdec_ctr);
        check("Serpent CTR round-trip", memcmp(sdec_ctr, pt, 32) == 0);
    }

    printf("\n%d/%d tests passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
