#include "aes_top.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

namespace {
 
void hex_to_bytes(const std::string& hex, u8* out, int len)
{
    for (int i = 0; i < len; i++)
        out[i] = static_cast<u8>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
}
 
std::string bytes_to_hex(const u8* bytes, int len)
{
    std::ostringstream oss;
    for (int i = 0; i < len; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    return oss.str();
}

struct TestVector { const char* key; const char* plain; const char* cipher; };

const TestVector test_vectors[] =
{
    // AESVS GFSbox test data
    {"00000000000000000000000000000000", "f34481ec3cc627bacd5dc3fb08f273e6", "0336763e966d92595a567cc9ce537f5e"},
    {"00000000000000000000000000000000", "9798c4640bad75c7c3227db910174e72", "a9a1631bf4996954ebc093957b234589"},
    {"00000000000000000000000000000000", "96ab5c2ff612d9dfaae8c31f30c42168", "ff4f8391a6a40ca5b25d23bedd44a597"},
    {"00000000000000000000000000000000", "6a118a874519e64e9963798a503f1d35", "dc43be40be0e53712f7e2bf5ca707209"},
    {"00000000000000000000000000000000", "cb9fceec81286ca3e989bd979b0cb284", "92beedab1895a94faa69b632e5cc47ce"},

    // AESVS KeySbox test data
    {"10a58869d74be5a374cf867cfb473859", "00000000000000000000000000000000", "6d251e6944b051e04eaa6fb4dbf78465"},
    {"caea65cdbb75e9169ecd22ebe6e54675", "00000000000000000000000000000000", "6e29201190152df4ee058139def610bb"},
    {"a2e2fa9baf7d20822ca9f0542f764a41", "00000000000000000000000000000000", "c3b44b95d9d2f25670eee9a0de099fa3"},
    {"b6364ac4e1de1e285eaf144a2415f7a0", "00000000000000000000000000000000", "5d9b05578fc944b3cf1ccf0e746cd581"},
    {"64cf9c7abc50b888af65f49d521944b2", "00000000000000000000000000000000", "f7efc89d5dba578104016ce5ad659c05"},

    // NIST, FIPS 197 ECB-AES128
    {"2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"},
    {"2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"},
    {"2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"},
    {"2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"},

    // Edge cases
    {"00000000000000000000000000000000", "00000000000000000000000000000000", "66e94bd4ef8a2c3b884cfa59ca342b2e"},
    {"ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff", "bcbf217cb280cf30b2517052193ab979"},
    {"00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "7aca0fd9bcd6ec7c9f97466616e6a282"},
    {"000102030405060708090a0b0c0d0e0f", "ffffffffffffffffffffffffffffffff", "3c441f32ce07822364d7a2990e50bb13"},
};
 
} // namespace
 
int main()
{
    int total = 0, passed = 0;
    std::cout << "AES-128 HLS wrapper tests" << std::endl;
 
    for (const auto& v : test_vectors)
    {
        total++;
 
        u8 key[AES_KEY_SIZE];
        u8 plain[AES_STATE_SIZE];
        u8 expected_cipher[AES_STATE_SIZE];
 
        hex_to_bytes(v.key, key, AES_KEY_SIZE);
        hex_to_bytes(v.plain, plain, AES_STATE_SIZE);
        hex_to_bytes(v.cipher, expected_cipher, AES_STATE_SIZE);
 
        u8 cipher_out[AES_STATE_SIZE];
        aes128_top(key, plain, cipher_out, 0);
        bool enc_ok = true;
        for (int i = 0; i < AES_STATE_SIZE; i++)
            if (cipher_out[i] != expected_cipher[i]) enc_ok = false;
 
        u8 plain_out[AES_STATE_SIZE];
        aes128_top(key, expected_cipher, plain_out, 1);
        bool dec_ok = true;
        for (int i = 0; i < AES_STATE_SIZE; i++)
            if (plain_out[i] != plain[i]) dec_ok = false;
 
        std::cout << "  key = " << v.key << std::endl;
        std::cout << "    encrypt: " << bytes_to_hex(cipher_out, AES_STATE_SIZE)
                   << (enc_ok ? " [OK]" : " [FAIL]") << std::endl;
        std::cout << "    decrypt: " << bytes_to_hex(plain_out, AES_STATE_SIZE)
                   << (dec_ok ? " [OK]" : " [FAIL]") << std::endl;
 
        if (enc_ok && dec_ok) passed++;
    }
 
    std::cout << passed << "/" << total << " tests passed" << std::endl;
    return (passed == total) ? 0 : 1;
}
 
