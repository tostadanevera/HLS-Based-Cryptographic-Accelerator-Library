#include "sha3_top.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::vector<u8> hex_to_bytes(const std::string& hex)
{
    std::vector<u8> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++)
        out[i] = static_cast<u8>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
    return out;
}

std::string bytes_to_hex(const u8* bytes, size_t len)
{
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    return oss.str();
}

struct TestVector { const char* message_hex; const char* expected_hex; const char* label; };

// Representative subset of NIST CAVS vectors
const TestVector test_vectors[] =
{
    {"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "Len=0"},
    {"e9", "f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6", "Len=8"},
    {"d477", "94279e8f5ccdf6e17f292b59698ab4e614dfe696a46c46da78305fc6a3146ab7", "Len=16"},
    {"e7372105", "3a42b68ab079f28c4ca3c752296f279006c4fe78b1eb79d989777f051e4046ae", "Len=32"},
    {"8bca931c8a132d2f", "dbb8be5dec1d715bd117b24566dc3f24f2cc0c799795d0638d9537481ef1e03e", "Len=64"},
    {"d83c721ee51b060c5a41438a8221e040", "b87d9e4722edd3918729ded9a6d03af8256998ee088a1ae662ef4bcaff142a96", "Len=128"},
    {"c178ce0f720a6d73c6cf1caa905ee724d5ba941c2e2628136e3aad7d853733ba", "64537b87892835ff0963ef9ad5145ab4cfce5d303a0cb0415b3b03f9d16e7d6b", "Len=256"},
    {"67e384d209f1bc449fa67da6ce5fbbe84f4610129f2f0b40f7c0caea7ed5cb69be22ffb7541b2077ec1045356d9db4ee7141f7d3f84d324a5d00b33689f0cb78", "9c9160268608ef09fe0bd3927d3dffa0c73499c528943e837be467b50e5c1f1e", "Len=512"},
    {"84b60cb3720bf29748483cf7abd0d1f1d9380459dfa968460c86e5d1a54f0b19dac6a78bf9509460e29dd466bb8bdf04e5483b782eb74d6448166f897add43d295e946942ad9a814fab95b4aaede6ae4c8108c8edaeff971f58f7cf96566c9dc9b6812586b70d5bc78e2f829ec8e179a6cd81d224b161175fd3a33aacfb1483f", "8814630a39dcb99792cc4e08cae5dd078973d15cd19f17bacf04deda9e62c45f", "Len=1024"},
};

} // namespace

int main()
{
    int total = 0, passed = 0;

    std::cout << "SHA3-256 HLS wrapper tests" << std::endl;

    for (const auto& v : test_vectors)
    {
        total++;

        std::vector<u8> msg = hex_to_bytes(v.message_hex);

        u8 message_buf[SHA3_MAX_MESSAGE_BYTES] = {0};
        std::memcpy(message_buf, msg.data(), msg.size());

        u8 hash[SHA3_256_HASH_BYTES];
        int rc = sha3_top(message_buf, static_cast<u32>(msg.size()), hash);

        std::string hex = bytes_to_hex(hash, SHA3_256_HASH_BYTES);

        bool ok = (rc == 0) && (hex == std::string(v.expected_hex));
        std::cout << "  " << v.label << " -> " << hex
                  << (ok ? " [OK]" : " [FAIL]") << std::endl;
        if (!ok)
            std::cout << "       expected: " << v.expected_hex << std::endl;

        if (ok) passed++;
    }

    total++;
    u8 big[SHA3_MAX_MESSAGE_BYTES] = {0};
    u8 hash[SHA3_256_HASH_BYTES];
    int rc = sha3_top(big, SHA3_MAX_MESSAGE_BYTES + 1, hash);
    bool overflow_ok = (rc == -1);
    std::cout << "  oversized input rejected: " << (overflow_ok ? "[OK]" : "[FAIL]") << std::endl;
    if (overflow_ok) passed++;

    std::cout << passed << "/" << total << " tests passed" << std::endl;
    return (passed == total) ? 0 : 1;
}