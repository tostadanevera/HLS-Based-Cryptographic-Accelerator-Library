#include "sha256_top.h"

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

std::string hash_to_hex(const u32 hash[SHA256_HASH_WORDS])
{
    std::ostringstream oss;
    for (int i = 0; i < SHA256_HASH_WORDS; i++)
        oss << std::hex << std::setfill('0') << std::setw(8) << hash[i];
    return oss.str();
}

struct TestVector { const char* message_hex; const char* expected_hex; const char* label; };

// Representative subset of NIST CAVS
const TestVector test_vectors[] =
{
    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Len=0"},
    {"d3", "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1", "Len=8"},
    {"11af", "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98", "Len=16"},
    {"74ba2521", "b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e", "Len=32"},
    {"5738c929c4f4ccb6", "963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf", "Len=64"},
    {"0a27847cdc98bd6f62220b046edd762b", "80c25ec1600587e7f28b18b1b18e3cdc89928e39cab3bc25e4d4a4c139bcedc4", "Len=128"},
    {"09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95", "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4", "Len=256"},
    {"5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509", "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa", "Len=512"},
};

} // namespace

int main()
{
    int total = 0, passed = 0;

    std::cout << "SHA-256 HLS wrapper tests" << std::endl;

    for (const auto& v : test_vectors)
    {
        total++;

        std::vector<u8> msg = hex_to_bytes(v.message_hex);

        u8 msg_buf[SHA256_MAX_MESSAGE_BYTES] = {0};
        std::memcpy(msg_buf, msg.data(), msg.size());

        u32 hash[SHA256_HASH_WORDS];
        int rc = sha256_top(msg_buf, static_cast<u32>(msg.size()), hash);

        std::string hex = hash_to_hex(hash);

        bool ok = (rc == 0) && (hex == std::string(v.expected_hex));
        std::cout << "  " << v.label << " -> " << hex
                  << (ok ? " [OK]" : " [FAIL]") << std::endl;
        if (!ok)
            std::cout << "       expected: " << v.expected_hex << std::endl;

        if (ok) passed++;
    }

    total++;
    u8 big[SHA256_MAX_MESSAGE_BYTES] = {0};
    u32 hash[SHA256_HASH_WORDS];
    int rc = sha256_top(big, SHA256_MAX_MESSAGE_BYTES, hash);
    bool overflow_ok = (rc == -1);
    std::cout << "  oversized input rejected: " << (overflow_ok ? "[OK]" : "[FAIL]") << std::endl;
    if (overflow_ok) passed++;

    std::cout << passed << "/" << total << " tests passed" << std::endl;
    return (passed == total) ? 0 : 1;
}