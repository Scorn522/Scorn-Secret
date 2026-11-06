#pragma once

#include <array>
#include <span>
#include <string>
#include <vector>

namespace himitsu::validation::crypto {
std::array<unsigned char, 32> sha256(std::span<const unsigned char> input);
std::string sha256_hex(std::span<const unsigned char> input);
std::string base64_encode(std::span<const unsigned char> input);
std::vector<unsigned char> base64_decode(const std::string& input);
std::string random_token(unsigned long size);
bool constant_equals(
    std::span<const unsigned char> first,
    std::span<const unsigned char> second
);

std::vector<unsigned char> aes_gcm_decrypt(
    std::span<const unsigned char> key,
    std::span<const unsigned char> nonce,
    std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> tag
);

std::array<unsigned char, 32> hkdf_sha256(
    std::span<const unsigned char> salt,
    std::span<const unsigned char> info,
    unsigned long output_length
);
}
