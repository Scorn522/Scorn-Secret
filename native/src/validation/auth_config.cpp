#include "himitsu/validation/auth_config.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace {
__declspec(noinline) std::uint16_t stream_word(std::size_t index, std::uint32_t domain) {
    volatile std::uint32_t value = 0xA5C39E71U
        ^ domain
        ^ (static_cast<std::uint32_t>(index) * 0x045D9F3BU);
    value ^= value >> 16U;
    value *= 0x7FEB352DU;
    value ^= value >> 15U;
    value *= 0x846CA68BU;
    value ^= value >> 16U;
    return static_cast<std::uint16_t>((value >> 16U) ^ value);
}

__declspec(noinline) unsigned char stream_byte(std::size_t index, std::uint32_t domain) {
    return static_cast<unsigned char>(stream_word(index, domain));
}

constexpr std::array<std::uint16_t, 31> encoded_endpoint = {
    0xE34E, 0x544D, 0x16B7, 0x3DDA, 0x1D1F, 0x3F96, 0x126D, 0xCAA9,
    0xE119, 0x4513, 0x2385, 0xF377, 0x336B, 0x0A37, 0x30C2, 0xC8C0,
    0x8069, 0xA698, 0xE17A, 0x564D, 0xAE14, 0x8F10, 0xBD07, 0xD8F8,
    0xC811, 0x61A2, 0x894D, 0xCDB8, 0x4A99, 0x246A, 0x5B68
};

constexpr std::array<unsigned char, 10> encoded_build_id = {
    0x4C, 0x49, 0x2D, 0xCC, 0xBF, 0x4F, 0x93, 0x7B, 0x68, 0xB7
};

constexpr std::array<unsigned char, 32> encoded_certificate_sha256 = {
    0x02, 0x77, 0xF8, 0x15, 0xD4, 0xCC, 0x69, 0xCC,
    0x0E, 0x65, 0x1C, 0xDF, 0xF4, 0xA0, 0x80, 0x15,
    0xDD, 0xDC, 0xAB, 0x3E, 0x5F, 0xDF, 0x16, 0xF3,
    0xB0, 0x99, 0x44, 0x62, 0x99, 0x36, 0x39, 0x93
};
}

namespace himitsu::validation::auth_config {
std::wstring endpoint() {
    std::wstring decoded(encoded_endpoint.size(), L'\0');
    for (std::size_t index = 0; index < encoded_endpoint.size(); ++index) {
        decoded[index] = static_cast<wchar_t>(
            encoded_endpoint[index] ^ stream_word(index, 0x13579BDFU)
        );
    }
    return decoded;
}

std::string build_id() {
    std::string decoded(encoded_build_id.size(), '\0');
    for (std::size_t index = 0; index < encoded_build_id.size(); ++index) {
        decoded[index] = static_cast<char>(
            encoded_build_id[index] ^ stream_byte(index, 0x2468ACE0U)
        );
    }
    return decoded;
}

bool allow_pinned_self_signed() {
    volatile std::uint32_t encoded = 0x91E2A74CU;
    return (encoded ^ 0x91E2A74DU) != 0;
}

std::array<unsigned char, 32> certificate_sha256() {
    std::array<unsigned char, 32> decoded{};
    for (std::size_t index = 0; index < encoded_certificate_sha256.size(); ++index) {
        decoded[index] = encoded_certificate_sha256[index]
            ^ stream_byte(index, 0xC371F00DU);
    }
    return decoded;
}
}
