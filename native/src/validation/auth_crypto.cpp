#include "himitsu/validation/auth_crypto.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace himitsu::validation::crypto {
std::array<unsigned char, 32> sha256(std::span<const unsigned char> input) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD returned = 0;
    std::vector<unsigned char> object;
    std::array<unsigned char, 32> digest{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0
        || BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &returned,
            0
        ) < 0) {
        if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("SHA-256 provider initialization failed");
    }
    object.resize(object_size);
    bool success = BCryptCreateHash(
        algorithm,
        &hash,
        object.data(),
        object_size,
        nullptr,
        0,
        0
    ) >= 0;
    if (success && !input.empty()) {
        success = BCryptHashData(
            hash,
            const_cast<PUCHAR>(input.data()),
            static_cast<ULONG>(input.size()),
            0
        ) >= 0;
    }
    if (success) {
        success = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    }
    if (hash != nullptr) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!success) throw std::runtime_error("SHA-256 operation failed");
    return digest;
}

std::string sha256_hex(std::span<const unsigned char> input) {
    const auto digest = sha256(input);
    std::string result;
    result.reserve(digest.size() * 2);
    char value[3]{};
    for (unsigned char byte : digest) {
        std::snprintf(value, sizeof(value), "%02x", byte);
        result.append(value);
    }
    return result;
}

std::string base64_encode(std::span<const unsigned char> input) {
    DWORD size = 0;
    if (!CryptBinaryToStringA(
            input.data(),
            static_cast<DWORD>(input.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr,
            &size
        )) {
        throw std::runtime_error("Base64 size calculation failed");
    }
    std::string result(size, '\0');
    if (!CryptBinaryToStringA(
            input.data(),
            static_cast<DWORD>(input.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            result.data(),
            &size
        )) {
        throw std::runtime_error("Base64 encoding failed");
    }
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

std::vector<unsigned char> base64_decode(const std::string& input) {
    DWORD size = 0;
    if (!CryptStringToBinaryA(
            input.c_str(),
            static_cast<DWORD>(input.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &size,
            nullptr,
            nullptr
        )) {
        throw std::runtime_error("Invalid Base64 data");
    }
    std::vector<unsigned char> result(size);
    if (!CryptStringToBinaryA(
            input.c_str(),
            static_cast<DWORD>(input.size()),
            CRYPT_STRING_BASE64,
            result.data(),
            &size,
            nullptr,
            nullptr
        )) {
        throw std::runtime_error("Base64 decoding failed");
    }
    result.resize(size);
    return result;
}

std::string random_token(unsigned long size) {
    std::vector<unsigned char> bytes(size);
    if (BCryptGenRandom(nullptr, bytes.data(), size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw std::runtime_error("Secure random generation failed");
    }
    return base64_encode(bytes);
}

bool constant_equals(
    std::span<const unsigned char> first,
    std::span<const unsigned char> second
) {
    if (first.size() != second.size()) return false;
    unsigned char difference = 0;
    for (std::size_t index = 0; index < first.size(); ++index) {
        difference |= first[index] ^ second[index];
    }
    return difference == 0;
}

std::vector<unsigned char> aes_gcm_decrypt(
    std::span<const unsigned char> key,
    std::span<const unsigned char> nonce,
    std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> tag
) {
    BCRYPT_ALG_HANDLE aes = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    DWORD object_size = 0;
    DWORD returned = 0;
    std::vector<unsigned char> key_object;
    std::vector<unsigned char> plaintext;
    bool ok = false;
    do {
        if (BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0
            || BCryptSetProperty(aes, BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                static_cast<DWORD>(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0) < 0
            || BCryptGetProperty(aes, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0) < 0) break;
        key_object.resize(object_size);
        if (BCryptGenerateSymmetricKey(aes, &key_handle, key_object.data(), object_size,
                const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0) < 0) break;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth{};
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = const_cast<PUCHAR>(nonce.data());
        auth.cbNonce = static_cast<ULONG>(nonce.size());
        auth.pbTag = const_cast<PUCHAR>(tag.data());
        auth.cbTag = static_cast<ULONG>(tag.size());
        plaintext.resize(ciphertext.size());
        ULONG written = 0;
        if (BCryptDecrypt(key_handle, const_cast<PUCHAR>(ciphertext.data()),
                static_cast<ULONG>(ciphertext.size()), &auth, nullptr, 0,
                plaintext.data(), static_cast<ULONG>(plaintext.size()), &written, 0) < 0) break;
        plaintext.resize(written);
        ok = true;
    } while (false);
    if (key_handle != nullptr) BCryptDestroyKey(key_handle);
    if (aes != nullptr) BCryptCloseAlgorithmProvider(aes, 0);
    if (!ok) throw std::runtime_error("AES-GCM decryption failed");
    return plaintext;
}

static std::vector<unsigned char> hmac_sha256_raw(
    std::span<const unsigned char> key_bytes,
    std::span<const unsigned char> data
) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD hash_size = 0;
    DWORD object_size = 0;
    DWORD returned = 0;
    std::vector<unsigned char> hash_object;
    std::array<unsigned char, 32> result{};
    bool ok = false;
    do {
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) break;
        if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size), &returned, 0) < 0) break;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0) < 0) break;
        hash_object.resize(object_size);
        if (BCryptCreateHash(alg, &hash, hash_object.data(), object_size,
                const_cast<PUCHAR>(key_bytes.data()), static_cast<ULONG>(key_bytes.size()), 0) < 0) break;
        if (!data.empty() && BCryptHashData(hash, const_cast<PUCHAR>(data.data()),
                static_cast<ULONG>(data.size()), 0) < 0) break;
        if (BCryptFinishHash(hash, result.data(), hash_size, 0) < 0) break;
        ok = true;
    } while (false);
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (alg != nullptr) BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) throw std::runtime_error("HMAC-SHA256 failed");
    return std::vector<unsigned char>(result.begin(), result.begin() + hash_size);
}

std::array<unsigned char, 32> hkdf_sha256(
    std::span<const unsigned char> salt,
    std::span<const unsigned char> info,
    unsigned long output_length
) {
    std::vector<unsigned char> initial_salt(salt.data(), salt.data() + salt.size());
    if (initial_salt.empty()) initial_salt.resize(32, 0);
    auto prk = hmac_sha256_raw(initial_salt, {});
    std::vector<unsigned char> okm;
    for (unsigned char c = 1; okm.size() < output_length; ++c) {
        std::vector<unsigned char> round_data(okm);
        round_data.insert(round_data.end(), info.begin(), info.end());
        round_data.push_back(c);
        auto t_block = hmac_sha256_raw(prk, round_data);
        okm.insert(okm.end(), t_block.begin(),
            t_block.begin() + (std::min)(static_cast<std::size_t>(32),
                output_length - okm.size()));
    }
    std::array<unsigned char, 32> result{};
    std::memcpy(result.data(), okm.data(), (std::min)(okm.size(), static_cast<std::size_t>(32)));
    return result;
}
}
