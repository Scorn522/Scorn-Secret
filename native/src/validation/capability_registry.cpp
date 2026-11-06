#include "himitsu/validation/capability_registry.hpp"

#include "himitsu/validation/auth_crypto.hpp"

#include <windows.h>

#include <chrono>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>
#ifdef HIMITSU_LOCAL_TEST
#include "himitsu/local_test_build.hpp"
#include <limits>
#endif

namespace {
struct ManifestClaims {
    int protocol = 0;
    std::string tier;
    long long account_id = 0;
    std::string device_id;
    std::string hwid;
    std::string session_id;
    std::uint64_t feature_mask = 0;
    std::string payload_sha256;
    std::string payload_key;
    long long issued_at = 0;
    long long expires_at = 0;
};

struct PayloadClaims {
    int protocol = 0;
    std::string outer_secret;
    std::string class_secret;
    std::string dll_sha256;
};

struct SealedState {
    std::mutex mutex;
    bool active = false;
    std::uint64_t feature_mask = 0;
    std::string tier;
    std::string outer_secret;
    std::string class_secret;
    std::string dll_sha256;
    long long expires_at = 0;
};

SealedState state;

void wipe(std::string& value) {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
}

std::size_t field_position(const std::string& json, const char* name) {
    const std::string token = std::string("\"") + name + "\"";
    std::size_t position = json.find(token);
    if (position == std::string::npos) {
        throw std::runtime_error(std::string("Missing field: ") + name);
    }
    position = json.find(':', position + token.size());
    if (position == std::string::npos) {
        throw std::runtime_error(std::string("Malformed field: ") + name);
    }
    do {
        ++position;
    } while (position < json.size()
        && (json[position] == ' '
            || json[position] == '\t'
            || json[position] == '\r'
            || json[position] == '\n'));
    return position;
}

std::string json_string(const std::string& json, const char* name) {
    std::size_t position = field_position(json, name);
    if (position >= json.size() || json[position++] != '"') {
        throw std::runtime_error(std::string("Field is not a string: ") + name);
    }
    std::string output;
    while (position < json.size()) {
        const char character = json[position++];
        if (character == '"') return output;
        if (character != '\\') {
            output.push_back(character);
            continue;
        }
        if (position >= json.size()) break;
        const char escaped = json[position++];
        switch (escaped) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            default: throw std::runtime_error("Unsupported JSON escape");
        }
    }
    throw std::runtime_error("Unterminated JSON string");
}

long long json_integer(const std::string& json, const char* name) {
    const std::size_t position = field_position(json, name);
    std::size_t consumed = 0;
    const long long value = std::stoll(json.substr(position), &consumed);
    if (consumed == 0) throw std::runtime_error("Invalid JSON integer");
    return value;
}

ManifestClaims parse_manifest(const std::string& json) {
    return {
        static_cast<int>(json_integer(json, "protocol")),
        json_string(json, "tier"),
        json_integer(json, "account_id"),
        json_string(json, "device_id"),
        json_string(json, "hwid"),
        json_string(json, "session_id"),
        static_cast<std::uint64_t>(json_integer(json, "feature_mask")),
        json_string(json, "payload_sha256"),
        json_string(json, "payload_key"),
        json_integer(json, "issued_at"),
        json_integer(json, "expires_at")
    };
}

PayloadClaims parse_payload(const std::string& json) {
    return {
        static_cast<int>(json_integer(json, "protocol")),
        json_string(json, "outer_secret"),
        json_string(json, "class_secret"),
        json_string(json, "dll_sha256")
    };
}

bool valid_hex_sha256(const std::string& value) {
    if (value.size() != 64) return false;
    for (const char character : value) {
        if (!((character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}
}

namespace himitsu::validation::capability {
#ifdef HIMITSU_LOCAL_TEST
bool initialize_local_test(void* module) {
    if (module == nullptr) return false;
    wchar_t path[32768]{};
    const DWORD length = GetModuleFileNameW(static_cast<HMODULE>(module), path, 32768);
    if (length == 0 || length >= 32768) return false;
    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    struct FileCloser { HANDLE handle; ~FileCloser() { CloseHandle(handle); } } closer{handle};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle, &size) || size.QuadPart <= 0 || size.QuadPart > 64 * 1024 * 1024) return false;
    try {
        std::vector<unsigned char> bytes(static_cast<std::size_t>(size.QuadPart));
        DWORD count = 0;
        if (!ReadFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr)
                || count != bytes.size()) return false;
        const auto hash = crypto::sha256_hex(bytes);
        std::lock_guard lock(state.mutex);
        state.tier = "local-test";
        state.feature_mask = (1ULL << 10) - 1;
        state.outer_secret = himitsu::local_test::outer_secret;
        state.class_secret = himitsu::local_test::class_secret;
        state.dll_sha256 = hash;
        state.expires_at = std::numeric_limits<long long>::max();
        state.active = true;
        return true;
    } catch (...) {
        return false;
    }
}
#endif
bool initialize(
    std::span<const unsigned char> encrypted_payload,
    std::span<const unsigned char> manifest_bytes,
    const std::string& device_id,
    const std::string& hwid,
    const std::string& session_id
) {
    if (encrypted_payload.size() < 28 || manifest_bytes.empty()) return false;

    ManifestClaims manifest;
    PayloadClaims payload;
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> payload_key;
    try {
        manifest = parse_manifest(std::string(
            reinterpret_cast<const char*>(manifest_bytes.data()),
            manifest_bytes.size()
        ));
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        if (manifest.protocol != 1
            || manifest.account_id <= 0
            || manifest.tier.empty()
            || manifest.device_id != device_id
            || manifest.hwid != hwid
            || manifest.session_id != session_id
            || manifest.expires_at <= now
            || manifest.issued_at > now + 60
            || manifest.issued_at < now - 900
            || manifest.expires_at - manifest.issued_at > 24 * 60 * 60
            || manifest.payload_sha256 != crypto::sha256_hex(encrypted_payload)) {
            return false;
        }

        payload_key = crypto::base64_decode(manifest.payload_key);
        if (payload_key.size() != 32) return false;
        const std::size_t ciphertext_size = encrypted_payload.size() - 28;
        plaintext = crypto::aes_gcm_decrypt(
            payload_key,
            encrypted_payload.first(12),
            encrypted_payload.subspan(12, ciphertext_size),
            encrypted_payload.last(16)
        );
        if (plaintext.empty() || plaintext.size() > 4096) return false;
        payload = parse_payload(std::string(
            reinterpret_cast<const char*>(plaintext.data()),
            plaintext.size()
        ));
        if (payload.protocol != 1
            || payload.outer_secret.size() < 32
            || payload.outer_secret.size() > 128
            || payload.class_secret.size() < 32
            || payload.class_secret.size() > 128
            || !valid_hex_sha256(payload.dll_sha256)) {
            return false;
        }
    } catch (...) {
        if (!payload_key.empty()) SecureZeroMemory(payload_key.data(), payload_key.size());
        if (!plaintext.empty()) SecureZeroMemory(plaintext.data(), plaintext.size());
        return false;
    }

    if (!payload_key.empty()) SecureZeroMemory(payload_key.data(), payload_key.size());
    if (!plaintext.empty()) SecureZeroMemory(plaintext.data(), plaintext.size());
    std::lock_guard lock(state.mutex);
    wipe(state.outer_secret);
    wipe(state.class_secret);
    state.active = true;
    state.feature_mask = manifest.feature_mask;
    state.tier = std::move(manifest.tier);
    state.outer_secret = std::move(payload.outer_secret);
    state.class_secret = std::move(payload.class_secret);
    state.dll_sha256 = std::move(payload.dll_sha256);
    state.expires_at = manifest.expires_at;
    return true;
}

bool is_enabled(Feature feature) {
    std::lock_guard lock(state.mutex);
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    return state.active
        && state.expires_at > now
        && (state.feature_mask & static_cast<std::uint64_t>(feature)) != 0;
}

bool valid() {
    std::lock_guard lock(state.mutex);
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    return state.active
        && state.expires_at > now
        && state.feature_mask != 0
        && !state.outer_secret.empty()
        && !state.class_secret.empty()
        && valid_hex_sha256(state.dll_sha256);
}

std::string payload_secret(bool class_payload) {
    std::lock_guard lock(state.mutex);
    return class_payload ? state.class_secret : state.outer_secret;
}

std::string dll_sha256() {
    std::lock_guard lock(state.mutex);
    return state.dll_sha256;
}

void revoke() {
    std::lock_guard lock(state.mutex);
    state.active = false;
    state.feature_mask = 0;
    state.tier.clear();
    wipe(state.outer_secret);
    wipe(state.class_secret);
    state.dll_sha256.clear();
    state.expires_at = 0;
}

void stop() {
    revoke();
}
}
