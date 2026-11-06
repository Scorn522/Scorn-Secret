#include "himitsu/validation/device_identity.hpp"

#include "himitsu/validation/auth_crypto.hpp"

#include <bcrypt.h>
#include <windows.h>

#include <array>
#include <cstdio>
#include <stdexcept>

namespace {
constexpr wchar_t device_key_name[] = L"HimitsuSecretDeviceKeyV1";

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (size <= 0) return {};
    std::string result(size, '\0');
    WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        size,
        nullptr,
        nullptr
    );
    return result;
}

std::wstring registry_machine_guid() {
    std::array<wchar_t, 256> value{};
    DWORD size = static_cast<DWORD>(value.size() * sizeof(wchar_t));
    if (RegGetValueW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography",
            L"MachineGuid",
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            nullptr,
            value.data(),
            &size
        ) != ERROR_SUCCESS) {
        return {};
    }
    return value.data();
}

std::string smbios_uuid() {
    constexpr DWORD provider = 'R' | ('S' << 8) | ('M' << 16) | ('B' << 24);
    const UINT size = GetSystemFirmwareTable(provider, 0, nullptr, 0);
    if (size < 8 || size > 4 * 1024 * 1024) return {};
    std::vector<unsigned char> data(size);
    if (GetSystemFirmwareTable(provider, 0, data.data(), size) != size) return {};
    const DWORD table_length = *reinterpret_cast<const DWORD*>(data.data() + 4);
    if (table_length > data.size() - 8) return {};
    const unsigned char* current = data.data() + 8;
    const unsigned char* end = current + table_length;
    while (current + 4 <= end) {
        const unsigned char type = current[0];
        const unsigned char length = current[1];
        if (length < 4 || current + length > end) break;
        if (type == 1 && length >= 24) {
            constexpr char digits[] = "0123456789abcdef";
            std::string output;
            output.reserve(32);
            for (int index = 0; index < 16; ++index) {
                const unsigned char value = current[8 + index];
                output.push_back(digits[value >> 4U]);
                output.push_back(digits[value & 0x0FU]);
            }
            return output;
        }
        const unsigned char* next = current + length;
        while (next + 1 < end && (next[0] != 0 || next[1] != 0)) ++next;
        current = next + 2;
        if (type == 127) break;
    }
    return {};
}

std::string collect_hwid() {
    std::array<wchar_t, MAX_PATH> windows{};
    GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    wchar_t root[] = L"C:\\";
    if (windows[1] == L':') root[0] = windows[0];
    DWORD volume_serial = 0;
    GetVolumeInformationW(root, nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0);

    char serial[16]{};
    std::snprintf(serial, sizeof(serial), "%x", volume_serial);
    const std::string value = "v2|" + utf8(registry_machine_guid())
        + '|' + smbios_uuid()
        + '|' + serial;
    return himitsu::validation::crypto::sha256_hex(
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(value.data()),
            value.size()
        )
    );
}

bool open_or_create_key(
    const wchar_t* provider_name,
    NCRYPT_PROV_HANDLE& provider,
    NCRYPT_KEY_HANDLE& key
) {
    if (NCryptOpenStorageProvider(&provider, provider_name, 0) != ERROR_SUCCESS) return false;
    SECURITY_STATUS status = NCryptOpenKey(
        provider,
        &key,
        device_key_name,
        0,
        NCRYPT_SILENT_FLAG
    );
    if (status == ERROR_SUCCESS) return true;
    status = NCryptCreatePersistedKey(
        provider,
        &key,
        NCRYPT_ECDSA_P256_ALGORITHM,
        device_key_name,
        0,
        NCRYPT_SILENT_FLAG
    );
    if (status != ERROR_SUCCESS
        || NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS) {
        if (key != 0) NCryptFreeObject(key);
        if (provider != 0) NCryptFreeObject(provider);
        key = 0;
        provider = 0;
        return false;
    }
    return true;
}
}

namespace himitsu::validation {
DeviceIdentity::~DeviceIdentity() {
    if (key_ != 0) NCryptFreeObject(key_);
    if (provider_ != 0) NCryptFreeObject(provider_);
}

DeviceIdentity::DeviceIdentity(DeviceIdentity&& other) noexcept
    : provider_(other.provider_),
      key_(other.key_),
      hwid_(std::move(other.hwid_)),
      public_key_(std::move(other.public_key_)) {
    other.provider_ = 0;
    other.key_ = 0;
}

DeviceIdentity& DeviceIdentity::operator=(DeviceIdentity&& other) noexcept {
    if (this == &other) return *this;
    if (key_ != 0) NCryptFreeObject(key_);
    if (provider_ != 0) NCryptFreeObject(provider_);
    provider_ = other.provider_;
    key_ = other.key_;
    hwid_ = std::move(other.hwid_);
    public_key_ = std::move(other.public_key_);
    other.provider_ = 0;
    other.key_ = 0;
    return *this;
}

DeviceIdentity DeviceIdentity::load() {
    DeviceIdentity identity;
    if (!open_or_create_key(MS_PLATFORM_CRYPTO_PROVIDER, identity.provider_, identity.key_)
        && !open_or_create_key(MS_KEY_STORAGE_PROVIDER, identity.provider_, identity.key_)) {
        throw std::runtime_error("Device key initialization failed");
    }
    DWORD public_key_size = 0;
    if (NCryptExportKey(
            identity.key_,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            nullptr,
            0,
            &public_key_size,
            0
        ) != ERROR_SUCCESS) {
        throw std::runtime_error("Device public key export failed");
    }
    std::vector<unsigned char> public_key(public_key_size);
    if (NCryptExportKey(
            identity.key_,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            public_key.data(),
            public_key_size,
            &public_key_size,
            0
        ) != ERROR_SUCCESS) {
        throw std::runtime_error("Device public key export failed");
    }
    public_key.resize(public_key_size);
    identity.public_key_ = crypto::base64_encode(public_key);
    identity.hwid_ = collect_hwid();
    return identity;
}

std::string DeviceIdentity::sign(const std::string& message) const {
    const auto digest = crypto::sha256(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size()
    ));
    DWORD signature_size = 0;
    if (NCryptSignHash(
            key_,
            nullptr,
            const_cast<PBYTE>(digest.data()),
            static_cast<DWORD>(digest.size()),
            nullptr,
            0,
            &signature_size,
            NCRYPT_SILENT_FLAG
        ) != ERROR_SUCCESS) {
        throw std::runtime_error("Device signature size calculation failed");
    }
    std::vector<unsigned char> signature(signature_size);
    if (NCryptSignHash(
            key_,
            nullptr,
            const_cast<PBYTE>(digest.data()),
            static_cast<DWORD>(digest.size()),
            signature.data(),
            signature_size,
            &signature_size,
            NCRYPT_SILENT_FLAG
        ) != ERROR_SUCCESS) {
        throw std::runtime_error("Device signature failed");
    }
    signature.resize(signature_size);
    return crypto::base64_encode(signature);
}
}
