#pragma once

#include <windows.h>
#include <ncrypt.h>

#include <string>
#include <vector>

namespace himitsu::validation {
class DeviceIdentity {
public:
    DeviceIdentity() = default;
    ~DeviceIdentity();

    DeviceIdentity(const DeviceIdentity&) = delete;
    DeviceIdentity& operator=(const DeviceIdentity&) = delete;
    DeviceIdentity(DeviceIdentity&& other) noexcept;
    DeviceIdentity& operator=(DeviceIdentity&& other) noexcept;

    static DeviceIdentity load();

    [[nodiscard]] const std::string& hwid() const { return hwid_; }
    [[nodiscard]] const std::string& public_key() const { return public_key_; }
    [[nodiscard]] std::string sign(const std::string& message) const;

private:
    NCRYPT_PROV_HANDLE provider_ = 0;
    NCRYPT_KEY_HANDLE key_ = 0;
    std::string hwid_;
    std::string public_key_;
};
}
