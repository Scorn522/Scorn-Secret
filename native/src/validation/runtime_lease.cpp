#include "himitsu/validation/runtime_lease.hpp"

#include "himitsu/validation/auth_client.hpp"
#include "himitsu/validation/auth_crypto.hpp"
#include "himitsu/validation/capability_registry.hpp"
#include "himitsu/validation/device_identity.hpp"
#include "himitsu/validation/integrity_check.hpp"
#include "himitsu/validation/validation_gate.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

namespace {
using himitsu::validation::DeviceIdentity;
using himitsu::validation::backend::Decision;
using himitsu::validation::backend::Request;
using himitsu::validation::backend::Result;

struct LeaseState {
    std::mutex mutex;
    std::condition_variable wake;
    std::thread worker;
    Result result;
    const DeviceIdentity* identity = nullptr;
    std::array<unsigned char, 32> process_secret{};
    std::array<unsigned char, 32> seal_mask{};
    std::array<unsigned char, 32> seal_share{};
    ULONGLONG monotonic_anchor = 0;
    std::int64_t ticket_lifetime = 0;
    bool active = false;
    bool stopping = false;
};

LeaseState lease_state;

constexpr std::chrono::seconds refresh_period{240};
constexpr std::chrono::seconds watchdog_period{5};

void wipe_string(std::string& value) {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
}

void wipe_result_secrets(Result& result) {
    wipe_string(result.refresh_token);
    wipe_string(result.ticket);
    wipe_string(result.ticket_signature);
    wipe_string(result.capability_payload);
    wipe_string(result.capability_manifest);
    wipe_string(result.capability_manifest_sig);
}

template<typename Value>
void append_value(std::vector<unsigned char>& output, const Value& value) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(&value);
    output.insert(output.end(), bytes, bytes + sizeof(value));
}

void append_string(std::vector<unsigned char>& output, const std::string& value) {
    const std::uint64_t size = static_cast<std::uint64_t>(value.size());
    append_value(output, size);
    output.insert(output.end(), value.begin(), value.end());
}

std::array<unsigned char, 32> calculate_seal_locked() {
    std::vector<unsigned char> material;
    material.reserve(
        lease_state.result.ticket.size()
        + lease_state.result.ticket_signature.size()
        + lease_state.result.ticket_username.size()
        + lease_state.result.ticket_hwid.size()
        + lease_state.result.ticket_device_id.size()
        + lease_state.result.capability_payload.size()
        + lease_state.result.capability_manifest.size()
        + lease_state.result.capability_manifest_sig.size()
        + 160
    );
    append_string(material, lease_state.result.ticket);
    append_string(material, lease_state.result.ticket_signature);
    append_string(material, lease_state.result.ticket_username);
    append_string(material, lease_state.result.ticket_hwid);
    append_string(material, lease_state.result.ticket_device_id);
    append_string(material, lease_state.result.capability_payload);
    append_string(material, lease_state.result.capability_manifest);
    append_string(material, lease_state.result.capability_manifest_sig);
    append_value(material, lease_state.result.ticket_issued_at);
    append_value(material, lease_state.result.ticket_expires_at);
    const DWORD process_id = GetCurrentProcessId();
    append_value(material, process_id);
    const std::uintptr_t state_address = reinterpret_cast<std::uintptr_t>(&lease_state);
    append_value(material, state_address);
    material.insert(
        material.end(),
        lease_state.process_secret.begin(),
        lease_state.process_secret.end()
    );
    const auto digest = himitsu::validation::crypto::sha256(material);
    if (!material.empty()) SecureZeroMemory(material.data(), material.size());
    return digest;
}

bool reseal_locked() {
    if (BCryptGenRandom(
            nullptr,
            lease_state.seal_mask.data(),
            static_cast<ULONG>(lease_state.seal_mask.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        ) < 0) {
        return false;
    }
    try {
        const auto digest = calculate_seal_locked();
        for (std::size_t index = 0; index < digest.size(); ++index) {
            lease_state.seal_share[index] = digest[index] ^ lease_state.seal_mask[index];
        }
    } catch (...) {
        return false;
    }
    lease_state.monotonic_anchor = GetTickCount64();
    lease_state.ticket_lifetime = lease_state.result.ticket_expires_at
        - lease_state.result.ticket_issued_at;
    return lease_state.ticket_lifetime > 0 && lease_state.ticket_lifetime <= 900;
}

bool seal_valid_locked() {
    try {
        const auto digest = calculate_seal_locked();
        std::array<unsigned char, 32> stored{};
        for (std::size_t index = 0; index < stored.size(); ++index) {
            stored[index] = lease_state.seal_mask[index] ^ lease_state.seal_share[index];
        }
        const bool equal = himitsu::validation::crypto::constant_equals(digest, stored);
        SecureZeroMemory(stored.data(), stored.size());
        return equal;
    } catch (...) {
        return false;
    }
}

void fail_closed() {
    himitsu::validation::latch_rejection();
    himitsu::validation::abort_with_message(
        L"授权校验失败\n\nLicense verification failed. Please restart.\n授权校验异常，请重新登录。",
        0x48560006UL
    );
}

void refresh_worker() {
    auto next_refresh = std::chrono::steady_clock::now() + refresh_period;
    for (;;) {
        {
            std::unique_lock lock(lease_state.mutex);
            if (lease_state.wake.wait_for(lock, watchdog_period, [] {
                    return lease_state.stopping;
                })) {
                return;
            }
        }

        if (!himitsu::validation::lease::valid()
            || !himitsu::validation::capability::valid()
            || !himitsu::validation::integrity::verify_runtime()) {
            fail_closed();
        }
        if (std::chrono::steady_clock::now() < next_refresh) continue;
        next_refresh = std::chrono::steady_clock::now() + refresh_period;

        Result current;
        const DeviceIdentity* identity = nullptr;
        {
            std::lock_guard lock(lease_state.mutex);
            if (lease_state.stopping || !lease_state.active || lease_state.identity == nullptr) return;
            current = lease_state.result;
            identity = lease_state.identity;
        }

        if (current.refresh_token.empty() || current.ticket_username.empty()) {
            fail_closed();
        }

        Request request{
            current.ticket_username,
            {},
            true,
            current.refresh_token,
            {}
        };
        Result refreshed;
        try {
            refreshed = himitsu::validation::authenticate_remote(request, *identity);
        } catch (...) {
            fail_closed();
        }
        wipe_string(request.refresh_token);
        wipe_result_secrets(current);
        if (refreshed.decision != Decision::approved
            || refreshed.refresh_token.empty()
            || refreshed.ticket.empty()
            || refreshed.ticket_signature.empty()
            || refreshed.ticket_username != current.ticket_username
            || refreshed.ticket_hwid != current.ticket_hwid
            || refreshed.ticket_device_id != current.ticket_device_id
            || refreshed.ticket_expires_at <= refreshed.ticket_issued_at) {
            fail_closed();
        }

        if (!refreshed.capability_manifest.empty() && !refreshed.capability_manifest_sig.empty()) {
            const auto payload = himitsu::validation::crypto::base64_decode(
                refreshed.capability_payload
            );
            const auto manifest = himitsu::validation::crypto::base64_decode(
                refreshed.capability_manifest
            );
            if (!himitsu::validation::capability::initialize(
                    payload, manifest,
                    refreshed.ticket_device_id,
                    refreshed.ticket_hwid,
                    refreshed.ticket_session_id)) {
                fail_closed();
            }
        }

        bool sealed = false;
        {
            std::lock_guard lock(lease_state.mutex);
            if (lease_state.stopping) {
                wipe_result_secrets(refreshed);
                return;
            }
            wipe_result_secrets(lease_state.result);
            lease_state.result = std::move(refreshed);
            sealed = reseal_locked();
        }
        if (!sealed) fail_closed();
    }
}
}

namespace himitsu::validation::lease {
bool establish(
    const backend::Result& result,
    const backend::Request& original_request,
    const DeviceIdentity& identity
) {
    if (result.decision != backend::Decision::approved
        || result.ticket.empty()
        || result.ticket_signature.empty()
        || result.ticket_username.empty()
        || result.ticket_hwid.empty()
        || result.ticket_device_id.empty()
        || result.ticket_expires_at <= result.ticket_issued_at
        || result.refresh_token.empty()
        || _stricmp(original_request.username.c_str(),
            result.ticket_username.c_str()) != 0) {
        return false;
    }

    if (result.capability_payload.empty()
        || result.capability_manifest.empty()
        || result.capability_manifest_sig.empty()) {
        return false;
    }
    try {
        const auto payload = himitsu::validation::crypto::base64_decode(
            result.capability_payload
        );
        const auto manifest = himitsu::validation::crypto::base64_decode(
            result.capability_manifest
        );
        if (!himitsu::validation::capability::initialize(
            payload,
            manifest,
            result.ticket_device_id,
            result.ticket_hwid,
            result.ticket_session_id
        )) {
            return false;
        }
    } catch (...) {
        return false;
    }

    std::lock_guard lock(lease_state.mutex);
    if (lease_state.active) return false;
    lease_state.result = result;
    lease_state.identity = &identity;
    if (BCryptGenRandom(
            nullptr,
            lease_state.process_secret.data(),
            static_cast<ULONG>(lease_state.process_secret.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        ) < 0
        || !reseal_locked()) {
        lease_state.identity = nullptr;
        wipe_result_secrets(lease_state.result);
        lease_state.result = {};
        SecureZeroMemory(lease_state.process_secret.data(), lease_state.process_secret.size());
        return false;
    }
    lease_state.stopping = false;
    lease_state.active = true;
    try {
        lease_state.worker = std::thread(refresh_worker);
    } catch (...) {
        lease_state.active = false;
        lease_state.identity = nullptr;
        wipe_result_secrets(lease_state.result);
        lease_state.result = {};
        return false;
    }
    return true;
}

bool valid() {
#ifdef HIMITSU_LOCAL_TEST
    return capability::valid();
#else
    std::lock_guard lock(lease_state.mutex);
    if (!lease_state.active || lease_state.stopping) return false;
    const auto now = std::chrono::system_clock::now();
    const auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();
    const ULONGLONG elapsed_seconds = (GetTickCount64() - lease_state.monotonic_anchor) / 1000ULL;
    return lease_state.result.ticket_issued_at <= now_seconds + 60
        && lease_state.result.ticket_expires_at > now_seconds
        && elapsed_seconds <= static_cast<ULONGLONG>(lease_state.ticket_lifetime + 60)
        && seal_valid_locked();
#endif
}

void stop() {
#ifdef HIMITSU_LOCAL_TEST
    capability::revoke();
    return;
#endif
    std::thread worker;
    {
        std::lock_guard lock(lease_state.mutex);
        if (!lease_state.active && !lease_state.worker.joinable()) return;
        lease_state.stopping = true;
        lease_state.wake.notify_all();
        worker = std::move(lease_state.worker);
    }
    if (worker.joinable()) worker.join();
    {
        std::lock_guard lock(lease_state.mutex);
        lease_state.active = false;
        lease_state.identity = nullptr;
        wipe_result_secrets(lease_state.result);
        SecureZeroMemory(lease_state.process_secret.data(), lease_state.process_secret.size());
        SecureZeroMemory(lease_state.seal_mask.data(), lease_state.seal_mask.size());
        SecureZeroMemory(lease_state.seal_share.data(), lease_state.seal_share.size());
        lease_state.result = {};
        lease_state.monotonic_anchor = 0;
        lease_state.ticket_lifetime = 0;
        lease_state.stopping = false;
    }
    himitsu::validation::capability::stop();
}
}

