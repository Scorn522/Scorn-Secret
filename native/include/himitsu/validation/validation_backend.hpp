#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace himitsu::validation::backend {
using ProgressCallback = std::function<void(float, const std::string&)>;

struct Request {
    std::string username;
    std::string password;
    bool remember_me = false;
    std::string refresh_token;
    ProgressCallback progress;
};

enum class Decision {
    approved,
    rejected,
    service_error
};

struct Result {
    Decision decision = Decision::service_error;
    std::string message;
    std::string refresh_token;
    std::string ticket;
    std::string ticket_signature;
    std::string ticket_username;
    std::string ticket_hwid;
    std::string ticket_device_id;
    std::string ticket_session_id;
    std::int64_t ticket_issued_at = 0;
    std::int64_t ticket_expires_at = 0;
    std::string capability_payload;
    std::string capability_manifest;
    std::string capability_manifest_sig;
};

Result verify(const Request& request);
}
