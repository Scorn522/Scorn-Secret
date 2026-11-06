#include "himitsu/validation/auth_client.hpp"

#include "himitsu/validation/auth_config.hpp"
#include "himitsu/validation/auth_crypto.hpp"
#include "himitsu/validation/device_identity.hpp"

#include <bcrypt.h>
#include <wincrypt.h>
#include <windows.h>
#include <winhttp.h>

#include <chrono>
#include <array>
#include <cctype>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using himitsu::validation::backend::Decision;
using himitsu::validation::backend::Result;

void report_progress(
    const himitsu::validation::backend::Request& request,
    float progress,
    const char* step
) {
    if (request.progress) request.progress(progress, step);
}

struct Handles {
    HINTERNET session = nullptr;
    HINTERNET connection = nullptr;
    HINTERNET request = nullptr;
    HINTERNET websocket = nullptr;
    PCCERT_CONTEXT certificate = nullptr;

    ~Handles() {
        if (websocket != nullptr) WinHttpCloseHandle(websocket);
        if (request != nullptr) WinHttpCloseHandle(request);
        if (connection != nullptr) WinHttpCloseHandle(connection);
        if (session != nullptr) WinHttpCloseHandle(session);
        if (certificate != nullptr) CertFreeCertificateContext(certificate);
    }
};

std::string json_escape(const std::string& value) {
    std::string output;
    output.reserve(value.size() + 16);
    for (unsigned char character : value) {
        switch (character) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (character < 0x20) {
                    char escaped[7]{};
                    std::snprintf(escaped, sizeof(escaped), "\\u%04x", character);
                    output += escaped;
                } else {
                    output.push_back(static_cast<char>(character));
                }
        }
    }
    return output;
}

std::size_t field_value(const std::string& json, const std::string& name) {
    const std::string token = "\"" + name + "\"";
    std::size_t position = json.find(token);
    if (position == std::string::npos) throw std::runtime_error("Missing response field: " + name);
    position = json.find(':', position + token.size());
    if (position == std::string::npos) throw std::runtime_error("Malformed response field: " + name);
    do { ++position; } while (position < json.size() && std::isspace(static_cast<unsigned char>(json[position])));
    return position;
}

std::string json_string(const std::string& json, const std::string& name, bool optional = false) {
    std::size_t position;
    try {
        position = field_value(json, name);
    } catch (const std::runtime_error&) {
        if (optional) return {};
        throw;
    }
    if (position >= json.size() || json[position++] != '"') {
        throw std::runtime_error("Response field is not a string: " + name);
    }
    std::string output;
    while (position < json.size()) {
        char character = json[position++];
        if (character == '"') return output;
        if (character != '\\') {
            output.push_back(character);
            continue;
        }
        if (position >= json.size()) break;
        char escaped = json[position++];
        switch (escaped) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            default: throw std::runtime_error("Unsupported JSON escape");
        }
    }
    throw std::runtime_error("Unterminated response string");
}

bool json_boolean(const std::string& json, const std::string& name) {
    const std::size_t position = field_value(json, name);
    if (json.compare(position, 4, "true") == 0) return true;
    if (json.compare(position, 5, "false") == 0) return false;
    throw std::runtime_error("Response field is not boolean: " + name);
}

long long json_integer(const std::string& json, const std::string& name) {
    const std::size_t position = field_value(json, name);
    std::size_t consumed = 0;
    long long value = std::stoll(json.substr(position), &consumed);
    if (consumed == 0) throw std::runtime_error("Response field is not integer: " + name);
    return value;
}

void websocket_send(HINTERNET websocket, const std::string& message) {
    if (message.size() > 32'768
        || WinHttpWebSocketSend(
            websocket,
            WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
            const_cast<char*>(message.data()),
            static_cast<DWORD>(message.size())
        ) != NO_ERROR) {
        throw std::runtime_error("WSS send failed");
    }
}

std::string websocket_receive(HINTERNET websocket) {
    std::string message;
    std::array<char, 4096> buffer{};
    for (;;) {
        DWORD read = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
        const DWORD result = WinHttpWebSocketReceive(
            websocket,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &read,
            &type
        );
        if (result != NO_ERROR) throw std::runtime_error("WSS receive failed");
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            throw std::runtime_error("WSS connection closed");
        }
        if (message.size() + read > 32'768) throw std::runtime_error("WSS response exceeds limit");
        message.append(buffer.data(), read);
        if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) return message;
        if (type != WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE) {
            throw std::runtime_error("Unexpected WSS frame type");
        }
    }
}

void verify_certificate_pin(PCCERT_CONTEXT certificate) {
    const auto digest = himitsu::validation::crypto::sha256(
        std::span<const unsigned char>(certificate->pbCertEncoded, certificate->cbCertEncoded)
    );
    const auto pinned_digest = himitsu::validation::auth_config::certificate_sha256();
    if (!himitsu::validation::crypto::constant_equals(
            digest,
            pinned_digest
        )) {
        throw std::runtime_error("Server certificate pin mismatch");
    }
}

void verify_ticket_signature(
    PCCERT_CONTEXT certificate,
    const std::vector<unsigned char>& payload,
    const std::vector<unsigned char>& signature
) {
    BCRYPT_KEY_HANDLE key = nullptr;
    if (!CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            &certificate->pCertInfo->SubjectPublicKeyInfo,
            0,
            nullptr,
            &key
        )) {
        throw std::runtime_error("Server ticket key import failed");
    }
    const auto digest = himitsu::validation::crypto::sha256(payload);
    const NTSTATUS status = BCryptVerifySignature(
        key,
        nullptr,
        const_cast<PUCHAR>(digest.data()),
        static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(signature.data()),
        static_cast<ULONG>(signature.size()),
        0
    );
    BCryptDestroyKey(key);
    if (status < 0) throw std::runtime_error("Server ticket signature is invalid");
}

struct TicketClaims {
    std::string username;
    std::string hwid;
    std::string device_id;
    long long issued_at = 0;
    long long expires_at = 0;
};

TicketClaims validate_ticket(
    const std::string& payload,
    const himitsu::validation::backend::Request& request,
    const himitsu::validation::DeviceIdentity& identity,
    const std::string& session_id,
    const std::string& client_nonce,
    const std::string& server_nonce,
    const std::string& build_id
) {
    const long long now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    TicketClaims claims{
        json_string(payload, "username"),
        json_string(payload, "hwid"),
        json_string(payload, "device_id"),
        json_integer(payload, "issued_at"),
        json_integer(payload, "expires_at")
    };
    const std::string expected_device_id = himitsu::validation::crypto::sha256_hex(
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(identity.public_key().data()),
            identity.public_key().size()
        )
    );
    if (json_integer(payload, "protocol") != 1
        || _stricmp(claims.username.c_str(), request.username.c_str()) != 0
        || claims.hwid != identity.hwid()
        || claims.device_id != expected_device_id
        || json_string(payload, "build_id") != build_id
        || json_string(payload, "session_id") != session_id
        || json_string(payload, "client_nonce") != client_nonce
        || json_string(payload, "server_nonce") != server_nonce
        || claims.issued_at > now + 60
        || claims.issued_at < now - 900
        || claims.expires_at <= now
        || claims.expires_at <= claims.issued_at
        || claims.expires_at - claims.issued_at > 900) {
        throw std::runtime_error("Server ticket claims are invalid");
    }
    return claims;
}

Result rejected_or_service(const std::string& response) {
    const std::string code = json_string(response, "code", true);
    const std::string message = json_string(response, "message", true);
    const bool rejected = code == "invalid_credentials"
        || code == "banned"
        || code == "device_mismatch"
        || code == "invalid_refresh"
        || code == "rate_limited";
    Result result;
    result.decision = rejected ? Decision::rejected : Decision::service_error;
    result.message = message.empty()
        ? (code.empty() ? "Authentication failed" : code)
        : message;
    return result;
}
}

namespace himitsu::validation {
backend::Result authenticate_remote(
    const backend::Request& request,
    const DeviceIdentity& identity
) {
    report_progress(request, 0.16F, "正在连接服务器");
    Handles handles;
    const std::string build_id = auth_config::build_id();
    std::wstring endpoint = auth_config::endpoint();
    if (endpoint.rfind(L"wss://", 0) == 0) {
        endpoint.replace(0, 6, L"https://");
    }
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(endpoint.c_str(), 0, 0, &components)) {
        throw std::runtime_error("Authentication endpoint is invalid");
    }
    const std::wstring host(components.lpszHostName, components.dwHostNameLength);
    const std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
    handles.session = WinHttpOpen(
        L"SecretNativeAuth/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (handles.session == nullptr) throw std::runtime_error("WinHTTP session creation failed");
    report_progress(request, 0.24F, "正在连接服务器");

    WinHttpSetTimeouts(handles.session, 8'000, 8'000, 20'000, 20'000);
    handles.connection = WinHttpConnect(handles.session, host.c_str(), components.nPort, 0);
    if (handles.connection == nullptr) throw std::runtime_error("Authentication connection failed");
    handles.request = WinHttpOpenRequest(
        handles.connection,
        L"GET",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (handles.request == nullptr) {
        throw std::runtime_error(
            "Authentication request failed (WinHTTP error "
            + std::to_string(GetLastError()) + ")"
        );
    }
    if (auth_config::allow_pinned_self_signed()) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(handles.request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }
    report_progress(request, 0.32F, "正在连接服务器");
    if (!WinHttpSetOption(
            handles.request,
            WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
            nullptr,
            0
        )) {
        throw std::runtime_error(
            "WSS setup failed (WinHTTP error "
            + std::to_string(GetLastError()) + ")"
        );
    }
    if (!WinHttpSendRequest(
            handles.request,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0
        )) {
        throw std::runtime_error(
            "WSS request failed (WinHTTP error "
            + std::to_string(GetLastError()) + ")"
        );
    }
    if (!WinHttpReceiveResponse(handles.request, nullptr)) {
        throw std::runtime_error(
            "WSS TLS handshake failed (WinHTTP error "
            + std::to_string(GetLastError()) + ")"
        );
    }
    DWORD certificate_size = sizeof(handles.certificate);
    if (!WinHttpQueryOption(
            handles.request,
            WINHTTP_OPTION_SERVER_CERT_CONTEXT,
            &handles.certificate,
            &certificate_size
        ) || handles.certificate == nullptr) {
        throw std::runtime_error("Server certificate query failed");
    }
    report_progress(request, 0.44F, "正在连接服务器");
    verify_certificate_pin(handles.certificate);
    handles.websocket = WinHttpWebSocketCompleteUpgrade(handles.request, 0);
    if (handles.websocket == nullptr) throw std::runtime_error("WSS upgrade failed");
    WinHttpCloseHandle(handles.request);
    handles.request = nullptr;

    report_progress(request, 0.56F, "正在验证登录信息");
    const std::string client_nonce = crypto::random_token(32);
    const std::string hello = "{\"type\":\"hello\",\"protocol\":1,\"username\":\""
        + json_escape(request.username)
        + "\",\"build_id\":\"" + json_escape(build_id)
        + "\",\"hwid\":\"" + identity.hwid()
        + "\",\"device_public_key\":\"" + identity.public_key()
        + "\",\"client_nonce\":\"" + client_nonce + "\"}";
    websocket_send(handles.websocket, hello);
    const std::string challenge = websocket_receive(handles.websocket);
    if (json_string(challenge, "type") != "challenge") return rejected_or_service(challenge);
    report_progress(request, 0.68F, "正在验证登录信息");
    const std::string session_id = json_string(challenge, "session_id");
    const std::string server_nonce = json_string(challenge, "server_nonce");
    const std::string signed_message = session_id + "\n"
        + server_nonce + "\n"
        + client_nonce + "\n"
        + identity.hwid() + "\n"
        + build_id;
    const std::string device_signature = identity.sign(signed_message);
    const bool refresh_mode = !request.refresh_token.empty();
    std::string credential = refresh_mode ? request.refresh_token : request.password;
    std::string authenticate = "{\"type\":\"authenticate\",\"session_id\":\""
        + json_escape(session_id)
        + "\",\"mode\":\"" + (refresh_mode ? "refresh" : "password")
        + "\",\"credential\":\"" + json_escape(credential)
        + "\",\"device_signature\":\"" + device_signature
        + "\",\"remember\":" + (request.remember_me ? "true" : "false") + "}";
    report_progress(request, 0.78F, "正在验证登录信息");
    websocket_send(handles.websocket, authenticate);
    if (!credential.empty()) SecureZeroMemory(credential.data(), credential.size());
    if (!authenticate.empty()) SecureZeroMemory(authenticate.data(), authenticate.size());
    const std::string response = websocket_receive(handles.websocket);
    if (json_string(response, "type") != "auth_result") {
        throw std::runtime_error("Unexpected authentication response type");
    }
    if (!json_boolean(response, "ok")) return rejected_or_service(response);

    report_progress(request, 0.90F, "正在完成验证");
    const std::string ticket = json_string(response, "ticket");
    const std::string ticket_signature = json_string(response, "ticket_signature");
    const auto payload = crypto::base64_decode(ticket);
    const auto signature = crypto::base64_decode(ticket_signature);
    verify_ticket_signature(handles.certificate, payload, signature);
    const std::string payload_json(payload.begin(), payload.end());
    const TicketClaims claims = validate_ticket(
        payload_json,
        request,
        identity,
        session_id,
        client_nonce,
        server_nonce,
        build_id
    );
    report_progress(request, 1.0F, "验证完成");
    WinHttpWebSocketClose(handles.websocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
    Result out{
        Decision::approved,
        "Authentication approved",
        json_string(response, "refresh_token", true),
        ticket,
        ticket_signature,
        claims.username,
        claims.hwid,
        claims.device_id,
        session_id,
        claims.issued_at,
        claims.expires_at
    };
    out.capability_payload = json_string(response, "payload", true);
    out.capability_manifest = json_string(response, "manifest", true);
    out.capability_manifest_sig = json_string(response, "manifest_sig", true);

    if (out.capability_payload.empty()
        || out.capability_manifest.empty()
        || out.capability_manifest_sig.empty()) {
        throw std::runtime_error("Server capability payload is missing");
    }
    const auto manifest_bytes = crypto::base64_decode(out.capability_manifest);
    const auto sig_bytes = crypto::base64_decode(out.capability_manifest_sig);
    verify_ticket_signature(handles.certificate, manifest_bytes, sig_bytes);

    return out;
}
}
