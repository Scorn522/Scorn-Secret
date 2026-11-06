#include "himitsu/validation/validation_backend.hpp"

#include "himitsu/validation/auth_client.hpp"
#include "himitsu/validation/device_identity.hpp"
#include "himitsu/validation/runtime_lease.hpp"

#include <exception>
#include <windows.h>

namespace {
void wipe(std::string& value) {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
}
}

namespace himitsu::validation::backend {
Result verify(const Request& request) {
    try {
        if (request.progress) request.progress(0.05F, "正在准备验证");
        static const DeviceIdentity identity = DeviceIdentity::load();
        if (request.progress) request.progress(0.12F, "正在连接服务器");
        auto result = authenticate_remote(request, identity);
        if (result.decision == Decision::approved) {
            const bool established = himitsu::validation::lease::establish(
                result,
                request,
                identity
            );
            if(!established) wipe(result.refresh_token);
            wipe(result.ticket);
            wipe(result.ticket_signature);
            wipe(result.capability_payload);
            wipe(result.capability_manifest);
            wipe(result.capability_manifest_sig);
            if (!established) {
                Result failure;
                failure.decision = Decision::service_error;
                failure.message = "Authentication lease initialization failed";
                return failure;
            }
        }
        return result;
    } catch (const std::exception& error) {
        Result failure;
        failure.decision = Decision::service_error;
        failure.message = error.what();
        return failure;
    } catch (...) {
        Result failure;
        failure.decision = Decision::service_error;
        failure.message = "Authentication service error";
        return failure;
    }
}
}
