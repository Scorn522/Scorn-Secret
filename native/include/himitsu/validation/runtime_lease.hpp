#pragma once

#include "himitsu/validation/validation_backend.hpp"

namespace himitsu::validation {
class DeviceIdentity;

namespace lease {

bool establish(
    const backend::Result& result,
    const backend::Request& original_request,
    const DeviceIdentity& identity
);

[[nodiscard]] bool valid();
void stop();

}
}
