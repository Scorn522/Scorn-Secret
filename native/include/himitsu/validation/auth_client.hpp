#pragma once

#include "himitsu/validation/validation_backend.hpp"

namespace himitsu::validation {
class DeviceIdentity;

backend::Result authenticate_remote(
    const backend::Request& request,
    const DeviceIdentity& identity
);
}
