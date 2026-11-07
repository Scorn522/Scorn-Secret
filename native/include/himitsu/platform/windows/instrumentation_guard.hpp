#pragma once
#include <cstdint>

namespace himitsu::platform::windows {
bool disable_instrumentation_entries();
bool stop_instrumentation_entries(std::uint64_t deadline);
}
