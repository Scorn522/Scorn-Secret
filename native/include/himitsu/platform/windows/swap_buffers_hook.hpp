#pragma once
#include <cstdint>

namespace himitsu::platform::windows {
bool install_swap_buffers_hook();
void maintain_swap_buffers_hook();
bool uninstall_swap_buffers_hook(std::uint64_t deadline);
}
