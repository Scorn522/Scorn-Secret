#pragma once

namespace himitsu::platform::windows {
bool install_swap_buffers_hook();
void maintain_swap_buffers_hook();
void uninstall_swap_buffers_hook();
}
