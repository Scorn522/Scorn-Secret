#pragma once

namespace himitsu::bootstrap {
bool install_early_guards(bool disable_jvmti);
bool early_guards_ready();
}
