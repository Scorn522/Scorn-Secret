#pragma once

#include <windows.h>

namespace himitsu::platform::windows::module_conceal {

bool hide(HMODULE module);
bool hidden();

}
