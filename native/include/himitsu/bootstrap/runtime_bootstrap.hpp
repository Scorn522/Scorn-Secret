#pragma once

#include <jni.h>
#include <windows.h>

namespace himitsu::bootstrap {
void set_module(HMODULE module);
HMODULE module();
bool start_runtime(JavaVM* known_vm = nullptr);
}
