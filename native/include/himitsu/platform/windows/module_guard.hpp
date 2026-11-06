#pragma once

#include <jni.h>
#include <jvmti.h>

#include <cstddef>
#include <cstdint>

namespace himitsu::platform::windows {
bool start_module_guard(JavaVM* vm, jvmtiEnv* jvmti);
void stop_module_guard();
bool suspend_export_restore(const char* module_name, const char* export_name, bool suspended);
std::uint64_t register_guarded_region(const char* name, void* address, std::size_t size);
void unregister_guarded_region(std::uint64_t token);
}
