#pragma once
#include <cstdint>

#include <jni.h>
#include <jvmti.h>

#include <cstddef>
#include <cstdint>

namespace himitsu::platform::windows {
bool start_module_guard(JavaVM* vm, jvmtiEnv* jvmti);
void request_module_guard_stop();
void suspend_jvmti_table_restore(bool suspended);
bool stop_module_guard(std::uint64_t deadline);
bool suspend_export_restore(const char* module_name, const char* export_name, bool suspended);
std::uint64_t register_guarded_region(const char* name, void* address, std::size_t size);
void unregister_guarded_region(std::uint64_t token);
}
