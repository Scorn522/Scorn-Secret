#pragma once
#include <cstdint>
#include <jni.h>
#include <jvmti.h>
#include "himitsu/jvm/late_recovery.hpp"
namespace himitsu::platform::windows {
bool start_module_guard(JavaVM* vm,jvmtiEnv* jvmti);
void request_module_guard_stop();
bool suspend_jvmti_table_restore(bool suspended);
bool native_interfaces_healthy();
void observe_guarded_module(HMODULE module);
bool stop_module_guard(std::uint64_t deadline);
std::uint64_t register_guarded_hook(const char* name,void* target);
std::uint64_t register_guarded_pointer(const char* name,void** slot,void* expected);
std::uint64_t register_guarded_code(const char* name,std::vector<himitsu::jvm::NativeCodeRange> ranges);
bool guarded_hook_intact(void* target);
bool apply_owned_code(void* address,unsigned char* expected,std::size_t size);
bool unregister_guarded_region(std::uint64_t token,std::uint64_t deadline=0);
}
