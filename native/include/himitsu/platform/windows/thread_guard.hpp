#pragma once
#include <windows.h>
#include <cstdint>
#include <jni.h>
namespace himitsu::platform::windows {
bool start_thread_guard();
jobject host_command(JNIEnv* env,const char* command,jobject first,jobject second);
bool host_shutdown_authorized();
void authorize_fatal_exit();
void retire_host_thread(JNIEnv*,jobject);
bool stop_thread_guard(std::uint64_t deadline);
bool register_native_thread(HANDLE thread);
void unregister_native_thread(HANDLE thread);
bool same_thread_handle(HANDLE first,HANDLE second);
// Only internal MinHook callers may enter this non-JNI scope.
class ThreadHookMaintenance {
public:
    ThreadHookMaintenance();
    ~ThreadHookMaintenance();
    ThreadHookMaintenance(const ThreadHookMaintenance&)=delete;
    ThreadHookMaintenance& operator=(const ThreadHookMaintenance&)=delete;
};
}
