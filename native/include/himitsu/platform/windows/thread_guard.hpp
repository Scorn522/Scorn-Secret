#pragma once
#include <windows.h>
#include <cstdint>
namespace himitsu::platform::windows {
bool start_thread_guard();
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
