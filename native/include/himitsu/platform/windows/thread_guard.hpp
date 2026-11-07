#pragma once
#include <windows.h>
#include <cstdint>
#include <jni.h>
namespace himitsu::platform::windows {
// JNI definitions need not have a JAR CodeSource. Trust only the authenticated actual Class objects.
inline bool owned_event_frame(JNIEnv* env,jclass type,jclass dispatcher,jclass bridge) {
    return type && ((dispatcher && env->IsSameObject(type,dispatcher)) || (bridge && env->IsSameObject(type,bridge)));
}
// 0=platform prefix, 1=Forge handleExit, 2=Minecraft crash, 3=game loop; other/order-changed frames reject.
inline int crash_exit_step(int state,int frame) {
    if(state==0 && frame==0)return 0;
    if(state>=0 && state<3 && frame==state+1)return frame;
    return -1;
}
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
