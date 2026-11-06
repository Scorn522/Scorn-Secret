#include <jni.h>
#include <jvmti.h>
#include <windows.h>
#include <cstdint>

namespace {
jobject JNICALL echo(JNIEnv*, jclass, jstring command, jobjectArray) { return command; }
jboolean JNICALL ready(JNIEnv*, jclass) { return JNI_TRUE; }
}

extern "C" JNIEXPORT jint JNICALL
Java_com_himitsu_secret_bridge_BridgeBindingCheck_bind(JNIEnv* env, jclass, jclass bridge, jclass owner) {
    JNINativeMethod methods[] = {
        {const_cast<char*>("invoke"), const_cast<char*>("(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"), reinterpret_cast<void*>(echo)},
        {const_cast<char*>("ready"), const_cast<char*>("()Z"), reinterpret_cast<void*>(ready)}
    };
    jint result = env->RegisterNatives(bridge, methods, 2);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (owner == nullptr) return result;
    if (result != JNI_OK) {
        jfieldID failure = env->GetStaticFieldID(owner, "bridgeFailure", "I");
        if (failure != nullptr) env->SetStaticIntField(owner, failure, 8);
        return result;
    }
    jfieldID publication = env->GetStaticFieldID(owner, "registeredBridge", "Ljava/lang/Class;");
    if (publication == nullptr) return JNI_ERR;
    env->SetStaticObjectField(owner, publication, bridge);
    return env->ExceptionCheck() ? JNI_ERR : JNI_OK;
}

// Disposable-JVM probes only. These symbols are never linked into himitsu.dll.
namespace {
struct CallerProbe {HANDLE target;bool allowed=false;};
DWORD WINAPI probe_caller(void* data) {
    auto* probe=static_cast<CallerProbe*>(data);
    DWORD result=SuspendThread(probe->target);
    if(result!=static_cast<DWORD>(-1)) {Sleep(10);probe->allowed=ResumeThread(probe->target)!=static_cast<DWORD>(-1);}
    return 0;
}
DWORD WINAPI ordinary_worker(void* ready) {SetEvent(static_cast<HANDLE>(ready));Sleep(INFINITE);return 0;}
jlong packed(DWORD result,DWORD error) {return static_cast<jlong>((static_cast<std::uint64_t>(error)<<32)|result);}
}
extern "C" JNIEXPORT jboolean JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_probeCallerSuspend(JNIEnv*,jclass) {
    HANDLE target=nullptr;
    if(!DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),&target,THREAD_SUSPEND_RESUME,FALSE,0))return false;
    CallerProbe probe{target};HANDLE worker=CreateThread(nullptr,0,probe_caller,&probe,0,nullptr);
    if(worker){WaitForSingleObject(worker,INFINITE);CloseHandle(worker);}CloseHandle(target);return probe.allowed;
}
extern "C" JNIEXPORT jlong JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_currentHandle(JNIEnv*,jclass) {
    HANDLE handle=nullptr;DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),&handle,0,FALSE,DUPLICATE_SAME_ACCESS);
    return reinterpret_cast<jlong>(handle);
}
extern "C" JNIEXPORT jlong JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_copyHandle(JNIEnv*,jclass,jlong value,jint access) {
    HANDLE copy=nullptr;DuplicateHandle(GetCurrentProcess(),reinterpret_cast<HANDLE>(value),GetCurrentProcess(),&copy,access,FALSE,0);
    return reinterpret_cast<jlong>(copy);
}
extern "C" JNIEXPORT jlong JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_suspendHandle(JNIEnv*,jclass,jlong value,jboolean base) {
    auto fn=reinterpret_cast<DWORD(WINAPI*)(HANDLE)>(GetProcAddress(GetModuleHandleW(base?L"kernelbase.dll":L"kernel32.dll"),"SuspendThread"));
    SetLastError(0);DWORD result=fn(reinterpret_cast<HANDLE>(value));return packed(result,GetLastError());
}
extern "C" JNIEXPORT jlong JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_terminateHandle(JNIEnv*,jclass,jlong value,jboolean base) {
    auto fn=reinterpret_cast<BOOL(WINAPI*)(HANDLE,DWORD)>(GetProcAddress(GetModuleHandleW(base?L"kernelbase.dll":L"kernel32.dll"),"TerminateThread"));
    SetLastError(0);BOOL result=fn(reinterpret_cast<HANDLE>(value),0);return packed(result,GetLastError());
}
extern "C" JNIEXPORT jint JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_resumeHandle(JNIEnv*,jclass,jlong value) {return static_cast<jint>(ResumeThread(reinterpret_cast<HANDLE>(value)));}
extern "C" JNIEXPORT jint JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_threadId(JNIEnv*,jclass,jlong value) {return static_cast<jint>(GetThreadId(reinterpret_cast<HANDLE>(value)));}
extern "C" JNIEXPORT void JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_closeHandle(JNIEnv*,jclass,jlong value) {if(value)CloseHandle(reinterpret_cast<HANDLE>(value));}
extern "C" JNIEXPORT jlong JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_ordinaryHandle(JNIEnv*,jclass) {
    HANDLE ready=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!ready)return 0;
    HANDLE worker=CreateThread(nullptr,0,ordinary_worker,ready,0,nullptr);
    if(!worker){CloseHandle(ready);return 0;}
    // Never terminate a probe while Windows is still running its loader/TLS entry.
    // On timeout retain the event: a late worker must not signal a recycled handle.
    if(WaitForSingleObject(ready,2000)!=WAIT_OBJECT_0){CloseHandle(worker);return 0;}
    CloseHandle(ready);return reinterpret_cast<jlong>(worker);
}
extern "C" JNIEXPORT jboolean JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_finishedHandle(JNIEnv*,jclass,jlong value) {return WaitForSingleObject(reinterpret_cast<HANDLE>(value),2000)==WAIT_OBJECT_0;}

extern "C" JNIEXPORT jint JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_createEnvironmentTail(JNIEnv* env,jclass,jint count) {
    JavaVM* vm=nullptr;
    if(env->GetJavaVM(&vm)!=JNI_OK || !vm) return -1;
    for(jint i=0;i<count;++i) {
        jvmtiEnv* added=nullptr;
        if(vm->GetEnv(reinterpret_cast<void**>(&added),JVMTI_VERSION_1_2)!=JNI_OK || !added) return i;
        jvmtiPhase phase{};
        if(added->GetPhase(&phase)!=JVMTI_ERROR_NONE || phase!=JVMTI_PHASE_LIVE) return i;
    }
    // The disposable process owns these inert environments; no callbacks are installed.
    return count;
}
