#include <jni.h>
#include <initializer_list>
#include "himitsu/platform/windows/thread_guard.hpp"
#include <jvmti.h>
#include <windows.h>
#include <cstdint>
#include <string>
#include <cstdio>
#include <atomic>
#include <shellapi.h>

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

extern "C" JNIEXPORT jint JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_ntThread(JNIEnv*,jclass,jlong value,jboolean terminate) {
    auto module=GetModuleHandleW(L"ntdll.dll");HANDLE target=reinterpret_cast<HANDLE>(value);
    if(terminate)return reinterpret_cast<LONG(NTAPI*)(HANDLE,LONG)>(GetProcAddress(module,"NtTerminateThread"))(target,0);
    ULONG previous=0;return reinterpret_cast<LONG(NTAPI*)(HANDLE,PULONG)>(GetProcAddress(module,"NtSuspendThread"))(target,&previous);
}
extern "C" JNIEXPORT jboolean JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_selfEndDenied(JNIEnv*,jclass,jboolean nt) {
    if(nt)return reinterpret_cast<LONG(NTAPI*)(HANDLE,LONG)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtTerminateProcess"))(GetCurrentProcess(),91)==static_cast<LONG>(0xC0000022L);
    SetLastError(0);return !TerminateProcess(GetCurrentProcess(),92)&&GetLastError()==ERROR_ACCESS_DENIED;
}
extern "C" JNIEXPORT jint JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_directAttach(JNIEnv*,jclass) {
    auto function=reinterpret_cast<jint(JNICALL*)(char*,char*,char*,char*,char*)>(GetProcAddress(GetModuleHandleW(L"jvm.dll"),"JVM_EnqueueOperation"));
    return function?function(nullptr,nullptr,nullptr,nullptr,nullptr):-1;
}
extern "C" JNIEXPORT jlong JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_nativeCreate(JNIEnv* env,jclass,jstring program,jstring arguments,jboolean ansi) {
    auto p=env->GetStringChars(program,nullptr),a=env->GetStringChars(arguments,nullptr);
    std::wstring app(reinterpret_cast<const wchar_t*>(p),env->GetStringLength(program)),args(reinterpret_cast<const wchar_t*>(a),env->GetStringLength(arguments));
    env->ReleaseStringChars(program,p);env->ReleaseStringChars(arguments,a);std::wstring line=L"\""+app+L"\" "+args;PROCESS_INFORMATION process{};BOOL created;
    if(ansi) {std::string name(app.begin(),app.end()),command(line.begin(),line.end());STARTUPINFOA startup{};startup.cb=sizeof(startup);created=CreateProcessA(name.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process);}
    else {STARTUPINFOW startup{};startup.cb=sizeof(startup);created=CreateProcessW(app.c_str(),line.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process);}
    if(!created)return -static_cast<jlong>(GetLastError());WaitForSingleObject(process.hProcess,3000);DWORD result=1;GetExitCodeProcess(process.hProcess,&result);CloseHandle(process.hThread);CloseHandle(process.hProcess);return 1+static_cast<jlong>(result);
}

namespace {
LONG CALLBACK startup_failure(EXCEPTION_POINTERS* error) {
    if(error->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION)return EXCEPTION_CONTINUE_SEARCH;
    HMODULE module=nullptr;auto address=error->ExceptionRecord->ExceptionAddress;
    if(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,static_cast<LPCWSTR>(address),&module)) {
        wchar_t path[MAX_PATH]{};GetModuleFileNameW(module,path,MAX_PATH);
        if(wcsstr(path,L"himitsu.dll")) {
            static std::atomic<int> count{0};if(count.fetch_add(1)<4)std::fprintf(stderr,"NATIVE_CHECK_FAULT code=%lx module=himitsu offset=%llx address=%llx\n",error->ExceptionRecord->ExceptionCode,
                static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(address)-reinterpret_cast<std::uintptr_t>(module)),
                static_cast<unsigned long long>(error->ExceptionRecord->ExceptionInformation[1]));
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
}
extern "C" JNIEXPORT void JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_installFailureProbe(JNIEnv*,jclass){AddVectoredExceptionHandler(0,startup_failure);}

extern "C" JNIEXPORT jlong JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_shellCreate(JNIEnv* env,jclass,jstring program,jstring arguments) {
    auto p=env->GetStringChars(program,nullptr),a=env->GetStringChars(arguments,nullptr);
    std::wstring app(reinterpret_cast<const wchar_t*>(p),env->GetStringLength(program)),args(reinterpret_cast<const wchar_t*>(a),env->GetStringLength(arguments));
    env->ReleaseStringChars(program,p);env->ReleaseStringChars(arguments,a);
    SHELLEXECUTEINFOW info{};info.cbSize=sizeof(info);info.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;info.lpVerb=L"open";info.lpFile=app.c_str();info.lpParameters=args.c_str();info.nShow=SW_HIDE;
    auto call=reinterpret_cast<decltype(&ShellExecuteExW)>(GetProcAddress(GetModuleHandleW(L"shell32.dll"),"ShellExecuteExW"));
    if(!call || !call(&info))return -static_cast<jlong>(GetLastError());
    if(!info.hProcess)return 0;WaitForSingleObject(info.hProcess,3000);DWORD result=1;GetExitCodeProcess(info.hProcess,&result);CloseHandle(info.hProcess);return 1+static_cast<jlong>(result);
}

extern "C" JNIEXPORT jboolean JNICALL Java_com_himitsu_secret_bridge_NativeStartupCheck_lifecycleFrames(JNIEnv* env,jclass,jclass dispatcher,jclass bridge,jclass foreign) {
    using namespace himitsu::platform::windows;
    auto alias=static_cast<jclass>(env->NewLocalRef(dispatcher));
    bool exact=owned_event_frame(env,alias,dispatcher,bridge)&&owned_event_frame(env,bridge,dispatcher,bridge)
        && !owned_event_frame(env,foreign,dispatcher,bridge)&&!owned_event_frame(env,nullptr,dispatcher,bridge);
    env->DeleteLocalRef(alias);
    auto accepts=[](std::initializer_list<int> frames){int state=0;for(int frame:frames){state=crash_exit_step(state,frame);if(state<0)return false;}return state==3;};
    return exact&&accepts({0,0,1,2,3})&&!accepts({0,1,3})&&!accepts({0,1,2})&&!accepts({0,1,2,-1,3})&&!accepts({0,2,3});
}
