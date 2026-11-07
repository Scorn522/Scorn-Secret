#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/platform/windows/module_guard.hpp"
#include "himitsu/platform/windows/instrumentation_guard.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include <jni.h>
#include <MinHook.h>
#include <algorithm>
#include <atomic>
#include <vector>
#ifdef _MSC_VER
#include <intrin.h>
#define THREAD_CALLER _ReturnAddress()
#else
#define THREAD_CALLER __builtin_return_address(0)
#endif
namespace {
using State=himitsu::core::RuntimeState;
using StopThreadFn=void (JNICALL*)(JNIEnv*,jobject,jobject);
using SuspendJavaFn=void (JNICALL*)(JNIEnv*,jobject);
using GetAllThreadsFn=jobjectArray (JNICALL*)(JNIEnv*,jclass);
using SuspendOsFn=DWORD (WINAPI*)(HANDLE);
using TerminateOsFn=BOOL (WINAPI*)(HANDLE,DWORD);
using CompareFn=BOOL (WINAPI*)(HANDLE,HANDLE);
struct Hook {
    const wchar_t* library; const char* name;
    void* target=nullptr;
    std::atomic<void*> trampoline{nullptr};
    bool created=false;
    std::uint64_t guard_token=0;
};
Hook stop_hook{L"jvm.dll","JVM_StopThread"}, suspend_hook{L"jvm.dll","JVM_SuspendThread"}, all_threads_hook{L"jvm.dll","JVM_GetAllThreads"};
Hook base_suspend{L"kernelbase.dll","SuspendThread"}, base_terminate{L"kernelbase.dll","TerminateThread"};
Hook kernel_suspend{L"kernel32.dll","SuspendThread"}, kernel_terminate{L"kernel32.dll","TerminateThread"};
Hook* hooks[]{&stop_hook,&suspend_hook,&all_threads_hook,&base_suspend,&base_terminate,&kernel_suspend,&kernel_terminate};
std::atomic<bool> installed{false}, admitting{false};
CompareFn compare_handles=nullptr;
std::uintptr_t jvm_begin=0,jvm_end=0;
SRWLOCK hook_lock=SRWLOCK_INIT;
thread_local unsigned maintenance_depth=0,suspend_forward_depth=0;
bool protected_java(const State::References& refs,JNIEnv* env,jobject thread) {
    if(!env || !thread) return false;
    for(const auto& entry:refs.threads) if(entry.java_thread && env->IsSameObject(entry.java_thread,thread)) return true;
    return false;
}
bool protected_os(HANDLE handle) {
    if(!handle || !compare_handles) return false;
    State::ReferenceRead read(State::instance());
    for(const auto& entry:read->threads) if(entry.os_thread && compare_handles(entry.os_thread,handle)) return true;
    return false;
}
bool jvm_caller(void* caller) {
    auto address=reinterpret_cast<std::uintptr_t>(caller);
    return address>=jvm_begin && address<jvm_end;
}
DWORD suspend_os(Hook& hook,HANDLE thread,void* caller) {
    const DWORD saved=GetLastError();
    if(admitting.load(std::memory_order_acquire) && !maintenance_depth && !suspend_forward_depth && !jvm_caller(caller) && protected_os(thread)) {
        SetLastError(ERROR_ACCESS_DENIED); return static_cast<DWORD>(-1);
    }
    SetLastError(saved); ++suspend_forward_depth;
    const DWORD result=reinterpret_cast<SuspendOsFn>(hook.trampoline.load(std::memory_order_acquire))(thread);
    const DWORD error=GetLastError(); --suspend_forward_depth; SetLastError(error); return result;
}
BOOL terminate_os(Hook& hook,HANDLE thread,DWORD code) {
    const DWORD saved=GetLastError();
    if(admitting.load(std::memory_order_acquire) && !maintenance_depth && protected_os(thread)) {
        SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    SetLastError(saved);
    return reinterpret_cast<TerminateOsFn>(hook.trampoline.load(std::memory_order_acquire))(thread,code);
}
DWORD WINAPI guarded_base_suspend(HANDLE thread) {return suspend_os(base_suspend,thread,THREAD_CALLER);}
DWORD WINAPI guarded_kernel_suspend(HANDLE thread) {return suspend_os(kernel_suspend,thread,THREAD_CALLER);}
BOOL WINAPI guarded_base_terminate(HANDLE thread,DWORD code) {return terminate_os(base_terminate,thread,code);}
BOOL WINAPI guarded_kernel_terminate(HANDLE thread,DWORD code) {return terminate_os(kernel_terminate,thread,code);}
void JNICALL guarded_stop(JNIEnv* env,jobject thread,jobject error) {
    bool denied=false;
    if(admitting.load(std::memory_order_acquire)) {State::ReferenceRead read(State::instance(),env);denied=protected_java(*read.get(),env,thread);}
    if(!denied) reinterpret_cast<StopThreadFn>(stop_hook.trampoline.load(std::memory_order_acquire))(env,thread,error);
}
void JNICALL guarded_suspend(JNIEnv* env,jobject thread) {
    bool denied=false;
    if(admitting.load(std::memory_order_acquire)) {State::ReferenceRead read(State::instance(),env);denied=protected_java(*read.get(),env,thread);}
    if(!denied) reinterpret_cast<SuspendJavaFn>(suspend_hook.trampoline.load(std::memory_order_acquire))(env,thread);
}
jobjectArray JNICALL guarded_threads(JNIEnv* env,jclass type) {
    jobjectArray source=reinterpret_cast<GetAllThreadsFn>(all_threads_hook.trampoline.load(std::memory_order_acquire))(env,type);
    if(!source || env->ExceptionCheck() || !admitting.load(std::memory_order_acquire)) return source;
    State::ReferenceRead read(State::instance(),env);
    if(std::none_of(read->threads.begin(),read->threads.end(),[](const auto& entry){return entry.java_thread!=nullptr;})) return source;
    const jsize length=env->GetArrayLength(source);
    std::vector<jobject> visible; visible.reserve(static_cast<std::size_t>(length));
    for(jsize i=0;i<length;i++) {
        jobject thread=env->GetObjectArrayElement(source,i);
        if(protected_java(*read.get(),env,thread)) env->DeleteLocalRef(thread); else visible.push_back(thread);
    }
    jclass thread_type=env->FindClass("java/lang/Thread");
    jobjectArray result=thread_type?env->NewObjectArray(static_cast<jsize>(visible.size()),thread_type,nullptr):nullptr;
    if(result) for(jsize i=0;i<static_cast<jsize>(visible.size());i++) env->SetObjectArrayElement(result,i,visible[i]);
    for(jobject thread:visible) env->DeleteLocalRef(thread);
    if(thread_type) env->DeleteLocalRef(thread_type);
    env->DeleteLocalRef(source); return result;
}
bool prepare(Hook& hook,void* replacement) {
    if(hook.created) return true;
    HMODULE library=GetModuleHandleW(hook.library);
    hook.target=library?reinterpret_cast<void*>(GetProcAddress(library,hook.name)):nullptr;
    if(!hook.target) {HIMITSU_LOG_ERROR("ThreadGuard","Required thread export unavailable: %s",hook.name);return false;}
    for(Hook* prior:hooks) if(prior!=&hook && prior->created && prior->target==hook.target) {
        hook.trampoline.store(prior->trampoline.load(std::memory_order_acquire),std::memory_order_release); return true;
    }
    void* original=nullptr;
    auto result=MH_CreateHook(hook.target,replacement,&original);
    if(result!=MH_OK || !original) {HIMITSU_LOG_ERROR("ThreadGuard","Cannot relocate %s: %s",hook.name,MH_StatusToString(result));return false;}
    hook.trampoline.store(original,std::memory_order_release);hook.created=true;return true;
}
bool enable(bool value,std::uint64_t deadline=0) {
    himitsu::platform::windows::ThreadHookMaintenance scope;
    bool queued=true;
    for(Hook* hook:hooks)if(hook->created) {
        if(!himitsu::platform::windows::guarded_hook_intact(hook->target))return false;
        if(!value && !himitsu::platform::windows::unregister_guarded_region(hook->guard_token,deadline))return false;
    }
    for(Hook* hook:hooks) if(hook->created) {
        auto result=value?MH_QueueEnableHook(hook->target):MH_QueueDisableHook(hook->target);
        if(result!=MH_OK) HIMITSU_LOG_ERROR("ThreadGuard","Cannot queue %s enable=%d: %s",hook->name,value,MH_StatusToString(result));
        queued=queued && result==MH_OK;
    }
    auto result=MH_ApplyQueued();
    if(result!=MH_OK) HIMITSU_LOG_ERROR("ThreadGuard","Cannot apply thread hooks: %s",MH_StatusToString(result));
    if(queued && result==MH_OK && value)for(Hook* hook:hooks)if(hook->created) {
        hook->guard_token=himitsu::platform::windows::register_guarded_hook(hook->name,hook->target);
        queued=queued && hook->guard_token!=0;
    }
    return queued && result==MH_OK;
}
}
namespace himitsu::platform::windows {
ThreadHookMaintenance::ThreadHookMaintenance() {++maintenance_depth;}
ThreadHookMaintenance::~ThreadHookMaintenance() {--maintenance_depth;}
bool same_thread_handle(HANDLE first,HANDLE second) {return compare_handles && first && second && compare_handles(first,second);}
bool register_native_thread(HANDLE thread) {
    if(!compare_handles || !thread) return false;
    HANDLE owned=nullptr;
    if(!DuplicateHandle(GetCurrentProcess(),thread,GetCurrentProcess(),&owned,SYNCHRONIZE,FALSE,0)) return false;
    auto& state=State::instance(); bool success=false;
    while(!state.shutting_down()) {
        State::ReferenceRead read(state);
        if(std::any_of(read->threads.begin(),read->threads.end(),[&](const auto& e){return same_thread_handle(e.os_thread,owned);})) {success=true;break;}
        auto next=std::make_unique<State::References>(*read.get());next->threads.push_back({nullptr,owned});
        if(state.publish_references(read.get(),next)) {owned=nullptr;success=true;break;}
    }
    if(owned) CloseHandle(owned); return success;
}
void unregister_native_thread(HANDLE thread) {
    auto& state=State::instance();
    for(;;) {
        State::ReferenceRead read(state);
        auto next=std::make_unique<State::References>(*read.get());
        std::erase_if(next->threads,[&](const auto& entry){return same_thread_handle(entry.os_thread,thread);});
        if(next->threads.size()==read->threads.size() || state.publish_references(read.get(),next,true)) return;
    }
}
bool start_thread_guard() {
    AcquireSRWLockExclusive(&hook_lock);
    if(installed.load(std::memory_order_acquire)) {ReleaseSRWLockExclusive(&hook_lock);return true;}
    HMODULE base=GetModuleHandleW(L"kernelbase.dll");
    compare_handles=base?reinterpret_cast<CompareFn>(GetProcAddress(base,"CompareObjectHandles")):nullptr;
    if(!compare_handles) HIMITSU_LOG_ERROR("ThreadGuard","CompareObjectHandles unavailable; exact OS thread protection cannot be installed");
    HMODULE jvm=GetModuleHandleW(L"jvm.dll");
    if(jvm) {
        jvm_begin=reinterpret_cast<std::uintptr_t>(jvm);
        auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(jvm);
        auto* nt=reinterpret_cast<IMAGE_NT_HEADERS*>(jvm_begin+dos->e_lfanew);
        jvm_end=jvm_begin+nt->OptionalHeader.SizeOfImage;
    }
    auto initialized=MH_Initialize();
    bool ready=initialized==MH_OK || initialized==MH_ERROR_ALREADY_INITIALIZED;
    bool success=ready && compare_handles && jvm
        && prepare(stop_hook,reinterpret_cast<void*>(guarded_stop))
        && prepare(suspend_hook,reinterpret_cast<void*>(guarded_suspend))
        && prepare(all_threads_hook,reinterpret_cast<void*>(guarded_threads))
        && prepare(base_suspend,reinterpret_cast<void*>(guarded_base_suspend))
        && prepare(base_terminate,reinterpret_cast<void*>(guarded_base_terminate))
        && prepare(kernel_suspend,reinterpret_cast<void*>(guarded_kernel_suspend))
        && prepare(kernel_terminate,reinterpret_cast<void*>(guarded_kernel_terminate));
    // All original addresses exist before the first detour can run.
    if(success) success=enable(true);
    if(!success && ready) enable(false);
    installed.store(success,std::memory_order_release);admitting.store(success,std::memory_order_release);
    HIMITSU_LOG_INFO("ThreadGuard","JVM/Win32 relocated hooks ready=%d object_identity=%d",success,compare_handles!=nullptr);
    ReleaseSRWLockExclusive(&hook_lock);return success;
}
bool stop_thread_guard(std::uint64_t deadline) {
    admitting.store(false,std::memory_order_release);
    if(GetTickCount64()>deadline) return false;
    AcquireSRWLockExclusive(&hook_lock);
    bool instrumentation=stop_instrumentation_entries(deadline);
    bool success=(!installed.load(std::memory_order_acquire) || enable(false,deadline)) && instrumentation;
    if(success) installed.store(false,std::memory_order_release);
    // Disabled entries may still have in-flight callers; keep originals and trampolines.
    ReleaseSRWLockExclusive(&hook_lock);return success;
}
}
