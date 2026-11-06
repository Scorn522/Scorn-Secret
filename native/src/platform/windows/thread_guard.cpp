#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include <jni.h>
#include <windows.h>
#include <MinHook.h>
#include <algorithm>
#include <atomic>
#include <vector>

namespace {
using StopThreadFn = void (JNICALL*)(JNIEnv*, jobject, jobject);
using SuspendThreadFn = void (JNICALL*)(JNIEnv*, jobject);
using GetAllThreadsFn = jobjectArray (JNICALL*)(JNIEnv*, jclass);

struct Hook {
    const char* name;
    void* target = nullptr;
    std::atomic<void*> trampoline{nullptr};
    bool created = false;
};
Hook stop_hook{"JVM_StopThread"};
Hook suspend_hook{"JVM_SuspendThread"};
Hook all_threads_hook{"JVM_GetAllThreads"};
std::atomic<bool> installed{false};
SRWLOCK hook_lock = SRWLOCK_INIT;

bool is_protected(JNIEnv* env, jobject thread) {
    if (env == nullptr || thread == nullptr) return false;
    auto& state = himitsu::core::RuntimeState::instance();
    himitsu::core::StateLock lock(state.references_lock());
    return std::any_of(state.protected_threads.begin(), state.protected_threads.end(), [&](jobject value) {
        return env->IsSameObject(value, thread) == JNI_TRUE;
    });
}

bool prepare_hook(Hook& hook, void* replacement) {
    if (hook.created) return true;
    HMODULE jvm = GetModuleHandleW(L"jvm.dll");
    if (jvm == nullptr) return false;
    hook.target = reinterpret_cast<void*>(GetProcAddress(jvm, hook.name));
    if (hook.target == nullptr) return false;
    void* original = nullptr;
    const MH_STATUS result = MH_CreateHook(hook.target, replacement, &original);
    if (result != MH_OK || original == nullptr) {
        HIMITSU_LOG_ERROR("ThreadGuard", "Cannot relocate %s: %s", hook.name, MH_StatusToString(result));
        return false;
    }
    // MinHook decodes complete instructions and relocates relative operands.
    // Publish all three originals before enabling any entry point.
    hook.trampoline.store(original, std::memory_order_release);
    hook.created = true;
    return true;
}

bool enable_hooks(bool enable) {
    Hook* hooks[]{&stop_hook, &suspend_hook, &all_threads_hook};
    for (Hook* hook : hooks) {
        if (!hook->created) continue;
        const MH_STATUS status = enable ? MH_QueueEnableHook(hook->target) : MH_QueueDisableHook(hook->target);
        if (status != MH_OK) {
            HIMITSU_LOG_ERROR("ThreadGuard", "Cannot queue %s enable=%d: %s", hook->name, enable, MH_StatusToString(status));
            return false;
        }
    }
    const MH_STATUS status = MH_ApplyQueued();
    if (status != MH_OK) HIMITSU_LOG_ERROR("ThreadGuard", "Cannot apply thread hooks: %s", MH_StatusToString(status));
    return status == MH_OK;
}

void JNICALL guarded_stop_thread(JNIEnv* env, jobject thread, jobject throwable) {
    if (!is_protected(env, thread))
        reinterpret_cast<StopThreadFn>(stop_hook.trampoline.load(std::memory_order_acquire))(env, thread, throwable);
}
void JNICALL guarded_suspend_thread(JNIEnv* env, jobject thread) {
    if (!is_protected(env, thread))
        reinterpret_cast<SuspendThreadFn>(suspend_hook.trampoline.load(std::memory_order_acquire))(env, thread);
}
jobjectArray JNICALL guarded_get_all_threads(JNIEnv* env, jclass type) {
    jobjectArray source = reinterpret_cast<GetAllThreadsFn>(all_threads_hook.trampoline.load(std::memory_order_acquire))(env, type);
    if (source == nullptr || env->ExceptionCheck()) return source;
    const jsize length = env->GetArrayLength(source);
    std::vector<jobject> visible;
    visible.reserve(static_cast<std::size_t>(length));
    for (jsize index = 0; index < length; ++index) {
        jobject thread = env->GetObjectArrayElement(source, index);
        if (is_protected(env, thread)) env->DeleteLocalRef(thread);
        else visible.push_back(thread);
    }
    jclass thread_type = env->FindClass("java/lang/Thread");
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(visible.size()), thread_type, nullptr);
    if (result != nullptr) for (jsize index = 0; index < static_cast<jsize>(visible.size()); ++index)
        env->SetObjectArrayElement(result, index, visible[static_cast<std::size_t>(index)]);
    for (jobject thread : visible) env->DeleteLocalRef(thread);
    env->DeleteLocalRef(thread_type);
    env->DeleteLocalRef(source);
    return result;
}
}

namespace himitsu::platform::windows {
bool start_thread_guard() {
    AcquireSRWLockExclusive(&hook_lock);
    if (installed.load(std::memory_order_acquire)) {
        ReleaseSRWLockExclusive(&hook_lock);
        return true;
    }
    const MH_STATUS initialization = MH_Initialize();
    const bool ready = initialization == MH_OK || initialization == MH_ERROR_ALREADY_INITIALIZED;
    const bool success = ready
        && prepare_hook(stop_hook, reinterpret_cast<void*>(guarded_stop_thread))
        && prepare_hook(suspend_hook, reinterpret_cast<void*>(guarded_suspend_thread))
        && prepare_hook(all_threads_hook, reinterpret_cast<void*>(guarded_get_all_threads))
        && enable_hooks(true);
    if (!success && ready) enable_hooks(false);
    installed.store(success, std::memory_order_release);
    HIMITSU_LOG_INFO("ThreadGuard", "Relocated thread hooks ready=%s", success ? "true" : "false");
    ReleaseSRWLockExclusive(&hook_lock);
    return success;
}

void stop_thread_guard() {
    AcquireSRWLockExclusive(&hook_lock);
    if (installed.load(std::memory_order_acquire) && enable_hooks(false))
        installed.store(false, std::memory_order_release);
    // A thread may already be inside a detour when entries are disabled. Keep
    // these three bounded trampolines valid until process exit; never free them
    // or globally uninitialize the shared MinHook backend underneath that call.
    ReleaseSRWLockExclusive(&hook_lock);
}
}
