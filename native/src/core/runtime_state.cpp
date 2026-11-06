#include "himitsu/core/runtime_state.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/platform/windows/module_guard.hpp"
#include "himitsu/platform/windows/swap_buffers_hook.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/validation/runtime_lease.hpp"
#include "himitsu/validation/validation_gate.hpp"

namespace himitsu::core {
namespace {
RuntimeState g_runtime_state;
thread_local unsigned int native_call_depth = 0;
}

RuntimeState& RuntimeState::instance() {
    return g_runtime_state;
}

int RuntimeState::initialize(JavaVM* vm, jvmtiEnv* jvmti) {
    if (!himitsu::validation::lease::valid()) {
        himitsu::validation::terminate_rejected(0x48560009UL);
    }
    StateLock lock(&lock_);
    if (initialized_) {
        HIMITSU_LOG_DEBUG("RuntimeState", "运行时状态已经就绪，跳过重复初始化");
        return 0;
    }

    if (vm == nullptr || jvmti == nullptr) {
        HIMITSU_LOG_ERROR("RuntimeState", "运行时状态初始化参数无效（vm=%p，jvmti=%p）", vm, jvmti);
        return 3;
    }

    vm_ = vm;
    jvmti_ = jvmti;
    initialized_ = true;
    HIMITSU_LOG_INFO("RuntimeState", "运行时状态初始化完成（vm=%p，jvmti=%p）", vm_, jvmti_);
    return 0;
}

void RuntimeState::replace_jvmti(jvmtiEnv* jvmti) {
    StateLock lock(&lock_);
    if (!initialized_ || jvmti == nullptr) return;
    HIMITSU_LOG_INFO("RuntimeState", "JVMTI 环境已替换（旧=%p，新=%p）", jvmti_, jvmti);
    jvmti_ = jvmti;
}

void RuntimeState::configure(std::string game_directory, std::string mod_path) {
    StateLock lock(&lock_);
    game_directory_ = std::move(game_directory);
    mod_path_ = std::move(mod_path);
    HIMITSU_LOG_INFO("RuntimeState", "配置完成：游戏目录='%s'，模组路径='%s'", game_directory_.c_str(), mod_path_.c_str());
}

bool RuntimeState::enter_call() {
    if (shutting_down_.load(std::memory_order_acquire)) return false;
    active_calls_.fetch_add(1, std::memory_order_acq_rel);
    ++native_call_depth;
    if (shutting_down_.load(std::memory_order_acquire)) { leave_call(); return false; }
    return true;
}

void RuntimeState::leave_call() {
    --native_call_depth;
    active_calls_.fetch_sub(1, std::memory_order_acq_rel);
    if (shutting_down_.load(std::memory_order_acquire)) {
        std::lock_guard lock(drain_mutex_);
        drained_.notify_all();
    }
}

bool RuntimeState::shutting_down() const { return shutting_down_.load(std::memory_order_acquire); }

bool RuntimeState::shutdown(JNIEnv* env) {
    // A callback cannot destroy the runtime underneath its own outer command.
    if (native_call_depth > 1) return false;
    if (shutting_down_.exchange(true, std::memory_order_acq_rel)) return true;
    {
        std::unique_lock lock(drain_mutex_);
        drained_.wait(lock, [&] { return active_calls_.load(std::memory_order_acquire) <= native_call_depth; });
    }
    HIMITSU_LOG_INFO("RuntimeState", "开始关闭运行时（env=%p）", env);
    himitsu::platform::windows::stop_module_guard();
    himitsu::platform::windows::stop_thread_guard();
    himitsu::jvm::shutdown_jvmti_guard();
    himitsu::platform::windows::uninstall_swap_buffers_hook();
    {
    StateLock lock(&lock_);
    if (env != nullptr) {
        if (transformer_class != nullptr) {
            env->DeleteGlobalRef(transformer_class);
        }
        if (render_callback_class != nullptr) {
            env->DeleteGlobalRef(render_callback_class);
        }
        for (jobject thread : protected_threads) {
            env->DeleteGlobalRef(thread);
        }
    }
    transformer_class = nullptr;
    transformer_method = nullptr;
    render_callback_class = nullptr;
    render_callback_method = nullptr;
    protected_threads.clear();
    initialized_ = false;
    vm_ = nullptr;
    jvmti_ = nullptr;
    game_directory_.clear();
    mod_path_.clear();
    }
    himitsu::validation::lease::stop();
    HIMITSU_LOG_INFO("RuntimeState", "运行时关闭结束");
    himitsu::core::log::shutdown();
    return true;
}

bool RuntimeState::initialized() const {
    StateLock lock(&lock_);
    return initialized_;
}

JavaVM* RuntimeState::vm() const {
    StateLock lock(&lock_);
    return vm_;
}

jvmtiEnv* RuntimeState::jvmti() const {
    StateLock lock(&lock_);
    return jvmti_;
}

std::string RuntimeState::game_directory_utf8() const {
    StateLock lock(&lock_);
    return game_directory_;
}

std::string RuntimeState::mod_path_utf8() const {
    StateLock lock(&lock_);
    return mod_path_;
}


SRWLOCK* RuntimeState::references_lock() {
    return &lock_;
}
}
