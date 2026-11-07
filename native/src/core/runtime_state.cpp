#include "himitsu/core/runtime_state.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/platform/windows/module_guard.hpp"
#include "himitsu/platform/windows/swap_buffers_hook.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/validation/runtime_lease.hpp"
#include "himitsu/validation/validation_gate.hpp"
#include <algorithm>
#include <chrono>

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

namespace {
bool holds_ref(const RuntimeState::References& refs,jobject value) {
    for(jobject ref:{static_cast<jobject>(refs.transformer),static_cast<jobject>(refs.render),static_cast<jobject>(refs.bootstrap),
            static_cast<jobject>(refs.cleanup_reader),static_cast<jobject>(refs.event_installer),static_cast<jobject>(refs.event_bridge),static_cast<jobject>(refs.event_bus),
            static_cast<jobject>(refs.event_array_type),refs.game_loader,refs.event_loader,refs.event_handles[0],refs.event_handles[1]})if(ref==value)return true;
    for(jobject ref:{static_cast<jobject>(refs.host_hooks[0]),static_cast<jobject>(refs.host_hooks[1]),static_cast<jobject>(refs.host_hooks[2]),
            refs.shutdown_hook,refs.host_objects[0],refs.host_objects[1],refs.host_threads[0],refs.host_threads[1]}) if(ref==value) return true;
    for(jobject ref:refs.exit_denials) if(ref==value) return true;
    for(const auto& thread:refs.threads) if(thread.java_thread==value) return true;
    return false;
}
bool holds_handle(const RuntimeState::References& refs,HANDLE value) {
    for(const auto& thread:refs.threads) if(thread.os_thread==value) return true;
    return false;
}
}
RuntimeState::ReferenceRead::ReferenceRead(RuntimeState& state,JNIEnv* env):state_(state),env_(env) {
    // The counter precedes the pointer load; publication/reclamation use the same SC order.
    state_.reference_readers_.fetch_add(1,std::memory_order_seq_cst);
    value_=state_.references_.load(std::memory_order_seq_cst);
}
RuntimeState::ReferenceRead::~ReferenceRead() {
    if(state_.reference_readers_.fetch_sub(1,std::memory_order_seq_cst)==1) {
        if(state_.retired_pending_.load(std::memory_order_acquire) && !state_.shutting_down()) state_.collect_references(env_);
        if(state_.shutting_down()) {std::lock_guard lock(state_.drain_mutex_);state_.drained_.notify_all();}
    }
}
bool RuntimeState::publish_references(const References* expected,std::unique_ptr<References>& next,bool retiring) {
    StateLock lock(&lock_);
    if((shutting_down() && !retiring) || references_.load(std::memory_order_seq_cst)!=expected) return false;
    // Reserve before publishing; allocation failure must leave the previous snapshot intact.
    retired_snapshots_.reserve(retired_snapshots_.size()+1);
    retired_refs_.reserve(retired_refs_.size()+expected->threads.size()+expected->exit_denials.size()+24);
    retired_handles_.reserve(retired_handles_.size()+expected->threads.size());
    auto retire_ref=[&](jobject value) {
        if(value && !holds_ref(*next,value) && std::find(retired_refs_.begin(),retired_refs_.end(),value)==retired_refs_.end()) retired_refs_.push_back(value);
    };
    for(jobject ref:{static_cast<jobject>(expected->transformer),static_cast<jobject>(expected->render),static_cast<jobject>(expected->bootstrap),
            static_cast<jobject>(expected->cleanup_reader),static_cast<jobject>(expected->event_installer),static_cast<jobject>(expected->event_bridge),static_cast<jobject>(expected->event_bus),
            static_cast<jobject>(expected->event_array_type),expected->game_loader,expected->event_loader,expected->event_handles[0],expected->event_handles[1]})retire_ref(ref);
    for(jobject ref:{static_cast<jobject>(expected->host_hooks[0]),static_cast<jobject>(expected->host_hooks[1]),static_cast<jobject>(expected->host_hooks[2]),
            expected->shutdown_hook,expected->host_objects[0],expected->host_objects[1],expected->host_threads[0],expected->host_threads[1]})retire_ref(ref);
    for(jobject ref:expected->exit_denials)retire_ref(ref);
    for(const auto& thread:expected->threads) {
        retire_ref(thread.java_thread);
        if(thread.os_thread && !holds_handle(*next,thread.os_thread)
            && std::find(retired_handles_.begin(),retired_handles_.end(),thread.os_thread)==retired_handles_.end()) retired_handles_.push_back(thread.os_thread);
    }
    retired_snapshots_.push_back(references_.exchange(next.release(),std::memory_order_seq_cst));
    retired_pending_.store(true,std::memory_order_release);
    return true;
}
void RuntimeState::collect_references(JNIEnv* env) {
    std::vector<References*> snapshots;
    std::vector<jobject> refs;
    std::vector<HANDLE> handles;
    {
        StateLock lock(&lock_);
        if(reference_readers_.load(std::memory_order_seq_cst)!=0) return;
        auto* current=references_.load(std::memory_order_seq_cst);
        if(env) {
            // A failed publication may have restored an old reference; never reclaim a live slot.
            std::erase_if(retired_refs_,[&](jobject value){return holds_ref(*current,value);});
            refs.swap(retired_refs_);
        }
        std::erase_if(retired_handles_,[&](HANDLE value){return holds_handle(*current,value);});
        handles.swap(retired_handles_); snapshots.swap(retired_snapshots_);
        retired_pending_.store(!retired_refs_.empty(),std::memory_order_release);
    }
    for(jobject ref:refs) env->DeleteGlobalRef(ref);
    for(HANDLE handle:handles) CloseHandle(handle);
    for(References* snapshot:snapshots) delete snapshot;
}
jclass RuntimeState::local_callback(JNIEnv* env,bool render,jmethodID& method) {
    ReferenceRead read(*this,env);
    method=render?read->render_method:read->transformer_method;
    jclass value=render?read->render:read->transformer;
    return value?static_cast<jclass>(env->NewLocalRef(value)):nullptr;
}
bool RuntimeState::shutdown(JNIEnv* env) {
    if(native_call_depth>1) return false;
    if(shutting_down_.exchange(true,std::memory_order_acq_rel)) return shutdown_complete_.load(std::memory_order_acquire);
    const std::uint64_t deadline=GetTickCount64()+5000;
    himitsu::platform::windows::request_module_guard_stop();
    himitsu::jvm::request_jvmti_guard_stop();
    bool calls_drained;
    {
        std::unique_lock lock(drain_mutex_);
        const auto now=GetTickCount64();
        calls_drained=drained_.wait_for(lock,std::chrono::milliseconds(now<deadline?deadline-now:0),[&] {
            return active_calls_.load(std::memory_order_acquire)<=native_call_depth;
        });
    }
    const bool module=himitsu::platform::windows::stop_module_guard(deadline);
    const bool threads=himitsu::platform::windows::stop_thread_guard(deadline);
    const bool jvmti=himitsu::jvm::shutdown_jvmti_guard(deadline);
    const bool render=calls_drained && module && himitsu::platform::windows::uninstall_swap_buffers_hook(deadline);
    bool references_drained=false;
    if(calls_drained && module && threads && jvmti && render) {
        bool cleared=false;
        {
            ReferenceRead read(*this);
            auto empty=std::make_unique<References>();
            cleared=publish_references(read.get(),empty,true);
        }
        std::unique_lock lock(drain_mutex_);
        const auto now=GetTickCount64();
        references_drained=cleared && drained_.wait_for(lock,std::chrono::milliseconds(now<deadline?deadline-now:0),[&] {
            return reference_readers_.load(std::memory_order_seq_cst)==0;
        });
    }
    if(!calls_drained || !module || !threads || !jvmti || !render || !references_drained) {
        HIMITSU_LOG_ERROR("RuntimeState","Shutdown incomplete; resources retained: calls=%d module=%d threads=%d jvmti=%d render=%d readers=%d",
            calls_drained,module,threads,jvmti,render,references_drained);
        return false;
    }
    collect_references(env);
    {
        StateLock lock(&lock_);
        initialized_=false; vm_=nullptr; jvmti_=nullptr;
        game_directory_.clear(); mod_path_.clear();
    }
    himitsu::validation::lease::stop();
    shutdown_complete_.store(true,std::memory_order_release);
    HIMITSU_LOG_INFO("RuntimeState","Runtime shutdown complete");
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
