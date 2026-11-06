#include "himitsu/bootstrap/early_guard.hpp"

#include "himitsu/bootstrap/runtime_bootstrap.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/jvm/java_vm.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/jvm/late_recovery.hpp"
#include "himitsu/platform/windows/instrumentation_guard.hpp"
#include "himitsu/platform/windows/module_guard.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"

#include <atomic>

namespace {
std::atomic<int> early_guard_state{0};
std::atomic<int> early_guard_jvmti_disable{-1};
}

namespace himitsu::bootstrap {
bool install_early_guards(bool disable_jvmti) {
    int expected = 0;
    if (!early_guard_state.compare_exchange_strong(expected, 1)) {
        HIMITSU_LOG_DEBUG(
            "EarlyGuard",
            "守护初始化已在执行或已经结束（当前状态=%d，请求禁用JVMTI=%s）",
            expected,
            disable_jvmti ? "是" : "否"
        );
        for (unsigned attempt=0; attempt<10000 && early_guard_state.load(std::memory_order_acquire)==1; ++attempt) {
            Sleep(1);
        }
        const int final_state = early_guard_state.load(std::memory_order_acquire);
        const bool compatible = final_state == 2
            && early_guard_jvmti_disable.load(std::memory_order_acquire) == (disable_jvmti ? 1 : 0);
        HIMITSU_LOG_INFO(
            "EarlyGuard",
            "复用守护初始化结果（状态=%d，参数兼容=%s）",
            final_state,
            compatible ? "是" : "否"
        );
        return compatible;
    }
    early_guard_jvmti_disable.store(disable_jvmti ? 1 : 0, std::memory_order_release);

    core::log::initialize(module());
    HIMITSU_LOG_INFO("EarlyGuard", "开始初始化运行时守护（禁用外部JVMTI=%s）", disable_jvmti ? "是" : "否");
    JavaVM* vm = jvm::find_created_vm();
    HIMITSU_LOG_INFO("EarlyGuard", "JavaVM 查找结果（vm=%p）", vm);
    JNIEnv* current_jni = nullptr;
    const bool jni_ready = vm != nullptr && vm->GetEnv(reinterpret_cast<void**>(&current_jni), JNI_VERSION_1_8)==JNI_OK
        && jvm::late_recover_jni_dispatch(current_jni);
    jvmtiEnv* jvmti = jni_ready ? jvm::get_jvmti(vm) : nullptr;
    HIMITSU_LOG_INFO("EarlyGuard", "JVMTI 环境查找结果（env=%p）", jvmti);
    const bool dispatch_recovered = jvmti != nullptr
        && jvm::late_recover_jvmti_dispatch(jvmti);
    HIMITSU_LOG_INFO("EarlyGuard", "JVMTI 分发表后置恢复结果（成功=%s）", dispatch_recovered ? "是" : "否");
    const bool jvmti_initialized = dispatch_recovered && jvm::initialize_jvmti_guard(vm, jvmti);
    HIMITSU_LOG_INFO("EarlyGuard", "JVMTI 守护状态捕获结果（成功=%s）", jvmti_initialized ? "是" : "否");
    bool capabilities_ok = false;
    if (jvmti_initialized) {
        jvmtiCapabilities required{};
        required.can_redefine_classes = 1;
        required.can_retransform_classes = 1;
        required.can_generate_all_class_hook_events = 1;
        required.can_tag_objects = 1;
        const jvmtiError potential_error = JVMTI_ERROR_NONE;
        const jvmtiError acquire_error = jvm::trusted_add_capabilities(&required);
        jvmtiCapabilities acquired{};
        const jvmtiError verify_error = acquire_error == JVMTI_ERROR_NONE
            ? jvmti->GetCapabilities(&acquired)
            : acquire_error;
        capabilities_ok = potential_error == JVMTI_ERROR_NONE
            && acquire_error == JVMTI_ERROR_NONE
            && verify_error == JVMTI_ERROR_NONE
            && acquired.can_redefine_classes
            && acquired.can_retransform_classes
            && acquired.can_generate_all_class_hook_events
            && acquired.can_tag_objects;
        HIMITSU_LOG_INFO(
            "EarlyGuard",
            "JVMTI 能力获取完成（potential=%d，add=%d，verify=%d，重定义=%d，重转换=%d，类钩子=%d，标签=%d）",
            potential_error,
            acquire_error,
            verify_error,
            acquired.can_redefine_classes,
            acquired.can_retransform_classes,
            acquired.can_generate_all_class_hook_events,
            acquired.can_tag_objects
        );
    }

    const bool prerequisites_ok = jvmti_initialized && capabilities_ok;
    const bool instrumentation_attempted = prerequisites_ok;
    const bool instrumentation_ok = instrumentation_attempted
        && platform::windows::disable_instrumentation_entries();
    const bool jvmti_guard_attempted = instrumentation_ok && disable_jvmti;
    const bool jvmti_guard_ok = instrumentation_ok
        && (!disable_jvmti || jvm::install_jvmti_guard());
    const bool isolated = jvmti_guard_ok && (!disable_jvmti || jvm::quarantine_external_jvmti(current_jni));
    const bool hook_ready = isolated && jvm::initialize_class_control(vm,jvmti);
    const bool thread_guard_attempted = hook_ready;
    const bool thread_guard_ok = thread_guard_attempted
        && platform::windows::start_thread_guard();
    const bool module_guard_attempted = thread_guard_ok;
    const bool module_guard_ok = module_guard_attempted
        && platform::windows::start_module_guard(vm, jvmti);
    const bool success = prerequisites_ok
        && instrumentation_ok
        && jvmti_guard_ok
        && thread_guard_ok
        && module_guard_ok;
    HIMITSU_LOG_INFO(
        "EarlyGuard",
        "守护组件结果（总成功=%s，插桩守护=%s/%s，JVMTI守护=%s/%s，线程守护=%s/%s，模块守护=%s/%s）",
        success ? "是" : "否",
        instrumentation_attempted ? "已执行" : "已跳过",
        instrumentation_ok ? "正常" : "失败",
        jvmti_guard_attempted ? "已执行" : "按选项跳过",
        jvmti_guard_ok ? "正常" : "失败",
        thread_guard_attempted ? "已执行" : "已跳过",
        thread_guard_ok ? "正常" : "失败",
        module_guard_attempted ? "已执行" : "已跳过",
        module_guard_ok ? "正常" : "失败"
    );
    early_guard_state.store(success ? 2 : 3, std::memory_order_release);
    HIMITSU_LOG_INFO(
        "EarlyGuard",
        "同步守护安装结束（成功=%s，禁用外部JVMTI=%s）",
        success ? "是" : "否",
        disable_jvmti ? "是" : "否"
    );
    return success;
}

bool early_guards_ready() {
    return early_guard_state.load(std::memory_order_acquire) == 2;
}
}
