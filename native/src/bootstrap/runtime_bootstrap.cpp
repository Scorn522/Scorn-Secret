#include "himitsu/bootstrap/runtime_bootstrap.hpp"

#include "himitsu/bootstrap/early_guard.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/java_vm.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/jvm/native_bridge.hpp"
#include "himitsu/platform/windows/instrumentation_guard.hpp"
#include "himitsu/validation/validation_gate.hpp"

#include <atomic>
#include <cstdio>
#include <cwchar>
#include <iterator>

namespace {
std::atomic<int> bootstrap_state{0};
HMODULE loaded_module = nullptr;

struct BootstrapContext {
    JavaVM* vm;
};

DWORD WINAPI bootstrap_worker(void* parameter) {
    const auto context = static_cast<BootstrapContext*>(parameter);
    JavaVM* vm = context == nullptr ? nullptr : context->vm;
    delete context;

    himitsu::validation::require_approval();

    himitsu::core::log::initialize(loaded_module);
    HIMITSU_LOG_INFO(
        "Bootstrap",
        "引导工作线程启动（模块=%p，传入VM=%p，线程ID=%lu）",
        loaded_module,
        vm,
        GetCurrentThreadId()
    );
    if (vm == nullptr) {
        unsigned int attempts = 0;
        while (vm == nullptr) {
            vm = himitsu::jvm::find_created_vm();
            if (vm == nullptr) {
                if (++attempts == 1 || attempts % 50 == 0) {
                    HIMITSU_LOG_DEBUG("Bootstrap", "等待已创建的 JVM（尝试次数=%u）", attempts);
                }
                Sleep(100);
            }
        }
        HIMITSU_LOG_INFO("Bootstrap", "已找到 JavaVM（vm=%p，尝试次数=%u）", vm, attempts + 1);
    } else {
        HIMITSU_LOG_INFO("Bootstrap", "使用调用方传入的 JavaVM（vm=%p）", vm);
    }

    JNIEnv* env = nullptr;
    bool attached = false;
    jint result = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
    HIMITSU_LOG_DEBUG("Bootstrap", "GetEnv(JNIEnv) 调用结束（jni=%d，env=%p）", result, env);
    if (result == JNI_EDETACHED) {
        HIMITSU_LOG_INFO("Bootstrap", "引导工作线程尚未附加，正在附加到 JVM");
        result = vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
        attached = result == JNI_OK;
        HIMITSU_LOG_INFO("Bootstrap", "AttachCurrentThread 调用结束（jni=%d，env=%p）", result, env);
    }
    if (result != JNI_OK || env == nullptr) {
        HIMITSU_LOG_ERROR("Bootstrap", "获取 JNIEnv 失败（jni=%d）", result);
        bootstrap_state.store(3);
        return 1;
    }

    jvmtiEnv* jvmti = himitsu::jvm::trusted_jvmti();
    const bool used_trusted_jvmti = jvmti != nullptr;
    if (jvmti == nullptr) {
        HIMITSU_LOG_WARNING("Bootstrap", "可信 JVMTI 环境缺失，正在请求当前环境");
        jvmti = himitsu::jvm::get_jvmti(vm);
    }
    const bool early_guards_ok = himitsu::bootstrap::early_guards_ready();
    const bool runtime_state_attempted = jvmti != nullptr && early_guards_ok;
    const int runtime_state_result = !runtime_state_attempted
        ? -1
        : himitsu::core::RuntimeState::instance().initialize(vm, jvmti);
    const bool class_control_attempted = jvmti != nullptr
        && early_guards_ok
        && runtime_state_result == 0;
    const bool class_control_ok = class_control_attempted
        && himitsu::jvm::initialize_class_control(vm, jvmti);
    HIMITSU_LOG_INFO(
        "Bootstrap",
        "运行时前置状态（jvmti=%p，来源=%s，早期守护=%s，运行时状态=%s/%d，类控制=%s/%s）",
        jvmti,
        used_trusted_jvmti ? "可信环境" : "GetEnv获取",
        early_guards_ok ? "就绪" : "缺失",
        runtime_state_attempted ? "已执行" : "已跳过",
        runtime_state_result,
        class_control_attempted ? "已执行" : "已跳过",
        class_control_ok ? "正常" : "失败"
    );
    if (jvmti == nullptr || !early_guards_ok || runtime_state_result != 0 || !class_control_ok) {
        HIMITSU_LOG_ERROR(
            "Bootstrap",
            "运行时初始化失败（vm=%p，env=%p，jvmti=%p）",
            vm,
            env,
            jvmti
        );
        bootstrap_state.store(3);
        if (attached) {
            const jint detach_result = vm->DetachCurrentThread();
            HIMITSU_LOG_DEBUG("Bootstrap", "初始化失败后已分离引导线程（jni=%d）", detach_result);
        }
        return 2;
    }

    int bridge_result = 7;
    unsigned int attempts = 0;
    while (bridge_result == 7 && attempts < 400) {
        bridge_result = himitsu::jvm::register_native_bridge(vm, jvmti);
        if (bridge_result != 7) {
            HIMITSU_LOG_INFO(
                "Bootstrap",
                "原生桥注册结束（结果=%d，尝试次数=%u）",
                bridge_result,
                attempts + 1
            );
        }
        if (bridge_result == 7) {
            if (++attempts == 1 || attempts % 40 == 0) {
                HIMITSU_LOG_DEBUG("Bootstrap", "等待 SecretNative 类加载（尝试次数=%u）", attempts);
            }
            Sleep(25);
        }
    }

    if (attached) {
        const jint detach_result = vm->DetachCurrentThread();
        HIMITSU_LOG_DEBUG("Bootstrap", "引导工作线程已分离（jni=%d）", detach_result);
    }
    bootstrap_state.store(bridge_result == 0 ? 2 : 3);
    HIMITSU_LOG_INFO("Bootstrap", "运行时引导结束（结果=%d）", bridge_result);
    return bridge_result == 0 ? 0 : 3;
}
}

namespace himitsu::bootstrap {
void set_module(HMODULE module_value) {
    loaded_module = module_value;
    wchar_t message[160]{};
    std::swprintf(
        message,
        std::size(message),
        L"[Himitsu] DLL 已加载（模块=%p，进程ID=%lu，线程ID=%lu）\r\n",
        module_value,
        GetCurrentProcessId(),
        GetCurrentThreadId()
    );
    OutputDebugStringW(message);
}

HMODULE module() {
    return loaded_module;
}

bool start_runtime(JavaVM* known_vm) {
    himitsu::core::log::initialize(loaded_module);
    HIMITSU_LOG_INFO("Bootstrap", "收到运行时启动请求（已知VM=%p，状态=%d）", known_vm, bootstrap_state.load());
    int expected = 0;
    if (!bootstrap_state.compare_exchange_strong(expected, 1)) {
        const bool accepted = expected == 1 || expected == 2;
        HIMITSU_LOG_INFO(
            "Bootstrap",
            "运行时启动复用现有状态（当前状态=%d，接受请求=%s）",
            expected,
            accepted ? "是" : "否"
        );
        return accepted;
    }
    auto* context = new (std::nothrow) BootstrapContext{known_vm};
    if (context == nullptr) {
        HIMITSU_LOG_ERROR("Bootstrap", "引导上下文内存分配失败");
        bootstrap_state.store(3);
        return false;
    }
    if (!QueueUserWorkItem(bootstrap_worker, context, WT_EXECUTEDEFAULT)) {
        const DWORD error = GetLastError();
        delete context;
        bootstrap_state.store(3);
        HIMITSU_LOG_ERROR("Bootstrap", "QueueUserWorkItem 调用失败（错误码=%lu）", error);
        return false;
    }
    HIMITSU_LOG_INFO("Bootstrap", "引导工作线程已成功加入队列");
    return true;
}
}
