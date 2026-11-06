#include "himitsu/jvm/java_vm.hpp"
#include "himitsu/jvm/late_recovery.hpp"

#include "himitsu/core/native_log.hpp"

#include <windows.h>

#include <atomic>

namespace himitsu::jvm {
JavaVM* find_created_vm() {
    static std::atomic<ULONGLONG> last_recovery{0};
    const ULONGLONG now = GetTickCount64();
    ULONGLONG previous = last_recovery.load(std::memory_order_acquire);
    if ((previous == 0 || now - previous >= 500)
        && last_recovery.compare_exchange_strong(previous, now, std::memory_order_acq_rel)) {
        HIMITSU_LOG_DEBUG("JavaVM", "尝试执行 JVM 后置恢复（tick=%llu）", static_cast<unsigned long long>(now));
        if (JavaVM* recovered = late_recover_created_vm(); recovered != nullptr) {
            HIMITSU_LOG_INFO("JavaVM", "JVM 后置恢复返回 vm=%p", recovered);
            return recovered;
        }
        HIMITSU_LOG_DEBUG("JavaVM", "JVM 后置恢复未返回 JavaVM");
    }
    return nullptr;
}

jvmtiEnv* get_jvmti(JavaVM* vm) {
    if (vm == nullptr) {
        HIMITSU_LOG_WARNING("JavaVM", "获取 JVMTI 时收到空 JavaVM");
        return nullptr;
    }
    jvmtiEnv* jvmti = nullptr;
    const jint result = vm->GetEnv(
        reinterpret_cast<void**>(&jvmti),
        JVMTI_VERSION_1_2
    );
    if (result != JNI_OK) {
        HIMITSU_LOG_WARNING("JavaVM", "GetEnv(JVMTI_VERSION_1_2) 调用失败（jni=%d）", result);
    } else {
        HIMITSU_LOG_INFO("JavaVM", "GetEnv(JVMTI_VERSION_1_2) 调用成功（env=%p，表=%p）", jvmti, jvmti == nullptr ? nullptr : jvmti->functions);
    }
    return result == JNI_OK ? jvmti : nullptr;
}
}
