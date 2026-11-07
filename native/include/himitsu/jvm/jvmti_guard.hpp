#pragma once
#include <cstdint>

#include <jvmti.h>

namespace himitsu::jvm {
bool expected_jvmti_dispatch(jvmtiInterface_1_*& address,jvmtiInterface_1_& expected);
bool initialize_jvmti_guard(JavaVM* vm, jvmtiEnv* env);
bool install_jvmti_guard();
bool quarantine_external_jvmti(JNIEnv* env);
bool jvmti_isolation_enabled();
bool start_jvmti_guard_monitor();
void request_jvmti_guard_stop();
bool shutdown_jvmti_guard(std::uint64_t deadline);
jvmtiError trusted_current_thread(jthread* thread);
jvmtiEnv* trusted_jvmti();
JavaVM* trusted_vm();
bool refresh_trusted_jvmti();
bool trusted_jvmti_healthy();

jvmtiError trusted_add_capabilities(const jvmtiCapabilities* capabilities);
jvmtiError trusted_set_event_callbacks(const jvmtiEventCallbacks* callbacks, jint size);
jvmtiError trusted_set_event_notification_mode(
    jvmtiEventMode mode,
    jvmtiEvent event_type,
    jthread event_thread
);
jvmtiError trusted_retransform_classes(jint class_count, const jclass* classes);
jvmtiError trusted_redefine_classes(
    jint class_count,
    const jvmtiClassDefinition* definitions
);
}
