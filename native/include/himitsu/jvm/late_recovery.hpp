#pragma once

#include <jni.h>
#include <jvmti.h>

namespace himitsu::jvm {

JavaVM* late_recover_created_vm();

bool late_recover_jvmti_dispatch(jvmtiEnv* env);
bool late_recover_jni_dispatch(JNIEnv* env);
}
