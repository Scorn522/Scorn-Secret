#pragma once

#include <jni.h>
#include <jvmti.h>

namespace himitsu::jvm {
int register_native_bridge(JavaVM* vm, jvmtiEnv* jvmti);
}
