#pragma once

#include <jni.h>
#include <jvmti.h>

namespace himitsu::jvm {
JavaVM* find_created_vm();
jvmtiEnv* get_jvmti(JavaVM* vm);
}
