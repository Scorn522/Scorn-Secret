#pragma once

#include <jni.h>

namespace himitsu::core {
jobject dispatch_command(JNIEnv* env, jstring command, jobjectArray arguments);
}
