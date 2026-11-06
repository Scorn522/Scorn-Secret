#pragma once
#include <jni.h>
#include <jvmti.h>
#include <cstddef>
namespace himitsu::jvm {
bool source_images_active();
bool remember_owned_image(const unsigned char* bytes, std::size_t size);
bool load_source_images(JNIEnv* env, jvmtiEnv* jvmti, const wchar_t* archive);
bool apply_source_image(jvmtiEnv* jvmti, const char* name, jint length,
    const unsigned char* input, jint* output_length, unsigned char** output);
}
