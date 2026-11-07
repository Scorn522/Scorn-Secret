#pragma once
#include <jni.h>
#include <jvmti.h>
#include <cstddef>
namespace himitsu::jvm {
bool source_images_active();
bool remember_owned_image(const unsigned char* bytes, std::size_t size);
bool load_source_images(JNIEnv* env, jvmtiEnv* jvmti, const wchar_t* archive);
bool remember_game_bootstrap(JNIEnv* env,jclass bootstrap);
bool remember_defined_installer(JNIEnv* env,jobject loader,jclass type,const unsigned char* bytes,std::size_t size);
jobject define_event_bridge(JNIEnv* env,jbyteArray bytes,jclass bus,jobjectArray handlers);
jobject verify_event_bridge(JNIEnv* env);
bool maintain_event_bridge(JNIEnv* env);
bool apply_source_image(JNIEnv* env,jvmtiEnv* jvmti,jobject loader,jclass redefining,const char* name,jint length,
    const unsigned char* input, jint* output_length, unsigned char** output);
}
