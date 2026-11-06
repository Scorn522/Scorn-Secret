#pragma once

#include <jni.h>
#include <jvmti.h>

namespace himitsu::jvm {
bool initialize_class_control(JavaVM* vm, jvmtiEnv* jvmti);
jobject take_exception(JNIEnv* env);
jobject new_exception(JNIEnv* env, const char* type, const char* message);
jobject get_loaded_classes(JNIEnv* env);
jobject get_class_instances(JNIEnv* env, jclass type);
jobject redefine_class(JNIEnv* env, jclass type, jbyteArray bytes);
jobject redefine_classes(JNIEnv* env, jobjectArray types, jobjectArray byte_arrays);
jobject retransform_class(JNIEnv* env, jobject value);
jobject retransform_class_observed(JNIEnv* env, jclass type);
jobject dump_class(JNIEnv* env, jclass type);
jobject configure_class_load_hook(JNIEnv* env, jclass callback, jobject reflected_method);
jobject define_class(JNIEnv* env, jstring name, jobject loader, jbyteArray bytes);
jobject lookup_define_class(JNIEnv* env, jobject lookup, jstring name, jbyteArray bytes, jobject context);
jobject read_zip_entry(JNIEnv* env, jstring zip_path, jstring entry_name);
jobject get_transformed_class_bytes(JNIEnv* env, jobject loader, jstring class_name);
jobject protect_thread(JNIEnv* env, jobject thread);
jobject unprotect_thread(JNIEnv* env, jobject thread);
jobject bind_render(JNIEnv* env, jclass callback, jobject reflected_method);
jobject render_frame(JNIEnv* env, jboolean before, jint stage, jlong context);
bool invoke_render_callback(bool before, jint stage, jlong context);
}
