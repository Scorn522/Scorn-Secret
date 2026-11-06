#include "himitsu/jvm/class_control.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/jvm/source_images.hpp"
#include "himitsu/platform/windows/swap_buffers_hook.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

namespace {
constexpr const char* transformer_signature = "(Ljava/lang/ClassLoader;Ljava/lang/String;Ljava/lang/Class;Ljava/security/ProtectionDomain;[B)[B";
constexpr const char* render_signature = "(ZIJ)Z";

struct ClassDump {
    jclass target;
    std::vector<unsigned char> bytes;
    ClassDump* previous;
};
thread_local ClassDump* current_dump = nullptr;

class DumpScope {
public:
    explicit DumpScope(ClassDump& request) : request_(request) {
        request_.previous = current_dump;
        current_dump = &request_;
    }
    ~DumpScope() { current_dump = request_.previous; }
    DumpScope(const DumpScope&) = delete;
    DumpScope& operator=(const DumpScope&) = delete;
private:
    ClassDump& request_;
};
std::atomic<jlong> heap_scan_tag{0x48494D4954535500LL};
thread_local unsigned int transformer_bypass_depth = 0;
thread_local unsigned int class_hook_depth = 0;
SRWLOCK transformed_class_log_lock = SRWLOCK_INIT;
std::unordered_set<std::string> logged_transformed_classes;
std::atomic<unsigned long long> class_hook_invocations{0};

class TransformerBypass {
public:
    TransformerBypass() {
        transformer_bypass_depth++;
    }

    ~TransformerBypass() {
        transformer_bypass_depth--;
    }

    TransformerBypass(const TransformerBypass&) = delete;
    TransformerBypass& operator=(const TransformerBypass&) = delete;
};

class ClassHookScope {
public:
    ClassHookScope() {
        class_hook_depth++;
    }

    ~ClassHookScope() {
        class_hook_depth--;
    }

    ClassHookScope(const ClassHookScope&) = delete;
    ClassHookScope& operator=(const ClassHookScope&) = delete;
};

struct HeapClassScan {
    jlong tag;
    std::size_t tagged;
    std::size_t already_tagged;
};

jvmtiIterationControl JNICALL tag_class_instance(
    jlong,
    jlong,
    jlong* tag_ptr,
    void* user_data
) {
    auto* scan = static_cast<HeapClassScan*>(user_data);
    if (*tag_ptr == 0) {
        *tag_ptr = scan->tag;
        scan->tagged++;
    } else {
        scan->already_tagged++;
    }
    return JVMTI_ITERATION_CONTINUE;
}

jobject boolean_value(JNIEnv* env, bool value) {
    jclass type = env->FindClass("java/lang/Boolean");
    jmethodID factory = env->GetStaticMethodID(type, "valueOf", "(Z)Ljava/lang/Boolean;");
    return env->CallStaticObjectMethod(type, factory, value ? JNI_TRUE : JNI_FALSE);
}

jobject jvmti_error(JNIEnv* env, jvmtiError error, const char* operation) {
    char message[160]{};
    std::snprintf(message, sizeof(message), "%s failed with JVMTI error %d", operation, static_cast<int>(error));
    return himitsu::jvm::new_exception(env, "java/lang/IllegalStateException", message);
}

void JNICALL class_file_load_hook(
    jvmtiEnv* jvmti,
    JNIEnv* env,
    jclass class_being_redefined,
    jobject loader,
    const char* name,
    jobject protection_domain,
    jint class_data_len,
    const unsigned char* class_data,
    jint* new_class_data_len,
    unsigned char** new_class_data
) {
    class_hook_invocations.fetch_add(1, std::memory_order_release);
    // Retransformation callbacks execute on the requesting thread. Each nested
    // request owns its capture; no native lock is carried across the VM call.
    for (ClassDump* request=current_dump; request!=nullptr; request=request->previous) {
        if (class_being_redefined!=nullptr && env->IsSameObject(request->target,class_being_redefined))
            request->bytes.assign(class_data,class_data+class_data_len);
    }

    const bool source_known=himitsu::jvm::apply_source_image(jvmti,name,class_data_len,class_data,new_class_data_len,new_class_data);
    const bool owned_source=source_known&&name!=nullptr&&std::strncmp(name,"com/himitsu/secret/",19)==0;
    if(source_known&&!owned_source)return; // JDK image restoration never enters mod transforms.
    const unsigned char* input_data=*new_class_data!=nullptr?*new_class_data:class_data;
    const jint input_length=*new_class_data!=nullptr?*new_class_data_len:class_data_len;
    if ((transformer_bypass_depth != 0 && !owned_source) || class_hook_depth != 0) {
        return;
    }
    const ClassHookScope hook_scope;

    auto& state = himitsu::core::RuntimeState::instance();
    jclass transformer = nullptr;
    jmethodID method = nullptr;
    {
        himitsu::core::StateLock lock(state.references_lock());
        if (state.transformer_class != nullptr) {
            transformer = static_cast<jclass>(env->NewLocalRef(state.transformer_class));
            method = state.transformer_method;
        }
    }
    if (transformer == nullptr || method == nullptr) return;

    jstring class_name = name == nullptr ? nullptr : env->NewStringUTF(name);
    jbyteArray input = env->NewByteArray(input_length);
    if (input == nullptr) {
        env->ExceptionClear();
        return;
    }
    env->SetByteArrayRegion(input, 0, input_length, reinterpret_cast<const jbyte*>(input_data));
    auto output = static_cast<jbyteArray>(env->CallStaticObjectMethod(
        transformer,
        method,
        loader,
        class_name,
        class_being_redefined,
        protection_domain,
        input
    ));
    if (env->ExceptionCheck()) {
        HIMITSU_LOG_ERROR(
            "ClassHook",
            "Java 转换器执行失败：类='%s'，重定义=%s",
            name == nullptr ? "<unnamed>" : name,
            class_being_redefined == nullptr ? "否" : "是"
        );
        env->ExceptionClear();
        return;
    }
    if (output == nullptr || env->IsSameObject(output, input)) {
        return;
    }

    const jsize length = env->GetArrayLength(output);
    unsigned char* transformed = nullptr;
    if (jvmti->Allocate(length, &transformed) != JVMTI_ERROR_NONE) {
        return;
    }
    env->GetByteArrayRegion(output, 0, length, reinterpret_cast<jbyte*>(transformed));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        jvmti->Deallocate(transformed);
        return;
    }
    if(*new_class_data!=nullptr)jvmti->Deallocate(*new_class_data);
    *new_class_data_len = length;
    *new_class_data = transformed;

    const std::string transformed_name = name == nullptr ? "<unnamed>" : name;
    AcquireSRWLockExclusive(&transformed_class_log_lock);
    const bool first_transform = logged_transformed_classes.insert(transformed_name).second;
    ReleaseSRWLockExclusive(&transformed_class_log_lock);
    if (first_transform) {
        HIMITSU_LOG_INFO(
            "ClassHook",
            "ASM 钩子已应用：类='%s'，输入=%d，输出=%d，重定义=%s",
            transformed_name.c_str(),
            class_data_len,
            length,
            class_being_redefined == nullptr ? "否" : "是"
        );
    }
}
}

namespace himitsu::jvm {
bool initialize_class_control(JavaVM*, jvmtiEnv*) {
    jvmtiCapabilities capabilities{};
    capabilities.can_redefine_classes = 1;
    capabilities.can_retransform_classes = 1;
    capabilities.can_generate_all_class_hook_events = 1;
    capabilities.can_tag_objects = 1;
    const jvmtiError capability_error = trusted_add_capabilities(&capabilities);
    if (capability_error != JVMTI_ERROR_NONE) {
        HIMITSU_LOG_ERROR("ClassControl", "AddCapabilities 调用失败（jvmti=%d）", capability_error);
        return false;
    }
    jvmtiEventCallbacks callbacks{};
    callbacks.ClassFileLoadHook = class_file_load_hook;
    const jvmtiError callback_error = trusted_set_event_callbacks(&callbacks, sizeof(callbacks));
    HIMITSU_LOG_INFO("ClassControl", "SetEventCallbacks 调用结束（jvmti=%d）", callback_error);
    return callback_error == JVMTI_ERROR_NONE;
}

jobject take_exception(JNIEnv* env) {
    jthrowable exception = env->ExceptionOccurred();
    env->ExceptionClear();
    return exception;
}

jobject new_exception(JNIEnv* env, const char* type, const char* message) {
    jclass exception_type = env->FindClass(type);
    if (exception_type == nullptr) {
        return take_exception(env);
    }
    jmethodID constructor = env->GetMethodID(exception_type, "<init>", "(Ljava/lang/String;)V");
    jstring text = env->NewStringUTF(message);
    jobject result = env->NewObject(exception_type, constructor, text);
    return env->ExceptionCheck() ? take_exception(env) : result;
}

jobject get_loaded_classes(JNIEnv* env) {
    jvmtiEnv* jvmti = core::RuntimeState::instance().jvmti();
    if (env->EnsureLocalCapacity(32768) != JNI_OK) {
        return take_exception(env);
    }
    jint count = 0;
    jclass* classes = nullptr;
    const jvmtiError error = jvmti->GetLoadedClasses(&count, &classes);
    if (error != JVMTI_ERROR_NONE) {
        return jvmti_error(env, error, "GetLoadedClasses");
    }
    jclass class_type = env->FindClass("java/lang/Class");
    jobjectArray result = env->NewObjectArray(count, class_type, nullptr);
    for (jint index = 0; index < count && result != nullptr; ++index) {
        env->SetObjectArrayElement(result, index, classes[index]);
        env->DeleteLocalRef(classes[index]);
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes));
    return env->ExceptionCheck() ? take_exception(env) : result;
}

jobject get_class_instances(JNIEnv* env, jclass type) {
    if (type == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "GetClassInstances requires Class");
    }

    jclass class_type = env->FindClass("java/lang/Class");
    if (!env->IsSameObject(type, class_type)) {
        return env->NewObjectArray(0, type, nullptr);
    }

    jvmtiEnv* jvmti = core::RuntimeState::instance().jvmti();
    HeapClassScan scan{
        heap_scan_tag.fetch_add(1, std::memory_order_relaxed) + 1,
        0,
        0
    };
    const jvmtiError iterate_error = jvmti->IterateOverInstancesOfClass(
        class_type,
        JVMTI_HEAP_OBJECT_EITHER,
        tag_class_instance,
        &scan
    );
    if (iterate_error != JVMTI_ERROR_NONE) {
        return jvmti_error(env, iterate_error, "IterateOverInstancesOfClass");
    }

    jint count = 0;
    jobject* objects = nullptr;
    jlong* tags = nullptr;
    const jvmtiError objects_error = jvmti->GetObjectsWithTags(
        1,
        &scan.tag,
        &count,
        &objects,
        &tags
    );
    if (objects_error != JVMTI_ERROR_NONE) {
        return jvmti_error(env, objects_error, "GetObjectsWithTags");
    }
    if (env->EnsureLocalCapacity(count + 16) != JNI_OK) {
        if (objects != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char*>(objects));
        if (tags != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char*>(tags));
        return take_exception(env);
    }

    jobjectArray result = env->NewObjectArray(count, class_type, nullptr);
    for (jint index = 0; index < count; ++index) {
        env->SetObjectArrayElement(result, index, objects[index]);
        jvmti->SetTag(objects[index], 0);
        env->DeleteLocalRef(objects[index]);
    }
    if (objects != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char*>(objects));
    if (tags != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char*>(tags));
    HIMITSU_LOG_INFO(
        "ClassControl",
        "类镜像堆扫描结束（新标签=%zu，已有标签=%zu，返回数量=%d）",
        scan.tagged,
        scan.already_tagged,
        count
    );
    return env->ExceptionCheck() ? take_exception(env) : result;
}

jobject redefine_class(JNIEnv* env, jclass type, jbyteArray bytes) {
    if (type == nullptr || bytes == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "RedefineClass requires Class and byte[]");
    }
    const jsize length = env->GetArrayLength(bytes);
    std::vector<unsigned char> data(static_cast<std::size_t>(length));
    env->GetByteArrayRegion(bytes, 0, length, reinterpret_cast<jbyte*>(data.data()));
    jvmtiClassDefinition definition{type, length, data.data()};
    const TransformerBypass bypass;
    const jvmtiError error = trusted_redefine_classes(1, &definition);
    return error == JVMTI_ERROR_NONE ? boolean_value(env, true) : jvmti_error(env, error, "RedefineClasses");
}

jobject redefine_classes(JNIEnv* env, jobjectArray types, jobjectArray byte_arrays) {
    if (types == nullptr || byte_arrays == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "RedefineClasses requires Class[] and byte[][]");
    }
    const jsize count = env->GetArrayLength(types);
    if (count == 0 || env->GetArrayLength(byte_arrays) != count) {
        return new_exception(env, "java/lang/IllegalArgumentException", "RedefineClasses arrays must have equal non-zero length");
    }

    std::vector<jclass> classes(static_cast<std::size_t>(count));
    std::vector<std::vector<unsigned char>> storage(static_cast<std::size_t>(count));
    std::vector<jvmtiClassDefinition> definitions(static_cast<std::size_t>(count));
    for (jsize index = 0; index < count; ++index) {
        classes[index] = static_cast<jclass>(env->GetObjectArrayElement(types, index));
        auto bytes = static_cast<jbyteArray>(env->GetObjectArrayElement(byte_arrays, index));
        if (classes[index] == nullptr || bytes == nullptr) {
            return new_exception(env, "java/lang/IllegalArgumentException", "RedefineClasses entries cannot be null");
        }
        const jsize length = env->GetArrayLength(bytes);
        storage[index].resize(static_cast<std::size_t>(length));
        env->GetByteArrayRegion(bytes, 0, length, reinterpret_cast<jbyte*>(storage[index].data()));
        env->DeleteLocalRef(bytes);
        if (env->ExceptionCheck()) return take_exception(env);
        definitions[index] = jvmtiClassDefinition{classes[index], length, storage[index].data()};
    }

    const TransformerBypass bypass;
    const jvmtiError error = trusted_redefine_classes(count, definitions.data());
    for (jclass type : classes) env->DeleteLocalRef(type);
    return error == JVMTI_ERROR_NONE ? boolean_value(env, true) : jvmti_error(env, error, "RedefineClasses");
}

jobject retransform_class(JNIEnv* env, jobject value) {
    if (value == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "RetransformClass requires Class or Class[]");
    }
    jclass class_array_type = env->FindClass("[Ljava/lang/Class;");
    std::vector<jclass> classes;
    bool array_input = false;
    if (env->IsInstanceOf(value, class_array_type)) {
        array_input = true;
        auto array = static_cast<jobjectArray>(value);
        const jsize count = env->GetArrayLength(array);
        classes.reserve(count);
        for (jsize index = 0; index < count; ++index) {
            classes.push_back(static_cast<jclass>(env->GetObjectArrayElement(array, index)));
        }
    } else {
        classes.push_back(static_cast<jclass>(value));
    }

    jvmtiEnv* jvmti = core::RuntimeState::instance().jvmti();
    std::size_t failed = 0;
    for (jclass type : classes) {
        char* signature = nullptr;
        char* generic = nullptr;
        if (type != nullptr) {
            jvmti->GetClassSignature(type, &signature, &generic);
        }
        const char* display_name = signature == nullptr ? "<invalid>" : signature;
        jboolean modifiable = JNI_FALSE;
        const jvmtiError modifiable_error = type == nullptr
            ? JVMTI_ERROR_INVALID_CLASS
            : jvmti->IsModifiableClass(type, &modifiable);
        if (modifiable_error == JVMTI_ERROR_NONE && modifiable == JNI_TRUE) {
            HIMITSU_LOG_INFO("ClassControl", "开始重转换类 '%s'", display_name);
            const jvmtiError error = trusted_retransform_classes(1, &type);
            HIMITSU_LOG_INFO(
                "ClassControl",
                "类重转换结束：类='%s'，jvmti=%d",
                display_name,
                static_cast<int>(error)
            );
            if (error != JVMTI_ERROR_NONE) {
                failed++;
            }
        } else {
            HIMITSU_LOG_WARNING(
                "ClassControl",
                "跳过类重转换：类='%s'，可修改检查=%d，可修改=%s",
                display_name,
                static_cast<int>(modifiable_error),
                modifiable == JNI_TRUE ? "是" : "否"
            );
        }
        if (signature != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char*>(signature));
        if (generic != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char*>(generic));
        if (array_input && type != nullptr) {
            env->DeleteLocalRef(type);
        }
    }
    return boolean_value(env, failed == 0);
}

jobject retransform_class_observed(JNIEnv* env, jclass type) {
    if (type == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "RetransformClassObserved requires Class");
    }
    jboolean modifiable = JNI_FALSE;
    const jvmtiError modifiable_error = trusted_jvmti()->IsModifiableClass(type, &modifiable);
    if (modifiable_error != JVMTI_ERROR_NONE || modifiable != JNI_TRUE) {
        return boolean_value(env, true);
    }
    const unsigned long long before = class_hook_invocations.load(std::memory_order_acquire);
    const jvmtiError error = trusted_retransform_classes(1, &type);
    const unsigned long long after = class_hook_invocations.load(std::memory_order_acquire);
    if (error != JVMTI_ERROR_NONE) {
        return jvmti_error(env, error, "RetransformClasses observation");
    }
    return boolean_value(env, after != before);
}

jobject dump_class(JNIEnv* env, jclass type) {
    if (type == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "DumpClass requires Class");
    }

    ClassDump request{type, {}, nullptr};
    jvmtiError error;
    {
        const DumpScope capture(request);
        const TransformerBypass bypass;
        error = trusted_retransform_classes(1, &type);
    }
    const auto& bytes = request.bytes;

    if (error != JVMTI_ERROR_NONE) {
        return jvmti_error(env, error, "DumpClass retransformation");
    }
    if (bytes.empty()) {
        return new_exception(env, "java/lang/IllegalStateException", "Class bytes were not observed by ClassFileLoadHook");
    }

    jbyteArray result = env->NewByteArray(static_cast<jsize>(bytes.size()));
    env->SetByteArrayRegion(
        result,
        0,
        static_cast<jsize>(bytes.size()),
        reinterpret_cast<const jbyte*>(bytes.data())
    );
    return env->ExceptionCheck() ? take_exception(env) : result;
}

static jmethodID resolve_reflected_static_method(
    JNIEnv* env,
    jclass callback,
    jobject reflected_method,
    const char* signature
) {
    if (callback == nullptr || reflected_method == nullptr) {
        return nullptr;
    }
    jclass method_type = env->FindClass("java/lang/reflect/Method");
    if (method_type == nullptr || !env->IsInstanceOf(reflected_method, method_type)) {
        if (method_type != nullptr) env->DeleteLocalRef(method_type);
        return nullptr;
    }
    jmethodID get_declaring_class = env->GetMethodID(
        method_type,
        "getDeclaringClass",
        "()Ljava/lang/Class;"
    );
    jmethodID get_name = env->GetMethodID(method_type, "getName", "()Ljava/lang/String;");
    if (get_declaring_class == nullptr || get_name == nullptr) {
        env->DeleteLocalRef(method_type);
        return nullptr;
    }
    jobject declaring_class = env->CallObjectMethod(reflected_method, get_declaring_class);
    if (env->ExceptionCheck() || declaring_class == nullptr) {
        if (declaring_class != nullptr) env->DeleteLocalRef(declaring_class);
        env->DeleteLocalRef(method_type);
        return nullptr;
    }
    if (!env->IsSameObject(callback, declaring_class)) {
        env->DeleteLocalRef(declaring_class);
        env->DeleteLocalRef(method_type);
        return nullptr;
    }
    jstring method_name = static_cast<jstring>(env->CallObjectMethod(reflected_method, get_name));
    if (env->ExceptionCheck() || method_name == nullptr) {
        if (method_name != nullptr) env->DeleteLocalRef(method_name);
        env->DeleteLocalRef(declaring_class);
        env->DeleteLocalRef(method_type);
        return nullptr;
    }
    const char* chars = env->GetStringUTFChars(method_name, nullptr);
    jmethodID method = chars == nullptr ? nullptr : env->GetStaticMethodID(callback, chars, signature);
    if (chars != nullptr) env->ReleaseStringUTFChars(method_name, chars);
    env->DeleteLocalRef(method_name);
    env->DeleteLocalRef(declaring_class);
    env->DeleteLocalRef(method_type);
    return method;
}

jobject configure_class_load_hook(JNIEnv* env, jclass callback, jobject reflected_method) {
    auto& state = core::RuntimeState::instance();
    jclass replacement = nullptr;
    jmethodID method = nullptr;
    if (callback != nullptr) {
        method = resolve_reflected_static_method(env, callback, reflected_method, transformer_signature);
        if (method == nullptr) {
            if (env->ExceptionCheck()) return take_exception(env);
            return new_exception(env, "java/lang/IllegalArgumentException", "ClassLoadHook requires a matching static Method");
        }
        replacement = static_cast<jclass>(env->NewGlobalRef(callback));
    }

    jclass previous_class = nullptr;
    jmethodID previous_method = nullptr;
    {
        himitsu::core::StateLock lock(state.references_lock());
        previous_class = state.transformer_class;
        previous_method = state.transformer_method;
        state.transformer_class = replacement;
        state.transformer_method = method;
    }
    HIMITSU_LOG_INFO(
        "ClassControl",
        "开始设置 ClassFileLoadHook 通知（模式=%s，回调=%p，方法=%p）",
        callback == nullptr ? "禁用" : "启用",
        replacement,
        method
    );
    const jvmtiError error = trusted_set_event_notification_mode(
        callback == nullptr && !source_images_active() ? JVMTI_DISABLE : JVMTI_ENABLE,
        JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
        nullptr
    );
    HIMITSU_LOG_INFO("ClassControl", "ClassFileLoadHook 通知设置结束（jvmti=%d）", error);
    if (error != JVMTI_ERROR_NONE) {
        {
            himitsu::core::StateLock lock(state.references_lock());
            state.transformer_class = previous_class;
            state.transformer_method = previous_method;
        }
        if (replacement != nullptr) env->DeleteGlobalRef(replacement);
        return jvmti_error(env, error, "ClassFileLoadHook notification");
    }
    if (previous_class != nullptr) env->DeleteGlobalRef(previous_class);
    return boolean_value(env, true);
}

jobject define_class(JNIEnv* env, jstring name, jobject loader, jbyteArray bytes) {
    if (name == nullptr || bytes == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "DefineClass requires name, loader, and byte[]");
    }
    const char* class_name = env->GetStringUTFChars(name, nullptr);
    jbyte* data = env->GetByteArrayElements(bytes, nullptr);
    const jsize length = env->GetArrayLength(bytes);
    HIMITSU_LOG_INFO("ClassControl", "请求 DefineClass：名称='%s'，加载器=%p，字节数=%d", class_name == nullptr ? "<invalid>" : class_name, loader, length);
    jclass result = env->DefineClass(class_name, loader, data, length);
    const bool failed = env->ExceptionCheck();
    env->ReleaseByteArrayElements(bytes, data, JNI_ABORT);
    env->ReleaseStringUTFChars(name, class_name);
    HIMITSU_LOG_INFO("ClassControl", "DefineClass 调用结束（类=%p，成功=%s）", result, failed ? "否" : "是");
    return failed ? take_exception(env) : result;
}

jobject lookup_define_class(
    JNIEnv* env,
    jobject lookup,
    jstring,
    jbyteArray bytes,
    jobject
) {
    if (lookup == nullptr || bytes == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "LookupDefineClass requires Lookup and byte[]");
    }
    jclass lookup_type = env->FindClass("java/lang/invoke/MethodHandles$Lookup");
    jmethodID define_class_method = env->GetMethodID(lookup_type, "defineClass", "([B)Ljava/lang/Class;");
    jobject result = env->CallObjectMethod(lookup, define_class_method, bytes);
    const bool failed = env->ExceptionCheck();
    HIMITSU_LOG_INFO("ClassControl", "LookupDefineClass 调用结束（类=%p，字节数=%d，成功=%s）", result, env->GetArrayLength(bytes), failed ? "否" : "是");
    return failed ? take_exception(env) : result;
}

jobject read_zip_entry(JNIEnv* env, jstring zip_path, jstring entry_name) {
    if (zip_path == nullptr || entry_name == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "ReadZipEntry requires zip path and entry name");
    }
    jclass zip_type = env->FindClass("java/util/zip/ZipFile");
    jmethodID constructor = env->GetMethodID(zip_type, "<init>", "(Ljava/lang/String;)V");
    jobject zip = env->NewObject(zip_type, constructor, zip_path);
    if (env->ExceptionCheck()) return take_exception(env);
    jmethodID get_entry = env->GetMethodID(zip_type, "getEntry", "(Ljava/lang/String;)Ljava/util/zip/ZipEntry;");
    jobject entry = env->CallObjectMethod(zip, get_entry, entry_name);
    if (entry == nullptr) {
        jmethodID close = env->GetMethodID(zip_type, "close", "()V");
        env->CallVoidMethod(zip, close);
        return new_exception(env, "java/io/FileNotFoundException", "ZIP entry was not found");
    }
    jmethodID get_stream = env->GetMethodID(zip_type, "getInputStream", "(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;");
    jobject stream = env->CallObjectMethod(zip, get_stream, entry);
    jclass stream_type = env->FindClass("java/io/InputStream");
    jmethodID read_all = env->GetMethodID(stream_type, "readAllBytes", "()[B");
    jobject result = env->CallObjectMethod(stream, read_all);
    const jsize result_length = result == nullptr ? 0 : env->GetArrayLength(static_cast<jbyteArray>(result));
    jmethodID stream_close = env->GetMethodID(stream_type, "close", "()V");
    env->CallVoidMethod(stream, stream_close);
    jmethodID zip_close = env->GetMethodID(zip_type, "close", "()V");
    env->CallVoidMethod(zip, zip_close);
    const bool failed = env->ExceptionCheck();
    HIMITSU_LOG_INFO("ClassControl", "读取 ZIP 条目结束（字节数=%d，成功=%s）", result_length, failed ? "否" : "是");
    return failed ? take_exception(env) : result;
}

jobject get_transformed_class_bytes(JNIEnv* env, jobject loader, jstring class_name) {
    if (loader == nullptr || class_name == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "GetTransformedClassBytes requires loader and class name");
    }
    jclass loader_type = env->GetObjectClass(loader);
    jmethodID method = env->GetMethodID(
        loader_type,
        "getMaybeTransformedClassBytes",
        "(Ljava/lang/String;Ljava/lang/String;)[B"
    );
    if (method == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
    jobject result = env->CallObjectMethod(loader, method, class_name, nullptr);
    const bool failed = env->ExceptionCheck();
    if (failed) {
        return take_exception(env);
    }
    return result;
}

jobject protect_thread(JNIEnv* env, jobject thread) {
    if (thread == nullptr) return new_exception(env, "java/lang/IllegalArgumentException", "ProtectThread requires Thread");
    jclass thread_type = env->FindClass("java/lang/Thread");
    if (!env->IsInstanceOf(thread, thread_type)) return new_exception(env, "java/lang/IllegalArgumentException", "ProtectThread argument is not a Thread");
    auto& state = core::RuntimeState::instance();
    {
        himitsu::core::StateLock lock(state.references_lock());
        const bool exists = std::any_of(state.protected_threads.begin(), state.protected_threads.end(), [&](jobject value) { return env->IsSameObject(value, thread); });
        if (!exists) state.protected_threads.push_back(env->NewGlobalRef(thread));
        HIMITSU_LOG_INFO("ClassControl", "保护线程完成（线程=%p，总数=%zu）", thread, state.protected_threads.size());
    }
    return boolean_value(env, true);
}

jobject unprotect_thread(JNIEnv* env, jobject thread) {
    if (thread == nullptr) return new_exception(env, "java/lang/IllegalArgumentException", "UnprotectThread requires Thread");
    auto& state = core::RuntimeState::instance();
    {
        himitsu::core::StateLock lock(state.references_lock());
        auto iterator = std::find_if(state.protected_threads.begin(), state.protected_threads.end(), [&](jobject value) { return env->IsSameObject(value, thread); });
        if (iterator != state.protected_threads.end()) {
            env->DeleteGlobalRef(*iterator);
            state.protected_threads.erase(iterator);
        }
        HIMITSU_LOG_INFO("ClassControl", "取消线程保护完成（线程=%p，总数=%zu）", thread, state.protected_threads.size());
    }
    return boolean_value(env, true);
}

jobject bind_render(JNIEnv* env, jclass callback, jobject reflected_method) {
    if (callback == nullptr || reflected_method == nullptr) {
        return new_exception(env, "java/lang/IllegalArgumentException", "BindRender requires callback Class and Method");
    }
    jmethodID method = resolve_reflected_static_method(env, callback, reflected_method, render_signature);
    if (method == nullptr) {
        if (env->ExceptionCheck()) return take_exception(env);
        return new_exception(env, "java/lang/IllegalArgumentException", "BindRender requires a matching static Method");
    }

    auto& state = core::RuntimeState::instance();
    jobject replacement = env->NewGlobalRef(callback);
    {
        himitsu::core::StateLock lock(state.references_lock());
        if (state.render_callback_class != nullptr) {
            env->DeleteGlobalRef(state.render_callback_class);
        }
        state.render_callback_class = static_cast<jclass>(replacement);
        state.render_callback_method = method;
    }
    const bool installed = himitsu::platform::windows::install_swap_buffers_hook();
    return boolean_value(env, installed);
}

jobject render_frame(JNIEnv* env, jboolean before, jint stage, jlong context) {
    auto& state = core::RuntimeState::instance();
    jclass callback = nullptr;
    jmethodID method = nullptr;
    {
        himitsu::core::StateLock lock(state.references_lock());
        if (state.render_callback_class != nullptr) {
            callback = static_cast<jclass>(env->NewLocalRef(state.render_callback_class));
            method = state.render_callback_method;
        }
    }
    if (callback == nullptr || method == nullptr) {
        return boolean_value(env, true);
    }
    const jboolean result = env->CallStaticBooleanMethod(callback, method, before, stage, context);
    env->DeleteLocalRef(callback);
    return env->ExceptionCheck() ? take_exception(env) : boolean_value(env, result == JNI_TRUE);
}

bool invoke_render_callback(bool before, jint stage, jlong context) {
    auto& state = core::RuntimeState::instance();
    JavaVM* vm = state.vm();
    if (vm == nullptr) {
        HIMITSU_LOG_WARNING("Render", "JVM 尚未就绪，跳过原生渲染回调");
        return true;
    }

    JNIEnv* env = nullptr;
    bool attached = false;
    const jint status = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
    if (status == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) != JNI_OK) {
            HIMITSU_LOG_WARNING("Render", "原生渲染线程附加到 JVM 失败");
            return true;
        }
        attached = true;
    } else if (status != JNI_OK) {
        HIMITSU_LOG_WARNING("Render", "原生渲染线程 GetEnv 调用失败（jni=%d）", status);
        return true;
    }

    bool result = true;
    jclass callback = nullptr;
    jmethodID method = nullptr;
    {
        himitsu::core::StateLock lock(state.references_lock());
        if (state.render_callback_class != nullptr) {
            callback = static_cast<jclass>(env->NewLocalRef(state.render_callback_class));
            method = state.render_callback_method;
        }
    }
    if (callback != nullptr && method != nullptr) {
        result = env->CallStaticBooleanMethod(
            callback,
            method,
            before ? JNI_TRUE : JNI_FALSE,
            stage,
            context
        ) == JNI_TRUE;
        env->DeleteLocalRef(callback);
    }
    if (env->ExceptionCheck()) {
        HIMITSU_LOG_WARNING("Render", "Java 渲染回调出现异常，本次继续交换缓冲区");
        env->ExceptionClear();
        result = true;
    }
    if (attached) {
        vm->DetachCurrentThread();
    }
    return result;
}
}
