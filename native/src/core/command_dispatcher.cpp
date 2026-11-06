#include "himitsu/core/command_dispatcher.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/source_images.hpp"
#include "himitsu/platform/windows/swap_buffers_hook.hpp"
#include "himitsu/validation/capability_registry.hpp"
#include "himitsu/validation/integrity_check.hpp"
#include "himitsu/validation/runtime_lease.hpp"
#include "himitsu/validation/validation_gate.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

namespace {
std::string utf8(JNIEnv* env, jstring value) {
    if (value == nullptr) {
        return {};
    }
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) {
        return {};
    }
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

jobject argument(JNIEnv* env, jobjectArray arguments, jsize index) {
    return arguments != nullptr && index < env->GetArrayLength(arguments)
        ? env->GetObjectArrayElement(arguments, index)
        : nullptr;
}

jobject boolean_value(JNIEnv* env, bool value) {
    jclass type = env->FindClass("java/lang/Boolean");
    jmethodID factory = env->GetStaticMethodID(type, "valueOf", "(Z)Ljava/lang/Boolean;");
    return env->CallStaticObjectMethod(type, factory, value ? JNI_TRUE : JNI_FALSE);
}

jobject decrypt_payload(JNIEnv* env, jbyteArray input, bool class_payload) {
    if (!himitsu::validation::lease::valid()
        || !himitsu::validation::capability::valid()
        || !himitsu::validation::integrity::verify_runtime()) {
        himitsu::validation::abort_with_message(
            L"功能授权已失效\n\nAuthorization lost. Please restart.\n授权过期，请重新登录。",
            0x48560007UL
        );
    }
    constexpr std::size_t magic_size = 4;
    constexpr std::size_t salt_size = 16;
    constexpr std::size_t nonce_size = 12;
    constexpr std::size_t tag_size = 16;
    constexpr std::size_t header_size = magic_size + salt_size + nonce_size;
    if (input == nullptr || env->GetArrayLength(input) < static_cast<jsize>(header_size + tag_size)) {
        return himitsu::jvm::new_exception(env, "java/lang/IllegalArgumentException", "Encrypted payload is invalid");
    }
    const jsize input_length = env->GetArrayLength(input);
    std::vector<unsigned char> encrypted(static_cast<std::size_t>(input_length));
    env->GetByteArrayRegion(input, 0, input_length, reinterpret_cast<jbyte*>(encrypted.data()));
    constexpr unsigned char magic[] = {'H', 'S', 'P', '3'};
    if (!std::equal(std::begin(magic), std::end(magic), encrypted.begin())) {
        return himitsu::jvm::new_exception(env, "java/lang/IllegalArgumentException", "Unsupported encrypted payload format");
    }

    BCRYPT_ALG_HANDLE sha = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    BCRYPT_ALG_HANDLE aes = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    std::vector<unsigned char> key_bytes(32);
    std::array<unsigned char,32> prk{};
    std::vector<unsigned char> hash_object;
    std::vector<unsigned char> key_object;
    std::vector<unsigned char> plaintext(encrypted.size() - header_size - tag_size);
    std::string payload_secret = himitsu::validation::capability::payload_secret(
        class_payload
    );
    if (payload_secret.empty()) {
        return himitsu::jvm::new_exception(
            env,
            "java/lang/SecurityException",
            "Payload capability is unavailable"
        );
    }
    bool ok = false;
    do {
        DWORD object_size = 0;
        DWORD result_size = 0;
        if (BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0
            || BCryptGetProperty(sha, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &result_size, 0) < 0) break;
        hash_object.resize(object_size);
        // HKDF-Extract(salt, IKM), then Expand(PRK, purpose/release || 0x01).
        if (BCryptCreateHash(sha, &hash, hash_object.data(), object_size,
                encrypted.data()+magic_size, static_cast<ULONG>(salt_size), 0) < 0
            || BCryptHashData(hash, reinterpret_cast<PUCHAR>(payload_secret.data()), static_cast<ULONG>(payload_secret.size()), 0) < 0
            || BCryptFinishHash(hash, prk.data(), static_cast<ULONG>(prk.size()), 0) < 0) break;
        BCryptDestroyHash(hash); hash=nullptr;
        const std::string info=std::string("Secret/HSP3/")+(class_payload?"class/":"outer/")+HIMITSU_PACKAGE_VERSION;
        unsigned char block=1;
        if (BCryptCreateHash(sha, &hash, hash_object.data(), object_size, prk.data(), static_cast<ULONG>(prk.size()), 0) < 0
            || BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(info.data())), static_cast<ULONG>(info.size()), 0) < 0
            || BCryptHashData(hash, &block, 1, 0) < 0
            || BCryptFinishHash(hash, key_bytes.data(), static_cast<ULONG>(key_bytes.size()), 0) < 0) break;

        if (BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0
            || BCryptSetProperty(aes, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0
            || BCryptGetProperty(aes, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &result_size, 0) < 0) break;
        key_object.resize(object_size);
        if (BCryptGenerateSymmetricKey(aes, &key, key_object.data(), object_size, key_bytes.data(), static_cast<ULONG>(key_bytes.size()), 0) < 0) break;

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = encrypted.data() + magic_size + salt_size;
        auth.cbNonce = static_cast<ULONG>(nonce_size);
        auth.pbAuthData = encrypted.data();
        auth.cbAuthData = static_cast<ULONG>(header_size);
        auth.pbTag = encrypted.data() + encrypted.size() - tag_size;
        auth.cbTag = static_cast<ULONG>(tag_size);
        ULONG written = 0;
        const ULONG ciphertext_size = static_cast<ULONG>(encrypted.size() - header_size - tag_size);
        if (BCryptDecrypt(key, encrypted.data() + header_size, ciphertext_size, &auth, nullptr, 0,
            plaintext.data(), static_cast<ULONG>(plaintext.size()), &written, 0) < 0) break;
        plaintext.resize(written);
        ok = true;
    } while (false);
    if (key != nullptr) BCryptDestroyKey(key);
    if (aes != nullptr) BCryptCloseAlgorithmProvider(aes, 0);
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (sha != nullptr) BCryptCloseAlgorithmProvider(sha, 0);
    SecureZeroMemory(payload_secret.data(), payload_secret.size());
    SecureZeroMemory(prk.data(),prk.size());
    SecureZeroMemory(key_bytes.data(),key_bytes.size());
    if(!hash_object.empty()) SecureZeroMemory(hash_object.data(),hash_object.size());
    if(!key_object.empty()) SecureZeroMemory(key_object.data(),key_object.size());
    if (!ok) return himitsu::jvm::new_exception(env, "java/lang/SecurityException", "Payload authentication or package version mismatch");
    if (class_payload && !himitsu::jvm::remember_owned_image(plaintext.data(),plaintext.size()))
        return himitsu::jvm::new_exception(env,"java/lang/SecurityException","Authenticated class conflicts with its source image");
    jbyteArray output = env->NewByteArray(static_cast<jsize>(plaintext.size()));
    env->SetByteArrayRegion(output, 0, static_cast<jsize>(plaintext.size()), reinterpret_cast<const jbyte*>(plaintext.data()));
    return output;
}
}

namespace himitsu::core {
jobject dispatch_command(JNIEnv* env, jstring command_value, jobjectArray arguments) {
    if (!himitsu::validation::lease::valid()
        || !himitsu::validation::capability::valid()
        || !himitsu::validation::integrity::verify_runtime()) {
        himitsu::validation::abort_with_message(
            L"功能授权已失效\n\nAuthorization lost. Please restart.\n授权过期，请重新登录。",
            0x48560008UL
        );
    }
    const std::string command = utf8(env, command_value);
    if (env->ExceptionCheck()) {
        HIMITSU_LOG_ERROR("RPC", "命令字符串解码失败");
        return himitsu::jvm::take_exception(env);
    }

    if (command == "Configure") {
        auto game_dir = static_cast<jstring>(argument(env, arguments, 0));
        auto mod_path = static_cast<jstring>(argument(env, arguments, 1));
        const std::string game = utf8(env, game_dir);
        const std::string mod = utf8(env, mod_path);
        if (game.empty() || mod.empty()) {
            HIMITSU_LOG_WARNING("RPC", "配置请求被拒绝：路径为空");
            return himitsu::jvm::new_exception(env, "java/lang/IllegalArgumentException", "Configure requires gameDir and modPath");
        }
        RuntimeState::instance().configure(game, mod);
        return boolean_value(env, true);
    }
    if (command == "GetLoadedClasses") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::class_control)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::get_loaded_classes(env);
    }
    if (command == "GetClassInstances") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::class_control)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::get_class_instances(
            env, static_cast<jclass>(argument(env, arguments, 0)));
    }
    if (command == "RedefineClass") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::redefine)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::redefine_class(
            env, static_cast<jclass>(argument(env, arguments, 0)),
            static_cast<jbyteArray>(argument(env, arguments, 1)));
    }
    if (command == "RedefineClasses") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::redefine)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::redefine_classes(
            env,
            static_cast<jobjectArray>(argument(env, arguments, 0)),
            static_cast<jobjectArray>(argument(env, arguments, 1))
        );
    }
    if (command == "RetransformClass") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::retransform)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::retransform_class(env, argument(env, arguments, 0));
    }
    if (command == "RetransformClassObserved") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::retransform)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::retransform_class_observed(
            env,
            static_cast<jclass>(argument(env, arguments, 0))
        );
    }
    if (command == "DumpClass") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::dump_class)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::dump_class(
            env, static_cast<jclass>(argument(env, arguments, 0)));
    }
    if (command == "ClassLoadHook") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::class_load)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::configure_class_load_hook(
            env,
            static_cast<jclass>(argument(env, arguments, 0)),
            argument(env, arguments, 1)
        );
    }
    if (command == "DefineClass") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::def_class)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::define_class(
            env, static_cast<jstring>(argument(env, arguments, 0)),
            argument(env, arguments, 1),
            static_cast<jbyteArray>(argument(env, arguments, 2)));
    }
    if (command == "LookupDefineClass") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::def_class)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::lookup_define_class(
            env,
            argument(env, arguments, 0),
            static_cast<jstring>(argument(env, arguments, 1)),
            static_cast<jbyteArray>(argument(env, arguments, 2)),
            argument(env, arguments, 3)
        );
    }
    if (command == "ReadZipEntry") {
        return himitsu::jvm::read_zip_entry(env, static_cast<jstring>(argument(env, arguments, 0)), static_cast<jstring>(argument(env, arguments, 1)));
    }
    if (command == "DecryptPayloadJar") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::decrypt_jar)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return decrypt_payload(
            env, static_cast<jbyteArray>(argument(env, arguments, 0)), false);
    }
    if (command == "DecryptPayloadClass") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::decrypt_class)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return decrypt_payload(
            env, static_cast<jbyteArray>(argument(env, arguments, 0)), true);
    }
    if (command == "GetTransformedClassBytes") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::class_control)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::get_transformed_class_bytes(
            env,
            argument(env, arguments, 0),
            static_cast<jstring>(argument(env, arguments, 1))
        );
    }
    if (command == "ProtectThread") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::thread_prot)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::protect_thread(env, argument(env, arguments, 0));
    }
    if (command == "UnprotectThread") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::thread_prot)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::unprotect_thread(env, argument(env, arguments, 0));
    }
    if (command == "BindRender") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::render_frame)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        return himitsu::jvm::bind_render(
            env,
            static_cast<jclass>(argument(env, arguments, 0)),
            argument(env, arguments, 1)
        );
    }
    if (command == "HookTrace") {
        const std::string message = utf8(env, static_cast<jstring>(argument(env, arguments, 0)));
        HIMITSU_LOG_INFO("HookTrace", "Java侧钩子跟踪：%s", message.c_str());
        return boolean_value(env, true);
    }
    if (command == "RenderFrame") {
        if (!himitsu::validation::capability::is_enabled(
                himitsu::validation::capability::Feature::render_frame)) {
            return himitsu::jvm::new_exception(env,
                "java/lang/SecurityException", "Feature not enabled");
        }
        jobject before_value = argument(env, arguments, 0);
        jobject stage_value = argument(env, arguments, 1);
        jobject context_value = argument(env, arguments, 2);
        jclass boolean_type = env->FindClass("java/lang/Boolean");
        jclass integer_type = env->FindClass("java/lang/Integer");
        jclass long_type = env->FindClass("java/lang/Long");
        jmethodID boolean_value_method = env->GetMethodID(boolean_type, "booleanValue", "()Z");
        jmethodID integer_value_method = env->GetMethodID(integer_type, "intValue", "()I");
        jmethodID long_value_method = env->GetMethodID(long_type, "longValue", "()J");
        const jboolean before = before_value == nullptr
            ? JNI_FALSE
            : env->CallBooleanMethod(before_value, boolean_value_method);
        const jint stage = stage_value == nullptr
            ? 0
            : env->CallIntMethod(stage_value, integer_value_method);
        const jlong context = context_value == nullptr
            ? 0
            : env->CallLongMethod(context_value, long_value_method);
        return himitsu::jvm::render_frame(env, before, stage, context);
    }
    if (command == "Shutdown") {
        if (!RuntimeState::instance().shutdown(env)) {
            return himitsu::jvm::new_exception(env, "java/lang/IllegalStateException", "Native shutdown incomplete; resources retained; see native log for callback, worker, hook or deadline failure");
        }
        return boolean_value(env, true);
    }
    if (command == "version") {
        return env->NewStringUTF("2");
    }
    if (command == "status") {
        return env->NewStringUTF(RuntimeState::instance().initialized() ? "ready" : "stopped");
    }
    HIMITSU_LOG_WARNING("RPC", "未知命令 '%s'", command.c_str());
    return himitsu::jvm::new_exception(env, "java/lang/IllegalArgumentException", "Unknown native command");
}
}
