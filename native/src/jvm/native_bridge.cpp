#include "himitsu/jvm/native_bridge.hpp"

#include "himitsu/validation/validation_gate.hpp"

#include "himitsu/core/command_dispatcher.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include "himitsu/embedded/native_bridge_class.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/late_recovery.hpp"
#include "himitsu/jvm/source_images.hpp"

#include <cstring>

namespace {
constexpr const char* bootstrap_signature = "Lcom/himitsu/secret/bridge/SecretNative;";
thread_local bool probe_active=false, ready_seen=false, invoke_seen=false;
struct RuntimeCall {
    bool entered = himitsu::core::RuntimeState::instance().enter_call();
    ~RuntimeCall() { if (entered) himitsu::core::RuntimeState::instance().leave_call(); }
};

jobject JNICALL invoke_native(JNIEnv* env, jclass, jstring command, jobjectArray arguments) {
    RuntimeCall call;
    if (!call.entered) return himitsu::jvm::new_exception(env, "java/lang/IllegalStateException", "Secret native runtime is stopping");
    himitsu::validation::require_approval();
    if (probe_active) {
        invoke_seen=true;
        return arguments!=nullptr && env->GetArrayLength(arguments)==1 ? env->GetObjectArrayElement(arguments,0) : nullptr;
    }
    return himitsu::core::dispatch_command(env, command, arguments);
}

jboolean JNICALL ready_native(JNIEnv*, jclass) {
    RuntimeCall call;
    if (!call.entered) return JNI_FALSE;
    himitsu::validation::require_approval();
    if (probe_active) ready_seen=true;
    return himitsu::core::RuntimeState::instance().initialized() ? JNI_TRUE : JNI_FALSE;
}

jclass find_loaded_class(jvmtiEnv* jvmti, const char* expected_signature) {
    JNIEnv* env = nullptr;
    JavaVM* vm = himitsu::core::RuntimeState::instance().vm();
    if (vm == nullptr
        || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK
        || env->EnsureLocalCapacity(32768) != JNI_OK) {
        HIMITSU_LOG_WARNING("NativeBridge", "按签名 '%s' 枚举已加载类失败", expected_signature);
        return nullptr;
    }

    jint count = 0;
    jclass* classes = nullptr;
    const jvmtiError loaded_error = jvmti->GetLoadedClasses(&count, &classes);
    if (loaded_error != JVMTI_ERROR_NONE) {
        HIMITSU_LOG_WARNING("NativeBridge", "查找 '%s' 时 GetLoadedClasses 调用失败（jvmti=%d）", expected_signature, loaded_error);
        return nullptr;
    }

    jclass bridge = nullptr;
    for (jint index = 0; index < count; ++index) {
        char* signature = nullptr;
        if (jvmti->GetClassSignature(classes[index], &signature, nullptr) == JVMTI_ERROR_NONE) {
            const bool matches = signature != nullptr && std::strcmp(signature, expected_signature) == 0;
            if (signature != nullptr) jvmti->Deallocate(reinterpret_cast<unsigned char*>(signature));
            if (matches) {
                jfieldID requested=env->GetStaticFieldID(classes[index],"bridgeRequested","Z");
                bool owner=requested && env->GetStaticBooleanField(classes[index],requested);
                if(env->ExceptionCheck()){env->ExceptionClear();owner=false;}
                if(owner && bridge==nullptr) bridge=static_cast<jclass>(env->NewLocalRef(classes[index]));
            }
        }
        env->DeleteLocalRef(classes[index]);
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes));
    if (bridge != nullptr) {
        HIMITSU_LOG_DEBUG("NativeBridge", "找到已加载类 '%s'（已扫描类数=%d）", expected_signature, count);
    }
    return bridge;
}

void report_exception(JNIEnv* env, const char* stage) {
    if(env->ExceptionCheck()) {
        HIMITSU_LOG_ERROR("NativeBridge","Bridge failure at %s",stage);
        env->ExceptionDescribe(); env->ExceptionClear();
    }
}

jclass define_bridge_class(JNIEnv* env,jclass bootstrap) {
    jclass type=env->FindClass("java/lang/Class");
    jmethodID get_loader=type?env->GetMethodID(type,"getClassLoader","()Ljava/lang/ClassLoader;"):nullptr;
    jobject loader=get_loader?env->CallObjectMethod(bootstrap,get_loader):nullptr;
    jclass bridge=nullptr;
    if(!env->ExceptionCheck() && get_loader) bridge=env->DefineClass("com/himitsu/secret/bridge/NativeBridge",loader,
        reinterpret_cast<const jbyte*>(himitsu::embedded::native_bridge_class),
        static_cast<jsize>(himitsu::embedded::native_bridge_class_size));
    report_exception(env,"named definition");
    if(loader)env->DeleteLocalRef(loader);if(type)env->DeleteLocalRef(type);
    return bridge;
}

bool verify_bridge(JNIEnv* env,jvmtiEnv* jvmti,jclass bridge) {
    if(bridge==nullptr)return false;
    if(env->PushLocalFrame(24)!=JNI_OK)return false;
    bool success=false;
    do {
        jclass object=env->FindClass("java/lang/Object");
        if(!object||env->IsSameObject(object,bridge))break;
        jmethodID invoke=env->GetStaticMethodID(bridge,"invoke","(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;");
        if(!invoke||env->ExceptionCheck())break;
        jmethodID ready=env->GetStaticMethodID(bridge,"ready","()Z");
        if(!ready||env->ExceptionCheck())break;
        jint invoke_flags=0,ready_flags=0;jclass invoke_owner=nullptr,ready_owner=nullptr;
        if(jvmti->GetMethodModifiers(invoke,&invoke_flags)!=JVMTI_ERROR_NONE
            ||jvmti->GetMethodModifiers(ready,&ready_flags)!=JVMTI_ERROR_NONE
            ||(invoke_flags&0x108)!=0x108||(ready_flags&0x108)!=0x108
            ||jvmti->GetMethodDeclaringClass(invoke,&invoke_owner)!=JVMTI_ERROR_NONE
            ||jvmti->GetMethodDeclaringClass(ready,&ready_owner)!=JVMTI_ERROR_NONE
            ||!env->IsSameObject(invoke_owner,bridge)||!env->IsSameObject(ready_owner,bridge))break;
        JNINativeMethod methods[]={
            {const_cast<char*>("invoke"),const_cast<char*>("(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"),reinterpret_cast<void*>(invoke_native)},
            {const_cast<char*>("ready"),const_cast<char*>("()Z"),reinterpret_cast<void*>(ready_native)}
        };
        if(env->RegisterNatives(bridge,methods,2)!=JNI_OK||env->ExceptionCheck())break;
        jmethodID constructor=env->GetMethodID(object,"<init>","()V");
        jobject token=constructor?env->NewObject(object,constructor):nullptr;
        jobjectArray arguments=token?env->NewObjectArray(1,object,token):nullptr;
        jstring command=env->NewStringUTF("BridgeSelfTest");
        if(!token||!arguments||!command||env->ExceptionCheck())break;
        ready_seen=false;invoke_seen=false;probe_active=true;
        jboolean value=env->CallStaticBooleanMethod(bridge,ready);
        jobject roundtrip=env->ExceptionCheck()?nullptr:env->CallStaticObjectMethod(bridge,invoke,command,arguments);
        probe_active=false;
        success=!env->ExceptionCheck()&&value==JNI_TRUE&&ready_seen&&invoke_seen&&env->IsSameObject(token,roundtrip);
    } while(false);
    probe_active=false;report_exception(env,"registration/end-to-end self-test");
    env->PopLocalFrame(nullptr);return success;
}

jclass hidden_bridge_class(JNIEnv* env, jclass bootstrap) {
    const jmethodID define = env->GetStaticMethodID(
        bootstrap, "defineNativeBridge", "([B)Ljava/lang/Class;"
    );
    if (define == nullptr) return nullptr;
    jbyteArray bytes = env->NewByteArray(static_cast<jsize>(himitsu::embedded::native_bridge_class_size));
    if (bytes == nullptr) return nullptr;
    env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(himitsu::embedded::native_bridge_class_size),
        reinterpret_cast<const jbyte*>(himitsu::embedded::native_bridge_class));
    jclass bridge = env->ExceptionCheck() ? nullptr
        : static_cast<jclass>(env->CallStaticObjectMethod(bootstrap, define, bytes));
    env->DeleteLocalRef(bytes);
    if (bridge != nullptr) {
        HIMITSU_LOG_INFO("NativeBridge", "Hidden NativeBridge defined (%zu bytes, class=%p)",
            himitsu::embedded::native_bridge_class_size, bridge);
    }
    return bridge;
}
}

namespace himitsu::jvm {
int register_native_bridge(JavaVM* vm, jvmtiEnv* jvmti) {
    JNIEnv* env = nullptr;
    bool attached = false;
    const jint status = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
    if (status == JNI_EDETACHED) {
        const jint attach_result = vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
        if (attach_result != JNI_OK) {
            HIMITSU_LOG_ERROR("NativeBridge", "注册原生桥时 AttachCurrentThread 调用失败（jni=%d）", attach_result);
            return 5;
        }
        attached = true;
    } else if (status != JNI_OK) {
        HIMITSU_LOG_ERROR("NativeBridge", "注册原生桥时 GetEnv 调用失败（jni=%d）", status);
        return 5;
    }
    int result=8;
    jclass bootstrap=nullptr,bridge=nullptr;
    // Recovery and isolation happen before any ordinary bridge definition.
    const bool clean_jni=late_recover_jni_dispatch(env);
    const bool isolated=clean_jni&&jvmti_isolation_enabled()&&quarantine_external_jvmti(env);
    if(clean_jni)bootstrap=find_loaded_class(jvmti,bootstrap_signature);
    if(bootstrap==nullptr)result=clean_jni?7:8;
    if(bootstrap!=nullptr && remember_owned_image(himitsu::embedded::native_bridge_class,himitsu::embedded::native_bridge_class_size)) {
        if(isolated)bridge=define_bridge_class(env,bootstrap);
        bool verified=verify_bridge(env,jvmti,bridge);
        if(bridge!=nullptr&&!verified) {
            jvmtiClassDefinition definition{bridge,static_cast<jint>(himitsu::embedded::native_bridge_class_size),himitsu::embedded::native_bridge_class};
            const jvmtiError repair=trusted_redefine_classes(1,&definition);
            HIMITSU_LOG_WARNING("NativeBridge","Bridge repair result=%d",repair);
            report_exception(env,"redefinition");
            verified=repair==JVMTI_ERROR_NONE&&verify_bridge(env,jvmti,bridge);
        }
        if(!verified) {
            if(bridge)env->DeleteLocalRef(bridge);
            bridge=hidden_bridge_class(env,bootstrap);
            report_exception(env,"hidden fallback definition");
            verified=verify_bridge(env,jvmti,bridge);
            HIMITSU_LOG_INFO("NativeBridge","Hidden fallback verified=%s",verified?"true":"false");
        }
        if(verified) {
            bool monitor=start_jvmti_guard_monitor();
            jfieldID publication=monitor?env->GetStaticFieldID(bootstrap,"registeredBridge","Ljava/lang/Class;"):nullptr;
            if(publication)env->SetStaticObjectField(bootstrap,publication,bridge);
            result=monitor&&publication&&!env->ExceptionCheck()?0:9;
        }
    }
    report_exception(env,"bridge publication");
    if(bootstrap!=nullptr&&result!=0&&result!=7) {
        jfieldID failure=env->GetStaticFieldID(bootstrap,"bridgeFailure","I");
        if(failure)env->SetStaticIntField(bootstrap,failure,result);
        report_exception(env,"failure publication");
    }
    HIMITSU_LOG_INFO("NativeBridge","Bridge complete: isolated=%s, result=%d",isolated?"true":"false",result);
    if(bridge)env->DeleteLocalRef(bridge);
    if(bootstrap)env->DeleteLocalRef(bootstrap);
    if (attached) {
        const jint detach_result = vm->DetachCurrentThread();
        HIMITSU_LOG_DEBUG("NativeBridge", "注册线程已分离（jni=%d）", detach_result);
    }
    return result;
}
}
