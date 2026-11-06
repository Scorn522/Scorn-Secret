#include <jni.h>

namespace {
jobject JNICALL echo(JNIEnv*, jclass, jstring command, jobjectArray) { return command; }
jboolean JNICALL ready(JNIEnv*, jclass) { return JNI_TRUE; }
}

extern "C" JNIEXPORT jint JNICALL
Java_com_himitsu_secret_bridge_BridgeBindingCheck_bind(JNIEnv* env, jclass, jclass bridge, jclass owner) {
    JNINativeMethod methods[] = {
        {const_cast<char*>("invoke"), const_cast<char*>("(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"), reinterpret_cast<void*>(echo)},
        {const_cast<char*>("ready"), const_cast<char*>("()Z"), reinterpret_cast<void*>(ready)}
    };
    jint result = env->RegisterNatives(bridge, methods, 2);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (owner == nullptr) return result;
    if (result != JNI_OK) {
        jfieldID failure = env->GetStaticFieldID(owner, "bridgeFailure", "I");
        if (failure != nullptr) env->SetStaticIntField(owner, failure, 8);
        return result;
    }
    jfieldID publication = env->GetStaticFieldID(owner, "registeredBridge", "Ljava/lang/Class;");
    if (publication == nullptr) return JNI_ERR;
    env->SetStaticObjectField(owner, publication, bridge);
    return env->ExceptionCheck() ? JNI_ERR : JNI_OK;
}
