#include "himitsu/bootstrap/exports.hpp"
#include "himitsu/bootstrap/early_guard.hpp"
#include "himitsu/bootstrap/runtime_bootstrap.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/jvm/source_images.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/jvm/late_recovery.hpp"
#include "himitsu/validation/validation_gate.hpp"

extern "C" int __cdecl HimitsuEarlyGuard(int disable_jvmti) {
    himitsu::validation::require_approval();
    himitsu::core::log::initialize(himitsu::bootstrap::module());
    HIMITSU_LOG_INFO("Exports", "进入 HimitsuEarlyGuard（禁用外部JVMTI=%d）", disable_jvmti);
    const int result = himitsu::bootstrap::install_early_guards(disable_jvmti != 0) ? 0 : 1;
    HIMITSU_LOG_INFO("Exports", "离开 HimitsuEarlyGuard（结果=%d）", result);
    return result;
}

extern "C" int __cdecl HimitsuBootstrap(const wchar_t* game_directory, const wchar_t* mod_path) {
    himitsu::validation::require_approval();
    himitsu::core::log::initialize(himitsu::bootstrap::module());
    HIMITSU_LOG_INFO(
        "Exports",
        "进入 HimitsuBootstrap（游戏目录='%ls'，模组路径='%ls'）",
        game_directory == nullptr ? L"<null>" : game_directory,
        mod_path == nullptr ? L"<null>" : mod_path
    );
    const int result = himitsu::bootstrap::start_runtime() ? 0 : 1;
    HIMITSU_LOG_INFO("Exports", "离开 HimitsuBootstrap（结果=%d）", result);
    return result;
}

extern "C" int __cdecl HimitsuLoadSources(const wchar_t* archive, void*) {
    himitsu::validation::require_approval();
    jvmtiEnv* jvmti=himitsu::jvm::trusted_jvmti();JavaVM* vm=himitsu::jvm::trusted_vm();JNIEnv* env=nullptr;
    if(!jvmti||!vm
        ||vm->GetEnv(reinterpret_cast<void**>(&env),JNI_VERSION_1_8)!=JNI_OK)return 1;
    if(!himitsu::jvm::late_recover_jni_dispatch(env))return 2;
    if(himitsu::jvm::jvmti_isolation_enabled()&&!himitsu::jvm::quarantine_external_jvmti(env))return 3;
    return himitsu::jvm::load_source_images(env,jvmti,archive)?0:4;
}
