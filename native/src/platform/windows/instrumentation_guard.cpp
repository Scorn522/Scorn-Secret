#include "himitsu/platform/windows/instrumentation_guard.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/platform/windows/module_guard.hpp"
#include "MinHook.h"
#include <jni.h>

#include <windows.h>

#include <array>
#include <cstring>
#include <string>

namespace {
std::wstring module_path(HMODULE module) {
    std::wstring path(512, L'\0');
    for (;;) {
        DWORD length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) return {};
        if (length < path.size() - 1) {
            path.resize(length);
            return path;
        }
        path.resize(path.size() * 2);
    }
}

HMODULE instrument_module() {
    HMODULE instrument = GetModuleHandleW(L"instrument.dll");
    if (instrument != nullptr) return instrument;

    HMODULE jvm = GetModuleHandleW(L"jvm.dll");
    std::wstring path = module_path(jvm);
    if (path.empty()) return nullptr;
    size_t server_separator = path.find_last_of(L"\\/");
    if (server_separator == std::wstring::npos) return nullptr;
    path.resize(server_separator);
    size_t bin_separator = path.find_last_of(L"\\/");
    if (bin_separator == std::wstring::npos) return nullptr;
    path.resize(bin_separator + 1);
    path += L"instrument.dll";
    return LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
}

void JNICALL blocked_load(JNIEnv*,jclass,jstring) {}
void JNICALL blocked_classes(JNIEnv*,jobject,jlong,jobjectArray) {}
void JNICALL blocked_flag(JNIEnv*,jobject,jlong,jboolean) {}
std::array<void*,5> installed_targets{};
std::array<std::uint64_t,5> installed_tokens{};

}

namespace himitsu::platform::windows {
bool disable_instrumentation_entries() {
    constexpr std::array<const char*, 5> targets{
        "Java_sun_instrument_InstrumentationImpl_loadAgent0",
        "Java_sun_instrument_InstrumentationImpl_redefineClasses0",
        "Java_sun_instrument_InstrumentationImpl_retransformClasses0",
        "Java_sun_instrument_InstrumentationImpl_setHasRetransformableTransformers",
        "Java_sun_instrument_InstrumentationImpl_setHasTransformers"
    };

    HMODULE instrument = instrument_module();
    if (instrument == nullptr) {
        HIMITSU_LOG_ERROR("Instrumentation", "加载 instrument.dll 失败（错误码=%lu）", GetLastError());
        return false;
    }

    auto status=MH_Initialize();if(status!=MH_OK && status!=MH_ERROR_ALREADY_INITIALIZED)return false;
    bool success = true;std::size_t index=0;
    for (const char* target : targets) {
        const auto slot=index++;
        void* function = reinterpret_cast<void*>(GetProcAddress(instrument, target));
        if (function == nullptr) {
            HIMITSU_LOG_ERROR("Instrumentation", "未找到原生入口：%s", target);
            success = false;
            continue;
        }
        void* replacement=slot==0?reinterpret_cast<void*>(blocked_load):slot<3?reinterpret_cast<void*>(blocked_classes):reinterpret_cast<void*>(blocked_flag);
        if(!installed_targets[slot]) {
            void* original=nullptr;
            if(MH_CreateHook(function,replacement,&original)!=MH_OK || !original){success=false;continue;}
            installed_targets[slot]=function;
        }
        if(installed_targets[slot]!=function || !guarded_hook_intact(function)){success=false;continue;}
        {ThreadHookMaintenance scope;status=MH_EnableHook(function);}
        if(status!=MH_OK && status!=MH_ERROR_ENABLED){success=false;continue;}
        installed_tokens[slot]=register_guarded_hook(target,function);success=installed_tokens[slot]!=0 && success;
        HIMITSU_LOG_INFO("Instrumentation", "原生入口已禁用：%s", target);
    }
    return success;
}
bool stop_instrumentation_entries(std::uint64_t deadline) {
    bool success=true;
    for(std::size_t i=0;i<installed_targets.size();++i)if(auto target=installed_targets[i]) {
        if(GetTickCount64()>deadline || !guarded_hook_intact(target) || !unregister_guarded_region(installed_tokens[i],deadline)){success=false;continue;}
        ThreadHookMaintenance scope;auto status=MH_DisableHook(target);
        success=(status==MH_OK || status==MH_ERROR_DISABLED) && success;
    }
    return success;
}
}
