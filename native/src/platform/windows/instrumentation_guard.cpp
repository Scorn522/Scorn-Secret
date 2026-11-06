#include "himitsu/platform/windows/instrumentation_guard.hpp"

#include "himitsu/core/native_log.hpp"

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

bool patch_function_return_zero(void* function) {
    constexpr std::array<unsigned char, 3> patch{0x31, 0xC0, 0xC3};
    DWORD old_protection = 0;
    if (!VirtualProtect(function, patch.size(), PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    std::memcpy(function, patch.data(), patch.size());
    bool flushed = FlushInstructionCache(GetCurrentProcess(), function, patch.size()) != FALSE;
    DWORD ignored = 0;
    bool restored = VirtualProtect(function, patch.size(), old_protection, &ignored) != FALSE;
    return flushed && restored;
}
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

    bool success = true;
    for (const char* target : targets) {
        void* function = reinterpret_cast<void*>(GetProcAddress(instrument, target));
        if (function == nullptr) {
            HIMITSU_LOG_ERROR("Instrumentation", "未找到原生入口：%s", target);
            success = false;
            continue;
        }
        if (!patch_function_return_zero(function)) {
            HIMITSU_LOG_ERROR("Instrumentation", "原生入口替换失败：%s（错误码=%lu）", target, GetLastError());
            success = false;
            continue;
        }
        HIMITSU_LOG_INFO("Instrumentation", "原生入口已禁用：%s", target);
    }
    return success;
}
}
