#include "himitsu/core/native_log.hpp"

#include "himitsu/build_info.hpp"

#include <cstdarg>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iterator>

namespace {
SRWLOCK log_lock = SRWLOCK_INIT;
HANDLE log_file = INVALID_HANDLE_VALUE;
std::atomic<unsigned long long> log_sequence{0};
ULONGLONG log_started_at = 0;
ULONGLONG log_last_flush = 0;
HMODULE log_module = nullptr;
wchar_t log_path[MAX_PATH]{};

const char* level_name(himitsu::core::log::Level level) {
    switch (level) {
        case himitsu::core::log::Level::debug: return "调试";
        case himitsu::core::log::Level::info: return "信息";
        case himitsu::core::log::Level::warning: return "警告";
        case himitsu::core::log::Level::error: return "错误";
    }
    return "未知";
}

const char* component_name(const char* component) {
    if (component == nullptr) return "原生模块";
    struct ComponentName {
        const char* source;
        const char* display;
    };
    static constexpr ComponentName names[]{
        {"Log", "日志"},
        {"Exports", "导出入口"},
        {"EarlyGuard", "早期守护"},
        {"Bootstrap", "运行时引导"},
        {"RuntimeState", "运行时状态"},
        {"RPC", "命令调度"},
        {"HookTrace", "钩子跟踪"},
        {"JavaVM", "JavaVM"},
        {"JvmtiGuard", "JVMTI守护"},
        {"LateRecovery", "后置恢复"},
        {"ClassControl", "类控制"},
        {"NativeBridge", "原生桥"},
        {"Render", "渲染"},
        {"Instrumentation", "插桩守护"},
        {"ModuleGuard", "模块守护"},
        {"ThreadGuard", "线程守护"}
    };
    for (const ComponentName& name : names) {
        if (std::strcmp(component, name.source) == 0) return name.display;
    }
    return component;
}

void debug_output(const char* text) {
    if (text == nullptr) return;
    const int length = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
    if (length <= 0) {
        OutputDebugStringA(text);
        return;
    }
    wchar_t wide[2304]{};
    if (length > static_cast<int>(std::size(wide))
        || MultiByteToWideChar(CP_UTF8, 0, text, -1, wide, static_cast<int>(std::size(wide))) <= 0) {
        OutputDebugStringA(text);
        return;
    }
    OutputDebugStringW(wide);
}
}

namespace himitsu::core::log {
void initialize(HMODULE module) {
    if (module == nullptr) {
        debug_output("[Himitsu] 原生日志初始化收到空模块\r\n");
        return;
    }

    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        debug_output("[Himitsu] 获取 DLL 路径失败，原生日志尚未初始化\r\n");
        return;
    }
    wchar_t* separator = wcsrchr(path, L'\\');
    if (separator == nullptr) {
        debug_output("[Himitsu] 获取 DLL 目录失败，原生日志尚未初始化\r\n");
        return;
    }
    wcscpy_s(separator + 1, MAX_PATH - static_cast<size_t>(separator + 1 - path), L"himitsu-native.log");

    AcquireSRWLockExclusive(&log_lock);
    if (log_file != INVALID_HANDLE_VALUE && log_module == module) {
        ReleaseSRWLockExclusive(&log_lock);
        write(Level::debug, "Log", "原生日志已初始化（模块=%p）", module);
        return;
    }
    if (log_file != INVALID_HANDLE_VALUE) CloseHandle(log_file);
    HANDLE opened = CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    const DWORD open_error = opened == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (opened != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER file_size{};
        if (GetFileSizeEx(opened, &file_size) && file_size.QuadPart == 0) {
            constexpr unsigned char utf8_bom[]{0xEF, 0xBB, 0xBF};
            DWORD bom_written = 0;
            WriteFile(opened, utf8_bom, sizeof(utf8_bom), &bom_written, nullptr);
        }
    }
    log_file = opened;
    log_module = module;
    log_started_at = GetTickCount64();
    log_last_flush = log_started_at;
    log_sequence.store(0, std::memory_order_release);
    wcscpy_s(log_path, path);
    ReleaseSRWLockExclusive(&log_lock);

    if (open_error != ERROR_SUCCESS) {
        char failure[256]{};
        std::snprintf(failure, sizeof(failure), "[Himitsu] 创建原生日志文件失败（错误码=%lu）\r\n", open_error);
        debug_output(failure);
    }

    wchar_t process_path[MAX_PATH]{};
    const DWORD process_length = GetModuleFileNameW(nullptr, process_path, MAX_PATH);
    wchar_t module_path[MAX_PATH]{};
    const DWORD module_length = GetModuleFileNameW(module, module_path, MAX_PATH);
    SYSTEM_INFO system_info{};
    GetNativeSystemInfo(&system_info);

    write(Level::info, "Log", "------------------------------------------------------------");
    write(
        Level::info,
        "Log",
        "原生日志初始化完成（进程ID=%lu，模块=%p，日志='%ls'）",
        GetCurrentProcessId(),
        module,
        log_path
    );
    write(
        Level::info,
        "Log",
        "进程信息（映像='%ls'，DLL='%ls'，指针位数=%zu，处理器数=%lu）",
        process_length == 0 ? L"<未知>" : process_path,
        module_length == 0 ? L"<未知>" : module_path,
        sizeof(void*) * 8,
        system_info.dwNumberOfProcessors
    );
#if defined(_DEBUG)
    write(
        Level::info,
        "Log",
        "原生构建信息（配置=Debug，本地构建时间=%s，UTC构建时间=%s）",
        himitsu::build_info::local_timestamp,
        himitsu::build_info::utc_timestamp
    );
#else
    write(
        Level::info,
        "Log",
        "原生构建信息（配置=Release，本地构建时间=%s，UTC构建时间=%s）",
        himitsu::build_info::local_timestamp,
        himitsu::build_info::utc_timestamp
    );
#endif
}

void shutdown() {
    write(Level::info, "Log", "正在关闭原生日志");
    AcquireSRWLockExclusive(&log_lock);
    if (log_file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(log_file);
        CloseHandle(log_file);
        log_file = INVALID_HANDLE_VALUE;
    }
    log_module = nullptr;
    ReleaseSRWLockExclusive(&log_lock);
}

void write(Level level, const char* component, const char* format, ...) {
    char message[2048]{};
    va_list arguments;
    va_start(arguments, format);
    vsnprintf_s(message, sizeof(message), _TRUNCATE, format, arguments);
    va_end(arguments);

    SYSTEMTIME time{};
    GetLocalTime(&time);
    const unsigned long long sequence = log_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
    const ULONGLONG started = log_started_at;
    const unsigned long long elapsed = started == 0
        ? 0
        : static_cast<unsigned long long>(GetTickCount64() - started);
    char line[2304]{};
    std::snprintf(
        line,
        sizeof(line),
        "%04u-%02u-%02u %02u:%02u:%02u.%03u [序号=%06llu] [运行=%llums] [进程=%lu] [线程=%lu] [%-5s] [%-14s] %s\r\n",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds,
        sequence,
        elapsed,
        GetCurrentProcessId(),
        GetCurrentThreadId(),
        level_name(level),
        component_name(component),
        message
    );

    AcquireSRWLockExclusive(&log_lock);
    if (log_file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(log_file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
        const ULONGLONG now = GetTickCount64();
        if (level == Level::warning || level == Level::error || now - log_last_flush >= 1000) {
            FlushFileBuffers(log_file);
            log_last_flush = now;
        }
    }
    debug_output(line);
    ReleaseSRWLockExclusive(&log_lock);
}
}
