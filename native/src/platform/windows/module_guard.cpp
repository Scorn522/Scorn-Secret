#include "himitsu/platform/windows/module_guard.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/platform/windows/swap_buffers_hook.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"

#include <windows.h>
#include <psapi.h>

#include <array>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace {
struct TableSnapshot {
    const char* name;
    unsigned char* base = nullptr;
    DWORD size = 0;
    unsigned char* original = nullptr;
    bool restore_suspended = false;
    ULONGLONG next_report = 0;
    unsigned long long restore_count = 0;
};

struct ExportSnapshot {
    const char* module_name;
    const char* export_name;
    HMODULE module = nullptr;
    unsigned char* address = nullptr;
    std::array<unsigned char, 16> original{};
    bool missing_reported = false;
    bool restore_suspended = false;
    unsigned long long restore_count = 0;
};

struct GuardedRegion {
    std::uint64_t token = 0;
    std::string name;
    unsigned char* address = nullptr;
    std::vector<unsigned char> expected;
    void* allocation_base = nullptr;
    bool invalid_reported = false;
    unsigned long long restore_count = 0;
};

TableSnapshot java_vm_table{"JavaVM_vtable"};
TableSnapshot jvmti_table{"JVMTI_vtable"};

std::array<ExportSnapshot, 16> exports{{
    {"gdi32.dll", "StretchBlt"},
    {"gdi32.dll", "BitBlt"},
    {"gdi32.dll", "SetPixel"},
    {"gdi32.dll", "SwapBuffers"},
    {"user32.dll", "EnableWindow"},
    {"user32.dll", "FillRect"},
    {"user32.dll", "SetWindowLongPtrA"},
    {"user32.dll", "SetWindowLongPtrW"},
    {"user32.dll", "CreateWindowExA"},
    {"user32.dll", "CreateWindowExW"},
    {"msimg32.dll", "AlphaBlend"},
    {"opengl32.dll", "wglGetCurrentContext"},
    {"opengl32.dll", "glGetIntegerv"},
    {"opengl32.dll", "glDrawBuffer"},
    {"opengl32.dll", "glFlush"},
    {"jvm.dll", "JNI_GetCreatedJavaVMs"}
}};
ExportSnapshot glfw_export{"", "glfwCreateWindow"};
std::array<char, MAX_PATH> glfw_module_name{};
bool glfw_wait_reported = false;
std::vector<GuardedRegion> guarded_regions;
std::atomic<std::uint64_t> next_region_token{1};

std::atomic<bool> stop_requested{false};
std::atomic<bool> running{false};
HANDLE guard_thread = nullptr;
SRWLOCK guard_lock = SRWLOCK_INIT;

bool protected_write(void* address, const void* data, SIZE_T size) {
    DWORD old_protection = 0;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old_protection)) {
        HIMITSU_LOG_ERROR("ModuleGuard", "写入前修改内存保护失败（地址=%p，大小=%zu，错误码=%lu）",
            address, static_cast<std::size_t>(size), GetLastError());
        return false;
    }
    std::memcpy(address, data, size);
    const bool flushed = FlushInstructionCache(GetCurrentProcess(), address, size) != FALSE;
    DWORD ignored = 0;
    const bool restored = VirtualProtect(address, size, old_protection, &ignored) != FALSE;
    if (!flushed || !restored) {
        HIMITSU_LOG_ERROR(
            "ModuleGuard",
            "受保护写入收尾失败（地址=%p，大小=%zu，刷新指令缓存=%s，恢复内存保护=%s，错误码=%lu）",
            address,
            static_cast<std::size_t>(size),
            flushed ? "成功" : "失败",
            restored ? "成功" : "失败",
            GetLastError()
        );
    }
    return flushed && restored;
}

bool initialize_table(TableSnapshot& snapshot, void* table, DWORD size) {
    if (table == nullptr || size == 0) {
        HIMITSU_LOG_ERROR("ModuleGuard", "表基线参数无效：%s（表=%p，大小=0x%lX）",
            snapshot.name, table, size);
        return false;
    }
    snapshot.original = static_cast<unsigned char*>(HeapAlloc(GetProcessHeap(), 0, size));
    if (snapshot.original == nullptr) {
        HIMITSU_LOG_ERROR("ModuleGuard", "表基线内存分配失败：%s（大小=0x%lX，错误码=%lu）",
            snapshot.name, size, GetLastError());
        return false;
    }
    snapshot.base = static_cast<unsigned char*>(table);
    snapshot.size = size;
    std::memcpy(snapshot.original, snapshot.base, snapshot.size);
    HIMITSU_LOG_INFO(
        "ModuleGuard",
        "表基线已捕获：%s（基址=%p，大小=0x%lX）",
        snapshot.name,
        snapshot.base,
        snapshot.size
    );
    return true;
}

bool initialize_export(ExportSnapshot& snapshot) {
    if (snapshot.address != nullptr) return true;
    HMODULE module = GetModuleHandleA(snapshot.module_name);
    if (module == nullptr) {
        if (!snapshot.missing_reported) {
            HIMITSU_LOG_DEBUG("ModuleGuard", "等待监控模块加载：%s（导出函数=%s）",
                snapshot.module_name, snapshot.export_name);
            snapshot.missing_reported = true;
        }
        return false;
    }
    FARPROC address = GetProcAddress(module, snapshot.export_name);
    if (address == nullptr) {
        if (!snapshot.missing_reported) {
            HIMITSU_LOG_WARNING("ModuleGuard", "监控导出函数缺失：%s!%s（模块=%p，错误码=%lu）",
                snapshot.module_name, snapshot.export_name, module, GetLastError());
            snapshot.missing_reported = true;
        }
        return false;
    }
    snapshot.module = module;
    snapshot.address = reinterpret_cast<unsigned char*>(address);
    snapshot.missing_reported = false;
    std::memcpy(snapshot.original.data(), snapshot.address, snapshot.original.size());
    HIMITSU_LOG_INFO(
        "ModuleGuard",
        "导出函数基线已捕获：%s!%s（地址=%p）",
        snapshot.module_name,
        snapshot.export_name,
        snapshot.address
    );
    return true;
}

void initialize_glfw_export() {
    if (glfw_export.address != nullptr) return;
    HMODULE modules[512]{};
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        if (!glfw_wait_reported) {
            HIMITSU_LOG_WARNING("ModuleGuard", "枚举模块以查找 GLFW 失败（错误码=%lu）", GetLastError());
            glfw_wait_reported = true;
        }
        return;
    }
    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD index = 0; index < count; ++index) {
        char path[MAX_PATH]{};
        if (GetModuleFileNameA(modules[index], path, sizeof(path)) == 0) continue;
        const char* name = path;
        for (const char* cursor = path; *cursor != '\0'; ++cursor) {
            if (*cursor == '\\' || *cursor == '/') name = cursor + 1;
        }
        if (_strnicmp(name, "glfw", 4) != 0) continue;
        FARPROC address = GetProcAddress(modules[index], glfw_export.export_name);
        if (address == nullptr) return;
        glfw_export.module = modules[index];
        glfw_export.address = reinterpret_cast<unsigned char*>(address);
        strncpy_s(glfw_module_name.data(), glfw_module_name.size(), name, _TRUNCATE);
        glfw_export.module_name = glfw_module_name.data();
        glfw_wait_reported = false;
        std::memcpy(glfw_export.original.data(), glfw_export.address, glfw_export.original.size());
        HIMITSU_LOG_INFO(
            "ModuleGuard",
            "导出函数基线已捕获：%s!%s（地址=%p）",
            name,
            glfw_export.export_name,
            glfw_export.address
        );
        return;
    }
    if (!glfw_wait_reported) {
        HIMITSU_LOG_DEBUG("ModuleGuard", "GLFW 模块或 glfwCreateWindow 导出函数尚未出现（已扫描模块=%lu）", count);
        glfw_wait_reported = true;
    }
}

void restore_table(TableSnapshot& snapshot) {
    if (snapshot.restore_suspended || !snapshot.base || !snapshot.original || !snapshot.size) return;
    if (std::memcmp(snapshot.base, snapshot.original, snapshot.size) == 0) return;
    const auto now = GetTickCount64();
    const bool report = now >= snapshot.next_report;
    if (report) {
        DWORD offset = 0;
        while (offset < snapshot.size && snapshot.base[offset] == snapshot.original[offset]) ++offset;
        HIMITSU_LOG_WARNING("ModuleGuard", "检测到表内容变化：%s（基址=%p，首个差异偏移=0x%lX）",
            snapshot.name, snapshot.base, offset);
        snapshot.next_report = now + 10000;
    }
    const bool restored = protected_write(snapshot.base, snapshot.original, snapshot.size);
    if (restored) ++snapshot.restore_count;
    if (report) HIMITSU_LOG_INFO("ModuleGuard", "表恢复结束：%s（成功=%s，累计恢复=%llu）",
        snapshot.name, restored ? "是" : "失败", snapshot.restore_count);
}

void restore_export(ExportSnapshot& snapshot) {
    if (snapshot.address == nullptr || snapshot.restore_suspended) return;
    if (std::memcmp(snapshot.address, snapshot.original.data(), snapshot.original.size()) == 0) return;
    std::size_t first_difference = 0;
    while (first_difference < snapshot.original.size()
        && snapshot.address[first_difference] == snapshot.original[first_difference]) {
        ++first_difference;
    }
    HIMITSU_LOG_WARNING(
        "ModuleGuard",
        "检测到导出函数变化：%s!%s（地址=%p，首个差异偏移=0x%zX，当前=0x%02X，基线=0x%02X）",
        snapshot.module_name,
        snapshot.export_name,
        snapshot.address,
        first_difference,
        snapshot.address[first_difference],
        snapshot.original[first_difference]
    );
    const bool restored = protected_write(snapshot.address, snapshot.original.data(), snapshot.original.size());
    if (restored) ++snapshot.restore_count;
    HIMITSU_LOG_INFO("ModuleGuard", "导出函数恢复结束：%s!%s（成功=%s，累计恢复=%llu）",
        snapshot.module_name, snapshot.export_name, restored ? "是" : "否", snapshot.restore_count);
}

bool query_guarded_region(void* address, std::size_t size, void** allocation_base = nullptr) {
    if (address == nullptr || size == 0) return false;
    MEMORY_BASIC_INFORMATION information{};
    if (VirtualQuery(address, &information, sizeof(information)) != sizeof(information)
        || information.State != MEM_COMMIT
        || (information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }
    const auto start = reinterpret_cast<std::uintptr_t>(address);
    const auto region_end = reinterpret_cast<std::uintptr_t>(information.BaseAddress)
        + information.RegionSize;
    if (start > region_end || size > region_end - start) return false;
    if (allocation_base != nullptr) *allocation_base = information.AllocationBase;
    return true;
}

void restore_guarded_region(GuardedRegion& region) {
    void* allocation_base = nullptr;
    if (!query_guarded_region(region.address, region.expected.size(), &allocation_base)
        || allocation_base != region.allocation_base) {
        if (!region.invalid_reported) {
            HIMITSU_LOG_WARNING(
                "ModuleGuard",
                "渲染守护区域暂时失效：%s（地址=%p，大小=%zu）",
                region.name.c_str(),
                region.address,
                region.expected.size()
            );
            region.invalid_reported = true;
        }
        return;
    }
    region.invalid_reported = false;
    if (std::memcmp(region.address, region.expected.data(), region.expected.size()) == 0) return;
    std::size_t difference = 0;
    while (difference < region.expected.size()
        && region.address[difference] == region.expected[difference]) {
        ++difference;
    }
    HIMITSU_LOG_WARNING(
        "ModuleGuard",
        "检测到渲染守护区域变化：%s（地址=%p，差异偏移=0x%zX，当前=0x%02X，基线=0x%02X）",
        region.name.c_str(),
        region.address,
        difference,
        region.address[difference],
        region.expected[difference]
    );
    if (protected_write(region.address, region.expected.data(), region.expected.size())) {
        ++region.restore_count;
        HIMITSU_LOG_INFO(
            "ModuleGuard",
            "渲染守护区域恢复完成：%s（累计恢复=%llu）",
            region.name.c_str(),
            region.restore_count
        );
    }
}

DWORD WINAPI guard_worker(void*) {
    HIMITSU_LOG_INFO("ModuleGuard", "持续模块恢复线程已启动（线程ID=%lu，轮询方式=持续检查）", GetCurrentThreadId());
    ULONGLONG next_summary = GetTickCount64() + 10000;
    while (!stop_requested.load(std::memory_order_acquire)) {
        unsigned long long render_restores = 0;
        AcquireSRWLockExclusive(&guard_lock);
        restore_table(java_vm_table);
        restore_table(jvmti_table);
        for (ExportSnapshot& snapshot : exports) {
            if (snapshot.address == nullptr) initialize_export(snapshot);
            restore_export(snapshot);
        }
        initialize_glfw_export();
        restore_export(glfw_export);
        for (GuardedRegion& region : guarded_regions) {
            restore_guarded_region(region);
            render_restores += region.restore_count;
        }
        ReleaseSRWLockExclusive(&guard_lock);

        himitsu::platform::windows::maintain_swap_buffers_hook();
        const ULONGLONG now = GetTickCount64();
        if (now >= next_summary) {
            unsigned long long export_restores = glfw_export.restore_count;
            for (const ExportSnapshot& snapshot : exports) export_restores += snapshot.restore_count;
            HIMITSU_LOG_DEBUG(
                "ModuleGuard",
                "模块守护运行摘要（JavaVM表恢复=%llu，JVMTI表恢复=%llu，导出函数恢复=%llu，渲染区域恢复=%llu）",
                java_vm_table.restore_count,
                jvmti_table.restore_count,
                export_restores,
                render_restores
            );
            next_summary = now + 10000;
        }
        Sleep(1);
    }
    running.store(false, std::memory_order_release);
    HIMITSU_LOG_INFO("ModuleGuard", "持续模块恢复线程已停止");
    return 0;
}

void release_snapshot(void*& memory) {
    if (memory != nullptr) {
        HeapFree(GetProcessHeap(), 0, memory);
        memory = nullptr;
    }
}
}

namespace himitsu::platform::windows {
std::uint64_t register_guarded_region(const char* name, void* address, std::size_t size) {
    if (name == nullptr || address == nullptr || size == 0 || size > 4096) return 0;
    void* allocation_base = nullptr;
    if (!query_guarded_region(address, size, &allocation_base)) return 0;

    GuardedRegion region;
    region.token = next_region_token.fetch_add(1, std::memory_order_relaxed);
    if (region.token == 0) region.token = next_region_token.fetch_add(1, std::memory_order_relaxed);
    region.name = name;
    region.address = static_cast<unsigned char*>(address);
    region.expected.assign(region.address, region.address + size);
    region.allocation_base = allocation_base;
    const std::uint64_t token = region.token;
    AcquireSRWLockExclusive(&guard_lock);
    guarded_regions.push_back(std::move(region));
    ReleaseSRWLockExclusive(&guard_lock);
    HIMITSU_LOG_INFO(
        "ModuleGuard",
        "渲染守护区域已登记：%s（令牌=%llu，地址=%p，大小=%zu）",
        name,
        static_cast<unsigned long long>(token),
        address,
        size
    );
    return token;
}

void unregister_guarded_region(std::uint64_t token) {
    if (token == 0) return;
    std::string name;
    AcquireSRWLockExclusive(&guard_lock);
    const auto iterator = std::find_if(
        guarded_regions.begin(),
        guarded_regions.end(),
        [&](const GuardedRegion& region) { return region.token == token; }
    );
    if (iterator != guarded_regions.end()) {
        name = iterator->name;
        guarded_regions.erase(iterator);
    }
    ReleaseSRWLockExclusive(&guard_lock);
    if (!name.empty()) {
        HIMITSU_LOG_INFO(
            "ModuleGuard",
            "渲染守护区域已注销：%s（令牌=%llu）",
            name.c_str(),
            static_cast<unsigned long long>(token)
        );
    }
}

bool suspend_export_restore(const char* module_name, const char* export_name, bool suspended) {
    if (module_name == nullptr || export_name == nullptr) return false;
    AcquireSRWLockExclusive(&guard_lock);
    ExportSnapshot* matched = nullptr;
    for (ExportSnapshot& snapshot : exports) {
        if (_stricmp(snapshot.module_name, module_name) == 0
            && std::strcmp(snapshot.export_name, export_name) == 0) {
            matched = &snapshot;
            break;
        }
    }
    if (matched == nullptr && glfw_export.module_name != nullptr
        && glfw_export.module_name[0] != '\0'
        && _stricmp(glfw_export.module_name, module_name) == 0
        && std::strcmp(glfw_export.export_name, export_name) == 0) {
        matched = &glfw_export;
    }
    bool success = matched != nullptr;
    if (matched != nullptr) {
        if (matched->address == nullptr) success = initialize_export(*matched);
        if (success) matched->restore_suspended = suspended;
    }
    ReleaseSRWLockExclusive(&guard_lock);
    if (success) {
        HIMITSU_LOG_INFO(
            "ModuleGuard",
            "导出函数恢复协调完成：%s!%s（状态=%s）",
            module_name,
            export_name,
            suspended ? "由本地组件接管" : "恢复守护"
        );
    }
    return success;
}

void suspend_jvmti_table_restore(bool suspended) {
    // The lock only changes native state; callers release it before any JVMTI call.
    AcquireSRWLockExclusive(&guard_lock);
    jvmti_table.restore_suspended = suspended;
    ReleaseSRWLockExclusive(&guard_lock);
}

bool start_module_guard(JavaVM* vm, jvmtiEnv* jvmti) {
    HIMITSU_LOG_INFO("ModuleGuard", "正在启动表与导出函数守护（vm=%p，jvmti=%p）", vm, jvmti);
    bool expected = false;
    if (!running.compare_exchange_strong(expected, true)) {
        HIMITSU_LOG_INFO("ModuleGuard", "表与导出函数守护已经在运行（线程=%p）", guard_thread);
        return true;
    }
    if (vm == nullptr || jvmti == nullptr || vm->functions == nullptr || jvmti->functions == nullptr) {
        HIMITSU_LOG_ERROR(
            "ModuleGuard",
            "启动参数无效（vm=%p，vm表=%p，jvmti=%p，jvmti表=%p）",
            vm,
            vm == nullptr ? nullptr : vm->functions,
            jvmti,
            jvmti == nullptr ? nullptr : jvmti->functions
        );
        running.store(false, std::memory_order_release);
        return false;
    }

    AcquireSRWLockExclusive(&guard_lock);
    const bool initialized = initialize_table(java_vm_table, const_cast<JNIInvokeInterface_*>(vm->functions), 8 * sizeof(void*))
        && initialize_table(jvmti_table, const_cast<jvmtiInterface_1_*>(jvmti->functions), sizeof(jvmtiInterface_1_));
    unsigned int export_baselines = 0;
    for (ExportSnapshot& snapshot : exports) {
        if (initialize_export(snapshot)) ++export_baselines;
    }
    initialize_glfw_export();
    const std::size_t guarded_region_count = guarded_regions.size();
    ReleaseSRWLockExclusive(&guard_lock);
    HIMITSU_LOG_INFO("ModuleGuard", "守护基线汇总（表=%s，导出函数=%u/%zu，GLFW=%s，渲染区域=%zu）",
        initialized ? "正常" : "失败",
        export_baselines,
        exports.size(),
        glfw_export.address == nullptr ? "等待加载" : "已捕获",
        guarded_region_count);
    if (!initialized) {
        HIMITSU_LOG_ERROR("ModuleGuard", "表或导出函数基线初始化失败");
        running.store(false, std::memory_order_release);
        return false;
    }

    stop_requested.store(false, std::memory_order_release);
    guard_thread = CreateThread(nullptr, 0, guard_worker, nullptr, CREATE_SUSPENDED, nullptr);
    if (guard_thread == nullptr) {
        HIMITSU_LOG_ERROR("ModuleGuard", "模块守护 CreateThread 调用失败（错误码=%lu）", GetLastError());
        running.store(false, std::memory_order_release);
        return false;
    }
    if(!register_native_thread(guard_thread) || ResumeThread(guard_thread)==static_cast<DWORD>(-1)) {
        stop_requested.store(true,std::memory_order_release);ResumeThread(guard_thread);
        if(WaitForSingleObject(guard_thread,5000)==WAIT_OBJECT_0) {
            unregister_native_thread(guard_thread);CloseHandle(guard_thread);guard_thread=nullptr;
        }
        HIMITSU_LOG_ERROR("ModuleGuard","Guard OS protection/launch failed");return false;
    }
    HIMITSU_LOG_INFO("ModuleGuard", "表与导出函数守护已启动（线程=%p）", guard_thread);
    return true;
}

void request_module_guard_stop() {stop_requested.store(true,std::memory_order_release);}
bool stop_module_guard(std::uint64_t deadline) {
    request_module_guard_stop();
    HANDLE thread=guard_thread;
    if(thread) {
        auto now=GetTickCount64();
        DWORD result=WaitForSingleObject(thread,static_cast<DWORD>(now<deadline?deadline-now:0));
        if(result!=WAIT_OBJECT_0) {HIMITSU_LOG_ERROR("ModuleGuard","Guard did not exit; state retained: %lu",result);return false;}
        unregister_native_thread(thread);CloseHandle(thread);guard_thread=nullptr;
    }
    running.store(false,std::memory_order_release);return true;
}
}
