#include "himitsu/validation/game_pause.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <mutex>
#include <string>
#include <vector>

namespace {
struct SuspendedThread {
    DWORD id = 0;
    HANDLE handle = nullptr;
};

struct ModuleRange {
    std::uintptr_t begin = 0;
    std::uintptr_t end = 0;
};

struct GameWindow {
    HWND handle = nullptr;
    bool was_visible = false;
    WINDOWPLACEMENT placement{};
    LONG_PTR original_extended_style = 0;
    bool originally_layered = false;
    bool layered_attributes_valid = false;
    COLORREF original_color_key = 0;
    BYTE original_alpha = 255;
    DWORD original_layered_flags = 0;
};

std::mutex pause_mutex;
std::vector<DWORD> captured_thread_ids;
std::vector<DWORD> forced_game_thread_ids;
std::vector<GameWindow> game_windows;
std::vector<SuspendedThread> suspended_threads;
std::vector<ModuleRange> system_module_ranges;
std::vector<ModuleRange> application_module_ranges;
std::vector<std::uintptr_t> wait_entry_points;
DWORD validation_thread_id = 0;
bool pause_active = false;
constexpr int window_fade_frames = 52;
constexpr DWORD window_fade_frame_delay_ms = 14;

std::wstring lower_copy(std::wstring value) {
    for (wchar_t& character : value) {
        character = static_cast<wchar_t>(std::towlower(character));
    }
    return value;
}

bool begins_with_path(const std::wstring& path, const std::wstring& root) {
    return path.size() >= root.size()
        && path.compare(0, root.size(), root) == 0
        && (path.size() == root.size() || path[root.size()] == L'\\');
}

bool address_in_ranges(std::uintptr_t address, const std::vector<ModuleRange>& ranges) {
    for (const ModuleRange& range : ranges) {
        if (address >= range.begin && address < range.end) return true;
    }
    return false;
}

bool id_in_list(DWORD id, const std::vector<DWORD>& ids) {
    for (const DWORD candidate : ids) {
        if (candidate == id) return true;
    }
    return false;
}

bool already_suspended(DWORD id) {
    for (const SuspendedThread& thread : suspended_threads) {
        if (thread.id == id) return true;
    }
    return false;
}

void capture_modules(DWORD process_id, const std::wstring& windows_root) {
    system_module_ranges.clear();
    application_module_ranges.clear();
    system_module_ranges.reserve(512);
    application_module_ranges.reserve(512);

    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        process_id
    );
    if (snapshot == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            const auto begin = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            const ModuleRange range{begin, begin + entry.modBaseSize};
            const std::wstring path = lower_copy(entry.szExePath);
            auto& destination = begins_with_path(path, windows_root)
                ? system_module_ranges
                : application_module_ranges;
            if (destination.size() < destination.capacity()) {
                destination.push_back(range);
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void add_wait_entry(HMODULE module, const char* name) {
    if (module == nullptr) return;
    const FARPROC address = GetProcAddress(module, name);
    if (address != nullptr) {
        wait_entry_points.push_back(reinterpret_cast<std::uintptr_t>(address));
    }
}

void capture_wait_entries() {
    wait_entry_points.clear();
    wait_entry_points.reserve(24);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
    add_wait_entry(ntdll, "NtWaitForSingleObject");
    add_wait_entry(ntdll, "NtWaitForMultipleObjects");
    add_wait_entry(ntdll, "NtDelayExecution");
    add_wait_entry(ntdll, "NtWaitForAlertByThreadId");
    add_wait_entry(kernel32, "Sleep");
    add_wait_entry(kernel32, "SleepEx");
    add_wait_entry(kernel32, "WaitForSingleObject");
    add_wait_entry(kernel32, "WaitForSingleObjectEx");
    add_wait_entry(kernel32, "WaitForMultipleObjects");
    add_wait_entry(kernel32, "WaitForMultipleObjectsEx");
    add_wait_entry(kernelbase, "Sleep");
    add_wait_entry(kernelbase, "SleepEx");
    add_wait_entry(kernelbase, "WaitForSingleObjectEx");
    add_wait_entry(kernelbase, "WaitForMultipleObjectsEx");
    add_wait_entry(kernelbase, "WaitOnAddress");
}

bool near_wait_entry(std::uintptr_t instruction) {
    for (const std::uintptr_t entry : wait_entry_points) {
        if (instruction >= entry && instruction < entry + 160U) return true;
    }
    return false;
}

bool stack_references_application(const CONTEXT& context) {
#if defined(_M_X64) || defined(__x86_64__)
    const std::uintptr_t stack_pointer = static_cast<std::uintptr_t>(context.Rsp);
#else
    const std::uintptr_t stack_pointer = static_cast<std::uintptr_t>(context.Esp);
#endif
    std::array<std::uintptr_t, 512> words{};
    MEMORY_BASIC_INFORMATION stack_memory{};
    if (VirtualQuery(
            reinterpret_cast<LPCVOID>(stack_pointer),
            &stack_memory,
            sizeof(stack_memory)
        ) == 0 || stack_memory.State != MEM_COMMIT) {
        return false;
    }
    const auto region_end = reinterpret_cast<std::uintptr_t>(stack_memory.BaseAddress)
        + stack_memory.RegionSize;
    if (region_end <= stack_pointer) return false;
    const SIZE_T readable = static_cast<SIZE_T>(
        (std::min)(
            static_cast<std::uintptr_t>(sizeof(words)),
            region_end - stack_pointer
        )
    );
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(stack_pointer),
            words.data(),
            readable,
            &bytes_read
        )) {
        return false;
    }
    const std::size_t count = bytes_read / sizeof(std::uintptr_t);
    for (std::size_t index = 0; index < count; ++index) {
        if (address_in_ranges(words[index], application_module_ranges)) return true;
    }
    return false;
}

using GetThreadDescriptionFn = HRESULT(WINAPI*)(HANDLE, PWSTR*);

bool has_game_thread_name(HANDLE thread) {
    static const auto get_description = []() -> GetThreadDescriptionFn {
        const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        return kernel32 == nullptr
            ? nullptr
            : reinterpret_cast<GetThreadDescriptionFn>(
                GetProcAddress(kernel32, "GetThreadDescription")
            );
    }();
    if (get_description == nullptr) return false;
    PWSTR description = nullptr;
    if (FAILED(get_description(thread, &description)) || description == nullptr) return false;
    const std::wstring name = lower_copy(description);
    LocalFree(description);
    return name == L"render thread"
        || name == L"client thread"
        || name == L"server thread"
        || name == L"game thread"
        || name == L"main"
        || name.find(L"minecraft") != std::wstring::npos;
}

bool window_was_minimized(const GameWindow& window) {
    return window.placement.showCmd == SW_SHOWMINIMIZED
        || window.placement.showCmd == SW_MINIMIZE
        || window.placement.showCmd == SW_SHOWMINNOACTIVE;
}

bool begin_window_fade(GameWindow& window, BYTE alpha) {
    if (window.handle == nullptr || !IsWindow(window.handle)) return false;

    if (window.originally_layered && !window.layered_attributes_valid) return false;
    SetWindowLongPtrW(
        window.handle,
        GWL_EXSTYLE,
        window.original_extended_style | WS_EX_LAYERED
    );
    return SetLayeredWindowAttributes(window.handle, 0, alpha, LWA_ALPHA) != FALSE;
}

void restore_window_composition(GameWindow& window) {
    if (window.handle == nullptr || !IsWindow(window.handle)) return;
    if (window.originally_layered && window.layered_attributes_valid) {
        SetLayeredWindowAttributes(
            window.handle,
            window.original_color_key,
            window.original_alpha,
            window.original_layered_flags
        );
    } else {
        SetWindowLongPtrW(
            window.handle,
            GWL_EXSTYLE,
            window.original_extended_style
        );
    }
}

BYTE smooth_alpha(float progress, bool appearing) {
    const float eased = progress * progress * (3.0F - 2.0F * progress);
    const float opacity = appearing ? eased : 1.0F - eased;
    return static_cast<BYTE>(opacity * 255.0F + 0.5F);
}

void fade_out_and_hide(GameWindow& window) {
    const bool can_animate = window.was_visible
        && !window_was_minimized(window)
        && begin_window_fade(window, 255);
    if (!can_animate) {
        ShowWindow(window.handle, SW_HIDE);
        restore_window_composition(window);
        return;
    }
    for (int frame = 0; frame <= window_fade_frames; ++frame) {
        const float progress = static_cast<float>(frame) / window_fade_frames;
        SetLayeredWindowAttributes(
            window.handle,
            0,
            smooth_alpha(progress, false),
            LWA_ALPHA
        );
        Sleep(window_fade_frame_delay_ms);
    }
    ShowWindow(window.handle, SW_HIDE);
    restore_window_composition(window);
}

void show_and_fade_in(GameWindow& window, int show_command) {
    const bool can_animate = !window_was_minimized(window)
        && begin_window_fade(window, 0);
    if (!can_animate) {
        ShowWindow(window.handle, show_command);
        restore_window_composition(window);
        return;
    }
    ShowWindow(window.handle, show_command);
    for (int frame = 0; frame <= window_fade_frames; ++frame) {
        const float progress = static_cast<float>(frame) / window_fade_frames;
        SetLayeredWindowAttributes(
            window.handle,
            0,
            smooth_alpha(progress, true),
            LWA_ALPHA
        );
        Sleep(window_fade_frame_delay_ms);
    }
    restore_window_composition(window);
    RedrawWindow(
        window.handle,
        nullptr,
        nullptr,
        RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN
    );
}

struct WindowSearch {
    DWORD process_id = 0;
};

BOOL CALLBACK capture_game_window(HWND window, LPARAM parameter) {
    const auto& search = *reinterpret_cast<WindowSearch*>(parameter);
    if (!IsWindowVisible(window)) return TRUE;
    DWORD process_id = 0;
    const DWORD thread_id = GetWindowThreadProcessId(window, &process_id);
    if (process_id != search.process_id || thread_id == 0) return TRUE;
    wchar_t class_name[64]{};
    GetClassNameW(window, class_name, static_cast<int>(std::size(class_name)));
    if (_wcsicmp(class_name, L"GLFW30") == 0
        ) {
        if (!id_in_list(thread_id, forced_game_thread_ids)) {
            forced_game_thread_ids.push_back(thread_id);
        }
        bool known_window = false;
        for (const GameWindow& captured : game_windows) {
            if (captured.handle == window) {
                known_window = true;
                break;
            }
        }
        if (!known_window && game_windows.size() < game_windows.capacity()) {
            GameWindow captured{};
            captured.handle = window;
            captured.was_visible = IsWindowVisible(window) != FALSE;
            captured.placement.length = sizeof(captured.placement);
            GetWindowPlacement(window, &captured.placement);
            captured.original_extended_style = GetWindowLongPtrW(window, GWL_EXSTYLE);
            captured.originally_layered =
                (captured.original_extended_style & WS_EX_LAYERED) != 0;
            if (captured.originally_layered) {
                captured.layered_attributes_valid = GetLayeredWindowAttributes(
                    window,
                    &captured.original_color_key,
                    &captured.original_alpha,
                    &captured.original_layered_flags
                ) != FALSE;
            }
            game_windows.push_back(captured);
        }
    }
    return TRUE;
}

void capture_process_threads(DWORD process_id) {
    captured_thread_ids.clear();
    forced_game_thread_ids.clear();
    game_windows.clear();
    captured_thread_ids.reserve(2048);
    forced_game_thread_ids.reserve(64);
    game_windows.reserve(8);

    wchar_t windows_directory[32768]{};
    const UINT windows_length = GetWindowsDirectoryW(
        windows_directory,
        static_cast<UINT>(std::size(windows_directory))
    );
    const std::wstring windows_root = windows_length > 0
        && windows_length < std::size(windows_directory)
        ? lower_copy(std::wstring(windows_directory, windows_length))
        : L"c:\\windows";
    capture_modules(process_id, windows_root);
    capture_wait_entries();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID != process_id) continue;
                if (captured_thread_ids.size() < captured_thread_ids.capacity()) {
                    captured_thread_ids.push_back(entry.th32ThreadID);
                }
                HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
                if (thread != nullptr) {
                    if (has_game_thread_name(thread)
                        && !id_in_list(entry.th32ThreadID, forced_game_thread_ids)) {
                        forced_game_thread_ids.push_back(entry.th32ThreadID);
                    }
                    CloseHandle(thread);
                }
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    WindowSearch search{process_id};
    EnumWindows(capture_game_window, reinterpret_cast<LPARAM>(&search));
}

void enforce_locked() {
    if (!pause_active) return;
    for (const DWORD thread_id : captured_thread_ids) {
        if (thread_id == validation_thread_id || already_suspended(thread_id)) continue;

        HANDLE thread = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
            FALSE,
            thread_id
        );
        if (thread == nullptr) continue;
        if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
            CloseHandle(thread);
            continue;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        const bool context_ready = GetThreadContext(thread, &context) != FALSE;
#if defined(_M_X64) || defined(__x86_64__)
        const std::uintptr_t instruction = context_ready
            ? static_cast<std::uintptr_t>(context.Rip)
            : 0;
#else
        const std::uintptr_t instruction = context_ready
            ? static_cast<std::uintptr_t>(context.Eip)
            : 0;
#endif
        const bool forced = id_in_list(thread_id, forced_game_thread_ids);
        const bool application_instruction = context_ready
            && (address_in_ranges(instruction, application_module_ranges)
                || (!address_in_ranges(instruction, system_module_ranges)
                    && stack_references_application(context)));
        const bool application_wait = context_ready
            && near_wait_entry(instruction)
            && stack_references_application(context);

        if (forced || application_instruction || application_wait || !context_ready) {
            suspended_threads.push_back({thread_id, thread});
        } else {

            ResumeThread(thread);
            CloseHandle(thread);
        }
    }
}
}

namespace himitsu::validation::game_pause {
void prepare() {
    std::lock_guard lock(pause_mutex);
    if (!suspended_threads.empty()) return;
    capture_process_threads(GetCurrentProcessId());
    suspended_threads.clear();
    suspended_threads.reserve(captured_thread_ids.size());
}

void engage(HWND validation_window) {
    (void)validation_window;
    std::lock_guard lock(pause_mutex);
    if (pause_active) return;
    if (captured_thread_ids.empty()) {
        capture_process_threads(GetCurrentProcessId());
        suspended_threads.reserve(captured_thread_ids.size());
    }

    WindowSearch search{GetCurrentProcessId()};
    EnumWindows(capture_game_window, reinterpret_cast<LPARAM>(&search));
    for (GameWindow& window : game_windows) {
        if (window.handle != nullptr && IsWindow(window.handle) && window.was_visible) {
            fade_out_and_hide(window);
        }
    }
    validation_thread_id = GetCurrentThreadId();
    pause_active = true;
    enforce_locked();
}

void enforce() {
    std::lock_guard lock(pause_mutex);
    enforce_locked();
}

void release() {
    std::lock_guard lock(pause_mutex);
    pause_active = false;
    for (auto iterator = suspended_threads.rbegin();
         iterator != suspended_threads.rend();
         ++iterator) {
        if (iterator->handle != nullptr) {
            ResumeThread(iterator->handle);
            CloseHandle(iterator->handle);
            iterator->handle = nullptr;
        }
    }
    suspended_threads.clear();
    for (GameWindow& window : game_windows) {
        if (window.handle == nullptr || !IsWindow(window.handle) || !window.was_visible) continue;
        int show_command = window.placement.showCmd;
        if (show_command == SW_HIDE) show_command = SW_RESTORE;
        show_and_fade_in(window, show_command);
        if (show_command != SW_SHOWMINIMIZED
            && show_command != SW_MINIMIZE
            && show_command != SW_SHOWMINNOACTIVE) {
            SetForegroundWindow(window.handle);
        }
    }
    captured_thread_ids.clear();
    forced_game_thread_ids.clear();
    game_windows.clear();
    system_module_ranges.clear();
    application_module_ranges.clear();
    wait_entry_points.clear();
    validation_thread_id = 0;
}
}
