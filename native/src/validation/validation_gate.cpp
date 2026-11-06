#include "himitsu/validation/validation_gate.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/platform/windows/module_conceal.hpp"
#include "himitsu/validation/capability_registry.hpp"
#include "himitsu/validation/game_pause.hpp"
#include "himitsu/validation/integrity_check.hpp"
#include "himitsu/validation/runtime_lease.hpp"
#include "himitsu/validation/validation_ui.hpp"

#include <tlhelp32.h>

#include <atomic>
#include <cstdint>

namespace {
std::atomic<himitsu::validation::GateState> gate_state{
    himitsu::validation::GateState::idle
};
std::atomic<bool> permanent_rejection{false};
std::atomic<std::uintptr_t> approval_seal{0};
HANDLE gate_complete = nullptr;
HMODULE gate_module = nullptr;
constexpr std::uintptr_t approval_magic = static_cast<std::uintptr_t>(0x7B63D91E5A24C8F1ULL);

std::uintptr_t expected_approval_seal() {
    return approval_magic
        ^ reinterpret_cast<std::uintptr_t>(gate_module)
        ^ (approval_magic >> 17U);
}

bool approval_is_sealed() {
    return !permanent_rejection.load(std::memory_order_acquire)
        && approval_seal.load(std::memory_order_acquire) == expected_approval_seal();
}

void freeze_other_threads() {
    const DWORD process_id = GetCurrentProcessId();
    const DWORD current_thread = GetCurrentThreadId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != process_id
                || entry.th32ThreadID == current_thread) {
                continue;
            }
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
            if (thread != nullptr) {
                SuspendThread(thread);
                CloseHandle(thread);
            }
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

DWORD WINAPI validation_worker(void*) {

    const bool integrity_baseline = himitsu::validation::integrity::capture_baseline(
        gate_module
    );
#ifdef HIMITSU_LOCAL_TEST
    const bool local_ready = himitsu::validation::capability::initialize_local_test(gate_module);
#endif
    const bool concealed = himitsu::platform::windows::module_conceal::hide(
        gate_module
    );
    himitsu::core::log::initialize(gate_module);
    HIMITSU_LOG_INFO(
        "Validation",
        "早期模块列表摘除已完成（结果=%s，模块=%p，线程=%lu）",
        concealed ? "成功" : "失败",
        gate_module,
        GetCurrentThreadId()
    );

#ifdef HIMITSU_LOCAL_TEST
    HIMITSU_LOG_INFO("Validation", "LOCAL_TEST_BUILD: standalone development capabilities; no remote authorization");
    auto final_state = local_ready ? himitsu::validation::GateState::approved
                                  : himitsu::validation::GateState::failed;
#else
    const auto result = himitsu::validation::ui::run(gate_module);
    auto final_state = result == himitsu::validation::ui::Result::approved
        ? himitsu::validation::GateState::approved
        : result == himitsu::validation::ui::Result::rejected
            ? himitsu::validation::GateState::rejected
            : himitsu::validation::GateState::failed;
#endif

    const bool integrity_valid = integrity_baseline
        && himitsu::validation::integrity::verify_self(
            gate_module,
            himitsu::validation::capability::dll_sha256()
        );

    if (!integrity_baseline) {
        himitsu::validation::abort_with_message(
            L"验证系统初始化失败\n\nDLL integrity baseline capture failed.",
            0x48560001UL
        );
    }
    if (final_state == himitsu::validation::GateState::approved
        && !integrity_valid) {
        himitsu::validation::abort_with_message(
            L"客户端完整性校验失败\n\n"
            L"DLL has been modified or does not match this release.\n"
            L"请重新安装当前版本。",
            0x48560001UL
        );
    }
    if (final_state == himitsu::validation::GateState::approved
        && !permanent_rejection.load(std::memory_order_acquire)
        && integrity_valid) {

        himitsu::validation::game_pause::release();
        approval_seal.store(expected_approval_seal(), std::memory_order_release);
        gate_state.store(final_state, std::memory_order_release);
    } else {
        permanent_rejection.store(true, std::memory_order_release);
        approval_seal.store(0, std::memory_order_release);
        if (final_state == himitsu::validation::GateState::approved) {
            final_state = himitsu::validation::GateState::rejected;
        }
        gate_state.store(final_state, std::memory_order_release);
    }
    if (gate_complete != nullptr) {
        SetEvent(gate_complete);
    }

    if (final_state != himitsu::validation::GateState::approved) {
        if (!integrity_baseline) {
            himitsu::validation::abort_with_message(
                L"验证系统初始化失败\n\nDLL integrity baseline capture failed.",
                0x48560001UL
            );
        }
        if (final_state == himitsu::validation::GateState::approved
            && !integrity_valid) {
            himitsu::validation::abort_with_message(
                L"客户端完整性校验失败\n\nDLL has been modified. Please reinstall.\nDLL 文件不匹配，请重新安装。",
                0x48560001UL
            );
        }
        himitsu::validation::terminate_rejected(
            final_state == himitsu::validation::GateState::rejected
                ? 0x48560001UL
                : 0x48560002UL
        );
    }
    return 0;
}
}

namespace himitsu::validation {
bool begin(HMODULE module) {
    if (permanent_rejection.load(std::memory_order_acquire)) return false;
    GateState expected = GateState::idle;
    if (!gate_state.compare_exchange_strong(
            expected,
            GateState::running,
            std::memory_order_acq_rel
        )) {
        return expected == GateState::running
            || (expected == GateState::approved && approval_is_sealed());
    }

    gate_module = module;
    gate_complete = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (gate_complete == nullptr) {
        gate_state.store(GateState::failed, std::memory_order_release);
        return false;
    }

    HANDLE thread = CreateThread(nullptr, 0, validation_worker, nullptr, 0, nullptr);
    if (thread == nullptr) {
        gate_state.store(GateState::failed, std::memory_order_release);
        SetEvent(gate_complete);
        return false;
    }
    CloseHandle(thread);
    return true;
}

void require_approval() {
    if (permanent_rejection.load(std::memory_order_acquire)) {
        abort_with_message(
            L"验证已被永久锁定\n\nPermission denied.",
            0x48560005UL
        );
    }
    GateState current = gate_state.load(std::memory_order_acquire);
    if (current == GateState::idle) {
        begin(gate_module);
        current = gate_state.load(std::memory_order_acquire);
    }
    if (current == GateState::approved
        && approval_is_sealed()
        && lease::valid()
        && capability::valid()
        && integrity::verify_runtime()) {
        return;
    }
    if (current == GateState::running && gate_complete != nullptr) {
        const DWORD wait_result = WaitForSingleObject(gate_complete, INFINITE);
        if (wait_result == WAIT_OBJECT_0
            && gate_state.load(std::memory_order_acquire) == GateState::approved
            && approval_is_sealed()
            && lease::valid()
            && capability::valid()
            && integrity::verify_runtime()) {
            return;
        }
    }
    if (current == GateState::approved || current == GateState::running) {
        if (!himitsu::validation::lease::valid()) {
            abort_with_message(
                L"登录会话已过期\n\nSession expired. Please restart and login again.\n会话过期，请重新登录。",
                0x48560003UL
            );
        }
        if (!himitsu::validation::capability::valid()) {
            abort_with_message(
                L"功能授权已过期\n\nLicense expired. Please restart and login again.\n授权过期，请重新登录。",
                0x48560003UL
            );
        }
        if (!himitsu::validation::integrity::verify_runtime()) {
            abort_with_message(
                L"内存完整性校验失败\n\nProcess memory integrity failure.\n程序完整性异常。",
                0x48560003UL
            );
        }
    }
    abort_with_message(
        L"验证未通过\n\nValidation failed.",
        0x48560003UL
    );
}

void latch_rejection() {
    permanent_rejection.store(true, std::memory_order_release);
    approval_seal.store(0, std::memory_order_release);
    gate_state.store(GateState::rejected, std::memory_order_release);
}

bool approved() {
    return gate_state.load(std::memory_order_acquire) == GateState::approved
        && approval_is_sealed()
        && himitsu::validation::lease::valid()
        && himitsu::validation::capability::valid()
        && himitsu::validation::integrity::verify_runtime();
}

bool rejection_latched() {
    return permanent_rejection.load(std::memory_order_acquire);
}

GateState state() {
    if (permanent_rejection.load(std::memory_order_acquire)) return GateState::rejected;
    const GateState current = gate_state.load(std::memory_order_acquire);
    if (current == GateState::approved && !approval_is_sealed()) return GateState::rejected;
    return current;
}

[[noreturn]] void terminate_rejected(unsigned long exit_code) {
    using TerminateProcessFn = BOOL(WINAPI*)(HANDLE, UINT);
    using ExitProcessFn = void(WINAPI*)(UINT);
    using RaiseFailFastFn = void(WINAPI*)(PEXCEPTION_RECORD, PCONTEXT, DWORD);

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto terminate_process = kernel32 == nullptr
        ? nullptr
        : reinterpret_cast<TerminateProcessFn>(
            GetProcAddress(kernel32, "TerminateProcess")
        );
    const auto raise_fail_fast = kernel32 == nullptr
        ? nullptr
        : reinterpret_cast<RaiseFailFastFn>(
            GetProcAddress(kernel32, "RaiseFailFastException")
        );
    const auto exit_process = kernel32 == nullptr
        ? nullptr
        : reinterpret_cast<ExitProcessFn>(
            GetProcAddress(kernel32, "ExitProcess")
        );

    latch_rejection();
    freeze_other_threads();
    if (gate_complete != nullptr) {
        SetEvent(gate_complete);
    }

    if (terminate_process != nullptr) {
        terminate_process(GetCurrentProcess(), static_cast<UINT>(exit_code));
    }
    if (raise_fail_fast != nullptr) {
        raise_fail_fast(nullptr, nullptr, 0);
    }
    if (exit_process != nullptr) {
        exit_process(static_cast<UINT>(exit_code));
    }

    for (;;) {
        WaitForSingleObject(GetCurrentProcess(), INFINITE);
        Sleep(INFINITE);
    }
}

[[noreturn]] void abort_with_message(const wchar_t* message, unsigned long exit_code) {
    MessageBoxW(
        nullptr,
        message,
        L"Secret Error",
        MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND
    );
    terminate_rejected(exit_code);
}
}
