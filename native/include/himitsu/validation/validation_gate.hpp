#pragma once

#include <windows.h>

namespace himitsu::validation {
enum class GateState : unsigned int {
    idle,
    running,
    approved,
    rejected,
    failed
};

bool begin(HMODULE module);

void require_approval();

void latch_rejection();

[[nodiscard]] bool approved();
[[nodiscard]] bool rejection_latched();
[[nodiscard]] GateState state();

[[noreturn]] void terminate_rejected(unsigned long exit_code);
[[noreturn]] void abort_with_message(const wchar_t* message, unsigned long exit_code);
}
