#pragma once

#include <windows.h>

namespace himitsu::validation::ui {
enum class Result {
    approved,
    rejected,
    initialization_failed
};

Result run(HMODULE module);
}
