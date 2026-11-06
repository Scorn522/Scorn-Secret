#pragma once

#include <windows.h>

#include <string>

namespace himitsu::validation::integrity {

bool capture_baseline(HMODULE module);
bool verify_self(HMODULE module, const std::string& expected_file_sha256);
bool verify_runtime();

}
