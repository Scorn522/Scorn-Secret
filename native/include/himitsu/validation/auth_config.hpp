#pragma once

#include <array>
#include <string>

namespace himitsu::validation::auth_config {
std::wstring endpoint();
std::string build_id();
bool allow_pinned_self_signed();
std::array<unsigned char, 32> certificate_sha256();
}
