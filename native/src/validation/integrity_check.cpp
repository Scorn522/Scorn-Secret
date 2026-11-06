#include "himitsu/validation/integrity_check.hpp"

#include "himitsu/validation/auth_crypto.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <mutex>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {
std::mutex integrity_mutex;
HMODULE baseline_module = nullptr;
std::vector<std::array<unsigned char, 32>> baseline_sections;
std::atomic<ULONGLONG> last_runtime_check{0};

std::vector<std::span<const unsigned char>> executable_sections(HMODULE module) {
    std::vector<std::span<const unsigned char>> sections;
    if (module == nullptr) return sections;
    const auto* base = reinterpret_cast<const unsigned char*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return sections;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return sections;
    }
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        if ((section[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0
            || section[index].Misc.VirtualSize == 0) {
            continue;
        }
        const std::size_t size = section[index].Misc.VirtualSize;
        if (section[index].VirtualAddress + size > nt->OptionalHeader.SizeOfImage) {
            return {};
        }
        sections.emplace_back(base + section[index].VirtualAddress, size);
    }
    return sections;
}

bool verify_memory_locked() {
    const auto sections = executable_sections(baseline_module);
    if (sections.empty() || sections.size() != baseline_sections.size()) return false;
    try {
        for (std::size_t index = 0; index < sections.size(); ++index) {
            if (!himitsu::validation::crypto::constant_equals(
                    himitsu::validation::crypto::sha256(sections[index]),
                    baseline_sections[index])) {
                return false;
            }
        }
    } catch (...) {
        return false;
    }
    return true;
}

std::wstring module_path(HMODULE module) {
    std::array<wchar_t, 32768> path{};
    const DWORD length = GetModuleFileNameW(
        module,
        path.data(),
        static_cast<DWORD>(path.size())
    );
    return length == 0 || length >= path.size()
        ? std::wstring{}
        : std::wstring(path.data(), length);
}
}

namespace himitsu::validation::integrity {
bool capture_baseline(HMODULE module) {
    const auto sections = executable_sections(module);
    if (sections.empty()) return false;
    std::vector<std::array<unsigned char, 32>> hashes;
    hashes.reserve(sections.size());
    try {
        for (const auto section : sections) hashes.push_back(crypto::sha256(section));
    } catch (...) {
        return false;
    }
    std::lock_guard lock(integrity_mutex);
    baseline_module = module;
    baseline_sections = std::move(hashes);
    last_runtime_check.store(GetTickCount64(), std::memory_order_release);
    return true;
}

bool verify_self(HMODULE module, const std::string& expected_file_sha256) {
    if (module == nullptr || expected_file_sha256.size() != 64) return false;
    const std::wstring path = module_path(module);
    if (path.empty()) return false;
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    const bool size_ok = GetFileSizeEx(file, &size) != FALSE
        && size.QuadPart > 0
        && size.QuadPart <= 64 * 1024 * 1024;
    if (!size_ok) {
        CloseHandle(file);
        return false;
    }
    std::vector<unsigned char> content(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const bool read_ok = ReadFile(
        file,
        content.data(),
        static_cast<DWORD>(content.size()),
        &read,
        nullptr
    ) != FALSE && read == static_cast<DWORD>(content.size());
    CloseHandle(file);
    if (!read_ok) return false;
    try {
        if (crypto::sha256_hex(content) != expected_file_sha256) return false;
    } catch (...) {
        return false;
    }
    std::lock_guard lock(integrity_mutex);
    return baseline_module == module && verify_memory_locked();
}

bool verify_runtime() {
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG previous = last_runtime_check.load(std::memory_order_acquire);
    if (now - previous < 5000) return true;
    std::lock_guard lock(integrity_mutex);
    if (now - last_runtime_check.load(std::memory_order_relaxed) < 5000) return true;
    const bool valid = verify_memory_locked();
    if (valid) last_runtime_check.store(now, std::memory_order_release);
    return valid;
}
}
