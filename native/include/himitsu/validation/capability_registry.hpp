#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace himitsu::validation::capability {
#ifdef HIMITSU_LOCAL_TEST
// Development packages only: initialize our own keys and this exact DLL image.
bool initialize_local_test(void* module);
#endif

enum class Feature : std::uint64_t {
    none          = 0,
    class_control = 1ULL << 0,
    redefine      = 1ULL << 1,
    retransform   = 1ULL << 2,
    class_load    = 1ULL << 3,
    dump_class    = 1ULL << 4,
    render_frame  = 1ULL << 5,
    def_class     = 1ULL << 6,
    decrypt_jar   = 1ULL << 7,
    decrypt_class = 1ULL << 8,
    thread_prot   = 1ULL << 9,
};

bool initialize(
    std::span<const unsigned char> encrypted_payload,
    std::span<const unsigned char> manifest_bytes,
    const std::string& device_id,
    const std::string& hwid,
    const std::string& session_id
);

[[nodiscard]] bool is_enabled(Feature feature);
[[nodiscard]] bool valid();
[[nodiscard]] std::string payload_secret(bool class_payload);
[[nodiscard]] std::string dll_sha256();

void revoke();
void stop();

}
