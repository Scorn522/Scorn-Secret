#include "himitsu/core/runtime_state.hpp"
#include "himitsu/core/native_log.hpp"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#define CHECK(value) do { if (!(value)) { std::fprintf(stderr, "check failed at %d\n", __LINE__); std::abort(); } } while (false)
std::atomic<int> hooks_stopped{0}, lease_stops{0};
namespace himitsu::core::log {
void write(Level, const char*, const char*, ...) {}
void shutdown() {}
}
namespace himitsu::validation {
[[noreturn]] void terminate_rejected(unsigned long) { std::abort(); }
namespace lease {
bool valid() { return lease_stops.load() == 0; }
void stop() { CHECK(hooks_stopped.load() == 4); ++lease_stops; }
}
}
namespace himitsu::platform::windows {
void stop_module_guard() { ++hooks_stopped; }
void stop_thread_guard() { ++hooks_stopped; }
void uninstall_swap_buffers_hook() { ++hooks_stopped; }
}
namespace himitsu::jvm { void shutdown_jvmti_guard() { ++hooks_stopped; } }
int main() {
    auto& state = himitsu::core::RuntimeState::instance();
    CHECK(state.enter_call()); CHECK(state.enter_call());
    CHECK(!state.shutdown(nullptr)); CHECK(!state.shutting_down());
    state.leave_call(); state.leave_call();
    std::atomic<bool> entered{false}, release{false}, done{false};
    std::thread worker([&] {
        CHECK(state.enter_call()); entered = true;
        while (!release.load()) std::this_thread::yield();
        CHECK(lease_stops.load() == 0);
        state.leave_call();
    });
    while (!entered.load()) std::this_thread::yield();
    std::thread closer([&] {
        CHECK(state.enter_call()); CHECK(state.shutdown(nullptr));
        state.leave_call(); done = true;
    });
    while (!state.shutting_down()) std::this_thread::yield();
    CHECK(!state.enter_call());
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    CHECK(!done.load() && lease_stops.load() == 0 && hooks_stopped.load() == 0);
    release = true; worker.join(); closer.join();
    CHECK(done.load() && lease_stops.load() == 1 && !state.initialized());
    CHECK(!state.enter_call()); CHECK(state.shutdown(nullptr)); CHECK(lease_stops.load() == 1);
    std::puts("NATIVE_SHUTDOWN_PASS production_admission inflight_drain ordered_revocation reentry_refused idempotent MODEL_NO_JVM");
}
