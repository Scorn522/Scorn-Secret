#include "himitsu/core/runtime_state.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/platform/windows/module_guard.hpp"
#include "himitsu/platform/windows/swap_buffers_hook.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#define CHECK(value) do {if(!(value)){std::fprintf(stderr,"check failed at %d\n",__LINE__);std::abort();}} while(false)
std::atomic<int> hooks_stopped{0},lease_stops{0},signals{0},deleted{0};
std::uint64_t stop_deadline=0;
bool stopped(std::uint64_t deadline) {
    CHECK(signals==2);if(stop_deadline)CHECK(stop_deadline==deadline);else stop_deadline=deadline;
    ++hooks_stopped;return GetTickCount64()<=deadline;
}
void unlocked() {
    auto* lock=himitsu::core::RuntimeState::instance().references_lock();
    CHECK(TryAcquireSRWLockExclusive(lock));ReleaseSRWLockExclusive(lock);
}
void JNICALL delete_ref(JNIEnv*,jobject) {unlocked();++deleted;}
jobject JNICALL local_ref(JNIEnv*,jobject ref) {unlocked();return ref;}
namespace himitsu::core::log {void write(Level,const char*,const char*,...) {} void shutdown() {}}
namespace himitsu::validation {
[[noreturn]] void terminate_rejected(unsigned long) {std::abort();}
namespace lease {bool valid(){return lease_stops==0;}void stop(){CHECK(hooks_stopped==4);++lease_stops;}}
}
namespace himitsu::platform::windows {
void request_module_guard_stop(){++signals;}
bool stop_module_guard(std::uint64_t deadline){return stopped(deadline);}
bool stop_thread_guard(std::uint64_t deadline){return stopped(deadline);}
bool uninstall_swap_buffers_hook(std::uint64_t deadline){return stopped(deadline);}
}
namespace himitsu::jvm {
void request_jvmti_guard_stop(){++signals;}
bool shutdown_jvmti_guard(std::uint64_t deadline){return stopped(deadline);}
}
int main(int argc,char** argv) {
    const bool reader_timeout=argc>1 && std::strcmp(argv[1],"reader-timeout")==0;
    const bool timeout=reader_timeout || (argc>1 && std::strcmp(argv[1],"timeout")==0);
    using State=himitsu::core::RuntimeState;auto& state=State::instance();
    JNINativeInterface_ table{};table.DeleteGlobalRef=delete_ref;table.NewLocalRef=local_ref;
    JNIEnv env{&table};
    CHECK(state.initialize(reinterpret_cast<JavaVM*>(1),reinterpret_cast<jvmtiEnv*>(1))==0);
    {
        State::ReferenceRead initial(state,&env);auto next=std::make_unique<State::References>(*initial.get());
        next->transformer=reinterpret_cast<jclass>(16);next->transformer_method=reinterpret_cast<jmethodID>(32);
        CHECK(state.publish_references(initial.get(),next));
    }
    {
        State::ReferenceRead pinned(state,&env);jmethodID method=nullptr;
        CHECK(state.local_callback(&env,false,method)==reinterpret_cast<jclass>(16));CHECK(method==reinterpret_cast<jmethodID>(32));
        auto empty=std::make_unique<State::References>();CHECK(state.publish_references(pinned.get(),empty));
        state.collect_references(&env);CHECK(deleted==0);
    }
    CHECK(deleted==1);
    {
        State::ReferenceRead initial(state,&env);auto next=std::make_unique<State::References>(*initial.get());
        next->threads.push_back({reinterpret_cast<jobject>(64),nullptr});CHECK(state.publish_references(initial.get(),next));
    }
    CHECK(state.enter_call());CHECK(state.enter_call());CHECK(!state.shutdown(&env));CHECK(!state.shutting_down());state.leave_call();state.leave_call();
    std::atomic<bool> entered{false},release{false},done{false};std::atomic<bool> complete{false};
    std::thread worker([&] {
        if(!reader_timeout) CHECK(state.enter_call());
        State::ReferenceRead read(state,&env);entered=true;
        while(!release.load())std::this_thread::yield();
        CHECK(lease_stops==0);if(!reader_timeout)state.leave_call();
    });
    while(!entered.load())std::this_thread::yield();
    const auto start=GetTickCount64();
    std::thread closer([&] {CHECK(state.enter_call());complete=state.shutdown(&env);state.leave_call();done=true;});
    while(!state.shutting_down())std::this_thread::yield();
    CHECK(!state.enter_call());Sleep(30);CHECK(!done && deleted==1 && lease_stops==0);
    if(timeout) {
        closer.join();CHECK(!complete && GetTickCount64()-start<6500 && deleted==1 && lease_stops==0);
        CHECK(state.initialized());CHECK(!state.shutdown(&env));
        release=true;worker.join();CHECK(deleted==1);
        std::puts(reader_timeout?"NATIVE_READER_TIMEOUT_PASS retired_reference_retained after_read_release_no_late_jni":"NATIVE_SHUTDOWN_TIMEOUT_PASS bounded_wait references_retained late_calls_refused duplicate_incomplete");
    } else {
        release=true;worker.join();closer.join();
        CHECK(complete && done && deleted==2 && lease_stops==1 && !state.initialized());
        CHECK(!state.enter_call());CHECK(state.shutdown(&env));CHECK(lease_stops==1);
        std::puts("NATIVE_SHUTDOWN_PASS snapshot_pinning jni_outside_lock common_deadline inflight_drain ordered_revocation idempotent MODEL_NO_JVM");
    }
}
