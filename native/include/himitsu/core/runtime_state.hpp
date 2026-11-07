#pragma once

#include <jni.h>
#include <jvmti.h>
#include <windows.h>

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <cstdint>

namespace himitsu::core {
class RuntimeState {
public:
    static RuntimeState& instance();

    int initialize(JavaVM* vm, jvmtiEnv* jvmti);
    void replace_jvmti(jvmtiEnv* jvmti);
    void configure(std::string game_directory, std::string mod_path);
    bool shutdown(JNIEnv* env);
    bool enter_call();
    void leave_call();
    [[nodiscard]] bool shutting_down() const;

    [[nodiscard]] bool initialized() const;
    [[nodiscard]] JavaVM* vm() const;
    [[nodiscard]] jvmtiEnv* jvmti() const;
    [[nodiscard]] std::string game_directory_utf8() const;
    [[nodiscard]] std::string mod_path_utf8() const;

    struct ProtectedThread { jobject java_thread=nullptr; HANDLE os_thread=nullptr; };
    struct References {
        jclass transformer=nullptr, render=nullptr;
        jclass bootstrap=nullptr, cleanup_reader=nullptr, event_installer=nullptr, event_bridge=nullptr, event_bus=nullptr, event_array_type=nullptr;
        jobject game_loader=nullptr, event_loader=nullptr, event_handles[2]{};
        jfieldID event_field=nullptr;
        std::shared_ptr<const std::vector<unsigned char>> event_image;
        std::uint64_t event_generation=0;
        jmethodID transformer_method=nullptr, render_method=nullptr;
        std::vector<ProtectedThread> threads;
        std::uint64_t transformer_version=0,render_version=0;
    };
    class ReferenceRead {
    public:
        explicit ReferenceRead(RuntimeState& state,JNIEnv* env=nullptr);
        ~ReferenceRead();
        ReferenceRead(const ReferenceRead&)=delete;
        ReferenceRead& operator=(const ReferenceRead&)=delete;
        const References* get() const { return value_; }
        const References* operator->() const { return value_; }
    private:
        RuntimeState& state_; JNIEnv* env_; const References* value_;
    };
    bool publish_references(const References* expected,std::unique_ptr<References>& next,bool retiring=false);
    jclass local_callback(JNIEnv* env,bool render,jmethodID& method);
    void collect_references(JNIEnv* env);
    SRWLOCK* references_lock(); // Native state only; never carry across JNI.

private:
    std::atomic<bool> shutting_down_{false}, shutdown_complete_{false};
    std::atomic<References*> references_{new References};
    std::atomic<unsigned int> reference_readers_{0};
    std::atomic<bool> retired_pending_{false};
    std::vector<References*> retired_snapshots_;
    std::vector<jobject> retired_refs_;
    std::vector<HANDLE> retired_handles_;
    std::atomic<unsigned int> active_calls_{0};
    std::mutex drain_mutex_;
    std::condition_variable drained_;
    mutable SRWLOCK lock_ = SRWLOCK_INIT;
    bool initialized_ = false;
    JavaVM* vm_ = nullptr;
    jvmtiEnv* jvmti_ = nullptr;
    std::string game_directory_;
    std::string mod_path_;
};

class StateLock {
public:
    explicit StateLock(SRWLOCK* lock) : lock_(lock) {
        AcquireSRWLockExclusive(lock_);
    }

    ~StateLock() {
        ReleaseSRWLockExclusive(lock_);
    }

    StateLock(const StateLock&) = delete;
    StateLock& operator=(const StateLock&) = delete;

private:
    SRWLOCK* lock_;
};
}
