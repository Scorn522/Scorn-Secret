#pragma once

#include <jni.h>
#include <jvmti.h>
#include <windows.h>

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>

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

    SRWLOCK* references_lock();
    jclass transformer_class = nullptr;
    jmethodID transformer_method = nullptr;
    jclass render_callback_class = nullptr;
    jmethodID render_callback_method = nullptr;
    std::vector<jobject> protected_threads;

private:
    std::atomic<bool> shutting_down_{false};
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
