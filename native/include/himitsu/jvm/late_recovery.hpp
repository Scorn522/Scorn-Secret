#pragma once

#include <jni.h>
#include <jvmti.h>
#include <windows.h>
#include <memory>
#include <vector>
#include <cstddef>

namespace himitsu::jvm {

struct NativeCodeRange {
    unsigned char* address=nullptr;
    std::vector<unsigned char> expected;
    std::shared_ptr<void> module; // Pins the actual module until the last reader retires.
};
bool native_table_baseline(const void* table,std::size_t slots,std::vector<void*>& values);
bool native_memory_read(const void* address,void* output,std::size_t size);
bool native_pointer_exchange(void** slot,void* before,void* after,void* allocation_base);
bool native_export_baseline(HMODULE module,const char* name,std::vector<NativeCodeRange>& ranges,bool* unsupported=nullptr);
bool native_function_baseline(void* address,std::vector<NativeCodeRange>& ranges);
JavaVM* late_recover_created_vm();

bool late_recover_jvmti_dispatch(jvmtiEnv* env);
bool late_recover_jni_dispatch(JNIEnv* env);
}
