#include <vector>
#include "himitsu/jvm/jvmti_guard.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/late_recovery.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace {
using AddCapabilitiesFn = decltype(jvmtiInterface_1_::AddCapabilities);
using SetEventCallbacksFn = decltype(jvmtiInterface_1_::SetEventCallbacks);
using SetEventNotificationModeFn = decltype(jvmtiInterface_1_::SetEventNotificationMode);
using RetransformClassesFn = decltype(jvmtiInterface_1_::RetransformClasses);
using RedefineClassesFn = decltype(jvmtiInterface_1_::RedefineClasses);
using DisposeEnvironmentFn = decltype(jvmtiInterface_1_::DisposeEnvironment);
using RelinquishCapabilitiesFn = decltype(jvmtiInterface_1_::RelinquishCapabilities);
using SetNativeMethodPrefixFn = decltype(jvmtiInterface_1_::SetNativeMethodPrefix);
using SetNativeMethodPrefixesFn = decltype(jvmtiInterface_1_::SetNativeMethodPrefixes);
using GenerateEventsFn = decltype(jvmtiInterface_1_::GenerateEvents);
using GetPhaseFn = decltype(jvmtiInterface_1_::GetPhase);
using GetCapabilitiesFn = decltype(jvmtiInterface_1_::GetCapabilities);
using VmGetEnvFn = decltype(JNIInvokeInterface_::GetEnv);
using VmAttachFn = decltype(JNIInvokeInterface_::AttachCurrentThread);

constexpr jint EVENT_SLOTS = 128;

struct GuardState {
    std::atomic<jvmtiEnv*> env{nullptr};
    JavaVM* vm = nullptr;
    jvmtiInterface_1_* table = nullptr;
    jvmtiInterface_1_ private_table{};

    AddCapabilitiesFn add_capabilities = nullptr;
    SetEventCallbacksFn set_event_callbacks = nullptr;
    SetEventNotificationModeFn set_event_notification_mode = nullptr;
    RetransformClassesFn retransform_classes = nullptr;
    RedefineClassesFn redefine_classes = nullptr;
    DisposeEnvironmentFn dispose_environment = nullptr;
    RelinquishCapabilitiesFn relinquish_capabilities = nullptr;
    SetNativeMethodPrefixFn set_native_method_prefix = nullptr;
    SetNativeMethodPrefixesFn set_native_method_prefixes = nullptr;
    GenerateEventsFn generate_events = nullptr;
    GetPhaseFn get_phase = nullptr;
    GetCapabilitiesFn get_capabilities = nullptr;

    VmGetEnvFn vm_get_env = nullptr;
    VmAttachFn vm_attach = nullptr;

    jvmtiCapabilities required_capabilities{};
    jvmtiEventCallbacks required_callbacks{};
    jint required_callbacks_size = 0;
    std::array<jvmtiEventMode, EVENT_SLOTS> event_modes{};

    SRWLOCK lock = SRWLOCK_INIT;
    std::atomic<bool> installed{false};
    std::atomic<bool> healthy{false};
    std::atomic<unsigned long long> generation{0};
    std::atomic<bool> monitor_stop{false};
    HANDLE monitor_thread = nullptr;

    std::atomic<jvmtiEnv**> environment_head_slot{nullptr};
    std::atomic<bool> environment_linked{true};
    std::atomic<unsigned int> chain_recovery_failures{0};
};

GuardState state;

constexpr std::size_t JVMTI_ENV_MAGIC_OFFSET = 0x08;
constexpr std::size_t JVMTI_ENV_NEXT_OFFSET = 0x10;
constexpr std::uint32_t JVMTI_ENV_MAGIC = 0x71EEu;
constexpr std::size_t MAX_JVMTI_ENVIRONMENTS = 256;

bool readable_memory(const void* address, std::size_t size) {
    if (address == nullptr || size == 0) return false;
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(address, &memory, sizeof(memory)) != sizeof(memory)
        || memory.State != MEM_COMMIT
        || (memory.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
    const auto begin = reinterpret_cast<std::uintptr_t>(address);
    const auto region_begin = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
    const auto region_end = region_begin + memory.RegionSize;
    return begin >= region_begin && begin <= region_end && size <= region_end - begin;
}

jvmtiEnv* environment_next(jvmtiEnv* env) {
    if (!readable_memory(env, JVMTI_ENV_NEXT_OFFSET + sizeof(void*))) return nullptr;
    return *reinterpret_cast<jvmtiEnv**>(reinterpret_cast<unsigned char*>(env) + JVMTI_ENV_NEXT_OFFSET);
}

bool valid_environment_node(jvmtiEnv* env) {
    if (!readable_memory(env, JVMTI_ENV_NEXT_OFFSET + sizeof(void*))) return false;
    const auto* bytes = reinterpret_cast<const unsigned char*>(env);
    const auto magic = *reinterpret_cast<const std::uint32_t*>(bytes + JVMTI_ENV_MAGIC_OFFSET);
    if (magic != JVMTI_ENV_MAGIC || env->functions == nullptr) return false;
    return readable_memory(env->functions, sizeof(jvmtiInterface_1_));
}

struct EnvironmentChainInspection {
    bool valid = false;
    bool contains_preferred = false;
    std::size_t length = 0;
};

EnvironmentChainInspection inspect_environment_chain(jvmtiEnv* head, jvmtiEnv* preferred) {
    EnvironmentChainInspection result{};
    jvmtiEnv* node = head;
    while (node != nullptr && result.length < MAX_JVMTI_ENVIRONMENTS) {
        if (!valid_environment_node(node)) return result;
        if (node == preferred) result.contains_preferred = true;
        jvmtiEnv* next = environment_next(node);
        if (next == node) return result;
        node = next;
        ++result.length;
    }
    result.valid = node == nullptr && result.length != 0;
    return result;
}

jvmtiEnv** locate_environment_head_slot(jvmtiEnv* preferred) {
    HMODULE jvm = GetModuleHandleW(L"jvm.dll");
    if (jvm == nullptr) return nullptr;
    auto* base = reinterpret_cast<unsigned char*>(jvm);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return nullptr;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;

    jvmtiEnv** best_slot = nullptr;
    EnvironmentChainInspection best{};
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (unsigned int section_index = 0; section_index < nt->FileHeader.NumberOfSections; ++section_index) {
        const IMAGE_SECTION_HEADER& current = section[section_index];
        if ((current.Characteristics & IMAGE_SCN_MEM_WRITE) == 0) continue;
        const std::size_t section_size = std::max<std::size_t>(
            current.Misc.VirtualSize, current.SizeOfRawData);
        unsigned char* begin = base + current.VirtualAddress;
        unsigned char* end = begin + section_size;
        for (unsigned char* cursor = begin;
             cursor + sizeof(void*) <= end;
             cursor += alignof(void*)) {
            auto** candidate_slot = reinterpret_cast<jvmtiEnv**>(cursor);
            jvmtiEnv* candidate = *candidate_slot;
            if (!valid_environment_node(candidate)) continue;
            const EnvironmentChainInspection inspected = inspect_environment_chain(candidate, preferred);
            if (!inspected.valid) continue;
            const bool better = best_slot == nullptr
                || (inspected.contains_preferred && !best.contains_preferred)
                || (inspected.contains_preferred == best.contains_preferred
                    && inspected.length > best.length);
            if (better) {
                best_slot = candidate_slot;
                best = inspected;
            }
        }
    }

    if (best_slot != nullptr) {
        HIMITSU_LOG_INFO(
            "JvmtiGuard",
            "HotSpot JVMTI 环境链已动态定位（链首槽=%p，链首=%p，节点数=%zu，包含当前环境=%s）",
            best_slot,
            *best_slot,
            best.length,
            best.contains_preferred ? "是" : "否"
        );
    }
    return best_slot;
}

bool environment_chain_contains(jvmtiEnv** head_slot, jvmtiEnv* target) {
    if (head_slot == nullptr || !readable_memory(head_slot, sizeof(void*)) || target == nullptr) return false;
    const EnvironmentChainInspection inspected = inspect_environment_chain(*head_slot, target);
    return inspected.valid && inspected.contains_preferred;
}

struct VmStructLayout {
    std::size_t klass_offset = 0;
    std::size_t access_flags_offset = 0;
    std::size_t flags_offset = 0;
    bool ready = false;
};

VmStructLayout vm_structs;
INIT_ONCE vm_structs_once = INIT_ONCE_STATIC_INIT;

template <typename Value>
bool read_export_value(HMODULE module, const char* name, Value& value) {
    FARPROC symbol = GetProcAddress(module, name);
    if (symbol == nullptr) return false;
    value = *reinterpret_cast<const Value*>(symbol);
    return true;
}

BOOL CALLBACK initialize_vm_structs(PINIT_ONCE, PVOID, PVOID*) {
    HMODULE jvm = GetModuleHandleA("jvm.dll");
    if (jvm == nullptr) return TRUE;

    unsigned char* entries = nullptr;
    std::size_t type_name_offset = 0;
    std::size_t field_name_offset = 0;
    std::size_t is_static_offset = 0;
    std::size_t offset_offset = 0;
    std::size_t address_offset = 0;
    std::size_t stride = 0;
    if (!read_export_value(jvm, "gHotSpotVMStructs", entries)
        || !read_export_value(jvm, "gHotSpotVMStructEntryTypeNameOffset", type_name_offset)
        || !read_export_value(jvm, "gHotSpotVMStructEntryFieldNameOffset", field_name_offset)
        || !read_export_value(jvm, "gHotSpotVMStructEntryIsStaticOffset", is_static_offset)
        || !read_export_value(jvm, "gHotSpotVMStructEntryOffsetOffset", offset_offset)
        || !read_export_value(jvm, "gHotSpotVMStructEntryAddressOffset", address_offset)
        || !read_export_value(jvm, "gHotSpotVMStructEntryArrayStride", stride)
        || entries == nullptr || stride == 0) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "HotSpot VMStruct 导出项缺失");
        return TRUE;
    }

    for (std::size_t index = 0; index < 65536; ++index) {
        unsigned char* entry = entries + index * stride;
        const char* type_name = *reinterpret_cast<const char* const*>(entry + type_name_offset);
        const char* field_name = *reinterpret_cast<const char* const*>(entry + field_name_offset);
        if (type_name == nullptr || field_name == nullptr) break;
        const int is_static = *reinterpret_cast<const int*>(entry + is_static_offset);
        const std::size_t field_offset = *reinterpret_cast<const std::size_t*>(entry + offset_offset);
        void* address = *reinterpret_cast<void* const*>(entry + address_offset);

        if (is_static && std::strcmp(type_name, "java_lang_Class") == 0
            && std::strcmp(field_name, "_klass_offset") == 0 && address != nullptr) {
            vm_structs.klass_offset = static_cast<std::size_t>(*reinterpret_cast<const int*>(address));
        } else if (!is_static && std::strcmp(type_name, "Klass") == 0
            && std::strcmp(field_name, "_access_flags") == 0) {
            vm_structs.access_flags_offset = field_offset;
        } else if (!is_static && std::strcmp(type_name, "AccessFlags") == 0
            && std::strcmp(field_name, "_flags") == 0) {
            vm_structs.flags_offset = field_offset;
        }
    }

    vm_structs.ready = vm_structs.klass_offset != 0 && vm_structs.access_flags_offset != 0;
    HIMITSU_LOG_INFO(
        "JvmtiGuard",
        "HotSpot 类标志偏移解析完成（就绪=%s，mirrorKlass=0x%zX，accessFlags=0x%zX，flags=0x%zX）",
        vm_structs.ready ? "是" : "否",
        vm_structs.klass_offset,
        vm_structs.access_flags_offset,
        vm_structs.flags_offset
    );
    return TRUE;
}

class RetransformFlagScope {
public:
    explicit RetransformFlagScope(jclass type) {
        InitOnceExecuteOnce(&vm_structs_once, initialize_vm_structs, nullptr, nullptr);
        if (!vm_structs.ready || type == nullptr) return;
        auto* mirror = *reinterpret_cast<unsigned char**>(type);
        if (mirror == nullptr) return;
        auto* klass = *reinterpret_cast<unsigned char**>(mirror + vm_structs.klass_offset);
        if (klass == nullptr) return;
        flags_ = reinterpret_cast<unsigned int*>(klass + vm_structs.access_flags_offset + vm_structs.flags_offset);
        original_ = *flags_;
        *flags_ = original_ & ~0x04000000u;
    }
    ~RetransformFlagScope() { if (flags_ != nullptr) *flags_ = original_; }
    RetransformFlagScope(const RetransformFlagScope&) = delete;
    RetransformFlagScope& operator=(const RetransformFlagScope&) = delete;
private:
    unsigned int* flags_ = nullptr;
    unsigned int original_ = 0;
};

jvmtiEnv* current_env() {
    return state.env.load(std::memory_order_acquire);
}

jvmtiError ignore(const char* operation) {
    HIMITSU_LOG_WARNING("JvmtiGuard", "已拦截外部 JVMTI 操作：%s", operation);
    return JVMTI_ERROR_NONE;
}

jvmtiError JNICALL guarded_add_capabilities(jvmtiEnv* env, const jvmtiCapabilities*) {
    return env == current_env() ? ignore("AddCapabilities") : JVMTI_ERROR_NOT_AVAILABLE;
}

jvmtiError JNICALL guarded_set_event_callbacks(jvmtiEnv* env, const jvmtiEventCallbacks*, jint) {
    return env == current_env() ? ignore("SetEventCallbacks") : JVMTI_ERROR_NOT_AVAILABLE;
}

jvmtiError JNICALL guarded_set_event_notification_mode(
    jvmtiEnv* env, jvmtiEventMode, jvmtiEvent, jthread, ...) {
    return env == current_env() ? ignore("SetEventNotificationMode") : JVMTI_ERROR_NOT_AVAILABLE;
}

jvmtiError JNICALL guarded_set_extension_event_callback(jvmtiEnv*, jint, jvmtiExtensionEvent) {
    return JVMTI_ERROR_NOT_AVAILABLE;
}

jvmtiError JNICALL guarded_retransform_classes(jvmtiEnv* env, jint, const jclass*) {
    return env == current_env() ? ignore("RetransformClasses") : JVMTI_ERROR_NOT_AVAILABLE;
}

jvmtiError JNICALL guarded_redefine_classes(jvmtiEnv* env, jint, const jvmtiClassDefinition*) {
    return env == current_env() ? ignore("RedefineClasses") : JVMTI_ERROR_NOT_AVAILABLE;
}

jvmtiError JNICALL guarded_dispose_environment(jvmtiEnv* env) {
    return env == current_env() ? ignore("DisposeEnvironment") : JVMTI_ERROR_NOT_AVAILABLE;
}

jvmtiError JNICALL guarded_relinquish_capabilities(jvmtiEnv* env, const jvmtiCapabilities*) {
    return env == current_env() ? ignore("RelinquishCapabilities") : JVMTI_ERROR_NOT_AVAILABLE;
}

struct SlotPatch {
    void** slot;
    void* replacement;
    void* original;
    const char* name;
};

bool exchange_slot(SlotPatch& patch, void* value) {
    DWORD old_protection = 0;
    if (!VirtualProtect(patch.slot, sizeof(void*), PAGE_READWRITE, &old_protection)) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "为 %s 调用 VirtualProtect 失败（错误码=%lu）", patch.name, GetLastError());
        return false;
    }
    InterlockedExchangePointer(reinterpret_cast<void* volatile*>(patch.slot), value);
    MemoryBarrier();
    DWORD ignored = 0;
    return VirtualProtect(patch.slot, sizeof(void*), old_protection, &ignored) != FALSE;
}

template <typename Function>
void* function_address(Function function) {
    static_assert(sizeof(Function) == sizeof(void*));
    return reinterpret_cast<void*>(function);
}

bool patch_return_none(void* function) {
    if (function == nullptr) return false;
    constexpr unsigned char patch[] = {0x31, 0xC0, 0xC3};
    DWORD old_protection = 0;
    if (!VirtualProtect(function, sizeof(patch), PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    std::memcpy(function, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), function, sizeof(patch));
    DWORD ignored = 0;
    return VirtualProtect(function, sizeof(patch), old_protection, &ignored) != FALSE;
}

void bind_recovered_dispatch(jvmtiEnv* env) {
    if (env == nullptr || env->functions == nullptr) return;

    state.table = const_cast<jvmtiInterface_1_*>(env->functions);
    HIMITSU_LOG_INFO(
        "JvmtiGuard",
        "已绑定恢复后的 JVMTI 分发表（env=%p，表=%p，原始回调=%p，原始事件=%p，原始重转换=%p）",
        env,
        state.table,
        function_address(state.set_event_callbacks),
        function_address(state.set_event_notification_mode),
        function_address(state.retransform_classes)
    );
}

bool restore_public_guard_slots() {
    if (!state.installed.load(std::memory_order_acquire)) return true;
    if (state.table == nullptr) return false;
    std::array<SlotPatch, 8> patches{
        SlotPatch{reinterpret_cast<void**>(&state.table->AddCapabilities), function_address(guarded_add_capabilities), function_address(state.add_capabilities), "AddCapabilities"},
        SlotPatch{reinterpret_cast<void**>(&state.table->SetEventCallbacks), function_address(guarded_set_event_callbacks), function_address(state.set_event_callbacks), "SetEventCallbacks"},
        SlotPatch{reinterpret_cast<void**>(&state.table->SetExtensionEventCallback), function_address(guarded_set_extension_event_callback), function_address(state.private_table.SetExtensionEventCallback), "SetExtensionEventCallback"},
        SlotPatch{reinterpret_cast<void**>(&state.table->SetEventNotificationMode), function_address(guarded_set_event_notification_mode), function_address(state.set_event_notification_mode), "SetEventNotificationMode"},
        SlotPatch{reinterpret_cast<void**>(&state.table->RetransformClasses), function_address(guarded_retransform_classes), function_address(state.retransform_classes), "RetransformClasses"},
        SlotPatch{reinterpret_cast<void**>(&state.table->RedefineClasses), function_address(guarded_redefine_classes), function_address(state.redefine_classes), "RedefineClasses"},
        SlotPatch{reinterpret_cast<void**>(&state.table->DisposeEnvironment), function_address(guarded_dispose_environment), function_address(state.dispose_environment), "DisposeEnvironment"},
        SlotPatch{reinterpret_cast<void**>(&state.table->RelinquishCapabilities), function_address(guarded_relinquish_capabilities), function_address(state.relinquish_capabilities), "RelinquishCapabilities"}
    };
    bool success = true;
    for (SlotPatch& patch : patches) success = exchange_slot(patch, patch.replacement) && success;
    const bool dispose_frozen = patch_return_none(function_address(state.dispose_environment));
    HIMITSU_LOG_INFO(
        "JvmtiGuard",
        "恢复后的公开 JVMTI 守护槽重装结束（表槽=%s，DisposeEnvironment冻结=%s）",
        success ? "正常" : "失败",
        dispose_frozen ? "正常" : "失败"
    );
    return success && dispose_frozen;
}

bool capabilities_contained(const jvmtiCapabilities& current, const jvmtiCapabilities& required) {

    return (!required.can_tag_objects || current.can_tag_objects)
        && (!required.can_redefine_classes || current.can_redefine_classes)
        && (!required.can_retransform_classes || current.can_retransform_classes)
        && (!required.can_generate_all_class_hook_events || current.can_generate_all_class_hook_events);
}

void log_capability_state(
    const char* prefix,
    const jvmtiCapabilities& current,
    const jvmtiCapabilities& required,
    jvmtiError query_error,
    jvmtiError repair_error
) {
    HIMITSU_LOG_WARNING(
        "JvmtiGuard",
        "%s（查询=%d，修复=%d，标签=%u/%u，重定义=%u/%u，重转换=%u/%u，类钩子=%u/%u）",
        prefix,
        query_error,
        repair_error,
        current.can_tag_objects,
        required.can_tag_objects,
        current.can_redefine_classes,
        required.can_redefine_classes,
        current.can_retransform_classes,
        required.can_retransform_classes,
        current.can_generate_all_class_hook_events,
        required.can_generate_all_class_hook_events
    );
}

bool restore_environment(jvmtiEnv* fresh) {
    if (fresh == nullptr || state.add_capabilities == nullptr) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "恢复 JVMTI 环境的参数无效（env=%p，AddCapabilities=%p）",
            fresh, function_address(state.add_capabilities));
        return false;
    }
    jvmtiCapabilities required;
    jvmtiEventCallbacks callbacks;
    jint callback_size;
    std::array<jvmtiEventMode, EVENT_SLOTS> modes;
    AcquireSRWLockShared(&state.lock);
    required = state.required_capabilities;
    callbacks = state.required_callbacks;
    callback_size = state.required_callbacks_size;
    modes = state.event_modes;
    ReleaseSRWLockShared(&state.lock);

    const jvmtiError capability_error = state.add_capabilities(fresh, &required);
    HIMITSU_LOG_DEBUG("JvmtiGuard", "恢复能力调用结束（env=%p，jvmti=%d）", fresh, capability_error);
    if (capability_error != JVMTI_ERROR_NONE) return false;
    if (callback_size > 0) {
        const jvmtiError callback_error = state.set_event_callbacks(fresh, &callbacks, callback_size);
        HIMITSU_LOG_DEBUG("JvmtiGuard", "恢复回调表调用结束（env=%p，大小=%d，jvmti=%d）",
            fresh, callback_size, callback_error);
        if (callback_error != JVMTI_ERROR_NONE) return false;
    }
    unsigned int enabled_events = 0;
    for (jint event = 0; event < EVENT_SLOTS; ++event) {
        if (modes[static_cast<std::size_t>(event)] == JVMTI_ENABLE) {
            const jvmtiError event_error = state.set_event_notification_mode(
                fresh, JVMTI_ENABLE, static_cast<jvmtiEvent>(event), nullptr);
            if (event_error != JVMTI_ERROR_NONE) {
                HIMITSU_LOG_ERROR("JvmtiGuard", "恢复事件通知失败（事件=%d，jvmti=%d）", event, event_error);
                return false;
            }
            ++enabled_events;
        }
    }
    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 环境内容恢复完成（env=%p，回调大小=%d，启用事件数=%u）",
        fresh, callback_size, enabled_events);
    return true;
}

bool refresh_impl() {
    HIMITSU_LOG_INFO("JvmtiGuard", "开始刷新 JVMTI 环境（旧环境=%p，代数=%llu）",
        current_env(), state.generation.load(std::memory_order_acquire));
    if (JavaVM* recovered_vm = himitsu::jvm::late_recover_created_vm(); recovered_vm != nullptr) {
        state.vm = recovered_vm;
        state.vm_get_env = recovered_vm->functions == nullptr ? nullptr : recovered_vm->functions->GetEnv;
        state.vm_attach = recovered_vm->functions == nullptr ? nullptr : recovered_vm->functions->AttachCurrentThread;
        HIMITSU_LOG_INFO("JvmtiGuard", "刷新前 JavaVM 调用链恢复完成（vm=%p，GetEnv=%p）",
            state.vm, function_address(state.vm_get_env));
    }
    if (state.vm == nullptr || state.vm_get_env == nullptr) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "刷新 JVMTI 的前置项缺失（vm=%p，getEnv=%p）", state.vm, function_address(state.vm_get_env));
        return false;
    }
    JNIEnv* jni = nullptr;
    jint result = state.vm_get_env(state.vm, reinterpret_cast<void**>(&jni), JNI_VERSION_1_8);
    if (result == JNI_EDETACHED && state.vm_attach != nullptr) {
        result = state.vm_attach(state.vm, reinterpret_cast<void**>(&jni), nullptr);
        HIMITSU_LOG_INFO("JvmtiGuard", "刷新线程附加 JVM 结束（jni=%d，env=%p）", result, jni);
    }
    if (result != JNI_OK || jni == nullptr) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "刷新过程中获取 JNIEnv 失败（jni=%d，env=%p）", result, jni);
        return false;
    }

    jvmtiEnv* fresh = nullptr;
    result = state.vm_get_env(state.vm, reinterpret_cast<void**>(&fresh), JVMTI_VERSION_1_2);
    if (result != JNI_OK || fresh == nullptr) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "刷新过程中 GetEnv(JVMTI) 调用失败（jni=%d，env=%p）", result, fresh);
        return false;
    }

    if (!himitsu::jvm::late_recover_jvmti_dispatch(fresh)) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "新 JVMTI 环境的分发表与函数体恢复失败（env=%p）", fresh);
        return false;
    }
    bind_recovered_dispatch(fresh);

    jvmtiPhase phase{};
    if (state.get_phase == nullptr || state.get_phase(fresh, &phase) != JVMTI_ERROR_NONE) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "刷新过程的阶段校验失败（env=%p）", fresh);
        return false;
    }
    if (!restore_environment(fresh)) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "刷新过程的能力或回调恢复失败（env=%p）", fresh);
        return false;
    }
    if (!restore_public_guard_slots()) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "刷新后的公开 JVMTI 守护槽重装失败（env=%p）", fresh);
        return false;
    }

    jvmtiCapabilities required{};
    AcquireSRWLockShared(&state.lock);
    required = state.required_capabilities;
    ReleaseSRWLockShared(&state.lock);
    jvmtiCapabilities verified{};
    const jvmtiError capability_error = state.get_capabilities == nullptr
        ? JVMTI_ERROR_NOT_AVAILABLE
        : state.get_capabilities(fresh, &verified);
    if (capability_error != JVMTI_ERROR_NONE || !capabilities_contained(verified, required)) {
        log_capability_state("刷新后的能力校验失败", verified, required, capability_error, JVMTI_ERROR_NONE);
        return false;
    }

    state.env.store(fresh, std::memory_order_release);
    jvmtiEnv** head_slot = state.environment_head_slot.load(std::memory_order_acquire);
    const bool linked = head_slot == nullptr || environment_chain_contains(head_slot, fresh);
    state.environment_linked.store(linked, std::memory_order_release);
    state.healthy.store(linked, std::memory_order_release);
    state.generation.fetch_add(1, std::memory_order_acq_rel);
    himitsu::core::RuntimeState::instance().replace_jvmti(fresh);
    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 环境刷新完成（env=%p，阶段=%d，链内=%s）",
        fresh, phase, linked ? "是" : "否");
    return linked;
}

DWORD WINAPI monitor_worker(void*) {
    JNIEnv* jni = nullptr;
    if (state.vm != nullptr && state.vm_get_env != nullptr) {
        jint status = state.vm_get_env(state.vm, reinterpret_cast<void**>(&jni), JNI_VERSION_1_8);
        if (status == JNI_EDETACHED && state.vm_attach != nullptr) {
            state.vm_attach(state.vm, reinterpret_cast<void**>(&jni), nullptr);
        }
    }
    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 健康监控线程已启动（线程ID=%lu，jni=%p，周期=250ms）",
        GetCurrentThreadId(), jni);

    unsigned int summary_tick = 0;
    unsigned int chain_tick = 3;
    while (!state.monitor_stop.load(std::memory_order_acquire)) {
        const bool chain_was_detached = !state.environment_linked.load(std::memory_order_acquire);
        if (chain_was_detached || ++chain_tick >= 4) {
            chain_tick = 0;
            jvmtiEnv** head_slot = state.environment_head_slot.load(std::memory_order_acquire);
            if (head_slot == nullptr) {
                head_slot = locate_environment_head_slot(current_env());
                if (head_slot != nullptr) {
                    state.environment_head_slot.store(head_slot, std::memory_order_release);
                }
            }
            if (head_slot != nullptr) {
                const bool linked = environment_chain_contains(head_slot, current_env());
                state.environment_linked.store(linked, std::memory_order_release);
                if (!linked) {
                    if (!refresh_impl()) {
                        const unsigned int failures = state.chain_recovery_failures.fetch_add(
                            1, std::memory_order_acq_rel) + 1;
                        HIMITSU_LOG_ERROR(
                            "JvmtiGuard",
                            "Secret JVMTI environment recreation failed（次数=%u，旧环境=%p，链首=%p）",
                            failures,
                            current_env(),
                            *head_slot
                        );
                    }
                }
            }
        }

        jvmtiEnv* env = current_env();
        const bool linked = state.environment_linked.load(std::memory_order_acquire);
        bool healthy = linked && valid_environment_node(env) && state.get_phase != nullptr;
        const char* health_reason = !linked
            ? "环境已脱离 HotSpot 链"
            : (healthy ? "正常" : "环境或分发表缺失");
        bool refresh_allowed = !healthy && linked;
        jvmtiPhase phase{};
        if (healthy && state.get_phase(env, &phase) != JVMTI_ERROR_NONE) {
            healthy = false;
            health_reason = "阶段检查失败";
            refresh_allowed = true;
        }

        jvmtiCapabilities caps{};
        if (healthy && state.get_capabilities != nullptr) {
            jvmtiCapabilities required{};
            AcquireSRWLockShared(&state.lock);
            required = state.required_capabilities;
            ReleaseSRWLockShared(&state.lock);
            jvmtiError capability_error = state.get_capabilities(env, &caps);
            if (capability_error != JVMTI_ERROR_NONE) {
                healthy = false;
                health_reason = "能力查询失败";
                refresh_allowed = true;
            } else if (!capabilities_contained(caps, required)) {

                jvmtiError repair_error = JVMTI_ERROR_NOT_AVAILABLE;
                if (state.add_capabilities != nullptr) {
                    repair_error = state.add_capabilities(env, &required);
                    jvmtiCapabilities repaired{};
                    capability_error = state.get_capabilities(env, &repaired);
                    if (repair_error == JVMTI_ERROR_NONE
                        && capability_error == JVMTI_ERROR_NONE
                        && capabilities_contained(repaired, required)) {
                        caps = repaired;
                        HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 能力已在当前环境内恢复（env=%p）", env);
                    } else {
                        caps = repaired;
                        healthy = false;
                        health_reason = "能力不匹配";
                        refresh_allowed = true;
                        log_capability_state("JVMTI 能力原地恢复失败，立即刷新环境", caps, required,
                            capability_error, repair_error);
                    }
                } else {
                    healthy = false;
                    health_reason = "能力不匹配";
                    refresh_allowed = true;
                }
            }
        }

        if (!healthy) {
            const bool was_healthy = state.healthy.exchange(false, std::memory_order_acq_rel);
            if (was_healthy) {
                HIMITSU_LOG_WARNING(
                    "JvmtiGuard",
                    "JVMTI 健康检查失败（原因=%s，env=%p，立即刷新=%s）",
                    health_reason,
                    env,
                    refresh_allowed ? "是" : "否"
                );
            }
            if (refresh_allowed) {
                if (refresh_impl()) {
                    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 健康恢复成功");
                } else {
                    HIMITSU_LOG_WARNING("JvmtiGuard", "JVMTI 健康恢复尝试失败");
                }
            }
        } else {
            const bool was_healthy = state.healthy.exchange(true, std::memory_order_acq_rel);
            if (!was_healthy) {
                HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 健康状态已经恢复（env=%p，阶段=%d）", env, phase);
            }
        }
        if (++summary_tick >= 40) {
            summary_tick = 0;
            HIMITSU_LOG_DEBUG(
                "JvmtiGuard",
                "JVMTI 健康摘要（健康=%s，env=%p，阶段=%d，代数=%llu）",
                healthy ? "是" : "否",
                current_env(),
                phase,
                state.generation.load(std::memory_order_acquire)
            );
        }
        Sleep(250);
    }
    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 健康监控线程已退出（线程ID=%lu）", GetCurrentThreadId());
    return 0;
}
}

namespace himitsu::jvm {
bool initialize_jvmti_guard(JavaVM* vm, jvmtiEnv* env) {
    static_assert(sizeof(void*) == 8);
    static_assert(std::is_standard_layout_v<jvmtiInterface_1_>);
    HIMITSU_LOG_INFO("JvmtiGuard", "正在初始化 JVMTI 守护（vm=%p，env=%p，表=%p）", vm, env, env == nullptr ? nullptr : env->functions);
    if (vm == nullptr || env == nullptr || env->functions == nullptr) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "JVMTI 守护初始化参数无效");
        return false;
    }
    if (current_env() != nullptr) {
        const bool same = current_env() == env;
        HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 守护已初始化（同一环境=%s）", same ? "是" : "否");
        return same;
    }

    state.vm = vm;
    state.vm_get_env = vm->functions == nullptr ? nullptr : vm->functions->GetEnv;
    state.vm_attach = vm->functions == nullptr ? nullptr : vm->functions->AttachCurrentThread;
    state.env.store(env, std::memory_order_release);
    state.table = const_cast<jvmtiInterface_1_*>(env->functions);
    state.private_table = *env->functions;
    state.add_capabilities = state.private_table.AddCapabilities;
    state.set_event_callbacks = state.private_table.SetEventCallbacks;
    state.set_event_notification_mode = state.private_table.SetEventNotificationMode;
    state.retransform_classes = state.private_table.RetransformClasses;
    state.redefine_classes = state.private_table.RedefineClasses;
    state.dispose_environment = state.private_table.DisposeEnvironment;
    state.relinquish_capabilities = state.private_table.RelinquishCapabilities;
    state.set_native_method_prefix = state.private_table.SetNativeMethodPrefix;
    state.set_native_method_prefixes = state.private_table.SetNativeMethodPrefixes;
    state.generate_events = state.private_table.GenerateEvents;
    state.get_phase = state.private_table.GetPhase;
    state.get_capabilities = state.private_table.GetCapabilities;

    HIMITSU_LOG_INFO(
        "JvmtiGuard",
        "已捕获 JVMTI 分发表（表=%p，AddCapabilities=%p，SetCallbacks=%p，SetEventMode=%p，Retransform=%p，Redefine=%p，Dispose=%p）",
        state.table,
        function_address(state.add_capabilities),
        function_address(state.set_event_callbacks),
        function_address(state.set_event_notification_mode),
        function_address(state.retransform_classes),
        function_address(state.redefine_classes),
        function_address(state.dispose_environment)
    );

    jvmtiEnv** head_slot = locate_environment_head_slot(env);
    state.environment_head_slot.store(head_slot, std::memory_order_release);
    const bool linked = head_slot == nullptr || environment_chain_contains(head_slot, env);
    state.environment_linked.store(linked, std::memory_order_release);
    if (head_slot == nullptr) {
        HIMITSU_LOG_WARNING("JvmtiGuard", "HotSpot JVMTI 环境链暂未定位，监控线程将继续动态查找");
    }

    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 私有分发表副本已捕获（env=%p，公开表=%p，私有表=%p）", env, state.table, &state.private_table);
    return state.add_capabilities != nullptr
        && state.set_event_callbacks != nullptr
        && state.set_event_notification_mode != nullptr
        && state.retransform_classes != nullptr
        && state.redefine_classes != nullptr
        && state.dispose_environment != nullptr
        && state.relinquish_capabilities != nullptr
        && state.get_phase != nullptr
        && state.get_capabilities != nullptr;
}

bool install_jvmti_guard() {
    HIMITSU_LOG_INFO("JvmtiGuard", "正在安装运行时 JVMTI 守护");
    if (state.installed.load(std::memory_order_acquire)) {
        HIMITSU_LOG_INFO("JvmtiGuard", "运行时 JVMTI 守护已安装");
        return true;
    }
    if (state.table == nullptr) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "JVMTI 分发表缺失，守护安装失败");
        return false;
    }

    std::array<SlotPatch, 8> patches{
        SlotPatch{reinterpret_cast<void**>(&state.table->AddCapabilities), function_address(guarded_add_capabilities), function_address(state.add_capabilities), "AddCapabilities"},
        SlotPatch{reinterpret_cast<void**>(&state.table->SetEventCallbacks), function_address(guarded_set_event_callbacks), function_address(state.set_event_callbacks), "SetEventCallbacks"},
        SlotPatch{reinterpret_cast<void**>(&state.table->SetExtensionEventCallback), function_address(guarded_set_extension_event_callback), function_address(state.private_table.SetExtensionEventCallback), "SetExtensionEventCallback"},
        SlotPatch{reinterpret_cast<void**>(&state.table->SetEventNotificationMode), function_address(guarded_set_event_notification_mode), function_address(state.set_event_notification_mode), "SetEventNotificationMode"},
        SlotPatch{reinterpret_cast<void**>(&state.table->RetransformClasses), function_address(guarded_retransform_classes), function_address(state.retransform_classes), "RetransformClasses"},
        SlotPatch{reinterpret_cast<void**>(&state.table->RedefineClasses), function_address(guarded_redefine_classes), function_address(state.redefine_classes), "RedefineClasses"},
        SlotPatch{reinterpret_cast<void**>(&state.table->DisposeEnvironment), function_address(guarded_dispose_environment), function_address(state.dispose_environment), "DisposeEnvironment"},
        SlotPatch{reinterpret_cast<void**>(&state.table->RelinquishCapabilities), function_address(guarded_relinquish_capabilities), function_address(state.relinquish_capabilities), "RelinquishCapabilities"}
    };

    std::size_t installed = 0;
    for (; installed < patches.size(); ++installed) {
        if (!exchange_slot(patches[installed], patches[installed].replacement)) break;
        HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 公开表槽已替换：%s", patches[installed].name);
    }
    if (installed != patches.size()) {
        while (installed > 0) {
            --installed;
            exchange_slot(patches[installed], patches[installed].original);
        }
        return false;
    }

    if (!patch_return_none(function_address(state.dispose_environment))) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "DisposeEnvironment 实现替换失败（目标=%p）", function_address(state.dispose_environment));
        return false;
    }
    HIMITSU_LOG_WARNING("JvmtiGuard", "DisposeEnvironment 实现已冻结（目标=%p）", function_address(state.dispose_environment));

    state.installed.store(true, std::memory_order_release);
    HIMITSU_LOG_INFO("JvmtiGuard", "运行时 JVMTI 守护安装结束");
    return true;
}

bool jvmti_isolation_enabled() { return state.installed.load(std::memory_order_acquire); }

bool quarantine_external_jvmti(JNIEnv* env) {
    if (env == nullptr || !jvmti_isolation_enabled()) return false;
    jvmtiEnv* own = current_env();
    auto** head_slot = state.environment_head_slot.load(std::memory_order_acquire);
    if (head_slot == nullptr) head_slot = locate_environment_head_slot(own);
    if (head_slot == nullptr) return false;
    const auto inspection = inspect_environment_chain(*head_slot, own);
    if (!inspection.valid || !inspection.contains_preferred) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "Unsupported or unstable HotSpot environment chain; isolation refused");
        return false;
    }
    std::vector<jvmtiEnv*> nodes;
    for (jvmtiEnv* node=*head_slot; node!=nullptr; node=environment_next(node)) {
        if (!valid_environment_node(node) || nodes.size()>=MAX_JVMTI_ENVIRONMENTS) return false;
        nodes.push_back(node);
    }
    // Shared public setters are already guarded. Use the captured clean dispatch
    // to disable existing registrations; no foreign tables/callback code are called.
    jint thread_count=0; jthread* threads=nullptr;
    if (state.private_table.GetAllThreads(own,&thread_count,&threads)!=JVMTI_ERROR_NONE) return false;
    bool success=true; unsigned isolated=0;
    const jvmtiEvent events[] = {
        JVMTI_EVENT_VM_INIT, JVMTI_EVENT_VM_DEATH, JVMTI_EVENT_THREAD_START, JVMTI_EVENT_THREAD_END,
        JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, JVMTI_EVENT_CLASS_LOAD, JVMTI_EVENT_CLASS_PREPARE,
        JVMTI_EVENT_VM_START, JVMTI_EVENT_EXCEPTION, JVMTI_EVENT_EXCEPTION_CATCH,
        JVMTI_EVENT_SINGLE_STEP, JVMTI_EVENT_FRAME_POP, JVMTI_EVENT_BREAKPOINT,
        JVMTI_EVENT_FIELD_ACCESS, JVMTI_EVENT_FIELD_MODIFICATION, JVMTI_EVENT_METHOD_ENTRY,
        JVMTI_EVENT_METHOD_EXIT, JVMTI_EVENT_NATIVE_METHOD_BIND, JVMTI_EVENT_COMPILED_METHOD_LOAD,
        JVMTI_EVENT_COMPILED_METHOD_UNLOAD, JVMTI_EVENT_DYNAMIC_CODE_GENERATED,
        JVMTI_EVENT_DATA_DUMP_REQUEST, JVMTI_EVENT_MONITOR_WAIT, JVMTI_EVENT_MONITOR_WAITED,
        JVMTI_EVENT_MONITOR_CONTENDED_ENTER, JVMTI_EVENT_MONITOR_CONTENDED_ENTERED,
        JVMTI_EVENT_RESOURCE_EXHAUSTED, JVMTI_EVENT_GARBAGE_COLLECTION_START,
        JVMTI_EVENT_GARBAGE_COLLECTION_FINISH, JVMTI_EVENT_OBJECT_FREE,
        JVMTI_EVENT_VM_OBJECT_ALLOC, JVMTI_EVENT_SAMPLED_OBJECT_ALLOC
    };
    for (jvmtiEnv* node:nodes) {
        if (node==own) continue;
        jvmtiPhase phase{};
        if (!valid_environment_node(node) || state.private_table.GetPhase(node,&phase)!=JVMTI_ERROR_NONE) {
            success=false;break;
        }
        jvmtiEventCallbacks empty{};
        bool ok=state.private_table.SetEventCallbacks(node,&empty,sizeof(empty))==JVMTI_ERROR_NONE;
        for (jvmtiEvent event:events) {
            jvmtiError error=state.private_table.SetEventNotificationMode(node,JVMTI_DISABLE,event,nullptr);
            ok=(error==JVMTI_ERROR_NONE)&&ok;
            for (jint i=0;i<thread_count;++i) {
                error=state.private_table.SetEventNotificationMode(node,JVMTI_DISABLE,event,threads[i]);
                // Global-only events reject a thread argument; terminated threads need no cleanup.
                ok=(error==JVMTI_ERROR_NONE||error==JVMTI_ERROR_ILLEGAL_ARGUMENT
                    ||error==JVMTI_ERROR_THREAD_NOT_ALIVE)&&ok;
            }
        }
        jint count=0;jvmtiExtensionEventInfo* extensions=nullptr;
        jvmtiError error=state.private_table.GetExtensionEvents(node,&count,&extensions);
        ok=(error==JVMTI_ERROR_NONE)&&ok;
        if(error==JVMTI_ERROR_NONE) {
            for(jint i=0;i<count;++i) {
                ok=(state.private_table.SetExtensionEventCallback(node,extensions[i].extension_event_index,nullptr)==JVMTI_ERROR_NONE)&&ok;
                for(jint p=0;p<extensions[i].param_count;++p)
                    state.private_table.Deallocate(node,reinterpret_cast<unsigned char*>(extensions[i].params[p].name));
                state.private_table.Deallocate(node,reinterpret_cast<unsigned char*>(extensions[i].params));
                state.private_table.Deallocate(node,reinterpret_cast<unsigned char*>(extensions[i].id));
                state.private_table.Deallocate(node,reinterpret_cast<unsigned char*>(extensions[i].short_description));
            }
            state.private_table.Deallocate(node,reinterpret_cast<unsigned char*>(extensions));
        }
        HIMITSU_LOG_INFO("JvmtiGuard", "External environment=%p isolation=%s",node,ok?"true":"false");
        success=ok&&success; ++isolated;
    }
    for(jint i=0;i<thread_count;++i)env->DeleteLocalRef(threads[i]);
    state.private_table.Deallocate(own,reinterpret_cast<unsigned char*>(threads));
    std::size_t index=0;
    for(jvmtiEnv* node=*head_slot;node!=nullptr;node=environment_next(node)) {
        if(index>=nodes.size()||node!=nodes[index++]||!valid_environment_node(node)){success=false;break;}
    }
    success=success&&index==nodes.size();
    if(success)state.environment_head_slot.store(head_slot,std::memory_order_release);
    HIMITSU_LOG_INFO("JvmtiGuard", "External callbacks disabled=%u verified=%s",isolated,success?"true":"false");
    return success;
}

bool start_jvmti_guard_monitor() {
    if (state.monitor_thread != nullptr) {
        HIMITSU_LOG_DEBUG("JvmtiGuard", "JVMTI 健康监控已经在运行（线程=%p）", state.monitor_thread);
        return true;
    }
    state.monitor_stop.store(false, std::memory_order_release);
    state.monitor_thread = CreateThread(nullptr, 0, monitor_worker, nullptr, 0, nullptr);
    if (state.monitor_thread == nullptr) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "创建 JVMTI 健康监控线程失败（错误码=%lu）", GetLastError());
        return false;
    }
    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 健康监控线程创建完成（句柄=%p）", state.monitor_thread);
    return true;
}

bool refresh_trusted_jvmti() {
    return refresh_impl();
}

bool trusted_jvmti_healthy() {
    return state.healthy.load(std::memory_order_acquire);
}

void shutdown_jvmti_guard() {
    HIMITSU_LOG_INFO("JvmtiGuard", "开始关闭 JVMTI 守护（env=%p，监控线程=%p）", current_env(), state.monitor_thread);
    state.monitor_stop.store(true, std::memory_order_release);
    if (state.monitor_thread != nullptr) {
        WaitForSingleObject(state.monitor_thread, 5000);
        CloseHandle(state.monitor_thread);
        state.monitor_thread = nullptr;
    }
    jvmtiEnv* env = current_env();
    if (env == nullptr) return;
    if (state.set_event_notification_mode != nullptr) {
        state.set_event_notification_mode(env, JVMTI_DISABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);
    }
    if (state.set_event_callbacks != nullptr) {
        jvmtiEventCallbacks callbacks{};
        state.set_event_callbacks(env, &callbacks, sizeof(callbacks));
    }
    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 守护关闭结束");
}

JavaVM* trusted_vm() { return state.vm; }

jvmtiEnv* trusted_jvmti() {
    return current_env();
}

jvmtiError trusted_add_capabilities(const jvmtiCapabilities* capabilities) {
    if (state.add_capabilities == nullptr || current_env() == nullptr || capabilities == nullptr) return JVMTI_ERROR_NOT_AVAILABLE;
    jvmtiError error = state.add_capabilities(current_env(), capabilities);
    HIMITSU_LOG_DEBUG("JvmtiGuard", "可信 AddCapabilities 调用结束（env=%p，jvmti=%d）", current_env(), error);
    if (error == JVMTI_ERROR_NONE) {
        AcquireSRWLockExclusive(&state.lock);
        const auto* source = reinterpret_cast<const unsigned char*>(capabilities);
        auto* target = reinterpret_cast<unsigned char*>(&state.required_capabilities);
        for (std::size_t i = 0; i < sizeof(jvmtiCapabilities); ++i) target[i] |= source[i];
        ReleaseSRWLockExclusive(&state.lock);
    }
    return error;
}

jvmtiError trusted_set_event_callbacks(const jvmtiEventCallbacks* callbacks, jint size) {
    if (state.set_event_callbacks == nullptr || current_env() == nullptr) return JVMTI_ERROR_NOT_AVAILABLE;
    jvmtiError error = state.set_event_callbacks(current_env(), callbacks, size);
    HIMITSU_LOG_DEBUG("JvmtiGuard", "可信 SetEventCallbacks 调用结束（env=%p，回调=%p，大小=%d，jvmti=%d）",
        current_env(), callbacks, size, error);
    if (error == JVMTI_ERROR_NONE) {
        AcquireSRWLockExclusive(&state.lock);
        std::memset(&state.required_callbacks, 0, sizeof(state.required_callbacks));
        if (callbacks != nullptr && size > 0) std::memcpy(&state.required_callbacks, callbacks, std::min<std::size_t>(sizeof(state.required_callbacks), static_cast<std::size_t>(size)));
        state.required_callbacks_size = std::max<jint>(0, std::min<jint>(size, static_cast<jint>(sizeof(state.required_callbacks))));
        ReleaseSRWLockExclusive(&state.lock);
    }
    return error;
}

jvmtiError trusted_set_event_notification_mode(jvmtiEventMode mode, jvmtiEvent event_type, jthread event_thread) {
    if (state.set_event_notification_mode == nullptr || current_env() == nullptr) return JVMTI_ERROR_NOT_AVAILABLE;
    jvmtiError error = state.set_event_notification_mode(current_env(), mode, event_type, event_thread);
    HIMITSU_LOG_DEBUG("JvmtiGuard", "可信事件通知调用结束（模式=%d，事件=%d，线程=%p，jvmti=%d）",
        mode, event_type, event_thread, error);
    if (error == JVMTI_ERROR_NONE && event_thread == nullptr && event_type >= 0 && event_type < EVENT_SLOTS) {
        AcquireSRWLockExclusive(&state.lock);
        state.event_modes[static_cast<std::size_t>(event_type)] = mode;
        ReleaseSRWLockExclusive(&state.lock);
    }
    return error;
}

jvmtiError trusted_retransform_classes(jint class_count, const jclass* classes) {
    if (state.retransform_classes == nullptr || current_env() == nullptr) return JVMTI_ERROR_NOT_AVAILABLE;
    if (class_count == 1 && classes != nullptr) {
        RetransformFlagScope flags(classes[0]);
        return state.retransform_classes(current_env(), class_count, classes);
    }
    return state.retransform_classes(current_env(), class_count, classes);
}

jvmtiError trusted_redefine_classes(jint class_count, const jvmtiClassDefinition* definitions) {
    return state.redefine_classes == nullptr || current_env() == nullptr
        ? JVMTI_ERROR_NOT_AVAILABLE
        : state.redefine_classes(current_env(), class_count, definitions);
}
}
