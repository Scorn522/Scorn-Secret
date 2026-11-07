#include <vector>
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/jvm/source_images.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"
#include "MinHook.h"

#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/late_recovery.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/platform/windows/module_guard.hpp"

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
using VmAttachFn = decltype(JNIInvokeInterface_::AttachCurrentThreadAsDaemon);
using VmDetachFn = decltype(JNIInvokeInterface_::DetachCurrentThread);

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
    VmAttachFn vm_attach_daemon = nullptr;
    VmDetachFn vm_detach = nullptr;

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
    std::atomic<bool> refreshing{false};
    std::atomic<ULONGLONG> next_refresh{0};
    jvmtiEnv* pending_env = nullptr; // Only the nonblocking refresh owner may change this.
};

GuardState state;

void cache_vm_calls(JavaVM* vm) {
    const auto* table=vm?vm->functions:nullptr;
    AcquireSRWLockExclusive(&state.lock);
    state.vm=vm;
    state.vm_get_env=table?table->GetEnv:nullptr;
    state.vm_attach_daemon=table?table->AttachCurrentThreadAsDaemon:nullptr;
    state.vm_detach=table?table->DetachCurrentThread:nullptr;
    ReleaseSRWLockExclusive(&state.lock);
}
struct VmAccess {
    JavaVM* vm=nullptr; VmGetEnvFn get_env=nullptr; VmDetachFn detach=nullptr;
    JNIEnv* env=nullptr; bool attached=false; jint result=JNI_ERR;
    VmAccess() {
        VmAttachFn attach=nullptr;
        AcquireSRWLockShared(&state.lock);
        vm=state.vm;get_env=state.vm_get_env;attach=state.vm_attach_daemon;detach=state.vm_detach;
        ReleaseSRWLockShared(&state.lock);
        if(!vm || !get_env) return;
        result=get_env(vm,reinterpret_cast<void**>(&env),JNI_VERSION_1_8);
        if(result==JNI_EDETACHED && attach && detach) {
            result=attach(vm,reinterpret_cast<void**>(&env),nullptr);attached=result==JNI_OK;
        }
    }
    ~VmAccess() {if(attached) detach(vm);}
};


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

// Membership is a prefix query. A foreign tail must not invalidate our live node.
// Unknown (an unreadable/truncated chain) is distinct from a proven absence.
enum class EnvironmentLink { unknown, linked, absent };
EnvironmentLink environment_link(jvmtiEnv** head_slot, jvmtiEnv* target) {
    if (!head_slot || !readable_memory(head_slot, sizeof(void*)) || !target)
        return EnvironmentLink::unknown;
    jvmtiEnv* node = *head_slot;
    for (std::size_t count = 0; node && count < MAX_JVMTI_ENVIRONMENTS; ++count) {
        if (!valid_environment_node(node)) return EnvironmentLink::unknown;
        if (node == target) return EnvironmentLink::linked;
        jvmtiEnv* next = environment_next(node);
        if (next == node) return EnvironmentLink::unknown;
        node = next;
    }
    return node ? EnvironmentLink::unknown : EnvironmentLink::absent;
}
bool environment_chain_contains(jvmtiEnv** head_slot, jvmtiEnv* target) {
    return environment_link(head_slot, target) == EnvironmentLink::linked;
}
EnvironmentLink resolve_environment_link(jvmtiEnv* target) {
    auto* slot = state.environment_head_slot.load(std::memory_order_acquire);
    EnvironmentLink link = environment_link(slot, target);
    if (link == EnvironmentLink::linked) return link;
    // Recheck the cached location before rebuilding an environment. Discovery is
    // used only on a transition/recovery attempt, never on the ordinary tick path.
    auto* relocated = locate_environment_head_slot(target);
    if (relocated && environment_chain_contains(relocated, target)) {
        state.environment_head_slot.store(relocated, std::memory_order_release);
        return EnvironmentLink::linked;
    }
    return environment_link(slot, target);
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

void* dispose_hook_target=nullptr;
std::uint64_t dispose_hook_token=0;
jvmtiError JNICALL frozen_dispose(jvmtiEnv*) {return JVMTI_ERROR_NONE;}
bool install_dispose_hook(void* function) {
    if(!function || (dispose_hook_target && dispose_hook_target!=function))return false;
    auto initialized=MH_Initialize();if(initialized!=MH_OK && initialized!=MH_ERROR_ALREADY_INITIALIZED)return false;
    if(!dispose_hook_target) {
        void* original=nullptr;
        if(MH_CreateHook(function,reinterpret_cast<void*>(frozen_dispose),&original)!=MH_OK || !original)return false;
        dispose_hook_target=function;
    }
    if(!himitsu::platform::windows::guarded_hook_intact(function))return false;
    MH_STATUS enabled;
    {himitsu::platform::windows::ThreadHookMaintenance scope;enabled=MH_EnableHook(function);}
    if(enabled!=MH_OK && enabled!=MH_ERROR_ENABLED)return false;
    dispose_hook_token=himitsu::platform::windows::register_guarded_hook("Owned JVMTI DisposeEnvironment",function);
    return dispose_hook_token!=0;
}
bool stop_dispose_hook(std::uint64_t deadline) {
    if(!dispose_hook_target)return true;
    if(GetTickCount64()>deadline || !himitsu::platform::windows::guarded_hook_intact(dispose_hook_target)
        || !himitsu::platform::windows::unregister_guarded_region(dispose_hook_token,deadline))return false;
    himitsu::platform::windows::ThreadHookMaintenance scope;auto status=MH_DisableHook(dispose_hook_target);
    return status==MH_OK || status==MH_ERROR_DISABLED; // Keep MinHook's trampoline alive.
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
    const bool dispose_frozen = install_dispose_hook(function_address(state.dispose_environment));
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
    const auto now = GetTickCount64();
    if (state.monitor_stop.load(std::memory_order_acquire) || !himitsu::platform::windows::native_interfaces_healthy()
        || now < state.next_refresh.load(std::memory_order_acquire)) return false;
    bool expected = false;
    if (!state.refreshing.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return false;
    // This is a non-waiting admission flag, not a lock across JNI/Safepoints.
    // Failed candidates stay private and are reused instead of leaking one GetEnv per poll.
    bool table_update = false;
    jvmtiEnv* previous = current_env();
    auto* previous_table = state.table;
    const bool success = [&] {
        if (state.monitor_stop.load(std::memory_order_acquire)) return false;
        HIMITSU_LOG_INFO("JvmtiGuard", "开始刷新 JVMTI 环境（旧环境=%p，代数=%llu）",
            previous, state.generation.load(std::memory_order_acquire));
        if (!state.pending_env) {
            JavaVM* vm=himitsu::jvm::late_recover_created_vm();if(!vm)return false;
            cache_vm_calls(vm);
        }
        VmAccess access;
        if (access.result != JNI_OK || !access.env || !access.get_env) return false;
        if (!state.pending_env) {
            jvmtiEnv* fresh = nullptr;
            const jint result = access.get_env(access.vm, reinterpret_cast<void**>(&fresh), JVMTI_VERSION_1_2);
            if (result != JNI_OK || !fresh) return false;
            state.pending_env = fresh;
        }
        jvmtiEnv* fresh = state.pending_env;
        if (resolve_environment_link(fresh) != EnvironmentLink::linked) return false;
        table_update = true;
        if(!himitsu::platform::windows::suspend_jvmti_table_restore(true))return false;
        if (!himitsu::jvm::late_recover_jvmti_dispatch(fresh)) return false;
        bind_recovered_dispatch(fresh);
        jvmtiPhase phase{};
        if (!state.get_phase || state.get_phase(fresh, &phase) != JVMTI_ERROR_NONE
            || phase == JVMTI_PHASE_DEAD || !restore_environment(fresh)) return false;
        jvmtiCapabilities required{}, verified{};
        AcquireSRWLockShared(&state.lock);
        required = state.required_capabilities;
        ReleaseSRWLockShared(&state.lock);
        if (!state.get_capabilities || state.get_capabilities(fresh, &verified) != JVMTI_ERROR_NONE
            || !capabilities_contained(verified, required) || !restore_public_guard_slots()
            || resolve_environment_link(fresh) != EnvironmentLink::linked
            || state.monitor_stop.load(std::memory_order_acquire)) return false;
        state.env.store(fresh, std::memory_order_release);
        state.pending_env = nullptr;
        state.environment_linked.store(true, std::memory_order_release);
        state.healthy.store(true, std::memory_order_release);
        state.generation.fetch_add(1, std::memory_order_acq_rel);
        himitsu::core::RuntimeState::instance().replace_jvmti(fresh);
        // Only retire our own old callbacks; foreign environments are untouched.
        if (previous && previous != fresh && valid_environment_node(previous)) {
            jvmtiEventCallbacks empty{};
            state.set_event_callbacks(previous, &empty, sizeof(empty));
        }
        HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 环境刷新完成（env=%p，阶段=%d，链内=是）", fresh, phase);
        return true;
    }();
    if (table_update) {
        if (!success) {
            if (state.pending_env && valid_environment_node(state.pending_env) && state.set_event_callbacks) {
                jvmtiEventCallbacks empty{};
                state.set_event_callbacks(state.pending_env, &empty, sizeof(empty));
            }
            restore_public_guard_slots();
            state.table = previous_table;
        }
        himitsu::platform::windows::suspend_jvmti_table_restore(false);
    }
    if (success) {
        state.chain_recovery_failures.store(0, std::memory_order_release);
        state.next_refresh.store(0, std::memory_order_release);
    } else {
        const unsigned int failures = state.chain_recovery_failures.fetch_add(1, std::memory_order_acq_rel) + 1;
        const ULONGLONG delay = std::min<ULONGLONG>(30000, 1000ULL << std::min(failures - 1, 5u));
        state.next_refresh.store(GetTickCount64() + delay, std::memory_order_release);
        HIMITSU_LOG_WARNING("JvmtiGuard", "JVMTI recovery deferred; previous environment retained (failures=%u retry_ms=%llu candidate=%p)",
            failures, delay, state.pending_env);
    }
    state.refreshing.store(false, std::memory_order_release);
    return success;
}

DWORD WINAPI monitor_worker(void*) {
    VmAccess access;
    JNIEnv* jni=access.env;
    if(access.result!=JNI_OK || !jni) {
        HIMITSU_LOG_ERROR("JvmtiGuard","Monitor daemon attachment failed: %d",access.result);
        return 1;
    }
    HIMITSU_LOG_INFO("JvmtiGuard", "JVMTI 健康监控线程已启动（线程ID=%lu，jni=%p，周期=250ms）",
        GetCurrentThreadId(), jni);

    unsigned int summary_tick = 0;
    unsigned int chain_tick = 3;
    bool link_reported = false;
    EnvironmentLink link = EnvironmentLink::unknown;
    ULONGLONG next_discovery = 0;
    while (!state.monitor_stop.load(std::memory_order_acquire)) {
        const auto now = GetTickCount64();
        jvmtiEnv* env = current_env();
        if (++chain_tick >= 4) {
            chain_tick = 0;
            link = environment_link(state.environment_head_slot.load(std::memory_order_acquire), env);
            if (link != EnvironmentLink::linked && now >= next_discovery) {
                link = resolve_environment_link(env);
                next_discovery = now + 30000;
            }
            state.environment_linked.store(link == EnvironmentLink::linked, std::memory_order_release);
        }
        bool healthy = link == EnvironmentLink::linked && valid_environment_node(env) && state.get_phase;
        bool recover = link == EnvironmentLink::absent || (link == EnvironmentLink::linked && !healthy);
        jvmtiPhase phase{};
        if (healthy) {
            healthy = state.get_phase(env, &phase) == JVMTI_ERROR_NONE;
            if (healthy && phase == JVMTI_PHASE_DEAD) break;
            recover = !healthy;
        }
        if (healthy && state.get_capabilities) {
            jvmtiCapabilities required{}, caps{};
            AcquireSRWLockShared(&state.lock);
            required = state.required_capabilities;
            ReleaseSRWLockShared(&state.lock);
            const auto error = state.get_capabilities(env, &caps);
            healthy = error == JVMTI_ERROR_NONE && capabilities_contained(caps, required);
            if (!healthy && now >= state.next_refresh.load(std::memory_order_acquire)) {
                // Repair our existing environment before allocating a replacement.
                healthy = error == JVMTI_ERROR_NONE && state.add_capabilities
                    && state.add_capabilities(env, &required) == JVMTI_ERROR_NONE
                    && state.get_capabilities(env, &caps) == JVMTI_ERROR_NONE
                    && capabilities_contained(caps, required);
            }
            recover = !healthy;
        }
        if(healthy)himitsu::jvm::maintain_event_bridge(jni);
        state.healthy.store(healthy, std::memory_order_release);
        if (!healthy && !link_reported) {
            HIMITSU_LOG_WARNING("JvmtiGuard", "JVMTI health unavailable (env=%p link=%d); unknown chains never trigger recreation", env, static_cast<int>(link));
            link_reported = true;
        } else if (healthy) link_reported = false;
        if (recover && now >= state.next_refresh.load(std::memory_order_acquire) && refresh_impl()) {
            link = EnvironmentLink::linked;
            healthy = true;
            link_reported = false;
        }
        if (++summary_tick >= 40) {
            summary_tick = 0;
            HIMITSU_LOG_DEBUG("JvmtiGuard", "JVMTI 健康摘要（健康=%s，env=%p，阶段=%d，代数=%llu）",
                healthy ? "是" : "否", current_env(), phase, state.generation.load(std::memory_order_acquire));
        }
        Sleep(250);
    }

    return 0;
}
}

namespace himitsu::jvm {
bool expected_jvmti_dispatch(jvmtiInterface_1_*& address,jvmtiInterface_1_& expected) {
    AcquireSRWLockShared(&state.lock);address=state.table;expected=state.private_table;
    bool ready=address && state.installed.load(std::memory_order_acquire);
    ReleaseSRWLockShared(&state.lock);
    if(!ready)return false;
    expected.AddCapabilities=guarded_add_capabilities;expected.SetEventCallbacks=guarded_set_event_callbacks;
    expected.SetExtensionEventCallback=guarded_set_extension_event_callback;expected.SetEventNotificationMode=guarded_set_event_notification_mode;
    expected.RetransformClasses=guarded_retransform_classes;expected.RedefineClasses=guarded_redefine_classes;
    expected.DisposeEnvironment=guarded_dispose_environment;expected.RelinquishCapabilities=guarded_relinquish_capabilities;
    return true;
}

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

    cache_vm_calls(vm);
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

    if (!install_dispose_hook(function_address(state.dispose_environment))) {
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
    state.monitor_thread = CreateThread(nullptr, 0, monitor_worker, nullptr, CREATE_SUSPENDED, nullptr);
    if (state.monitor_thread == nullptr) {
        HIMITSU_LOG_ERROR("JvmtiGuard", "创建 JVMTI 健康监控线程失败（错误码=%lu）", GetLastError());
        return false;
    }
    if(!himitsu::platform::windows::register_native_thread(state.monitor_thread)
        || ResumeThread(state.monitor_thread)==static_cast<DWORD>(-1)) {
        state.monitor_stop.store(true,std::memory_order_release);
        ResumeThread(state.monitor_thread);
        if(WaitForSingleObject(state.monitor_thread,5000)==WAIT_OBJECT_0) {
            himitsu::platform::windows::unregister_native_thread(state.monitor_thread);
            CloseHandle(state.monitor_thread);state.monitor_thread=nullptr;
        }
        HIMITSU_LOG_ERROR("JvmtiGuard","Monitor OS protection/launch failed");return false;
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

void request_jvmti_guard_stop() {state.monitor_stop.store(true,std::memory_order_release);}
bool shutdown_jvmti_guard(std::uint64_t deadline) {
    request_jvmti_guard_stop();
    if(state.monitor_thread) {
        auto now=GetTickCount64();
        if(WaitForSingleObject(state.monitor_thread,static_cast<DWORD>(now<deadline?deadline-now:0))!=WAIT_OBJECT_0) {
            HIMITSU_LOG_ERROR("JvmtiGuard","Monitor did not exit; handle and JVM state retained");return false;
        }
        himitsu::platform::windows::unregister_native_thread(state.monitor_thread);
        CloseHandle(state.monitor_thread);state.monitor_thread=nullptr;
    }
    bool success=stop_dispose_hook(deadline);
    jvmtiEnv* env=current_env();if(!env)return success;
    if(state.set_event_notification_mode) success=(state.set_event_notification_mode(env,JVMTI_DISABLE,JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,nullptr)==JVMTI_ERROR_NONE)&&success;
    if(state.set_event_callbacks) {jvmtiEventCallbacks callbacks{};success=state.set_event_callbacks(env,&callbacks,sizeof(callbacks))==JVMTI_ERROR_NONE && success;}
    return success;
}
jvmtiError trusted_current_thread(jthread* thread) {
    jvmtiEnv* env=current_env();
    auto function=state.private_table.GetCurrentThread;
    return env && function && thread?function(env,thread):JVMTI_ERROR_NOT_AVAILABLE;
}
JavaVM* trusted_vm() {
    AcquireSRWLockShared(&state.lock);JavaVM* vm=state.vm;ReleaseSRWLockShared(&state.lock);return vm;
}

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
