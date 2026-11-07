#include "himitsu/platform/windows/module_guard.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/platform/windows/swap_buffers_hook.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/core/native_log.hpp"
#include "MinHook.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <psapi.h>

namespace {
using himitsu::jvm::NativeCodeRange;
using himitsu::jvm::native_memory_read;
using himitsu::jvm::native_pointer_exchange;
struct GuardedRegion {
    std::uint64_t token=0;
    std::string name;
    void** slots=nullptr;void* allocation=nullptr;
    std::vector<void*> pointers;
    std::vector<NativeCodeRange> code;
    void* hook=nullptr;
    MH_HOOK_SNAPSHOT snapshot{};
    std::atomic<bool> retired{false};
    std::atomic<unsigned> readers{0};
    std::atomic<int> last_result{-1};
    std::atomic<bool> critical{false};
};
using Registry=std::vector<std::shared_ptr<GuardedRegion>>;
SRWLOCK registry_lock=SRWLOCK_INIT;
std::shared_ptr<const Registry> registry=std::make_shared<const Registry>();
std::atomic<std::uint64_t> next_token{1};
std::atomic<bool> stop_requested{false},running{false},jvmti_suspended{false},interfaces_healthy{true};
HANDLE guard_thread=nullptr,guard_wake=nullptr;
std::shared_ptr<const Registry> snapshot() {
    AcquireSRWLockShared(&registry_lock);auto result=registry;ReleaseSRWLockShared(&registry_lock);return result;
}
void wake_guard(){if(guard_wake)SetEvent(guard_wake);}
bool publish(const std::shared_ptr<const Registry>& before,std::shared_ptr<const Registry> after) {
    AcquireSRWLockExclusive(&registry_lock);
    bool ok=registry==before && !stop_requested.load(std::memory_order_acquire);
    if(ok)registry=std::move(after);
    ReleaseSRWLockExclusive(&registry_lock);return ok; // before keeps retired resources alive until outside the lock.
}
std::uint64_t register_region(std::shared_ptr<GuardedRegion> entry) {
    if(stop_requested.load(std::memory_order_acquire))return 0;
    entry->token=next_token.fetch_add(1,std::memory_order_relaxed);
    for(unsigned retry=0;retry<8;++retry) {
        auto before=snapshot();
        for(const auto& old:*before)if(!old->retired.load() &&
            ((entry->hook && old->hook==entry->hook) || (entry->slots && old->slots==entry->slots)
                || (!entry->hook && !entry->code.empty() && !old->hook && !old->code.empty() && entry->code.front().address==old->code.front().address))) {
            // A duplicate cannot replace a trusted baseline with a newly observed value.
            bool same=entry->pointers==old->pointers && entry->code.size()==old->code.size();
            for(std::size_t i=0;same && i<entry->code.size();++i)same=entry->code[i].address==old->code[i].address && entry->code[i].expected==old->code[i].expected;
            if(same && entry->critical.load())old->critical.store(true,std::memory_order_release);
            return same?old->token:0;
        }
        auto after=std::make_shared<Registry>(*before);after->push_back(entry);
        if(publish(before,after)){wake_guard();return entry->token;}
    }
    return 0;
}
bool memory_matches(const void* address,const unsigned char* expected,std::size_t size,void* allocation=nullptr) {
    std::array<unsigned char,512> bytes{};
    for(std::size_t offset=0;offset<size;) {
        auto count=(std::min)(size-offset,bytes.size());auto* cursor=static_cast<const unsigned char*>(address)+offset;
        MEMORY_BASIC_INFORMATION page{};
        if(VirtualQuery(cursor,&page,sizeof(page))!=sizeof(page) || (allocation && page.AllocationBase!=allocation)
            || !native_memory_read(cursor,bytes.data(),count) || std::memcmp(bytes.data(),expected+offset,count))return false;
        offset+=count;
    }
    return true;
}
bool hook_matches(const GuardedRegion& entry) {
    MH_HOOK_SNAPSHOT current{};
    if(MH_GetHookSnapshot(entry.hook,&current)!=MH_OK || current.trampoline!=entry.snapshot.trampoline
        || current.patch!=entry.snapshot.patch || current.patchSize!=entry.snapshot.patchSize
        || current.trampolineSize!=entry.snapshot.trampolineSize)return false;
    return memory_matches(current.patch,current.enabled?entry.snapshot.installed:entry.snapshot.original,current.patchSize)
        && memory_matches(current.trampoline,entry.snapshot.relocated,current.trampolineSize,entry.allocation);
}
bool overlay_owned(const Registry& owners,void* address,unsigned char* expected,std::size_t size) {
        auto begin=reinterpret_cast<std::uintptr_t>(address),end=begin+size;
        for(const auto& owner:owners)if(owner->hook && !owner->retired.load(std::memory_order_acquire)) {
            const auto& hook=owner->snapshot;auto start=reinterpret_cast<std::uintptr_t>(hook.patch),finish=start+hook.patchSize;
            if(start>=end || finish<=begin)continue;
            MH_HOOK_SNAPSHOT live{};
            if(MH_GetHookSnapshot(owner->hook,&live)!=MH_OK || !live.enabled)continue;
            for(auto pos=(std::max)(begin,start);pos<(std::min)(end,finish);++pos) {
                auto byte=pos-start;
                // An earlier foreign hook is not silently accepted as a clean disk baseline.
                if(expected[pos-begin]!=hook.original[byte]) {
                    return false;
                }
                expected[pos-begin]=hook.installed[byte];
            }
        }
    return true;
}
bool code_matches(const GuardedRegion& entry,const Registry& owners) {
    std::array<unsigned char,512> actual{},expected{};
    for(const auto& range:entry.code)for(std::size_t offset=0;offset<range.expected.size();) {
        auto count=(std::min)(actual.size(),range.expected.size()-offset);auto* cursor=range.address+offset;
        MEMORY_BASIC_INFORMATION page{};
        if(VirtualQuery(cursor,&page,sizeof(page))!=sizeof(page) || page.AllocationBase!=range.module.get()
            || !(page.Protect&(PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))
            || !native_memory_read(cursor,actual.data(),count))return false;
        std::memcpy(expected.data(),range.expected.data()+offset,count);
        if(!overlay_owned(owners,cursor,expected.data(),count))return false;
        if(std::memcmp(actual.data(),expected.data(),count)) {
            if(entry.last_result.load()!=1)for(std::size_t i=0;i<count;++i)if(actual[i]!=expected[i]) {
                HIMITSU_LOG_WARNING("ModuleGuard","Code differs: %s address=%p offset=%zu current=%02X expected=%02X",entry.name.c_str(),range.address,offset+i,actual[i],expected[i]);break;
            }
            return false;
        }
        offset+=count;
    }
    return true;
}
void check_region(const std::shared_ptr<GuardedRegion>& entry,const Registry& owners) {
    entry->readers.fetch_add(1,std::memory_order_acq_rel);
    if(entry->retired.load(std::memory_order_acquire) || stop_requested.load(std::memory_order_acquire)
        || (entry->name=="JVMTI_vtable" && jvmti_suspended.load(std::memory_order_acquire))) {
        entry->readers.fetch_sub(1,std::memory_order_release);return;
    }
    bool ok=true,changed=false;
    if(entry->slots)for(std::size_t i=0;i<entry->pointers.size();++i) {
        void* value=nullptr;
        if(!native_memory_read(entry->slots+i,&value,sizeof(value))){ok=false;break;}
        if(value==entry->pointers[i])continue;
        changed=true;
        if(entry->retired.load(std::memory_order_acquire) || stop_requested.load(std::memory_order_acquire)
            || (entry->name=="JVMTI_vtable" && jvmti_suspended.load(std::memory_order_acquire))
            || !native_pointer_exchange(entry->slots+i,value,entry->pointers[i],entry->allocation)){ok=false;break;}
    } else ok=entry->hook?hook_matches(*entry):code_matches(*entry,owners);
    int state=ok?0:1,previous=entry->last_result.exchange(state,std::memory_order_acq_rel);
    entry->readers.fetch_sub(1,std::memory_order_release);
    if(previous!=state && (!ok || previous==1))HIMITSU_LOG_WARNING("ModuleGuard","%s: %s (token=%llu)",entry->name.c_str(),ok?"verified":"NOT_RECOVERED active-code-or-mapping",entry->token);
    else if(changed && ok && previous!=0)HIMITSU_LOG_INFO("ModuleGuard","Pointer slots recovered: %s",entry->name.c_str());
}
struct ExportSnapshot {
    const char* module;const char* name;
    ULONGLONG next_attempt=0;unsigned attempts=0;
    std::uint64_t token=0;bool reported=false;
    HMODULE attempted_module=nullptr;DWORD attempted_stamp=0;
};
std::array<ExportSnapshot,17> exports{{
    {"gdi32.dll","StretchBlt"},{"gdi32.dll","BitBlt"},{"gdi32.dll","SetPixel"},{"gdi32.dll","SwapBuffers"},
    {"user32.dll","EnableWindow"},{"user32.dll","FillRect"},{"user32.dll","SetWindowLongPtrA"},{"user32.dll","SetWindowLongPtrW"},
    {"user32.dll","CreateWindowExA"},{"user32.dll","CreateWindowExW"},{"msimg32.dll","AlphaBlend"},
    {"opengl32.dll","wglGetCurrentContext"},{"opengl32.dll","glGetIntegerv"},{"opengl32.dll","glDrawBuffer"},
    {"opengl32.dll","glFlush"},{"jvm.dll","JNI_GetCreatedJavaVMs"},{"glfw.dll","glfwCreateWindow"}
}};
std::atomic<HMODULE> initial_glfw{nullptr};
std::atomic<bool> module_changed{false};
void discover_exports() {
    auto now=GetTickCount64();
    if(module_changed.exchange(false,std::memory_order_acq_rel))for(auto& item:exports)if(!item.token)item.next_attempt=0;
    for(auto& item:exports)if(!item.token && now>=item.next_attempt) {
        HMODULE module=GetModuleHandleA(item.module);
        if(!module && !std::strcmp(item.module,"glfw.dll"))module=initial_glfw.load(std::memory_order_acquire);
        DWORD stamp=0;IMAGE_DOS_HEADER dos{};IMAGE_NT_HEADERS64 nt{};
        if(module && native_memory_read(module,&dos,sizeof(dos)) && dos.e_magic==IMAGE_DOS_SIGNATURE && dos.e_lfanew>0 && dos.e_lfanew<0x100000
            && native_memory_read(reinterpret_cast<unsigned char*>(module)+dos.e_lfanew,&nt,sizeof(nt)))stamp=nt.FileHeader.TimeDateStamp;
        if(module && item.attempted_module==module && item.attempted_stamp==stamp){item.next_attempt=now+30000;continue;}
        item.attempted_module=module;item.attempted_stamp=stamp;
        std::vector<NativeCodeRange> ranges;bool unsupported=false;
        if(module && himitsu::jvm::native_export_baseline(module,item.name,ranges,&unsupported))
            item.token=himitsu::platform::windows::register_guarded_code(item.name,std::move(ranges));
        // Cache only a proven unsupported function shape. Unreadable/mismatched mappings or missing forwarded modules retry with backoff.
        if(!item.token && !unsupported)item.attempted_module=nullptr;
        if(!item.token && !item.reported) {
            HIMITSU_LOG_WARNING("ModuleGuard","Export %s: %s!%s; no code write",module?"UNVERIFIED_RANGE_OR_IMAGE":"WAITING_FOR_MODULE",item.module,item.name);item.reported=true;
        }
        auto delay=(std::min)(30000ULL,250ULL<<((std::min)(item.attempts++,7u)));
        item.next_attempt=now+delay;
    }
}
DWORD WINAPI guard_worker(void*) {
    HIMITSU_LOG_INFO("ModuleGuard","Native fixed-list guard started: interval=250ms; active code is check-only");
    while(!stop_requested.load(std::memory_order_acquire)) {
        discover_exports();auto current=snapshot();
        bool healthy=true;
        for(const auto& item:*current) {
            check_region(item,*current);
            if(!item->retired.load() && item->critical.load() && item->last_result.load()==1)healthy=false;
        }
        interfaces_healthy.store(healthy,std::memory_order_release);
        himitsu::platform::windows::maintain_swap_buffers_hook();
        WaitForSingleObject(guard_wake,250);
    }
    running.store(false,std::memory_order_release);return 0;
}
std::uint64_t register_table(const char* name,void** slots,const std::vector<void*>& values) {
    MEMORY_BASIC_INFORMATION page{};
    if(values.empty() || VirtualQuery(slots,&page,sizeof(page))!=sizeof(page))return 0;
    auto entry=std::make_shared<GuardedRegion>();entry->name=name;entry->slots=slots;entry->allocation=page.AllocationBase;entry->pointers=values;
    return register_region(std::move(entry));
}
}
namespace himitsu::platform::windows {
std::uint64_t register_guarded_code(const char* name,std::vector<NativeCodeRange> ranges) {
    if(!name || ranges.empty())return 0;
    std::uint64_t first=0;
    for(auto& range:ranges) {
        auto entry=std::make_shared<GuardedRegion>();entry->name=name;
        entry->critical=std::strcmp(name,"JVM required interface")==0;
        entry->code.push_back(std::move(range));auto token=register_region(std::move(entry));
        if(!token)return 0;if(!first)first=token;
    }
    return first; // Shared tail ranges are registered once, even when multiple functions reach them.
}
std::uint64_t register_guarded_pointer(const char* name,void** slot,void* expected) {return register_table(name,slot,{expected});}
std::uint64_t register_guarded_hook(const char* name,void* target) {
    if(!name || !target)return 0;MH_HOOK_SNAPSHOT info{};
    if(MH_GetHookSnapshot(target,&info)!=MH_OK || !info.patchSize || info.patchSize>8 || !info.trampolineSize || info.trampolineSize>64)return 0;
    MEMORY_BASIC_INFORMATION page{};if(VirtualQuery(info.trampoline,&page,sizeof(page))!=sizeof(page))return 0;
    auto entry=std::make_shared<GuardedRegion>();entry->name=name;entry->hook=target;entry->snapshot=info;entry->allocation=page.AllocationBase;
    if(!hook_matches(*entry))return 0;
    auto token=register_region(std::move(entry));if(!token)return 0;
    std::vector<NativeCodeRange> callback;
    if(himitsu::jvm::native_function_baseline(info.replacement,callback)) {
        if(!register_guarded_code(name,std::move(callback)))return 0;
    } else HIMITSU_LOG_WARNING("ModuleGuard","Callback body range unverified: %s; patch/trampoline remain verified",name);
    return token;
}
bool apply_owned_code(void* address,unsigned char* expected,std::size_t size) {
    auto current=snapshot();return overlay_owned(*current,address,expected,size);
}
bool guarded_hook_intact(void* target) {
    auto current=snapshot();for(const auto& item:*current)if(item->hook==target && !item->retired.load())return hook_matches(*item);
    // Before first publication, use immutable creation metadata, never a live recapture.
    MH_HOOK_SNAPSHOT info{};if(MH_GetHookSnapshot(target,&info)!=MH_OK)return false;
    return memory_matches(info.patch,info.enabled?info.installed:info.original,info.patchSize)
        && memory_matches(info.trampoline,info.relocated,info.trampolineSize);
}
bool unregister_guarded_region(std::uint64_t token,std::uint64_t deadline) {
    if(!token)return true;auto current=snapshot();std::shared_ptr<GuardedRegion> found;
    for(const auto& item:*current)if(item->token==token){found=item;break;}
    if(!found)return true;found->retired.store(true,std::memory_order_release);
    while(found->readers.load(std::memory_order_acquire)) {
        if(!deadline || GetTickCount64()>=deadline)return false;Sleep(1);
    }
    for(unsigned retry=0;retry<8;++retry) {
        auto before=snapshot();auto after=std::make_shared<Registry>();after->reserve(before->size());
        for(const auto& item:*before)if(item!=found)after->push_back(item);
        // Retiring is allowed during shutdown; references are released outside the lock.
        AcquireSRWLockExclusive(&registry_lock);bool ok=registry==before;
        if(ok)registry=after;ReleaseSRWLockExclusive(&registry_lock);if(ok)return true;
    }
    return false;
}
void observe_guarded_module(HMODULE module) {
    if(initial_glfw.load(std::memory_order_acquire)==module)return;
    if(!stop_requested.load() && module && GetProcAddress(module,"glfwCreateWindow")) {
        initial_glfw.store(module,std::memory_order_release);module_changed.store(true,std::memory_order_release);wake_guard();
    }
}
bool native_interfaces_healthy(){return interfaces_healthy.load(std::memory_order_acquire);}
bool suspend_jvmti_table_restore(bool suspended) {
    if(suspended) {
        jvmti_suspended.store(true,std::memory_order_release);
        auto current=snapshot();auto deadline=GetTickCount64()+250;
        for(const auto& item:*current)if(item->name=="JVMTI_vtable")while(item->readers.load(std::memory_order_acquire)) {
            if(GetTickCount64()>=deadline)return false;Sleep(1);
        }
        return true;
    }
    jvmtiInterface_1_* address=nullptr;jvmtiInterface_1_ expected{};
    if(himitsu::jvm::expected_jvmti_dispatch(address,expected)) {
        std::vector<void*> values(sizeof(expected)/sizeof(void*));std::memcpy(values.data(),&expected,sizeof(expected));
        auto current=snapshot();for(const auto& item:*current)if(item->name=="JVMTI_vtable" && item->slots!=reinterpret_cast<void**>(address))
            unregister_guarded_region(item->token,GetTickCount64()+250);
        register_table("JVMTI_vtable",reinterpret_cast<void**>(address),values);
    }
    jvmti_suspended.store(false,std::memory_order_release);wake_guard();return true;
}
void request_module_guard_stop() {stop_requested.store(true,std::memory_order_release);wake_guard();}
bool start_module_guard(JavaVM* vm,jvmtiEnv* jvmti) {
    bool expected=false;if(!running.compare_exchange_strong(expected,true))return true;
    stop_requested.store(false,std::memory_order_release);
    if(!vm || !jvmti){running=false;return false;}
    std::vector<void*> vm_values,ti_values(sizeof(jvmtiInterface_1_)/sizeof(void*));
    jvmtiInterface_1_* ti_address=nullptr;jvmtiInterface_1_ expected_ti{};
    bool trusted_ti=himitsu::jvm::expected_jvmti_dispatch(ti_address,expected_ti);
    if(trusted_ti)std::memcpy(ti_values.data(),&expected_ti,sizeof(expected_ti));
    else {ti_address=const_cast<jvmtiInterface_1_*>(jvmti->functions);trusted_ti=himitsu::jvm::native_table_baseline(ti_address,ti_values.size(),ti_values);}
    if(!himitsu::jvm::native_table_baseline(vm->functions,8,vm_values) || !trusted_ti
        || !register_table("JavaVM_vtable",reinterpret_cast<void**>(const_cast<JNIInvokeInterface_*>(vm->functions)),vm_values)
        || !register_table("JVMTI_vtable",reinterpret_cast<void**>(ti_address),ti_values)){running=false;return false;}
    // One bounded cold-start discovery; missing entries later use names and backoff only.
    HMODULE modules[512]{};DWORD needed=0;
    if(EnumProcessModules(GetCurrentProcess(),modules,sizeof(modules),&needed))for(DWORD i=0;i<(std::min)(needed/sizeof(HMODULE),std::size_t{512});++i) {
        if(GetProcAddress(modules[i],"glfwCreateWindow")){initial_glfw=modules[i];break;}
    }
    guard_wake=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    if(!guard_wake){running=false;return false;}
    guard_thread=CreateThread(nullptr,0,guard_worker,nullptr,CREATE_SUSPENDED,nullptr);
    if(!guard_thread){CloseHandle(guard_wake);guard_wake=nullptr;running=false;return false;}
    if(!register_native_thread(guard_thread) || ResumeThread(guard_thread)==static_cast<DWORD>(-1)) {
        request_module_guard_stop();ResumeThread(guard_thread);
        if(WaitForSingleObject(guard_thread,5000)==WAIT_OBJECT_0){unregister_native_thread(guard_thread);CloseHandle(guard_thread);guard_thread=nullptr;}
        return false;
    }
    return true;
}
bool stop_module_guard(std::uint64_t deadline) {
    request_module_guard_stop();HANDLE thread=guard_thread;
    if(thread) {
        auto now=GetTickCount64();DWORD result=WaitForSingleObject(thread,static_cast<DWORD>(now<deadline?deadline-now:0));
        if(result!=WAIT_OBJECT_0){HIMITSU_LOG_ERROR("ModuleGuard","Guard not drained; references retained");return false;}
        unregister_native_thread(thread);CloseHandle(thread);guard_thread=nullptr;
    }
    // Late registered callbacks can still signal this event; retain its handle until process exit.
    running=false;return true;
}
}
