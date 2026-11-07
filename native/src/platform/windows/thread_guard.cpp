#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/platform/windows/module_guard.hpp"
#include "himitsu/platform/windows/instrumentation_guard.hpp"
#include "himitsu/core/native_log.hpp"
#include "himitsu/core/runtime_state.hpp"
#include <jni.h>
#include <MinHook.h>
#include <algorithm>
#include <atomic>
#include <vector>
#include <string>
#include <cstring>
#include <shellapi.h>
#include <bcrypt.h>
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/jvm/source_images.hpp"
#include "himitsu/jvm/jvmti_guard.hpp"
#include "himitsu/jvm/late_recovery.hpp"
#ifdef _MSC_VER
#include <intrin.h>
#define THREAD_CALLER _ReturnAddress()
#else
#define THREAD_CALLER __builtin_return_address(0)
#endif
namespace {
using State=himitsu::core::RuntimeState;
using StopThreadFn=void (JNICALL*)(JNIEnv*,jobject,jobject);
using SuspendJavaFn=void (JNICALL*)(JNIEnv*,jobject);
using GetAllThreadsFn=jobjectArray (JNICALL*)(JNIEnv*,jclass);
using SuspendOsFn=DWORD (WINAPI*)(HANDLE);
using TerminateOsFn=BOOL (WINAPI*)(HANDLE,DWORD);
using CompareFn=BOOL (WINAPI*)(HANDLE,HANDLE);
struct Hook {
    const wchar_t* library; const char* name;
    void* target=nullptr;
    std::atomic<void*> trampoline{nullptr};
    bool created=false;
    std::uint64_t guard_token=0;
    std::vector<himitsu::jvm::NativeCodeRange> forwarding;
};
Hook stop_hook{L"jvm.dll","JVM_StopThread"}, suspend_hook{L"jvm.dll","JVM_SuspendThread"}, all_threads_hook{L"jvm.dll","JVM_GetAllThreads"};
Hook base_suspend{L"kernelbase.dll","SuspendThread"}, base_terminate{L"kernelbase.dll","TerminateThread"};
Hook kernel_suspend{L"kernel32.dll","SuspendThread"}, kernel_terminate{L"kernel32.dll","TerminateThread"};
Hook nt_suspend{L"ntdll.dll","NtSuspendThread"},nt_terminate{L"ntdll.dll","NtTerminateThread"};
Hook attach_hook{L"jvm.dll","JVM_EnqueueOperation"};
Hook before_halt{L"java.dll","Java_java_lang_Shutdown_beforeHalt"},halt_hook{L"java.dll","Java_java_lang_Shutdown_halt0"};
Hook base_process_end{L"kernelbase.dll","TerminateProcess"},kernel_process_end{L"kernel32.dll","TerminateProcess"},nt_process_end{L"ntdll.dll","NtTerminateProcess"};
Hook java_process{L"java.dll","Java_java_lang_ProcessImpl_create"};
Hook base_create_w{L"kernelbase.dll","CreateProcessW"},base_create_a{L"kernelbase.dll","CreateProcessA"};
Hook kernel_create_w{L"kernel32.dll","CreateProcessW"},kernel_create_a{L"kernel32.dll","CreateProcessA"};
Hook shell_w{L"shell32.dll","ShellExecuteW"},shell_a{L"shell32.dll","ShellExecuteA"},shell_ex_w{L"shell32.dll","ShellExecuteExW"},shell_ex_a{L"shell32.dll","ShellExecuteExA"};
Hook* hooks[]{&nt_suspend,&nt_terminate,&attach_hook,&before_halt,&halt_hook,&base_process_end,&kernel_process_end,&nt_process_end,
    &java_process,&base_create_w,&base_create_a,&kernel_create_w,&kernel_create_a,&shell_w,&shell_a,&shell_ex_w,&shell_ex_a,&stop_hook,&suspend_hook,&all_threads_hook,&base_suspend,&base_terminate,&kernel_suspend,&kernel_terminate};
std::atomic<bool> installed{false}, admitting{false};
CompareFn compare_handles=nullptr;
std::uintptr_t jvm_begin=0,jvm_end=0;
SRWLOCK hook_lock=SRWLOCK_INIT;

std::atomic<bool> host_policy_ready{false};
std::atomic<unsigned long long> next_denial_log{0};
std::vector<himitsu::jvm::NativeCodeRange> rtl_exit_ranges,rtl_thread_exit_ranges;
struct ProcessRule { std::wstring kind,source,source_hash,program,program_hash,arguments,directory,verb,target,child_arguments; };
std::shared_ptr<const std::vector<ProcessRule>> process_rules;
struct ProcessPermit { std::wstring program,arguments,directory; unsigned depth=0; bool java=false,used=false; };
// Attach remote stubs have no compiler TLS vector. Win32 TLS remains valid on such threads.
struct ThreadContext {
    unsigned maintenance=0,forward=0;
    bool shutdown=false,fatal=false;
    std::uint64_t generation=0;
    int owner=-1;
    ProcessPermit* process=nullptr;
    const ProcessRule* shell=nullptr;
};
std::atomic<DWORD> context_index{TLS_OUT_OF_INDEXES};
INIT_ONCE context_once=INIT_ONCE_STATIC_INIT;
ThreadContext* thread_context(bool create=false) {
    DWORD saved=GetLastError();
    if(context_index.load(std::memory_order_acquire)==TLS_OUT_OF_INDEXES) {
        if(!create || !InitOnceExecuteOnce(&context_once,[](PINIT_ONCE,PVOID,PVOID*)->BOOL {
            DWORD slot=TlsAlloc();context_index.store(slot,std::memory_order_release);return slot!=TLS_OUT_OF_INDEXES;
        },nullptr,nullptr)) {SetLastError(saved);return nullptr;}
    }
    auto* value=static_cast<ThreadContext*>(TlsGetValue(context_index.load(std::memory_order_acquire)));
    if(!value && create) {
        value=static_cast<ThreadContext*>(HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(ThreadContext)));
        if(value){value->owner=-1;if(!TlsSetValue(context_index,value)){HeapFree(GetProcessHeap(),0,value);value=nullptr;}}
    }
    SetLastError(saved);return value;
}
ThreadContext& local_context() {auto* value=thread_context(true);if(!value)throw std::bad_alloc();return *value;}
void release_context() {
    auto* value=thread_context();if(!value || value->maintenance || value->forward || value->process || value->shell)return;
    TlsSetValue(context_index,nullptr);HeapFree(GetProcessHeap(),0,value);
}
#define maintenance_depth (local_context().maintenance)
#define suspend_forward_depth (local_context().forward)
#define shutdown_permit (local_context().shutdown)
#define fatal_permit (local_context().fatal)
#define exit_generation (local_context().generation)
#define exit_owner (local_context().owner)
#define process_permit (local_context().process)
#define shell_permit (local_context().shell)
void denied_log(const char* operation) {
    auto now=GetTickCount64(),previous=next_denial_log.load(std::memory_order_relaxed);
    if(now>=previous && next_denial_log.compare_exchange_strong(previous,now+5000)) HIMITSU_LOG_WARNING("HostGuard","Unauthorized %s denied (arguments omitted)",operation);
}
std::wstring wide(JNIEnv* env,jstring value) {
    if(!value)return {};auto* chars=env->GetStringChars(value,nullptr);if(!chars)return {};
    std::wstring result(reinterpret_cast<const wchar_t*>(chars),env->GetStringLength(value));env->ReleaseStringChars(value,chars);return result;
}
std::wstring wide(const char* value) {
    if(!value)return {};int count=MultiByteToWideChar(CP_ACP,MB_ERR_INVALID_CHARS,value,-1,nullptr,0);if(count<=0)return {};
    std::wstring result(count,0);MultiByteToWideChar(CP_ACP,MB_ERR_INVALID_CHARS,value,-1,result.data(),count);result.pop_back();return result;
}
bool equal_path(const std::wstring& a,const std::wstring& b) {return !a.empty() && CompareStringOrdinal(a.data(),static_cast<int>(a.size()),b.data(),static_cast<int>(b.size()),TRUE)==CSTR_EQUAL;}
// Handles pin both the checked contents and the pathname through the actual create.
HANDLE pinned_file(const std::wstring& path,std::wstring& canonical,std::wstring* digest=nullptr) {
    if(path.size()<3 || !(path[1]==L':' && (path[2]==L'\\' || path[2]==L'/')) && path.rfind(L"\\\\",0)!=0)return nullptr;
    HANDLE file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return nullptr;
    wchar_t buffer[32768];DWORD count=GetFinalPathNameByHandleW(file,buffer,32768,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if(!count || count>=32768) {CloseHandle(file);return nullptr;}
    canonical.assign(buffer,count);if(canonical.rfind(L"\\\\?\\UNC\\",0)==0)canonical=L"\\\\"+canonical.substr(8);else if(canonical.rfind(L"\\\\?\\",0)==0)canonical.erase(0,4);
    if(digest) {
        BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;unsigned char output[32],bytes[16384];DWORD size=0;
        bool ok=BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0
            && BCryptCreateHash(algorithm,&hash,nullptr,0,nullptr,0,0)>=0;
        while(ok) {if(!ReadFile(file,bytes,sizeof(bytes),&size,nullptr)){ok=false;break;}if(!size)break;ok=BCryptHashData(hash,bytes,size,0)>=0;}
        if(ok)ok=BCryptFinishHash(hash,output,sizeof(output),0)>=0;
        if(hash)BCryptDestroyHash(hash);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);
        if(!ok){CloseHandle(file);return nullptr;}
        constexpr wchar_t hex[]=L"0123456789abcdef";digest->clear();for(auto b:output){digest->push_back(hex[b>>4]);digest->push_back(hex[b&15]);}
    }
    return file;
}
bool hash_valid(const std::wstring& value) {return value.size()==64 && std::all_of(value.begin(),value.end(),[](wchar_t c){return c>=L'0'&&c<=L'9'||c>=L'a'&&c<=L'f';});}
std::wstring module_path(void* caller) {
    HMODULE module=nullptr;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,reinterpret_cast<LPCWSTR>(caller),&module))return {};
    wchar_t path[32768];DWORD length=GetModuleFileNameW(module,path,32768);FreeLibrary(module);return length && length<32768?std::wstring(path,length):std::wstring{};
}
bool split_command(const wchar_t* application,const wchar_t* command,std::wstring& program,std::wstring& arguments) {
    std::wstring text=command?command:L"";std::size_t begin=text.find_first_not_of(L" \t");
    if(begin==std::wstring::npos){program=application?application:L"";return !program.empty();}
    std::size_t end;
    if(text[begin]==L'"'){end=text.find(L'"',begin+1);if(end==std::wstring::npos)return false;program=text.substr(begin+1,end-begin-1);++end;}
    else {end=text.find_first_of(L" \t",begin);if(end==std::wstring::npos)end=text.size();program=text.substr(begin,end-begin);}
    if(application && *application)program=application;
    auto rest=text.find_first_not_of(L" \t",end);arguments=rest==std::wstring::npos?L"":text.substr(rest);return !program.empty();
}
std::wstring working_directory(const wchar_t* directory) {
    wchar_t result[32768];DWORD n=directory&&*directory?GetFullPathNameW(directory,32768,result,nullptr):GetCurrentDirectoryW(32768,result);
    return n&&n<32768?std::wstring(result,n):std::wstring{};
}
bool authorize_process(const std::wstring& kind,const std::wstring& source,const std::wstring& program,const std::wstring& arguments,
        const std::wstring& directory,const std::wstring& verb,HANDLE& source_pin,HANDLE& program_pin,std::wstring& executable) {
    auto rules=std::atomic_load_explicit(&process_rules,std::memory_order_acquire);if(!rules || rules->empty())return false;
    std::wstring source_path,source_hash,program_hash;
    source_pin=pinned_file(source,source_path,&source_hash);if(!source_pin)return false;
    program_pin=pinned_file(program,executable,&program_hash);if(!program_pin)return false;
    for(const auto& rule:*rules) if(rule.kind==kind && equal_path(rule.source,source_path) && rule.source_hash==source_hash
        && (equal_path(rule.program,executable)&&rule.program_hash==program_hash)
        && rule.arguments==arguments && equal_path(rule.directory,directory) && rule.verb==verb)return true;
    return false;
}
void close_pins(HANDLE a,HANDLE b){if(a)CloseHandle(a);if(b)CloseHandle(b);}
bool same_source(JNIEnv* env,jclass left,jclass right) {
    if(env->IsSameObject(left,right))return true;
    jclass type=env->FindClass("java/lang/Class"),pd=env->FindClass("java/security/ProtectionDomain"),cs=env->FindClass("java/security/CodeSource");
    if(!type||!pd||!cs)return false;
    auto protection=env->GetMethodID(type,"getProtectionDomain","()Ljava/security/ProtectionDomain;");
    auto source=env->GetMethodID(pd,"getCodeSource","()Ljava/security/CodeSource;");
    auto equals=env->GetMethodID(cs,"equals","(Ljava/lang/Object;)Z");
    if(!protection||!source||!equals)return false;
    jobject a=env->CallObjectMethod(left,protection),b=env->CallObjectMethod(right,protection);
    a=a?env->CallObjectMethod(a,source):nullptr;b=b?env->CallObjectMethod(b,source):nullptr;
    return a&&b&&env->CallBooleanMethod(a,equals,b)&&!env->ExceptionCheck();
}
bool lifecycle_stack(JNIEnv* env,const State::References& refs,int owner,const char* method,const char* alias,bool begin) {
    auto* ti=State::instance().jvmti();jvmtiFrameInfo frames[128];jint count=0;
    if(!ti || ti->GetStackTrace(nullptr,0,128,frames,&count)!=JVMTI_ERROR_NONE || count==128)return false;
    bool hook=false,entry=false,root=false;jclass entry_type=nullptr;
    for(jint i=0;i<count;++i) {
        jclass type=nullptr;char* name=nullptr;char* signature=nullptr;
        if(ti->GetMethodDeclaringClass(frames[i].method,&type)!=JVMTI_ERROR_NONE)return false;
        if(!hook) {hook=env->IsSameObject(type,refs.host_hooks[owner]);continue;}
        if(ti->GetMethodName(frames[i].method,&name,nullptr,nullptr)!=JVMTI_ERROR_NONE || ti->GetClassSignature(type,&signature,nullptr)!=JVMTI_ERROR_NONE)return false;
        std::string n=name?name:"",c=signature?signature:"";if(name)ti->Deallocate(reinterpret_cast<unsigned char*>(name));if(signature)ti->Deallocate(reinterpret_cast<unsigned char*>(signature));
        if(!entry) {
            if((n!=method && n!=alias) || c!=(owner==0?"Lnet/minecraft/client/Minecraft;":n=="onServerExit"||n=="m_6988_"?"Lnet/minecraft/server/dedicated/DedicatedServer;":"Lnet/minecraft/server/MinecraftServer;"))return false;
            entry=true;entry_type=type;if(begin)return true;continue;
        }
        jobject loader=nullptr;if(ti->GetClassLoader(type,&loader)!=JVMTI_ERROR_NONE)return false;
        if(!loader)continue;
        if(same_source(env,type,entry_type)) {
            if(owner==0 && (c=="Lnet/minecraft/client/Minecraft;" && (n=="run"||n=="m_91374_"||n=="runTick"||n=="m_91383_")
                || c=="Lnet/minecraft/client/main/Main;"&&n=="main"))root=true;
            if(owner==1 && c=="Lnet/minecraft/server/MinecraftServer;" && (n=="runServer"||n=="m_130011_"))root=true;
            if(root)return true;
            continue;
        }
        // Command execution uses Brigadier; validate its actual origin, not a package-name exemption.
        jclass commands=env->FindClass("com/mojang/brigadier/CommandDispatcher");
        if(owner==1 && commands && same_source(env,type,commands))continue;
        return false;
    }
    return false;
}

bool lifecycle_event(JNIEnv* env,const State::References& refs,int owner,jobject object) {
    auto* ti=State::instance().jvmti();jvmtiFrameInfo frames[128];jint count=0;jthread current=nullptr;
    jclass game=env->FindClass(owner==0?"net/minecraft/client/Minecraft":"net/minecraft/server/MinecraftServer");
    jclass authority=env->FindClass(owner==0?"net/minecraftforge/event/ForgeEventFactory":"net/minecraftforge/server/ServerLifecycleHooks");
    if(!game||!authority||!env->IsInstanceOf(object,game))return false;
    jfieldID field=env->GetFieldID(game,owner==0?"gameThread":"serverThread","Ljava/lang/Thread;");
    if(!field) {env->ExceptionClear();field=env->GetFieldID(game,owner==0?"f_91018_":"f_129725_","Ljava/lang/Thread;");}
    if(!field || himitsu::jvm::trusted_current_thread(&current)!=JVMTI_ERROR_NONE || !env->IsSameObject(current,env->GetObjectField(object,field)))return false;
    if(!ti || ti->GetStackTrace(nullptr,0,128,frames,&count)!=JVMTI_ERROR_NONE || count==128)return false;
    bool hook=false,dispatcher=false;
    for(jint i=0;i<count;++i) {
        jclass type=nullptr;jobject loader=nullptr;char* raw=nullptr;
        if(ti->GetMethodDeclaringClass(frames[i].method,&type)!=JVMTI_ERROR_NONE)return false;
        if(!hook){hook=env->IsSameObject(type,refs.host_hooks[owner]);continue;}
        if(ti->GetMethodName(frames[i].method,&raw,nullptr,nullptr)!=JVMTI_ERROR_NONE)return false;
        std::string name=raw?raw:"";if(raw)ti->Deallocate(reinterpret_cast<unsigned char*>(raw));
        if(env->IsSameObject(type,refs.host_hooks[2])&&name=="dispatchSecret")dispatcher=true;
        if(dispatcher && env->IsSameObject(type,authority)&&name==(owner==0?"onPostClientTick":"handleServerStarting"))return true;
        if(ti->GetClassLoader(type,&loader)!=JVMTI_ERROR_NONE)return false;if(!loader)continue;
        if(himitsu::platform::windows::owned_event_frame(env,type,refs.host_hooks[2],refs.event_bridge))continue;
        if(!same_source(env,type,refs.bootstrap) && !(refs.event_bus&&same_source(env,type,refs.event_bus))
            && !same_source(env,type,authority) && !same_source(env,type,game))return false;
    }
    return false;
}

bool natural_shutdown(JNIEnv* env) {
    auto type=env->FindClass("java/lang/ApplicationShutdownHooks");auto field=type?env->GetStaticFieldID(type,"hooks","Ljava/util/IdentityHashMap;"):nullptr;
    auto pending=field?env->GetStaticObjectField(type,field):nullptr;bool active=field&&!pending&&!env->ExceptionCheck();
    if(pending)env->DeleteLocalRef(pending);if(type)env->DeleteLocalRef(type);return active;
}
bool actual_exit_frame(JNIEnv* env,const State::References& refs,int owner) {
    auto* ti=State::instance().jvmti();jvmtiFrameInfo frames[64];jint count=0;
    if(!ti || !refs.host_objects[owner] || ti->GetStackTrace(nullptr,0,64,frames,&count)!=JVMTI_ERROR_NONE || count==64)return false;
    jclass core=env->GetObjectClass(refs.host_objects[owner]);
    for(jint i=0;i<count;++i) {
        jclass type=nullptr;jobject loader=nullptr;char* raw=nullptr;
        if(ti->GetMethodDeclaringClass(frames[i].method,&type)!=JVMTI_ERROR_NONE || ti->GetClassLoader(type,&loader)!=JVMTI_ERROR_NONE)return false;
        if(!loader)continue;
        if(!same_source(env,type,core))return false;
        if(ti->GetMethodName(frames[i].method,&raw,nullptr,nullptr)!=JVMTI_ERROR_NONE)return false;
        std::string name=raw?raw:"";if(raw)ti->Deallocate(reinterpret_cast<unsigned char*>(raw));
        if(env->IsSameObject(type,core) && (owner==0?(name=="destroy"||name=="m_91393_"):(name=="onServerExit"||name=="m_6988_")))return true;
    }
    return false;
}

bool client_crash_exit(JNIEnv* env,const State::References& refs) {
    // Exact Forge crash-report outlet, not a reusable exit ticket. JNI FindClass here uses the JDK loader.
    auto* ti=State::instance().jvmti();jvmtiFrameInfo frames[64];jint count=0;int stage=0;jclass game=nullptr;
    if(!refs.game_loader || !ti || ti->GetStackTrace(nullptr,0,64,frames,&count)!=JVMTI_ERROR_NONE || count==64)return false;
    for(jint i=0;i<count;++i) {
        jclass type=nullptr;jobject loader=nullptr;char *method=nullptr,*descriptor=nullptr,*signature=nullptr;
        if(ti->GetMethodDeclaringClass(frames[i].method,&type)!=JVMTI_ERROR_NONE || ti->GetClassLoader(type,&loader)!=JVMTI_ERROR_NONE)return false;
        int frame=-1;
        if(!loader)frame=0;
        else if(env->IsSameObject(loader,refs.game_loader)) {
            auto named=ti->GetMethodName(frames[i].method,&method,&descriptor,nullptr);
            auto typed=ti->GetClassSignature(type,&signature,nullptr);
            if(named==JVMTI_ERROR_NONE&&typed==JVMTI_ERROR_NONE&&method&&descriptor&&signature) {
                if(!std::strcmp(signature,"Lnet/minecraftforge/server/ServerLifecycleHooks;")&&!std::strcmp(method,"handleExit")&&!std::strcmp(descriptor,"(I)V"))frame=1;
                if(!std::strcmp(signature,"Lnet/minecraft/client/Minecraft;")) {
                    if((!std::strcmp(method,"crash")||!std::strcmp(method,"m_91332_"))&&!std::strcmp(descriptor,"(Lnet/minecraft/CrashReport;)V")){frame=2;game=type;}
                    if(game&&env->IsSameObject(game,type)&&(!std::strcmp(method,"run")||!std::strcmp(method,"m_91374_"))&&!std::strcmp(descriptor,"()V"))frame=3;
                }
            }
            for(char* value:{method,descriptor,signature})if(value)ti->Deallocate(reinterpret_cast<unsigned char*>(value));
        }
        stage=himitsu::platform::windows::crash_exit_step(stage,frame);if(stage<0)return false;
        if(stage!=3)continue;
        auto instance=env->GetStaticFieldID(game,"instance","Lnet/minecraft/client/Minecraft;");
        if(!instance){env->ExceptionClear();instance=env->GetStaticFieldID(game,"f_90981_","Lnet/minecraft/client/Minecraft;");}
        auto thread=env->GetFieldID(game,"gameThread","Ljava/lang/Thread;");
        if(!thread){env->ExceptionClear();thread=env->GetFieldID(game,"f_91018_","Ljava/lang/Thread;");}
        if(!instance||!thread)return false;
        auto object=env->GetStaticObjectField(game,instance);jthread current=nullptr;
        if(!object || (refs.host_objects[0]&&!env->IsSameObject(object,refs.host_objects[0])) || himitsu::jvm::trusted_current_thread(&current)!=JVMTI_ERROR_NONE)return false;
        return env->IsSameObject(current,env->GetObjectField(object,thread))&&!env->ExceptionCheck();
    }
    return false;
}

bool exit_allowed(JNIEnv* env) {
    if(fatal_permit||shutdown_permit)return true;
    State::ReferenceRead read(State::instance(),env);
    if(env->PushLocalFrame(512)<0)return false;
    bool allowed=client_crash_exit(env,*read.get());
    if(!allowed && !env->ExceptionCheck() && exit_owner>=0 && exit_generation) {
        jthread current=nullptr;
        if(himitsu::jvm::trusted_current_thread(&current)==JVMTI_ERROR_NONE)
            allowed=read->host_generation[exit_owner]==exit_generation && read->host_phase[exit_owner]>=3
                && env->IsSameObject(current,read->host_threads[exit_owner]) && actual_exit_frame(env,*read.get(),exit_owner);
    }
    env->PopLocalFrame(nullptr);return allowed&&!env->ExceptionCheck();
}

void deny_exit(JNIEnv* env) {
    denied_log("process exit");jobject error=himitsu::jvm::new_exception(env,"java/lang/SecurityException","Secret denied an unauthorized process exit");
    if(!error)return;auto global=env->NewGlobalRef(error);bool published=false;
    if(global)for(unsigned i=0;i<8;++i) {
        State::ReferenceRead read(State::instance(),env);auto next=std::make_unique<State::References>(*read.get());
        if(next->exit_denials.size()==32)next->exit_denials.erase(next->exit_denials.begin());next->exit_denials.push_back(global);
        if(State::instance().publish_references(read.get(),next)){published=true;break;}
    }
    if(global&&!published)env->DeleteGlobalRef(global);env->Throw(static_cast<jthrowable>(error));env->DeleteLocalRef(error);
}
bool protected_java(const State::References& refs,JNIEnv* env,jobject thread) {
    if(!env || !thread) return false;
    for(const auto& entry:refs.threads) if(entry.java_thread && env->IsSameObject(entry.java_thread,thread)) return true;
    return false;
}
bool protected_os(HANDLE handle) {
    if(!handle || !compare_handles) return false;
    State::ReferenceRead read(State::instance());
    for(const auto& entry:read->threads) if(entry.os_thread && compare_handles(entry.os_thread,handle)) return true;
    return false;
}
bool jvm_caller(void* caller) {
    auto address=reinterpret_cast<std::uintptr_t>(caller);
    return address>=jvm_begin && address<jvm_end;
}
DWORD suspend_os(Hook& hook,HANDLE thread,void* caller) {
    const DWORD saved=GetLastError();
    if(admitting.load(std::memory_order_acquire) && !maintenance_depth && !suspend_forward_depth && !jvm_caller(caller) && protected_os(thread)) {
        SetLastError(ERROR_ACCESS_DENIED); return static_cast<DWORD>(-1);
    }
    SetLastError(saved); ++suspend_forward_depth;
    const DWORD result=reinterpret_cast<SuspendOsFn>(hook.trampoline.load(std::memory_order_acquire))(thread);
    const DWORD error=GetLastError(); --suspend_forward_depth; SetLastError(error); return result;
}
BOOL terminate_os(Hook& hook,HANDLE thread,DWORD code) {
    const DWORD saved=GetLastError();
    if(admitting.load(std::memory_order_acquire) && !maintenance_depth && protected_os(thread)) {
        SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    SetLastError(saved);
    return reinterpret_cast<TerminateOsFn>(hook.trampoline.load(std::memory_order_acquire))(thread,code);
}
DWORD WINAPI guarded_base_suspend(HANDLE thread) {return suspend_os(base_suspend,thread,THREAD_CALLER);}
DWORD WINAPI guarded_kernel_suspend(HANDLE thread) {return suspend_os(kernel_suspend,thread,THREAD_CALLER);}
BOOL WINAPI guarded_base_terminate(HANDLE thread,DWORD code) {return terminate_os(base_terminate,thread,code);}
BOOL WINAPI guarded_kernel_terminate(HANDLE thread,DWORD code) {return terminate_os(kernel_terminate,thread,code);}
void JNICALL guarded_stop(JNIEnv* env,jobject thread,jobject error) {
    bool denied=false;
    if(admitting.load(std::memory_order_acquire)) {State::ReferenceRead read(State::instance(),env);denied=protected_java(*read.get(),env,thread);}
    if(!denied) reinterpret_cast<StopThreadFn>(stop_hook.trampoline.load(std::memory_order_acquire))(env,thread,error);
}
void JNICALL guarded_suspend(JNIEnv* env,jobject thread) {
    bool denied=false;
    if(admitting.load(std::memory_order_acquire)) {State::ReferenceRead read(State::instance(),env);denied=protected_java(*read.get(),env,thread);}
    if(!denied) reinterpret_cast<SuspendJavaFn>(suspend_hook.trampoline.load(std::memory_order_acquire))(env,thread);
}
jobjectArray JNICALL guarded_threads(JNIEnv* env,jclass type) {
    jobjectArray source=reinterpret_cast<GetAllThreadsFn>(all_threads_hook.trampoline.load(std::memory_order_acquire))(env,type);
    if(!source || env->ExceptionCheck() || !admitting.load(std::memory_order_acquire)) return source;
    State::ReferenceRead read(State::instance(),env);
    if(std::none_of(read->threads.begin(),read->threads.end(),[](const auto& entry){return entry.java_thread!=nullptr;})) return source;
    const jsize length=env->GetArrayLength(source);
    std::vector<jobject> visible; visible.reserve(static_cast<std::size_t>(length));
    for(jsize i=0;i<length;i++) {
        jobject thread=env->GetObjectArrayElement(source,i);
        if(protected_java(*read.get(),env,thread)) env->DeleteLocalRef(thread); else visible.push_back(thread);
    }
    jclass thread_type=env->FindClass("java/lang/Thread");
    jobjectArray result=thread_type?env->NewObjectArray(static_cast<jsize>(visible.size()),thread_type,nullptr):nullptr;
    if(result) for(jsize i=0;i<static_cast<jsize>(visible.size());i++) env->SetObjectArrayElement(result,i,visible[i]);
    for(jobject thread:visible) env->DeleteLocalRef(thread);
    if(thread_type) env->DeleteLocalRef(thread_type);
    env->DeleteLocalRef(source); return result;
}

LONG NTAPI guarded_nt_suspend(HANDLE thread,PULONG previous) {
    const DWORD saved=GetLastError();
    if(admitting.load(std::memory_order_acquire) && !jvm_caller(THREAD_CALLER) && protected_os(thread)) {
        auto* context=thread_context();if(!context || (!context->maintenance&&!context->forward))return static_cast<LONG>(0xC0000022L);
    }
    SetLastError(saved);return reinterpret_cast<LONG(NTAPI*)(HANDLE,PULONG)>(nt_suspend.trampoline.load())(thread,previous);
}
LONG NTAPI guarded_nt_terminate(HANDLE thread,LONG status) {
    const DWORD saved=GetLastError();HANDLE target=thread?thread:GetCurrentThread();
    auto caller=reinterpret_cast<unsigned char*>(THREAD_CALLER);
    bool normal_end=compare_handles && compare_handles(target,GetCurrentThread())
        && (jvm_caller(caller) || std::any_of(rtl_thread_exit_ranges.begin(),rtl_thread_exit_ranges.end(),[&](const auto& range){return caller>=range.address&&caller<range.address+range.expected.size();}));
    if(admitting.load(std::memory_order_acquire) && !normal_end && protected_os(target)) {
        auto* context=thread_context();if(!context || !context->maintenance)return static_cast<LONG>(0xC0000022L);
    }
    SetLastError(saved);return reinterpret_cast<LONG(NTAPI*)(HANDLE,LONG)>(nt_terminate.trampoline.load())(thread,status);
}
jint JNICALL guarded_attach(char*,char*,char*,char*,char*) {
    // Also refuse stale/in-flight detours during shutdown. Disabled hooks use the retained original entry.
    return 100; // OpenJDK ATTACH_ERROR_DISABLED; no TLS, JNI, allocation or pipe wait.
}

void JNICALL guarded_before_halt(JNIEnv* env,jclass type) {
    if(admitting.load(std::memory_order_acquire) && !exit_allowed(env)){deny_exit(env);return;}
    reinterpret_cast<void(JNICALL*)(JNIEnv*,jclass)>(before_halt.trampoline.load())(env,type);
}
void JNICALL guarded_halt(JNIEnv* env,jclass type,jint status) {
    if(admitting.load(std::memory_order_acquire) && !exit_allowed(env)){deny_exit(env);return;}
    reinterpret_cast<void(JNICALL*)(JNIEnv*,jclass,jint)>(halt_hook.trampoline.load())(env,type,status);
}
bool self_process(HANDLE process) {return process==GetCurrentProcess() || process && compare_handles && compare_handles(process,GetCurrentProcess());}
bool raw_exit_allowed(){auto* context=thread_context();return context&&(context->fatal||context->shutdown);}

BOOL end_process(Hook& hook,HANDLE process,UINT status) {
    if(admitting.load(std::memory_order_acquire)&&self_process(process)&&!raw_exit_allowed()){denied_log("TerminateProcess");SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return reinterpret_cast<BOOL(WINAPI*)(HANDLE,UINT)>(hook.trampoline.load())(process,status);
}
BOOL WINAPI guarded_base_process_end(HANDLE process,UINT status){return end_process(base_process_end,process,status);}
BOOL WINAPI guarded_kernel_process_end(HANDLE process,UINT status){return end_process(kernel_process_end,process,status);}
LONG NTAPI guarded_nt_process_end(HANDLE process,LONG status) {
    auto caller=reinterpret_cast<unsigned char*>(THREAD_CALLER);
    // ExitProcess/RtlExitUserProcess has already entered a no-return teardown. Do not fake recovery there.
    bool teardown=std::any_of(rtl_exit_ranges.begin(),rtl_exit_ranges.end(),[&](const auto& range){return caller>=range.address&&caller<range.address+range.expected.size();});
    if(admitting.load(std::memory_order_acquire)&&(!process||self_process(process))&&!raw_exit_allowed()&&!teardown)return static_cast<LONG>(0xC0000022L);
    return reinterpret_cast<LONG(NTAPI*)(HANDLE,LONG)>(nt_process_end.trampoline.load())(process,status);
}
using CreateW=BOOL(WINAPI*)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
using CreateA=BOOL(WINAPI*)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
bool create_forwarder(void* caller) {
    auto address=reinterpret_cast<unsigned char*>(caller);
    for(const auto* hook:{&base_create_w,&base_create_a,&kernel_create_w,&kernel_create_a})
        for(const auto& range:hook->forwarding)if(address>=range.address&&address<range.address+range.expected.size())return true;
    return false;
}
bool enter_create(void* caller,const std::wstring& source,const wchar_t* app,const wchar_t* command,const wchar_t* directory,ProcessPermit& permit,HANDLE& a,HANDLE& b,bool& nested) {
    if(!split_command(app,command,permit.program,permit.arguments))return false;permit.directory=working_directory(directory);
    if(process_permit) {
        // Only same-operation Kernel32 -> KernelBase forwarding may reuse a granted operation.
        bool same=equal_path(process_permit->program,permit.program)&&process_permit->arguments==permit.arguments&&equal_path(process_permit->directory,permit.directory);
        if(!same || process_permit->used && (!process_permit->depth || !create_forwarder(caller)))return false;
        process_permit->used=true;++process_permit->depth;nested=true;return true;
    }
    if(shell_permit)return false; // Shell forwarding must match its pinned, single child permit.
    if(!authorize_process(L"native",source,permit.program,permit.arguments,permit.directory,L"",a,b,permit.program))return false;
    permit.depth=1;process_permit=&permit;return true;
}
BOOL create_w(Hook& hook,void* caller,LPCWSTR app,LPWSTR command,LPSECURITY_ATTRIBUTES pa,LPSECURITY_ATTRIBUTES ta,BOOL inherit,DWORD flags,LPVOID environment,LPCWSTR directory,LPSTARTUPINFOW startup,LPPROCESS_INFORMATION result) {
    if(!admitting.load(std::memory_order_acquire))return reinterpret_cast<CreateW>(hook.trampoline.load())(app,command,pa,ta,inherit,flags,environment,directory,startup,result);
    ProcessPermit permit;HANDLE a=nullptr,b=nullptr;bool nested=false;
    if(!enter_create(caller,module_path(caller),app,command,directory,permit,a,b,nested)){close_pins(a,b);denied_log("CreateProcess");SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    BOOL ok=reinterpret_cast<CreateW>(hook.trampoline.load())(permit.program.c_str(),command,pa,ta,inherit,flags,environment,directory,startup,result);
    DWORD error=GetLastError();if(nested)--process_permit->depth;else process_permit=nullptr;close_pins(a,b);SetLastError(error);return ok;
}
BOOL create_a(Hook& hook,void* caller,LPCSTR app,LPSTR command,LPSECURITY_ATTRIBUTES pa,LPSECURITY_ATTRIBUTES ta,BOOL inherit,DWORD flags,LPVOID environment,LPCSTR directory,LPSTARTUPINFOA startup,LPPROCESS_INFORMATION result) {
    if(!admitting.load(std::memory_order_acquire))return reinterpret_cast<CreateA>(hook.trampoline.load())(app,command,pa,ta,inherit,flags,environment,directory,startup,result);
    ProcessPermit permit;HANDLE a=nullptr,b=nullptr;bool nested=false;auto aw=wide(app),cw=wide(command),dw=wide(directory);
    if(!enter_create(caller,module_path(caller),aw.c_str(),cw.c_str(),dw.c_str(),permit,a,b,nested)){close_pins(a,b);denied_log("CreateProcess");SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    BOOL ok=reinterpret_cast<CreateA>(hook.trampoline.load())(app,command,pa,ta,inherit,flags,environment,directory,startup,result);
    DWORD error=GetLastError();if(nested)--process_permit->depth;else process_permit=nullptr;close_pins(a,b);SetLastError(error);return ok;
}
#define CREATE_W(name,hook) BOOL WINAPI name(LPCWSTR a,LPWSTR c,LPSECURITY_ATTRIBUTES p,LPSECURITY_ATTRIBUTES t,BOOL i,DWORD f,LPVOID e,LPCWSTR d,LPSTARTUPINFOW s,LPPROCESS_INFORMATION r){return create_w(hook,THREAD_CALLER,a,c,p,t,i,f,e,d,s,r);}
#define CREATE_A(name,hook) BOOL WINAPI name(LPCSTR a,LPSTR c,LPSECURITY_ATTRIBUTES p,LPSECURITY_ATTRIBUTES t,BOOL i,DWORD f,LPVOID e,LPCSTR d,LPSTARTUPINFOA s,LPPROCESS_INFORMATION r){return create_a(hook,THREAD_CALLER,a,c,p,t,i,f,e,d,s,r);}
CREATE_W(guarded_base_create_w,base_create_w) CREATE_W(guarded_kernel_create_w,kernel_create_w)
CREATE_A(guarded_base_create_a,base_create_a) CREATE_A(guarded_kernel_create_a,kernel_create_a)
#undef CREATE_W
#undef CREATE_A
jlong JNICALL guarded_java_process(JNIEnv* env,jclass type,jstring command,jstring environment,jstring directory,jlongArray handles,jboolean redirect) {
    using Fn=jlong(JNICALL*)(JNIEnv*,jclass,jstring,jstring,jstring,jlongArray,jboolean);
    if(!admitting.load(std::memory_order_acquire))return reinterpret_cast<Fn>(java_process.trampoline.load())(env,type,command,environment,directory,handles,redirect);
    ProcessPermit permit;HANDLE a=nullptr,b=nullptr;bool allowed=false;
    if(env->PushLocalFrame(32)<0)return 0;
    State::ReferenceRead read(State::instance(),env);
    auto method=read->bootstrap?env->GetStaticMethodID(read->bootstrap,"processSource","()Ljava/lang/String;"):nullptr;
    jstring origin=method?static_cast<jstring>(env->CallStaticObjectMethod(read->bootstrap,method)):nullptr;
    auto text=wide(env,command),dir=wide(env,directory),source=wide(env,origin);
    if(!env->ExceptionCheck()&&!process_permit&&split_command(nullptr,text.c_str(),permit.program,permit.arguments)) {
        permit.directory=working_directory(dir.c_str());allowed=authorize_process(L"java",source,permit.program,permit.arguments,permit.directory,L"",a,b,permit.program);
    }
    env->PopLocalFrame(nullptr);
    if(!allowed){close_pins(a,b);if(!env->ExceptionCheck()) {denied_log("Java child process");env->ThrowNew(env->FindClass("java/io/IOException"),"Secret process policy denied this request");}return 0;}
    permit.java=true;process_permit=&permit;
    jlong result=reinterpret_cast<Fn>(java_process.trampoline.load())(env,type,command,environment,directory,handles,redirect);
    DWORD error=GetLastError();process_permit=nullptr;close_pins(a,b);SetLastError(error);return result;
}

// Nested ShellExecute -> ShellExecuteEx forwarding is tied to the same verb, target, arguments and directory.
const ProcessRule* enter_shell(void* caller,const std::wstring& target,const std::wstring& arguments,const std::wstring& directory,const std::wstring& verb,
    std::shared_ptr<const std::vector<ProcessRule>>& held,HANDLE& source_pin,HANDLE& program_pin,ProcessPermit& child,bool& nested) {
    auto dir=working_directory(directory.c_str());auto operation=verb.empty()?L"open":verb;
    if(shell_permit) {
        if(shell_permit->target==target && shell_permit->arguments==arguments && shell_permit->verb==operation && equal_path(shell_permit->directory,dir)) {nested=true;return shell_permit;}
        return nullptr;
    }
    held=std::atomic_load_explicit(&process_rules,std::memory_order_acquire);if(!held)return nullptr;
    std::wstring source_path,source_hash,program_path,program_hash;
    source_pin=pinned_file(module_path(caller),source_path,&source_hash);if(!source_pin)return nullptr;
    for(const auto& rule:*held)if(rule.kind==L"shell" && rule.target==target && rule.verb==operation && rule.arguments==arguments && equal_path(rule.directory,dir)
        && equal_path(rule.source,source_path) && rule.source_hash==source_hash) {
        program_pin=pinned_file(rule.program,program_path,&program_hash);if(!program_pin||program_hash!=rule.program_hash)return nullptr;
        // The exact command arguments may include the target; no association/PATH fallback is adopted.
        child.program=program_path;child.arguments=rule.child_arguments;child.directory=dir;child.java=true;
        if(process_permit)return nullptr;process_permit=&child;shell_permit=&rule;return &rule;
    }
    return nullptr;
}
void leave_shell(bool nested,HANDLE a,HANDLE b){if(!nested){shell_permit=nullptr;process_permit=nullptr;}close_pins(a,b);}
HINSTANCE WINAPI guarded_shell_w(HWND window,LPCWSTR verb,LPCWSTR file,LPCWSTR args,LPCWSTR directory,INT show) {
    if(!admitting.load())return reinterpret_cast<decltype(&ShellExecuteW)>(shell_w.trampoline.load())(window,verb,file,args,directory,show);
    HANDLE a=nullptr,b=nullptr;ProcessPermit child;bool nested=false;std::shared_ptr<const std::vector<ProcessRule>> held;
    if(!enter_shell(THREAD_CALLER,file?file:L"",args?args:L"",directory?directory:L"",verb?verb:L"open",held,a,b,child,nested)){close_pins(a,b);denied_log("Shell action");SetLastError(ERROR_ACCESS_DENIED);return reinterpret_cast<HINSTANCE>(SE_ERR_ACCESSDENIED);}
    auto result=reinterpret_cast<decltype(&ShellExecuteW)>(shell_w.trampoline.load())(window,verb,file,args,directory,show);DWORD error=GetLastError();leave_shell(nested,a,b);SetLastError(error);return result;
}
HINSTANCE WINAPI guarded_shell_a(HWND window,LPCSTR verb,LPCSTR file,LPCSTR args,LPCSTR directory,INT show) {
    if(!admitting.load())return reinterpret_cast<decltype(&ShellExecuteA)>(shell_a.trampoline.load())(window,verb,file,args,directory,show);
    HANDLE a=nullptr,b=nullptr;ProcessPermit child;bool nested=false;std::shared_ptr<const std::vector<ProcessRule>> held;
    if(!enter_shell(THREAD_CALLER,wide(file),wide(args),wide(directory),verb?wide(verb):L"open",held,a,b,child,nested)){close_pins(a,b);denied_log("Shell action");SetLastError(ERROR_ACCESS_DENIED);return reinterpret_cast<HINSTANCE>(SE_ERR_ACCESSDENIED);}
    auto result=reinterpret_cast<decltype(&ShellExecuteA)>(shell_a.trampoline.load())(window,verb,file,args,directory,show);DWORD error=GetLastError();leave_shell(nested,a,b);SetLastError(error);return result;
}
BOOL WINAPI guarded_shell_ex_w(SHELLEXECUTEINFOW* info) {
    if(!admitting.load())return reinterpret_cast<decltype(&ShellExecuteExW)>(shell_ex_w.trampoline.load())(info);
    HANDLE a=nullptr,b=nullptr;ProcessPermit child;bool nested=false;std::shared_ptr<const std::vector<ProcessRule>> held;
    if(!info || info->cbSize!=sizeof(*info) || (info->fMask&(SEE_MASK_IDLIST|SEE_MASK_INVOKEIDLIST|SEE_MASK_CLASSKEY|SEE_MASK_CLASSNAME))
        || !enter_shell(THREAD_CALLER,info->lpFile?info->lpFile:L"",info->lpParameters?info->lpParameters:L"",info->lpDirectory?info->lpDirectory:L"",info->lpVerb?info->lpVerb:L"open",held,a,b,child,nested)){close_pins(a,b);SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    auto result=reinterpret_cast<decltype(&ShellExecuteExW)>(shell_ex_w.trampoline.load())(info);DWORD error=GetLastError();leave_shell(nested,a,b);SetLastError(error);return result;
}
BOOL WINAPI guarded_shell_ex_a(SHELLEXECUTEINFOA* info) {
    if(!admitting.load())return reinterpret_cast<decltype(&ShellExecuteExA)>(shell_ex_a.trampoline.load())(info);
    HANDLE a=nullptr,b=nullptr;ProcessPermit child;bool nested=false;std::shared_ptr<const std::vector<ProcessRule>> held;
    if(!info || info->cbSize!=sizeof(*info) || (info->fMask&(SEE_MASK_IDLIST|SEE_MASK_INVOKEIDLIST|SEE_MASK_CLASSKEY|SEE_MASK_CLASSNAME))
        || !enter_shell(THREAD_CALLER,wide(info->lpFile),wide(info->lpParameters),wide(info->lpDirectory),info->lpVerb?wide(info->lpVerb):L"open",held,a,b,child,nested)){close_pins(a,b);SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    auto result=reinterpret_cast<decltype(&ShellExecuteExA)>(shell_ex_a.trampoline.load())(info);DWORD error=GetLastError();leave_shell(nested,a,b);SetLastError(error);return result;
}

bool prepare(Hook& hook,void* replacement) {
    if(hook.created) return true;
    HMODULE library=GetModuleHandleW(hook.library);
    hook.target=library?reinterpret_cast<void*>(GetProcAddress(library,hook.name)):nullptr;
    if(!hook.target) {HIMITSU_LOG_ERROR("ThreadGuard","Required thread export unavailable: %s",hook.name);return false;}
    for(Hook* prior:hooks) if(prior!=&hook && prior->created && prior->target==hook.target) {
        hook.trampoline.store(prior->trampoline.load(std::memory_order_acquire),std::memory_order_release); return true;
    }
    if(&hook==&base_create_w||&hook==&base_create_a||&hook==&kernel_create_w||&hook==&kernel_create_a)
        himitsu::jvm::native_function_baseline(hook.target,hook.forwarding);
    void* original=nullptr;
    auto result=MH_CreateHook(hook.target,replacement,&original);
    if(result!=MH_OK || !original) {HIMITSU_LOG_ERROR("ThreadGuard","Cannot relocate %s: %s",hook.name,MH_StatusToString(result));return false;}
    hook.trampoline.store(original,std::memory_order_release);hook.created=true;return true;
}
bool enable(bool value,std::uint64_t deadline=0) {
    himitsu::platform::windows::ThreadHookMaintenance scope;
    bool queued=true;
    for(Hook* hook:hooks)if(hook->created) {
        if(!himitsu::platform::windows::guarded_hook_intact(hook->target))return false;
        if(!value && !himitsu::platform::windows::unregister_guarded_region(hook->guard_token,deadline))return false;
    }
    for(Hook* hook:hooks) if(hook->created) {
        auto result=value?MH_QueueEnableHook(hook->target):MH_QueueDisableHook(hook->target);
        if(result!=MH_OK) HIMITSU_LOG_ERROR("ThreadGuard","Cannot queue %s enable=%d: %s",hook->name,value,MH_StatusToString(result));
        queued=queued && result==MH_OK;
    }
    auto result=MH_ApplyQueued();
    if(result!=MH_OK) HIMITSU_LOG_ERROR("ThreadGuard","Cannot apply thread hooks: %s",MH_StatusToString(result));
    if(queued && result==MH_OK && value)for(Hook* hook:hooks)if(hook->created) {
        hook->guard_token=himitsu::platform::windows::register_guarded_hook(hook->name,hook->target);
        queued=queued && hook->guard_token!=0;
    }
    return queued && result==MH_OK;
}
}
namespace himitsu::platform::windows {

void authorize_fatal_exit(){if(auto* context=thread_context(true))context->fatal=true;}
bool host_shutdown_authorized(){auto* context=thread_context();return context&&context->shutdown;}
void retire_host_thread(JNIEnv* env,jobject thread) {
    release_context();
    auto& state=State::instance();
    for(unsigned attempt=0;attempt<8 && !state.shutting_down();++attempt) {
        State::ReferenceRead read(state,env);bool found=false;
        for(const auto& entry:read->threads)if(entry.java_thread && env->IsSameObject(entry.java_thread,thread)){found=true;break;}
        if(!found)return;
        auto next=std::make_unique<State::References>(*read.get());
        std::erase_if(next->threads,[&](const auto& entry){return entry.java_thread&&env->IsSameObject(entry.java_thread,thread);});
        for(int i=0;i<2;++i)if(next->host_threads[i]&&env->IsSameObject(next->host_threads[i],thread)) {
            next->host_threads[i]=nullptr;next->host_objects[i]=nullptr;next->host_phase[i]=0;++next->host_generation[i];
        }
        if(state.publish_references(read.get(),next,true))return;
    }
}
jobject host_command(JNIEnv* env,const char* command,jobject first,jobject second) {
    using himitsu::jvm::authenticated_host_call;using himitsu::jvm::new_exception;
    auto& state=State::instance();
    auto fail=[&](const char* reason){return new_exception(env,"java/lang/SecurityException",reason);};
    auto result=[&](bool value)->jobject {jclass type=env->FindClass("java/lang/Boolean");return type?env->GetStaticObjectField(type,env->GetStaticFieldID(type,value?"TRUE":"FALSE","Ljava/lang/Boolean;")):nullptr;};
    if(!std::strcmp(command,"HostInstall")) {
        HIMITSU_LOG_INFO("HostGuard","Registering shutdown coordinator");
        if(!authenticated_host_call(env,-1,"registerShutdownHook","(Ljava/nio/file/Path;)V"))return fail("Authenticated bootstrap required");
        if(!first || !env->IsInstanceOf(first,env->FindClass("java/lang/Thread")))return fail("Shutdown Thread required");
        State::ReferenceRead read(state,env);if(read->shutdown_hook)return fail("Shutdown hook already registered");
        auto owned=env->NewGlobalRef(first);if(!owned)return himitsu::jvm::take_exception(env);
        auto next=std::make_unique<State::References>(*read.get());next->shutdown_hook=owned;
        if(!state.publish_references(read.get(),next)){env->DeleteGlobalRef(owned);return fail("Concurrent host install rejected");}
        HIMITSU_LOG_INFO("HostGuard","Shutdown coordinator pinned");
        return result(true);
    }
    if(!std::strcmp(command,"HostPolicy")) {
        HIMITSU_LOG_INFO("HostGuard","Validating startup process policy");
        if(!authenticated_host_call(env,-1,"registerShutdownHook","(Ljava/nio/file/Path;)V"))return fail("Authenticated bootstrap required");
        State::ReferenceRead read(state,env);
        if(!first || !env->IsSameObject(first,read->shutdown_hook) || host_policy_ready.load())return fail("Host policy is startup-only");
        if(!second || !env->IsInstanceOf(second,env->FindClass("[Ljava/lang/String;")))return fail("Exact process rules required");
        auto array=static_cast<jobjectArray>(second);auto count=env->GetArrayLength(array);if(count%10 || count>1280)return fail("Invalid process rule count");
        auto rules=std::make_shared<std::vector<ProcessRule>>();
        for(jsize i=0;i<count;i+=10) {
            ProcessRule rule;std::wstring* fields[]{&rule.kind,&rule.source,&rule.source_hash,&rule.program,&rule.program_hash,&rule.arguments,&rule.directory,&rule.verb,&rule.target,&rule.child_arguments};
            for(jsize j=0;j<10;++j){auto value=static_cast<jstring>(env->GetObjectArrayElement(array,i+j));*fields[j]=wide(env,value);env->DeleteLocalRef(value);}
            if((rule.kind!=L"java"&&rule.kind!=L"native"&&rule.kind!=L"shell") || !hash_valid(rule.source_hash)
                || !hash_valid(rule.program_hash) || rule.arguments.find(L'\0')!=std::wstring::npos || rule.directory.empty())return fail("Invalid exact process rule");
            std::wstring canonical,hash;HANDLE source=pinned_file(rule.source,canonical,&hash);
            if(!source || hash!=rule.source_hash){close_pins(source,nullptr);return fail("Process source identity mismatch");}rule.source=canonical;CloseHandle(source);
            {HANDLE program=pinned_file(rule.program,canonical,&hash);
                if(!program || hash!=rule.program_hash){close_pins(program,nullptr);return fail("Process program identity mismatch");}rule.program=canonical;CloseHandle(program);
            }
            if(rule.kind==L"shell" && (rule.target.empty()||rule.verb.empty()))return fail("Shell action requires exact target, verb and child program");
            rule.directory=working_directory(rule.directory.c_str());rules->push_back(std::move(rule));
        }
        std::atomic_store_explicit(&process_rules,std::shared_ptr<const std::vector<ProcessRule>>(rules),std::memory_order_release);
        host_policy_ready.store(true,std::memory_order_release);HIMITSU_LOG_INFO("HostGuard","Policy installed: exact_rules=%zu attach=disabled",rules->size());return result(true);
    }
    if(!std::strcmp(command,"HostDenied")) {
        if(!authenticated_host_call(env,2,"dispatchOrdinary","(Lnet/minecraftforge/eventbus/EventBus;Lnet/minecraftforge/eventbus/api/Event;Lnet/minecraftforge/eventbus/api/IEventBusInvokeDispatcher;)V"))return fail("Authenticated event dispatcher required");
        for(unsigned attempt=0;attempt<8;++attempt) {
            State::ReferenceRead read(state,env);std::size_t at=0;for(;at<read->exit_denials.size();++at)if(env->IsSameObject(first,read->exit_denials[at]))break;
            if(at==read->exit_denials.size())return result(false);auto next=std::make_unique<State::References>(*read.get());next->exit_denials.erase(next->exit_denials.begin()+at);
            if(state.publish_references(read.get(),next))return result(true);
        }
        return result(false);
    }
    if(!std::strcmp(command,"HostShutdown")) {
        if(!authenticated_host_call(env,-1,"shutdown","()V"))return fail("Authenticated shutdown coordinator required");
        State::ReferenceRead read(state,env);jthread current=nullptr;
        if(himitsu::jvm::trusted_current_thread(&current)!=JVMTI_ERROR_NONE)return fail("Cannot identify shutdown thread");
        bool same=read->shutdown_hook&&env->IsSameObject(current,read->shutdown_hook);env->DeleteLocalRef(current);
        jclass hooks=env->FindClass("java/lang/ApplicationShutdownHooks");jfieldID field=hooks?env->GetStaticFieldID(hooks,"hooks","Ljava/util/IdentityHashMap;"):nullptr;
        jobject pending=field?env->GetStaticObjectField(hooks,field):nullptr;
        bool closing=same&&field&&!pending&&!env->ExceptionCheck();if(pending)env->DeleteLocalRef(pending);
        if(!closing)return fail("JVM shutdown has not begun");shutdown_permit=true;return result(true);
    }
    if(std::strcmp(command,"HostLifecycle") || !first || !second)return fail("Invalid host lifecycle operation");
    auto name=wide(env,static_cast<jstring>(first));bool client=name.rfind(L"client-",0)==0;int owner=client?0:1;
    bool event=name==(client?L"client-register":L"server-register");
    bool begin=event||name==(client?L"client-run":L"server-run");
    const char* hook=event?(client?"clientCore":"serverStarting"):begin?(client?"clientRun":"serverRun"):name==L"client-stop"?"clientStop":name==L"client-close"?"clientClose":name==L"server-stop"?"serverStop":name==L"server-exit"?"serverExit":"";
    const char* descriptor=event?(client?"()V":"(Lnet/minecraftforge/event/server/ServerStartingEvent;)V"):client?"(Lnet/minecraft/client/Minecraft;)V":name==L"server-stop"?"(Lnet/minecraft/server/MinecraftServer;Z)V":name==L"server-exit"?"(Lnet/minecraft/server/dedicated/DedicatedServer;)V":"(Lnet/minecraft/server/MinecraftServer;)V";
    if(!*hook || !authenticated_host_call(env,owner,hook,descriptor))return fail("Authenticated lifecycle hook required");
    const char* method=begin?(client?"run":"runServer"):name==L"client-stop"?"stop":name==L"client-close"?"destroy":name==L"server-stop"?"halt":"onServerExit";
    const char* alias=begin?(client?"m_91374_":"m_130011_"):name==L"client-stop"?"m_91395_":name==L"client-close"?"m_91393_":name==L"server-stop"?"m_7570_":"m_6988_";
    if(!begin && natural_shutdown(env)) {
        State::ReferenceRead read(state,env);
        if(env->IsSameObject(second,read->host_objects[owner]))return result(true);
    }
    if(env->PushLocalFrame(1024)<0)return himitsu::jvm::take_exception(env);
    bool valid=false;
    {State::ReferenceRead read(state,env);valid=event?lifecycle_event(env,*read.get(),owner,second):lifecycle_stack(env,*read.get(),owner,method,alias,begin);}
    env->PopLocalFrame(nullptr);if(env->ExceptionCheck())return himitsu::jvm::take_exception(env);
    if(!valid)return fail("Lifecycle request did not originate in the game loop");
    jthread current=nullptr;if(himitsu::jvm::trusted_current_thread(&current)!=JVMTI_ERROR_NONE)return fail("Missing core thread identity");
    jobject thread=env->NewGlobalRef(current),object=env->NewGlobalRef(second);env->DeleteLocalRef(current);
    if(!thread||!object){if(thread)env->DeleteGlobalRef(thread);if(object)env->DeleteGlobalRef(object);return himitsu::jvm::take_exception(env);}
    bool ok=false;
    for(unsigned attempt=0;attempt<8&&!state.shutting_down();++attempt) {
        State::ReferenceRead read(state,env);auto next=std::make_unique<State::References>(*read.get());
        if(begin) {
            if(read->host_objects[owner] && !env->IsSameObject(read->host_objects[owner],object))break;
            if(read->host_threads[owner] && !env->IsSameObject(read->host_threads[owner],thread))break;
            if(read->host_objects[owner]) {ok=true;break;}
            next->host_objects[owner]=object;next->host_threads[owner]=thread;next->host_phase[owner]=1;++next->host_generation[owner];
        } else {
            if(!env->IsSameObject(read->host_objects[owner],object)||!env->IsSameObject(read->host_threads[owner],thread))break;
            next->host_phase[owner]=name==L"client-close"||name==L"server-exit"?3:2;
            // A running integrated server never grants process-exit authority.
            if(next->host_phase[owner]==3 && (client||!read->host_objects[0])) {exit_owner=owner;exit_generation=next->host_generation[owner];}
        }
        if(state.publish_references(read.get(),next)){ok=true;if(begin){thread=nullptr;object=nullptr;}break;}
        exit_generation=0;exit_owner=-1;
    }
    if(thread)env->DeleteGlobalRef(thread);if(object)env->DeleteGlobalRef(object);
    if(!ok)return fail("Lifecycle identity or generation conflict");
    if(begin) {jthread self=nullptr;if(himitsu::jvm::trusted_current_thread(&self)==JVMTI_ERROR_NONE){auto protected_result=himitsu::jvm::protect_thread(env,self);env->DeleteLocalRef(self);return protected_result;}}
    return result(true);
}

ThreadHookMaintenance::ThreadHookMaintenance() {++maintenance_depth;}
ThreadHookMaintenance::~ThreadHookMaintenance() {--maintenance_depth;}
bool same_thread_handle(HANDLE first,HANDLE second) {return compare_handles && first && second && compare_handles(first,second);}
bool register_native_thread(HANDLE thread) {
    if(!compare_handles || !thread) return false;
    HANDLE owned=nullptr;
    if(!DuplicateHandle(GetCurrentProcess(),thread,GetCurrentProcess(),&owned,SYNCHRONIZE,FALSE,0)) return false;
    auto& state=State::instance(); bool success=false;
    while(!state.shutting_down()) {
        State::ReferenceRead read(state);
        if(std::any_of(read->threads.begin(),read->threads.end(),[&](const auto& e){return same_thread_handle(e.os_thread,owned);})) {success=true;break;}
        auto next=std::make_unique<State::References>(*read.get());next->threads.push_back({nullptr,owned});
        if(state.publish_references(read.get(),next)) {owned=nullptr;success=true;break;}
    }
    if(owned) CloseHandle(owned); return success;
}
void unregister_native_thread(HANDLE thread) {
    auto& state=State::instance();
    for(;;) {
        State::ReferenceRead read(state);
        auto next=std::make_unique<State::References>(*read.get());
        std::erase_if(next->threads,[&](const auto& entry){return same_thread_handle(entry.os_thread,thread);});
        if(next->threads.size()==read->threads.size() || state.publish_references(read.get(),next,true)) return;
    }
}
bool start_thread_guard() {
    AcquireSRWLockExclusive(&hook_lock);
    if(installed.load(std::memory_order_acquire)) {ReleaseSRWLockExclusive(&hook_lock);return true;}
    if(!thread_context(true)){ReleaseSRWLockExclusive(&hook_lock);HIMITSU_LOG_ERROR("HostGuard","Win32 TLS unavailable");return false;}
    HMODULE base=GetModuleHandleW(L"kernelbase.dll");
    compare_handles=base?reinterpret_cast<CompareFn>(GetProcAddress(base,"CompareObjectHandles")):nullptr;
    if(!compare_handles) HIMITSU_LOG_ERROR("ThreadGuard","CompareObjectHandles unavailable; exact OS thread protection cannot be installed");
    HMODULE jvm=GetModuleHandleW(L"jvm.dll");
    if(jvm) {
        jvm_begin=reinterpret_cast<std::uintptr_t>(jvm);
        auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(jvm);
        auto* nt=reinterpret_cast<IMAGE_NT_HEADERS*>(jvm_begin+dos->e_lfanew);
        jvm_end=jvm_begin+nt->OptionalHeader.SizeOfImage;
    }
    HMODULE shell=GetModuleHandleW(L"shell32.dll");if(!shell)shell=LoadLibraryExW(L"shell32.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    auto rtl=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlExitUserProcess");
    bool exit_range=rtl && himitsu::jvm::native_function_baseline(reinterpret_cast<void*>(rtl),rtl_exit_ranges);
    auto rtl_thread=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlExitUserThread");
    exit_range=exit_range && rtl_thread && himitsu::jvm::native_function_baseline(reinterpret_cast<void*>(rtl_thread),rtl_thread_exit_ranges);
    auto initialized=MH_Initialize();
    bool ready=initialized==MH_OK || initialized==MH_ERROR_ALREADY_INITIALIZED;
    bool success=ready && compare_handles && jvm && shell && exit_range
        && prepare(stop_hook,reinterpret_cast<void*>(guarded_stop))
        && prepare(suspend_hook,reinterpret_cast<void*>(guarded_suspend))
        && prepare(all_threads_hook,reinterpret_cast<void*>(guarded_threads))
        && prepare(base_suspend,reinterpret_cast<void*>(guarded_base_suspend))
        && prepare(base_terminate,reinterpret_cast<void*>(guarded_base_terminate))
        && prepare(kernel_suspend,reinterpret_cast<void*>(guarded_kernel_suspend))
        && prepare(kernel_terminate,reinterpret_cast<void*>(guarded_kernel_terminate))
        && prepare(nt_suspend,reinterpret_cast<void*>(guarded_nt_suspend)) && prepare(nt_terminate,reinterpret_cast<void*>(guarded_nt_terminate))
        && prepare(attach_hook,reinterpret_cast<void*>(guarded_attach)) && prepare(before_halt,reinterpret_cast<void*>(guarded_before_halt)) && prepare(halt_hook,reinterpret_cast<void*>(guarded_halt))
        && prepare(base_process_end,reinterpret_cast<void*>(guarded_base_process_end)) && prepare(kernel_process_end,reinterpret_cast<void*>(guarded_kernel_process_end)) && prepare(nt_process_end,reinterpret_cast<void*>(guarded_nt_process_end))
        && prepare(java_process,reinterpret_cast<void*>(guarded_java_process))
        && prepare(base_create_w,reinterpret_cast<void*>(guarded_base_create_w)) && prepare(kernel_create_w,reinterpret_cast<void*>(guarded_kernel_create_w))
        && prepare(base_create_a,reinterpret_cast<void*>(guarded_base_create_a)) && prepare(kernel_create_a,reinterpret_cast<void*>(guarded_kernel_create_a))
        && prepare(shell_w,reinterpret_cast<void*>(guarded_shell_w)) && prepare(shell_a,reinterpret_cast<void*>(guarded_shell_a))
        && prepare(shell_ex_w,reinterpret_cast<void*>(guarded_shell_ex_w)) && prepare(shell_ex_a,reinterpret_cast<void*>(guarded_shell_ex_a));
    // All original addresses exist before the first detour can run.
    if(success) success=enable(true);
    if(!success && ready) enable(false);
    installed.store(success,std::memory_order_release);admitting.store(success,std::memory_order_release);
    HIMITSU_LOG_INFO("ThreadGuard","JVM/Win32 relocated hooks ready=%d object_identity=%d",success,compare_handles!=nullptr);
    ReleaseSRWLockExclusive(&hook_lock);return success;
}
bool stop_thread_guard(std::uint64_t deadline) {
    admitting.store(false,std::memory_order_release);
    if(GetTickCount64()>deadline) return false;
    AcquireSRWLockExclusive(&hook_lock);
    bool instrumentation=stop_instrumentation_entries(deadline);
    bool success=(!installed.load(std::memory_order_acquire) || enable(false,deadline)) && instrumentation;
    if(success) installed.store(false,std::memory_order_release);
    // Disabled entries may still have in-flight callers; keep originals and trampolines.
    ReleaseSRWLockExclusive(&hook_lock);return success;
}
}
