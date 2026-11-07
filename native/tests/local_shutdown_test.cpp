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
std::atomic<int> recovery_visits{0};
namespace himitsu::core::log {
void write(Level,const char*,const char* format,...) {if(std::strncmp(format,"Function rva=",13)==0)++recovery_visits;}
void shutdown() {}
}
namespace himitsu::validation {
[[noreturn]] void terminate_rejected(unsigned long) {std::abort();}
namespace lease {bool valid(){return lease_stops==0;}void stop(){CHECK(hooks_stopped==4);++lease_stops;}}
}
namespace himitsu::platform::windows {
#ifndef HIMITSU_REGION_CHECK
std::uint64_t register_guarded_code(const char*,std::vector<himitsu::jvm::NativeCodeRange>){return 1;}
bool apply_owned_code(void*,unsigned char*,std::size_t){return true;}
void request_module_guard_stop(){++signals;}
bool stop_module_guard(std::uint64_t deadline){return stopped(deadline);}
#endif
bool stop_thread_guard(std::uint64_t deadline){return stopped(deadline);}
bool uninstall_swap_buffers_hook(std::uint64_t deadline){return stopped(deadline);}
}
namespace himitsu::jvm {
void request_jvmti_guard_stop(){++signals;}
bool shutdown_jvmti_guard(std::uint64_t deadline){return stopped(deadline);}
}
// Only this test translation unit redirects failure points; himitsu.dll has no test switches.
int protect_calls=0,fail_protect_call=0;
bool fail_write=false,fail_flush=false,fail_readback=false,wrote=false;
BOOL WINAPI recovery_protect(void* address,SIZE_T size,DWORD protection,PDWORD prior) {
    if(++protect_calls==fail_protect_call){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    return VirtualProtect(address,size,protection,prior);
}
BOOL WINAPI recovery_flush(HANDLE process,const void* address,SIZE_T size) {
    return fail_flush?FALSE:FlushInstructionCache(process,address,size);
}
BOOL WINAPI recovery_write(HANDLE process,void* address,const void* source,SIZE_T size,SIZE_T* count) {
    if(fail_write){if(count)*count=0;return FALSE;}
    auto ok=WriteProcessMemory(process,address,source,size,count);if(ok)wrote=true;return ok;
}
BOOL WINAPI recovery_read(HANDLE process,const void* address,void* output,SIZE_T size,SIZE_T* count) {
    if(fail_readback && wrote){if(count)*count=0;return FALSE;}
    return ReadProcessMemory(process,address,output,size,count);
}
HMODULE fixture_modules[2]{};
int fixture_pins[2]{};
std::wstring fixture_paths[2];
DWORD WINAPI fixture_module_name(HMODULE module,LPWSTR output,DWORD size) {
    for(int i=0;i<2;++i)if(module && module==fixture_modules[i]) {
        if(fixture_paths[i].size()+1>size)return size;
        std::wcscpy(output,fixture_paths[i].c_str());return static_cast<DWORD>(fixture_paths[i].size());
    }
    return GetModuleFileNameW(module,output,size);
}
BOOL WINAPI fixture_pin(DWORD flags,LPCWSTR address,HMODULE* output) {
    for(int i=0;i<2;++i)if(fixture_modules[i] && reinterpret_cast<const void*>(address)==fixture_modules[i]){*output=fixture_modules[i];++fixture_pins[i];return TRUE;}
    return GetModuleHandleExW(flags,address,output);
}
BOOL WINAPI fixture_free(HMODULE module) {for(int i=0;i<2;++i)if(module && fixture_modules[i]==module){CHECK(fixture_pins[i]>0);--fixture_pins[i];return TRUE;}return FreeLibrary(module);}
HMODULE WINAPI fixture_module(LPCSTR name) {
    if(!std::strcmp(name,"r22a.dll"))return fixture_modules[0];if(!std::strcmp(name,"r22b.dll"))return fixture_modules[1];return GetModuleHandleA(name);
}
FARPROC WINAPI fixture_export(HMODULE module,LPCSTR name) {
    for(auto value:fixture_modules)if(module && value==module)
        return reinterpret_cast<FARPROC>(reinterpret_cast<unsigned char*>(module)+0x1000);
    return GetProcAddress(module,name);
}
#define GetModuleFileNameW fixture_module_name
#define GetModuleHandleExW fixture_pin
#define FreeLibrary fixture_free
#define GetModuleHandleA fixture_module
#define GetProcAddress fixture_export
#define VirtualProtect recovery_protect
#define FlushInstructionCache recovery_flush
#define WriteProcessMemory recovery_write
#define ReadProcessMemory recovery_read
#include "../src/jvm/late_recovery.cpp"
#undef VirtualProtect
#undef FlushInstructionCache
#undef WriteProcessMemory
#undef ReadProcessMemory
#undef GetModuleFileNameW
#undef GetModuleHandleExW
#undef FreeLibrary
#undef GetModuleHandleA
#undef GetProcAddress

struct RecoveryFixture {
    std::vector<unsigned char> file=std::vector<unsigned char>(0x5400);
    unsigned char* live=static_cast<unsigned char*>(VirtualAlloc(nullptr,0x6000,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    static constexpr ULONGLONG preferred=0x180000000ull;
    static std::size_t offset(DWORD rva) {return rva<0x400?rva:rva<0x3000?rva-0x1000+0x400:rva<0x5000?rva-0x3000+0x2400:rva-0x5000+0x4400;}
    template<class T> void put(DWORD rva,const T& value) {std::memcpy(file.data()+offset(rva),&value,sizeof(value));}
    void code(DWORD rva,std::initializer_list<unsigned char> bytes) {std::copy(bytes.begin(),bytes.end(),file.begin()+offset(rva));}
    RecoveryFixture() {
        CHECK(live);
        IMAGE_DOS_HEADER dos{};dos.e_magic=IMAGE_DOS_SIGNATURE;dos.e_lfanew=0x80;put(0,dos);
        IMAGE_NT_HEADERS64 nt{};nt.Signature=IMAGE_NT_SIGNATURE;nt.FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections=3;nt.FileHeader.TimeDateStamp=123;nt.FileHeader.SizeOfOptionalHeader=sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;nt.OptionalHeader.ImageBase=preferred;
        nt.OptionalHeader.SizeOfHeaders=0x400;nt.OptionalHeader.SizeOfImage=0x6000;
        nt.OptionalHeader.SectionAlignment=0x1000;nt.OptionalHeader.FileAlignment=0x200;
        nt.OptionalHeader.NumberOfRvaAndSizes=IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]={0x3000,sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)};
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]={0x5000,12};put(0x80,nt);
        IMAGE_SECTION_HEADER sections[3]{};
        const DWORD vas[]={0x1000,0x3000,0x5000},raws[]={0x400,0x2400,0x4400},sizes[]={0x2000,0x2000,0x1000};
        for(int i=0;i<3;i++) {sections[i].VirtualAddress=vas[i];sections[i].Misc.VirtualSize=sizes[i];sections[i].PointerToRawData=raws[i];sections[i].SizeOfRawData=sizes[i];sections[i].Characteristics=IMAGE_SCN_MEM_READ|(i==0?IMAGE_SCN_MEM_EXECUTE:0);}
        std::memcpy(file.data()+0x80+sizeof(nt),sections,sizeof(sections));
        std::fill(file.begin()+0x400,file.begin()+0x2400,0xCC);code(0x1000,{0xB8,42,0,0,0,0xC3});
        IMAGE_RUNTIME_FUNCTION_ENTRY function{};function.BeginAddress=0x1000;function.EndAddress=0x1006;function.UnwindInfoAddress=0x3100;put(0x3000,function);
        code(0x3100,{1,0,0,0});
        put(0x3300,preferred+0x1000);put(0x3308,preferred+0x1000);
        IMAGE_BASE_RELOCATION reloc{0x3000,12};put(0x5000,reloc);WORD entries[]={0xA300,0xA308};std::memcpy(file.data()+offset(0x5008),entries,sizeof(entries));
        materialize();
    }
    void materialize() {
        DWORD prior=0;CHECK(VirtualProtect(live,0x6000,PAGE_READWRITE,&prior));
        std::memcpy(live,file.data(),0x400);std::memcpy(live+0x1000,file.data()+0x400,0x2000);
        std::memcpy(live+0x3000,file.data()+0x2400,0x2000);std::memcpy(live+0x5000,file.data()+0x4400,0x1000);
        CHECK(VirtualProtect(live+0x1000,0x2000,PAGE_EXECUTE_READ,&prior));
    }
    void corrupt(DWORD rva,unsigned char value) {DWORD prior=0;CHECK(VirtualProtect(live+rva,1,PAGE_EXECUTE_READWRITE,&prior));live[rva]=value;DWORD ignored=0;CHECK(VirtualProtect(live+rva,1,prior,&ignored));}
    ~RecoveryFixture(){if(live)VirtualFree(live,0,MEM_RELEASE);}
};
void recovery_checks() {
    auto no_image=[](std::vector<unsigned char> bytes,void* live){DiskImage image;CHECK(!image.initialize(std::move(bytes),static_cast<HMODULE>(live)));};
    RecoveryFixture fixture;DiskImage image;CHECK(image.initialize(fixture.file,reinterpret_cast<HMODULE>(fixture.live)));
    CHECK(image.raw_rva(0x1000,6) && !image.raw_rva(0x2FFF,2) && !image.raw_rva(0x3FF,2));
    CHECK(!image.raw_rva(0xFFFFFFFFu,8) && !image.raw_rva(0x1000,SIZE_MAX));
    CHECK(image.restore_function(0x1000,fixture.live+0x1000)==RecoveryResult::unchanged);
    {DWORD prior=0;CHECK(VirtualProtect(fixture.live+0x1000,0x1000,PAGE_READONLY,&prior));
        CHECK(image.restore_function(0x1000,fixture.live+0x1000)==RecoveryResult::failed);DWORD ignored=0;CHECK(VirtualProtect(fixture.live+0x1000,0x1000,prior,&ignored));}
    fixture.corrupt(0x1001,9);CHECK(image.restore_function(0x1001,fixture.live+0x1001)==RecoveryResult::unsupported && fixture.live[0x1001]==9);
    CHECK(image.restore_function(0x1000,fixture.live+0x1000,false)==RecoveryResult::failed && fixture.live[0x1001]==9);
    CHECK(image.restore_function(0x1000,fixture.live+0x1000,true)==RecoveryResult::repaired && fixture.live[0x1001]==42);
    no_image(std::vector<unsigned char>(10),fixture.live);
    auto broken=fixture.file;auto* dos=reinterpret_cast<IMAGE_DOS_HEADER*>(broken.data());dos->e_lfanew=INT32_MAX;no_image(broken,fixture.live);
    broken=fixture.file;auto* nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(broken.data()+0x80);nt->FileHeader.SizeOfOptionalHeader=4;no_image(broken,fixture.live);
    broken=fixture.file;nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(broken.data()+0x80);nt->FileHeader.TimeDateStamp++;no_image(broken,fixture.live);
    {RecoveryFixture relocated;auto* header=reinterpret_cast<IMAGE_NT_HEADERS64*>(relocated.live+0x80);
        header->OptionalHeader.ImageBase=reinterpret_cast<ULONGLONG>(relocated.live);DiskImage checked;
        CHECK(checked.initialize(relocated.file,reinterpret_cast<HMODULE>(relocated.live)));
        header->OptionalHeader.ImageBase++;no_image(relocated.file,relocated.live);}
    broken=fixture.file;auto* section=reinterpret_cast<IMAGE_SECTION_HEADER*>(broken.data()+0x80+sizeof(IMAGE_NT_HEADERS64));section[0].PointerToRawData=0xFFFFFFF0u;no_image(broken,fixture.live);
    broken=fixture.file;section=reinterpret_cast<IMAGE_SECTION_HEADER*>(broken.data()+0x80+sizeof(IMAGE_NT_HEADERS64));section[1].VirtualAddress=0x2000;no_image(broken,fixture.live);
    {RecoveryFixture zero;auto* row=reinterpret_cast<IMAGE_SECTION_HEADER*>(zero.file.data()+0x80+sizeof(IMAGE_NT_HEADERS64));row[0].SizeOfRawData=0x1000;zero.materialize();DiskImage checked;CHECK(checked.initialize(zero.file,reinterpret_cast<HMODULE>(zero.live)));CHECK(!checked.raw_rva(0x2000,1));}
    broken=fixture.file;nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(broken.data()+0x80);nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size=11;no_image(broken,fixture.live);
    broken=fixture.file;reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(broken.data()+RecoveryFixture::offset(0x3000))->EndAddress=0x3001;no_image(broken,fixture.live);
    {RecoveryFixture invalid;invalid.code(0x3100,{0,0,0,0});invalid.materialize();DiskImage checked;CHECK(checked.initialize(invalid.file,reinterpret_cast<HMODULE>(invalid.live)));CHECK(checked.restore_function(0x1000,invalid.live+0x1000)==RecoveryResult::unsupported);}
    {RecoveryFixture cycle;cycle.code(0x3100,{0x21,0,0,0});IMAGE_RUNTIME_FUNCTION_ENTRY parent{};parent.BeginAddress=0x1000;parent.EndAddress=0x1006;parent.UnwindInfoAddress=0x3100;cycle.put(0x3104,parent);cycle.materialize();DiskImage checked;CHECK(checked.initialize(cycle.file,reinterpret_cast<HMODULE>(cycle.live)));CHECK(checked.restore_function(0x1000,cycle.live+0x1000)==RecoveryResult::unsupported);}
    {RecoveryFixture leaf;leaf.code(0x1010,{0x85,0xC0,0x74,6,0xB8,1,0,0,0,0xC3,0x31,0xC0,0xC3});leaf.materialize();DiskImage checked;CHECK(checked.initialize(leaf.file,reinterpret_cast<HMODULE>(leaf.live)));CHECK(checked.restore_function(0x1010,leaf.live+0x1010)==RecoveryResult::unchanged);}
    {RecoveryFixture leaf;leaf.code(0x1010,{0xEB,3,0xCC,0xCC,0xCC,0xB8,42,0,0,0,0xC3});leaf.materialize();DiskImage checked;CHECK(checked.initialize(leaf.file,reinterpret_cast<HMODULE>(leaf.live)));leaf.corrupt(0x1012,0x90);leaf.corrupt(0x1016,7);CHECK(checked.restore_function(0x1010,leaf.live+0x1010)==RecoveryResult::repaired);CHECK(leaf.live[0x1012]==0x90 && leaf.live[0x1016]==42);}
    {RecoveryFixture tail;tail.code(0x1200,{0x85,0xC0,0x74,1,0xC3,0xE9,0,0,0,0});std::int32_t jump=0x1000-0x120A;tail.put(0x1206,jump);tail.materialize();
        DiskImage checked;CHECK(checked.initialize(tail.file,reinterpret_cast<HMODULE>(tail.live)));
        std::vector<std::pair<DWORD,RecoveryResult>> dependencies;
        CHECK(checked.restore_function(0x1200,tail.live+0x1200,true,&dependencies)==RecoveryResult::unchanged && dependencies.size()==1);
        CHECK(checked.restore_function(0x1200,tail.live+0x1200,true,&dependencies)==RecoveryResult::unchanged && dependencies.size()==1);
        tail.corrupt(0x1001,7);tail.corrupt(0x1201,0xC1);
        CHECK(checked.restore_function(0x1200,tail.live+0x1200)==RecoveryResult::failed && tail.live[0x1001]==7 && tail.live[0x1201]==0xC1);}
    for(int mode=0;mode<3;++mode) {
        RecoveryFixture tail;tail.code(0x1200,{0xE9,0,0,0,0});std::int32_t jump=(mode==0?0x1001:mode==1?0x1100:0x1000)-0x1205;tail.put(0x1201,jump);
        if(mode==2)tail.code(0x3100,{0,0,0,0});tail.materialize();DiskImage checked;CHECK(checked.initialize(tail.file,reinterpret_cast<HMODULE>(tail.live)));
        CHECK(checked.restore_function(0x1200,tail.live+0x1200)==RecoveryResult::unsupported);
    }
    for(auto code:{std::vector<unsigned char>{0xEB,0xFE},std::vector<unsigned char>{0xE8,0,0,0,0,0xC3},std::vector<unsigned char>{0xFF,0xE0},
            std::vector<unsigned char>{0x75,1,0xB8,0x31,0xC0,0xC3,0,0xC3},std::vector<unsigned char>{0xE9,0,0x10,0,0},std::vector<unsigned char>(32,0x66)}) {
        RecoveryFixture bad;std::copy(code.begin(),code.end(),bad.file.begin()+RecoveryFixture::offset(0x1010));bad.materialize();DiskImage checked;CHECK(checked.initialize(bad.file,reinterpret_cast<HMODULE>(bad.live)));
        CHECK(checked.restore_function(0x1010,bad.live+0x1010)==RecoveryResult::unsupported);CHECK(!std::memcmp(bad.live+0x1010,code.data(),code.size()));
    }
    for(int mode=0;mode<4;mode++) {
        broken=fixture.file;auto* block=reinterpret_cast<IMAGE_BASE_RELOCATION*>(broken.data()+RecoveryFixture::offset(0x5000));
        if(mode==0)block->SizeOfBlock=6;else if(mode==1)block->SizeOfBlock=16;
        else if(mode==2){WORD wrong=0x3300;std::memcpy(broken.data()+RecoveryFixture::offset(0x5008),&wrong,2);}
        else {WORD duplicate=0xA300;std::memcpy(broken.data()+RecoveryFixture::offset(0x500A),&duplicate,2);}
        no_image(broken,fixture.live);
    }
    {RecoveryFixture reloc;reloc.code(0x1020,{0x48,0xB8,0,0,0,0,0,0,0,0,0xC3});reloc.put(0x1022,RecoveryFixture::preferred+0x3200);
        IMAGE_BASE_RELOCATION block{0x1000,12};reloc.put(0x5000,block);WORD target=0xA022,zero=0;reloc.put(0x5008,target);reloc.put(0x500A,zero);reloc.materialize();
        DiskImage checked;CHECK(checked.initialize(reloc.file,reinterpret_cast<HMODULE>(reloc.live)));CHECK(checked.restore_function(0x1020,reloc.live+0x1020)==RecoveryResult::repaired);
        std::uint64_t value=0;std::memcpy(&value,reloc.live+0x1022,8);CHECK(value==reinterpret_cast<std::uint64_t>(reloc.live+0x3200));}
    {RecoveryFixture overlap;IMAGE_BASE_RELOCATION block{0x1000,12};overlap.put(0x5000,block);WORD target=0xA001,zero=0;overlap.put(0x5008,target);overlap.put(0x500A,zero);overlap.materialize();DiskImage checked;CHECK(checked.initialize(overlap.file,reinterpret_cast<HMODULE>(overlap.live)));CHECK(checked.restore_function(0x1000,overlap.live+0x1000)==RecoveryResult::failed);}
    fixture.corrupt(0x1001,5);recovery_visits=0;
    CHECK(!restore_table_functions(image,0x3300,2,{}, {0,1,1}));CHECK(recovery_visits==1 && fixture.live[0x1001]==5);
    recovery_visits=0;CHECK(!restore_table_functions(image,0x3300,2,{0},{1}));CHECK(recovery_visits==1 && fixture.live[0x1001]==5);
    CHECK(image.restore_function(0x1000,fixture.live+0x1000,true)==RecoveryResult::repaired);
    CHECK(!restore_table_functions(image,0x3300,2,{}, {SIZE_MAX}));
    CHECK(restore_pointer_table(image,0x3300,reinterpret_cast<void**>(fixture.live+0x3300),2));
    CHECK(*reinterpret_cast<void**>(fixture.live+0x3300)==fixture.live+0x1000);
    void* values[]={fixture.live+0x1000,fixture.live+0x1000};CHECK(!image.write_pointers(fixture.live+0x3301,values,sizeof(values)));
    DWORD prior=0;CHECK(VirtualProtect(fixture.live+0x3000,0x1000,PAGE_READONLY,&prior));CHECK(VirtualProtect(fixture.live+0x4000,0x1000,PAGE_EXECUTE_READ,&prior));
    protect_calls=0;fail_protect_call=2;CHECK(!image.write_pointers(fixture.live+0x3FF8,values,sizeof(values)));fail_protect_call=0;
    MEMORY_BASIC_INFORMATION page{};CHECK(VirtualQuery(fixture.live+0x3000,&page,sizeof(page)) && page.Protect==PAGE_READONLY);
    CHECK(*reinterpret_cast<void**>(fixture.live+0x3FF8)==nullptr && *reinterpret_cast<void**>(fixture.live+0x4000)==nullptr);
    CHECK(image.write_pointers(fixture.live+0x3FF8,values,sizeof(values)));
    CHECK(VirtualQuery(fixture.live+0x4000,&page,sizeof(page)) && page.Protect==PAGE_EXECUTE_READ);
    for(int mode=0;mode<4;mode++) {
        fixture.corrupt(0x1001,17);protect_calls=0;fail_write=mode==0;fail_flush=mode==1;fail_protect_call=mode==2?2:0;fail_readback=mode==3;wrote=false;
        CHECK(image.restore_function(0x1000,fixture.live+0x1000)==RecoveryResult::failed);
        if(mode==0)CHECK(fixture.live[0x1001]==17);
        fail_write=fail_flush=fail_readback=false;fail_protect_call=0;
        CHECK(VirtualProtect(fixture.live+0x1000,0x2000,PAGE_EXECUTE_READ,&prior));
    }
    CHECK(VirtualProtect(fixture.live,0x1000,PAGE_NOACCESS,&prior));DiskImage unreadable;CHECK(!unreadable.initialize(fixture.file,reinterpret_cast<HMODULE>(fixture.live)));CHECK(VirtualProtect(fixture.live,0x1000,prior,&prior));
    {
        RecoveryFixture first,second;RecoveryFixture* fixtures[]{&first,&second};
        auto exports=[](RecoveryFixture& target,const char* forward) {
            auto* nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(target.file.data()+0x80);nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]={0x3400,0x100};
            IMAGE_EXPORT_DIRECTORY table{};table.Base=1;table.NumberOfFunctions=table.NumberOfNames=1;table.AddressOfFunctions=0x3460;table.AddressOfNames=0x3480;table.AddressOfNameOrdinals=0x3490;target.put(0x3400,table);
            DWORD function=forward?0x34C0:0x1000,name=0x34A0;WORD ordinal=0;target.put(0x3460,function);target.put(0x3480,name);target.put(0x3490,ordinal);
            std::memcpy(target.file.data()+RecoveryFixture::offset(name),"check",6);
            if(forward)std::memcpy(target.file.data()+RecoveryFixture::offset(function),forward,std::strlen(forward)+1);
            target.materialize();
        };
        exports(first,"r22b.#1");exports(second,nullptr);
        wchar_t directory[MAX_PATH]{},path[MAX_PATH]{};CHECK(GetFullPathNameW(L"build",MAX_PATH,directory,nullptr));
        for(int i=0;i<2;i++){CHECK(GetTempFileNameW(directory,L"r22",0,path));fixture_paths[i]=path;fixture_modules[i]=reinterpret_cast<HMODULE>(fixtures[i]->live);}
        auto save=[&](int index){HANDLE file=CreateFileW(fixture_paths[index].c_str(),GENERIC_WRITE,0,nullptr,TRUNCATE_EXISTING,FILE_ATTRIBUTE_TEMPORARY,nullptr);CHECK(file!=INVALID_HANDLE_VALUE);DWORD written=0;CHECK(WriteFile(file,fixtures[index]->file.data(),static_cast<DWORD>(fixtures[index]->file.size()),&written,nullptr)&&written==fixtures[index]->file.size());CloseHandle(file);};
        save(0);save(1);std::vector<himitsu::jvm::NativeCodeRange> ranges;
        CHECK(himitsu::jvm::native_export_baseline(fixture_modules[0],"check",ranges));CHECK(ranges.size()==1&&ranges[0].address==second.live+0x1000 && fixture_pins[0]==0 && fixture_pins[1]==1);ranges.clear();CHECK(fixture_pins[1]==0);
        exports(second,"r22a.check");save(1);CHECK(!himitsu::jvm::native_export_baseline(fixture_modules[0],"check",ranges)); // Real production cycle detector.
        exports(second,"missing_module.check");save(1);CHECK(!himitsu::jvm::native_export_baseline(fixture_modules[0],"check",ranges));
        exports(first,nullptr);save(0);CHECK(himitsu::jvm::native_export_baseline(fixture_modules[0],"#1",ranges));ranges.clear();
        CHECK(!himitsu::jvm::native_export_baseline(fixture_modules[0],"#999999999999",ranges));
        for(int i=0;i<2;++i){CHECK(fixture_pins[i]==0);CHECK(DeleteFileW(fixture_paths[i].c_str()));fixture_modules[i]=nullptr;fixture_paths[i].clear();}
    }
    CHECK(!himitsu::jvm::late_recover_jni_dispatch(nullptr));CHECK(!himitsu::jvm::late_recover_jvmti_dispatch(nullptr));
    std::puts("NATIVE_RECOVERY_PASS pe_bounds directory_unwind cfg_leaf forwarded_ordinal_cycle pdata_tail_only executable_mapping no_fixed_copy relocation atomic_pointer per_region_restore write_failures verify_only dedup NO_JVM_CODE_PATCH");
}

#ifndef HIMITSU_REGION_CHECK
int main(int argc,char** argv) {
    if(argc>1 && std::strcmp(argv[1],"recovery")==0) {recovery_checks();return 0;}
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

#else
namespace himitsu::jvm {
bool expected_jvmti_dispatch(jvmtiInterface_1_*&,jvmtiInterface_1_&){return false;}
}
namespace himitsu::platform::windows {
bool register_native_thread(HANDLE){return true;}
void unregister_native_thread(HANDLE){}
std::atomic<unsigned> region_ticks{0};HANDLE region_tick_event=nullptr;
void maintain_swap_buffers_hook(){++region_ticks;if(region_tick_event)SetEvent(region_tick_event);}
}
HANDLE inspected_wake=nullptr;std::atomic<bool> saw_guard_interval{false};
DWORD WINAPI region_wait(HANDLE handle,DWORD timeout) {
    if(handle==inspected_wake){CHECK(timeout==250);saw_guard_interval=true;}
    return WaitForSingleObject(handle,timeout);
}
#define WaitForSingleObject region_wait
#include "../src/platform/windows/module_guard.cpp"
#undef WaitForSingleObject
int main() {
    using namespace himitsu::platform::windows;
    auto* storage=static_cast<unsigned char*>(VirtualAlloc(nullptr,0x4000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));CHECK(storage);
    void** slot=reinterpret_cast<void**>(storage+0x2000);*slot=reinterpret_cast<void*>(4);
    auto token=register_guarded_pointer("test slot",slot,reinterpret_cast<void*>(4));CHECK(token);
    CHECK(!register_guarded_pointer("conflicting slot",slot,reinterpret_cast<void*>(8)));
    CHECK(!himitsu::jvm::native_pointer_exchange(slot,reinterpret_cast<void*>(4),reinterpret_cast<void*>(8),storage+0x1000));CHECK(*slot==reinterpret_cast<void*>(4));
    *slot=reinterpret_cast<void*>(12);auto view=snapshot();for(auto& item:*view)check_region(item,*view);CHECK(*slot==reinterpret_cast<void*>(4));
    CHECK(!himitsu::jvm::native_pointer_exchange(slot,reinterpret_cast<void*>(8),nullptr,storage));CHECK(*slot==reinterpret_cast<void*>(4));
    auto entry=(*view)[0];entry->readers=1;CHECK(!unregister_guarded_region(token,GetTickCount64()));CHECK(entry->retired);
    entry->readers=0;CHECK(unregister_guarded_region(token));*slot=reinterpret_cast<void*>(12);for(auto& item:*view)check_region(item,*view);CHECK(*slot==reinterpret_cast<void*>(12));
    CHECK(MH_Initialize()==MH_OK);
    const unsigned char body[]={0xB8,1,0,0,0,0xC3};const unsigned char replacement[]={0xB8,2,0,0,0,0xC3};
    std::memcpy(storage+0x20,body,sizeof(body));std::memcpy(storage+0x100,replacement,sizeof(replacement));
    DWORD prior=0;CHECK(VirtualProtect(storage,0x1000,PAGE_EXECUTE_READWRITE,&prior));void* trampoline=nullptr;
    CHECK(MH_CreateHook(storage+0x20,storage+0x100,&trampoline)==MH_OK);
    MH_HOOK_SNAPSHOT metadata{};CHECK(MH_GetHookSnapshot(storage+0x20,&metadata)==MH_OK && !metadata.patchAbove && metadata.patchSize==5);
    CHECK(metadata.trampolineSize>5 && metadata.trampolineSize<=64 && guarded_hook_intact(storage+0x20));
    CHECK(MH_EnableHook(storage+0x20)==MH_OK);auto hook=register_guarded_hook("test hook",storage+0x20);CHECK(hook && guarded_hook_intact(storage+0x20));
    himitsu::jvm::NativeCodeRange owned{storage+0x20,{body,body+sizeof(body)},std::shared_ptr<void>(storage,[](void*){})};
    auto body_token=register_guarded_code("test owned body",{owned});CHECK(body_token);
    auto count=snapshot()->size();CHECK(register_guarded_code("alias body",{owned,owned})==body_token && snapshot()->size()==count);
    view=snapshot();
    for(auto& item:*view)check_region(item,*view);
    for(auto& item:*view)if(item->token==body_token)CHECK(item->last_result==0);
    storage[0x25]=0x90;for(auto& item:*view)check_region(item,*view);
    for(auto& item:*view)if(item->token==body_token)CHECK(item->last_result==1); // Outside the owned patch remains checked.
    storage[0x25]=0xC3;CHECK(unregister_guarded_region(body_token));
    storage[0x21]^=1;CHECK(!guarded_hook_intact(storage+0x20));auto corrupt=storage[0x21];view=snapshot();for(auto& item:*view)check_region(item,*view);CHECK(storage[0x21]==corrupt);
    // Only the fixture restores its bytes. Production guards never repair active instruction buffers.
    std::memcpy(metadata.patch,metadata.installed,metadata.patchSize);CHECK(guarded_hook_intact(storage+0x20));
    CHECK(unregister_guarded_region(hook));CHECK(MH_DisableHook(storage+0x20)==MH_OK);
    std::memset(storage+0x400,0xCC,32);storage[0x405]=0xC3;storage[0x406]=0x90; // Different padding forces patchAbove.
    void* short_trampoline=nullptr;CHECK(MH_CreateHook(storage+0x405,storage+0x100,&short_trampoline)==MH_OK);
    CHECK(MH_GetHookSnapshot(storage+0x405,&metadata)==MH_OK && metadata.patchAbove && metadata.patch==storage+0x400 && metadata.patchSize==7);
    CHECK(MH_EnableHook(storage+0x405)==MH_OK);CHECK(guarded_hook_intact(storage+0x405));CHECK(MH_DisableHook(storage+0x405)==MH_OK);
    // Exercise the production scheduler with only fixture regions; no module discovery/JVM work is injected.
    for(auto& item:exports)item.token=UINT64_MAX;
    guard_wake=CreateEventW(nullptr,FALSE,FALSE,nullptr);region_tick_event=CreateEventW(nullptr,FALSE,FALSE,nullptr);CHECK(guard_wake&&region_tick_event);
    inspected_wake=guard_wake;running=true;guard_thread=CreateThread(nullptr,0,guard_worker,nullptr,0,nullptr);CHECK(guard_thread);
    CHECK(WaitForSingleObject(region_tick_event,1000)==WAIT_OBJECT_0);
    auto scheduler_token=register_guarded_pointer("scheduler slot",slot,*slot);CHECK(scheduler_token);
    CHECK(WaitForSingleObject(region_tick_event,1000)==WAIT_OBJECT_0 && region_ticks>=2 && saw_guard_interval);
    CHECK(unregister_guarded_region(scheduler_token,GetTickCount64()+1000));
    request_module_guard_stop();CHECK(!register_guarded_pointer("late",slot,nullptr));CHECK(stop_module_guard(GetTickCount64()+1000));
    CHECK(!running && !guard_thread);CloseHandle(region_tick_event);region_tick_event=nullptr;

    // Keep enabled-once trampolines alive, matching production shutdown. This process owns the fixture.
    std::puts("NATIVE_REGION_PASS immutable_baseline cas_conflict retired_generation inflight_retention actual_patchAbove trampoline_bounds enabled_bytes_mismatch interval_250 event_wakeup stop_wakeup NO_JVM_CODE_PATCH");
    return 0;
}
#endif
