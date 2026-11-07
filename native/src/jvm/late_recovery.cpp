#include "himitsu/jvm/late_recovery.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/platform/windows/module_guard.hpp"

#include <windows.h>
#include <psapi.h>
extern "C" IMAGE_DOS_HEADER __ImageBase;

#include <algorithm>
#include <array>
#include "../../third_party/minhook/src/hde/hde64.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <limits>
#include <iterator>
#include <string>
#include <vector>

namespace {
enum class RecoveryResult { unchanged, repaired, unsupported, failed };
const char* result_name(RecoveryResult value) {
    static const char* names[]={"unchanged","repaired","unsupported","failed"};
    return names[static_cast<unsigned>(value)];
}
bool recovered(RecoveryResult value) {return value==RecoveryResult::unchanged || value==RecoveryResult::repaired;}

class DiskImage {
public:
    DiskImage()=default;
    DiskImage(const DiskImage&)=delete;
    DiskImage& operator=(const DiskImage&)=delete;
    static bool span(std::size_t start,std::size_t length,std::size_t total) {
        return start<=total && length<=total-start;
    }
    static bool read_memory(const void* address,void* output,std::size_t length) {
        auto begin=reinterpret_cast<std::uintptr_t>(address);
        if(!address || !output || !length || length>UINTPTR_MAX-begin) return false;
        auto cursor=begin;const auto end=begin+length;
        while(cursor<end) {
            MEMORY_BASIC_INFORMATION page{};
            if(VirtualQuery(reinterpret_cast<void*>(cursor),&page,sizeof(page))!=sizeof(page)
                || page.State!=MEM_COMMIT || (page.Protect&(PAGE_GUARD|PAGE_NOACCESS))
                || !(page.Protect&(PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) return false;
            auto base=reinterpret_cast<std::uintptr_t>(page.BaseAddress);
            if(base>cursor || page.RegionSize>UINTPTR_MAX-base || base+page.RegionSize<=cursor) return false;
            cursor=(std::min)(end,base+page.RegionSize);
        }
        SIZE_T read=0;
        return ReadProcessMemory(GetCurrentProcess(),address,output,length,&read) && read==length;
    }
    bool load(HMODULE module=GetModuleHandleW(L"jvm.dll")) {
        if(!module) return false;
        wchar_t path[MAX_PATH*4]{};
        DWORD count=GetModuleFileNameW(module,path,static_cast<DWORD>(std::size(path)));
        std::wstring file_path;
        if(count && count<std::size(path))file_path.assign(path,count);
        else if(module==reinterpret_cast<HMODULE>(&__ImageBase)) {
            count=GetMappedFileNameW(GetCurrentProcess(),module,path,static_cast<DWORD>(std::size(path)));
            if(!count || count>=std::size(path) || std::wcsncmp(path,L"\\Device\\",8))return false;
            file_path=L"\\\\?\\GLOBALROOT";file_path.append(path,count);
        } else return false;
        HANDLE file=CreateFileW(file_path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file==INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER size{};std::vector<unsigned char> bytes;DWORD read=0;
        bool ok=GetFileSizeEx(file,&size) && size.QuadPart>=sizeof(IMAGE_DOS_HEADER)
            && static_cast<ULONGLONG>(size.QuadPart)<=std::numeric_limits<DWORD>::max();
        if(ok) {
            try {bytes.resize(static_cast<std::size_t>(size.QuadPart));}
            catch(...) {CloseHandle(file);return false;}
            ok=ReadFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr) && read==bytes.size();
        }
        CloseHandle(file);
        if(!ok) {HIMITSU_LOG_ERROR("LateRecovery","Cannot read JVM image");return false;}
        return initialize(std::move(bytes),module);
    }
    bool initialize(std::vector<unsigned char> bytes,HMODULE module) {
        mapped_=false;bytes_=std::move(bytes);module_=module;header_={};sections_.clear();functions_.clear();relocations_.clear();
        if(!parse_headers()) {HIMITSU_LOG_ERROR("LateRecovery","Invalid PE header/section bounds");return false;}
        mapped_=true;
        if(!parse_directories()) {
            mapped_=false;HIMITSU_LOG_ERROR("LateRecovery","Invalid PE directories");return false;
        }
        if(!match_live()) {
            mapped_=false;HIMITSU_LOG_ERROR("LateRecovery","Loaded/disk identity could not be verified");return false;
        }
        HIMITSU_LOG_INFO("LateRecovery","Validated native image: bytes=%zu functions=%zu relocations=%zu",bytes_.size(),functions_.size(),relocations_.size());
        return true;
    }
    HMODULE module() const {return module_;}
    unsigned char* live_base() const {return reinterpret_cast<unsigned char*>(module_);}
    ULONGLONG image_base() const {return image_base_;}
    DWORD image_size() const {return image_size_;}
    const unsigned char* raw_rva(DWORD rva,std::size_t length=1) const {
        if(!mapped_ || !span(rva,length,image_size_)) return nullptr;
        if(rva<nt_->OptionalHeader.SizeOfHeaders)
            return span(rva,length,nt_->OptionalHeader.SizeOfHeaders) && span(rva,length,bytes_.size()) ? bytes_.data()+rva : nullptr;
        for(const auto& section:sections_) {
            if(rva<section.VirtualAddress) continue;
            std::size_t offset=rva-section.VirtualAddress;
            if(span(offset,length,section.SizeOfRawData) && offset<section.SizeOfRawData
                && span(section.PointerToRawData+offset,length,bytes_.size()))
                return bytes_.data()+section.PointerToRawData+offset;
        }
        return nullptr;
    }
    bool in_image(const void* address,std::size_t length=1) const {
        auto value=reinterpret_cast<std::uintptr_t>(address),base=reinterpret_cast<std::uintptr_t>(module_);
        return mapped_ && value>=base && span(value-base,length,image_size_);
    }
    bool executable_rva(DWORD rva,std::size_t length=1) const {
        if(!raw_rva(rva,length)) return false;
        for(const auto& section:sections_) if((section.Characteristics&IMAGE_SCN_MEM_EXECUTE)
            && rva>=section.VirtualAddress && span(rva-section.VirtualAddress,length,section.SizeOfRawData)) return true;
        return false;
    }
    bool pointer_table_valid(
        DWORD rva,
        std::size_t slots,
        const std::vector<std::size_t>& required,
        std::size_t minimum_executable,
        std::size_t leading_zeroes
    ) const {
        if(slots==0 || slots>image_size_/sizeof(void*) || rva%sizeof(void*)) return false;
        const unsigned char* source = raw_rva(rva, slots * sizeof(std::uint64_t));
        if (source == nullptr) return false;
        std::size_t executable = 0;
        for (std::size_t i = 0; i < slots; ++i) {
            std::uint64_t preferred = 0;
            std::memcpy(&preferred, source + i * sizeof(preferred), sizeof(preferred));
            if (i < leading_zeroes && preferred != 0) return false;
            if (preferred == 0) continue;
            if (preferred < image_base_ || preferred - image_base_ >= image_size_) return false;
            if (!executable_rva(static_cast<DWORD>(preferred - image_base_))) return false;
            ++executable;
        }
        if (executable < minimum_executable) return false;
        for (std::size_t index : required) {
            if (index >= slots) return false;
            std::uint64_t preferred = 0;
            std::memcpy(&preferred, source + index * sizeof(preferred), sizeof(preferred));
            if (preferred < image_base_ || preferred - image_base_ >= image_size_
                || !executable_rva(static_cast<DWORD>(preferred - image_base_))) {
                return false;
            }
        }
        return true;
    }

    DWORD find_pointer_table(
        std::size_t slots,
        const std::vector<std::size_t>& required,
        std::size_t minimum_executable,
        std::size_t leading_zeroes,
        bool unique = false,
        const void* const* observed = nullptr
    ) const {
        if(slots==0 || slots>image_size_/sizeof(void*)) return 0;
        DWORD match = 0;
        std::size_t best_score = 0;
        bool tied = false;
        const std::size_t table_size = slots * sizeof(std::uint64_t);
        const IMAGE_SECTION_HEADER* section = sections_.data();
        for (WORD i = 0; i < nt_->FileHeader.NumberOfSections; ++i) {
            if ((section[i].Characteristics & IMAGE_SCN_MEM_READ) == 0
                || (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                || section[i].SizeOfRawData < table_size) {
                continue;
            }
            for (std::size_t offset = 0; offset <= section[i].SizeOfRawData-table_size; offset += sizeof(void*)) {
                const DWORD rva = section[i].VirtualAddress + static_cast<DWORD>(offset);
                if (pointer_table_valid(rva, slots, required, minimum_executable, leading_zeroes)) {
                    HIMITSU_LOG_INFO(
                        "LateRecovery",
                        "通过干净映像扫描定位到指针表（rva=0x%lX，槽数=%zu，节索引=%u）",
                        rva,
                        slots,
                        i
                    );
                    if (!unique) return rva;
                    if (observed != nullptr) {
                        std::size_t score=0;
                        const unsigned char* raw=raw_rva(rva,slots*sizeof(void*));
                        for(std::size_t slot=leading_zeroes;slot<slots;++slot) {
                            std::uint64_t preferred=0;std::memcpy(&preferred,raw+slot*sizeof(void*),sizeof(preferred));
                            void* translated=nullptr;
                            if(preferred_to_live(preferred,translated)&&observed[slot]==translated)++score;
                        }
                        HIMITSU_LOG_INFO("LateRecovery","JNI candidate rva=0x%lX matching slots=%zu/%zu",rva,score,slots);
                        if(score>best_score){best_score=score;match=rva;tied=false;}
                        else if(score==best_score&&match!=rva)tied=true;
                    } else {
                        if(match!=0&&match!=rva)tied=true;
                        match=rva;
                    }
                }
            }
        }
        if(unique && (tied || (observed!=nullptr && best_score<slots*2/3))) {
            HIMITSU_LOG_ERROR("LateRecovery","No uniquely corroborated JNI table; refusing recovery");
            return 0;
        }
        return match;
    }


    DWORD export_rva(const char* wanted,std::string* forward=nullptr) const {
        const auto& dir=nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        auto* source=raw_rva(dir.VirtualAddress,sizeof(IMAGE_EXPORT_DIRECTORY));
        if(dir.Size<sizeof(IMAGE_EXPORT_DIRECTORY) || !source) return 0;
        IMAGE_EXPORT_DIRECTORY value{};std::memcpy(&value,source,sizeof(value));const auto* table=&value;
        auto* names=raw_rva(table->AddressOfNames,static_cast<std::size_t>(table->NumberOfNames)*sizeof(DWORD));
        auto* ordinals=raw_rva(table->AddressOfNameOrdinals,static_cast<std::size_t>(table->NumberOfNames)*sizeof(WORD));
        auto* functions=raw_rva(table->AddressOfFunctions,static_cast<std::size_t>(table->NumberOfFunctions)*sizeof(DWORD));
        if(!names || !ordinals || !functions) return 0;
        DWORD index=table->NumberOfFunctions;
        if(wanted[0]=='#') {
            DWORD ordinal=0;if(!wanted[1])return 0;
            for(const char* digit=wanted+1;*digit;++digit) {
                if(*digit<'0' || *digit>'9' || ordinal>(65535u-static_cast<unsigned>(*digit-'0'))/10)return 0;
                ordinal=ordinal*10+static_cast<unsigned>(*digit-'0');
            }
            if(ordinal<table->Base)return 0;index=ordinal-table->Base;
        } else {
            auto length=std::strlen(wanted);
            for(DWORD i=0;i<table->NumberOfNames;++i) {
                DWORD rva=0;std::memcpy(&rva,names+i*sizeof(DWORD),sizeof(rva));auto* name=raw_rva(rva,length+1);
                if(name && !std::memcmp(name,wanted,length) && name[length]==0) {
                    WORD ordinal=0;std::memcpy(&ordinal,ordinals+i*sizeof(WORD),sizeof(ordinal));index=ordinal;break;
                }
            }
        }
        if(index>=table->NumberOfFunctions)return 0;
        DWORD rva=0;std::memcpy(&rva,functions+index*sizeof(DWORD),sizeof(rva));
        if(rva>=dir.VirtualAddress && rva-dir.VirtualAddress<dir.Size) {
            if(!forward)return 0;auto remaining=(std::min)(DWORD{256},dir.Size-(rva-dir.VirtualAddress));
            auto* text=raw_rva(rva,remaining);if(!text)return 0;
            auto* end=static_cast<const unsigned char*>(std::memchr(text,0,remaining));
            if(!end || end==text)return 0;forward->assign(reinterpret_cast<const char*>(text),end-text);return rva;
        }
        return executable_rva(rva)?rva:0;
    }

    bool preferred_to_live(std::uint64_t preferred,void*& live) const {
        if(preferred<image_base_ || preferred-image_base_>=image_size_) return false;
        live=live_base()+static_cast<DWORD>(preferred-image_base_);return true;
    }
    bool write_pointers(void* address,const void* data,std::size_t size) const {
        return write_checked(address,data,size,false);
    }
    RecoveryResult restore_function(DWORD rva,void* address,bool repair=true,
            std::vector<std::pair<DWORD,RecoveryResult>>* tail_checks=nullptr) const {
        if(!mapped_ || !executable_rva(rva) || address!=live_base()+rva) return RecoveryResult::failed;
        if(tail_checks) for(const auto& prior:*tail_checks) if(prior.first==rva) return prior.second;
        std::vector<std::pair<DWORD,std::size_t>> ranges;std::vector<DWORD> tails;
        if(!function_ranges(rva,ranges,tails)) return RecoveryResult::unsupported;
        std::vector<std::pair<DWORD,RecoveryResult>> local_checks;
        auto& checks=tail_checks?*tail_checks:local_checks;
        for(DWORD target:tails) {
            auto found=std::find_if(checks.begin(),checks.end(),[&](const auto& row){return row.first==target;});
            RecoveryResult result;
            if(found!=checks.end()) result=found->second;
            else {
                result=restore_function(target,live_base()+target,false);checks.emplace_back(target,result);
                HIMITSU_LOG_DEBUG("LateRecovery","Tail target rva=0x%lX check-only result=%s",target,result_name(result));
            }
            if(!recovered(result)) return result; // Do not write even the thunk on a failed dependency.
        }
        std::vector<std::vector<unsigned char>> expected,observed;bool changed=false;
        for(auto [start,size]:ranges) {
            auto* source=raw_rva(start,size);if(!source) return RecoveryResult::failed;
            expected.emplace_back(source,source+size);observed.emplace_back(size);
            if(!apply_relocations(start,expected.back().data(),size)
                || !code_mapping(start,size) || !read_memory(live_base()+start,observed.back().data(),size)) return RecoveryResult::failed;
            if(!himitsu::platform::windows::apply_owned_code(live_base()+start,expected.back().data(),size))return RecoveryResult::failed;
            changed|=expected.back()!=observed.back();
        }
        if(!changed) return RecoveryResult::unchanged;

        MEMORY_BASIC_INFORMATION mapping{};
        // A loaded module is live even during bootstrap. Only private, unpublished buffers may be written here.
        if(!repair || VirtualQuery(address,&mapping,sizeof(mapping))!=sizeof(mapping) || mapping.Type==MEM_IMAGE) {
            HIMITSU_LOG_WARNING("LateRecovery","Active/check-only code changed rva=0x%lX; not restored",rva);return RecoveryResult::failed;
        }
        for(std::size_t i=0;i<ranges.size();++i) if(expected[i]!=observed[i]
            && !write_checked(live_base()+ranges[i].first,expected[i].data(),expected[i].size(),true)) return RecoveryResult::failed;
        // Verify every selected instruction range again after the final write.
        for(std::size_t i=0;i<ranges.size();++i) if(!read_memory(live_base()+ranges[i].first,observed[i].data(),observed[i].size())
            || expected[i]!=observed[i]) return RecoveryResult::failed;
        return RecoveryResult::repaired;
    }
    bool capture(DWORD rva,std::vector<himitsu::jvm::NativeCodeRange>& output,const std::shared_ptr<void>& owner) const {
        std::vector<std::pair<DWORD,std::size_t>> ranges;std::vector<DWORD> tails;
        if(!function_ranges(rva,ranges,tails))return false;
        for(auto [start,size]:ranges) {
            auto* bytes=raw_rva(start,size);if(!bytes)return false;
            himitsu::jvm::NativeCodeRange row{live_base()+start,{bytes,bytes+size},owner};
            if(!apply_relocations(start,row.expected.data(),size))return false;
            if(std::none_of(output.begin(),output.end(),[&](const auto& old){return old.address==row.address;}))output.push_back(std::move(row));
        }
        for(auto tail:tails)if(!capture(tail,output,owner))return false;
        return true;
    }
    bool function_ranges(DWORD rva,std::vector<std::pair<DWORD,std::size_t>>& ranges,std::vector<DWORD>& tails) const {
        ranges.clear();tails.clear();if(!executable_rva(rva)) return false;
        auto entry=std::lower_bound(functions_.begin(),functions_.end(),rva,[](const auto& row,DWORD value){return row.BeginAddress<value;});
        if(entry!=functions_.end() && entry->BeginAddress==rva) {
            DWORD visited[8]{};
            if(entry->EndAddress-rva>0x10000 || !valid_unwind(*entry,visited,0)) return false;
            ranges.emplace_back(rva,entry->EndAddress-rva);return true;
        }
        if(entry!=functions_.begin() && rva<std::prev(entry)->EndAddress) return false;
        // Only the reachable, acyclic, call-free instructions are covered. Never copy gaps/padding.
        std::size_t limit=256;
        if(entry!=functions_.end()) limit=(std::min)(limit,static_cast<std::size_t>(entry->BeginAddress-rva));
        while(limit && !executable_rva(rva,limit)) --limit;
        if(!limit) return false;
        const auto* code=raw_rva(rva,limit);
        std::array<unsigned char,256> state{},lengths{};
        std::array<short,256> owner;owner.fill(-1);unsigned decoded=0;
        auto walk=[&](auto&& self,std::size_t offset)->bool {
            if(offset>=limit || (owner[offset]>=0 && owner[offset]!=offset) || state[offset]==1) return false;
            if(state[offset]==2) return true;
            if(++decoded>64) return false;
            unsigned char buffer[32]{};auto available=(std::min)(std::size_t{15},limit-offset);
            std::memcpy(buffer,code+offset,available);hde64s instruction{};hde64_disasm(buffer,&instruction);
            auto size=instruction.len;
            if(!size || size>available || (instruction.flags&F_ERROR)) return false;
            for(std::size_t i=offset;i<offset+size;++i) if(owner[i]>=0 && owner[i]!=offset) return false;
            for(std::size_t i=offset;i<offset+size;++i) owner[i]=static_cast<short>(offset);
            lengths[offset]=size;state[offset]=1;
            const auto op=instruction.opcode;bool ok=false;
            if(op==0xC3 || op==0xC2) ok=true;
            else if(op==0xE9 || op==0xEB || (op>=0x70 && op<=0x7F) || (op==0x0F && instruction.opcode2>=0x80 && instruction.opcode2<=0x8F)) {
                std::int64_t displacement=(instruction.flags&F_IMM8)?static_cast<std::int8_t>(instruction.imm.imm8):static_cast<std::int32_t>(instruction.imm.imm32);
                auto target=static_cast<std::int64_t>(offset+size)+displacement;
                if(target>=0 && target<limit) ok=self(self,static_cast<std::size_t>(target));
                else if(op==0xE9 || op==0xEB) {
                    auto destination=static_cast<std::int64_t>(rva)+target;
                    if(destination>=0 && destination<image_size_) {
                        auto tail=std::lower_bound(functions_.begin(),functions_.end(),destination,[](const auto& row,std::int64_t value){return row.BeginAddress<value;});
                        DWORD visited[8]{};
                        if(tail!=functions_.end() && tail->BeginAddress==destination && tail->EndAddress-tail->BeginAddress<=0x10000
                            && valid_unwind(*tail,visited,0)) {
                            auto value=static_cast<DWORD>(destination);
                            if(std::find(tails.begin(),tails.end(),value)==tails.end()) tails.push_back(value);
                            ok=true; // Exact pdata tail target is checked separately, never merged or newly patched.
                        }
                    }
                }
                if(ok && op!=0xE9 && op!=0xEB) ok=self(self,offset+size);
            } else if(!(instruction.flags&F_RELATIVE) && op!=0x9A && op!=0xEA && op!=0xCA && op!=0xCB
                && op!=0xCC && op!=0xCD && op!=0xCE && op!=0xCF && op!=0xF1 && op!=0xF4
                && !(op>=0xE0 && op<=0xE3) && !(op==0xFF && instruction.modrm_reg>=2 && instruction.modrm_reg<=5)
                && !(op==0x0F && (instruction.opcode2==0x05 || instruction.opcode2==0x07 || instruction.opcode2==0x0B
                    || instruction.opcode2==0x34 || instruction.opcode2==0x35))) ok=self(self,offset+size);
            if(ok) state[offset]=2;return ok;
        };
        if(!walk(walk,0)) return false;
        for(std::size_t i=0;i<limit;++i) if(lengths[i]) {
            if(!ranges.empty() && ranges.back().first+ranges.back().second==rva+i) ranges.back().second+=lengths[i];
            else ranges.emplace_back(rva+static_cast<DWORD>(i),lengths[i]);
        }
        return !ranges.empty();
    }
private:
    bool parse_headers() {
        IMAGE_DOS_HEADER dos{};
        if(bytes_.size()<sizeof(dos)) return false;std::memcpy(&dos,bytes_.data(),sizeof(dos));
        if(dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<=0) return false;
        header_offset_=static_cast<std::size_t>(dos.e_lfanew);
        constexpr auto prefix=sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER);
        if(!span(header_offset_,prefix,bytes_.size())) return false;
        std::memcpy(&header_,bytes_.data()+header_offset_,prefix);
        auto optional=header_offset_+prefix;auto declared=header_.FileHeader.SizeOfOptionalHeader;
        if(header_.Signature!=IMAGE_NT_SIGNATURE || header_.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64
            || declared<offsetof(IMAGE_OPTIONAL_HEADER64,DataDirectory) || !span(optional,declared,bytes_.size())) return false;
        std::memcpy(&header_.OptionalHeader,bytes_.data()+optional,(std::min)(static_cast<std::size_t>(declared),sizeof(IMAGE_OPTIONAL_HEADER64)));
        auto& opt=header_.OptionalHeader;
        if(opt.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC || opt.NumberOfRvaAndSizes>IMAGE_NUMBEROF_DIRECTORY_ENTRIES
            || declared<offsetof(IMAGE_OPTIONAL_HEADER64,DataDirectory)+opt.NumberOfRvaAndSizes*sizeof(IMAGE_DATA_DIRECTORY)
            || !opt.SizeOfImage || !opt.SizeOfHeaders || opt.SizeOfHeaders>opt.SizeOfImage || opt.SizeOfHeaders>bytes_.size()
            || !header_.FileHeader.NumberOfSections || opt.ImageBase>UINT64_MAX-opt.SizeOfImage) return false;
        for(DWORD i=opt.NumberOfRvaAndSizes;i<IMAGE_NUMBEROF_DIRECTORY_ENTRIES;++i) opt.DataDirectory[i]={};
        auto start=optional+declared;auto size=static_cast<std::size_t>(header_.FileHeader.NumberOfSections)*sizeof(IMAGE_SECTION_HEADER);
        if(!span(start,size,opt.SizeOfHeaders) || !span(start,size,bytes_.size())) return false;
        sections_.resize(header_.FileHeader.NumberOfSections);std::memcpy(sections_.data(),bytes_.data()+start,size);
        image_base_=opt.ImageBase;image_size_=opt.SizeOfImage;
        for(std::size_t i=0;i<sections_.size();++i) {
            const auto& section=sections_[i];auto mapped=(std::max)(section.Misc.VirtualSize,section.SizeOfRawData);
            if(mapped && (section.VirtualAddress<opt.SizeOfHeaders || !span(section.VirtualAddress,mapped,image_size_))) return false;
            if(section.SizeOfRawData && (section.PointerToRawData<opt.SizeOfHeaders || !span(section.PointerToRawData,section.SizeOfRawData,bytes_.size()))) return false;
            for(std::size_t j=0;j<i;++j) {
                const auto& prior=sections_[j];auto prior_size=(std::max)(prior.Misc.VirtualSize,prior.SizeOfRawData);
                if(mapped && prior_size && section.VirtualAddress<static_cast<std::uint64_t>(prior.VirtualAddress)+prior_size
                    && prior.VirtualAddress<static_cast<std::uint64_t>(section.VirtualAddress)+mapped) return false;
                if(section.SizeOfRawData && prior.SizeOfRawData && section.PointerToRawData<static_cast<std::uint64_t>(prior.PointerToRawData)+prior.SizeOfRawData
                    && prior.PointerToRawData<static_cast<std::uint64_t>(section.PointerToRawData)+section.SizeOfRawData) return false;
            }
        }
        return true;
    }
    bool match_live() const {
        if(!module_ || reinterpret_cast<std::uintptr_t>(module_)>UINTPTR_MAX-image_size_) return false;
        IMAGE_DOS_HEADER dos{};
        if(!read_memory(module_,&dos,sizeof(dos)) || dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew!=header_offset_) {
            HIMITSU_LOG_ERROR("LateRecovery","Loaded DOS header unreadable/different");return false;
        }
        std::vector<unsigned char> live(nt_->OptionalHeader.SizeOfHeaders);
        if(!read_memory(module_,live.data(),live.size())) {HIMITSU_LOG_ERROR("LateRecovery","Loaded PE headers unreadable: bytes=%zu error=%lu",live.size(),GetLastError());return false;}
        const auto base_offset=header_offset_+offsetof(IMAGE_NT_HEADERS64,OptionalHeader)+offsetof(IMAGE_OPTIONAL_HEADER64,ImageBase);
        ULONGLONG loaded_base=0;std::memcpy(&loaded_base,live.data()+base_offset,sizeof(loaded_base));
        // Windows may publish the relocated base in the loaded header. Nothing else is normalized.
        if(loaded_base!=image_base_ && loaded_base!=reinterpret_cast<std::uintptr_t>(module_)) {
            HIMITSU_LOG_ERROR("LateRecovery","Loaded ImageBase invalid: header=%llX mapped=%p preferred=%llX",loaded_base,module_,image_base_);return false;
        }
        std::memcpy(live.data()+base_offset,&image_base_,sizeof(image_base_));
        const auto size=sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_->FileHeader.SizeOfOptionalHeader
            +sections_.size()*sizeof(IMAGE_SECTION_HEADER);
        for(std::size_t i=0;i<size;++i) if(live[header_offset_+i]!=bytes_[header_offset_+i]) {
            HIMITSU_LOG_ERROR("LateRecovery","Loaded PE header differs: offset=0x%zX live=%02X disk=%02X",header_offset_+i,live[header_offset_+i],bytes_[header_offset_+i]);return false;
        }
        return true;
    }
    bool parse_directories() {
        for(DWORD i=0;i<nt_->OptionalHeader.NumberOfRvaAndSizes;++i) {
            const auto& dir=nt_->OptionalHeader.DataDirectory[i];
            if(!dir.VirtualAddress && !dir.Size) continue;
            if(!dir.VirtualAddress || !dir.Size) return false;
            if(i==IMAGE_DIRECTORY_ENTRY_SECURITY) {
                if((dir.VirtualAddress&7) || !span(dir.VirtualAddress,dir.Size,bytes_.size())) return false;
            } else if(!raw_rva(dir.VirtualAddress,dir.Size)) return false;
        }
        const auto& pd=nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if(pd.Size) {
            if(pd.Size%sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) return false;
            functions_.resize(pd.Size/sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
            std::memcpy(functions_.data(),raw_rva(pd.VirtualAddress,pd.Size),pd.Size);
            DWORD end=0;
            for(const auto& row:functions_) {
                if(row.BeginAddress<end || row.EndAddress<=row.BeginAddress || !executable_rva(row.BeginAddress,row.EndAddress-row.BeginAddress)
                    || !raw_rva(row.UnwindInfoAddress,4)) return false;
                end=row.EndAddress;
            }
        }
        const auto& dir=nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        auto* bytes=dir.Size?raw_rva(dir.VirtualAddress,dir.Size):nullptr;
        for(std::size_t offset=0;offset<dir.Size;) {
            if(!span(offset,sizeof(IMAGE_BASE_RELOCATION),dir.Size)) return false;
            IMAGE_BASE_RELOCATION block{};std::memcpy(&block,bytes+offset,sizeof(block));
            if(block.SizeOfBlock<sizeof(block) || (block.SizeOfBlock%4) || !span(offset,block.SizeOfBlock,dir.Size)
                || (block.VirtualAddress&0xFFF)) return false;
            for(std::size_t i=sizeof(block);i<block.SizeOfBlock;i+=sizeof(WORD)) {
                WORD item=0;std::memcpy(&item,bytes+offset+i,sizeof(item));auto type=item>>12;
                if(type==IMAGE_REL_BASED_ABSOLUTE) continue;
                if(type!=IMAGE_REL_BASED_DIR64 || !span(block.VirtualAddress,item&0xFFF,image_size_)) return false;
                DWORD target=block.VirtualAddress+(item&0xFFF);
                if(!raw_rva(target,sizeof(std::uint64_t))) return false;
                relocations_.push_back(target);
            }
            offset+=block.SizeOfBlock;
        }
        std::sort(relocations_.begin(),relocations_.end());
        for(std::size_t i=1;i<relocations_.size();++i) if(relocations_[i]-relocations_[i-1]<sizeof(std::uint64_t)) return false;
        return true;
    }
    bool valid_unwind(const IMAGE_RUNTIME_FUNCTION_ENTRY& row,DWORD* visited,unsigned depth) const {
        auto rva=row.UnwindInfoAddress;if(depth>=8 || (rva&3)) return false;
        for(unsigned i=0;i<depth;++i) if(visited[i]==rva) return false;visited[depth]=rva;
        auto* h=raw_rva(rva,4);if(!h || (h[0]&7)!=1) return false;
        unsigned flags=h[0]>>3,codes=h[2],frame=h[3]&15;
        if((flags&~7) || ((flags&4)&&(flags&3)) || (!frame && (h[3]>>4)) || h[1]>row.EndAddress-row.BeginAddress) return false;
        std::size_t tail=4+((codes+1)&~1u)*2;
        auto* data=raw_rva(rva,tail+(flags&4?12:flags&3?4:0));if(!data) return false;
        unsigned previous=256;
        for(unsigned i=0;i<codes;) {
            auto offset=data[4+2*i];auto op=data[5+2*i]&15;auto info=data[5+2*i]>>4;unsigned slots=1;
            if(offset>h[1] || offset>previous) return false;previous=offset;
            if(op==1) {if(info>1)return false;slots=info?3:2;}
            else if(op==4 || op==8) slots=2;
            else if(op==5 || op==9) slots=3;
            else if(op==3) {if(info || !frame)return false;}
            else if(op==10) {if(info>1)return false;}
            else if(op!=0 && op!=2) return false;
            if(slots>codes-i) return false;i+=slots;
        }
        if(flags&4) {
            IMAGE_RUNTIME_FUNCTION_ENTRY parent{};std::memcpy(&parent,data+tail,sizeof(parent));
            return parent.EndAddress>parent.BeginAddress && executable_rva(parent.BeginAddress,parent.EndAddress-parent.BeginAddress)
                && valid_unwind(parent,visited,depth+1);
        }
        if(flags&3) {DWORD handler=0;std::memcpy(&handler,data+tail,sizeof(handler));if(!executable_rva(handler))return false;}
        return true;
    }
    bool apply_relocations(DWORD rva,unsigned char* data,std::size_t size) const {
        if(!raw_rva(rva,size)) return false;
        auto delta=reinterpret_cast<std::uintptr_t>(module_)-image_base_;
        if(delta && !nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return false;
        auto it=std::lower_bound(relocations_.begin(),relocations_.end(),rva>7?rva-7:0);
        for(;it!=relocations_.end() && *it<static_cast<std::uint64_t>(rva)+size;++it) {
            if(*it<rva || !span(*it-rva,sizeof(std::uint64_t),size)) return false;
            std::uint64_t value=0;std::memcpy(&value,data+(*it-rva),sizeof(value));value+=delta;
            std::memcpy(data+(*it-rva),&value,sizeof(value));
        }
        return true;
    }
    bool code_mapping(DWORD rva,std::size_t size) const {
        if(!executable_rva(rva,size)) return false;
        auto cursor=reinterpret_cast<std::uintptr_t>(live_base()+rva),end=cursor+size;
        while(cursor<end) {
            MEMORY_BASIC_INFORMATION page{};
            if(VirtualQuery(reinterpret_cast<void*>(cursor),&page,sizeof(page))!=sizeof(page) || page.AllocationBase!=module_
                || page.State!=MEM_COMMIT || (page.Protect&(PAGE_GUARD|PAGE_NOACCESS))
                || !(page.Protect&(PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) return false;
            auto base=reinterpret_cast<std::uintptr_t>(page.BaseAddress);
            if(base>cursor || page.RegionSize>UINTPTR_MAX-base || base+page.RegionSize<=cursor) return false;
            cursor=(std::min)(end,base+page.RegionSize);
        }
        return true;
    }
    bool write_checked(void* address,const void* data,std::size_t size,bool code) const {
        auto begin=reinterpret_cast<std::uintptr_t>(address);
        if(!address || !data || !size || size>UINTPTR_MAX-begin
            || (!code && (begin%sizeof(void*) || size%sizeof(void*))) || (code && !in_image(address,size))) return false;
        std::vector<unsigned char> observed(size);
        if(!read_memory(address,observed.data(),size)) return false;
        if(!std::memcmp(observed.data(),data,size)) return true;
        std::vector<MEMORY_BASIC_INFORMATION> pages;auto cursor=begin;const auto end=begin+size;
        while(cursor<end) {
            MEMORY_BASIC_INFORMATION page{};
            if(VirtualQuery(reinterpret_cast<void*>(cursor),&page,sizeof(page))!=sizeof(page) || page.State!=MEM_COMMIT
                || (code && (page.AllocationBase!=module_ || !(page.Protect&(PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))))) return false;
            auto base=reinterpret_cast<std::uintptr_t>(page.BaseAddress);
            if(base>cursor || page.RegionSize>UINTPTR_MAX-base || base+page.RegionSize<=cursor) return false;
            auto next=(std::min)(end,base+page.RegionSize);page.BaseAddress=reinterpret_cast<void*>(cursor);page.RegionSize=next-cursor;
            pages.push_back(page);cursor=next;
        }
        std::size_t changed=0;bool ok=true;
        for(auto& page:pages) {
            DWORD prior=0;
            if(!VirtualProtect(page.BaseAddress,page.RegionSize,code?PAGE_EXECUTE_READWRITE:PAGE_READWRITE,&prior)){ok=false;break;}
            ++changed;
            if(prior!=page.Protect){page.Protect=prior;ok=false;break;}
        }
        if(ok) {
            if(code) {SIZE_T written=0;ok=WriteProcessMemory(GetCurrentProcess(),address,data,size,&written) && written==size;}
            else for(std::size_t i=0;i<size/sizeof(void*);++i) {
                void* value=nullptr;std::memcpy(&value,static_cast<const unsigned char*>(data)+i*sizeof(void*),sizeof(value));
                void* before=nullptr;std::memcpy(&before,observed.data()+i*sizeof(void*),sizeof(before));
                if(InterlockedCompareExchangePointer(static_cast<void* volatile*>(address)+i,value,before)!=before){ok=false;break;}
            }
            if(code && !FlushInstructionCache(GetCurrentProcess(),address,size)) ok=false;
        }
        while(changed) {
            const auto& page=pages[--changed];DWORD ignored=0;
            if(!VirtualProtect(page.BaseAddress,page.RegionSize,page.Protect,&ignored)) ok=false;
            MEMORY_BASIC_INFORMATION current{};
            if(VirtualQuery(page.BaseAddress,&current,sizeof(current))!=sizeof(current) || current.Protect!=page.Protect) ok=false;
        }
        return ok && read_memory(address,observed.data(),size) && !std::memcmp(observed.data(),data,size);
    }
    HMODULE module_=nullptr;
    std::vector<unsigned char> bytes_;
    IMAGE_NT_HEADERS64 header_{};
    const IMAGE_NT_HEADERS64* nt_=&header_;
    std::vector<IMAGE_SECTION_HEADER> sections_;
    std::vector<IMAGE_RUNTIME_FUNCTION_ENTRY> functions_;
    std::vector<DWORD> relocations_;
    std::size_t header_offset_=0;
    ULONGLONG image_base_=0;
    DWORD image_size_=0;
    bool mapped_=false;
};

bool restore_pointer_table(const DiskImage& image, DWORD table_rva, void** live_table, std::size_t slots) {
    if (live_table == nullptr || !slots || slots>image.image_size()/sizeof(void*)
        || !image.in_image(live_table,slots*sizeof(void*)) || table_rva==0 || !image.raw_rva(table_rva,slots*sizeof(void*))
        || live_table!=reinterpret_cast<void**>(image.live_base()+table_rva)) {
        HIMITSU_LOG_WARNING(
            "LateRecovery",
            "指针表恢复参数校验失败（表=%p，rva=0x%lX，槽数=%zu，位于映像内=%s）",
            live_table,
            table_rva,
            slots,
            live_table != nullptr && image.in_image(live_table) ? "是" : "否"
        );
        return false;
    }
    const unsigned char* source = image.raw_rva(table_rva, slots * sizeof(void*));
    if (source == nullptr) {
        HIMITSU_LOG_WARNING("LateRecovery", "干净映像中缺少指针表字节（rva=0x%lX，槽数=%zu）", table_rva, slots);
        return false;
    }

    std::vector<void*> restored(slots, nullptr);
    std::size_t function_slots = 0;
    std::size_t reserved_slots = 0;
    for (std::size_t i = 0; i < slots; ++i) {
        std::uint64_t preferred = 0;
        std::memcpy(&preferred, source + i * sizeof(preferred), sizeof(preferred));
        if (preferred == 0) {
            ++reserved_slots;
        } else if (!image.preferred_to_live(preferred, restored[i])) {
            HIMITSU_LOG_ERROR("LateRecovery", "干净指针表中存在无效指针（rva=0x%lX，槽=%zu，值=0x%llX）", table_rva, i, static_cast<unsigned long long>(preferred));
            return false;
        } else {
            ++function_slots;
        }
    }
    const bool written = image.write_pointers(live_table, restored.data(), restored.size() * sizeof(void*));
    HIMITSU_LOG_INFO(
        "LateRecovery",
        "指针表重建结束（表=%p，rva=0x%lX，槽数=%zu，函数=%zu，保留项=%zu，成功=%s）",
        live_table,
        table_rva,
        slots,
        function_slots,
        reserved_slots,
        written ? "是" : "否"
    );
    return written;
}

bool restore_table_functions(const DiskImage& image,DWORD table_rva,std::size_t slots,
        const std::vector<std::size_t>& repair,const std::vector<std::size_t>& verify={}) {
    if(!slots || slots>image.image_size()/sizeof(void*)) return false;
    const auto* source=image.raw_rva(table_rva,slots*sizeof(void*));if(!source)return false;
    std::vector<std::pair<DWORD,bool>> targets;
    for(bool writable:{true,false}) for(auto slot:writable?repair:verify) {
        if(slot>=slots)return false;
        std::uint64_t preferred=0;std::memcpy(&preferred,source+slot*sizeof(void*),sizeof(preferred));void* live=nullptr;
        if(!image.preferred_to_live(preferred,live))return false;
        DWORD rva=static_cast<DWORD>(preferred-image.image_base());
        auto found=std::find_if(targets.begin(),targets.end(),[&](const auto& row){return row.first==rva;});
        if(found==targets.end())targets.emplace_back(rva,writable);else found->second|=writable;
    }
    unsigned counts[4]{};std::vector<std::pair<DWORD,RecoveryResult>> tail_checks;
    std::shared_ptr<void> owner;MEMORY_BASIC_INFORMATION mapping{};
    if(VirtualQuery(image.live_base(),&mapping,sizeof(mapping))==sizeof(mapping) && mapping.Type==MEM_IMAGE) {
        HMODULE handle=nullptr;
        if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,reinterpret_cast<LPCWSTR>(image.live_base()),&handle))return false;
        owner={handle,[](void* value){FreeLibrary(static_cast<HMODULE>(value));}};
    }
    for(auto [rva,writable]:targets) {
        auto result=image.restore_function(rva,image.live_base()+rva,false,&tail_checks);++counts[static_cast<unsigned>(result)];
        if(recovered(result) && owner) {
            std::vector<himitsu::jvm::NativeCodeRange> ranges;
            if(!image.capture(rva,ranges,owner)
                || !himitsu::platform::windows::register_guarded_code("JVM required interface",std::move(ranges))) {
                --counts[static_cast<unsigned>(result)];result=RecoveryResult::failed;++counts[3];
            }
        }
        if(std::none_of(tail_checks.begin(),tail_checks.end(),[&](const auto& row){return row.first==rva;})) tail_checks.emplace_back(rva,result);
        HIMITSU_LOG_DEBUG("LateRecovery","Function rva=0x%lX mode=%s result=%s",rva,writable?"legacy-verify":"check-only",result_name(result));
        if(!recovered(result)) HIMITSU_LOG_ERROR("LateRecovery","Function not verified/recovered: rva=0x%lX result=%s",rva,result_name(result));
    }
    HIMITSU_LOG_INFO("LateRecovery","Function results: unique=%zu unchanged=%u repaired=%u unsupported=%u failed=%u",targets.size(),counts[0],counts[1],counts[2],counts[3]);
    return counts[2]==0 && counts[3]==0;
}

bool repair_vm_table(const DiskImage& image,JavaVM* vm) {
    const JNIInvokeInterface_* original=nullptr;
    if(!DiskImage::read_memory(vm,&original,sizeof(original)))return false;
    constexpr std::size_t slots=8;const std::vector<std::size_t> required{3,4,5,6,7};
    auto* table=const_cast<JNIInvokeInterface_*>(original);
    DWORD rva=image.in_image(table,sizeof(*table))?static_cast<DWORD>(reinterpret_cast<unsigned char*>(table)-image.live_base()):0;
    if(!rva || !image.pointer_table_valid(rva,slots,required,5,3)) {
        rva=image.find_pointer_table(slots,required,5,3);if(!rva)return false;
        table=reinterpret_cast<JNIInvokeInterface_*>(image.live_base()+rva);
    }
    if(!restore_table_functions(image,rva,slots,required)
        || !restore_pointer_table(image,rva,reinterpret_cast<void**>(table),slots)) return false;
    const JNIInvokeInterface_* replacement=table;
    return original==replacement || image.write_pointers(vm,&replacement,sizeof(replacement));
}

}

namespace himitsu::jvm {
bool native_table_baseline(const void* table,std::size_t slots,std::vector<void*>& values) {
    DiskImage image;if(!image.load() || !slots || slots>image.image_size()/sizeof(void*) || !image.in_image(table,slots*sizeof(void*)))return false;
    auto rva=static_cast<DWORD>(static_cast<const unsigned char*>(table)-image.live_base());
    auto* bytes=image.raw_rva(rva,slots*sizeof(void*));if(!bytes)return false;
    std::vector<void*> pending(slots,nullptr);
    for(std::size_t i=0;i<slots;++i) {
        std::uint64_t preferred=0;std::memcpy(&preferred,bytes+i*sizeof(void*),sizeof(preferred));
        if(preferred && !image.preferred_to_live(preferred,pending[i]))return false;
    }
    values=std::move(pending);return true;
}
bool native_memory_read(const void* address,void* output,std::size_t size) {return DiskImage::read_memory(address,output,size);}
bool native_pointer_exchange(void** slot,void* before,void* after,void* allocation_base) {
    if(!slot || reinterpret_cast<std::uintptr_t>(slot)%sizeof(void*))return false;
    MEMORY_BASIC_INFORMATION page{};void* current=nullptr;
    if(VirtualQuery(slot,&page,sizeof(page))!=sizeof(page) || page.AllocationBase!=allocation_base
        || !DiskImage::read_memory(slot,&current,sizeof(current)) || current!=before)return false;
    DWORD old=0;
    const bool executable=(page.Protect&(PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))!=0;
    if(!VirtualProtect(slot,sizeof(void*),executable?PAGE_EXECUTE_READWRITE:PAGE_READWRITE,&old))return false;
    bool ok=old==page.Protect;
    if(ok)ok=InterlockedCompareExchangePointer(reinterpret_cast<void* volatile*>(slot),after,before)==before;
    DWORD ignored=0;ok=(VirtualProtect(slot,sizeof(void*),old,&ignored)!=FALSE)&&ok;
    MEMORY_BASIC_INFORMATION restored{};
    return ok && VirtualQuery(slot,&restored,sizeof(restored))==sizeof(restored) && restored.Protect==old
        && restored.AllocationBase==allocation_base && DiskImage::read_memory(slot,&current,sizeof(current)) && current==after;
}
static std::shared_ptr<void> pin_module(void* address) {
    HMODULE module=nullptr;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,reinterpret_cast<LPCWSTR>(address),&module)) {
        MEMORY_BASIC_INFORMATION page{};
        if(VirtualQuery(address,&page,sizeof(page))!=sizeof(page) || page.Type!=MEM_IMAGE || page.AllocationBase!=&__ImageBase)return {};
        // The production library retains its own load handle; only this exact image may use the mapped-file fallback.
        return {page.AllocationBase,[](void*){}};
    }
    return {module,[](void* value){FreeLibrary(static_cast<HMODULE>(value));}};
}
bool native_function_baseline(void* address,std::vector<NativeCodeRange>& ranges) {
    auto owner=pin_module(address);if(!owner)return false;
    DiskImage image;if(!image.load(static_cast<HMODULE>(owner.get())) || !image.in_image(address))return false;
    auto rva=static_cast<DWORD>(static_cast<unsigned char*>(address)-image.live_base());
    std::vector<NativeCodeRange> pending;
    if(!image.capture(rva,pending,owner))return false;ranges=std::move(pending);return true;
}
bool native_export_baseline(HMODULE module,const char* name,std::vector<NativeCodeRange>& ranges,bool* unsupported) {
    if(unsupported)*unsupported=false;
    if(!module || !name || !*name)return false;
    std::vector<std::pair<HMODULE,std::string>> visited;std::string symbol=name;
    for(unsigned depth=0;depth<8;++depth) {
        if(std::find(visited.begin(),visited.end(),std::make_pair(module,symbol))!=visited.end())return false;
        visited.emplace_back(module,symbol);auto owner=pin_module(module);if(!owner)return false;
        DiskImage image;if(!image.load(module))return false;
        std::string forward;auto rva=image.export_rva(symbol.c_str(),&forward);if(!rva)return false;
        if(forward.empty()) {
            const char* lookup=symbol.c_str();
            if(symbol.front()=='#') {unsigned ordinal=0;for(std::size_t i=1;i<symbol.size();++i)ordinal=ordinal*10+symbol[i]-'0';lookup=MAKEINTRESOURCEA(ordinal);}
            if(GetProcAddress(module,lookup)!=reinterpret_cast<FARPROC>(image.live_base()+rva))return false;
            std::vector<NativeCodeRange> pending;
            if(!image.capture(rva,pending,owner)){if(unsupported)*unsupported=true;return false;}
            ranges=std::move(pending);return true;
        }
        auto dot=forward.find_last_of('.');if(dot==std::string::npos || !dot || dot+1==forward.size())return false;
        std::string library=forward.substr(0,dot);symbol=forward.substr(dot+1);
        if(library.find_first_of("/\\:")!=std::string::npos)return false;
        if(library.size()<4 || _stricmp(library.c_str()+library.size()-4,".dll"))library+=".dll";
        module=GetModuleHandleA(library.c_str());if(!module)return false;
    }
    return false;
}
JavaVM* late_recover_created_vm() {
    HIMITSU_LOG_INFO("LateRecovery", "开始执行 JavaVM 后置恢复");
    DiskImage image;
    if (!image.load()) {
        HIMITSU_LOG_ERROR("LateRecovery", "干净 jvm.dll 映像初始化失败");
        return nullptr;
    }

    const DWORD rva = image.export_rva("JNI_GetCreatedJavaVMs");
    auto getter = GetProcAddress(image.module(), "JNI_GetCreatedJavaVMs");
    HIMITSU_LOG_INFO("LateRecovery", "JNI_GetCreatedJavaVMs 解析完成（rva=0x%lX，实时地址=%p）", rva, getter);
    if (rva == 0 || getter == nullptr) {
        HIMITSU_LOG_ERROR("LateRecovery", "JNI_GetCreatedJavaVMs 解析失败");
        return nullptr;
    }

    if (!recovered(image.restore_function(rva, reinterpret_cast<void*>(getter),false))) {
        HIMITSU_LOG_ERROR("LateRecovery", "JNI_GetCreatedJavaVMs not verified/recovered; refusing call");
        return nullptr;
    }

    using GetCreatedJavaVMs = jint(JNICALL*)(JavaVM**, jsize, jsize*);
    JavaVM* vm = nullptr;
    jsize count = 0;
    const jint result = reinterpret_cast<GetCreatedJavaVMs>(getter)(&vm, 1, &count);
    HIMITSU_LOG_INFO("LateRecovery", "JNI_GetCreatedJavaVMs 调用结束（jni=%d，数量=%d，vm=%p）", result, count, vm);
    if (result != JNI_OK || count == 0 || vm == nullptr) {
        HIMITSU_LOG_WARNING("LateRecovery", "已创建的 JavaVM 暂未就绪");
        return nullptr;
    }

    if (!repair_vm_table(image, vm)) {
        HIMITSU_LOG_ERROR("LateRecovery", "JavaVM interface verification/recovery failed; not published");
        return nullptr;
    }
    HIMITSU_LOG_INFO("LateRecovery", "JavaVM 后置恢复完成（vm=%p，表=%p）", vm, vm->functions);
    return vm;
}

bool late_recover_jvmti_dispatch(jvmtiEnv* env) {
    const jvmtiInterface_1_* original=nullptr;
    if(!DiskImage::read_memory(env,&original,sizeof(original)))return false;
    DiskImage image;if(!image.load())return false;
    constexpr std::size_t slots=sizeof(jvmtiInterface_1_)/sizeof(void*);
    const std::vector<std::size_t> repair{
        offsetof(jvmtiInterface_1_, SetEventNotificationMode) / sizeof(void*),
        offsetof(jvmtiInterface_1_, DisposeEnvironment) / sizeof(void*),
        offsetof(jvmtiInterface_1_, SetEventCallbacks) / sizeof(void*),
        offsetof(jvmtiInterface_1_, SetExtensionEventCallback) / sizeof(void*),
        offsetof(jvmtiInterface_1_, GetExtensionEvents) / sizeof(void*),
        offsetof(jvmtiInterface_1_, GetAllThreads) / sizeof(void*),
        offsetof(jvmtiInterface_1_, GetMethodModifiers) / sizeof(void*),
        offsetof(jvmtiInterface_1_, GetMethodDeclaringClass) / sizeof(void*),
        offsetof(jvmtiInterface_1_, GetPhase) / sizeof(void*),
        offsetof(jvmtiInterface_1_, GetCapabilities) / sizeof(void*),
        offsetof(jvmtiInterface_1_, AddCapabilities) / sizeof(void*),
        offsetof(jvmtiInterface_1_, RelinquishCapabilities) / sizeof(void*),
        offsetof(jvmtiInterface_1_, RetransformClasses) / sizeof(void*),
        offsetof(jvmtiInterface_1_, RedefineClasses) / sizeof(void*)
    };
    const std::vector<std::size_t> verify{
        offsetof(jvmtiInterface_1_, GetStackTrace)/sizeof(void*),
        offsetof(jvmtiInterface_1_, GetMethodName)/sizeof(void*),
        offsetof(jvmtiInterface_1_, GetClassLoader)/sizeof(void*),
        offsetof(jvmtiInterface_1_, GetFieldModifiers)/sizeof(void*),
        offsetof(jvmtiInterface_1_, Allocate)/sizeof(void*),
        offsetof(jvmtiInterface_1_, Deallocate)/sizeof(void*),
        offsetof(jvmtiInterface_1_, GetLoadedClasses)/sizeof(void*),
        offsetof(jvmtiInterface_1_, GetClassSignature)/sizeof(void*),
        offsetof(jvmtiInterface_1_, IsModifiableClass)/sizeof(void*),
        offsetof(jvmtiInterface_1_, GetCurrentThread)/sizeof(void*),
        offsetof(jvmtiInterface_1_, SetTag)/sizeof(void*),
        offsetof(jvmtiInterface_1_, GetObjectsWithTags)/sizeof(void*),
        offsetof(jvmtiInterface_1_, IterateOverInstancesOfClass)/sizeof(void*)
    };
    auto required=repair;required.insert(required.end(),verify.begin(),verify.end());
    auto* table=const_cast<jvmtiInterface_1_*>(original);
    DWORD rva=image.in_image(table,sizeof(*table))?static_cast<DWORD>(reinterpret_cast<unsigned char*>(table)-image.live_base()):0;
    if(!rva || !image.pointer_table_valid(rva,slots,required,140,1)) {
        rva=image.find_pointer_table(slots,required,140,1);if(!rva)return false;
        table=reinterpret_cast<jvmtiInterface_1_*>(image.live_base()+rva);
    }
    if(!restore_table_functions(image,rva,slots,repair,verify)
        || !restore_pointer_table(image,rva,reinterpret_cast<void**>(table),slots)) return false;
    const jvmtiInterface_1_* replacement=table;
    bool ok=original==replacement || image.write_pointers(env,&replacement,sizeof(replacement));
    HIMITSU_LOG_INFO("LateRecovery","JVMTI interface recovered: slots=%zu ready=%s",slots,ok?"true":"false");return ok;
}
bool late_recover_jni_dispatch(JNIEnv* env) {
    const JNINativeInterface_* original=nullptr;
    if(!DiskImage::read_memory(env,&original,sizeof(original)))return false;
    DiskImage image;if(!image.load())return false;
    constexpr std::size_t slots=sizeof(JNINativeInterface_)/sizeof(void*);
    const std::vector<std::size_t> repair{
        offsetof(JNINativeInterface_, GetVersion)/sizeof(void*),
        offsetof(JNINativeInterface_, DefineClass)/sizeof(void*),
        offsetof(JNINativeInterface_, FindClass)/sizeof(void*),
        offsetof(JNINativeInterface_, RegisterNatives)/sizeof(void*),
        offsetof(JNINativeInterface_, GetStaticMethodID)/sizeof(void*),
        offsetof(JNINativeInterface_, CallStaticBooleanMethod)/sizeof(void*),
        offsetof(JNINativeInterface_, CallStaticBooleanMethodV)/sizeof(void*),
        offsetof(JNINativeInterface_, CallStaticObjectMethodV)/sizeof(void*),
        offsetof(JNINativeInterface_, SetStaticObjectField)/sizeof(void*)
    };
    const std::vector<std::size_t> verify{
        offsetof(JNINativeInterface_, CallStaticVoidMethodV)/sizeof(void*),
        offsetof(JNINativeInterface_, GetStaticObjectField)/sizeof(void*),
        offsetof(JNINativeInterface_, CallBooleanMethodV)/sizeof(void*),
        offsetof(JNINativeInterface_, CallIntMethodV)/sizeof(void*),
        offsetof(JNINativeInterface_, CallLongMethodV)/sizeof(void*),
        offsetof(JNINativeInterface_, CallObjectMethodV)/sizeof(void*),
        offsetof(JNINativeInterface_, CallVoidMethodV)/sizeof(void*),
        offsetof(JNINativeInterface_, DeleteGlobalRef)/sizeof(void*),
        offsetof(JNINativeInterface_, DeleteLocalRef)/sizeof(void*),
        offsetof(JNINativeInterface_, EnsureLocalCapacity)/sizeof(void*),
        offsetof(JNINativeInterface_, ExceptionCheck)/sizeof(void*),
        offsetof(JNINativeInterface_, ExceptionClear)/sizeof(void*),
        offsetof(JNINativeInterface_, ExceptionDescribe)/sizeof(void*),
        offsetof(JNINativeInterface_, ExceptionOccurred)/sizeof(void*),
        offsetof(JNINativeInterface_, GetArrayLength)/sizeof(void*),
        offsetof(JNINativeInterface_, GetByteArrayElements)/sizeof(void*),
        offsetof(JNINativeInterface_, GetByteArrayRegion)/sizeof(void*),
        offsetof(JNINativeInterface_, GetMethodID)/sizeof(void*),
        offsetof(JNINativeInterface_, GetObjectArrayElement)/sizeof(void*),
        offsetof(JNINativeInterface_, GetObjectClass)/sizeof(void*),
        offsetof(JNINativeInterface_, GetStaticBooleanField)/sizeof(void*),
        offsetof(JNINativeInterface_, GetStaticFieldID)/sizeof(void*),
        offsetof(JNINativeInterface_, GetStringUTFChars)/sizeof(void*),
        offsetof(JNINativeInterface_, IsInstanceOf)/sizeof(void*),
        offsetof(JNINativeInterface_, IsSameObject)/sizeof(void*),
        offsetof(JNINativeInterface_, NewByteArray)/sizeof(void*),
        offsetof(JNINativeInterface_, NewGlobalRef)/sizeof(void*),
        offsetof(JNINativeInterface_, NewLocalRef)/sizeof(void*),
        offsetof(JNINativeInterface_, NewObjectArray)/sizeof(void*),
        offsetof(JNINativeInterface_, NewObjectV)/sizeof(void*),
        offsetof(JNINativeInterface_, NewString)/sizeof(void*),
        offsetof(JNINativeInterface_, NewStringUTF)/sizeof(void*),
        offsetof(JNINativeInterface_, PopLocalFrame)/sizeof(void*),
        offsetof(JNINativeInterface_, PushLocalFrame)/sizeof(void*),
        offsetof(JNINativeInterface_, ReleaseByteArrayElements)/sizeof(void*),
        offsetof(JNINativeInterface_, ReleaseStringUTFChars)/sizeof(void*),
        offsetof(JNINativeInterface_, SetByteArrayRegion)/sizeof(void*),
        offsetof(JNINativeInterface_, SetObjectArrayElement)/sizeof(void*),
        offsetof(JNINativeInterface_, SetStaticIntField)/sizeof(void*)
    };
    auto required=repair;required.insert(required.end(),verify.begin(),verify.end());
    auto* table=const_cast<JNINativeInterface_*>(original);
    DWORD rva=image.in_image(table,sizeof(*table))?static_cast<DWORD>(reinterpret_cast<unsigned char*>(table)-image.live_base()):0;
    if(!rva || !image.pointer_table_valid(rva,slots,required,200,4)) {
        JNINativeInterface_ observed{};
        if(!DiskImage::read_memory(original,&observed,sizeof(observed)))return false;
        rva=image.find_pointer_table(slots,required,200,4,true,reinterpret_cast<const void* const*>(&observed));
        if(!rva)return false;table=reinterpret_cast<JNINativeInterface_*>(image.live_base()+rva);
    }
    if(!restore_table_functions(image,rva,slots,repair,verify)
        || !restore_pointer_table(image,rva,reinterpret_cast<void**>(table),slots))return false;
    const JNINativeInterface_* replacement=table;
    bool ok=original==replacement || image.write_pointers(env,&replacement,sizeof(replacement));
    HIMITSU_LOG_INFO("LateRecovery","JNI interface recovered: slots=%zu ready=%s",slots,ok?"true":"false");return ok;
}
}
