#include "himitsu/jvm/late_recovery.hpp"

#include "himitsu/core/native_log.hpp"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <iterator>
#include <string>
#include <vector>

namespace {
class DiskImage {
public:
    bool load() {
        module_ = GetModuleHandleW(L"jvm.dll");
        if (module_ == nullptr) {
            HIMITSU_LOG_WARNING("LateRecovery", "jvm.dll 尚未加载");
            return false;
        }

        wchar_t path[MAX_PATH * 4]{};
        const DWORD length = GetModuleFileNameW(module_, path, static_cast<DWORD>(std::size(path)));
        if (length == 0 || length >= std::size(path)) {
            HIMITSU_LOG_ERROR("LateRecovery", "GetModuleFileNameW 调用失败（错误码=%lu）", GetLastError());
            return false;
        }
        HIMITSU_LOG_INFO("LateRecovery", "正在加载干净的 JVM 映像（路径='%ls'，实时基址=%p）", path, module_);

        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            HIMITSU_LOG_ERROR("LateRecovery", "打开 jvm.dll 失败（错误码=%lu）", GetLastError());
            return false;
        }

        LARGE_INTEGER size{};
        DWORD io_error = ERROR_SUCCESS;
        DWORD read = 0;
        bool ok = GetFileSizeEx(file, &size) != FALSE;
        if (!ok) {
            io_error = GetLastError();
            HIMITSU_LOG_ERROR("LateRecovery", "获取 jvm.dll 文件大小失败（错误码=%lu）", io_error);
        } else if (size.QuadPart <= 0) {
            ok = false;
            io_error = ERROR_FILE_INVALID;
            HIMITSU_LOG_ERROR("LateRecovery", "jvm.dll 文件大小无效（大小=%lld）", size.QuadPart);
        } else if (static_cast<ULONGLONG>(size.QuadPart) > std::numeric_limits<DWORD>::max()) {
            ok = false;
            io_error = ERROR_FILE_TOO_LARGE;
            HIMITSU_LOG_ERROR("LateRecovery", "jvm.dll 文件超过单次读取上限（大小=%lld）", size.QuadPart);
        }

        if (ok) {
            bytes_.resize(static_cast<std::size_t>(size.QuadPart));
            ok = ReadFile(file, bytes_.data(), static_cast<DWORD>(bytes_.size()), &read, nullptr) != FALSE;
            if (!ok) {
                io_error = GetLastError();
            } else if (static_cast<std::size_t>(read) != bytes_.size()) {
                ok = false;
                io_error = ERROR_HANDLE_EOF;
            }
        }
        CloseHandle(file);
        if (!ok || bytes_.size() < sizeof(IMAGE_DOS_HEADER)) {
            HIMITSU_LOG_ERROR(
                "LateRecovery",
                "读取 jvm.dll 失败（文件大小=%lld，缓冲区=%zu，已读取=%lu，错误码=%lu）",
                size.QuadPart,
                bytes_.size(),
                read,
                io_error
            );
            return false;
        }
        HIMITSU_LOG_INFO("LateRecovery", "读取 jvm.dll 完成（文件大小=%lld，已读取=%lu）", size.QuadPart, read);

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes_.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE
            || dos->e_lfanew <= 0
            || static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > bytes_.size()) {
            HIMITSU_LOG_ERROR("LateRecovery", "jvm.dll 的 DOS/NT 头位置无效");
            return false;
        }
        nt_ = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes_.data() + dos->e_lfanew);
        if (nt_->Signature != IMAGE_NT_SIGNATURE
            || nt_->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            HIMITSU_LOG_ERROR("LateRecovery", "jvm.dll 的 PE 头格式不受支持");
            return false;
        }
        const auto* live_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_);
        if (live_dos->e_magic != IMAGE_DOS_SIGNATURE || live_dos->e_lfanew <= 0) return false;
        const auto* live_nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const unsigned char*>(module_) + live_dos->e_lfanew);
        if (live_nt->Signature != IMAGE_NT_SIGNATURE
            || live_nt->FileHeader.TimeDateStamp != nt_->FileHeader.TimeDateStamp
            || live_nt->FileHeader.Machine != nt_->FileHeader.Machine
            || live_nt->OptionalHeader.SizeOfImage != nt_->OptionalHeader.SizeOfImage) {
            HIMITSU_LOG_ERROR("LateRecovery", "Loaded JVM and disk image differ; refusing recovery");
            return false;
        }
        image_base_ = nt_->OptionalHeader.ImageBase;
        image_size_ = nt_->OptionalHeader.SizeOfImage;
        HIMITSU_LOG_INFO(
            "LateRecovery",
            "干净 JVM 映像准备完成（文件字节=%zu，首选基址=0x%llX，映像大小=0x%lX，时间戳=0x%lX，节数=%u）",
            bytes_.size(),
            static_cast<unsigned long long>(image_base_),
            image_size_,
            nt_->FileHeader.TimeDateStamp,
            nt_->FileHeader.NumberOfSections
        );
        return true;
    }

    HMODULE module() const { return module_; }
    unsigned char* live_base() const { return reinterpret_cast<unsigned char*>(module_); }
    ULONGLONG image_base() const { return image_base_; }
    DWORD image_size() const { return image_size_; }

    const unsigned char* raw_rva(DWORD rva, std::size_t size = 1) const {
        if (rva < nt_->OptionalHeader.SizeOfHeaders) {
            return rva + size <= bytes_.size() ? bytes_.data() + rva : nullptr;
        }
        const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_);
        for (WORD i = 0; i < nt_->FileHeader.NumberOfSections; ++i) {
            const DWORD section_size = std::max(section[i].Misc.VirtualSize, section[i].SizeOfRawData);
            if (rva < section[i].VirtualAddress || rva - section[i].VirtualAddress >= section_size) continue;
            const DWORD offset = section[i].PointerToRawData + (rva - section[i].VirtualAddress);
            return static_cast<std::size_t>(offset) + size <= bytes_.size()
                ? bytes_.data() + offset
                : nullptr;
        }
        return nullptr;
    }

    bool in_image(const void* address) const {
        const auto value = reinterpret_cast<std::uintptr_t>(address);
        const auto begin = reinterpret_cast<std::uintptr_t>(live_base());
        return value >= begin && value < begin + image_size_;
    }

    bool executable_rva(DWORD rva) const {
        const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_);
        for (WORD i = 0; i < nt_->FileHeader.NumberOfSections; ++i) {
            const DWORD section_size = std::max(section[i].Misc.VirtualSize, section[i].SizeOfRawData);
            if (rva >= section[i].VirtualAddress && rva - section[i].VirtualAddress < section_size) {
                return (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            }
        }
        return false;
    }

    bool pointer_table_valid(
        DWORD rva,
        std::size_t slots,
        const std::vector<std::size_t>& required,
        std::size_t minimum_executable,
        std::size_t leading_zeroes
    ) const {
        const unsigned char* source = raw_rva(rva, slots * sizeof(std::uint64_t));
        if (source == nullptr) return false;
        std::size_t executable = 0;
        for (std::size_t i = 0; i < slots; ++i) {
            std::uint64_t preferred = 0;
            std::memcpy(&preferred, source + i * sizeof(preferred), sizeof(preferred));
            if (i < leading_zeroes && preferred != 0) return false;
            if (preferred == 0) continue;
            if (preferred < image_base_ || preferred >= image_base_ + image_size_) return false;
            if (!executable_rva(static_cast<DWORD>(preferred - image_base_))) return false;
            ++executable;
        }
        if (executable < minimum_executable) return false;
        for (std::size_t index : required) {
            if (index >= slots) return false;
            std::uint64_t preferred = 0;
            std::memcpy(&preferred, source + index * sizeof(preferred), sizeof(preferred));
            if (preferred < image_base_ || preferred >= image_base_ + image_size_
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
        DWORD match = 0;
        std::size_t best_score = 0;
        bool tied = false;
        const std::size_t table_size = slots * sizeof(std::uint64_t);
        const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_);
        for (WORD i = 0; i < nt_->FileHeader.NumberOfSections; ++i) {
            if ((section[i].Characteristics & IMAGE_SCN_MEM_READ) == 0
                || (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                || section[i].SizeOfRawData < table_size) {
                continue;
            }
            for (DWORD offset = 0; offset + table_size <= section[i].SizeOfRawData; offset += sizeof(void*)) {
                const DWORD rva = section[i].VirtualAddress + offset;
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

    DWORD export_rva(const char* wanted) const {
        const auto& directory = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        auto* export_directory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(raw_rva(directory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)));
        if (export_directory == nullptr) return 0;
        auto* names = reinterpret_cast<const DWORD*>(raw_rva(export_directory->AddressOfNames, export_directory->NumberOfNames * sizeof(DWORD)));
        auto* ordinals = reinterpret_cast<const WORD*>(raw_rva(export_directory->AddressOfNameOrdinals, export_directory->NumberOfNames * sizeof(WORD)));
        auto* functions = reinterpret_cast<const DWORD*>(raw_rva(export_directory->AddressOfFunctions, export_directory->NumberOfFunctions * sizeof(DWORD)));
        if (names == nullptr || ordinals == nullptr || functions == nullptr) return 0;
        for (DWORD i = 0; i < export_directory->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(raw_rva(names[i]));
            if (name != nullptr && std::strcmp(name, wanted) == 0) {
                const WORD ordinal = ordinals[i];
                return ordinal < export_directory->NumberOfFunctions ? functions[ordinal] : 0;
            }
        }
        return 0;
    }

    bool preferred_to_live(std::uint64_t preferred, void*& live) const {
        if (preferred < image_base_ || preferred >= image_base_ + image_size_) return false;
        const DWORD rva = static_cast<DWORD>(preferred - image_base_);
        live = live_base() + rva;
        return true;
    }

    bool write_live(void* address, const void* data, std::size_t size) const {
        DWORD old_protection = 0;
        if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old_protection)) return false;
        std::memcpy(address, data, size);
        FlushInstructionCache(GetCurrentProcess(), address, size);
        DWORD ignored = 0;
        return VirtualProtect(address, size, old_protection, &ignored) != FALSE;
    }

    bool restore_function(DWORD rva, void* live_address) const {
        if (rva == 0 || live_address == nullptr) {
            HIMITSU_LOG_WARNING("LateRecovery", "函数恢复参数校验失败（rva=0x%lX，实时地址=%p）", rva, live_address);
            return false;
        }
        DWORD end = rva + 64;
        const auto& directory = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        auto* entries = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(raw_rva(directory.VirtualAddress, directory.Size));
        const std::size_t count = directory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        if (entries != nullptr) {
            for (std::size_t i = 0; i < count; ++i) {
                if (rva >= entries[i].BeginAddress && rva < entries[i].EndAddress) {
                    end = entries[i].EndAddress;
                    break;
                }
            }
        }
        if (end <= rva || end - rva > 0x10000) {
            HIMITSU_LOG_WARNING("LateRecovery", "函数范围无效（rva=0x%lX，结束=0x%lX）", rva, end);
            return false;
        }
        const unsigned char* source = raw_rva(rva, end - rva);
        if (source == nullptr) {
            HIMITSU_LOG_WARNING("LateRecovery", "干净映像中缺少函数字节（rva=0x%lX，字节数=%lu）", rva, end - rva);
            return false;
        }
        std::vector<unsigned char> restored(source, source + (end - rva));
        apply_relocations(rva, restored.data(), restored.size());
        if (std::memcmp(live_address, restored.data(), restored.size()) == 0) {
            HIMITSU_LOG_DEBUG("LateRecovery", "函数内容已经一致（rva=0x%lX，实时地址=%p，字节数=%zu）", rva, live_address, restored.size());
            return true;
        }
        const bool written = write_live(live_address, restored.data(), restored.size());
        HIMITSU_LOG_WARNING(
            "LateRecovery",
            "函数字节修复结束（rva=0x%lX，实时地址=%p，字节数=%zu，成功=%s）",
            rva,
            live_address,
            restored.size(),
            written ? "是" : "否"
        );
        return written;
    }

private:
    void apply_relocations(DWORD rva, unsigned char* data, std::size_t size) const {
        const auto& directory = nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(raw_rva(directory.VirtualAddress, directory.Size));
        if (block == nullptr) return;
        const std::intptr_t delta = static_cast<std::intptr_t>(
            reinterpret_cast<std::uintptr_t>(live_base()) - image_base_
        );
        std::size_t consumed = 0;
        while (consumed + sizeof(IMAGE_BASE_RELOCATION) <= directory.Size && block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
            const std::size_t entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* types = reinterpret_cast<const WORD*>(block + 1);
            for (std::size_t i = 0; i < entries; ++i) {
                const WORD type = types[i] >> 12;
                const DWORD offset = types[i] & 0x0FFF;
                const DWORD target = block->VirtualAddress + offset;
                if (type == IMAGE_REL_BASED_DIR64 && target >= rva && target + sizeof(std::uint64_t) <= rva + size) {
                    auto* value = reinterpret_cast<std::uint64_t*>(data + (target - rva));
                    *value = static_cast<std::uint64_t>(static_cast<std::int64_t>(*value) + delta);
                }
            }
            consumed += block->SizeOfBlock;
            block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reinterpret_cast<const unsigned char*>(block) + block->SizeOfBlock);
        }
    }

    HMODULE module_ = nullptr;
    std::vector<unsigned char> bytes_;
    const IMAGE_NT_HEADERS64* nt_ = nullptr;
    ULONGLONG image_base_ = 0;
    DWORD image_size_ = 0;
};

bool restore_pointer_table(const DiskImage& image, DWORD table_rva, void** live_table, std::size_t slots) {
    if (live_table == nullptr || !image.in_image(live_table) || table_rva == 0) {
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
    const bool written = image.write_live(live_table, restored.data(), restored.size() * sizeof(void*));
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

bool restore_table_functions(
    const DiskImage& image,
    DWORD table_rva,
    const std::vector<std::size_t>& indexes
) {
    bool success = true;
    HIMITSU_LOG_INFO("LateRecovery", "开始恢复表内函数体（表Rva=0x%lX，数量=%zu）", table_rva, indexes.size());
    for (std::size_t index : indexes) {
        const unsigned char* source = image.raw_rva(
            table_rva + static_cast<DWORD>(index * sizeof(std::uint64_t)),
            sizeof(std::uint64_t)
        );
        if (source == nullptr) return false;
        std::uint64_t preferred = 0;
        std::memcpy(&preferred, source, sizeof(preferred));
        void* live = nullptr;
        if (!image.preferred_to_live(preferred, live)) {
            success = false;
            continue;
        }
        const DWORD function_rva = static_cast<DWORD>(preferred - image.image_base());
        const bool restored = image.restore_function(function_rva, live);
        HIMITSU_LOG_DEBUG(
            "LateRecovery",
            "表内函数检查结束（槽=%zu，函数Rva=0x%lX，实时地址=%p，成功=%s）",
            index,
            function_rva,
            live,
            restored ? "是" : "否"
        );
        success = restored && success;
    }
    HIMITSU_LOG_INFO("LateRecovery", "表内函数恢复结束（成功=%s）", success ? "是" : "否");
    return success;
}

bool repair_vm_table(const DiskImage& image, JavaVM* vm) {
    if (vm == nullptr) {
        HIMITSU_LOG_WARNING("LateRecovery", "JavaVM 表修复收到空 VM");
        return false;
    }
    constexpr std::size_t slots = 8;
    const std::vector<std::size_t> required{3, 4, 5, 6, 7};
    auto* table = const_cast<JNIInvokeInterface_*>(vm->functions);
    DWORD table_rva = image.in_image(table)
        ? static_cast<DWORD>(reinterpret_cast<unsigned char*>(table) - image.live_base())
        : 0;
    HIMITSU_LOG_INFO(
        "LateRecovery",
        "正在检查 JavaVM 表（vm=%p，当前表=%p，当前Rva=0x%lX，位于映像内=%s）",
        vm,
        table,
        table_rva,
        image.in_image(table) ? "是" : "否"
    );
    if (table_rva == 0 || !image.pointer_table_valid(table_rva, slots, required, 5, 3)) {
        HIMITSU_LOG_WARNING("LateRecovery", "当前 JavaVM 表校验失败，开始扫描干净映像");
        table_rva = image.find_pointer_table(slots, required, 5, 3);
        if (table_rva == 0) {
            HIMITSU_LOG_ERROR("LateRecovery", "未在干净映像中定位到 JavaVM 调用表");
            return false;
        }
        table = reinterpret_cast<JNIInvokeInterface_*>(image.live_base() + table_rva);
        const JNIInvokeInterface_* replacement = table;
        if (!image.write_live(&vm->functions, &replacement, sizeof(replacement))) {
            HIMITSU_LOG_ERROR("LateRecovery", "JavaVM 表指针替换失败");
            return false;
        }
        HIMITSU_LOG_WARNING("LateRecovery", "JavaVM 表指针已替换（新表=%p，rva=0x%lX）", table, table_rva);
    }
    const bool restored = restore_pointer_table(image, table_rva, reinterpret_cast<void**>(table), slots)
        && restore_table_functions(image, table_rva, required);
    HIMITSU_LOG_INFO("LateRecovery", "JavaVM 表修复结束（成功=%s）", restored ? "是" : "否");
    return restored;
}
}

namespace himitsu::jvm {
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

    if (!image.restore_function(rva, reinterpret_cast<void*>(getter))) {
        HIMITSU_LOG_WARNING("LateRecovery", "JNI_GetCreatedJavaVMs 恢复失败");
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
        HIMITSU_LOG_WARNING("LateRecovery", "JavaVM 调用表位于实时 jvm.dll 映像之外");
        return nullptr;
    }
    HIMITSU_LOG_INFO("LateRecovery", "JavaVM 后置恢复完成（vm=%p，表=%p）", vm, vm->functions);
    return vm;
}

bool late_recover_jvmti_dispatch(jvmtiEnv* env) {
    HIMITSU_LOG_INFO("LateRecovery", "开始执行 JVMTI 分发表后置恢复（env=%p）", env);
    if (env == nullptr) {
        HIMITSU_LOG_ERROR("LateRecovery", "JVMTI 分发表恢复收到空环境");
        return false;
    }
    DiskImage image;
    if (!image.load()) {
        HIMITSU_LOG_ERROR("LateRecovery", "用于 JVMTI 恢复的干净 jvm.dll 映像初始化失败");
        return false;
    }

    auto* table = const_cast<jvmtiInterface_1_*>(env->functions);
    constexpr std::size_t slots = sizeof(jvmtiInterface_1_) / sizeof(void*);
    const std::vector<std::size_t> required{
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
    DWORD table_rva = image.in_image(table)
        ? static_cast<DWORD>(reinterpret_cast<unsigned char*>(table) - image.live_base())
        : 0;
    HIMITSU_LOG_INFO(
        "LateRecovery",
        "正在检查 JVMTI 表（env=%p，当前表=%p，当前Rva=0x%lX，槽数=%zu，位于映像内=%s）",
        env,
        table,
        table_rva,
        slots,
        image.in_image(table) ? "是" : "否"
    );
    if (table_rva == 0 || !image.pointer_table_valid(table_rva, slots, required, 140, 1)) {
        HIMITSU_LOG_WARNING("LateRecovery", "当前 JVMTI 表校验失败，开始扫描干净映像");
        table_rva = image.find_pointer_table(slots, required, 140, 1);
        if (table_rva == 0) {
            HIMITSU_LOG_WARNING("LateRecovery", "干净映像中未定位到 JVMTI 分发表");
            return false;
        }
        table = reinterpret_cast<jvmtiInterface_1_*>(image.live_base() + table_rva);
        const jvmtiInterface_1_* replacement = table;
        if (!image.write_live(&env->functions, &replacement, sizeof(replacement))) {
            HIMITSU_LOG_ERROR("LateRecovery", "JVMTI 表指针替换失败");
            return false;
        }
        HIMITSU_LOG_WARNING("LateRecovery", "JVMTI 表指针已替换（新表=%p，rva=0x%lX）", table, table_rva);
    }

    const bool restored = restore_pointer_table(
        image,
        table_rva,
        reinterpret_cast<void**>(table),
        slots
    ) && restore_table_functions(image, table_rva, required);
    if (restored) {
        HIMITSU_LOG_INFO("LateRecovery", "JVMTI 分发表已从磁盘 jvm.dll 恢复");
    } else {
        HIMITSU_LOG_ERROR("LateRecovery", "JVMTI 分发表恢复失败");
    }
    return restored;
}
bool late_recover_jni_dispatch(JNIEnv* env) {
    if (env == nullptr) return false;
    DiskImage image;
    if (!image.load()) return false;
    constexpr std::size_t slots = sizeof(JNINativeInterface_) / sizeof(void*);
    const std::vector<std::size_t> required{
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
    auto* table = const_cast<JNINativeInterface_*>(env->functions);
    DWORD rva = image.in_image(table)
        ? static_cast<DWORD>(reinterpret_cast<unsigned char*>(table)-image.live_base()) : 0;
    if (rva == 0 || !image.pointer_table_valid(rva,slots,required,200,4)) {
        JNINativeInterface_ observed=*env->functions;
        rva = image.find_pointer_table(slots,required,200,4,true,reinterpret_cast<const void* const*>(&observed));
        if (rva == 0) return false;
        table = reinterpret_cast<JNINativeInterface_*>(image.live_base()+rva);
    }
    if (!restore_pointer_table(image,rva,reinterpret_cast<void**>(table),slots)
        || !restore_table_functions(image,rva,required)) return false;
    const JNINativeInterface_* replacement = table;
    const bool ok = env->functions == replacement
        || image.write_live(&env->functions,&replacement,sizeof(replacement));
    HIMITSU_LOG_INFO("LateRecovery", "JNI interface recovered: slots=%zu ready=%s",slots,ok?"true":"false");
    return ok;
}

}
