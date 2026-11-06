#include "himitsu/platform/windows/module_conceal.hpp"

#include <atomic>
#include <cstddef>

namespace {
struct LoaderData {
    ULONG length;
    BOOLEAN initialized;
    BYTE padding[3];
    HANDLE ss_handle;
    LIST_ENTRY load_order;
    LIST_ENTRY memory_order;
    LIST_ENTRY initialization_order;
};

struct LoaderEntry {
    LIST_ENTRY load_order_links;
    LIST_ENTRY memory_order_links;
    LIST_ENTRY initialization_order_links;
    PVOID dll_base;
    PVOID entry_point;
    ULONG size_of_image;
};

struct PebPartial {
    BYTE inherited_address_space;
    BYTE read_image_file_exec_options;
    BYTE being_debugged;
    BYTE bit_field;
    HANDLE mutant;
    PVOID image_base_address;
    LoaderData* loader_data;
};

struct ProcessBasicInformation {
    LONG exit_status;
    PebPartial* peb;
    ULONG_PTR affinity_mask;
    LONG base_priority;
    ULONG_PTR unique_process_id;
    ULONG_PTR inherited_from_unique_process_id;
};

using NtQueryInformationProcessFn = LONG(NTAPI*)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG,
    PULONG
);
using LdrLockLoaderLockFn = LONG(NTAPI*)(ULONG, ULONG*, ULONG_PTR*);
using LdrUnlockLoaderLockFn = LONG(NTAPI*)(ULONG, ULONG_PTR);

std::atomic<bool> is_hidden{false};

bool successful_status(LONG status) {
    return status >= 0;
}

void detach_link(LIST_ENTRY& link) {
    if (link.Flink == nullptr || link.Blink == nullptr
        || link.Flink == &link || link.Blink == &link) {
        return;
    }
    link.Blink->Flink = link.Flink;
    link.Flink->Blink = link.Blink;
    link.Flink = &link;
    link.Blink = &link;
}

LoaderEntry* find_entry(LoaderData* loader, HMODULE module) {
    if (loader == nullptr || module == nullptr) return nullptr;
    LIST_ENTRY* const head = &loader->load_order;
    for (LIST_ENTRY* link = head->Flink;
         link != nullptr && link != head;
         link = link->Flink) {
        auto* entry = reinterpret_cast<LoaderEntry*>(
            reinterpret_cast<BYTE*>(link)
            - offsetof(LoaderEntry, load_order_links)
        );
        if (entry->dll_base == module) return entry;
    }
    return nullptr;
}
}

namespace himitsu::platform::windows::module_conceal {
bool hide(HMODULE module) {
    if (is_hidden.load(std::memory_order_acquire)) return true;
    if (module == nullptr) return false;

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) return false;
    const auto query_process = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(ntdll, "NtQueryInformationProcess")
    );
    const auto lock_loader = reinterpret_cast<LdrLockLoaderLockFn>(
        GetProcAddress(ntdll, "LdrLockLoaderLock")
    );
    const auto unlock_loader = reinterpret_cast<LdrUnlockLoaderLockFn>(
        GetProcAddress(ntdll, "LdrUnlockLoaderLock")
    );
    if (query_process == nullptr || lock_loader == nullptr || unlock_loader == nullptr) {
        return false;
    }

    ProcessBasicInformation process_information{};
    if (!successful_status(query_process(
            GetCurrentProcess(),
            0,
            &process_information,
            static_cast<ULONG>(sizeof(process_information)),
            nullptr
        )) || process_information.peb == nullptr
        || process_information.peb->loader_data == nullptr) {
        return false;
    }

    ULONG disposition = 0;
    ULONG_PTR cookie = 0;
    if (!successful_status(lock_loader(0, &disposition, &cookie))) return false;

    LoaderEntry* const entry = find_entry(
        process_information.peb->loader_data,
        module
    );
    if (entry != nullptr) {
        detach_link(entry->load_order_links);
        detach_link(entry->memory_order_links);
        detach_link(entry->initialization_order_links);
        is_hidden.store(true, std::memory_order_release);
    }
    unlock_loader(0, cookie);
    return entry != nullptr;
}

bool hidden() {
    return is_hidden.load(std::memory_order_acquire);
}
}
