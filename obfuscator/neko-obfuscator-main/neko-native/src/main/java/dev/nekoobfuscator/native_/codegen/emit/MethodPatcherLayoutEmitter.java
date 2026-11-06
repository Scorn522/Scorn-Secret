package dev.nekoobfuscator.native_.codegen.emit;

/**
 * Emits Method* layout data structures and low-level dlsym scaffolding.
 */
final class MethodPatcherLayoutEmitter {
    private MethodPatcherLayoutEmitter() {}

    static String render() {
        return """
/* === Method* layout discovery + entry patcher === */
#include <dlfcn.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/mman.h>
#endif

#define NEKO_ACC_NATIVE_BIT 0x00000100u
#define NEKO_ACC_NOT_C1_COMPILABLE_FALLBACK  0x04000000u
#define NEKO_ACC_NOT_C2_COMPILABLE_FALLBACK  0x02000000u
#define NEKO_ACC_NOT_OSR_COMPILABLE_FALLBACK 0x08000000u

static JavaVM *g_neko_java_vm = NULL;

typedef struct {
    jboolean initialized;
    jboolean usable;
    jint java_spec_version;
    ptrdiff_t off_method_access_flags;
    ptrdiff_t off_method_code;
    ptrdiff_t off_method_i2i_entry;
    ptrdiff_t off_method_from_interpreted_entry;
    ptrdiff_t off_method_from_compiled_entry;
    ptrdiff_t off_method_flags_status;
    ptrdiff_t off_method_intrinsic_id;
    ptrdiff_t off_method_vtable_index;
    ptrdiff_t off_method_constMethod;
    size_t method_size;
    size_t access_flags_size;
    uint32_t access_not_c1_compilable;
    uint32_t access_not_c2_compilable;
    uint32_t access_not_osr_compilable;
    uint32_t method_flag_not_c1_compilable;
    uint32_t method_flag_not_c2_compilable;
    uint32_t method_flag_not_osr_compilable;
    /* Thread-state machine — populated from VMStructs Thread::_thread_state +
     * VMIntConstants JavaThreadState enum values. The trampoline reads these
     * via the exported globals below to flip between in_Java and in_native. */
    ptrdiff_t off_thread_state;
    int32_t thread_state_in_java;
    int32_t thread_state_in_native;
    int32_t thread_state_in_native_trans;
    /* SafepointMechanism polling: the byte at ((char*)thread)[off_safepoint_poll]
     * (when present) is non-zero whenever a safepoint is requested; the
     * trampoline's transition-back checks it and yields if needed. */
    ptrdiff_t off_thread_polling_word;
    /* JavaFrameAnchor inside JavaThread (so GC can walk our stack while we are
     * in _thread_in_native). Two emission paths: direct flat fields on
     * JavaThread (older JDKs) or via the embedded _anchor struct. We pick
     * whichever resolved and publish the final byte offsets to the asm. */
    ptrdiff_t off_thread_anchor;
    ptrdiff_t off_frame_anchor_sp;
    ptrdiff_t off_frame_anchor_fp;
    ptrdiff_t off_frame_anchor_pc;
    ptrdiff_t off_thread_last_Java_sp_direct;
    ptrdiff_t off_thread_last_Java_fp_direct;
    ptrdiff_t off_thread_last_Java_pc_direct;
    ptrdiff_t off_thread_jni_environment;
    /* JNIHandleBlock plumbing: our dispatcher pushes ref args into the
     * thread's _active_handles so GC tracks them as roots. */
    ptrdiff_t off_thread_active_handles;
    ptrdiff_t off_jnih_block_top;
    ptrdiff_t off_jnih_block_handles;
    ptrdiff_t off_jnih_block_next;
    ptrdiff_t off_thread_tlab;
    ptrdiff_t off_tlab_top;
    ptrdiff_t off_tlab_end;
    size_t    sizeof_JNIHandleBlock;
    int32_t   jnih_block_capacity;
    /* Direct read of the pending exception so the dispatcher can substitute
     * JNI ExceptionCheck (index 228) without a JNI call after impl_fn returns.
     * VMStructs exposes Thread::_pending_exception as a stable field. */
    ptrdiff_t off_thread_pending_exception;
    /* === CodeCache / CodeHeap / VirtualSpace / GrowableArray / CodeBlob ===
     * Discovered via VMStructs so we can register our own CodeHeap into
     * HotSpot's _heaps list, making our trampoline PCs visible to
     * CodeCache::find_blob_at(). Phase 1 is read-only walking; Phase 2 will
     * allocate. */
    void *addr_codecache_heaps;          /* address of CodeCache::_heaps (a static field; deref to GrowableArray<CodeHeap*>*) */
    ptrdiff_t off_growable_array_len;    /* GrowableArrayBase::_len */
    ptrdiff_t off_growable_array_capacity;
    ptrdiff_t off_growable_array_data;   /* GrowableArray<E>::_data (we use the int specialization's offset) */
    ptrdiff_t off_codeheap_memory;       /* CodeHeap::_memory (VirtualSpace) */
    ptrdiff_t off_codeheap_segmap;       /* CodeHeap::_segmap (VirtualSpace) */
    ptrdiff_t off_codeheap_log2_segment_size;
    ptrdiff_t off_virtualspace_low_boundary;
    ptrdiff_t off_virtualspace_high_boundary;
    ptrdiff_t off_virtualspace_low;
    ptrdiff_t off_virtualspace_high;
    ptrdiff_t off_codeblob_name;
    ptrdiff_t off_codeblob_size;
    ptrdiff_t off_codeblob_header_size;
    ptrdiff_t off_codeblob_frame_complete_offset;
    ptrdiff_t off_codeblob_data_offset;
    ptrdiff_t off_codeblob_frame_size;
    ptrdiff_t off_codeblob_code_begin;
    ptrdiff_t off_codeblob_code_end;
    ptrdiff_t off_codeblob_content_begin;
    ptrdiff_t off_codeblob_data_end;
    size_t    sizeof_CodeHeap;           /* total size of CodeHeap object */
    size_t    sizeof_BufferBlob;
    size_t    sizeof_VirtualSpace;
    /* Vtable pointer harvested from a known existing BufferBlob in the cache.
     * Required to construct our own BufferBlob in-place. */
    void *bufferblob_vtable;
    /* CompressedOops state, recovered from VMStructs static entries
     *   CompressedOops::_narrow_oop._base   (address of an oop pointer)
     *   CompressedOops::_narrow_oop._shift  (address of an int)
     * These are static fields with non-NULL static_addr in gHotSpotVMStructs.
     * We capture their addresses here so native code can decode narrow oops
     * (`oop = (narrow << shift) + base`) directly from VMStructs. */
    void *addr_compressed_oops_base;
    void *addr_compressed_oops_shift;
    void *addr_compressed_klass_base;
    void *addr_compressed_klass_shift;
    void *addr_universe_collected_heap;
    void *addr_barrierset_barrier_set;
    void *addr_stringtable_the_table;
    void *addr_zglobals_instance_p;
    void *addr_zglobals_address_offset_mask;
    void *addr_zglobals_pointer_load_good_mask;
    void *addr_zglobals_pointer_load_bad_mask;
    void *addr_zglobals_pointer_store_good_mask;
    void *addr_zglobals_pointer_store_bad_mask;
    void *addr_zglobals_pointer_load_shift;
    ptrdiff_t off_zglobals_address_offset_mask;
    ptrdiff_t off_zglobals_pointer_load_good_mask;
    ptrdiff_t off_zglobals_pointer_load_bad_mask;
    ptrdiff_t off_zglobals_pointer_store_good_mask;
    ptrdiff_t off_zglobals_pointer_store_bad_mask;
    ptrdiff_t off_zglobals_pointer_load_shift;
    ptrdiff_t off_jcw_anchor;
    size_t    sizeof_JavaCallWrapper;
    /* === Native metadata resolution prerequisites (T0.1) ===
     * These are the VMStructs offsets and JVM/native symbols required before
     * bind-time class/method/field/string resolution may replace JNI lookup. */
    ptrdiff_t off_instanceklass_methods;
    ptrdiff_t off_instanceklass_fieldinfo_stream;
    ptrdiff_t off_instanceklass_fields;
    ptrdiff_t off_instanceklass_constants;
    ptrdiff_t off_instanceklass_local_interfaces;
    ptrdiff_t off_instanceklass_transitive_interfaces;
    ptrdiff_t off_instanceklass_java_fields_count;
    ptrdiff_t off_klass_super_check_offset;
    ptrdiff_t off_klass_secondary_super_cache;
    ptrdiff_t off_klass_secondary_supers;
    ptrdiff_t off_klass_primary_supers_0;
    ptrdiff_t off_klass_layout_helper;
    ptrdiff_t off_klass_java_mirror;
    ptrdiff_t off_klass_super;
    ptrdiff_t off_klass_subklass;
    ptrdiff_t off_klass_next_link;
    ptrdiff_t off_klass_name;
    ptrdiff_t off_objarrayklass_element_klass;
    ptrdiff_t off_java_lang_class_klass;
    void *addr_classloaderdatagraph_head;
    ptrdiff_t off_classloaderdata_next;
    ptrdiff_t off_classloaderdata_klasses;
    ptrdiff_t off_constantpool_tags;
    ptrdiff_t off_constantpool_cache;
    ptrdiff_t off_constantpool_pool_holder;
    ptrdiff_t off_constantpool_operands;
    ptrdiff_t off_constantpool_resolved_klasses;
    ptrdiff_t off_constantpool_length;
    ptrdiff_t off_constantpool_base;
    size_t    sizeof_ConstantPool;
    ptrdiff_t off_constmethod_constants;
    ptrdiff_t off_constmethod_name_index;
    ptrdiff_t off_constmethod_signature_index;
    ptrdiff_t off_symbol_length;
    ptrdiff_t off_symbol_body;
    ptrdiff_t off_array_length;
    ptrdiff_t off_array_data;
    ptrdiff_t off_array_u1_data;
    ptrdiff_t off_array_u2_data;
    ptrdiff_t off_barrierset_fake_rtti;
    ptrdiff_t off_barrierset_fakertti_concrete_tag;
    ptrdiff_t off_cardtablebarrierset_card_table;
    ptrdiff_t off_cardtable_byte_map_base;
    int32_t vmconst_barrierset_modref;
    int32_t vmconst_barrierset_cardtable;
    int32_t vmconst_barrierset_g1;
    int32_t vmconst_barrierset_z;
    int32_t vmconst_barrierset_shenandoah;
    int32_t vmconst_cardtable_clean_card;
    int32_t vmconst_cardtable_dirty_card;
    int32_t vmconst_g1_young_card;
    int32_t current_barrier_kind;
    void *current_barrier_set;
    void *current_card_table;
    void *card_table_byte_map_base;
    void *sym_g1_write_ref_array_pre_oop_entry;
    void *sym_g1_write_ref_field_pre_entry;
    void *sym_g1_write_ref_field_post_entry;
    void *sym_z_load_barrier_on_oop_field_preloaded;
    void *sym_z_load_barrier_on_oop_array;
    void *sym_z_store_barrier_on_oop_field_with_healing;
    ptrdiff_t off_z_thread_address_bad_mask;
    void *sym_shenandoah_load_reference_barrier_strong;
    void *sym_shenandoah_load_reference_barrier_strong_narrow;
    void *sym_shenandoah_write_ref_field_pre_entry;
    void *sym_shenandoah_arraycopy_barrier_oop_entry;
    void *sym_shenandoah_arraycopy_barrier_narrow_oop_entry;
    jboolean gc_barrier_ready;
    void *sym_jvm_find_loaded_class;
    void *sym_jvm_find_class_from_boot_loader;
    void *sym_jvm_find_class_from_class;
    void *sym_jvm_intern_string;
    void *sym_jvm_find_primitive_class;
    void *sym_jvm_new_array;
    void *sym_jvm_new_multi_array;
    void *sym_jvm_get_class_methods_count;
    void *sym_jvm_get_class_declared_methods;
    void *sym_jvm_get_class_declared_constructors;
    void *sym_systemdictionary_find_instance_klass;
    void *sym_systemdictionary_find_instance_or_array_klass;
    void *sym_stringtable_intern_symbol;
    void *sym_stringtable_intern_utf8;
    void *sym_oopfactory_new_type_array;
    void *sym_oopfactory_new_obj_array;
    jboolean native_resolution_ready;
    /* === Native→Java direct invoke ===
     * HotSpot does not publish StubRoutines::_call_stub_entry through
     * VMStructs, but it does publish _call_stub_return_address. We find the
     * owning initial-stubs CodeBlob and scan backward to the call_stub prologue.
     * The BasicType enum values feed call_stub's result_type argument. */
    void *addr_call_stub_return_address;   /* address of StubRoutines::_call_stub_return_address slot */
    int32_t basictype_void;
    int32_t basictype_boolean;
    int32_t basictype_byte;
    int32_t basictype_char;
    int32_t basictype_short;
    int32_t basictype_int;
    int32_t basictype_long;
    int32_t basictype_float;
    int32_t basictype_double;
    int32_t basictype_object;
    int32_t basictype_array;
    jboolean basictypes_resolved;
    /* Runtime1 monitor stubs and BasicObjectLock layout for native
     * MONITORENTER/MONITOREXIT. The stubs are not dlsym-exported on stripped
     * JDK 21 libjvm builds, so we harvest their CodeBlob entries by name while
     * walking CodeHeap. */
    void *runtime1_monitorenter_entry;
    void *runtime1_monitorexit_entry;
    ptrdiff_t off_basicobjectlock_lock;
    ptrdiff_t off_basicobjectlock_obj;
    ptrdiff_t off_basiclock_displaced_header;
    size_t sizeof_BasicObjectLock;
    size_t sizeof_BasicLock;
} neko_method_layout_t;

static neko_method_layout_t g_neko_method_layout = {0};

/* === Globals exported to naked-asm trampolines via RIP-relative loads. ===
 * Hidden visibility lets the linker resolve them to local definitions while
 * still allowing the inline asm to reference them as if external symbols. */
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_thread_state = 0;
__attribute__((visibility("hidden"))) int32_t   g_neko_thread_state_in_java = 0;
__attribute__((visibility("hidden"))) int32_t   g_neko_thread_state_in_native = 0;
__attribute__((visibility("hidden"))) int32_t   g_neko_thread_state_in_native_trans = 0;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_thread_polling_word = 0;
__attribute__((visibility("hidden"))) jboolean  g_neko_thread_state_ready = JNI_FALSE;
/* Final byte offsets within JavaThread for the frame anchor fields. Picked
 * from either the flat-field path (older JDKs) or _anchor + sub-offset. */
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_last_Java_sp = 0;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_last_Java_fp = 0;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_last_Java_pc = 0;
__attribute__((visibility("hidden"))) jboolean  g_neko_frame_anchor_ready = JNI_FALSE;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_thread_active_handles = 0;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_jnih_block_top      = 0;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_jnih_block_handles  = 0;
__attribute__((visibility("hidden"))) int32_t   g_neko_jnih_block_capacity     = 32;
__attribute__((visibility("hidden"))) jboolean  g_neko_handle_push_ready = JNI_FALSE;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_thread_tlab = 0;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_tlab_top = 0;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_tlab_end = 0;
__attribute__((visibility("hidden"))) jboolean  g_neko_tlab_alloc_ready = JNI_FALSE;
/* Final byte offset within JavaThread of the _pending_exception oop slot.
 * Set during VMStructs walk; used by the direct-call dispatcher to read the
 * pending exception without crossing the JNI boundary. */
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_thread_pending_exception = 0;
/* Mirror of g_neko_method_layout.off_thread_jni_environment, exported with a
 * stable hidden symbol so the inline neko_exception_check (declared in the
 * top-of-file region, before g_neko_method_layout exists) can subtract it
 * from JNIEnv* to derive the JavaThread*. Set once during layout init. */
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_thread_jni_environment_for_check = 0;
/* 0 unset, 1 VMStructs, 2 validated process cache, 3 cold memory walk. */
__attribute__((visibility("hidden"))) int32_t g_neko_env_offset_publication_kind = 0;
/* === Native→Java direct invoke globals ===
 * Exported so the per-shape direct dispatchers can issue a call into HotSpot's
 * shared call_stub without going through any JNI function pointer. The signed
 * int32_t BasicType slots match the third argument expected by the call_stub
 * (HotSpot's BasicType enum). g_neko_call_stub_entry holds the *current* entry
 * pointer — it is loaded once at OnLoad time from the StubRoutines static slot
 * (HotSpot doesn't repatch this pointer post-init in production builds). */
__attribute__((visibility("hidden"))) void *g_neko_call_stub_entry = NULL;
__attribute__((visibility("hidden"))) void *g_neko_call_stub_return_address = NULL;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_jcw_anchor = 0;
__attribute__((visibility("hidden"))) jboolean g_neko_direct_invoke_ready = JNI_FALSE;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_void    = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_boolean = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_byte    = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_char    = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_short   = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_int     = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_long    = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_float   = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_double  = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_object  = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_basictype_array   = 0;
__attribute__((visibility("hidden"))) void *g_neko_runtime1_monitorenter_entry = NULL;
__attribute__((visibility("hidden"))) void *g_neko_runtime1_monitorexit_entry = NULL;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_basicobjectlock_lock = -1;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_basicobjectlock_obj = -1;
__attribute__((visibility("hidden"))) ptrdiff_t g_neko_off_basiclock_displaced_header = -1;
__attribute__((visibility("hidden"))) size_t g_neko_sizeof_basicobjectlock = 0;
__attribute__((visibility("hidden"))) size_t g_neko_sizeof_basiclock = 0;
__attribute__((visibility("hidden"))) jboolean g_neko_monitor_stub_ready = JNI_FALSE;
/* HotSpot's r12_heapbase value — what %r12 must contain when calling
 * compiled Java code. The narrow_oop encode/decode in JIT'd methods reads
 * %r12 as the heap base register. Set once at OnLoad from the
 * CompressedOops::_narrow_oop._base static field. */
__attribute__((visibility("hidden"))) void *g_neko_heap_base = NULL;
__attribute__((visibility("hidden"))) void *g_neko_addr_compressed_oops_base = NULL;
__attribute__((visibility("hidden"))) void *g_neko_addr_compressed_oops_shift = NULL;
__attribute__((visibility("hidden"))) void *g_neko_addr_compressed_klass_base = NULL;
__attribute__((visibility("hidden"))) void *g_neko_addr_compressed_klass_shift = NULL;
/* Thread-register snapshot captured right at JNI_OnLoad entry, before any C
 * code can clobber r15 (x86_64) / x28 (AArch64). HotSpot keeps the current
 * JavaThread* there across the JNI dispatch. We use this to derive
 * off_thread_jni_environment when VMStructs does not export it (the field
 * is only registered in the JVMCI-only struct list). */
__attribute__((visibility("hidden"))) void *g_neko_jni_onload_thread_reg = NULL;
__attribute__((visibility("hidden"))) void *g_neko_jni_functions_table = NULL;
__attribute__((visibility("hidden"))) jboolean g_neko_native_resolution_ready = JNI_FALSE;
__attribute__((visibility("hidden"))) jboolean g_neko_gc_barrier_ready = JNI_FALSE;
__attribute__((visibility("hidden"))) int32_t g_neko_gc_barrier_kind = 0;
__attribute__((visibility("hidden"))) void *g_neko_barrier_load_oop_field_preloaded = NULL;
__attribute__((visibility("hidden"))) void *g_neko_barrier_load_oop_array = NULL;
__attribute__((visibility("hidden"))) void *g_neko_barrier_store_oop_field = NULL;
__attribute__((visibility("hidden"))) void *g_neko_barrier_write_ref_array_pre = NULL;
__attribute__((visibility("hidden"))) void *g_neko_barrier_write_ref_field_pre = NULL;
__attribute__((visibility("hidden"))) void *g_neko_barrier_write_ref_field_post = NULL;
__attribute__((visibility("hidden"))) void *g_neko_card_table_byte_map_base = NULL;
__attribute__((visibility("hidden"))) int32_t g_neko_card_table_dirty_card = 0;
__attribute__((visibility("hidden"))) int32_t g_neko_card_table_clean_card = -1;
__attribute__((visibility("hidden"))) int32_t g_neko_g1_young_card = -1;
__attribute__((visibility("hidden"))) int32_t g_neko_card_table_shift = 9;

enum {
    NEKO_GC_BARRIER_UNKNOWN = 0,
    NEKO_GC_BARRIER_CARDTABLE = 1,
    NEKO_GC_BARRIER_G1 = 2,
    NEKO_GC_BARRIER_Z = 3,
    NEKO_GC_BARRIER_SHENANDOAH = 4
};

/* Debug flag is cached once at JNI_OnLoad time. The original macro called
 * getenv("NEKO_PATCH_DEBUG") on every NEKO_PATCH_LOG invocation — and the
 * dispatcher hot path emits one such call per dispatch, so each native call
 * was crossing into libc to scan environ. Caching collapses that to a single
 * RIP-relative load + branch in release builds. */
__attribute__((visibility("hidden"))) int g_neko_patch_debug_cached = 0;
__attribute__((visibility("hidden"))) int g_neko_patch_debug_initialized = 0;
static inline int neko_patch_debug_enabled(void) {
    if (__builtin_expect(!g_neko_patch_debug_initialized, 0)) {
        g_neko_patch_debug_cached = (getenv("NEKO_PATCH_DEBUG") != NULL) ? 1 : 0;
        g_neko_patch_debug_initialized = 1;
    }
    return g_neko_patch_debug_cached;
}
#define NEKO_PATCH_DEBUG neko_patch_debug_enabled()
#define NEKO_PATCH_LOG(fmt, ...) do { if (__builtin_expect(NEKO_PATCH_DEBUG, 0)) { fprintf(stderr, "[neko-patch] " fmt "\\n", ##__VA_ARGS__); fflush(stderr); } } while (0)

static int neko_streq_safe(const char *a, const char *b) {
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}
static int neko_strstr_safe(const char *h, const char *n) {
    return h != NULL && n != NULL && strstr(h, n) != NULL;
}

#if defined(__linux__)
static int neko_find_libjvm_path(char *out, size_t cap) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[1024];
    if (fp == NULL) return 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *slash = strchr(line, '/');
        if (slash == NULL) continue;
        size_t len = strlen(slash);
        if (len > 0 && slash[len - 1] == '\\n') slash[len - 1] = '\\0';
        if (strstr(slash, "libjvm.so") != NULL) {
            size_t copy_len = strlen(slash);
            if (copy_len + 1 > cap) copy_len = cap - 1;
            memcpy(out, slash, copy_len);
            out[copy_len] = '\\0';
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}
#endif

static void* neko_resolve_libjvm_handle(void) {
#if defined(_WIN32)
    HMODULE hjvm = GetModuleHandleA("jvm.dll");
    if (hjvm == NULL) hjvm = LoadLibraryA("jvm.dll");
    return (void*)hjvm;
#elif defined(__linux__) || defined(__APPLE__)
    void *h = dlopen("libjvm.so", RTLD_NOLOAD | RTLD_NOW);
    if (h != NULL && dlsym(h, "gHotSpotVMStructs") != NULL) return h;
    h = dlopen("libjvm.so", RTLD_NOW);
    if (h != NULL && dlsym(h, "gHotSpotVMStructs") != NULL) return h;
#  if defined(__linux__)
    {
        char path[1024];
        if (neko_find_libjvm_path(path, sizeof(path))) {
            h = dlopen(path, RTLD_NOLOAD | RTLD_NOW);
            if (h != NULL && dlsym(h, "gHotSpotVMStructs") != NULL) return h;
            h = dlopen(path, RTLD_NOW);
            if (h != NULL && dlsym(h, "gHotSpotVMStructs") != NULL) return h;
        }
    }
#  endif
    if (dlsym(RTLD_DEFAULT, "gHotSpotVMStructs") != NULL) return (void*)(uintptr_t)0x1u;
    return NULL;
#else
    return NULL;
#endif
}

static void* neko_dlsym(void *h, const char *name) {
    if (h == NULL || name == NULL) return NULL;
#if defined(_WIN32)
    return (void*)GetProcAddress((HMODULE)h, name);
#else
    if ((uintptr_t)h == 0x1u) return dlsym(RTLD_DEFAULT, name);
    return dlsym(h, name);
#endif
}

static void neko_resolve_native_resolution_symbols(void *jvm) {
    if (jvm == NULL) return;
    g_neko_method_layout.sym_jvm_find_loaded_class =
        neko_dlsym(jvm, "JVM_FindLoadedClass");
    g_neko_method_layout.sym_jvm_find_class_from_boot_loader =
        neko_dlsym(jvm, "JVM_FindClassFromBootLoader");
    g_neko_method_layout.sym_jvm_find_class_from_class =
        neko_dlsym(jvm, "JVM_FindClassFromClass");
    g_neko_method_layout.sym_jvm_intern_string =
        neko_dlsym(jvm, "JVM_InternString");
    g_neko_method_layout.sym_jvm_find_primitive_class =
        neko_dlsym(jvm, "JVM_FindPrimitiveClass");
    g_neko_method_layout.sym_jvm_new_array =
        neko_dlsym(jvm, "JVM_NewArray");
    g_neko_method_layout.sym_jvm_new_multi_array =
        neko_dlsym(jvm, "JVM_NewMultiArray");
    g_neko_method_layout.sym_jvm_get_class_methods_count =
        neko_dlsym(jvm, "JVM_GetClassMethodsCount");
    g_neko_method_layout.sym_jvm_get_class_declared_methods =
        neko_dlsym(jvm, "JVM_GetClassDeclaredMethods");
    g_neko_method_layout.sym_jvm_get_class_declared_constructors =
        neko_dlsym(jvm, "JVM_GetClassDeclaredConstructors");
    /* Internal C++ symbols are stripped on common product builds. Resolve
     * them opportunistically for builds that export them, but readiness does
     * not treat their absence as a JNI fallback path. Later stages must either
     * use the stable JVM_* entries / VMStruct walk or abort. */
    g_neko_method_layout.sym_systemdictionary_find_instance_klass =
        neko_dlsym(jvm, "_ZN16SystemDictionary19find_instance_klassEP6ThreadP6Symbol6HandleS4_");
    g_neko_method_layout.sym_systemdictionary_find_instance_or_array_klass =
        neko_dlsym(jvm, "_ZN16SystemDictionary28find_instance_or_array_klassEP6ThreadP6Symbol6HandleS4_");
    g_neko_method_layout.sym_stringtable_intern_symbol =
        neko_dlsym(jvm, "_ZN11StringTable6internEP6SymbolP6Thread");
    g_neko_method_layout.sym_stringtable_intern_utf8 =
        neko_dlsym(jvm, "_ZN11StringTable6internEPKcP6Thread");
    g_neko_method_layout.sym_oopfactory_new_type_array =
        neko_dlsym(jvm, "_ZN10oopFactory13new_typeArrayE9BasicTypeiP6Thread");
    g_neko_method_layout.sym_oopfactory_new_obj_array =
        neko_dlsym(jvm, "_ZN10oopFactory12new_objArrayEP5KlassiP6Thread");
    g_neko_method_layout.addr_stringtable_the_table =
        neko_dlsym(jvm, "_ZN11StringTable10_the_tableE");
}

static void neko_resolve_gc_barrier_symbols(void *jvm) {
    if (jvm == NULL) return;
    g_neko_method_layout.sym_g1_write_ref_array_pre_oop_entry =
        neko_dlsym(jvm, "_ZN19G1BarrierSetRuntime29write_ref_array_pre_oop_entryEPP7oopDescm");
    g_neko_method_layout.sym_g1_write_ref_field_pre_entry =
        neko_dlsym(jvm, "_ZN19G1BarrierSetRuntime25write_ref_field_pre_entryEP7oopDescP10JavaThread");
    g_neko_method_layout.sym_g1_write_ref_field_post_entry =
        neko_dlsym(jvm, "_ZN19G1BarrierSetRuntime26write_ref_field_post_entryEPVhP10JavaThread");
    g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded =
        neko_dlsym(jvm, "_ZN18ZBarrierSetRuntime35load_barrier_on_oop_field_preloadedEP7oopDescPS0_");
    if (g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded == NULL) {
        g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded =
            neko_dlsym(jvm, "_ZN18XBarrierSetRuntime35load_barrier_on_oop_field_preloadedEP7oopDescPS0_");
    }
    g_neko_method_layout.sym_z_load_barrier_on_oop_array =
        neko_dlsym(jvm, "_ZN18ZBarrierSetRuntime25load_barrier_on_oop_arrayEPP7oopDescm");
    if (g_neko_method_layout.sym_z_load_barrier_on_oop_array == NULL) {
        g_neko_method_layout.sym_z_load_barrier_on_oop_array =
            neko_dlsym(jvm, "_ZN18XBarrierSetRuntime25load_barrier_on_oop_arrayEPP7oopDescm");
    }
    g_neko_method_layout.sym_z_store_barrier_on_oop_field_with_healing =
        neko_dlsym(jvm, "_ZN18ZBarrierSetRuntime39store_barrier_on_oop_field_with_healingEPP7oopDesc");
    if (g_neko_method_layout.sym_z_store_barrier_on_oop_field_with_healing == NULL) {
        g_neko_method_layout.sym_z_store_barrier_on_oop_field_with_healing =
            neko_dlsym(jvm, "_ZN18XBarrierSetRuntime39store_barrier_on_oop_field_with_healingEPP7oopDesc");
    }
    g_neko_method_layout.sym_shenandoah_load_reference_barrier_strong =
        neko_dlsym(jvm, "_ZN17ShenandoahRuntime29load_reference_barrier_strongEP7oopDescPS0_");
    g_neko_method_layout.sym_shenandoah_load_reference_barrier_strong_narrow =
        neko_dlsym(jvm, "_ZN17ShenandoahRuntime36load_reference_barrier_strong_narrowEP7oopDescPj");
    g_neko_method_layout.sym_shenandoah_write_ref_field_pre_entry =
        neko_dlsym(jvm, "_ZN17ShenandoahRuntime25write_ref_field_pre_entryEP7oopDescP10JavaThread");
    g_neko_method_layout.sym_shenandoah_arraycopy_barrier_oop_entry =
        neko_dlsym(jvm, "_ZN17ShenandoahRuntime27arraycopy_barrier_oop_entryEPP7oopDescS2_m");
    g_neko_method_layout.sym_shenandoah_arraycopy_barrier_narrow_oop_entry =
        neko_dlsym(jvm, "_ZN17ShenandoahRuntime34arraycopy_barrier_narrow_oop_entryEPjS0_m");
}

""";
    }

}
