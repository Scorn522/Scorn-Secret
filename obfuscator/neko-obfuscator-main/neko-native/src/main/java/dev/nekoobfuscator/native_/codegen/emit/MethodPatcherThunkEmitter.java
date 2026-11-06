package dev.nekoobfuscator.native_.codegen.emit;

/**
 * Emits entry thunk allocation and Method* patching routines.
 */
final class MethodPatcherThunkEmitter {
    private MethodPatcherThunkEmitter() {}

    static String render() {
        return """
static void *neko_alloc_rw_pages(size_t size) {
#if defined(__linux__) || defined(__APPLE__)
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
#else
    return NULL;
#endif
}

static void neko_codeheap_set_virtualspace(void *vspace, void *low, void *high) {
    *(void**)((char*)vspace + g_neko_method_layout.off_virtualspace_low_boundary) = low;
    *(void**)((char*)vspace + g_neko_method_layout.off_virtualspace_high_boundary) = high;
    *(void**)((char*)vspace + g_neko_method_layout.off_virtualspace_low) = low;
    *(void**)((char*)vspace + g_neko_method_layout.off_virtualspace_high) = high;
}

static jboolean neko_priv_heap_init(void) {
    if (g_neko_priv_heap.codeheap != NULL) return JNI_TRUE;
    if (!neko_codecache_layout_ready()) {
        NEKO_PATCH_LOG("priv heap init: codecache layout not ready");
        return JNI_FALSE;
    }
    if (g_neko_method_layout.sizeof_CodeHeap == 0) {
        NEKO_PATCH_LOG("priv heap init: sizeof(CodeHeap) unknown");
        return JNI_FALSE;
    }
    if (g_neko_method_layout.bufferblob_vtable == NULL) {
        NEKO_PATCH_LOG("priv heap init: vtable not harvested");
        return JNI_FALSE;
    }

    const size_t exec_bytes = NEKO_PRIV_HEAP_BYTES;
    const size_t seg_bytes  = NEKO_PRIV_SEGMENT_BYTES;
    const size_t segments   = exec_bytes / seg_bytes;

    void *exec = neko_alloc_exec_pages(exec_bytes);
    if (exec == NULL) { NEKO_PATCH_LOG("priv heap init: mmap exec failed"); return JNI_FALSE; }
    void *segmap = neko_alloc_rw_pages(segments);
    if (segmap == NULL) {
        NEKO_PATCH_LOG("priv heap init: mmap segmap failed");
        munmap(exec, exec_bytes);
        return JNI_FALSE;
    }
    /* segmap initial state: 0xFF means "no block here" / free.
     * HotSpot's CodeHeap::find_block_for treats 0xFF as a chain marker
     * meaning "skip 254 segments back" — for empty regions there's no
     * block to find, so find_blob_at will iterate to a different heap. */
    memset(segmap, 0xFF, segments);

    void *heap = calloc(1, g_neko_method_layout.sizeof_CodeHeap);
    if (heap == NULL) {
        munmap(exec, exec_bytes);
        munmap(segmap, segments);
        return JNI_FALSE;
    }

    /* Fill the two embedded VirtualSpace structs. */
    char *vs_mem = (char*)heap + g_neko_method_layout.off_codeheap_memory;
    char *vs_seg = (char*)heap + g_neko_method_layout.off_codeheap_segmap;
    neko_codeheap_set_virtualspace(vs_mem, exec, (char*)exec + exec_bytes);
    neko_codeheap_set_virtualspace(vs_seg, segmap, (char*)segmap + segments);

    /* log2_segment_size and friends. The neighbours' offsets are derived
     * from the VMStructs-exposed _log2_segment_size offset. Verified
     * against jdk-21.0.10 heap.hpp:
     *   ptrdiff_t off = g_neko_method_layout.off_codeheap_log2_segment_size;
     *   _number_of_committed_segments = off - 24
     *   _number_of_reserved_segments  = off - 16
     *   _segment_size                 = off - 8
     *   _log2_segment_size            = off       (int)
     *   _next_segment                 = off + 8   (skip 4-byte int + 4-byte pad)
     */
    ptrdiff_t off_log2 = g_neko_method_layout.off_codeheap_log2_segment_size;
    *(size_t*)((char*)heap + off_log2 - 24) = segments; /* _number_of_committed_segments */
    *(size_t*)((char*)heap + off_log2 - 16) = segments; /* _number_of_reserved_segments  */
    *(size_t*)((char*)heap + off_log2 - 8)  = seg_bytes;/* _segment_size */
    *(int*   )((char*)heap + off_log2)      = 7;        /* _log2_segment_size */
    *(size_t*)((char*)heap + off_log2 + 8)  = 0;        /* _next_segment (used segments) */

    g_neko_priv_heap.codeheap = heap;
    g_neko_priv_heap.exec_region = exec;
    g_neko_priv_heap.exec_size = exec_bytes;
    g_neko_priv_heap.segmap_region = segmap;
    g_neko_priv_heap.segmap_size = segments;
    g_neko_priv_heap.segment_size = seg_bytes;
    g_neko_priv_heap.next_byte = 0;
    g_neko_priv_heap.registered = JNI_FALSE;
    NEKO_PATCH_LOG("priv heap init: heap=%p exec=[%p..%p) segmap=[%p..%p)",
        heap, exec, (char*)exec + exec_bytes, segmap, (char*)segmap + segments);
    return JNI_TRUE;
}

static jboolean neko_priv_heap_register(void) {
    if (g_neko_priv_heap.codeheap == NULL) return JNI_FALSE;
    if (g_neko_priv_heap.registered) return JNI_TRUE;
    if (g_neko_method_layout.addr_codecache_heaps == NULL) return JNI_FALSE;
    void **heaps_static = (void**)g_neko_method_layout.addr_codecache_heaps;
    void *heaps_array = *heaps_static;
    if (heaps_array == NULL) return JNI_FALSE;
    int *len_ptr = (int*)((char*)heaps_array + g_neko_method_layout.off_growable_array_len);
    int *cap_ptr = (int*)((char*)heaps_array + g_neko_method_layout.off_growable_array_capacity);
    void ***data_pp = (void***)((char*)heaps_array + g_neko_method_layout.off_growable_array_data);
    int len = *len_ptr;
    int cap = *cap_ptr;
    void **data = *data_pp;
    NEKO_PATCH_LOG("priv heap register: heaps=%p len=%d cap=%d data=%p",
        heaps_array, len, cap, data);
    if (data == NULL) return JNI_FALSE;
    if (cap > len) {
        /* Slack capacity present — append in place. */
        data[len] = g_neko_priv_heap.codeheap;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        *len_ptr = len + 1;
        g_neko_priv_heap.registered = JNI_TRUE;
        NEKO_PATCH_LOG("priv heap register: appended at slot %d", len);
        return JNI_TRUE;
    }
    /* No slack. Build a brand-new GrowableArray with extra capacity, copy
     * old entries plus ours, then atomic-swap the static _heaps pointer.
     * The old array stays valid for any in-flight reader — leaks ~24 bytes
     * but that's a one-time cost.
     *
     * HotSpot only mutates _heaps in CodeCache::add_heap, which is gated
     * on !Universe::is_fully_initialized(). By the time our JNI_OnLoad
     * runs the universe is fully initialized, so HotSpot itself won't be
     * concurrently growing _heaps and we don't need a CodeCache_lock. */
    {
        size_t array_size = (size_t)g_neko_method_layout.off_growable_array_data + sizeof(void*);
        /* Pad to 16 bytes for safety (matches typical alignment). */
        array_size = (array_size + 15u) & ~(size_t)15u;
        void *new_array = calloc(1, array_size);
        if (new_array == NULL) {
            NEKO_PATCH_LOG("priv heap register: malloc new array failed");
            return JNI_FALSE;
        }
        int new_cap = len + 4;
        void **new_data = (void**)calloc((size_t)new_cap, sizeof(void*));
        if (new_data == NULL) {
            free(new_array);
            NEKO_PATCH_LOG("priv heap register: malloc new data failed");
            return JNI_FALSE;
        }
        for (int i = 0; i < len; i++) new_data[i] = data[i];
        new_data[len] = g_neko_priv_heap.codeheap;
        *(int*)((char*)new_array + g_neko_method_layout.off_growable_array_len) = len + 1;
        *(int*)((char*)new_array + g_neko_method_layout.off_growable_array_capacity) = new_cap;
        *(void***)((char*)new_array + g_neko_method_layout.off_growable_array_data) = new_data;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        __atomic_store_n(heaps_static, new_array, __ATOMIC_RELEASE);
        g_neko_priv_heap.registered = JNI_TRUE;
        NEKO_PATCH_LOG("priv heap register: swapped _heaps from %p to %p (len %d -> %d, cap %d -> %d)",
            heaps_array, new_array, len, len + 1, cap, new_cap);
        return JNI_TRUE;
    }
}

/* === Phase 3: per-signature thunk + CodeBlob construction ===
 * For each signature trampoline (lives in libneko.so), build a small
 * position-independent thunk inside our private CodeHeap exec region:
 *
 *   push   %rbp                          ;  1 byte
 *   mov    %rsp,%rbp                     ;  3 bytes
 *   movabs $real_trampoline_addr, %r11   ; 10 bytes
 *   call   *%r11                         ;  3 bytes
 *   pop    %rbp                          ;  1 byte
 *   ret                                  ;  1 byte
 *
 * Total 19 bytes (rounded up to a 32-byte tail). Around the thunk we lay
 * out a HeapBlock header (16 bytes: size_t _length, bool _used) and a
 * synthetic BufferBlob struct (vtable harvested from an existing adapter)
 * so HotSpot's CodeCache::find_blob_at(thunk_pc) can resolve the blob and
 * walk its metadata without crashing. Interpreter entries use an i2i thunk;
 * compiled entries use a c2i thunk so compiled callers keep a walkable callee
 * frame for RegisterMap saved-rbp tracking. */

/* Per-method thunks: each (Method*, entry-type) installs its own thunk that
 * pre-loads `r10 = manifest entry pointer` before calling the shared per-
 * signature naked function. This eliminates the O(N) manifest scan that the
 * naked function previously did on every invocation (matching rbx == Method*
 * against the primary + alias arrays). For obfusjack with hundreds of patched
 * methods, the scan was the single largest per-call cost.
 *
 * Slot count: bindings * 3 (interp i2i / path-2 i2i / c2i) plus a margin for
 * defineClass aliases. 4096 covers ~1300 methods, well above realistic jars. */
#define NEKO_PRIV_THUNK_SLOT_MAX 4096

typedef struct {
    void *real_trampoline;   /* libneko.so trampoline PC */
    int   frame_size_words;  /* BufferBlob _frame_size for this thunk */
    void *entry_ptr;         /* manifest entry pointer baked into thunk's r10 immediate */
    void *thunk_pc;          /* relocated thunk PC inside our exec heap */
} neko_priv_thunk_slot_t;

static neko_priv_thunk_slot_t g_neko_priv_thunks[NEKO_PRIV_THUNK_SLOT_MAX] = {0};
static uint32_t g_neko_priv_thunk_count = 0;

/* Round x up to multiple of n (n must be power-of-two). */
#define NEKO_ROUND_UP(x, n) (((x) + ((n) - 1u)) & ~((typeof(x))(n) - 1u))

static void *neko_priv_alloc_thunk(void *real_trampoline, int frame_size_words, void *entry_ptr) {
    if (g_neko_priv_heap.codeheap == NULL || !g_neko_priv_heap.registered) return NULL;
    if (real_trampoline == NULL) return NULL;
    if (g_neko_method_layout.bufferblob_vtable == NULL) return NULL;
    if (g_neko_method_layout.sizeof_BufferBlob == 0) return NULL;

    /* Layout inside one segment-aligned block:
     *   [HeapBlock header (16)]  [BufferBlob struct]  [thunk (48)]
     * Round total bytes up to segment_size. The thunk now embeds an extra
     * 10-byte movabs r10,$entry_ptr so the naked trampoline can skip the
     * manifest scan; bumped from 32 to 48 bytes to keep 16-byte alignment. */
    const size_t header_bytes = 16;
    const size_t blob_bytes   = g_neko_method_layout.sizeof_BufferBlob;
    const size_t thunk_bytes  = 48;
    size_t total = header_bytes + blob_bytes + thunk_bytes;
    size_t seg_bytes = g_neko_priv_heap.segment_size;
    size_t segments  = (total + seg_bytes - 1u) / seg_bytes;
    size_t block_bytes = segments * seg_bytes;
    if (g_neko_priv_heap.next_byte + block_bytes > g_neko_priv_heap.exec_size) return NULL;

    char *block = (char*)g_neko_priv_heap.exec_region + g_neko_priv_heap.next_byte;
    size_t base_segment = g_neko_priv_heap.next_byte / seg_bytes;
    g_neko_priv_heap.next_byte += block_bytes;

    /* HeapBlock header. _length is in segment units (per HotSpot). _used==1. */
    *(size_t*)block = segments;
    *(int8_t*)(block + sizeof(size_t)) = 1;
    /* Remaining bytes of the 16-byte header are zero. */

    /* BufferBlob: vtable + _name + _size + _header_size + _data_offset +
     * _frame_complete_offset + _frame_size + _code_begin/_code_end +
     * _content_begin/_data_end. Everything else stays zero (calloc'd region). */
    char *blob = block + header_bytes;
    memset(blob, 0, blob_bytes);
    *(void**)blob = g_neko_method_layout.bufferblob_vtable;
    if (g_neko_method_layout.off_codeblob_name > 0) {
        *(const char**)(blob + g_neko_method_layout.off_codeblob_name) = "neko_trampoline";
    }
    if (g_neko_method_layout.off_codeblob_size > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_size) = (int)block_bytes;
    }
    if (g_neko_method_layout.off_codeblob_header_size > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_header_size) = (int)blob_bytes;
    }
    /* CodeBlob::content/code/data layout: code starts immediately after the
     * BufferBlob struct ends; thunk_bytes is its length; no data section. */
    char *code_begin = blob + blob_bytes;
    char *code_end   = code_begin + thunk_bytes;
    if (g_neko_method_layout.off_codeblob_code_begin > 0) {
        *(void**)(blob + g_neko_method_layout.off_codeblob_code_begin) = code_begin;
    }
    if (g_neko_method_layout.off_codeblob_code_end > 0) {
        *(void**)(blob + g_neko_method_layout.off_codeblob_code_end) = code_end;
    }
    if (g_neko_method_layout.off_codeblob_content_begin > 0) {
        *(void**)(blob + g_neko_method_layout.off_codeblob_content_begin) = code_begin;
    }
    if (g_neko_method_layout.off_codeblob_data_end > 0) {
        *(void**)(blob + g_neko_method_layout.off_codeblob_data_end) = code_end;
    }
    /* _data_offset is computed in CodeBlob constructors as relative to
     * the blob start. Setting it to point at code_end keeps any
     * data_address() reads inside the blob bounds. */
    if (g_neko_method_layout.off_codeblob_data_offset > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_data_offset) = (int)(blob_bytes + thunk_bytes);
    }
    /* The thunk creates a tiny real frame before calling into libneko. The
     * libneko trampoline tail-jumps back to Java with rsp restored from r13,
     * so this frame is discarded instead of returned through. HotSpot can
     * nevertheless walk it while JNI upcalls are active because the synthetic
     * BufferBlob reports a coherent three-word frame. With last_Java_sp
     * published as the return-to-libneko slot, HotSpot computes
     * sender_sp = sp + frame_size = Java caller sp after its return pc,
     * then reads [sender_sp - 2] as saved rbp and [sender_sp - 1] as the
     * Java return pc:
     *   [return-to-libneko] [saved rbp] [Java return pc]
     */
    if (g_neko_method_layout.off_codeblob_frame_complete_offset > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_frame_complete_offset) = 4;
    }
    if (g_neko_method_layout.off_codeblob_frame_size > 0) {
        /* Path-2-aware sizing. The base 3 words cover the thunk's own frame
         * (thunk's saved-rbp + thunk_after_call_pc + naked's saved-rbp). For
         * thunks installed as _i2i_entry (reached via HotSpot's c2i adapter),
         * we add the adapter's extraspace shift in word units so
         * sender_sp = caller_pre_call_rsp matches accept's true _sp. */
        *(int*)(blob + g_neko_method_layout.off_codeblob_frame_size) = frame_size_words;
    }

    /* Thunk bytes (29 used + 0xCC pad to 48):
     *   push rbp                   ; 0x55                   [1]
     *   mov  rsp,rbp               ; 0x48 0x89 0xE5         [3]
     *   movabs $entry_ptr,%r10     ; 0x49 0xBA imm64        [10]  -- per-method preload
     *   movabs $real_trampoline,%r11; 0x49 0xBB imm64       [10]
     *   call  *%r11                ; 0x41 0xFF 0xD3         [3]
     *   pop  rbp                   ; 0x5D                   [1]
     *   ret                        ; 0xC3                   [1]
     * The naked trampoline reads %r10 immediately as its "entry pointer"
     * (formerly recovered via a manifest scan keyed on rbx == Method*).
     * i2i never returns through `pop rbp; ret` — it tail-jumps back to Java
     * via r13. c2i does return normally through this thunk frame. */
    char *thunk = code_begin;
    /* push rbp ; mov rsp,rbp */
    thunk[0] = (char)0x55;
    thunk[1] = (char)0x48; thunk[2] = (char)0x89; thunk[3] = (char)0xE5;
    /* movabs $entry_ptr, %r10  ;  REX.W + B8+r10 register encoding = 0x49 0xBA */
    thunk[4] = (char)0x49; thunk[5] = (char)0xBA;
    memcpy(thunk + 6, &entry_ptr, sizeof(void*));
    /* movabs $real_trampoline, %r11 */
    thunk[14] = (char)0x49; thunk[15] = (char)0xBB;
    memcpy(thunk + 16, &real_trampoline, sizeof(void*));
    /* call *%r11 */
    thunk[24] = (char)0x41; thunk[25] = (char)0xFF; thunk[26] = (char)0xD3;
    /* pop rbp ; ret */
    thunk[27] = (char)0x5D;
    thunk[28] = (char)0xC3;
    for (size_t i = 29; i < thunk_bytes; i++) thunk[i] = (char)0xCC;

    /* Segmap: HotSpot encodes "segments since the start of this block" at
     * each segment index. Index 0 is 0, index 1 is 1, ..., capped at 0xFE
     * (0xFF means "not allocated / chain marker"). */
    char *segmap = (char*)g_neko_priv_heap.segmap_region;
    for (size_t i = 0; i < segments; i++) {
        segmap[base_segment + i] = (char)(i < 0xFEu ? i : 0xFEu);
    }

    /* _next_segment: HotSpot's bump-pointer cursor. Updated so future scans
     * iterate up to here. We're the sole writer, so a plain store suffices. */
    ptrdiff_t off_log2 = g_neko_method_layout.off_codeheap_log2_segment_size;
    *(size_t*)((char*)g_neko_priv_heap.codeheap + off_log2 + 8) = base_segment + segments;

    NEKO_PATCH_LOG("priv thunk: real=%p thunk=%p blob=%p seg_base=%zu segs=%zu entry=%p",
        real_trampoline, code_begin, blob, base_segment, segments, entry_ptr);
    return code_begin;
}

static void *neko_priv_get_thunk(void *real_trampoline, int frame_size_words, void *entry_ptr) {
    if (real_trampoline == NULL) return NULL;
    /* Dedup keyed on (trampoline, frame_size, entry_ptr). With per-method
     * thunks each entry_ptr is unique, so dedup mostly helps re-entrant
     * patching of the same Method* (defineClass alias replays). */
    for (uint32_t i = 0; i < g_neko_priv_thunk_count; i++) {
        if (g_neko_priv_thunks[i].real_trampoline == real_trampoline
            && g_neko_priv_thunks[i].frame_size_words == frame_size_words
            && g_neko_priv_thunks[i].entry_ptr == entry_ptr) {
            return g_neko_priv_thunks[i].thunk_pc;
        }
    }
    if (g_neko_priv_thunk_count >= NEKO_PRIV_THUNK_SLOT_MAX) return NULL;
    void *thunk = neko_priv_alloc_thunk(real_trampoline, frame_size_words, entry_ptr);
    if (thunk == NULL) return NULL;
    g_neko_priv_thunks[g_neko_priv_thunk_count].real_trampoline = real_trampoline;
    g_neko_priv_thunks[g_neko_priv_thunk_count].frame_size_words = frame_size_words;
    g_neko_priv_thunks[g_neko_priv_thunk_count].entry_ptr = entry_ptr;
    g_neko_priv_thunks[g_neko_priv_thunk_count].thunk_pc = thunk;
    g_neko_priv_thunk_count++;
    return thunk;
}

/* === Native→Java trampoline CodeBlob registration ===
 *
 * Copy each generated native→Java trampoline into the private CodeHeap and
 * wrap the copied bytes in a synthetic BufferBlob. The copied code contains
 * the `call *Method::_from_compiled_entry` instruction, so a Java callee's
 * sender PC is inside a HotSpot-recognized CodeBlob instead of libneko text.
 * That is the property fillInStackTrace/GC stack walks need. */

typedef struct {
    void *code_start;
    void *code_end;
    void *wrapper_pc;
} neko_priv_njx_wrapper_slot_t;

static neko_priv_njx_wrapper_slot_t g_neko_priv_njx_wrappers[256] = {0};
static uint32_t g_neko_priv_njx_wrapper_count = 0;

static void *neko_priv_alloc_njx_trampoline(void *code_start_src, void *code_end_src, int frame_size_words) {
    if (g_neko_priv_heap.codeheap == NULL || !g_neko_priv_heap.registered) return NULL;
    if (code_start_src == NULL || code_end_src == NULL || (char*)code_end_src <= (char*)code_start_src) return NULL;
    if (frame_size_words <= 0) return NULL;
    if (g_neko_method_layout.bufferblob_vtable == NULL) return NULL;
    if (g_neko_method_layout.sizeof_BufferBlob == 0) return NULL;

    /* Dedup. */
    for (uint32_t i = 0; i < g_neko_priv_njx_wrapper_count; i++) {
        if (g_neko_priv_njx_wrappers[i].code_start == code_start_src
            && g_neko_priv_njx_wrappers[i].code_end == code_end_src) {
            return g_neko_priv_njx_wrappers[i].wrapper_pc;
        }
    }
    if (g_neko_priv_njx_wrapper_count >= 256) return NULL;

    const size_t header_bytes = 16;
    const size_t blob_bytes   = g_neko_method_layout.sizeof_BufferBlob;
    const size_t code_bytes   = (size_t)((char*)code_end_src - (char*)code_start_src);
    const size_t code_alloc_bytes = (code_bytes + 15u) & ~(size_t)15u;
    size_t total = header_bytes + blob_bytes + code_alloc_bytes;
    size_t seg_bytes = g_neko_priv_heap.segment_size;
    size_t segments  = (total + seg_bytes - 1u) / seg_bytes;
    size_t block_bytes = segments * seg_bytes;
    if (g_neko_priv_heap.next_byte + block_bytes > g_neko_priv_heap.exec_size) return NULL;

    char *block = (char*)g_neko_priv_heap.exec_region + g_neko_priv_heap.next_byte;
    size_t base_segment = g_neko_priv_heap.next_byte / seg_bytes;
    g_neko_priv_heap.next_byte += block_bytes;

    /* HeapBlock header. */
    *(size_t*)block = segments;
    *(int8_t*)(block + sizeof(size_t)) = 1;

    /* BufferBlob struct. */
    char *blob = block + header_bytes;
    memset(blob, 0, blob_bytes);
    *(void**)blob = g_neko_method_layout.bufferblob_vtable;
    if (g_neko_method_layout.off_codeblob_name > 0) {
        *(const char**)(blob + g_neko_method_layout.off_codeblob_name) = "neko_njx_trampoline";
    }
    if (g_neko_method_layout.off_codeblob_size > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_size) = (int)block_bytes;
    }
    if (g_neko_method_layout.off_codeblob_header_size > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_header_size) = (int)blob_bytes;
    }
    char *code_begin = blob + blob_bytes;
    char *code_end   = code_begin + code_bytes;
    if (g_neko_method_layout.off_codeblob_code_begin > 0) {
        *(void**)(blob + g_neko_method_layout.off_codeblob_code_begin) = code_begin;
    }
    if (g_neko_method_layout.off_codeblob_code_end > 0) {
        *(void**)(blob + g_neko_method_layout.off_codeblob_code_end) = code_end;
    }
    if (g_neko_method_layout.off_codeblob_content_begin > 0) {
        *(void**)(blob + g_neko_method_layout.off_codeblob_content_begin) = code_begin;
    }
    if (g_neko_method_layout.off_codeblob_data_end > 0) {
        *(void**)(blob + g_neko_method_layout.off_codeblob_data_end) = code_begin + code_alloc_bytes;
    }
    if (g_neko_method_layout.off_codeblob_data_offset > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_data_offset) = (int)(blob_bytes + code_alloc_bytes);
    }
    if (g_neko_method_layout.off_codeblob_frame_complete_offset > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_frame_complete_offset) = 4;
    }
    if (g_neko_method_layout.off_codeblob_frame_size > 0) {
        *(int*)(blob + g_neko_method_layout.off_codeblob_frame_size) = frame_size_words;
    }

    memcpy(code_begin, code_start_src, code_bytes);
    for (size_t i = code_bytes; i < code_alloc_bytes; i++) code_begin[i] = (char)0xCC;
    __builtin___clear_cache(code_begin, code_begin + code_alloc_bytes);

    /* Segmap. */
    char *segmap = (char*)g_neko_priv_heap.segmap_region;
    for (size_t i = 0; i < segments; i++) {
        segmap[base_segment + i] = (char)(i < 0xFEu ? i : 0xFEu);
    }
    ptrdiff_t off_log2 = g_neko_method_layout.off_codeheap_log2_segment_size;
    *(size_t*)((char*)g_neko_priv_heap.codeheap + off_log2 + 8) = base_segment + segments;

    g_neko_priv_njx_wrappers[g_neko_priv_njx_wrapper_count].code_start = code_start_src;
    g_neko_priv_njx_wrappers[g_neko_priv_njx_wrapper_count].code_end = code_end_src;
    g_neko_priv_njx_wrappers[g_neko_priv_njx_wrapper_count].wrapper_pc = code_begin;
    g_neko_priv_njx_wrapper_count++;

    NEKO_PATCH_LOG("[neko-direct] njx trampoline copied src=[%p..%p) dst=%p bytes=%zu frame=%d",
        code_start_src, code_end_src, code_begin, code_bytes, frame_size_words);
    return code_begin;
}

static jboolean neko_codecache_walk(void) {
    if (!neko_codecache_layout_ready()) {
        NEKO_PATCH_LOG("codecache walk: layout not ready");
        return JNI_FALSE;
    }
    void *heaps_array = *(void**)g_neko_method_layout.addr_codecache_heaps;
    if (heaps_array == NULL) {
        NEKO_PATCH_LOG("codecache walk: _heaps is NULL");
        return JNI_FALSE;
    }
    int len = *(int*)((char*)heaps_array + g_neko_method_layout.off_growable_array_len);
    void **data = *(void***)((char*)heaps_array + g_neko_method_layout.off_growable_array_data);
    NEKO_PATCH_LOG("codecache walk: heaps=%p len=%d data=%p", heaps_array, len, data);
    if (data == NULL || len <= 0) return JNI_FALSE;
    neko_blob_visit_ctx_t ctx = {0};
    if (g_neko_method_layout.addr_call_stub_return_address != NULL) {
        ctx.call_stub_return_pc = *(void**)g_neko_method_layout.addr_call_stub_return_address;
    }
    for (int i = 0; i < len; i++) {
        void *heap = data[i];
        if (heap == NULL) continue;
        void *mem_low = neko_virtualspace_low((char*)heap + g_neko_method_layout.off_codeheap_memory);
        void *mem_high = neko_virtualspace_high((char*)heap + g_neko_method_layout.off_codeheap_memory);
        int log2_seg = *(int*)((char*)heap + g_neko_method_layout.off_codeheap_log2_segment_size);
        NEKO_PATCH_LOG("codeheap[%d]=%p memory=[%p..%p) log2_seg=%d", i, heap, mem_low, mem_high, log2_seg);
        neko_walk_codeheap(heap, neko_blob_visit_log, &ctx);
    }
    g_neko_method_layout.bufferblob_vtable = ctx.target_vtable;
    if (ctx.call_stub_entry != NULL) {
        g_neko_call_stub_return_address = ctx.call_stub_return_pc;
        g_neko_call_stub_entry = ctx.call_stub_entry;
    }
    NEKO_PATCH_LOG("codecache walk: harvested vtable=%p call_stub=%p ret=%p sizeof(CodeHeap)=%zu sizeof(BufferBlob)=%zu sizeof(VirtualSpace)=%zu",
        ctx.target_vtable, g_neko_call_stub_entry, g_neko_call_stub_return_address,
        g_neko_method_layout.sizeof_CodeHeap,
        g_neko_method_layout.sizeof_BufferBlob, g_neko_method_layout.sizeof_VirtualSpace);
    return ctx.target_vtable != NULL ? JNI_TRUE : JNI_FALSE;
}

""";
    }

}
