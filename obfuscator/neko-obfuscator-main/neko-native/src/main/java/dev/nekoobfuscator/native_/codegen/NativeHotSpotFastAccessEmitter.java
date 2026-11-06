package dev.nekoobfuscator.native_.codegen;

/**
 * Emits HotSpot fast-path field and primitive-array access helpers.
 */
final class NativeHotSpotFastAccessEmitter {
    private NativeHotSpotFastAccessEmitter() {}

    static String renderHotSpotFastAccessHelpers() {
        StringBuilder sb = new StringBuilder();
        sb.append("""

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define NEKO_FAST_INLINE static inline
#else
#define NEKO_FAST_INLINE static
#endif

#if defined(__GNUC__) || defined(__clang__)
#define NEKO_LIKELY(x)   __builtin_expect(!!(x), 1)
#define NEKO_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define NEKO_FLATTEN     __attribute__((flatten))
#define NEKO_HOT         __attribute__((hot))
/* Apply only to the function DEFINITION (not the forward declaration). When
 * the body is in scope at the call site, the compiler must inline. When the
 * body is not yet in scope (forward-declared callers), the function is left
 * out-of-line at that call — which is the only safe behavior. */
#define NEKO_HOT_INLINE  static inline __attribute__((always_inline))
/* `pure` lets the compiler CSE/hoist the call across iterations of a loop
 * that contains no other calls / volatile accesses / safepoint-eligible
 * operations. Translated impl bodies between two opcodes have no implicit
 * safepoints — HotSpot only safepoints at JVM-controlled boundaries, and
 * the inner k-loop of a pure-arithmetic body never enters one. Use sparingly
 * on helpers whose return value depends only on their args + globals that
 * are stable for the lifetime of a hot region (no allocation, no JNI). */
#define NEKO_PURE_INLINE static inline __attribute__((always_inline, pure))
/* `const` is stronger than `pure`: the function is treated as if it depends
 * only on its arguments and never observes mutable memory. Applied to
 * accessors over g_hotspot fields that are written once at OnLoad and never
 * mutated again. The "lie" is that the function does load from memory; in
 * exchange the compiler aggressively CSEs/hoists/LICMs across calls.
 *
 * Safety: only apply to accessors whose backing storage is genuinely
 * write-once (post-OnLoad). Never apply to anything that can change after
 * the bootstrap publishes capability bits. */
#define NEKO_CONST_INLINE static inline __attribute__((always_inline, const))
#else
#define NEKO_LIKELY(x)   (x)
#define NEKO_UNLIKELY(x) (x)
#define NEKO_FLATTEN
#define NEKO_HOT
#define NEKO_HOT_INLINE  NEKO_FAST_INLINE
#define NEKO_PURE_INLINE NEKO_FAST_INLINE
#define NEKO_CONST_INLINE NEKO_FAST_INLINE
#endif

#if defined(__GNUC__) || defined(__clang__)
/* Tell the optimizer a runtime invariant is true so it can prune the cold
 * recheck branches that the per-call helpers carry. Used at translated
 * impl entry to fold away every per-iteration capability check. */
#define NEKO_ASSUME(cond) do { if (!(cond)) __builtin_unreachable(); } while (0)
#else
#define NEKO_ASSUME(cond) ((void)0)
#endif

/* g_hotspot_const_storage is defined earlier (alongside g_hotspot) so that
 * the one-shot freeze memcpy at the end of neko_hotspot_init can reach it.
 * Hot paths read through this const-typed alias, which keeps the same
 * backing memory but tells the optimizer the read is repeatable. */
#if defined(__GNUC__) || defined(__clang__)
extern const neko_hotspot_state g_hotspot_const __attribute__((alias("g_hotspot_const_storage")));
#else
#define g_hotspot_const g_hotspot_const_storage
#endif

/* Const accessors over post-OnLoad-immutable g_hotspot fields. The compiler
 * treats each call as returning the same value forever, enabling LICM out of
 * inner loops and CSE across translated opcodes. Backing storage IS modified
 * once during JNI_OnLoad — we deliberately lie to the compiler so it can do
 * cross-iteration motion. The bootstrap publishes all fields before any
 * translated impl_X function is reachable, so reads observed by the
 * compiler-visible "constant" view are always after the publish. */
NEKO_CONST_INLINE int32_t neko_const_array_length_offset(void) {
    return g_hotspot_const.array_length_offset;
}
NEKO_CONST_INLINE int32_t neko_const_klass_offset_bytes(void) {
    return g_hotspot_const.klass_offset_bytes;
}
NEKO_CONST_INLINE jboolean neko_const_use_zgc(void) {
    return g_hotspot_const.use_zgc;
}
NEKO_CONST_INLINE jboolean neko_const_use_compressed_klass_ptrs(void) {
    return g_hotspot_const.use_compressed_klass_ptrs;
}
NEKO_CONST_INLINE jboolean neko_const_compressed_oops_enabled(void) {
    return g_hotspot_const.compressed_oops_enabled;
}
NEKO_CONST_INLINE int32_t neko_const_compressed_oops_shift(void) {
    return g_hotspot_const.compressed_oops_shift;
}
NEKO_CONST_INLINE jlong neko_const_compressed_oops_base(void) {
    return g_hotspot_const.compressed_oops_base;
}
NEKO_CONST_INLINE jlong neko_const_fast_bits(void) {
    return g_hotspot_const.fast_bits;
}
NEKO_CONST_INLINE jboolean neko_const_initialized(void) {
    return g_hotspot_const.initialized;
}
NEKO_CONST_INLINE int32_t neko_const_gc_kind(void) {
    return g_neko_gc_barrier_kind;
}
NEKO_CONST_INLINE int32_t neko_const_prim_array_base(int kind) {
    return g_hotspot_const.primitive_array_base_offsets[kind];
}
NEKO_CONST_INLINE int32_t neko_const_prim_array_scale(int kind) {
    return g_hotspot_const.primitive_array_index_scales[kind];
}
NEKO_CONST_INLINE size_t neko_const_oop_ref_size(void) {
    return neko_const_compressed_oops_enabled() ? 4u : sizeof(void*);
}

/* One-shot capability gate emitted at the top of every translated impl. After
 * the gate, NEKO_ASSUME tells the compiler the bits are known so it can fold
 * away every per-iteration recheck inside the inlined fast helpers. */
NEKO_HOT_INLINE void neko_hotspot_fast_require(void *thread, JNIEnv *env) {
    (void)env;
    if (NEKO_UNLIKELY(!neko_const_initialized())) {
        fprintf(stderr, "[neko-direct] hotspot layout uninitialized at impl entry thread=%p\\n", thread);
        abort();
    }
    if (NEKO_UNLIKELY(thread == NULL)) {
        fprintf(stderr, "[neko-direct] hotspot fast path requires non-NULL thread\\n");
        abort();
    }
    int32_t kind = neko_const_gc_kind();
    if (NEKO_UNLIKELY(kind != NEKO_EARLY_GC_BARRIER_G1
                   && kind != NEKO_EARLY_GC_BARRIER_CARDTABLE
                   && kind != NEKO_EARLY_GC_BARRIER_Z
                   && kind != NEKO_EARLY_GC_BARRIER_SHENANDOAH)) {
        fprintf(stderr, "[neko-direct] hotspot fast path: unsupported gc barrier kind=%d\\n", (int)kind);
        abort();
    }
    /* Hand the compiler invariants it can use to fold per-iteration checks. */
    NEKO_ASSUME(neko_const_initialized());
    NEKO_ASSUME(thread != NULL);
    NEKO_ASSUME(neko_const_array_length_offset() >= 0);
    NEKO_ASSUME(neko_const_prim_array_base(NEKO_PRIM_I) >= 0);
    NEKO_ASSUME(neko_const_prim_array_base(NEKO_PRIM_B) >= 0);
}

NEKO_HOT_INLINE void neko_hotspot_fast_assume(void *thread) {
    NEKO_ASSUME(neko_const_initialized());
    NEKO_ASSUME(thread != NULL);
    NEKO_ASSUME(neko_const_array_length_offset() >= 0);
    NEKO_ASSUME(neko_const_prim_array_base(NEKO_PRIM_I) >= 0);
    NEKO_ASSUME(neko_const_prim_array_base(NEKO_PRIM_B) >= 0);
}

NEKO_HOT_INLINE uintptr_t neko_zgc_addr_mask(void) {
    uintptr_t value;
    if (g_hotspot.z_zglobals_addr_mask_p != NULL) {
        value = *(uintptr_t*)g_hotspot.z_zglobals_addr_mask_p;
        if (value != 0) return value;
    }
    return g_hotspot.z_address_offset_mask;
}

NEKO_HOT_INLINE uintptr_t neko_zgc_load_good_mask(void) {
    uintptr_t value;
    if (g_hotspot.z_zglobals_load_good_mask_p != NULL) {
        value = *(uintptr_t*)g_hotspot.z_zglobals_load_good_mask_p;
        if (value != 0) return value;
    }
    return g_hotspot.z_pointer_load_good_mask;
}

NEKO_HOT_INLINE uintptr_t neko_zgc_load_bad_mask(void) {
    uintptr_t value;
    if (g_hotspot.z_zglobals_load_bad_mask_p != NULL) {
        value = *(uintptr_t*)g_hotspot.z_zglobals_load_bad_mask_p;
        if (value != 0) return value;
    }
    return g_hotspot.z_pointer_load_bad_mask;
}

NEKO_HOT_INLINE uintptr_t neko_zgc_store_good_mask(void) {
    uintptr_t value;
    if (g_hotspot.z_zglobals_store_good_mask_p != NULL) {
        value = *(uintptr_t*)g_hotspot.z_zglobals_store_good_mask_p;
        if (value != 0) return value;
    }
    return g_hotspot.z_pointer_store_good_mask;
}

NEKO_HOT_INLINE uintptr_t neko_zgc_store_bad_mask(void) {
    uintptr_t value;
    if (g_hotspot.z_zglobals_store_bad_mask_p != NULL) {
        value = *(uintptr_t*)g_hotspot.z_zglobals_store_bad_mask_p;
        if (value != 0) return value;
    }
    return g_hotspot.z_pointer_store_bad_mask;
}

NEKO_HOT_INLINE void neko_zgc_abort_missing_masks(const char *where, uintptr_t addr_mask, uintptr_t good_mask) {
    if (NEKO_UNLIKELY(addr_mask == 0 || good_mask == 0)) {
        fprintf(stderr, "[neko-direct] ZGC %s masks unavailable addr=0x%llx good=0x%llx\\n",
            where != NULL ? where : "oop",
            (unsigned long long)addr_mask,
            (unsigned long long)good_mask);
        abort();
    }
}

NEKO_HOT_INLINE jboolean neko_zgc_try_bootstrap_sample_masks(uintptr_t sample) {
    /* JDK 21 x86 ZGC pointer metadata is dynamic low-bit state published
     * by ZGlobalsForVMStructs. A single sampled oop cannot safely derive
     * load/store good/bad masks, so missing live masks must fail closed. */
    (void)sample;
    return JNI_FALSE;
}
NEKO_HOT_INLINE jboolean neko_ref_is_direct_oop(jobject ref) {
    uintptr_t raw;
    if (ref == NULL) return JNI_FALSE;
    raw = (uintptr_t)ref;
    if (NEKO_UNLIKELY(neko_const_use_zgc())) {
        uintptr_t addr_mask = neko_zgc_addr_mask();
        uintptr_t load_good = neko_zgc_load_good_mask();
        uintptr_t store_good = neko_zgc_store_good_mask();
        uintptr_t load_bad = neko_zgc_load_bad_mask();
        uintptr_t good_mask = load_good | store_good;
        uintptr_t metadata_mask = good_mask | load_bad;
        uintptr_t valid_mask = addr_mask | metadata_mask;
        uintptr_t color;
        if (NEKO_UNLIKELY(addr_mask == 0 || good_mask == 0)) {
            if (!g_hotspot.initialized) return JNI_FALSE;
            neko_zgc_abort_missing_masks("direct oop recognition", addr_mask, good_mask);
        }
        if ((raw & ~valid_mask) != 0) return JNI_FALSE;
        if (load_bad != 0 && (raw & load_bad) != 0) return JNI_FALSE;
        color = raw & good_mask;
        return color != 0 && (raw & metadata_mask) == color ? JNI_TRUE : JNI_FALSE;
    }
#if UINTPTR_MAX > 0xffffffffu
    if ((raw & (uintptr_t)0x7u) == 0 && raw < (uintptr_t)0x0000100000000000ULL) {
        return JNI_TRUE;
    }
#endif
    return JNI_FALSE;
}

NEKO_FAST_INLINE void *neko_zgc_uncolor_oop(void *oop) {
    uintptr_t raw = (uintptr_t)oop;
    uintptr_t addr_mask;
    uintptr_t metadata_mask;
    uintptr_t good_mask;
    if (NEKO_LIKELY(raw == 0 || !neko_const_use_zgc())) return oop;
    addr_mask = neko_zgc_addr_mask();
    good_mask = neko_zgc_load_good_mask() | neko_zgc_store_good_mask();
    metadata_mask = good_mask | neko_zgc_load_bad_mask();
    if (NEKO_UNLIKELY(addr_mask == 0 || good_mask == 0)) {
        (void)neko_zgc_try_bootstrap_sample_masks(raw);
        addr_mask = neko_zgc_addr_mask();
        good_mask = neko_zgc_load_good_mask() | neko_zgc_store_good_mask();
        metadata_mask = good_mask | neko_zgc_load_bad_mask();
    }
    neko_zgc_abort_missing_masks("oop uncolor", addr_mask, good_mask);
    if (metadata_mask != 0 && (raw & metadata_mask) != 0) {
        return (void*)(raw & addr_mask);
    }
    return oop;
}

NEKO_HOT_INLINE void *neko_zgc_good_oop(void *oop) {
    uintptr_t raw = (uintptr_t)oop;
    uintptr_t addr_mask;
    uintptr_t load_good;
    uintptr_t store_good;
    uintptr_t load_bad;
    uintptr_t good_mask;
    uintptr_t metadata_mask;
    uintptr_t addr;
    if (NEKO_LIKELY(raw == 0 || !neko_const_use_zgc())) return oop;
    addr_mask = neko_zgc_addr_mask();
    load_good = neko_zgc_load_good_mask();
    store_good = neko_zgc_store_good_mask();
    load_bad = neko_zgc_load_bad_mask();
    good_mask = load_good != 0 ? load_good : store_good;
    metadata_mask = load_good | store_good | load_bad;
    if (NEKO_UNLIKELY(addr_mask == 0 || (load_good | store_good) == 0)) {
        (void)neko_zgc_try_bootstrap_sample_masks(raw);
        addr_mask = neko_zgc_addr_mask();
        load_good = neko_zgc_load_good_mask();
        store_good = neko_zgc_store_good_mask();
        load_bad = neko_zgc_load_bad_mask();
        good_mask = load_good != 0 ? load_good : store_good;
        metadata_mask = load_good | store_good | load_bad;
    }
    neko_zgc_abort_missing_masks("oop load", addr_mask, load_good | store_good);
    if (load_bad != 0 && (raw & load_bad) != 0) {
        fprintf(stderr, "[neko-direct] ZGC bad oop load needs runtime barrier raw=%p bad_mask=0x%llx\\n",
            oop, (unsigned long long)load_bad);
        abort();
    }
    if ((raw & metadata_mask) != 0) {
        addr = raw & addr_mask;
        return (void*)(addr | good_mask);
    }
    if ((raw & ~addr_mask) == 0) {
        return (void*)(raw | good_mask);
    }
    return oop;
}

NEKO_HOT_INLINE void *neko_zgc_store_oop(void *oop) {
    uintptr_t raw = (uintptr_t)oop;
    uintptr_t addr_mask;
    uintptr_t store_good;
    uintptr_t load_bad;
    uintptr_t store_bad;
    uintptr_t metadata_mask;
    uintptr_t addr;
    if (NEKO_LIKELY(raw == 0 || !neko_const_use_zgc())) return oop;
    addr_mask = neko_zgc_addr_mask();
    store_good = neko_zgc_store_good_mask();
    load_bad = neko_zgc_load_bad_mask();
    store_bad = neko_zgc_store_bad_mask();
    metadata_mask = neko_zgc_load_good_mask() | load_bad | store_good | store_bad;
    if (NEKO_UNLIKELY(addr_mask == 0 || store_good == 0)) {
        (void)neko_zgc_try_bootstrap_sample_masks(raw);
        addr_mask = neko_zgc_addr_mask();
        store_good = neko_zgc_store_good_mask();
        load_bad = neko_zgc_load_bad_mask();
        store_bad = neko_zgc_store_bad_mask();
        metadata_mask = neko_zgc_load_good_mask() | load_bad | store_good | store_bad;
    }
    neko_zgc_abort_missing_masks("oop store", addr_mask, store_good);
    if ((load_bad != 0 && (raw & load_bad) != 0)
        || (store_bad != 0 && (raw & store_bad) != 0)) {
        fprintf(stderr, "[neko-direct] ZGC bad oop store needs runtime barrier raw=%p load_bad=0x%llx store_bad=0x%llx\\n",
            oop, (unsigned long long)load_bad, (unsigned long long)store_bad);
        abort();
    }
    if ((raw & metadata_mask) != 0) {
        addr = raw & addr_mask;
        return (void*)(addr | store_good);
    }
    if ((raw & ~addr_mask) == 0) {
        return (void*)(raw | store_good);
    }
    return oop;
}

NEKO_HOT_INLINE void *neko_barrier_oop_load(void *raw_oop) {
    uintptr_t raw = (uintptr_t)raw_oop;
    if (raw == 0) return NULL;
    if (NEKO_UNLIKELY(neko_const_use_zgc())) {
        (void)neko_zgc_try_bootstrap_sample_masks(raw);
        uintptr_t load_bad = neko_zgc_load_bad_mask();
        if (load_bad != 0 && (raw & load_bad) != 0) {
            fprintf(stderr, "[neko-direct] ZGC bad oop load needs runtime barrier raw=%p bad_mask=0x%llx\\n",
                raw_oop, (unsigned long long)load_bad);
            abort();
        }
        return neko_zgc_good_oop(raw_oop);
    }
    return raw_oop;
}

typedef void *(*neko_z_lrb_field_preloaded_t)(void*, void**);
typedef void (*neko_z_lrb_array_t)(void**, size_t);
typedef void *(*neko_sh_lrb_strong_t)(void*);
typedef void *(*neko_oop_field_load_barrier_t)(void*, void*);
typedef void *(*neko_oop_array_load_barrier_t)(void*, void*);
typedef void (*neko_z_store_field_t)(void**);
typedef void (*neko_write_ref_field_pre_t)(void*, void*);
typedef void (*neko_write_ref_field_post_t)(void*, void*);
typedef void (*neko_oop_field_store_pre_barrier_t)(void*, void*, void*);
typedef void (*neko_oop_field_store_post_barrier_t)(void*, void*);

static void *neko_barrier_load_oop_field_unavailable(void *field_addr, void *raw_oop) {
    fprintf(stderr, "[neko-direct] object field load barrier not selected kind=%d raw=%p addr=%p\\n",
        g_neko_gc_barrier_kind, raw_oop, field_addr);
    abort();
}

static void *neko_barrier_load_oop_field_raw(void *field_addr, void *raw_oop) {
    (void)field_addr;
    return neko_barrier_oop_load(raw_oop);
}

static void *neko_barrier_load_oop_field_z(void *field_addr, void *raw_oop) {
    if (g_neko_barrier_load_oop_field_preloaded == NULL || field_addr == NULL) {
        fprintf(stderr, "[neko-direct] ZGC object field load barrier unavailable raw=%p addr=%p\\n",
            raw_oop, field_addr);
        abort();
    }
    return ((neko_z_lrb_field_preloaded_t)g_neko_barrier_load_oop_field_preloaded)(raw_oop, (void**)field_addr);
}

/* Inline ZGC load barrier used when libjvm has stripped
 * ZBarrierSetRuntime::load_barrier_on_oop_field_preloaded. The mask
 * pointers are published into g_hotspot at OnLoad by MethodPatcherEmitter
 * (z_zglobals_addr_mask_p, z_zglobals_load_bad_mask_p, z_zglobals_load_good_mask_p), then dereferenced
 * each call so that modern generational ZGC's dynamic per-cycle mask
 * publication is observed. On a bad-marked oop the runtime healing
 * routine is required; we abort cleanly per CLAUDE.md "missing required
 * barrier support must abort". */
static void *neko_barrier_load_oop_field_z_inline(void *field_addr, void *raw_oop) {
    (void)field_addr;
    if (raw_oop == NULL) return NULL;
    if (g_hotspot.z_zglobals_addr_mask_p == NULL
        || g_hotspot.z_zglobals_load_bad_mask_p == NULL
        || g_hotspot.z_zglobals_load_good_mask_p == NULL) {
        fprintf(stderr, "[neko-direct] ZGC inline barrier: mask-pointer publication missing\\n");
        abort();
    }
    uintptr_t load_bad = neko_zgc_load_bad_mask();
    uintptr_t addr_mask = neko_zgc_addr_mask();
    uintptr_t load_good = neko_zgc_load_good_mask();
    uintptr_t raw = (uintptr_t)raw_oop;
    neko_zgc_abort_missing_masks("inline load barrier", addr_mask, load_good);
    if (load_bad != 0 && (raw & load_bad) != 0) {
        fprintf(stderr, "[neko-direct] ZGC bad-marked oop load needs runtime healing (sym stripped) raw=%p bad=0x%llx\\n",
            raw_oop, (unsigned long long)load_bad);
        abort();
    }
    return neko_zgc_good_oop(raw_oop);
}

static void *neko_barrier_load_oop_field_shenandoah(void *field_addr, void *raw_oop) {
    (void)field_addr;
    if (g_neko_barrier_load_oop_field_preloaded == NULL) {
        fprintf(stderr, "[neko-direct] Shenandoah object field load barrier unavailable raw=%p\\n", raw_oop);
        abort();
    }
    return ((neko_sh_lrb_strong_t)g_neko_barrier_load_oop_field_preloaded)(raw_oop);
}

static neko_oop_field_load_barrier_t g_neko_oop_field_load_barrier = neko_barrier_load_oop_field_unavailable;

static void neko_select_oop_field_load_barrier(void) {
    if (!g_neko_gc_barrier_ready) {
        fprintf(stderr, "[neko-direct] GC barrier layout unavailable for object field load kind=%d\\n",
            g_neko_gc_barrier_kind);
        abort();
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_CARDTABLE
        || g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_G1) {
        g_neko_oop_field_load_barrier = neko_barrier_load_oop_field_raw;
        return;
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_Z) {
        if (g_neko_barrier_load_oop_field_preloaded != NULL) {
            g_neko_oop_field_load_barrier = neko_barrier_load_oop_field_z;
        } else {
            /* libjvm stripped ZBarrierSetRuntime — fall back to the inline
             * dynamic-mask reader. It still hard-aborts on a bad-marked oop
             * (no runtime healing without dlsym), satisfying CLAUDE.md. */
            g_neko_oop_field_load_barrier = neko_barrier_load_oop_field_z_inline;
        }
        return;
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_SHENANDOAH) {
        if (g_neko_barrier_load_oop_field_preloaded == NULL) {
            fprintf(stderr, "[neko-direct] Shenandoah object field load barrier symbol missing\\n");
            abort();
        }
        g_neko_oop_field_load_barrier = neko_barrier_load_oop_field_shenandoah;
        return;
    }
    fprintf(stderr, "[neko-direct] unsupported GC barrier kind for object field load: %d\\n",
        g_neko_gc_barrier_kind);
    abort();
}

NEKO_HOT_INLINE void *neko_barrier_load_oop_field(void *field_addr, void *raw_oop) {
    if (raw_oop == NULL) return NULL;
    /* Hot path for stop-the-world / non-relocating collectors (G1/Parallel/Serial/CardTable)
     * skips the indirect dispatch and returns the raw oop directly. ZGC and Shenandoah
     * still route through the barrier function pointer where loads can rewrite the oop. */
    int32_t kind = neko_const_gc_kind();
    if (NEKO_LIKELY(kind == NEKO_EARLY_GC_BARRIER_G1
                 || kind == NEKO_EARLY_GC_BARRIER_CARDTABLE)) {
        return raw_oop;
    }
    return g_neko_oop_field_load_barrier(field_addr, raw_oop);
}

static void *neko_barrier_load_oop_array_unavailable(void *element_addr, void *raw_oop) {
    fprintf(stderr, "[neko-direct] object array load barrier not selected kind=%d raw=%p addr=%p\\n",
        g_neko_gc_barrier_kind, raw_oop, element_addr);
    abort();
}

static void *neko_barrier_load_oop_array_raw(void *element_addr, void *raw_oop) {
    (void)element_addr;
    return neko_barrier_oop_load(raw_oop);
}

static void *neko_barrier_load_oop_array_z_inline(void *element_addr, void *raw_oop);

static void *neko_barrier_load_oop_array_z(void *element_addr, void *raw_oop) {
    if (g_neko_barrier_load_oop_array == NULL) {
        fprintf(stderr, "[neko-direct] ZGC object array load barrier unavailable raw=%p\\n", raw_oop);
        abort();
    }
    if (g_hotspot.compressed_oops_enabled) {
        return neko_barrier_load_oop_array_z_inline(element_addr, raw_oop);
    }
    if (element_addr == NULL) {
        fprintf(stderr, "[neko-direct] ZGC object array load barrier unavailable raw=%p addr=%p\\n",
            raw_oop, element_addr);
        abort();
    }
    ((neko_z_lrb_array_t)g_neko_barrier_load_oop_array)((void**)element_addr, 1u);
    return *(void**)element_addr;
}

/* Inline ZGC array load barrier — same dynamic-mask read as the field
 * variant. Used when the libjvm has stripped ZBarrierSetRuntime symbols. */
static void *neko_barrier_load_oop_array_z_inline(void *element_addr, void *raw_oop) {
    return neko_barrier_load_oop_field_z_inline(element_addr, raw_oop);
}

static void *neko_barrier_load_oop_array_shenandoah(void *element_addr, void *raw_oop) {
    (void)element_addr;
    if (g_neko_barrier_load_oop_field_preloaded == NULL) {
        fprintf(stderr, "[neko-direct] Shenandoah object array load barrier unavailable raw=%p\\n", raw_oop);
        abort();
    }
    return ((neko_sh_lrb_strong_t)g_neko_barrier_load_oop_field_preloaded)(raw_oop);
}

static neko_oop_array_load_barrier_t g_neko_oop_array_load_barrier = neko_barrier_load_oop_array_unavailable;

static void neko_select_oop_array_load_barrier(void) {
    if (!g_neko_gc_barrier_ready) {
        fprintf(stderr, "[neko-direct] GC barrier layout unavailable for object array load kind=%d\\n",
            g_neko_gc_barrier_kind);
        abort();
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_CARDTABLE
        || g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_G1) {
        g_neko_oop_array_load_barrier = neko_barrier_load_oop_array_raw;
        return;
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_Z) {
        if (g_neko_barrier_load_oop_array != NULL && !g_hotspot.compressed_oops_enabled) {
            g_neko_oop_array_load_barrier = neko_barrier_load_oop_array_z;
        } else {
            /* Stripped libjvm: fall through to inline dynamic-mask reader. */
            g_neko_oop_array_load_barrier = neko_barrier_load_oop_array_z_inline;
        }
        return;
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_SHENANDOAH) {
        if (g_neko_barrier_load_oop_field_preloaded == NULL) {
            fprintf(stderr, "[neko-direct] Shenandoah object array load barrier symbol missing\\n");
            abort();
        }
        g_neko_oop_array_load_barrier = neko_barrier_load_oop_array_shenandoah;
        return;
    }
    fprintf(stderr, "[neko-direct] unsupported GC barrier kind for object array load: %d\\n",
        g_neko_gc_barrier_kind);
    abort();
}

NEKO_HOT_INLINE void *neko_barrier_load_oop_array(void *element_addr, void *raw_oop) {
    if (raw_oop == NULL) return NULL;
    /* Hot path for stop-the-world / non-relocating collectors (G1/Parallel/Serial/CardTable)
     * skips the indirect dispatch and returns the raw oop directly. ZGC and Shenandoah
     * still route through the barrier function pointer where loads can rewrite the oop. */
    int32_t kind = neko_const_gc_kind();
    if (NEKO_LIKELY(kind == NEKO_EARLY_GC_BARRIER_G1
                 || kind == NEKO_EARLY_GC_BARRIER_CARDTABLE)) {
        return raw_oop;
    }
    return g_neko_oop_array_load_barrier(element_addr, raw_oop);
}

static void neko_card_mark_field(void *field_addr) {
    uintptr_t card;
    if (field_addr == NULL
        || g_neko_card_table_byte_map_base == NULL
        || g_neko_card_table_shift < 0
        || g_neko_card_table_dirty_card < 0) {
        fprintf(stderr, "[neko-direct] card table field store barrier unavailable addr=%p base=%p shift=%d dirty=%d\\n",
            field_addr, g_neko_card_table_byte_map_base, g_neko_card_table_shift, g_neko_card_table_dirty_card);
        abort();
    }
    card = ((uintptr_t)field_addr) >> (unsigned)g_neko_card_table_shift;
    ((volatile int8_t*)g_neko_card_table_byte_map_base)[card] = (int8_t)g_neko_card_table_dirty_card;
}

static void neko_barrier_pre_store_oop_field_unavailable(void *thread, void *field_addr, void *old_oop) {
    fprintf(stderr, "[neko-direct] object field pre-store barrier not selected kind=%d thread=%p addr=%p old=%p\\n",
        g_neko_gc_barrier_kind, thread, field_addr, old_oop);
    abort();
}

static void neko_barrier_post_store_oop_field_unavailable(void *thread, void *field_addr) {
    fprintf(stderr, "[neko-direct] object field post-store barrier not selected kind=%d thread=%p addr=%p\\n",
        g_neko_gc_barrier_kind, thread, field_addr);
    abort();
}

static void neko_barrier_pre_store_oop_field_noop(void *thread, void *field_addr, void *old_oop) {
    (void)thread; (void)field_addr; (void)old_oop;
}

static void neko_barrier_post_store_oop_field_card(void *thread, void *field_addr) {
    (void)thread;
    neko_card_mark_field(field_addr);
}

static void neko_barrier_pre_store_oop_field_g1(void *thread, void *field_addr, void *old_oop) {
    (void)field_addr;
    if (g_neko_barrier_write_ref_field_pre != NULL && old_oop != NULL) {
        ((neko_write_ref_field_pre_t)g_neko_barrier_write_ref_field_pre)(old_oop, thread);
    }
}

static void neko_barrier_post_store_oop_field_g1(void *thread, void *field_addr) {
    if (g_neko_barrier_write_ref_field_post != NULL) {
        ((neko_write_ref_field_post_t)g_neko_barrier_write_ref_field_post)(field_addr, thread);
        return;
    }
    neko_card_mark_field(field_addr);
}

static void neko_barrier_pre_store_oop_field_z(void *thread, void *field_addr, void *old_oop) {
    (void)thread; (void)old_oop;
    if (g_neko_barrier_store_oop_field == NULL || field_addr == NULL) {
        fprintf(stderr, "[neko-direct] ZGC object field store barrier unavailable addr=%p\\n", field_addr);
        abort();
    }
    ((neko_z_store_field_t)g_neko_barrier_store_oop_field)((void**)field_addr);
}

static void neko_barrier_post_store_oop_field_z(void *thread, void *field_addr) {
    (void)thread; (void)field_addr;
}

/* Inline ZGC store pre-barrier used when libjvm has stripped
 * ZBarrierSetRuntime::store_barrier_on_oop_field_* symbols. This implements
 * the HotSpot fast path: a non-null previous field value whose store-bad bits
 * are clear needs no runtime call. If the previous value is store-bad, the
 * slow runtime/barrier-buffer path is required and we hard-abort. */
static void neko_barrier_pre_store_oop_field_z_inline(void *thread, void *field_addr, void *old_oop) {
    uintptr_t raw;
    uintptr_t addr_mask;
    uintptr_t store_good;
    uintptr_t store_bad;
    uintptr_t load_good;
    uintptr_t load_bad;
    uintptr_t metadata_mask;
    (void)thread; (void)old_oop;
    if (field_addr == NULL) {
        fprintf(stderr, "[neko-direct] ZGC object field store barrier unavailable addr=%p\\n", field_addr);
        abort();
    }
    if (g_hotspot.compressed_oops_enabled) {
        uint32_t narrow = *(uint32_t*)field_addr;
        if (narrow == 0u) return;
        raw = ((uintptr_t)narrow << g_hotspot.compressed_oops_shift)
            + (uintptr_t)g_hotspot.compressed_oops_base;
    } else {
        raw = *(uintptr_t*)field_addr;
    }
    if (raw == 0) return;
    (void)neko_zgc_try_bootstrap_sample_masks(raw);
    addr_mask = neko_zgc_addr_mask();
    store_good = neko_zgc_store_good_mask();
    store_bad = neko_zgc_store_bad_mask();
    load_good = neko_zgc_load_good_mask();
    load_bad = neko_zgc_load_bad_mask();
    metadata_mask = store_good | store_bad | load_good | load_bad;
    neko_zgc_abort_missing_masks("store barrier", addr_mask, store_good);
    if (store_bad == 0) {
        fprintf(stderr, "[neko-direct] ZGC object field store barrier needs store-bad mask addr=%p raw=%p\\n",
            field_addr, (void*)raw);
        abort();
    }
    if ((raw & ~(addr_mask | metadata_mask)) != 0) {
        fprintf(stderr, "[neko-direct] ZGC object field store saw invalid oop addr=%p raw=%p addr_mask=0x%llx meta=0x%llx\\n",
            field_addr, (void*)raw, (unsigned long long)addr_mask, (unsigned long long)metadata_mask);
        abort();
    }
    if ((raw & store_bad) != 0) {
        fprintf(stderr, "[neko-direct] ZGC object field store needs runtime barrier (sym stripped) addr=%p raw=%p store_bad=0x%llx\\n",
            field_addr, (void*)raw, (unsigned long long)store_bad);
        abort();
    }
}

static void neko_barrier_post_store_oop_field_z_inline(void *thread, void *field_addr) {
    (void)thread; (void)field_addr;
}

static void neko_barrier_pre_store_oop_field_shenandoah(void *thread, void *field_addr, void *old_oop) {
    (void)field_addr;
    if (g_neko_barrier_write_ref_field_pre == NULL) {
        fprintf(stderr, "[neko-direct] Shenandoah object field store barrier unavailable addr=%p old=%p\\n",
            field_addr, old_oop);
        abort();
    }
    if (old_oop != NULL) {
        ((neko_write_ref_field_pre_t)g_neko_barrier_write_ref_field_pre)(old_oop, thread);
    }
}

static void neko_barrier_post_store_oop_field_shenandoah(void *thread, void *field_addr) {
    (void)thread;
    if (g_neko_card_table_byte_map_base != NULL) {
        neko_card_mark_field(field_addr);
    }
}

static neko_oop_field_store_pre_barrier_t g_neko_oop_field_store_pre_barrier = neko_barrier_pre_store_oop_field_unavailable;
static neko_oop_field_store_post_barrier_t g_neko_oop_field_store_post_barrier = neko_barrier_post_store_oop_field_unavailable;

static void neko_select_oop_field_store_barrier(void) {
    if (!g_neko_gc_barrier_ready) {
        fprintf(stderr, "[neko-direct] GC barrier layout unavailable for object field store kind=%d\\n",
            g_neko_gc_barrier_kind);
        abort();
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_CARDTABLE) {
        g_neko_oop_field_store_pre_barrier = neko_barrier_pre_store_oop_field_noop;
        g_neko_oop_field_store_post_barrier = neko_barrier_post_store_oop_field_card;
        return;
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_G1) {
        g_neko_oop_field_store_pre_barrier = neko_barrier_pre_store_oop_field_g1;
        g_neko_oop_field_store_post_barrier = neko_barrier_post_store_oop_field_g1;
        return;
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_Z) {
        g_neko_oop_field_store_pre_barrier = neko_barrier_pre_store_oop_field_noop;
        if (g_neko_barrier_store_oop_field != NULL) {
            g_neko_oop_field_store_pre_barrier = neko_barrier_pre_store_oop_field_z;
            g_neko_oop_field_store_post_barrier = neko_barrier_post_store_oop_field_z;
        } else {
            /* Stripped libjvm: install the inline fast-path pre-barrier and
             * a no-op post-barrier. The inline path hard-aborts when the
             * previous field value is store-bad and needs the slow runtime /
             * barrier-buffer path. */
            g_neko_oop_field_store_pre_barrier = neko_barrier_pre_store_oop_field_z_inline;
            g_neko_oop_field_store_post_barrier = neko_barrier_post_store_oop_field_z_inline;
        }
        return;
    }
    if (g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_SHENANDOAH) {
        if (g_neko_barrier_write_ref_field_pre == NULL) {
            fprintf(stderr, "[neko-direct] Shenandoah object field store barrier symbol missing\\n");
            abort();
        }
        g_neko_oop_field_store_pre_barrier = neko_barrier_pre_store_oop_field_shenandoah;
        g_neko_oop_field_store_post_barrier = neko_barrier_post_store_oop_field_shenandoah;
        return;
    }
    fprintf(stderr, "[neko-direct] unsupported GC barrier kind for object field store: %d\\n",
        g_neko_gc_barrier_kind);
    abort();
}

NEKO_FAST_INLINE void neko_barrier_pre_store_oop_field(void *thread, void *field_addr, void *old_oop) {
    g_neko_oop_field_store_pre_barrier(thread, field_addr, old_oop);
}

NEKO_FAST_INLINE void neko_barrier_post_store_oop_field(void *thread, void *field_addr) {
    g_neko_oop_field_store_post_barrier(thread, field_addr);
}

NEKO_PURE_INLINE void* neko_handle_oop(jobject handle) {
    uintptr_t raw;
    uintptr_t slot;
    void *slot_oop;
    if (handle == NULL) return NULL;
    raw = (uintptr_t)handle;
    /* HotSpot JNI local handles are untagged and resolve by a plain
     * slot load (JNIHandles::resolve_impl local path). ZGC local-handle
     * slots hold already-dereferenceable oopDesc pointer / zaddress values, not
     * zpointer field/array contents requiring the ZGC load barrier. If ZGC
     * masks have not yet been initialized, do NOT run the direct-oop classifier
     * first: local handle slots live in native/JNIHandleBlock memory and would
     * otherwise fail closed before bootstrap class/static-field setup can read
     * their mirror oops. Tagged global/weak handles continue through the
     * barriered path below. */
    if (neko_const_use_zgc()
        && (((neko_const_fast_bits() & NEKO_HOTSPOT_FAST_HANDLE_TAGS) == 0)
            || ((raw & (uintptr_t)0x3u) == 0))) {
        uintptr_t addr_mask = neko_zgc_addr_mask();
        uintptr_t good_mask = neko_zgc_load_good_mask() | neko_zgc_store_good_mask();
        if (!g_hotspot.initialized || addr_mask == 0 || good_mask == 0) {
            slot = raw;
            slot_oop = *(void**)slot;
            if (getenv("NEKO_PATCH_DEBUG") != NULL && !g_hotspot.initialized) {
                fprintf(stderr, "[neko-direct] ZGC bootstrap handle raw=%p slot=%p slot_oop=%p\\n",
                    (void*)raw, (void*)slot, slot_oop);
            }
            return slot_oop;
        }
    }
    /* Direct call_stub entry can re-enter translated native code with raw
     * HotSpot oops in Java heap registers/stack slots. JNI handle slots live
     * in native stack or JNIHandleBlock memory, which is far above the zero-
     * based compressed-oops heap used by the supported JDK 21 test targets.
     * Treat low aligned references as already-unwrapped oops so nested direct
     * calls do not dereference the object mark word as a handle slot. */
    if (neko_ref_is_direct_oop(handle)) {
        return neko_zgc_good_oop((void*)raw);
    }
    slot = (neko_const_fast_bits() & NEKO_HOTSPOT_FAST_HANDLE_TAGS) != 0 ? (raw & ~(uintptr_t)0x3u) : raw;
    slot_oop = *(void**)slot;
    if (getenv("NEKO_PATCH_DEBUG") != NULL && neko_const_use_zgc() && !g_hotspot.initialized) {
        fprintf(stderr, "[neko-direct] ZGC bootstrap handle raw=%p slot=%p slot_oop=%p\\n",
            (void*)raw, (void*)slot, slot_oop);
    }
    if (neko_const_use_zgc()
        && (((neko_const_fast_bits() & NEKO_HOTSPOT_FAST_HANDLE_TAGS) == 0)
            || ((raw & (uintptr_t)0x3u) == 0))) {
        return slot_oop;
    }
    return neko_barrier_oop_load(slot_oop);
}

NEKO_FAST_INLINE void* neko_prepare_return_oop(void *thread, jobject handle, const char *site) {
    void *oop;
    if (handle == NULL) return NULL;
    oop = neko_handle_oop(handle);
    if (oop == NULL) {
        fprintf(stderr, "[neko-direct] object return did not resolve site=%s thread=%p handle=%p\\n",
            site != NULL ? site : "unknown", thread, (void*)handle);
        abort();
    }
    return neko_zgc_good_oop(oop);
}

NEKO_FAST_INLINE jboolean neko_ref_equal(jobject a, jobject b) {
    void *aoop;
    void *boop;
    if (a == b) return JNI_TRUE;
    if (a == NULL || b == NULL) return JNI_FALSE;
    aoop = neko_handle_oop(a);
    boop = neko_handle_oop(b);
    if (aoop == NULL || boop == NULL) {
        fprintf(stderr, "[neko-direct] object reference equality source did not resolve a=%p b=%p\\n", (void*)a, (void*)b);
        abort();
    }
    return aoop == boop ? JNI_TRUE : JNI_FALSE;
}

NEKO_HOT_INLINE void* neko_static_base_oop(jobject staticBase) {
    /* Static-base mirrors may be JNI locals, globals, or already-unwrapped
     * direct refs. Use the same ABI-correct resolver as ordinary object
     * references so ZGC untagged JNI locals take the plain local-handle path
     * while tagged globals/weak globals and true zpointer field contents remain
     * barrier-governed. */
    return neko_handle_oop(staticBase);
}

NEKO_HOT_INLINE jint neko_fast_array_length(jarray arr) {
    if (NEKO_LIKELY(neko_const_initialized()
        && ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) != 0 || neko_const_use_zgc())
        && neko_const_array_length_offset() >= 0
        && arr != NULL)) {
        char *oop = (char*)neko_handle_oop((jobject)arr);
        if (oop != NULL) {
            return *(jint*)(oop + neko_const_array_length_offset());
        }
    }
    fprintf(stderr, "[neko-direct] ARRAYLENGTH direct path unavailable arr=%p\\n", (void*)arr);
    abort();
}

NEKO_FAST_INLINE jboolean neko_receiver_key_supported(void) {
    return g_hotspot.initialized
        && g_hotspot.use_compact_object_headers == JNI_FALSE
        && ((g_hotspot.fast_bits & NEKO_FAST_RECEIVER_KEY) != 0
            || (g_hotspot.use_zgc && g_hotspot.klass_offset_bytes > 0));
}


typedef jvalue (*neko_icache_direct_stub)(void *thread, JNIEnv *env, jobject receiver, const jvalue *args);

/* neko_njx_dispatcher_t was already typedef'd in the
 * NativeToJavaInvokeEmitter prelude (rendered before renderHotSpotSupport).
 * The per-shape dispatcher functions are forward-declared there too. */

typedef struct {
    const char *name;
    const char *desc;
    const jclass *translated_class_slot;
    neko_icache_direct_stub translated_stub;
    jboolean is_interface;
    /* Per-shape direct dispatcher. NULL means this site isn't wired for
     * direct invoke (the shape wasn't registered by the codegen). When
     * non-NULL, neko_icache_dispatch will route through it once we have a
     * resolved Method* + compiled-entry pair for the receiver class. */
    neko_njx_dispatcher_t direct_dispatcher;
} neko_icache_meta;

NEKO_FAST_INLINE char neko_icache_return_kind(const char *desc) {
    const char *ret = desc == NULL ? NULL : strrchr(desc, ')');
    return (ret != NULL && ret[1] != '\\0') ? ret[1] : 'V';
}

NEKO_FAST_INLINE int neko_icache_find_slot(neko_icache_site *site, uintptr_t receiverKey) {
    uint32_t i;
    if (site == NULL || receiverKey == 0) return -1;
    for (i = 0u; i < NEKO_ICACHE_PIC_SIZE; i++) {
        if (site->target_kind[i] != NEKO_ICACHE_EMPTY && site->receiver_key[i] == receiverKey) {
            return (int)i;
        }
    }
    return -1;
}

NEKO_FAST_INLINE uint32_t neko_icache_claim_slot(neko_icache_site *site, uintptr_t receiverKey) {
    uint32_t i;
    int existing;
    if (site == NULL) return 0u;
    existing = neko_icache_find_slot(site, receiverKey);
    if (existing >= 0) return (uint32_t)existing;
    for (i = 0u; i < NEKO_ICACHE_PIC_SIZE; i++) {
        if (site->target_kind[i] == NEKO_ICACHE_EMPTY) return i;
    }
    i = (uint32_t)(site->next_slot++ & (NEKO_ICACHE_PIC_SIZE - 1u));
    site->receiver_key[i] = 0;
    site->target[i] = NULL;
    site->target2[i] = NULL;
    site->target_kind[i] = NEKO_ICACHE_EMPTY;
    return i;
}

/* Forward decls: defined later in the methodPatcherEmitter region. */
extern jboolean g_neko_direct_invoke_ready;

/* Runtime gate for direct-NJX diagnostics. Direct invoke is mandatory;
 * NEKO_DIRECT_DEBUG=1 enables the final one-line stats report. */
static int g_neko_njx_enabled_cached = 1;
static int g_neko_njx_enabled_initialized = 0;
static int g_neko_njx_debug_cached = 0;
static volatile uint64_t g_neko_njx_dispatch_count = 0;
static volatile uint64_t g_neko_njx_resolve_fail_count = 0;
#ifndef NEKO_ICACHE_AUDIT
#define NEKO_ICACHE_AUDIT 0
#endif
#if NEKO_ICACHE_AUDIT
static volatile uint64_t g_neko_icache_direct_c_hit_count = 0;
static volatile uint64_t g_neko_icache_direct_njx_hit_count = 0;
static volatile uint64_t g_neko_icache_miss_count = 0;
static volatile uint64_t g_neko_icache_translated_store_count = 0;
static volatile uint64_t g_neko_icache_direct_njx_store_count = 0;
static volatile uint64_t g_neko_icache_unresolved_count = 0;
#endif
#ifndef NEKO_HANDLE_AUDIT
#define NEKO_HANDLE_AUDIT 0
#endif
#define NEKO_HANDLE_ORIGIN_OTHER 0
#define NEKO_HANDLE_ORIGIN_OBJECT_ARRAY_ALLOC 1
#define NEKO_HANDLE_ORIGIN_PRIMITIVE_ARRAY_ALLOC 2
#define NEKO_HANDLE_ORIGIN_OBJECT_ALLOC 3
#define NEKO_HANDLE_ORIGIN_AALOAD 4
#define NEKO_HANDLE_ORIGIN_CHECKED_AALOAD 5
#define NEKO_HANDLE_ORIGIN_FUSED_AALOAD_AALOAD 6
#define NEKO_HANDLE_ORIGIN_OBJECT_FIELD 7
#define NEKO_HANDLE_ORIGIN_STATIC_OBJECT_FIELD 8
#define NEKO_HANDLE_ORIGIN_NJX_RETURN 9
#define NEKO_HANDLE_ORIGIN_BOUND_STRING 10
#if NEKO_HANDLE_AUDIT
static volatile uint64_t g_neko_handle_direct_total_count = 0;
static volatile uint64_t g_neko_handle_direct_fast_slot_count = 0;
static volatile uint64_t g_neko_handle_direct_overflow_alloc_count = 0;
static volatile uint64_t g_neko_handle_direct_unavailable_count = 0;
static volatile uint64_t g_neko_handle_direct_max_top = 0;
static volatile uint64_t g_neko_handle_direct_max_capacity = 0;
static volatile uint64_t g_neko_handle_origin_other_count = 0;
static volatile uint64_t g_neko_handle_origin_object_array_alloc_count = 0;
static volatile uint64_t g_neko_handle_origin_primitive_array_alloc_count = 0;
static volatile uint64_t g_neko_handle_origin_object_alloc_count = 0;
static volatile uint64_t g_neko_handle_origin_aaload_count = 0;
static volatile uint64_t g_neko_handle_origin_checked_aaload_count = 0;
static volatile uint64_t g_neko_handle_origin_fused_aaload_aaload_count = 0;
static volatile uint64_t g_neko_handle_origin_object_field_count = 0;
static volatile uint64_t g_neko_handle_origin_static_object_field_count = 0;
static volatile uint64_t g_neko_handle_origin_njx_return_count = 0;
static volatile uint64_t g_neko_handle_origin_bound_string_count = 0;
static volatile uint64_t g_neko_concat_accumulate_total_count = 0;
static volatile uint64_t g_neko_concat_accumulate_njx_count = 0;
static volatile uint64_t g_neko_concat_final_push_count = 0;
static volatile uint64_t g_neko_stringbuilder_concat_fast_total_count = 0;
static volatile uint64_t g_neko_stringbuilder_concat_fast_literal_count = 0;
static volatile uint64_t g_neko_stringbuilder_concat_fast_dynamic_count = 0;
#endif
static volatile int g_neko_njx_stats_printed = 0;
NEKO_FAST_INLINE int neko_njx_debug(void) { return g_neko_njx_debug_cached; }
NEKO_FAST_INLINE int neko_njx_enabled(void) {
    if (__builtin_expect(!g_neko_njx_enabled_initialized, 0)) {
        g_neko_njx_enabled_cached = 1;
        const char *d = getenv("NEKO_DIRECT_DEBUG");
        g_neko_njx_debug_cached = (d != NULL && d[0] != '\\0' && d[0] != '0') ? 1 : 0;
        g_neko_njx_enabled_initialized = 1;
    }
    return g_neko_njx_enabled_cached;
}

#if NEKO_ICACHE_AUDIT
#define NEKO_ICACHE_AUDIT_HIT(counter) do { \
    if (__builtin_expect(g_neko_njx_debug_cached, 0)) { \
        __atomic_fetch_add(&(counter), 1, __ATOMIC_RELAXED); \
    } \
} while (0)
#else
#define NEKO_ICACHE_AUDIT_HIT(counter) ((void)0)
#endif

#if NEKO_HANDLE_AUDIT
#define NEKO_HANDLE_AUDIT_HIT(counter) do { \
    if (__builtin_expect(neko_njx_debug(), 0)) { \
        __atomic_fetch_add(&(counter), 1, __ATOMIC_RELAXED); \
    } \
} while (0)
#define NEKO_HANDLE_AUDIT_ORIGIN(origin) do { \
    if (__builtin_expect(neko_njx_debug(), 0)) { \
        switch (origin) { \
            case NEKO_HANDLE_ORIGIN_OBJECT_ARRAY_ALLOC: __atomic_fetch_add(&g_neko_handle_origin_object_array_alloc_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_PRIMITIVE_ARRAY_ALLOC: __atomic_fetch_add(&g_neko_handle_origin_primitive_array_alloc_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_OBJECT_ALLOC: __atomic_fetch_add(&g_neko_handle_origin_object_alloc_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_AALOAD: __atomic_fetch_add(&g_neko_handle_origin_aaload_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_CHECKED_AALOAD: __atomic_fetch_add(&g_neko_handle_origin_checked_aaload_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_FUSED_AALOAD_AALOAD: __atomic_fetch_add(&g_neko_handle_origin_fused_aaload_aaload_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_OBJECT_FIELD: __atomic_fetch_add(&g_neko_handle_origin_object_field_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_STATIC_OBJECT_FIELD: __atomic_fetch_add(&g_neko_handle_origin_static_object_field_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_NJX_RETURN: __atomic_fetch_add(&g_neko_handle_origin_njx_return_count, 1, __ATOMIC_RELAXED); break; \
            case NEKO_HANDLE_ORIGIN_BOUND_STRING: __atomic_fetch_add(&g_neko_handle_origin_bound_string_count, 1, __ATOMIC_RELAXED); break; \
            default: __atomic_fetch_add(&g_neko_handle_origin_other_count, 1, __ATOMIC_RELAXED); break; \
        } \
    } \
} while (0)
static inline void neko_handle_audit_max(volatile uint64_t *slot, uint64_t value) {
    if (__builtin_expect(neko_njx_debug(), 0)) {
        uint64_t current = __atomic_load_n(slot, __ATOMIC_RELAXED);
        while (value > current
            && !__sync_bool_compare_and_swap(slot, current, value)) {
            current = __atomic_load_n(slot, __ATOMIC_RELAXED);
        }
    }
}
#else
#define NEKO_HANDLE_AUDIT_HIT(counter) ((void)0)
#define NEKO_HANDLE_AUDIT_ORIGIN(origin) ((void)0)
#define neko_handle_audit_max(slot, value) ((void)0)
#endif

NEKO_FAST_INLINE void neko_njx_note_dispatch(void) {
    if (__builtin_expect(neko_njx_debug(), 0)) {
        __atomic_fetch_add(&g_neko_njx_dispatch_count, 1, __ATOMIC_RELAXED);
    }
}

NEKO_FAST_INLINE void neko_njx_note_resolve_fail(void) {
    if (__builtin_expect(neko_njx_debug(), 0)) {
        __atomic_fetch_add(&g_neko_njx_resolve_fail_count, 1, __ATOMIC_RELAXED);
    }
}

#define NEKO_DIRECT_LOG(fmt, ...) do { if (__builtin_expect(neko_njx_debug(), 0)) { fprintf(stderr, "[neko-direct] " fmt "\\n", ##__VA_ARGS__); fflush(stderr); } } while (0)

NEKO_FAST_INLINE void neko_icache_store_direct(neko_icache_site *site, uintptr_t receiverKey, void *target) {
    uint32_t slot;
    if (site == NULL) return;
    slot = neko_icache_claim_slot(site, receiverKey);
    site->receiver_key[slot] = receiverKey;
    site->target[slot] = target;
    site->target2[slot] = NULL;
    site->target_kind[slot] = NEKO_ICACHE_DIRECT_C;
}

/* Cache a resolved (Method*, _from_compiled_entry) pair for the receiver
 * class. Subsequent dispatches to the same class skip the JNI GetMethodID
 * and invoke the per-shape dispatcher (from meta) directly with the cached
 * entry pointer. */
NEKO_FAST_INLINE void neko_icache_store_direct_njx(neko_icache_site *site, uintptr_t receiverKey, void *method_ptr, void *compiled_entry) {
    uint32_t slot;
    if (site == NULL) return;
    slot = neko_icache_claim_slot(site, receiverKey);
    site->receiver_key[slot] = receiverKey;
    site->target[slot] = method_ptr;
    site->target2[slot] = compiled_entry;
    site->target_kind[slot] = NEKO_ICACHE_DIRECT_NJX;
}

NEKO_FAST_INLINE jboolean neko_icache_note_miss(JNIEnv *env, neko_icache_site *site) {
    if (site == NULL) return JNI_FALSE;
    if (site->miss_count < (uint16_t)0xFFFFu) site->miss_count++;
    NEKO_ICACHE_AUDIT_HIT(g_neko_icache_miss_count);
    (void)env;
    return JNI_FALSE;
}

/* Forward decls for direct-NJX helpers — actual definitions live in the
 * NativeToJavaInvokeEmitter prelude/body regions. */
static int neko_njx_resolve_method_entry(void *method, void **out_method, void **out_entry);
static int neko_njx_resolve_entry(jmethodID mid, void **out_method, void **out_entry);

static jvalue neko_icache_dispatch(
    void *thread,
    JNIEnv *env,
    neko_icache_site *site,
    const neko_icache_meta *meta,
    jobject receiver,
    jmethodID declared_mid,
    const jvalue *args
) {
    jvalue result = {0};
    uintptr_t receiverKey;
    void *receiverKlass;
    void *__receiver_jni_slot = NULL;
    jobject receiver_jni;
    if (env == NULL || receiver == NULL || declared_mid == NULL) return result;
    if (meta == NULL || meta->name == NULL || meta->desc == NULL || meta->direct_dispatcher == NULL) {
        fprintf(stderr, "[neko-direct] virtual dispatch metadata incomplete receiver=%p site=%p\\n",
            receiver, (void*)site);
        abort();
    }
    receiverKlass = neko_object_handle_klass(receiver);
    if (receiverKlass == NULL) {
        fprintf(stderr, "[neko-direct] receiver Klass unavailable for %s%s receiver=%p\\n",
            meta->name, meta->desc, receiver);
        abort();
    }
    receiver_jni = receiver;
    if (neko_ref_is_direct_oop(receiver)) {
        __receiver_jni_slot = (void*)receiver;
        receiver_jni = (jobject)&__receiver_jni_slot;
    }
    if (site != NULL && neko_receiver_key_supported()) {
        int cacheSlot;
        receiverKey = (uintptr_t)receiverKlass;
        if (receiverKey != 0) {
            cacheSlot = neko_icache_find_slot(site, receiverKey);
            if (cacheSlot >= 0) {
                if (site->target_kind[cacheSlot] == NEKO_ICACHE_DIRECT_C && site->target[cacheSlot] != NULL) {
                    NEKO_ICACHE_AUDIT_HIT(g_neko_icache_direct_c_hit_count);
                    return ((neko_icache_direct_stub)site->target[cacheSlot])(thread, env, receiver_jni, args);
                }
                if (site->target_kind[cacheSlot] == NEKO_ICACHE_DIRECT_NJX && site->target[cacheSlot] != NULL && site->target2[cacheSlot] != NULL
                    && neko_njx_enabled()) {
                    NEKO_ICACHE_AUDIT_HIT(g_neko_icache_direct_njx_hit_count);
                    NEKO_DIRECT_LOG("icache hit direct-njx %s%s method=%p entry=%p receiver=%p",
                        meta->name, meta->desc, site->target[cacheSlot], site->target2[cacheSlot], receiver);
                    result = meta->direct_dispatcher(thread, env, site->target[cacheSlot], site->target2[cacheSlot], receiver, args);
                    return result;
                }
            }
            if (!neko_icache_note_miss(env, site)) {
                jclass translatedClass = (meta->translated_class_slot != NULL) ? *meta->translated_class_slot : NULL;
                if (translatedClass != NULL && meta->translated_stub != NULL) {
                    void *translatedKlass = neko_class_mirror_to_klass(translatedClass);
                    if (translatedKlass == receiverKlass) {
                        neko_icache_store_direct(site, receiverKey, (void*)meta->translated_stub);
                        NEKO_ICACHE_AUDIT_HIT(g_neko_icache_translated_store_count);
                        return meta->translated_stub(thread, env, receiver_jni, args);
                    }
                }
                /* Resolve the concrete target through HotSpot metadata, not
                 * JNI GetMethodID. This is required for interface-declared
                 * JDK targets such as ExecutorService.shutdown(): decoding a
                 * JNI jmethodID as a native Method* cell can return without
                 * executing the concrete method body. */
                neko_handle_save_t icache_window;
                jclass exactMirror;
                neko_handle_window_begin(thread, &icache_window);
                exactMirror = (jclass)neko_klass_java_mirror_handle(thread, receiverKlass);
                if (exactMirror == NULL) {
                    fprintf(stderr, "[neko-direct] receiver mirror unavailable for %s%s klass=%p\\n",
                        meta->name, meta->desc, receiverKlass);
                    abort();
                }
                neko_link_class_methods(env, exactMirror, "<virtual>", meta->name, meta->desc);
                void *exactMethod = neko_resolve_method(receiverKlass, meta->name, meta->desc);
                neko_handle_window_end(&icache_window);
                int __holder_len = 1;
                const char *__holder_name = neko_method_holder_name_utf8(exactMethod, &__holder_len);
                NEKO_DIRECT_LOG("icache miss resolved %s%s exactMethod=%p holder=%.*s receiverKlass=%p receiver=%p",
                    meta->name, meta->desc, exactMethod, __holder_len, __holder_name, receiverKlass, receiver);
                if (neko_njx_enabled() && g_neko_direct_invoke_ready) {
                    void *m_ptr = NULL, *m_entry = NULL;
                    if (neko_njx_resolve_method_entry(exactMethod, &m_ptr, &m_entry)) {
                        NEKO_DIRECT_LOG("icache store direct-njx %s%s method=%p entry=%p receiver=%p",
                            meta->name, meta->desc, m_ptr, m_entry, receiver);
                        neko_icache_store_direct_njx(site, receiverKey, m_ptr, m_entry);
                        NEKO_ICACHE_AUDIT_HIT(g_neko_icache_direct_njx_store_count);
                        result = meta->direct_dispatcher(thread, env, m_ptr, m_entry, receiver, args);
                        return result;
                    }
                    neko_njx_note_resolve_fail();
                    fprintf(stderr, "[neko-direct] resolve-failed %s%s method=%p\\n",
                        meta->name, meta->desc, exactMethod);
                    abort();
                }
                fprintf(stderr, "[neko-direct] direct invoke unavailable for %s%s\\n", meta->name, meta->desc);
                abort();
            }
        }
    }
    neko_njx_note_resolve_fail();
    NEKO_ICACHE_AUDIT_HIT(g_neko_icache_unresolved_count);
    fprintf(stderr, "[neko-direct] unresolved virtual dispatch %s%s declared_mid=%p receiver=%p site=%p\\n",
        meta->name, meta->desc, declared_mid, receiver, (void*)site);
    abort();
    return result;
}

__attribute__((used)) static void neko_njx_dump_stats_at_exit(void) {
    uint64_t hits;
    uint64_t fails;
#if NEKO_ICACHE_AUDIT
    uint64_t ic_direct_c;
    uint64_t ic_direct_njx;
    uint64_t ic_miss;
    uint64_t ic_translated_store;
    uint64_t ic_direct_njx_store;
    uint64_t ic_unresolved;
#endif
#if NEKO_HANDLE_AUDIT
    uint64_t handle_total;
    uint64_t handle_fast_slot;
    uint64_t handle_overflow_alloc;
    uint64_t handle_unavailable;
    uint64_t handle_max_top;
    uint64_t handle_max_capacity;
#endif
    if (!neko_njx_debug()) return;
    hits = __atomic_load_n(&g_neko_njx_dispatch_count, __ATOMIC_RELAXED);
    fails = __atomic_load_n(&g_neko_njx_resolve_fail_count, __ATOMIC_RELAXED);
#if NEKO_HANDLE_AUDIT
    handle_total = __atomic_load_n(&g_neko_handle_direct_total_count, __ATOMIC_RELAXED);
    handle_fast_slot = __atomic_load_n(&g_neko_handle_direct_fast_slot_count, __ATOMIC_RELAXED);
    handle_overflow_alloc = __atomic_load_n(&g_neko_handle_direct_overflow_alloc_count, __ATOMIC_RELAXED);
    handle_unavailable = __atomic_load_n(&g_neko_handle_direct_unavailable_count, __ATOMIC_RELAXED);
    handle_max_top = __atomic_load_n(&g_neko_handle_direct_max_top, __ATOMIC_RELAXED);
    handle_max_capacity = __atomic_load_n(&g_neko_handle_direct_max_capacity, __ATOMIC_RELAXED);
#endif
#if NEKO_ICACHE_AUDIT
    ic_direct_c = __atomic_load_n(&g_neko_icache_direct_c_hit_count, __ATOMIC_RELAXED);
    ic_direct_njx = __atomic_load_n(&g_neko_icache_direct_njx_hit_count, __ATOMIC_RELAXED);
    ic_miss = __atomic_load_n(&g_neko_icache_miss_count, __ATOMIC_RELAXED);
    ic_translated_store = __atomic_load_n(&g_neko_icache_translated_store_count, __ATOMIC_RELAXED);
    ic_direct_njx_store = __atomic_load_n(&g_neko_icache_direct_njx_store_count, __ATOMIC_RELAXED);
    ic_unresolved = __atomic_load_n(&g_neko_icache_unresolved_count, __ATOMIC_RELAXED);
    if (hits == 0 && fails == 0 && ic_direct_c == 0 && ic_direct_njx == 0
        && ic_miss == 0 && ic_translated_store == 0 && ic_direct_njx_store == 0
        && ic_unresolved == 0
#if NEKO_HANDLE_AUDIT
        && handle_total == 0 && handle_fast_slot == 0 && handle_overflow_alloc == 0
        && handle_unavailable == 0
#endif
    ) return;
    if (!__sync_bool_compare_and_swap(&g_neko_njx_stats_printed, 0, 1)) return;
#if NEKO_HANDLE_AUDIT
    fprintf(stderr, "[neko-direct] stats: dispatched=%llu resolve_failed=%llu icache_direct_c_hit=%llu icache_direct_njx_hit=%llu icache_miss=%llu icache_translated_store=%llu icache_direct_njx_store=%llu icache_unresolved=%llu handle_direct_total=%llu handle_direct_fast_slot=%llu handle_direct_overflow_alloc=%llu handle_direct_unavailable=%llu handle_direct_max_top=%llu handle_direct_max_capacity=%llu\\n",
        (unsigned long long)hits, (unsigned long long)fails,
        (unsigned long long)ic_direct_c,
        (unsigned long long)ic_direct_njx,
        (unsigned long long)ic_miss,
        (unsigned long long)ic_translated_store,
        (unsigned long long)ic_direct_njx_store,
        (unsigned long long)ic_unresolved,
        (unsigned long long)handle_total,
        (unsigned long long)handle_fast_slot,
        (unsigned long long)handle_overflow_alloc,
        (unsigned long long)handle_unavailable,
        (unsigned long long)handle_max_top,
        (unsigned long long)handle_max_capacity);
#else
    fprintf(stderr, "[neko-direct] stats: dispatched=%llu resolve_failed=%llu icache_direct_c_hit=%llu icache_direct_njx_hit=%llu icache_miss=%llu icache_translated_store=%llu icache_direct_njx_store=%llu icache_unresolved=%llu\\n",
        (unsigned long long)hits, (unsigned long long)fails,
        (unsigned long long)ic_direct_c,
        (unsigned long long)ic_direct_njx,
        (unsigned long long)ic_miss,
        (unsigned long long)ic_translated_store,
        (unsigned long long)ic_direct_njx_store,
        (unsigned long long)ic_unresolved);
#endif
#else
    if (hits == 0 && fails == 0
#if NEKO_HANDLE_AUDIT
        && handle_total == 0 && handle_fast_slot == 0 && handle_overflow_alloc == 0
        && handle_unavailable == 0
#endif
    ) return;
    if (!__sync_bool_compare_and_swap(&g_neko_njx_stats_printed, 0, 1)) return;
#if NEKO_HANDLE_AUDIT
    fprintf(stderr, "[neko-direct] stats: dispatched=%llu resolve_failed=%llu handle_direct_total=%llu handle_direct_fast_slot=%llu handle_direct_overflow_alloc=%llu handle_direct_unavailable=%llu handle_direct_max_top=%llu handle_direct_max_capacity=%llu\\n",
        (unsigned long long)hits,
        (unsigned long long)fails,
        (unsigned long long)handle_total,
        (unsigned long long)handle_fast_slot,
        (unsigned long long)handle_overflow_alloc,
        (unsigned long long)handle_unavailable,
        (unsigned long long)handle_max_top,
        (unsigned long long)handle_max_capacity);
#else
    fprintf(stderr, "[neko-direct] stats: dispatched=%llu resolve_failed=%llu\\n",
        (unsigned long long)hits, (unsigned long long)fails);
#endif
#endif
#if NEKO_HANDLE_AUDIT
    fprintf(stderr, "[neko-direct] handle-origins: other=%llu object_array_alloc=%llu primitive_array_alloc=%llu object_alloc=%llu aaload=%llu checked_aaload=%llu fused_aaload_aaload=%llu object_field=%llu static_object_field=%llu njx_return=%llu bound_string=%llu\\n",
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_other_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_object_array_alloc_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_primitive_array_alloc_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_object_alloc_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_aaload_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_checked_aaload_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_fused_aaload_aaload_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_object_field_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_static_object_field_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_njx_return_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_handle_origin_bound_string_count, __ATOMIC_RELAXED));
    {
        uint64_t concat_njx = __atomic_load_n(&g_neko_concat_accumulate_njx_count, __ATOMIC_RELAXED);
        uint64_t concat_final = __atomic_load_n(&g_neko_concat_final_push_count, __ATOMIC_RELAXED);
        fprintf(stderr, "[neko-direct] concat-continuation: accumulate_total=%llu accumulate_njx=%llu final_push=%llu intermediate_candidate=%llu\\n",
            (unsigned long long)__atomic_load_n(&g_neko_concat_accumulate_total_count, __ATOMIC_RELAXED),
            (unsigned long long)concat_njx,
            (unsigned long long)concat_final,
            (unsigned long long)(concat_njx > concat_final ? concat_njx - concat_final : 0));
    }
    fprintf(stderr, "[neko-direct] stringbuilder-fast-concat: total=%llu literal=%llu dynamic=%llu\\n",
        (unsigned long long)__atomic_load_n(&g_neko_stringbuilder_concat_fast_total_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_stringbuilder_concat_fast_literal_count, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_neko_stringbuilder_concat_fast_dynamic_count, __ATOMIC_RELAXED));
#endif
}
__attribute__((constructor)) static void neko_njx_register_atexit(void) {
    atexit(neko_njx_dump_stats_at_exit);
}

""");
        appendStaticFieldRefHelpers(sb);
        appendPrimitiveFieldHelpers(sb, 'Z', "jboolean", "boolean");
        appendPrimitiveFieldHelpers(sb, 'B', "jbyte", "byte");
        appendPrimitiveFieldHelpers(sb, 'C', "jchar", "char");
        appendPrimitiveFieldHelpers(sb, 'S', "jshort", "short");
        appendPrimitiveFieldHelpers(sb, 'I', "jint", "int");
        appendPrimitiveFieldHelpers(sb, 'J', "jlong", "long");
        appendPrimitiveFieldHelpers(sb, 'F', "jfloat", "float");
        appendPrimitiveFieldHelpers(sb, 'D', "jdouble", "double");
        appendPrimitiveArrayHelpers(sb, "z", "jboolean", "boolean", "NEKO_PRIM_Z");
        appendPrimitiveArrayHelpers(sb, "b", "jbyte", "byte", "NEKO_PRIM_B");
        appendPrimitiveArrayHelpers(sb, "c", "jchar", "char", "NEKO_PRIM_C");
        appendPrimitiveArrayHelpers(sb, "s", "jshort", "short", "NEKO_PRIM_S");
        appendPrimitiveArrayHelpers(sb, "i", "jint", "int", "NEKO_PRIM_I");
        appendPrimitiveArrayHelpers(sb, "l", "jlong", "long", "NEKO_PRIM_J");
        appendPrimitiveArrayHelpers(sb, "f", "jfloat", "float", "NEKO_PRIM_F");
        appendPrimitiveArrayHelpers(sb, "d", "jdouble", "double", "NEKO_PRIM_D");
        return sb.toString();
    }

    private static void appendStaticFieldRefHelpers(StringBuilder sb) {
        sb.append("""
NEKO_FAST_INLINE jclass neko_static_field_ref_class(JNIEnv *env, const neko_static_field_ref *ref) {
    if (ref == NULL || ref->class_slot == NULL || ref->class_init_slot == NULL) {
        fprintf(stderr, "[neko-direct] static field ref class metadata unavailable ref=%p\\n", (void*)ref);
        abort();
    }
    jclass cls = neko_bound_class(env, *(ref->class_slot), ref->owner);
    neko_ensure_class_initialized_once(env, cls, ref->owner, ref->class_init_slot);
    return cls;
}

NEKO_FAST_INLINE jfieldID neko_static_field_ref_field(JNIEnv *env, const neko_static_field_ref *ref) {
    jfieldID fid;
    if (ref == NULL || ref->field_slot == NULL) {
        fprintf(stderr, "[neko-direct] static field ref field metadata unavailable ref=%p\\n", (void*)ref);
        abort();
    }
    fid = neko_bound_field(env, *(ref->field_slot), ref->owner, ref->name, ref->desc, JNI_TRUE);
    return fid;
}

""");
    }


    private static void appendPrimitiveFieldHelpers(StringBuilder sb, char desc, String cType, String wrapperStem) {
        sb.append("NEKO_FAST_INLINE ").append(cType).append(" neko_fast_get_").append(desc)
            .append("_field(JNIEnv *env, jobject obj, jfieldID fid, jlong offset, uint32_t access_flags, const char *owner, const char *name) {\n")
            .append("    (void)env; (void)fid;\n")
            .append("    if (g_hotspot.initialized && (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_FIELD_HELPERS) != 0 && offset > 0) {\n")
            .append("        char *oop = (char*)neko_handle_oop(obj);\n")
            .append("        if (oop != NULL) return (access_flags & 0x0040u) != 0u ? *((volatile ").append(cType).append("*)(oop + offset)) : *((").append(cType).append("*)(oop + offset));\n")
            .append("    }\n")
            .append("    fprintf(stderr, \"[neko-direct] missing primitive instance field direct metadata %s.%s kind=").append(desc).append(" offset=%lld obj=%p\\n\", owner, name, (long long)offset, (void*)obj); abort();\n")
            .append("}\n\n")
            .append("NEKO_FAST_INLINE void neko_fast_set_").append(desc)
            .append("_field(JNIEnv *env, jobject obj, jfieldID fid, jlong offset, uint32_t access_flags, ").append(cType).append(" value, const char *owner, const char *name) {\n")
            .append("    (void)env; (void)fid;\n")
            .append("    if (g_hotspot.initialized && (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_FIELD_HELPERS) != 0 && offset > 0) {\n")
            .append("        char *oop = (char*)neko_handle_oop(obj);\n")
            .append("        if (oop != NULL) { if ((access_flags & 0x0040u) != 0u) *((volatile ").append(cType).append("*)(oop + offset)) = value; else *((").append(cType).append("*)(oop + offset)) = value; return; }\n")
            .append("    }\n")
            .append("    fprintf(stderr, \"[neko-direct] missing primitive instance field direct metadata %s.%s kind=").append(desc).append(" offset=%lld obj=%p\\n\", owner, name, (long long)offset, (void*)obj); abort();\n")
            .append("}\n\n")
            .append("NEKO_FAST_INLINE ").append(cType).append(" neko_fast_get_static_").append(desc)
            .append("_field(JNIEnv *env, jclass cls, jfieldID fid, jobject staticBase, jlong offset, uint32_t access_flags) {\n")
            .append("    (void)env; (void)cls; (void)fid;\n")
            .append("    if (g_hotspot.initialized && (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_FIELD_HELPERS) != 0 && offset > 0) {\n")
            .append("        char *oop = (char*)neko_static_base_oop((jobject)cls);\n")
            .append("        if (oop == NULL) oop = (char*)neko_static_base_oop(staticBase);\n")
            .append("        if (oop != NULL) return (access_flags & 0x0040u) != 0u ? *((volatile ").append(cType).append("*)(oop + offset)) : *((").append(cType).append("*)(oop + offset));\n")
            .append("    }\n")
            .append("    fprintf(stderr, \"[neko-direct] missing primitive static field direct metadata kind=").append(desc).append(" offset=%lld base=%p\\n\", (long long)offset, (void*)staticBase); abort();\n")
            .append("}\n\n")
            .append("NEKO_FAST_INLINE ").append(cType).append(" neko_fast_get_static_").append(desc)
            .append("_field_ref(JNIEnv *env, const neko_static_field_ref *ref) {\n")
            .append("    jclass cls = neko_static_field_ref_class(env, ref);\n")
            .append("    jfieldID fid = neko_static_field_ref_field(env, ref);\n")
            .append("    return neko_fast_get_static_").append(desc).append("_field(env, cls, fid, *(ref->static_base_slot), *(ref->static_offset_slot), *(ref->access_flags_slot));\n")
            .append("}\n\n")
            .append("NEKO_FAST_INLINE void neko_fast_set_static_").append(desc)
            .append("_field(JNIEnv *env, jclass cls, jfieldID fid, jobject staticBase, jlong offset, uint32_t access_flags, ").append(cType).append(" value) {\n")
            .append("    (void)env; (void)cls; (void)fid;\n")
            .append("    if (g_hotspot.initialized && (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_FIELD_HELPERS) != 0 && offset > 0) {\n")
            .append("        char *oop = (char*)neko_static_base_oop((jobject)cls);\n")
            .append("        if (oop == NULL) oop = (char*)neko_static_base_oop(staticBase);\n")
            .append("        if (oop != NULL) { if ((access_flags & 0x0040u) != 0u) *((volatile ").append(cType).append("*)(oop + offset)) = value; else *((").append(cType).append("*)(oop + offset)) = value; return; }\n")
            .append("    }\n")
            .append("    fprintf(stderr, \"[neko-direct] missing primitive static field direct metadata kind=").append(desc).append(" offset=%lld base=%p\\n\", (long long)offset, (void*)staticBase); abort();\n")
            .append("}\n\n");
    }

    private static void appendPrimitiveArrayHelpers(StringBuilder sb, String prefix, String cType, String wrapperStem, String kindConstant) {
        sb.append("NEKO_HOT_INLINE ").append(cType).append(" neko_fast_").append(prefix)
            .append("aload(jarray arr, jint idx) {\n")
            .append("    if (NEKO_LIKELY(neko_const_initialized() && ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) != 0 || neko_const_use_zgc()) && arr != NULL)) {\n")
            .append("        char *oop = (char*)neko_handle_oop((jobject)arr);\n")
            .append("        if (NEKO_LIKELY(oop != NULL)) {\n")
            .append("            jint arrayLen = *(jint*)(oop + neko_const_array_length_offset());\n")
            .append("            if (NEKO_LIKELY(idx >= 0 && idx < arrayLen)) {\n")
            .append("                char *addr = oop + neko_const_prim_array_base(").append(kindConstant).append(") + ((jlong)idx * neko_const_prim_array_scale(").append(kindConstant).append("));\n")
            .append("                return *(").append(cType).append("*)addr;\n")
            .append("            }\n")
            .append("        }\n")
            .append("    }\n")
            .append("    fprintf(stderr, \"[neko-direct] ").append(prefix).append("ALOAD direct path unavailable arr=%p idx=%d\\n\", (void*)arr, (int)idx); abort();\n")
            .append("}\n\n")
            .append("NEKO_HOT_INLINE void neko_fast_").append(prefix)
            .append("astore(jarray arr, jint idx, ").append(cType).append(" value) {\n")
            .append("    if (NEKO_LIKELY(neko_const_initialized() && ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) != 0 || neko_const_use_zgc()) && arr != NULL)) {\n")
            .append("        char *oop = (char*)neko_handle_oop((jobject)arr);\n")
            .append("        if (NEKO_LIKELY(oop != NULL)) {\n")
            .append("            jint arrayLen = *(jint*)(oop + neko_const_array_length_offset());\n")
            .append("            if (NEKO_LIKELY(idx >= 0 && idx < arrayLen)) {\n")
            .append("                char *addr = oop + neko_const_prim_array_base(").append(kindConstant).append(") + ((jlong)idx * neko_const_prim_array_scale(").append(kindConstant).append("));\n")
            .append("                *(").append(cType).append("*)addr = value;\n")
            .append("                return;\n")
            .append("            }\n")
            .append("        }\n")
            .append("    }\n")
            .append("    fprintf(stderr, \"[neko-direct] ").append(prefix).append("ASTORE direct path unavailable arr=%p idx=%d\\n\", (void*)arr, (int)idx); abort();\n")
            .append("}\n\n");
    }

    static String cTypeForArray(String prefix) {
        return switch (prefix) {
            case "z" -> "jbooleanArray";
            case "b" -> "jbyteArray";
            case "c" -> "jcharArray";
            case "s" -> "jshortArray";
            case "i" -> "jintArray";
            case "l" -> "jlongArray";
            case "f" -> "jfloatArray";
            case "d" -> "jdoubleArray";
            default -> "jarray";
        };
    }

}
