package dev.nekoobfuscator.native_.codegen;

/**
 * Emits common translated-method runtime state, stack, and HotSpot snapshot support.
 */
final class NativeRuntimeSupportEmitter {
    private NativeRuntimeSupportEmitter() {}

    static String renderRuntimeSupport() {
        return """
typedef union {
    jint i;
    jlong j;
    jfloat f;
    jdouble d;
    jobject o;
} neko_slot;

#define PUSH_I(v) do { jint __tmp = (jint)(v); stack[sp++].i = __tmp; } while (0)
#define PUSH_L(v) do { jlong __tmp = (jlong)(v); stack[sp].j = __tmp; stack[sp + 1].j = __tmp; sp += 2; } while (0)
#define PUSH_F(v) do { jfloat __tmp = (jfloat)(v); stack[sp++].f = __tmp; } while (0)
#define PUSH_D(v) do { jdouble __tmp = (jdouble)(v); stack[sp].d = __tmp; stack[sp + 1].d = __tmp; sp += 2; } while (0)
#define PUSH_O(v) do { jobject __tmp = (jobject)(v); stack[sp++].o = __tmp; } while (0)
#define POP_I() (stack[--sp].i)
#define POP_L() (sp -= 2, stack[sp].j)
#define POP_F() (stack[--sp].f)
#define POP_D() (sp -= 2, stack[sp].d)
#define POP_O() (stack[--sp].o)

/* T3.20: the macro that did typed function-table indexing through env, plus
 * every opcode-side wrapper replaced by T3.1..T3.19 (object class / instanceof
 * checks, allocation, static-field oop reads, String UTF probes, array length
 * + region accessors, object-array allocation/get/set, primitive-array
 * allocations), is gone. The remaining bind-time helpers below expand the
 * function-table indexing inline; they are the only JNI surface left in
 * renderRuntimeSupport and only fire from the bootstrap / discovery path,
 * never from translated method bodies. */

__attribute__((visibility("hidden"))) void neko_transition_java_to_native(void *thread);
__attribute__((visibility("hidden"))) void neko_transition_native_to_java(void *thread);

/* T4.11 — the eight bind-time inline JNI wrappers
 *   neko_find_class, neko_get_method_id, neko_get_static_method_id,
 *   neko_get_static_field_id, neko_exception_clear,
 *   neko_new_global_ref, neko_delete_global_ref, neko_delete_local_ref
 * are sweep-deleted now that T4.1-T4.10 have driven the wrapper call
 * count to zero. Every former call site routes either through a
 * libjvm-internal direct read (T4.1 / T4.2c / T4.10 / T4.9) or through
 * a captured JNI function-table pointer (T4.2a / T4.2b / T4.3 / T4.4 /
 * T4.5 / T4.6 / T4.8). The forward declaration of
 * neko_exception_clear_direct stays because renderBindSupport call
 * sites need it before the actual definition (which lives after
 * neko_exception_check in renderHotSpotSupport). */
static inline __attribute__((always_inline)) void neko_exception_clear_direct(JNIEnv *env);
/* Some HotSpot helper blocks use `neko_handle_oop` before the fast-access
 * section is emitted in the final C file. Declare it here so C99 does not
 * infer an implicit int-returning prototype on first use. */
static inline void* neko_handle_oop(jobject handle);
static inline void* neko_handle_push(void *thread, void *raw_oop);
static inline void* neko_prepare_return_oop(void *thread, jobject handle, const char *site);
static inline void neko_handle_window_begin(void *thread, neko_handle_save_t *out);
static inline void neko_handle_window_end(neko_handle_save_t *saved);
static jint neko_fast_array_length(jarray arr);
static jobject neko_fast_aaload(void *thread, JNIEnv *env, jobjectArray arr, jint idx);
static void neko_fast_aastore(void *thread, JNIEnv *env, jobjectArray arr, jint idx, jobject val);

static inline void neko_set_pending_exception(void *thread, jthrowable exc) {
    void *exc_oop;
    if (thread == NULL || g_neko_off_thread_pending_exception <= 0) {
        fprintf(stderr, "[neko-direct] cannot set pending exception thread=%p pending_off=%td\\n",
            thread, g_neko_off_thread_pending_exception);
        abort();
    }
    if (exc == NULL) {
        fprintf(stderr, "[neko-direct] ATHROW null throwable requires implicit NPE construction\\n");
        abort();
    }
    exc_oop = neko_handle_oop((jobject)exc);
    if (exc_oop == NULL) {
        fprintf(stderr, "[neko-direct] ATHROW throwable handle did not resolve exc=%p\\n", (void*)exc);
        abort();
    }
    *(void**)((char*)thread + g_neko_off_thread_pending_exception) = exc_oop;
}

static inline void *neko_pending_exception_oop(void *thread) {
    if (thread == NULL || g_neko_off_thread_pending_exception <= 0) {
        fprintf(stderr, "[neko-direct] cannot read pending exception thread=%p pending_off=%td\\n",
            thread, g_neko_off_thread_pending_exception);
        abort();
    }
    return *(void**)((char*)thread + g_neko_off_thread_pending_exception);
}

static inline void neko_clear_pending_exception(void *thread) {
    if (thread == NULL || g_neko_off_thread_pending_exception <= 0) {
        fprintf(stderr, "[neko-direct] cannot clear pending exception thread=%p pending_off=%td\\n",
            thread, g_neko_off_thread_pending_exception);
        abort();
    }
    *(void**)((char*)thread + g_neko_off_thread_pending_exception) = NULL;
}

static inline jthrowable neko_take_pending_exception(void *thread) {
    void *exc_oop = neko_pending_exception_oop(thread);
    if (exc_oop == NULL) return NULL;
    jthrowable exc = (jthrowable)neko_handle_push(thread, exc_oop);
    neko_clear_pending_exception(thread);
    return exc;
}

/* Forward decl + helper: read JavaThread::_pending_exception directly. The
 * field offset is recovered by VMStructs (g_neko_off_thread_pending_exception)
 * and the JNIEnv->JavaThread distance is recovered by the patcher init
 * (g_neko_off_thread_jni_environment_for_check). When both are known,
 * neko_exception_check becomes a load + compare instead of a JNI call. The
 * translator emits one neko_exception_check after every JNI call inside an
 * impl_fn, so saving the JNI dispatch (~50 cycles) per check buys a lot in
 * tight loops (matrix multiply: ~35M checks per microbench iteration). */
extern ptrdiff_t g_neko_off_thread_pending_exception;
__attribute__((visibility("hidden"))) extern ptrdiff_t g_neko_off_thread_jni_environment_for_check;
__attribute__((visibility("hidden"))) extern void *g_neko_jni_onload_thread_reg;
__attribute__((visibility("hidden"))) extern void *g_neko_jni_functions_table;
__attribute__((visibility("hidden"))) extern int32_t g_neko_env_offset_publication_kind;
__attribute__((visibility("hidden"))) extern ptrdiff_t g_neko_off_thread_state;
__attribute__((visibility("hidden"))) extern int32_t g_neko_thread_state_in_java;
__attribute__((visibility("hidden"))) extern int32_t g_neko_thread_state_in_native;
__attribute__((visibility("hidden"))) extern int32_t g_neko_thread_state_in_native_trans;

/* T4.0: bootstrap derivation of the JNIEnv -> JavaThread distance. The
 * previous (T3.20) version was reached lazily from the hot-path
 * neko_exception_check; that defeated CSE of the offset across multiple
 * inlined exception checks in the same impl_fn. T4.0 moves the call site
 * to neko_method_layout_init (end of JNI_OnLoad). The first generated library
 * that must memory-walk publishes a validated process-wide cache; later
 * generated libraries validate and reuse that cache before scanning, so the
 * resolver performs at most one memory walk per JVM process. The hot path no
 * longer references the resolver or the atomic acquire-load. We mark the
 * function `cold` + `noinline` so
 * GCC keeps it in a separate text segment partition and never speculates
 * a cross-function inline that would force a register-allocation barrier
 * around the hot path. The body itself is unchanged: env is the address
 * of JavaThread::_jni_environment, so the JavaThread base sits at
 * `env - off` for some `off` in the JNI environment field's offset
 * within JavaThread. We scan candidate offsets, accepting the one whose
 * first slot (the C++ vtable pointer) lies within libjvm's text mapping
 * (anchored against the published JNI function-table pointer, which
 * itself lives in libjvm). The pending-exception oop slot is additionally
 * required to look like NULL or a non-low aligned pointer so a coincidental
 * vtable hit cannot wedge in a wrong offset. No JNI calls are made; an
 * unvalidated candidate is hard-rejected. */
extern int setenv(const char *name, const char *value, int overwrite);
#define NEKO_ENV_OFFSET_CACHE_NAME "NEKO_NATIVE_JNI_ENV_OFFSET"

__attribute__((cold)) __attribute__((noinline))
static jboolean neko_exception_check_validate_env_offset(JNIEnv *env, ptrdiff_t off, void **thread_out, void **vtbl_out) {
    uintptr_t env_bits;
    uintptr_t fn_table_bits;
    intptr_t libjvm_window;
    uintptr_t candidate_bits;
    void *thread_candidate;
    void *vtbl;
    intptr_t diff;
    void *pending;
    int32_t state;
    if (env == NULL || g_neko_jni_functions_table == NULL
        || g_neko_off_thread_pending_exception <= 0
        || off < (ptrdiff_t)0x100 || off >= (ptrdiff_t)0x4000
        || (off % (ptrdiff_t)sizeof(void*)) != 0) {
        return JNI_FALSE;
    }
    env_bits = (uintptr_t)env;
    candidate_bits = env_bits - (uintptr_t)off;
    if (candidate_bits < (uintptr_t)0x100000ULL) {
        return JNI_FALSE;
    }
    if ((candidate_bits & (uintptr_t)0xfULL) != 0u) {
        /* JavaThread is allocated with C++ new which guarantees at
         * least 16-byte alignment on 64-bit Linux. */
        return JNI_FALSE;
    }
    thread_candidate = (void*)candidate_bits;
    if (*(void**)((char*)thread_candidate + off) != g_neko_jni_functions_table) {
        return JNI_FALSE;
    }
    vtbl = *(void**)thread_candidate;
    if (vtbl == NULL) {
        return JNI_FALSE;
    }
    if (((uintptr_t)vtbl & (uintptr_t)0x7ULL) != 0u) {
        return JNI_FALSE;
    }
    fn_table_bits = (uintptr_t)g_neko_jni_functions_table;
    /* libjvm's text and data sections sit on different mmap'd regions,
     * sometimes hundreds of megabytes apart. Use a 1 GB window from the
     * published function-table pointer; this is wide enough to cover both
     * libjvm pages while still rejecting random non-libjvm vtables. */
    libjvm_window = (intptr_t)0x40000000;  /* 1 GB on each side */
    diff = (intptr_t)vtbl - (intptr_t)fn_table_bits;
    if (diff < -libjvm_window || diff > libjvm_window) {
        return JNI_FALSE;
    }
    pending = *(void**)((char*)thread_candidate + g_neko_off_thread_pending_exception);
    if (pending != NULL
        && ((uintptr_t)pending < (uintptr_t)0x100000ULL
            || ((uintptr_t)pending & (uintptr_t)0x7ULL) != 0u)) {
        return JNI_FALSE;
    }
    if (g_neko_off_thread_state > 0) {
        state = *(int32_t*)((char*)thread_candidate + g_neko_off_thread_state);
        /* Thread state is a small enum (HotSpot uses 0..9). A real JavaThread
         * is in `_thread_in_native` while we run inside JNI_OnLoad / bind
         * helpers, but accept any of the states the patcher already published
         * to keep this generic. */
        if (state != g_neko_thread_state_in_java
            && state != g_neko_thread_state_in_native
            && state != g_neko_thread_state_in_native_trans) {
            return JNI_FALSE;
        }
    }
    if (thread_out != NULL) {
        *thread_out = thread_candidate;
    }
    if (vtbl_out != NULL) {
        *vtbl_out = vtbl;
    }
    return JNI_TRUE;
}

__attribute__((cold)) __attribute__((noinline))
static jboolean neko_exception_check_load_process_env_offset(JNIEnv *env) {
    const char *cached = getenv(NEKO_ENV_OFFSET_CACHE_NAME);
    unsigned long value = 0;
    const unsigned char *p;
    ptrdiff_t off;
    void *thread_candidate = NULL;
    void *vtbl = NULL;
    if (cached == NULL || cached[0] == '\\0') {
        return JNI_FALSE;
    }
    p = (const unsigned char*)cached;
    while (*p >= (unsigned char)'0' && *p <= (unsigned char)'9') {
        value = (value * 10UL) + (unsigned long)(*p - (unsigned char)'0');
        if (value >= 0x4000UL) {
            return JNI_FALSE;
        }
        p++;
    }
    if (*p != (unsigned char)'\\0') {
        return JNI_FALSE;
    }
    off = (ptrdiff_t)value;
    if (!neko_exception_check_validate_env_offset(env, off, &thread_candidate, &vtbl)) {
        if (getenv("NEKO_PATCH_DEBUG") != NULL) {
            fprintf(stderr,
                "[neko-direct] ignored invalid process JNIEnv->JavaThread offset cache: value=%s env=%p fn_table=%p\\n",
                cached, (void*)env, g_neko_jni_functions_table);
        }
        return JNI_FALSE;
    }
    __atomic_store_n(&g_neko_off_thread_jni_environment_for_check, off, __ATOMIC_RELEASE);
    g_neko_env_offset_publication_kind = 2;
    if (getenv("NEKO_PATCH_DEBUG") != NULL) {
        fprintf(stderr,
            "[neko-direct] reused process JNIEnv->JavaThread offset cache:"
            " off=%td env=%p thread=%p vtbl=%p\\n",
            off, (void*)env, thread_candidate, vtbl);
    }
    return JNI_TRUE;
}

__attribute__((cold)) __attribute__((noinline))
static jboolean neko_exception_check_publish_process_env_offset(ptrdiff_t off) {
    char encoded[32];
    int n;
    if (off <= 0) {
        return JNI_FALSE;
    }
    n = snprintf(encoded, sizeof(encoded), "%td", off);
    if (n <= 0 || (size_t)n >= sizeof(encoded)) {
        return JNI_FALSE;
    }
    if (setenv(NEKO_ENV_OFFSET_CACHE_NAME, encoded, 1) != 0) {
        if (getenv("NEKO_PATCH_DEBUG") != NULL) {
            fprintf(stderr,
                "[neko-direct] failed to publish process JNIEnv->JavaThread offset cache:"
                " off=%td\\n",
                off);
        }
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

__attribute__((cold)) __attribute__((noinline))
static jboolean neko_exception_check_resolve_env_offset(JNIEnv *env) {
    ptrdiff_t off;
    /* `g_neko_off_thread_jni_environment_for_check` is updated once and never
     * reset. The eager publication wrapper in neko_method_layout_init
     * already short-circuits when the VMStructs path supplied the offset,
     * so by the time we reach this scan, the global is guaranteed to be
     * zero unless a parallel JNI_OnLoad invocation raced us (impossible:
     * System.load() serializes). Read via __atomic_load_n with RELAXED
     * to keep the cold-path symmetry with the publishing store below; no
     * fence semantics are needed because the publishing happens before
     * any dispatcher entry can race against it. */
    if (__atomic_load_n(&g_neko_off_thread_jni_environment_for_check, __ATOMIC_RELAXED) > 0) {
        return JNI_TRUE;
    }
    if (env == NULL || g_neko_jni_functions_table == NULL
        || g_neko_off_thread_pending_exception <= 0) {
        return JNI_FALSE;
    }
    if (neko_exception_check_load_process_env_offset(env)) {
        return JNI_TRUE;
    }
    /* `_jni_environment` is the embedded JNIEnv member of JavaThread. In
     * HotSpot 21 it sits hundreds of bytes into the struct (after the
     * Thread base, OSThread*, _stack_base, the JavaFrameAnchor, etc.), so
     * candidates below 0x100 are never plausible and accepting one would
     * land us mid-record on a random earlier field whose memory happens to
     * mimic a vtable pointer. The lower bound also excludes the struct
     * preamble (vtable, mutex pointers) where `*(thread + off)` would
     * trivially match by aliasing. */
    for (off = 0x100; off < 0x4000; off += (ptrdiff_t)sizeof(void*)) {
        void *thread_candidate = NULL;
        void *vtbl = NULL;
        if (!neko_exception_check_validate_env_offset(env, off, &thread_candidate, &vtbl)) {
            continue;
        }
        __atomic_store_n(&g_neko_off_thread_jni_environment_for_check, off, __ATOMIC_RELEASE);
        if (!neko_exception_check_publish_process_env_offset(off)) {
            return JNI_FALSE;
        }
        g_neko_env_offset_publication_kind = 3;
        if (getenv("NEKO_PATCH_DEBUG") != NULL) {
            fprintf(stderr,
                "[neko-direct] derived JNIEnv->JavaThread distance via memory walk:"
                " off=%td env=%p thread=%p vtbl=%p\\n",
                off, (void*)env, thread_candidate, vtbl);
        }
        return JNI_TRUE;
    }
    if (getenv("NEKO_PATCH_DEBUG") != NULL) {
        fprintf(stderr,
            "[neko-direct] memory-walk derivation failed: env=%p fn_table=%p"
            " (no JavaThread vtable found in scan window)\\n",
            (void*)env, g_neko_jni_functions_table);
    }
    return JNI_FALSE;
}

/* T4.0 hot-path collapse:
 *   load env_off (plain non-atomic global)
 *   compute thread = env - env_off
 *   load _pending_exception
 *   compare and return.
 *
 * Both `g_neko_off_thread_jni_environment_for_check` and
 * `g_neko_off_thread_pending_exception` are published EAGERLY at the end of
 * `neko_method_layout_init` (driven from `JNI_OnLoad`) before any obfuscated
 * method can dispatch through us; missing publication aborts inside layout
 * init, so by the time control reaches this inline check, both globals are
 * non-zero. The plain global loads are CSE-safe across multiple inlined
 * neko_exception_check calls in the same impl_fn — the previous T3.20
 * `__atomic_load_n(..., __ATOMIC_ACQUIRE)` form blocked CSE because acquire
 * fences are conservative compiler barriers, which is the regression that
 * pushed matrix-mul Seq from ~25 ms to ~57 ms at T3.20 commit. The cold
 * `__builtin_expect(env_off <= 0, 0)` defensive abort stays in case some
 * cleanup path tears down the offset; production runs never enter it after
 * a successful JNI_OnLoad. The resolver function is unreachable from here. */
static inline __attribute__((always_inline))
jboolean neko_exception_check(JNIEnv *env) {
    ptrdiff_t env_off = g_neko_off_thread_jni_environment_for_check;
    void *thread;
    if (__builtin_expect(env_off <= 0, 0)) {
        fprintf(stderr,
            "[neko-direct] hot-path env-offset unpublished (env_off=%td pending_off=%td"
            " functions_table=%p thread_reg=%p); T4.0 eager publication required\\n",
            env_off, g_neko_off_thread_pending_exception,
            g_neko_jni_functions_table, g_neko_jni_onload_thread_reg);
        abort();
    }
    thread = (void*)((char*)env - env_off);
    return *(void**)((char*)thread + g_neko_off_thread_pending_exception) != NULL
        ? JNI_TRUE : JNI_FALSE;
}

/* T4.9 — direct _pending_exception clear via the offset published by T4.0
 * eager publication. Drop-in for `neko_exception_clear(env)`; idempotent
 * (clearing a NULL slot is a no-op store), so the surrounding
 * `if (neko_exception_check(env)) ...` guard becomes optional and may be
 * elided. The check + write are equivalent to two acquire-loads + a store
 * + a branch — strictly cheaper than the JNI function-table indirection
 * (index 17 = ExceptionClear). Missing offsets abort because T4.0
 * publishes both before any obfuscated method dispatches. */
static inline __attribute__((always_inline))
void neko_exception_clear_direct(JNIEnv *env) {
    ptrdiff_t env_off = g_neko_off_thread_jni_environment_for_check;
    void *thread;
    if (__builtin_expect(env_off <= 0 || g_neko_off_thread_pending_exception <= 0, 0)) {
        fprintf(stderr,
            "[neko-direct] T4.9 exception clear missing offsets (env_off=%td pending_off=%td)\\n",
            env_off, g_neko_off_thread_pending_exception);
        abort();
    }
    thread = (void*)((char*)env - env_off);
    *(void**)((char*)thread + g_neko_off_thread_pending_exception) = NULL;
}

typedef jvalue (*neko_njx_dispatcher_t)(void*, JNIEnv*, void*, void*, jobject, const jvalue*);

/* Cold + noinline so the bounds-check / NPE failure paths in every translated
 * impl body are kept out of the inline copy. Without this every AALOAD,
 * GETFIELD, etc. carries the constructor argument-load + dispatcher call
 * inline beside the fast path, bloating the hot loop's icache footprint. */
__attribute__((cold, noinline))
static void neko_raise_implicit_exception(void *thread, JNIEnv *env, jclass cls, void *ctor_method, void *ctor_entry, neko_njx_dispatcher_t ctor_dispatcher, const char *name) {
    jobject exc;
    jvalue args[1];
    if (thread == NULL || cls == NULL || ctor_method == NULL || ctor_entry == NULL || ctor_dispatcher == NULL) {
        fprintf(stderr, "[neko-direct] implicit exception precondition failed name=%s thread=%p cls=%p method=%p entry=%p dispatch=%p\\n",
            name == NULL ? "<null>" : name, thread, (void*)cls, ctor_method, ctor_entry, (void*)ctor_dispatcher);
        abort();
    }
    exc = neko_fast_alloc_object(thread, env, cls);
    args[0].l = NULL;
    ctor_dispatcher(thread, env, ctor_method, ctor_entry, exc, args);
    if (!neko_exception_check(env)) {
        neko_set_pending_exception(thread, (jthrowable)exc);
    }
}

typedef struct {
    const char *owner;
    const char *method;
    const char *file;
} neko_shadow_frame_desc;

typedef struct {
    const neko_shadow_frame_desc *desc;
} neko_shadow_frame;

#define NEKO_SHADOW_STACK_MAX 256
static __thread neko_shadow_frame g_neko_shadow_stack[NEKO_SHADOW_STACK_MAX];
static __thread uint32_t g_neko_shadow_depth = 0u;

static void neko_shadow_push(const neko_shadow_frame_desc *desc) {
    if (desc == NULL || desc->owner == NULL || desc->method == NULL || desc->file == NULL) return;
    if (g_neko_shadow_depth < NEKO_SHADOW_STACK_MAX) {
        g_neko_shadow_stack[g_neko_shadow_depth].desc = desc;
        g_neko_shadow_depth++;
    }
}

static void neko_shadow_pop(void) {
    if (g_neko_shadow_depth > 0u) g_neko_shadow_depth--;
}

/* T3.20: shadow-stack StackTrace helpers retain their pre-existing object and
 * array JNI surface while the string materialization path is routed through the
 * direct string interner used by LDC String support. */
static jstring neko_shadow_utf_string(void *thread, JNIEnv *env, const char *text) {
    void *string_oop;
    jstring string_ref;
    if (text == NULL) return NULL;
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] shadow stack string intern has no JavaThread\\n");
        abort();
    }
    string_oop = neko_intern_string(thread, env, (const uint8_t*)text, strlen(text));
    if (string_oop == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] shadow stack string intern failed text=%s\\n", text);
        abort();
    }
    string_ref = (jstring)neko_handle_push(thread, string_oop);
    if (string_ref == NULL) {
        fprintf(stderr, "[neko-bind] shadow stack string handle push failed text=%s\\n", text);
        abort();
    }
    return string_ref;
}

static jstring neko_shadow_dotted_string(void *thread, JNIEnv *env, const char *internal_name) {
    char buf[512];
    size_t i;
    if (internal_name == NULL) return NULL;
    for (i = 0u; i + 1u < sizeof(buf) && internal_name[i] != '\\0'; i++) {
        buf[i] = internal_name[i] == '/' ? '.' : internal_name[i];
    }
    buf[i] = '\\0';
    return neko_shadow_utf_string(thread, env, buf);
}

static jboolean g_neko_shadow_stack_trace_ready = JNI_FALSE;
static uintptr_t g_neko_shadow_ste_array_klass_bits = 0;
static void *g_neko_shadow_ste_ctor_method = NULL;
static void *g_neko_shadow_ste_ctor_entry = NULL;

static void neko_ensure_shadow_stack_trace_cache(JNIEnv *env, jclass ste_cls, void *ste_klass) {
    void *ctor_method;
    if (g_neko_shadow_stack_trace_ready) return;
    if (env == NULL || ste_cls == NULL || ste_klass == NULL) {
        fprintf(stderr, "[neko-bind] StackTraceElement cache prerequisites unavailable env=%p mirror=%p klass=%p\\n",
            (void*)env, (void*)ste_cls, ste_klass);
        abort();
    }
    neko_ensure_class_initialized(env, ste_cls, "java/lang/StackTraceElement");
    g_neko_shadow_ste_array_klass_bits =
        neko_array_klass_bits_for_descriptor(env, "[Ljava/lang/StackTraceElement;", NULL);
    if (getenv("NEKO_NATIVE_DIAG_FAIL_SHADOW_TRACE_ARRAY_ALLOC") != NULL) {
        g_neko_shadow_ste_array_klass_bits = 0;
    }
    if (g_neko_shadow_ste_array_klass_bits == 0) {
        fprintf(stderr, "[neko-bind] StackTraceElement array direct allocation unavailable\\n");
        abort();
    }
    ctor_method = neko_resolve_method(
        ste_klass,
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");
    if (ctor_method == NULL) {
        fprintf(stderr, "[neko-bind] StackTraceElement.<init> Method* unavailable\\n");
        abort();
    }
    g_neko_shadow_ste_ctor_method = ctor_method;
    g_neko_shadow_ste_ctor_entry = neko_bound_method_i_entry(ctor_method,
        &g_neko_shadow_ste_ctor_entry, "java/lang/StackTraceElement",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");
    if (getenv("NEKO_NATIVE_DIAG_FAIL_SHADOW_STE_CTOR_ENTRY") != NULL) {
        g_neko_shadow_ste_ctor_entry = NULL;
    }
    if (g_neko_shadow_ste_ctor_entry == NULL) {
        fprintf(stderr, "[neko-bind] StackTraceElement.<init> entry unavailable\\n");
        abort();
    }
    g_neko_shadow_stack_trace_ready = JNI_TRUE;
}

static jobjectArray neko_shadow_stack_trace(JNIEnv *env) {
    void *thread = neko_jni_env_to_thread(env);
    void *ste_klass = NULL;
    jclass ste_cls;
    jobjectArray trace;
    void *trace_oop;
    jobjectArray trace_result;
    neko_handle_save_t handle_window;
    uint32_t depth = g_neko_shadow_depth;
    uint32_t count;
    uint32_t i;
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] shadow stack trace has no JavaThread\\n");
        abort();
    }
    neko_handle_window_begin(thread, &handle_window);
    ste_cls = neko_resolve_class_mirror_with_env(env, "java/lang/StackTraceElement", NULL, &ste_klass);
    if (ste_cls == NULL || ste_klass == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] StackTraceElement class unavailable for shadow stack\\n");
        abort();
    }
    neko_ensure_shadow_stack_trace_cache(env, ste_cls, ste_klass);
    count = depth == 0u ? 0u : depth;
    trace = neko_fast_new_object_array(thread, env, (jint)count, g_neko_shadow_ste_array_klass_bits, NULL);
    if (trace == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] StackTraceElement array allocation failed count=%u\\n", count);
        abort();
    }
    for (i = 0u; i < count; i++) {
        neko_shadow_frame *frame = &g_neko_shadow_stack[depth - 1u - i];
        const neko_shadow_frame_desc *desc = frame->desc;
        jvalue args[4];
        jobject element;
        if (desc == NULL) continue;
        element = neko_fast_alloc_object(thread, env, ste_cls);
        if (element == NULL || neko_exception_check(env)) {
            if (neko_exception_check(env)) neko_exception_clear_direct(env);
            fprintf(stderr, "[neko-bind] StackTraceElement allocation failed index=%u\\n", i);
            abort();
        }
        args[0].l = neko_shadow_dotted_string(thread, env, desc->owner);
        args[1].l = neko_shadow_utf_string(thread, env, desc->method);
        args[2].l = neko_shadow_utf_string(thread, env, desc->file);
        args[3].i = -1;
        if (neko_exception_check(env)) {
            neko_exception_clear_direct(env);
            fprintf(stderr, "[neko-bind] StackTraceElement argument preparation failed index=%u\\n", i);
            abort();
        }
        (void)neko_njx_V_V_LLLI(thread, env,
            g_neko_shadow_ste_ctor_method,
            g_neko_shadow_ste_ctor_entry,
            element,
            args);
        if (neko_exception_check(env)) {
            neko_exception_clear_direct(env);
            fprintf(stderr, "[neko-bind] StackTraceElement.<init> failed index=%u\\n", i);
            abort();
        }
        neko_fast_aastore(thread, env, trace, (jint)i, element);
        if (neko_exception_check(env)) {
            neko_exception_clear_direct(env);
            fprintf(stderr, "[neko-bind] StackTraceElement array store failed index=%u\\n", i);
            abort();
        }
    }
    trace_oop = neko_prepare_return_oop(thread, trace, "shadow_stack_trace");
    neko_handle_window_end(&handle_window);
    trace_result = (jobjectArray)neko_handle_push(thread, trace_oop);
    if (trace_result == NULL) {
        fprintf(stderr, "[neko-bind] StackTraceElement array return handle push failed\\n");
        abort();
    }
    return trace_result;
}

/* T3.20: dead helpers (`neko_dotted_class_name`, `neko_load_class_noinit`,
 * `neko_public_lookup`) had no remaining callers and depended on the
 * opcode-side wrappers + the typed function-table macro that were removed in
 * this stage; they are deleted entirely. The remaining helpers
 * (`neko_class_for_descriptor`, `neko_impl_lookup`, `neko_lookup_for_*`,
 * `neko_method_type_from_descriptor`, `neko_bootstrap_parameter_array`,
 * `neko_invoke_bootstrap`) are still emitted by the translator (LDC Class /
 * MethodType, MethodHandles.lookup() intrinsic, CONDY) and must keep working;
 * each function-table call is expanded inline below. */

/* T4.1: primitive descriptor → mirror table.
 *
 * The pre-T4.1 implementation routed each primitive switch arm through a
 * `neko_find_class("java/lang/Boolean") + neko_get_static_field_id("TYPE",
 * "Ljava/lang/Class;") + JNI GetStaticObjectField (index 145) triplet —
 * three JNI function-table indices per LDC, plus dedicated allocation per
 * call site. T4.1 collapses the entire primitive surface into one
 * generic table populated at OnLoad in `neko_primitive_mirror_table_init`
 * (renderHotSpotFastAccessHelpers region):
 *   - Each of Z/B/C/S/I/J/F/D resolves its wrapper InstanceKlass via
 *     `neko_resolve_class` and records (wrapper_klass, TYPE_offset).
 *   - Hot path: read the wrapper's `Klass::_java_mirror` OopHandle,
 *     dereference twice to reach the wrapper Class oop, read TYPE through
 *     compressed-oops decode + GC barrier, push to local handle.
 * Removed function-table indices for this helper: 6=FindClass,
 * 144=GetStaticFieldID, 145=GetStaticObjectField. The L<owner>; and
 * [...] arms route through `neko_resolve_class_mirror_with_env` which
 * already uses libjvm-internal `JVM_FindClassFromBootLoader` /
 * `JVM_FindClassFromClass` symbols (not JNI function-table calls). */
typedef struct {
    void *wrapper_klass;       /* InstanceKlass* of java.lang.{Boolean..Double} */
    uint32_t type_static_offset; /* offset of static TYPE field in the wrapper's Class oop */
    char tag;                   /* descriptor leaf char for diagnostics */
    jboolean ready;             /* set after a successful per-entry init */
} neko_primitive_mirror_entry_t;

static neko_primitive_mirror_entry_t g_neko_primitive_mirror_table[9] = {
    {NULL, 0u, 'Z', JNI_FALSE},
    {NULL, 0u, 'B', JNI_FALSE},
    {NULL, 0u, 'C', JNI_FALSE},
    {NULL, 0u, 'S', JNI_FALSE},
    {NULL, 0u, 'I', JNI_FALSE},
    {NULL, 0u, 'J', JNI_FALSE},
    {NULL, 0u, 'F', JNI_FALSE},
    {NULL, 0u, 'D', JNI_FALSE},
    {NULL, 0u, 'V', JNI_FALSE}
};
static jboolean g_neko_primitive_mirror_ready = JNI_FALSE;

static jclass neko_class_for_descriptor(JNIEnv *env, const char *desc) {
    switch (desc[0]) {
        case 'Z': case 'B': case 'C': case 'S':
        case 'I': case 'J': case 'F': case 'D':
        case 'V':
            return neko_primitive_mirror_for_char(env, desc[0]);
        case 'L': {
            const char *start = desc + 1;
            const char *semi = strchr(start, ';');
            size_t len;
            char *buf;
            jclass out;
            if (semi == NULL) {
                fprintf(stderr, "[neko-bind] malformed L-descriptor missing ';': %s\\n", desc);
                abort();
            }
            len = (size_t)(semi - start);
            buf = (char*)malloc(len + 1u);
            if (buf == NULL) {
                fprintf(stderr, "[neko-bind] L-descriptor buffer alloc failed for %s\\n", desc);
                abort();
            }
            memcpy(buf, start, len); buf[len] = '\\0';
            out = neko_resolve_class_mirror_with_env(env, buf, NULL, NULL);
            free(buf);
            return out;
        }
        case '[':
            return neko_resolve_class_mirror_with_env(env, desc, NULL, NULL);
        default:
            fprintf(stderr, "[neko-bind] unsupported descriptor char '%c' in neko_class_for_descriptor\\n",
                desc[0]);
            abort();
    }
}

/* T4.2c — see renderImplLookup() below for the actual body. Forward
 * declaration here so the in-block neko_lookup_for_jclass call site (a few
 * lines down) resolves. */
static jobject neko_impl_lookup(JNIEnv *env);

static jobject neko_lookup_for_jclass(JNIEnv *env, jclass ownerClass);

static jobject neko_lookup_for_class(JNIEnv *env, const char *owner) {
    jclass ownerClass = neko_resolve_class_mirror_with_env(env, owner, NULL, NULL);
    return neko_lookup_for_jclass(env, ownerClass);
}

static jboolean g_neko_private_lookup_ready = JNI_FALSE;
static void *g_neko_private_lookup_method = NULL;
static void *g_neko_private_lookup_entry = NULL;

static void neko_ensure_private_lookup_cache(JNIEnv *env) {
    jclass mhClass;
    void *mh_klass = NULL;
    void *method;
    if (g_neko_private_lookup_ready) return;
    mhClass = neko_resolve_class_mirror_with_env(env, "java/lang/invoke/MethodHandles", NULL, &mh_klass);
    if (mhClass == NULL || mh_klass == NULL) {
        fprintf(stderr, "[neko-bind] MethodHandles class unavailable for privateLookupIn\\n");
        abort();
    }
    method = neko_resolve_method(
        mh_klass,
        "privateLookupIn",
        "(Ljava/lang/Class;Ljava/lang/invoke/MethodHandles$Lookup;)Ljava/lang/invoke/MethodHandles$Lookup;");
    if (method == NULL) {
        fprintf(stderr, "[neko-bind] MethodHandles.privateLookupIn method unavailable\\n");
        abort();
    }
    g_neko_private_lookup_method = method;
    g_neko_private_lookup_entry = neko_bound_method_i_entry(method,
        &g_neko_private_lookup_entry, "java/lang/invoke/MethodHandles",
        "privateLookupIn",
        "(Ljava/lang/Class;Ljava/lang/invoke/MethodHandles$Lookup;)Ljava/lang/invoke/MethodHandles$Lookup;");
    if (getenv("NEKO_NATIVE_DIAG_FAIL_PRIVATE_LOOKUP_ENTRY") != NULL) {
        g_neko_private_lookup_entry = NULL;
    }
    if (g_neko_private_lookup_entry == NULL) {
        fprintf(stderr, "[neko-bind] MethodHandles.privateLookupIn entry unavailable\\n");
        abort();
    }
    g_neko_private_lookup_ready = JNI_TRUE;
}

static jobject neko_lookup_for_jclass(JNIEnv *env, jclass ownerClass) {
    void *thread = neko_jni_env_to_thread(env);
    jvalue result;
    jvalue args[2];
    if (thread == NULL || ownerClass == NULL) {
        fprintf(stderr, "[neko-bind] privateLookupIn prerequisites unavailable thread=%p owner=%p\\n",
            thread, (void*)ownerClass);
        abort();
    }
    neko_ensure_private_lookup_cache(env);
    args[0].l = ownerClass;
    args[1].l = neko_impl_lookup(env);
    result = neko_njx_S_L_LL(thread, env,
        g_neko_private_lookup_method,
        g_neko_private_lookup_entry,
        NULL,
        args);
    if (neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] MethodHandles.privateLookupIn failed owner=%p\\n", (void*)ownerClass);
        abort();
    }
    return result.l;
}

static jboolean g_neko_method_type_descriptor_ready = JNI_FALSE;
static void *g_neko_method_type_descriptor_method = NULL;
static void *g_neko_method_type_descriptor_entry = NULL;
static jboolean g_neko_method_type_parameter_array_ready = JNI_FALSE;
static void *g_neko_method_type_parameter_array_method = NULL;
static void *g_neko_method_type_parameter_array_entry = NULL;
static jboolean g_neko_bootstrap_invoke_ready = JNI_FALSE;
static void *g_neko_bootstrap_get_declared_method_method = NULL;
static void *g_neko_bootstrap_get_declared_method_entry = NULL;
static void *g_neko_bootstrap_set_accessible_method = NULL;
static void *g_neko_bootstrap_set_accessible_entry = NULL;
static void *g_neko_bootstrap_method_invoke_method = NULL;
static void *g_neko_bootstrap_method_invoke_entry = NULL;

static void neko_ensure_method_type_descriptor_cache(JNIEnv *env) {
    void *mt_klass = NULL;
    jclass mtClass;
    void *method;
    if (g_neko_method_type_descriptor_ready) return;
    if (env == NULL) {
        fprintf(stderr, "[neko-bind] MethodType descriptor cache requires JNIEnv*\\n");
        abort();
    }
    mtClass = neko_resolve_class_mirror_with_env(env, "java/lang/invoke/MethodType", NULL, &mt_klass);
    if (mtClass == NULL || mt_klass == NULL) {
        fprintf(stderr, "[neko-bind] MethodType class unavailable for descriptor cache mirror=%p klass=%p\\n",
            (void*)mtClass, mt_klass);
        abort();
    }
    neko_ensure_class_initialized(env, mtClass, "java/lang/invoke/MethodType");
    method = neko_resolve_method(mt_klass, "fromMethodDescriptorString",
        "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/invoke/MethodType;");
    if (method == NULL) {
        fprintf(stderr, "[neko-bind] MethodType.fromMethodDescriptorString Method* unavailable\\n");
        abort();
    }
    g_neko_method_type_descriptor_method = method;
    g_neko_method_type_descriptor_entry = neko_bound_method_i_entry(method,
        &g_neko_method_type_descriptor_entry, "java/lang/invoke/MethodType",
        "fromMethodDescriptorString",
        "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/invoke/MethodType;");
    if (getenv("NEKO_NATIVE_DIAG_FAIL_METHODTYPE_DESCRIPTOR_ENTRY") != NULL) {
        g_neko_method_type_descriptor_entry = NULL;
    }
    if (g_neko_method_type_descriptor_entry == NULL) {
        fprintf(stderr, "[neko-bind] MethodType.fromMethodDescriptorString entry unavailable\\n");
        abort();
    }
    g_neko_method_type_descriptor_ready = JNI_TRUE;
}

static void neko_ensure_method_type_parameter_array_cache(JNIEnv *env) {
    void *mt_klass = NULL;
    jclass mtClass;
    void *method;
    if (g_neko_method_type_parameter_array_ready) return;
    if (env == NULL) {
        fprintf(stderr, "[neko-bind] MethodType.parameterArray cache requires JNIEnv*\\n");
        abort();
    }
    mtClass = neko_resolve_class_mirror_with_env(env, "java/lang/invoke/MethodType", NULL, &mt_klass);
    if (mtClass == NULL || mt_klass == NULL) {
        fprintf(stderr, "[neko-bind] MethodType class unavailable for parameterArray cache mirror=%p klass=%p\\n",
            (void*)mtClass, mt_klass);
        abort();
    }
    neko_ensure_class_initialized(env, mtClass, "java/lang/invoke/MethodType");
    method = neko_resolve_method(mt_klass, "parameterArray", "()[Ljava/lang/Class;");
    if (method == NULL) {
        fprintf(stderr, "[neko-bind] MethodType.parameterArray Method* unavailable\\n");
        abort();
    }
    g_neko_method_type_parameter_array_method = method;
    g_neko_method_type_parameter_array_entry = neko_bound_method_i_entry(method,
        &g_neko_method_type_parameter_array_entry, "java/lang/invoke/MethodType",
        "parameterArray", "()[Ljava/lang/Class;");
    if (getenv("NEKO_NATIVE_DIAG_FAIL_METHODTYPE_PARAMETER_ARRAY_ENTRY") != NULL) {
        g_neko_method_type_parameter_array_entry = NULL;
    }
    if (g_neko_method_type_parameter_array_entry == NULL) {
        fprintf(stderr, "[neko-bind] MethodType.parameterArray entry unavailable\\n");
        abort();
    }
    g_neko_method_type_parameter_array_ready = JNI_TRUE;
}

static void neko_ensure_bootstrap_invoke_cache(JNIEnv *env) {
    void *class_klass = NULL;
    void *accessible_klass = NULL;
    void *method_klass = NULL;
    jclass classClass;
    jclass accessibleClass;
    jclass methodClass;
    void *method;
    if (g_neko_bootstrap_invoke_ready) return;
    if (env == NULL) {
        fprintf(stderr, "[neko-bind] bootstrap invocation cache requires JNIEnv*\\n");
        abort();
    }

    classClass = neko_resolve_class_mirror_with_env(env, "java/lang/Class", NULL, &class_klass);
    if (classClass == NULL || class_klass == NULL) {
        fprintf(stderr, "[neko-bind] Class mirror unavailable for bootstrap invocation cache mirror=%p klass=%p\\n",
            (void*)classClass, class_klass);
        abort();
    }
    neko_ensure_class_initialized(env, classClass, "java/lang/Class");
    method = neko_resolve_method(class_klass, "getDeclaredMethod",
        "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    if (method == NULL) {
        fprintf(stderr, "[neko-bind] Class.getDeclaredMethod Method* unavailable\\n");
        abort();
    }
    g_neko_bootstrap_get_declared_method_method = method;
    g_neko_bootstrap_get_declared_method_entry = neko_bound_method_i_entry(method,
        &g_neko_bootstrap_get_declared_method_entry, "java/lang/Class",
        "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    if (getenv("NEKO_NATIVE_DIAG_FAIL_BOOTSTRAP_GET_DECLARED_METHOD_ENTRY") != NULL) {
        g_neko_bootstrap_get_declared_method_entry = NULL;
    }
    if (g_neko_bootstrap_get_declared_method_entry == NULL) {
        fprintf(stderr, "[neko-bind] Bootstrap Class.getDeclaredMethod entry unavailable\\n");
        abort();
    }

    accessibleClass = neko_resolve_class_mirror_with_env(env, "java/lang/reflect/AccessibleObject", NULL, &accessible_klass);
    if (accessibleClass == NULL || accessible_klass == NULL) {
        fprintf(stderr, "[neko-bind] AccessibleObject mirror unavailable for bootstrap invocation cache mirror=%p klass=%p\\n",
            (void*)accessibleClass, accessible_klass);
        abort();
    }
    neko_ensure_class_initialized(env, accessibleClass, "java/lang/reflect/AccessibleObject");
    method = neko_resolve_method(accessible_klass, "setAccessible", "(Z)V");
    if (method == NULL) {
        fprintf(stderr, "[neko-bind] AccessibleObject.setAccessible Method* unavailable\\n");
        abort();
    }
    g_neko_bootstrap_set_accessible_method = method;
    g_neko_bootstrap_set_accessible_entry = neko_bound_method_i_entry(method,
        &g_neko_bootstrap_set_accessible_entry, "java/lang/reflect/AccessibleObject",
        "setAccessible", "(Z)V");
    if (getenv("NEKO_NATIVE_DIAG_FAIL_BOOTSTRAP_SET_ACCESSIBLE_ENTRY") != NULL) {
        g_neko_bootstrap_set_accessible_entry = NULL;
    }
    if (g_neko_bootstrap_set_accessible_entry == NULL) {
        fprintf(stderr, "[neko-bind] Bootstrap AccessibleObject.setAccessible entry unavailable\\n");
        abort();
    }

    methodClass = neko_resolve_class_mirror_with_env(env, "java/lang/reflect/Method", NULL, &method_klass);
    if (methodClass == NULL || method_klass == NULL) {
        fprintf(stderr, "[neko-bind] Method mirror unavailable for bootstrap invocation cache mirror=%p klass=%p\\n",
            (void*)methodClass, method_klass);
        abort();
    }
    neko_ensure_class_initialized(env, methodClass, "java/lang/reflect/Method");
    method = neko_resolve_method(method_klass, "invoke",
        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    if (method == NULL) {
        fprintf(stderr, "[neko-bind] Method.invoke Method* unavailable\\n");
        abort();
    }
    g_neko_bootstrap_method_invoke_method = method;
    g_neko_bootstrap_method_invoke_entry = neko_bound_method_i_entry(method,
        &g_neko_bootstrap_method_invoke_entry, "java/lang/reflect/Method",
        "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    if (getenv("NEKO_NATIVE_DIAG_FAIL_BOOTSTRAP_METHOD_INVOKE_ENTRY") != NULL) {
        g_neko_bootstrap_method_invoke_entry = NULL;
    }
    if (g_neko_bootstrap_method_invoke_entry == NULL) {
        fprintf(stderr, "[neko-bind] Bootstrap Method.invoke entry unavailable\\n");
        abort();
    }

    g_neko_bootstrap_invoke_ready = JNI_TRUE;
}

static jobject neko_method_type_from_descriptor(JNIEnv *env, const char *desc) {
    jvalue args[2];
    jvalue result;
    void *thread;
    void *desc_oop;
    jobject desc_ref;
    if (env == NULL || desc == NULL) {
        fprintf(stderr, "[neko-bind] MethodType descriptor invocation requires env=%p desc=%p\\n",
            (void*)env, (const void*)desc);
        abort();
    }
    neko_ensure_method_type_descriptor_cache(env);
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] MethodType descriptor invocation has no JavaThread\\n");
        abort();
    }
    desc_oop = neko_intern_string(thread, env, (const uint8_t*)desc, strlen(desc));
    if (desc_oop == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] MethodType descriptor string intern failed desc=%s\\n", desc);
        abort();
    }
    desc_ref = (jobject)neko_handle_push(thread, desc_oop);
    if (desc_ref == NULL) {
        fprintf(stderr, "[neko-bind] MethodType descriptor handle push failed desc=%s\\n", desc);
        abort();
    }
    args[0].l = desc_ref;
    args[1].l = NULL;
    result = neko_njx_S_L_LL(thread, env,
        g_neko_method_type_descriptor_method,
        g_neko_method_type_descriptor_entry,
        NULL, args);
    if (result.l == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] MethodType.fromMethodDescriptorString failed desc=%s\\n", desc);
        abort();
    }
    return result.l;
}

static jobjectArray neko_bootstrap_parameter_array(JNIEnv *env, const char *bsm_desc) {
    jobject mt = neko_method_type_from_descriptor(env, bsm_desc);
    jvalue result;
    void *thread;
    if (env == NULL || bsm_desc == NULL) {
        fprintf(stderr, "[neko-bind] MethodType.parameterArray requires env=%p desc=%p\\n",
            (void*)env, (const void*)bsm_desc);
        abort();
    }
    if (mt == NULL) {
        fprintf(stderr, "[neko-bind] MethodType.parameterArray received null MethodType desc=%s\\n", bsm_desc);
        abort();
    }
    neko_ensure_method_type_parameter_array_cache(env);
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] MethodType.parameterArray has no JavaThread\\n");
        abort();
    }
    result = neko_njx_V_L_(thread, env,
        g_neko_method_type_parameter_array_method,
        g_neko_method_type_parameter_array_entry,
        mt, NULL);
    if (result.l == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] MethodType.parameterArray failed desc=%s\\n", bsm_desc);
        abort();
    }
    return (jobjectArray)result.l;
}

static jobject neko_invoke_bootstrap(JNIEnv *env, const char *bsm_owner, const char *bsm_name, const char *bsm_desc, jobjectArray invoke_args) {
    jclass bsmClass;
    jobjectArray paramTypes;
    jvalue getArgs[2];
    jvalue result;
    jvalue accessibleArgs[1];
    jvalue invokeArgs[2];
    void *thread;
    void *name_oop;
    jobject name_ref;
    jobject method;
    if (env == NULL || bsm_owner == NULL || bsm_name == NULL || bsm_desc == NULL) {
        fprintf(stderr, "[neko-bind] bootstrap invocation requires env=%p owner=%p name=%p desc=%p\\n",
            (void*)env, (const void*)bsm_owner, (const void*)bsm_name, (const void*)bsm_desc);
        abort();
    }
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] bootstrap invocation has no JavaThread\\n");
        abort();
    }
    bsmClass = neko_resolve_class_mirror_with_env(env, bsm_owner, NULL, NULL);
    if (bsmClass == NULL) {
        fprintf(stderr, "[neko-bind] bootstrap owner class unavailable owner=%s\\n", bsm_owner);
        abort();
    }
    paramTypes = neko_bootstrap_parameter_array(env, bsm_desc);
    if (paramTypes == NULL) {
        fprintf(stderr, "[neko-bind] bootstrap parameter array unavailable desc=%s\\n", bsm_desc);
        abort();
    }
    neko_ensure_bootstrap_invoke_cache(env);
    name_oop = neko_intern_string(thread, env, (const uint8_t*)bsm_name, strlen(bsm_name));
    if (name_oop == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] bootstrap method-name intern failed name=%s\\n", bsm_name);
        abort();
    }
    name_ref = (jobject)neko_handle_push(thread, name_oop);
    if (name_ref == NULL) {
        fprintf(stderr, "[neko-bind] bootstrap method-name handle push failed name=%s\\n", bsm_name);
        abort();
    }
    getArgs[0].l = name_ref;
    getArgs[1].l = paramTypes;
    result = neko_njx_V_L_LL(thread, env,
        g_neko_bootstrap_get_declared_method_method,
        g_neko_bootstrap_get_declared_method_entry,
        bsmClass, getArgs);
    if (result.l == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] bootstrap getDeclaredMethod failed owner=%s name=%s desc=%s\\n",
            bsm_owner, bsm_name, bsm_desc);
        abort();
    }
    method = result.l;
    accessibleArgs[0].i = (jint)JNI_TRUE;
    (void)neko_njx_V_V_I(thread, env,
        g_neko_bootstrap_set_accessible_method,
        g_neko_bootstrap_set_accessible_entry,
        method, accessibleArgs);
    if (neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] bootstrap setAccessible failed owner=%s name=%s desc=%s\\n",
            bsm_owner, bsm_name, bsm_desc);
        abort();
    }
    invokeArgs[0].l = NULL;
    invokeArgs[1].l = invoke_args;
    result = neko_njx_V_L_LL(thread, env,
        g_neko_bootstrap_method_invoke_method,
        g_neko_bootstrap_method_invoke_entry,
        method, invokeArgs);
    if (neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] bootstrap Method.invoke failed owner=%s name=%s desc=%s\\n",
            bsm_owner, bsm_name, bsm_desc);
        abort();
    }
    return result.l;
}

static jstring neko_string_null(JNIEnv *env) {
    static jstring g_str_null = NULL;
    return NEKO_ENSURE_STRING(g_str_null, env, "null");
}

static jobjectArray neko_condy_new_object_array(void *thread, JNIEnv *env, jint len) {
    uintptr_t objectArrayKlassBits;
    if (thread == NULL || env == NULL || len < 0) {
        fprintf(stderr, "[neko-bind] invalid ConstantDynamic Object[] allocation len=%d thread=%p env=%p\\n",
            (int)len, thread, (void*)env);
        abort();
    }
    if (getenv("NEKO_NATIVE_DIAG_FAIL_CONDY_OBJ_ARRAY_ALLOC") != NULL) {
        fprintf(stderr, "[neko-bind] ConstantDynamic object-array direct allocation unavailable\\n");
        abort();
    }
    objectArrayKlassBits = neko_array_klass_bits_for_descriptor(env, "[Ljava/lang/Object;", NULL);
    if (objectArrayKlassBits == 0) {
        fprintf(stderr, "[neko-bind] ConstantDynamic Object[] klass bits unavailable\\n");
        abort();
    }
    return neko_fast_new_object_array(thread, env, len, objectArrayKlassBits, NULL);
}

/* T3.20: the legacy StringBuilder-style concat helpers (`_concat2` /
 * `_concat_string`) became unreachable from the translator after T3.19
 * (`neko_require_fast_string_concat` covers every recipe), referenced the
 * removed typed function-table macro plus the Call*MethodA dispatch entries,
 * and are now deleted entirely.
 *
 * `neko_resolve_constant_dynamic` still feeds the LDC ConstantDynamic path
 * through bootstrap-method invocation; the argument array is built through
 * HotSpot allocation plus the same barrier-aware array helpers used by
 * translated AALOAD/AASTORE. */
static jobject neko_resolve_constant_dynamic(JNIEnv *env, const char *caller_owner, const char *name, const char *desc, const char *bsm_owner, const char *bsm_name, const char *bsm_desc, jobjectArray static_args) {
    void *thread = neko_jni_env_to_thread(env);
    jobjectArray paramTypes = neko_bootstrap_parameter_array(env, bsm_desc);
    jsize paramCount = neko_fast_array_length((jarray)paramTypes);
    void *nameOop;
    jobject nameHandle;
    jobjectArray invokeArgs;
    if (thread == NULL || name == NULL) {
        fprintf(stderr, "[neko-bind] ConstantDynamic thread/name unavailable thread=%p name=%p\\n",
            thread, (const void*)name);
        abort();
    }
    invokeArgs = neko_condy_new_object_array(thread, env, paramCount);
    nameOop = neko_intern_string(thread, env, (const uint8_t*)name, strlen(name));
    if (nameOop == NULL) {
        fprintf(stderr, "[neko-bind] ConstantDynamic name intern failed name=%s\\n", name);
        abort();
    }
    nameHandle = (jobject)neko_handle_push(thread, nameOop);
    neko_fast_aastore(thread, env, invokeArgs, 0, neko_lookup_for_class(env, caller_owner));
    neko_fast_aastore(thread, env, invokeArgs, 1, nameHandle);
    neko_fast_aastore(thread, env, invokeArgs, 2, neko_class_for_descriptor(env, desc));
    {
        jsize static_count = static_args == NULL ? 0 : neko_fast_array_length((jarray)static_args);
        for (jsize i = 0; i < static_count; i++) {
            jobject element = neko_fast_aaload(thread, env, static_args, i);
            neko_fast_aastore(thread, env, invokeArgs, i + 3, element);
        }
    }
    return neko_invoke_bootstrap(env, bsm_owner, bsm_name, bsm_desc, invokeArgs);
}

static int neko_primitive_kind_from_descriptor_char(char leaf) {
    switch (leaf) {
        case 'Z': return 0;
        case 'B': return 1;
        case 'C': return 2;
        case 'S': return 3;
        case 'I': return 4;
        case 'J': return 5;
        case 'F': return 6;
        case 'D': return 7;
        default: return -1;
    }
}

static int neko_primitive_mirror_kind_from_descriptor_char(char leaf) {
    switch (leaf) {
        case 'Z': return 0;
        case 'B': return 1;
        case 'C': return 2;
        case 'S': return 3;
        case 'I': return 4;
        case 'J': return 5;
        case 'F': return 6;
        case 'D': return 7;
        case 'V': return 8;
        default: return -1;
    }
}

static jobject neko_multi_new_array(void *thread, JNIEnv *env, jint num_dims, jint *dims, const char *desc, jclass fromClass) {
    if (num_dims <= 0 || dims == NULL || desc == NULL || desc[0] != '[') {
        fprintf(stderr, "[neko-direct] MULTIANEWARRAY invalid input dims=%d desc=%s\\n",
            (int)num_dims, desc == NULL ? "<null>" : desc);
        abort();
    }
    if (dims[0] < 0) {
        fprintf(stderr, "[neko-direct] MULTIANEWARRAY negative length %d desc=%s\\n",
            (int)dims[0], desc);
        abort();
    }
    if (num_dims == 1) {
        char leaf = desc[1];
        int kind = neko_primitive_kind_from_descriptor_char(leaf);
        if (kind >= 0) {
            return (jobject)neko_fast_new_primitive_array(thread, env, dims[0], kind);
        }
        return (jobject)neko_fast_new_object_array(
            thread, env, dims[0], neko_array_klass_bits_for_descriptor(env, desc, fromClass), NULL);
    }
    jobjectArray arr = (jobjectArray)neko_fast_new_object_array(
        thread, env, dims[0], neko_array_klass_bits_for_descriptor(env, desc, fromClass), NULL);
    for (jint i = 0; i < dims[0]; i++) {
        jobject sub = neko_multi_new_array(thread, env, num_dims - 1, dims + 1, desc + 1, fromClass);
        neko_fast_aastore(thread, env, arr, i, sub);
    }
    return (jobject)arr;
}

""";
    }

    static String renderHotSpotSupport() {
        return """
typedef enum {
    NEKO_COOP_MODE_UNKNOWN = 0,
    NEKO_COOP_MODE_DISABLED = 1,
    NEKO_COOP_MODE_ZERO_BASED = 2,
    NEKO_COOP_MODE_HEAP_BASED = 3
} neko_coop_encoded_mode;

enum {
    NEKO_PRIM_Z = 0,
    NEKO_PRIM_B = 1,
    NEKO_PRIM_C = 2,
    NEKO_PRIM_S = 3,
    NEKO_PRIM_I = 4,
    NEKO_PRIM_J = 5,
    NEKO_PRIM_F = 6,
    NEKO_PRIM_D = 7,
    NEKO_PRIM_COUNT = 8
};

enum {
    NEKO_HOTSPOT_FAST_RAW_HEAP = 1ll << 16,
    NEKO_HOTSPOT_FAST_ARRAY_LAYOUT = 1ll << 18,
    NEKO_HOTSPOT_FAST_HANDLE_TAGS = 1ll << 19,
    NEKO_HOTSPOT_FAST_FIELD_HELPERS = 1ll << 20,
    NEKO_FAST_RECEIVER_KEY = 0x10ll,
    NEKO_FAST_PRIM_FIELD = 0x4ll,
    NEKO_FAST_PRIM_ARRAY = 0x8ll
};

enum {
    NEKO_EARLY_GC_BARRIER_CARDTABLE = 1,
    NEKO_EARLY_GC_BARRIER_G1 = 2,
    NEKO_EARLY_GC_BARRIER_Z = 3,
    NEKO_EARLY_GC_BARRIER_SHENANDOAH = 4
};

typedef struct {
    jboolean initialized;
    jint address_size;
    jboolean compressed_oops_enabled;
    jint compressed_oops_shift;
    jlong compressed_oops_base;
    jboolean compressed_klass_ptrs;
    jboolean use_compact_object_headers;
    jint coop_encoded_mode;
    jint primitive_array_base_offsets[NEKO_PRIM_COUNT];
    jint primitive_array_index_scales[NEKO_PRIM_COUNT];
    uintptr_t primitive_array_klass_bits[NEKO_PRIM_COUNT];
    jint array_length_offset;
    jlong fast_bits;
    jboolean is_hotspot;
    jboolean use_zgc;
    jboolean use_shenandoah_gc;
    uintptr_t z_address_offset_mask;
    uintptr_t z_pointer_load_good_mask;
    uintptr_t z_pointer_load_bad_mask;
    uintptr_t z_pointer_store_good_mask;
    uintptr_t z_pointer_store_bad_mask;
    size_t z_pointer_load_shift;
    /* Live mask pointers for the inline ZGC barrier (T0.2 partial). The
     * MethodPatcherEmitter publishes these at OnLoad so the inline path
     * can read fresh values per call without depending on dlsym'd
     * libjvm symbols. NULL when ZGC is not in use or when the layout
     * isn't published. */
    void *z_zglobals_addr_mask_p;
    void *z_zglobals_load_bad_mask_p;
    void *z_zglobals_load_good_mask_p;
    void *z_zglobals_store_good_mask_p;
    void *z_zglobals_store_bad_mask_p;
    jint object_alignment_in_bytes;
    /*
     * Receiver-key scaffold state is appended so existing field offsets stay
     * unchanged for T1-T4 fast paths. klass_offset_bytes is derived from the
     * object-header mark word width (4 bytes on 32-bit, 8 bytes on 64-bit).
     */
    jboolean use_compressed_klass_ptrs;
    jint klass_offset_bytes;
} neko_hotspot_state;

static neko_hotspot_state g_hotspot;
/* Frozen snapshot. Storage is mutable (writable .bss) so the freeze memcpy
 * works on platforms that put `static const` into .rodata. Hot-path reads go
 * through the const-typed alias declared in renderHotSpotFastAccessHelpers
 * so the optimizer treats them as const for CSE. */
__attribute__((aligned(64))) static neko_hotspot_state g_hotspot_const_storage;
static uintptr_t g_neko_handle_sample_oop = 0;

static jlong neko_native_instance_field_offset(JNIEnv *env, jclass cls, const char *name, const char *desc);
static jlong neko_native_static_field_offset(JNIEnv *env, jclass cls, const char *name, const char *desc);
static void neko_select_oop_field_load_barrier(void);
static void neko_select_oop_array_load_barrier(void);
static void neko_select_oop_field_store_barrier(void);

static const char* neko_hotspot_primitive_name(int kind) {
    switch (kind) {
        case NEKO_PRIM_Z: return "boolean";
        case NEKO_PRIM_B: return "byte";
        case NEKO_PRIM_C: return "char";
        case NEKO_PRIM_S: return "short";
        case NEKO_PRIM_I: return "int";
        case NEKO_PRIM_J: return "long";
        case NEKO_PRIM_F: return "float";
        case NEKO_PRIM_D: return "double";
        default: return NULL;
    }
}

static const char* neko_hotspot_primitive_array_descriptor(int kind) {
    switch (kind) {
        case NEKO_PRIM_Z: return "[Z";
        case NEKO_PRIM_B: return "[B";
        case NEKO_PRIM_C: return "[C";
        case NEKO_PRIM_S: return "[S";
        case NEKO_PRIM_I: return "[I";
        case NEKO_PRIM_J: return "[J";
        case NEKO_PRIM_F: return "[F";
        case NEKO_PRIM_D: return "[D";
        default: return NULL;
    }
}

static jint neko_hotspot_primitive_scale(int kind) {
    switch (kind) {
        case NEKO_PRIM_Z:
        case NEKO_PRIM_B:
            return 1;
        case NEKO_PRIM_C:
        case NEKO_PRIM_S:
            return 2;
        case NEKO_PRIM_I:
        case NEKO_PRIM_F:
            return 4;
        case NEKO_PRIM_J:
        case NEKO_PRIM_D:
            return 8;
        default:
            return 0;
    }
}

static size_t neko_hotspot_align_up_size(size_t value, size_t alignment) {
    if (alignment == 0 || (alignment & (alignment - 1u)) != 0) {
        fprintf(stderr, "[neko-hotspot] invalid alignment %zu\\n", alignment);
        abort();
    }
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static jint neko_hotspot_array_base_offset_for(const neko_hotspot_state *state, int kind) {
    size_t heap_word = sizeof(void*);
    size_t length_offset;
    size_t header_bytes;
    size_t header_words;
    if (state == NULL || state->klass_offset_bytes <= 0) return -1;
    length_offset = state->use_compressed_klass_ptrs
        ? (size_t)state->klass_offset_bytes + sizeof(uint32_t)
        : (size_t)state->klass_offset_bytes + sizeof(void*);
    header_bytes = neko_hotspot_align_up_size(length_offset + sizeof(jint), heap_word);
    header_words = header_bytes / heap_word;
    if (kind == NEKO_PRIM_J || kind == NEKO_PRIM_D) {
        size_t words_per_long = (sizeof(jlong) + heap_word - 1u) / heap_word;
        header_words = neko_hotspot_align_up_size(header_words, words_per_long);
    }
    return (jint)(header_words * heap_word);
}

static uintptr_t neko_hotspot_klass_header_bits_for(const neko_hotspot_state *state, void *klass) {
    uintptr_t base;
    int shift;
    if (state == NULL || klass == NULL) return 0;
    if (state->use_compressed_klass_ptrs) {
        if (g_neko_addr_compressed_klass_base == NULL
            || g_neko_addr_compressed_klass_shift == NULL) {
            fprintf(stderr, "[neko-hotspot] compressed Klass VMStructs unavailable\\n");
            abort();
        }
        base = (uintptr_t)(*(void**)g_neko_addr_compressed_klass_base);
        shift = *(int*)g_neko_addr_compressed_klass_shift;
        if (shift < 0 || shift > 31 || (uintptr_t)klass < base) {
            fprintf(stderr, "[neko-hotspot] invalid compressed Klass encoding klass=%p base=%p shift=%d\\n",
                klass, (void*)base, shift);
            abort();
        }
        return (uintptr_t)(((uintptr_t)klass - base) >> shift);
    }
    return (uintptr_t)klass;
}

static void neko_hotspot_abort_missing(const char *what) {
    fprintf(stderr, "[neko-hotspot] required native HotSpot layout missing: %s\\n",
        what != NULL ? what : "unknown");
    abort();
}

static void neko_hotspot_init(JNIEnv *env) {
    neko_hotspot_state state;
    jlong fastBits = 0;
    jboolean arraysOk = JNI_TRUE;
    jboolean fieldHelpersOk = JNI_FALSE;
    if (g_hotspot.initialized) return;
    memset(&state, 0, sizeof(state));
    if (env == NULL) neko_hotspot_abort_missing("JNIEnv anchor");
    if (!g_neko_native_resolution_ready) neko_hotspot_abort_missing("native resolution layout");
    if (g_neko_addr_compressed_oops_base == NULL
        || g_neko_addr_compressed_oops_shift == NULL) {
        neko_hotspot_abort_missing("CompressedOops VMStructs");
    }
    if (g_neko_addr_compressed_klass_base == NULL
        || g_neko_addr_compressed_klass_shift == NULL) {
        neko_hotspot_abort_missing("CompressedKlassPointers VMStructs");
    }

    state.is_hotspot = JNI_TRUE;
    state.address_size = (jint)sizeof(void*);
    state.compressed_oops_enabled = JNI_TRUE;
    state.compressed_oops_shift = *(int*)g_neko_addr_compressed_oops_shift;
    state.compressed_oops_base = (jlong)(uintptr_t)(*(void**)g_neko_addr_compressed_oops_base);
    if (state.compressed_oops_shift < 0 || state.compressed_oops_shift > 31) {
        neko_hotspot_abort_missing("valid CompressedOops shift");
    }
    state.coop_encoded_mode = state.compressed_oops_base == 0
        ? (state.compressed_oops_shift == 0 ? NEKO_COOP_MODE_ZERO_BASED : NEKO_COOP_MODE_ZERO_BASED)
        : NEKO_COOP_MODE_HEAP_BASED;
    state.object_alignment_in_bytes = state.compressed_oops_shift >= 3
        ? (jint)(1u << state.compressed_oops_shift)
        : 8;
    state.compressed_klass_ptrs = sizeof(void*) == 8 ? JNI_TRUE : JNI_FALSE;
    state.use_compressed_klass_ptrs = state.compressed_klass_ptrs;
    state.klass_offset_bytes = (jint)sizeof(void*);
    state.use_zgc = g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_Z ? JNI_TRUE : JNI_FALSE;
    state.use_shenandoah_gc = g_neko_gc_barrier_kind == NEKO_EARLY_GC_BARRIER_SHENANDOAH ? JNI_TRUE : JNI_FALSE;
    if (state.use_zgc) {
        state.compressed_oops_enabled = JNI_FALSE;
        state.compressed_oops_shift = 0;
        state.compressed_oops_base = 0;
        state.coop_encoded_mode = NEKO_COOP_MODE_ZERO_BASED;
    }
    neko_select_oop_field_load_barrier();
    neko_select_oop_array_load_barrier();
    neko_select_oop_field_store_barrier();

    for (int i = 0; i < NEKO_PRIM_COUNT; i++) {
        jint baseOffset;
        jint indexScale;
        if (neko_hotspot_primitive_name(i) == NULL) neko_hotspot_abort_missing("primitive kind name");
        baseOffset = neko_hotspot_array_base_offset_for(&state, i);
        indexScale = neko_hotspot_primitive_scale(i);
        state.primitive_array_base_offsets[i] = baseOffset;
        state.primitive_array_index_scales[i] = indexScale;
        if (baseOffset < 0 || indexScale <= 0) arraysOk = JNI_FALSE;
    }

    {
        jclass integerClass = neko_resolve_class_mirror_with_env(env, "java/lang/Integer", NULL, NULL);
        jlong instanceOffset;
        jlong staticOffset;
        if (integerClass == NULL) neko_hotspot_abort_missing("java/lang/Integer mirror");
        instanceOffset = neko_native_instance_field_offset(env, integerClass, "value", "I");
        staticOffset = neko_native_static_field_offset(env, integerClass, "TYPE", "Ljava/lang/Class;");
        fieldHelpersOk = (instanceOffset >= 0 && staticOffset >= 0) ? JNI_TRUE : JNI_FALSE;
        if (state.address_size == 8) {
            if (instanceOffset == 12) {
                state.use_compressed_klass_ptrs = JNI_TRUE;
                state.compressed_klass_ptrs = JNI_TRUE;
            } else if (instanceOffset >= 16) {
                state.use_compressed_klass_ptrs = JNI_FALSE;
                state.compressed_klass_ptrs = JNI_FALSE;
            }
        }
    }

    for (int i = 0; i < NEKO_PRIM_COUNT; i++) {
        state.primitive_array_base_offsets[i] = neko_hotspot_array_base_offset_for(&state, i);
    }
    state.array_length_offset = state.primitive_array_base_offsets[NEKO_PRIM_I] - (jint)sizeof(jint);
    if (state.array_length_offset < 0) arraysOk = JNI_FALSE;

    for (int i = 0; i < NEKO_PRIM_COUNT; i++) {
        const char *arrayDesc = neko_hotspot_primitive_array_descriptor(i);
        void *arrayKlass = NULL;
        if (arrayDesc == NULL) neko_hotspot_abort_missing("primitive array descriptor");
        (void)neko_resolve_class_mirror_with_env(env, arrayDesc, NULL, &arrayKlass);
        if (arrayKlass == NULL) {
            arraysOk = JNI_FALSE;
            continue;
        }
        state.primitive_array_klass_bits[i] = neko_hotspot_klass_header_bits_for(&state, arrayKlass);
    }

    fastBits |= NEKO_HOTSPOT_FAST_HANDLE_TAGS;

    if (arraysOk) fastBits |= NEKO_HOTSPOT_FAST_ARRAY_LAYOUT;
    if (fieldHelpersOk) fastBits |= NEKO_HOTSPOT_FAST_FIELD_HELPERS;
    if ((fastBits & NEKO_HOTSPOT_FAST_HANDLE_TAGS) != 0u && arraysOk && fieldHelpersOk
        && !state.use_zgc && !state.use_shenandoah_gc) {
        fastBits |= NEKO_HOTSPOT_FAST_RAW_HEAP;
    }

    if ((fastBits & NEKO_HOTSPOT_FAST_RAW_HEAP) != 0 && !state.use_compact_object_headers) {
        if (fieldHelpersOk) fastBits |= NEKO_FAST_PRIM_FIELD;
        if (arraysOk) fastBits |= NEKO_FAST_PRIM_ARRAY;
        if (state.klass_offset_bytes > 0) fastBits |= NEKO_FAST_RECEIVER_KEY;
    }

    /*
     * Compact object headers change where klass metadata lives, so any future
     * receiver-key extraction or raw heap layout shortcut must stay disabled.
     */
    if (state.use_compact_object_headers) fastBits = 0;

    state.fast_bits = fastBits;
    state.initialized = JNI_TRUE;
    /* Preserve ZGC masks that neko_method_layout_init already published to
     * g_hotspot. neko_hotspot_init's `g_hotspot = state` would otherwise
     * zero them out before direct-oop recognition/barrier helpers can use
     * them under raw-disabled collectors. Live pointer fields remain stable
     * while the pointed-to mask values can change per ZGC cycle. */
    state.z_address_offset_mask = g_hotspot.z_address_offset_mask;
    state.z_pointer_load_good_mask = g_hotspot.z_pointer_load_good_mask;
    state.z_pointer_load_bad_mask = g_hotspot.z_pointer_load_bad_mask;
    state.z_pointer_store_good_mask = g_hotspot.z_pointer_store_good_mask;
    state.z_pointer_store_bad_mask = g_hotspot.z_pointer_store_bad_mask;
    state.z_pointer_load_shift = g_hotspot.z_pointer_load_shift;
    state.z_zglobals_addr_mask_p = g_hotspot.z_zglobals_addr_mask_p;
    state.z_zglobals_load_bad_mask_p = g_hotspot.z_zglobals_load_bad_mask_p;
    state.z_zglobals_load_good_mask_p = g_hotspot.z_zglobals_load_good_mask_p;
    state.z_zglobals_store_good_mask_p = g_hotspot.z_zglobals_store_good_mask_p;
    state.z_zglobals_store_bad_mask_p = g_hotspot.z_zglobals_store_bad_mask_p;
    g_hotspot = state;
    /* Publish the frozen snapshot for hot-path reads. After this memcpy,
     * the const-aliased view (g_hotspot_const) used by neko_const_*
     * accessors observes a value that never changes again. */
    __builtin_memcpy(&g_hotspot_const_storage, &g_hotspot, sizeof(neko_hotspot_state));
    return;
}

""";
    }

}
