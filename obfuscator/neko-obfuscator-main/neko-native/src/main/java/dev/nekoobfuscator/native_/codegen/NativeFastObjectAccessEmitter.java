package dev.nekoobfuscator.native_.codegen;

/**
 * Emits object allocation, object-array, object-field, and fused AALOAD helpers.
 */
final class NativeFastObjectAccessEmitter {
    private NativeFastObjectAccessEmitter() {}

    /**
     * Emit fast paths for AALOAD / AASTORE that avoid the per-element JNI
     * GetObjectArrayElement / SetObjectArrayElement round-trip. The slow JNI
     * path allocates a fresh local-ref handle for every load — for a tight
     * matrix-multiply inner loop this is the single biggest cost (millions of
     * handle allocations chained into JNIHandleBlock _next blocks).
     *
     * Fast path: read the element oop directly from the array's narrow-oop /
     * wide-oop slot and push it into the active JNIHandleBlock via the same
     * inlined neko_handle_push the dispatcher uses for ref args. Falls back
     * to the JNI version if VMStructs didn't recover all the bits we need
     * (compressed-oops shift, primitive-array layout — used as a stand-in for
     * object-array base since both are 16 bytes on 64-bit hotspot with
     * compressed klass pointers, the only configuration that ships today).
     *
     * Emitted AFTER methodPatcherEmitter so the inline neko_handle_push is
     * already in scope.
     */
    static String renderObjectArrayFastHelpers() {
        StringBuilder sb = new StringBuilder();
        appendObjectArrayHelpers(sb);
        return sb.toString();
    }

    private static void appendObjectArrayHelpers(StringBuilder sb) {
        sb.append("""
static uintptr_t g_neko_string_klass_bits = 0;
static uintptr_t g_neko_byte_array_klass_bits = 0;
static size_t g_neko_string_instance_bytes = 0;
static jboolean g_neko_fast_string_alloc_ready = JNI_FALSE;

/* TLAB-NULL fix: NJX-cached java.lang.String.concat(String) Method* + entry
 * pointer used as a non-JNI fallback when neko_fast_tlab_alloc cannot
 * allocate the String/byte[] pair (TLAB retired by HotSpot's slow allocator
 * during the previous JVM_NewArray refill attempt). NJX call_stub runs
 * Java bytecode under HotSpot's normal _thread_in_java semantics, so HotSpot
 * itself handles TLAB initialization / refill — no JNI is involved. */
static void *g_neko_string_concat_method = NULL;
static void *g_neko_string_concat_entry = NULL;
static jboolean g_neko_string_concat_ready = JNI_FALSE;

/* Raw-disabled string literal binding initializes VM-managed String objects
 * through the package-private String(byte[],byte) constructor via NJX instead
 * of writing oop fields directly when collector store barriers are unavailable
 * as exported native symbols. */
static void *g_neko_string_byte_coder_ctor_method = NULL;
static void *g_neko_string_byte_coder_ctor_entry = NULL;
static jboolean g_neko_string_byte_coder_ctor_ready = JNI_FALSE;

/* TLAB-NULL fix for NEW: NJX-cached jdk.internal.misc.Unsafe instance +
 * allocateInstance(Class) Method* + entry pointer. Same rationale as the
 * String.concat fallback — when neko_fast_tlab_alloc fails for instance
 * allocation, route through Unsafe.allocateInstance which lets HotSpot
 * own the TLAB lifecycle. theInternalUnsafe is captured as a global ref
 * via the T4.8 captured NewGlobalRef pointer so it survives across
 * impl_fn frames. */
static jobject g_neko_unsafe_instance_global = NULL;
static void *g_neko_unsafe_allocate_instance_method = NULL;
static void *g_neko_unsafe_allocate_instance_entry = NULL;
static jboolean g_neko_unsafe_allocate_instance_ready = JNI_FALSE;

NEKO_FAST_INLINE jobject neko_direct_oop_to_handle_origin(void *thread, void *raw_oop, int origin);
NEKO_FAST_INLINE jobject neko_direct_oop_to_handle(void *thread, void *raw_oop);
NEKO_FAST_INLINE jobject neko_store_local_oop_raw(void *thread, jobject *slot_ref, void *raw_oop);

/* T4.7 — `neko_fast_string_runtime_init` deleted. The probe used JNI
 * function-table indices 167 (NewStringUTF) and 176 (NewByteArray) to
 * derive `g_neko_string_klass_bits` / `g_neko_byte_array_klass_bits`
 * from a freshly allocated empty String + byte[] pair. The VMStructs
 * path `neko_ensure_string_alloc_bits` (rendered earlier in this file)
 * is authoritative: it resolves `java/lang/String` via libjvm-internal
 * `JVM_FindClassFromBootLoader`, reads its Klass bits, and sets the
 * byte-array bits from `g_hotspot.primitive_array_klass_bits[NEKO_PRIM_B]`.
 * `neko_method_layout_init` now drives that path instead of the probe;
 * any missing prerequisite aborts there. */

NEKO_FAST_INLINE size_t neko_align_object_bytes(size_t bytes) {
    size_t alignment = (size_t)(g_hotspot.object_alignment_in_bytes > 0 ? g_hotspot.object_alignment_in_bytes : 8);
    return (bytes + alignment - 1u) & ~(alignment - 1u);
}

NEKO_FAST_INLINE void *neko_fast_tlab_alloc(void *thread, size_t bytes) {
    char *tlab;
    char *top;
    char *end;
    char *new_top;
    size_t aligned;
    if (!g_neko_tlab_alloc_ready || thread == NULL || bytes == 0) return NULL;
    aligned = neko_align_object_bytes(bytes);
    tlab = (char*)thread + g_neko_off_thread_tlab;
    top = *(char**)(tlab + g_neko_off_tlab_top);
    end = *(char**)(tlab + g_neko_off_tlab_end);
    if (top == NULL || end == NULL || top > end || aligned > (size_t)(end - top)) return NULL;
    new_top = top + aligned;
    *(char**)(tlab + g_neko_off_tlab_top) = new_top;
    memset(top, 0, aligned);
    return top;
}

NEKO_FAST_INLINE void neko_init_oop_header(char *oop, uintptr_t klass_bits) {
    *(uintptr_t*)oop = (uintptr_t)1u;
    if (g_hotspot.use_compressed_klass_ptrs) {
        *(uint32_t*)(oop + g_hotspot.klass_offset_bytes) = (uint32_t)klass_bits;
    } else {
        *(uintptr_t*)(oop + g_hotspot.klass_offset_bytes) = klass_bits;
    }
}

NEKO_HOT_INLINE void* neko_decode_narrow_oop(uint32_t narrow) {
    if (narrow == 0) return NULL;
    return neko_barrier_oop_load((void*)((uintptr_t)((uintptr_t)narrow << neko_const_compressed_oops_shift())
                   + (uintptr_t)neko_const_compressed_oops_base()));
}

NEKO_FAST_INLINE uint32_t neko_encode_narrow_oop(void *oop) {
    if (oop == NULL) return 0u;
    return (uint32_t)(((uintptr_t)oop - (uintptr_t)g_hotspot.compressed_oops_base) >> g_hotspot.compressed_oops_shift);
}

NEKO_FAST_INLINE void neko_store_oop_raw(char *oop, jlong offset, void *value) {
    value = neko_zgc_store_oop(value);
    if (g_hotspot.compressed_oops_enabled) {
        *(uint32_t*)(oop + offset) = neko_encode_narrow_oop(value);
    } else {
        *(void**)(oop + offset) = value;
    }
}

NEKO_FAST_INLINE void *neko_load_oop_field_raw(char *oop, jlong offset) {
    char *field_addr;
    void *value;
    if (oop == NULL || offset <= 0) return NULL;
    field_addr = oop + offset;
    if (g_hotspot.compressed_oops_enabled) {
        value = neko_decode_narrow_oop(*(uint32_t*)field_addr);
    } else {
        value = *(void**)field_addr;
    }
    return neko_barrier_load_oop_field(field_addr, value);
}

NEKO_FAST_INLINE void neko_copy_string_payload(
    char *dst_array_oop,
    jint dst_char_index,
    jbyte dst_coder,
    char *src_array_oop,
    jint src_chars,
    jbyte src_coder
) {
    size_t base;
    uint8_t *dst;
    uint8_t *src;
    if (src_chars <= 0) return;
    if (dst_array_oop == NULL || src_array_oop == NULL || neko_const_prim_array_base(NEKO_PRIM_B) < 0) {
        fprintf(stderr, "[neko-direct] raw String graph copy layout unavailable dst=%p src=%p base=%d\\n",
            (void*)dst_array_oop, (void*)src_array_oop, (int)neko_const_prim_array_base(NEKO_PRIM_B));
        abort();
    }
    base = (size_t)neko_const_prim_array_base(NEKO_PRIM_B);
    dst = (uint8_t*)dst_array_oop + base + (((size_t)dst_char_index) << (((uint8_t)dst_coder) & 1u));
    src = (uint8_t*)src_array_oop + base;
    if ((((uint8_t)src_coder) & 1u) == (((uint8_t)dst_coder) & 1u)) {
        memcpy(dst, src, ((size_t)src_chars) << (((uint8_t)src_coder) & 1u));
        return;
    }
    if ((((uint8_t)src_coder) & 1u) == 0u && (((uint8_t)dst_coder) & 1u) == 1u) {
        for (jint i = 0; i < src_chars; i++) {
            dst[((size_t)i) * 2u] = src[i];
            dst[((size_t)i) * 2u + 1u] = 0u;
        }
        return;
    }
    fprintf(stderr, "[neko-direct] unsupported raw String graph coder copy src=%d dst=%d chars=%d\\n",
        (int)src_coder, (int)dst_coder, (int)src_chars);
    abort();
}

NEKO_FAST_INLINE jobject neko_build_raw_string_graph_store_local(
    void *thread,
    JNIEnv *env,
    jobject *slot_ref,
    jstring left,
    jstring right,
    jlong valueOffset,
    jlong coderOffset
) {
    char *left_oop;
    char *right_oop;
    char *left_value;
    char *right_value;
    char *array_oop;
    char *string_oop;
    jarray local_array;
    jobject array_handle;
    jobject string_handle;
    jint left_bytes;
    jint right_bytes;
    jint left_chars;
    jint right_chars;
    jint total_chars;
    jint payload_bytes;
    jbyte left_coder;
    jbyte right_coder;
    jbyte result_coder;
    size_t array_bytes;
    if (NEKO_UNLIKELY(thread == NULL || env == NULL || slot_ref == NULL || left == NULL || right == NULL
        || valueOffset <= 0 || coderOffset <= 0)) {
        fprintf(stderr, "[neko-direct] raw String graph precondition failed thread=%p env=%p slot=%p left=%p right=%p value=%lld coder=%lld\\n",
            thread, (void*)env, (void*)slot_ref, (void*)left, (void*)right,
            (long long)valueOffset, (long long)coderOffset);
        abort();
    }
    if (NEKO_UNLIKELY(!neko_const_initialized()
        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())
        || neko_const_array_length_offset() < 0
        || neko_const_prim_array_base(NEKO_PRIM_B) < 0)) {
        fprintf(stderr, "[neko-direct] raw String graph array layout unavailable init=%d fast=0x%x lenOff=%d base=%d\\n",
            (int)neko_const_initialized(), (unsigned)neko_const_fast_bits(),
            (int)neko_const_array_length_offset(), (int)neko_const_prim_array_base(NEKO_PRIM_B));
        abort();
    }
    neko_ensure_string_alloc_bits(env);
    if (NEKO_UNLIKELY(!g_neko_fast_string_alloc_ready
        || g_neko_string_klass_bits == 0
        || g_neko_byte_array_klass_bits == 0
        || g_neko_string_instance_bytes == 0)) {
        fprintf(stderr, "[neko-direct] raw String graph allocation metadata unavailable ready=%d stringBits=0x%llx byteBits=0x%llx stringBytes=%zu\\n",
            (int)g_neko_fast_string_alloc_ready,
            (unsigned long long)g_neko_string_klass_bits,
            (unsigned long long)g_neko_byte_array_klass_bits,
            g_neko_string_instance_bytes);
        abort();
    }
    left_oop = (char*)neko_handle_oop((jobject)left);
    right_oop = (char*)neko_handle_oop((jobject)right);
    if (NEKO_UNLIKELY(left_oop == NULL || right_oop == NULL)) {
        fprintf(stderr, "[neko-direct] raw String graph input handle unresolved left=%p/%p right=%p/%p\\n",
            (void*)left, (void*)left_oop, (void*)right, (void*)right_oop);
        abort();
    }
    left_value = (char*)neko_load_oop_field_raw(left_oop, valueOffset);
    right_value = (char*)neko_load_oop_field_raw(right_oop, valueOffset);
    if (NEKO_UNLIKELY(left_value == NULL || right_value == NULL)) {
        fprintf(stderr, "[neko-direct] raw String graph value array unresolved leftValue=%p rightValue=%p\\n",
            (void*)left_value, (void*)right_value);
        abort();
    }
    left_coder = (jbyte)(*(jbyte*)(left_oop + coderOffset) & 1);
    right_coder = (jbyte)(*(jbyte*)(right_oop + coderOffset) & 1);
    left_bytes = *(jint*)(left_value + neko_const_array_length_offset());
    right_bytes = *(jint*)(right_value + neko_const_array_length_offset());
    if (NEKO_UNLIKELY(left_bytes < 0 || right_bytes < 0)) {
        fprintf(stderr, "[neko-direct] raw String graph negative byte length left=%d right=%d\\n",
            (int)left_bytes, (int)right_bytes);
        abort();
    }
    left_chars = left_bytes >> ((jint)((uint8_t)left_coder) & 1);
    right_chars = right_bytes >> ((jint)((uint8_t)right_coder) & 1);
    if (NEKO_UNLIKELY(left_chars > INT32_MAX - right_chars)) {
        fprintf(stderr, "[neko-direct] raw String graph char length overflow left=%d right=%d\\n",
            (int)left_chars, (int)right_chars);
        abort();
    }
    total_chars = left_chars + right_chars;
    result_coder = (jbyte)((left_coder | right_coder) & 1);
    if (NEKO_UNLIKELY(result_coder != 0 && total_chars > (INT32_MAX >> 1))) {
        fprintf(stderr, "[neko-direct] raw String graph byte length overflow chars=%d coder=%d\\n",
            (int)total_chars, (int)result_coder);
        abort();
    }
    payload_bytes = total_chars << ((jint)((uint8_t)result_coder) & 1);
    array_bytes = (size_t)neko_const_prim_array_base(NEKO_PRIM_B) + (size_t)payload_bytes;
    local_array = NULL;
    array_handle = NULL;
    string_handle = NULL;
    array_oop = (char*)neko_fast_tlab_alloc(thread, array_bytes);
    if (array_oop == NULL) {
        array_oop = neko_alloc_jbyte_array_oop_slow(env, payload_bytes, &local_array);
    } else {
        neko_init_oop_header(array_oop, g_neko_byte_array_klass_bits);
        *(jint*)(array_oop + neko_const_prim_array_base(NEKO_PRIM_B) - 4) = payload_bytes;
    }
    if (NEKO_UNLIKELY(array_oop == NULL)) {
        fprintf(stderr, "[neko-direct] raw String graph byte[] allocation failed bytes=%d totalBytes=%zu slowRef=%p\\n",
            (int)payload_bytes, array_bytes, (void*)local_array);
        abort();
    }
    if (local_array != NULL) {
        array_handle = (jobject)local_array;
        array_oop = (char*)neko_handle_oop(array_handle);
        if (NEKO_UNLIKELY(array_oop == NULL)) {
            fprintf(stderr, "[neko-direct] raw String graph slow byte[] handle unresolved handle=%p\\n", (void*)array_handle);
            abort();
        }
    }
    if (array_handle != NULL) {
        left_oop = (char*)neko_handle_oop((jobject)left);
        right_oop = (char*)neko_handle_oop((jobject)right);
        if (NEKO_UNLIKELY(left_oop == NULL || right_oop == NULL)) {
            fprintf(stderr, "[neko-direct] raw String graph input unresolved after byte[] allocation left=%p/%p right=%p/%p\\n",
                (void*)left, (void*)left_oop, (void*)right, (void*)right_oop);
            abort();
        }
        left_value = (char*)neko_load_oop_field_raw(left_oop, valueOffset);
        right_value = (char*)neko_load_oop_field_raw(right_oop, valueOffset);
        if (NEKO_UNLIKELY(left_value == NULL || right_value == NULL)) {
            fprintf(stderr, "[neko-direct] raw String graph value array unresolved after byte[] allocation leftValue=%p rightValue=%p\\n",
                (void*)left_value, (void*)right_value);
            abort();
        }
    }
    neko_copy_string_payload(array_oop, 0, result_coder, left_value, left_chars, left_coder);
    neko_copy_string_payload(array_oop, left_chars, result_coder, right_value, right_chars, right_coder);
    string_oop = (char*)neko_fast_tlab_alloc(thread, g_neko_string_instance_bytes);
    if (string_oop == NULL) {
        if (array_handle == NULL) {
            array_handle = neko_direct_oop_to_handle_origin(thread, array_oop, NEKO_HANDLE_ORIGIN_PRIMITIVE_ARRAY_ALLOC);
            if (NEKO_UNLIKELY(array_handle == NULL)) {
                fprintf(stderr, "[neko-direct] raw String graph byte[] root publication failed before String slow allocation\\n");
                abort();
            }
            array_oop = (char*)neko_handle_oop(array_handle);
            if (NEKO_UNLIKELY(array_oop == NULL)) {
                fprintf(stderr, "[neko-direct] raw String graph rooted byte[] unresolved before String slow allocation handle=%p\\n",
                    (void*)array_handle);
                abort();
            }
        }
        neko_refill_tlab_with_slow_byte_array(env,
            g_neko_string_instance_bytes > (size_t)INT32_MAX ? INT32_MAX : (jint)g_neko_string_instance_bytes);
        string_oop = (char*)neko_fast_tlab_alloc(thread, g_neko_string_instance_bytes);
    }
    if (string_oop == NULL) {
        jclass string_mirror;
        jvalue alloc_arg;
        jvalue alloc_result;
        string_mirror = neko_resolve_class_mirror_with_env(env, "java/lang/String", NULL, NULL);
        if (NEKO_UNLIKELY(string_mirror == NULL || neko_exception_check(env))) {
            if (neko_exception_check(env)) neko_exception_clear_direct(env);
            fprintf(stderr, "[neko-direct] raw String graph String mirror unavailable for managed allocation\\n");
            abort();
        }
        if (!g_neko_unsafe_allocate_instance_ready) {
            neko_ensure_unsafe_allocate_instance_njx_cache(env);
        }
        if (NEKO_UNLIKELY(!g_neko_unsafe_allocate_instance_ready
            || g_neko_unsafe_instance_global == NULL
            || g_neko_unsafe_allocate_instance_method == NULL
            || g_neko_unsafe_allocate_instance_entry == NULL)) {
            fprintf(stderr, "[neko-direct] raw String graph Unsafe.allocateInstance cache unavailable ready=%d unsafe=%p method=%p entry=%p\\n",
                (int)g_neko_unsafe_allocate_instance_ready, (void*)g_neko_unsafe_instance_global,
                g_neko_unsafe_allocate_instance_method, g_neko_unsafe_allocate_instance_entry);
            abort();
        }
        alloc_arg.l = (jobject)string_mirror;
        alloc_result = neko_njx_V_L_L(thread, env,
            g_neko_unsafe_allocate_instance_method,
            g_neko_unsafe_allocate_instance_entry,
            g_neko_unsafe_instance_global, &alloc_arg);
        if (NEKO_UNLIKELY(alloc_result.l == NULL || neko_exception_check(env))) {
            if (neko_exception_check(env)) neko_exception_clear_direct(env);
            fprintf(stderr, "[neko-direct] raw String graph Unsafe.allocateInstance failed bytes=%zu\\n",
                g_neko_string_instance_bytes);
            abort();
        }
        string_handle = alloc_result.l;
        string_oop = (char*)neko_handle_oop(string_handle);
        if (NEKO_UNLIKELY(string_oop == NULL)) {
            fprintf(stderr, "[neko-direct] raw String graph managed String handle unresolved handle=%p\\n",
                (void*)string_handle);
            abort();
        }
    } else {
        neko_init_oop_header(string_oop, g_neko_string_klass_bits);
    }
    if (array_handle != NULL) {
        array_oop = (char*)neko_handle_oop(array_handle);
        if (NEKO_UNLIKELY(array_oop == NULL)) {
            fprintf(stderr, "[neko-direct] raw String graph byte[] unresolved after String allocation handle=%p stringHandle=%p\\n",
                (void*)array_handle, (void*)string_handle);
            abort();
        }
    } else if (NEKO_UNLIKELY(array_oop == NULL)) {
        fprintf(stderr, "[neko-direct] raw String graph unrooted byte[] lost before String publication\\n");
        abort();
    }
    neko_store_oop_raw(string_oop, valueOffset, array_oop);
    *(jbyte*)(string_oop + coderOffset) = result_coder;
    return neko_store_local_oop_raw(thread, slot_ref, string_oop);
}

NEKO_FAST_INLINE jboolean neko_raw_string_graph_prereq_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        cached = getenv("NEKO_RAW_STRING_GRAPH_PREREQ") != NULL ? 1 : 0;
    }
    return cached != 0 ? JNI_TRUE : JNI_FALSE;
}

NEKO_FAST_INLINE jobject neko_require_fast_string_concat(
    void *thread,
    JNIEnv *env,
    jstring left,
    jstring right,
    jlong valueOffset,
    jlong coderOffset
) {
    (void)valueOffset;
    (void)coderOffset;
    /*
     * Preserve the original JDK method body: this helper is allowed to optimize
     * the NJX call path, but not to construct String payloads natively.
     */
    if (g_neko_string_concat_ready && left != NULL && right != NULL) {
        jvalue concat_arg;
        jvalue concat_result;
        concat_arg.l = right;
        concat_result = neko_njx_V_L_L(thread, env,
            g_neko_string_concat_method, g_neko_string_concat_entry,
            left, &concat_arg);
        if (!neko_exception_check(env)) return concat_result.l;
        return NULL;
    }
    fprintf(stderr, "[neko-direct] String.concat JVM target unavailable left=%p right=%p string_concat_ready=%d\\n",
        (void*)left, (void*)right, (int)g_neko_string_concat_ready);
    abort();
}

NEKO_FAST_INLINE jobject neko_require_fast_string_concat_store_local(
    void *thread,
    JNIEnv *env,
    jobject *slot_ref,
    jstring left,
    jstring right,
    jlong valueOffset,
    jlong coderOffset
) {
    (void)valueOffset;
    (void)coderOffset;
    /*
     * Same JVM String.concat target as neko_require_fast_string_concat, but the
     * raw oop is published directly into an already prepared translated local
     * root when the bytecode consumer is an immediate ASTORE.
     */
    if (neko_raw_string_graph_prereq_enabled() && left != NULL && right != NULL) {
        return neko_build_raw_string_graph_store_local(thread, env, slot_ref, left, right, valueOffset, coderOffset);
    }
    if (g_neko_string_concat_ready && left != NULL && right != NULL) {
        jvalue concat_arg;
        void *concat_raw;
        concat_arg.l = right;
        concat_raw = neko_njx_V_L_L_raw_oop(thread, env,
            g_neko_string_concat_method, g_neko_string_concat_entry,
            left, &concat_arg);
        if (neko_exception_check(env)) {
            return neko_store_local_oop_raw(thread, slot_ref, NULL);
        }
        return neko_store_local_oop_raw(thread, slot_ref, concat_raw);
    }
    fprintf(stderr, "[neko-direct] String.concat JVM target unavailable for local store left=%p right=%p string_concat_ready=%d\\n",
        (void*)left, (void*)right, (int)g_neko_string_concat_ready);
    abort();
}

__attribute__((visibility("hidden"))) jobject neko_concat_append(
    void *thread,
    JNIEnv *env,
    jstring acc,
    jstring rhs,
    jlong valueOffset,
    jlong coderOffset
) {
    jstring lhs = acc == NULL ? neko_string_null(env) : acc;
    jstring normalized_rhs = rhs == NULL ? neko_string_null(env) : rhs;
    return neko_require_fast_string_concat(thread, env, lhs, normalized_rhs, valueOffset, coderOffset);
}

NEKO_FAST_INLINE jobject neko_concat_append_inline(
    void *thread,
    JNIEnv *env,
    jstring acc,
    jstring rhs,
    jlong valueOffset,
    jlong coderOffset
) {
    jstring lhs = acc == NULL ? neko_string_null(env) : acc;
    jstring normalized_rhs = rhs == NULL ? neko_string_null(env) : rhs;
    return neko_require_fast_string_concat(thread, env, lhs, normalized_rhs, valueOffset, coderOffset);
}

NEKO_FAST_INLINE jobject neko_concat_append_inline_store_local(
    void *thread,
    JNIEnv *env,
    jobject *slot_ref,
    jstring acc,
    jstring rhs,
    jlong valueOffset,
    jlong coderOffset
) {
    jstring lhs = acc == NULL ? neko_string_null(env) : acc;
    jstring normalized_rhs = rhs == NULL ? neko_string_null(env) : rhs;
    return neko_require_fast_string_concat_store_local(thread, env, slot_ref, lhs, normalized_rhs, valueOffset, coderOffset);
}

NEKO_FAST_INLINE jstring neko_concat_accumulate(
    void *thread,
    JNIEnv *env,
    jstring acc,
    jstring rhs,
    jlong valueOffset,
    jlong coderOffset
) {
    NEKO_HANDLE_AUDIT_HIT(g_neko_concat_accumulate_total_count);
    if (acc == NULL) return rhs == NULL ? neko_string_null(env) : rhs;
    NEKO_HANDLE_AUDIT_HIT(g_neko_concat_accumulate_njx_count);
    return (jstring)neko_concat_append_inline(thread, env, acc, rhs, valueOffset, coderOffset);
}

typedef jvalue (*neko_string_value_of_dispatcher)(void*, JNIEnv*, void*, void*, jobject, const jvalue*);

NEKO_FAST_INLINE jstring neko_string_value_of_I(
    void *thread,
    JNIEnv *env,
    neko_string_value_of_dispatcher dispatcher,
    void *method_ptr,
    void *entry_point,
    jint value
) {
    jvalue args[1];
    args[0].i = value;
    jvalue result = dispatcher(thread, env, method_ptr, entry_point, NULL, args);
    return neko_exception_check(env) ? NULL : (jstring)result.l;
}

NEKO_FAST_INLINE jstring neko_string_value_of_J(
    void *thread,
    JNIEnv *env,
    neko_string_value_of_dispatcher dispatcher,
    void *method_ptr,
    void *entry_point,
    jlong value
) {
    jvalue args[1];
    args[0].j = value;
    jvalue result = dispatcher(thread, env, method_ptr, entry_point, NULL, args);
    return neko_exception_check(env) ? NULL : (jstring)result.l;
}

NEKO_FAST_INLINE jstring neko_string_value_of_F(
    void *thread,
    JNIEnv *env,
    neko_string_value_of_dispatcher dispatcher,
    void *method_ptr,
    void *entry_point,
    jfloat value
) {
    jvalue args[1];
    args[0].f = value;
    jvalue result = dispatcher(thread, env, method_ptr, entry_point, NULL, args);
    return neko_exception_check(env) ? NULL : (jstring)result.l;
}

NEKO_FAST_INLINE jstring neko_string_value_of_D(
    void *thread,
    JNIEnv *env,
    neko_string_value_of_dispatcher dispatcher,
    void *method_ptr,
    void *entry_point,
    jdouble value
) {
    jvalue args[1];
    args[0].d = value;
    jvalue result = dispatcher(thread, env, method_ptr, entry_point, NULL, args);
    return neko_exception_check(env) ? NULL : (jstring)result.l;
}

NEKO_FAST_INLINE jstring neko_string_value_of_L(
    void *thread,
    JNIEnv *env,
    neko_string_value_of_dispatcher dispatcher,
    void *method_ptr,
    void *entry_point,
    jobject value
) {
    jvalue args[1];
    args[0].l = value;
    jvalue result = dispatcher(thread, env, method_ptr, entry_point, NULL, args);
    return neko_exception_check(env) ? NULL : (jstring)result.l;
}

NEKO_FAST_INLINE jobject neko_direct_oop_to_handle(void *thread, void *raw_oop) {
    return neko_direct_oop_to_handle_origin(thread, raw_oop, NEKO_HANDLE_ORIGIN_OTHER);
}

NEKO_FAST_INLINE jobject neko_direct_oop_to_handle_origin(void *thread, void *raw_oop, int origin) {
    NEKO_HANDLE_AUDIT_ORIGIN(origin);
    NEKO_HANDLE_AUDIT_HIT(g_neko_handle_direct_total_count);
    if (raw_oop == NULL) return NULL;
    raw_oop = neko_zgc_good_oop(raw_oop);
    if (g_neko_handle_push_ready && thread != NULL) {
        void *block = *(void**)((char*)thread + g_neko_off_thread_active_handles);
        if (block != NULL) {
            int32_t *top_ptr = (int32_t*)((char*)block + g_neko_off_jnih_block_top);
            int32_t top = *top_ptr;
            neko_handle_audit_max(&g_neko_handle_direct_max_top, top > 0 ? (uint64_t)top : 0u);
            neko_handle_audit_max(&g_neko_handle_direct_max_capacity,
                g_neko_jnih_block_capacity > 0 ? (uint64_t)g_neko_jnih_block_capacity : 0u);
            if (top < g_neko_jnih_block_capacity) {
                void **handles = (void**)((char*)block + g_neko_off_jnih_block_handles);
                handles[top] = raw_oop;
                *top_ptr = top + 1;
                NEKO_HANDLE_AUDIT_HIT(g_neko_handle_direct_fast_slot_count);
                if (g_neko_method_layout.off_jnih_block_next > 0) {
                    ptrdiff_t off_last = g_neko_method_layout.off_jnih_block_next + 8;
                    *(void**)((char*)block + off_last) = block;
                }
                return (jobject)&handles[top];
            }
            if (g_neko_method_layout.sizeof_JNIHandleBlock > 0 && g_neko_method_layout.off_jnih_block_next > 0) {
                jboolean new_allocation = JNI_FALSE;
                void *new_block = neko_alloc_jnih_block(&new_allocation);
                if (new_block != NULL && new_allocation) {
                    NEKO_HANDLE_AUDIT_HIT(g_neko_handle_direct_overflow_alloc_count);
                }
                if (new_block != NULL) {
                    void **new_handles = (void**)((char*)new_block + g_neko_off_jnih_block_handles);
                    new_handles[0] = raw_oop;
                    *(int32_t*)((char*)new_block + g_neko_off_jnih_block_top) = 1;
                    *(void**)((char*)new_block + g_neko_method_layout.off_jnih_block_next) = block;
                    {
                        ptrdiff_t off_last = g_neko_method_layout.off_jnih_block_next + 8;
                        *(void**)((char*)new_block + off_last) = new_block;
                    }
                    *(void**)((char*)thread + g_neko_off_thread_active_handles) = new_block;
                    return (jobject)&new_handles[0];
                }
            }
        }
    }
    NEKO_HANDLE_AUDIT_HIT(g_neko_handle_direct_unavailable_count);
    fprintf(stderr, "[neko-direct] JNIHandleBlock direct slot unavailable thread=%p raw=%p\\n", thread, raw_oop);
    abort();
}

NEKO_FAST_INLINE void neko_prepare_local_oop_roots(void *thread, jobject *roots, int32_t count) {
    void *head;
    void *last;
    int32_t root_index = 0;
    if (count <= 0) return;
    if (roots == NULL || !g_neko_handle_push_ready || thread == NULL
        || g_neko_off_thread_active_handles <= 0
        || g_neko_method_layout.sizeof_JNIHandleBlock <= 0
        || g_neko_method_layout.off_jnih_block_next <= 0
        || g_neko_off_jnih_block_top < 0
        || g_neko_off_jnih_block_handles < 0
        || g_neko_jnih_block_capacity <= 0) {
        fprintf(stderr, "[neko-direct] JNIHandleBlock local root preparation unavailable thread=%p count=%d\\n",
            thread, (int)count);
        abort();
    }
    head = *(void**)((char*)thread + g_neko_off_thread_active_handles);
    if (head == NULL) {
        fprintf(stderr, "[neko-direct] JNIHandleBlock active block missing for local roots thread=%p count=%d\\n",
            thread, (int)count);
        abort();
    }
    last = *(void**)((char*)head + g_neko_method_layout.off_jnih_block_next + 8);
    if (last == NULL) last = head;
    for (int32_t i = 0; i < count; i++) roots[i] = NULL;
    while (root_index < count) {
        int32_t *top_ptr = (int32_t*)((char*)last + g_neko_off_jnih_block_top);
        int32_t top = *top_ptr;
        if (top < 0 || top > g_neko_jnih_block_capacity) {
            fprintf(stderr, "[neko-direct] JNIHandleBlock local root invalid top thread=%p top=%d cap=%d\\n",
                thread, (int)top, (int)g_neko_jnih_block_capacity);
            abort();
        }
        if (top < g_neko_jnih_block_capacity) {
            int32_t take = count - root_index;
            int32_t room = g_neko_jnih_block_capacity - top;
            void **handles = (void**)((char*)last + g_neko_off_jnih_block_handles);
            if (take > room) take = room;
            for (int32_t j = 0; j < take; j++) {
                handles[top + j] = NULL;
                roots[root_index++] = (jobject)&handles[top + j];
            }
            *top_ptr = top + take;
            *(void**)((char*)head + g_neko_method_layout.off_jnih_block_next + 8) = last;
            continue;
        }
        {
            void *new_block = calloc(1, g_neko_method_layout.sizeof_JNIHandleBlock);
            if (new_block == NULL) {
                fprintf(stderr, "[neko-direct] JNIHandleBlock local root block allocation failed thread=%p count=%d\\n",
                    thread, (int)count);
                abort();
            }
            *(void**)((char*)last + g_neko_method_layout.off_jnih_block_next) = new_block;
            *(void**)((char*)new_block + g_neko_method_layout.off_jnih_block_next) = NULL;
            *(void**)((char*)new_block + g_neko_method_layout.off_jnih_block_next + 8) = new_block;
            *(void**)((char*)head + g_neko_method_layout.off_jnih_block_next + 8) = new_block;
            last = new_block;
        }
    }
}

NEKO_FAST_INLINE jobject neko_store_local_oop_ref(void *thread, jobject *slot_ref, jobject ref) {
    void *raw_oop;
    if (ref == NULL) {
        return neko_store_local_oop_raw(thread, slot_ref, NULL);
    }
    raw_oop = neko_handle_oop(ref);
    if (raw_oop == NULL) {
        fprintf(stderr, "[neko-direct] object local store source did not resolve ref=%p\\n", (void*)ref);
        abort();
    }
    return neko_store_local_oop_raw(thread, slot_ref, raw_oop);
}

NEKO_FAST_INLINE jobject neko_store_local_oop_raw(void *thread, jobject *slot_ref, void *raw_oop) {
    uintptr_t slot;
    (void)thread;
    if (slot_ref == NULL) {
        fprintf(stderr, "[neko-direct] object local raw store missing slot\\n");
        abort();
    }
    if (*slot_ref == NULL) {
        fprintf(stderr, "[neko-direct] object local raw root slot not prepared\\n");
        abort();
    }
    slot = (uintptr_t)*slot_ref;
    slot = (neko_const_fast_bits() & NEKO_HOTSPOT_FAST_HANDLE_TAGS) != 0 ? (slot & ~(uintptr_t)0x3u) : slot;
    if (raw_oop != NULL) {
        raw_oop = neko_zgc_good_oop(raw_oop);
    }
    *(void**)slot = raw_oop;
    return (jobject)raw_oop;
}

NEKO_FAST_INLINE jobjectArray neko_fast_new_object_array(void *thread, JNIEnv *env, jint len, uintptr_t klass_bits, jobject init) {
    if (len < 0) {
        fprintf(stderr, "[neko-direct] negative object array length %d\\n", (int)len);
        abort();
    }
    if (klass_bits != 0
        && g_hotspot.initialized
        && ((g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) != 0 || g_hotspot.use_zgc)
        && g_hotspot.primitive_array_base_offsets[NEKO_PRIM_I] >= 0
        && !g_hotspot.use_compact_object_headers
        && g_neko_tlab_alloc_ready) {
        size_t ref_size = g_hotspot.compressed_oops_enabled ? 4u : sizeof(void*);
        size_t base = (size_t)g_hotspot.primitive_array_base_offsets[NEKO_PRIM_I];
        size_t bytes = base + ((size_t)len * ref_size);
        char *array_oop = (char*)neko_fast_tlab_alloc(thread, bytes);
        if (array_oop == NULL && env != NULL) {
            neko_refill_tlab_with_slow_byte_array(env, bytes > (size_t)INT32_MAX ? INT32_MAX : (jint)bytes);
            array_oop = (char*)neko_fast_tlab_alloc(thread, bytes);
        }
        if (array_oop != NULL) {
            neko_init_oop_header(array_oop, klass_bits);
            *(jint*)(array_oop + base - 4u) = len;
            memset(array_oop + base, 0, ((size_t)len * ref_size));
            if (init != NULL) {
                void *init_oop = neko_handle_oop(init);
                for (jint i = 0; i < len; i++) {
                    neko_store_oop_raw(array_oop, (jlong)(base + ((size_t)i * ref_size)), init_oop);
                }
            }
            return (jobjectArray)neko_direct_oop_to_handle_origin(thread, array_oop, NEKO_HANDLE_ORIGIN_OBJECT_ARRAY_ALLOC);
        }
    }
    fprintf(stderr, "[neko-direct] object array allocation direct path unavailable len=%d klass=0x%llx thread=%p init=%d raw=%d zgc=%d coh=%d tlab=%d base=%d\\n",
        (int)len, (unsigned long long)klass_bits, thread,
        (int)g_hotspot.initialized,
        (int)((g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) != 0),
        (int)g_hotspot.use_zgc,
        (int)g_hotspot.use_compact_object_headers,
        (int)g_neko_tlab_alloc_ready,
        (int)g_hotspot.primitive_array_base_offsets[NEKO_PRIM_I]);
    abort();
}

NEKO_FAST_INLINE jarray neko_fast_new_primitive_array(void *thread, JNIEnv *env, jint len, int kind) {
    if (len < 0) {
        fprintf(stderr, "[neko-direct] negative primitive array length %d kind=%d\\n", (int)len, kind);
        abort();
    }
    if (kind >= 0 && kind < NEKO_PRIM_COUNT
        && g_hotspot.primitive_array_klass_bits[kind] != 0
        && g_hotspot.primitive_array_base_offsets[kind] >= 0
        && g_hotspot.primitive_array_index_scales[kind] > 0
        && g_hotspot.initialized
        && ((g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) != 0 || g_hotspot.use_zgc)
        && !g_hotspot.use_compact_object_headers
        && g_neko_tlab_alloc_ready) {
        size_t base = (size_t)g_hotspot.primitive_array_base_offsets[kind];
        size_t scale = (size_t)g_hotspot.primitive_array_index_scales[kind];
        size_t bytes = base + ((size_t)len * scale);
        char *array_oop = (char*)neko_fast_tlab_alloc(thread, bytes);
        if (array_oop == NULL && env != NULL) {
            neko_refill_tlab_with_slow_byte_array(env, bytes > (size_t)INT32_MAX ? INT32_MAX : (jint)bytes);
            array_oop = (char*)neko_fast_tlab_alloc(thread, bytes);
            if (array_oop == NULL) {
                return neko_alloc_primitive_array_slow(env, len, kind);
            }
        }
        if (array_oop != NULL) {
            neko_init_oop_header(array_oop, g_hotspot.primitive_array_klass_bits[kind]);
            *(jint*)(array_oop + base - 4u) = len;
            memset(array_oop + base, 0, ((size_t)len * scale));
            return (jarray)neko_direct_oop_to_handle_origin(thread, array_oop, NEKO_HANDLE_ORIGIN_PRIMITIVE_ARRAY_ALLOC);
        }
    }
    fprintf(stderr, "[neko-direct] primitive array allocation direct path unavailable len=%d kind=%d thread=%p init=%d klass=0x%llx base=%d scale=%d raw=%d zgc=%d coh=%d tlab=%d\\n",
        (int)len, kind, thread,
        (int)g_hotspot.initialized,
        (unsigned long long)((kind >= 0 && kind < NEKO_PRIM_COUNT) ? g_hotspot.primitive_array_klass_bits[kind] : 0),
        (int)((kind >= 0 && kind < NEKO_PRIM_COUNT) ? g_hotspot.primitive_array_base_offsets[kind] : -1),
        (int)((kind >= 0 && kind < NEKO_PRIM_COUNT) ? g_hotspot.primitive_array_index_scales[kind] : 0),
        (int)((g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) != 0),
        (int)g_hotspot.use_zgc,
        (int)g_hotspot.use_compact_object_headers,
        (int)g_neko_tlab_alloc_ready);
    abort();
}

NEKO_FAST_INLINE jobject neko_fast_alloc_object(void *thread, JNIEnv *env, jclass cls) {
    void *klass;
    jint layout_helper;
    size_t bytes;
    char *oop;
    uintptr_t klass_bits;
    if (thread == NULL || cls == NULL) {
        fprintf(stderr, "[neko-direct] NEW direct allocation missing thread/class thread=%p cls=%p\\n",
            thread, (void*)cls);
        abort();
    }
    if (!g_hotspot.initialized) {
        fprintf(stderr, "[neko-direct] NEW direct allocation hotspot state unavailable thread=%p cls=%p\\n",
            thread, (void*)cls);
        abort();
    }
    if ((g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) == 0
        || g_hotspot.use_compact_object_headers
        || g_hotspot.klass_offset_bytes <= 0
        || !g_neko_tlab_alloc_ready) {
        jvalue alloc_arg;
        jvalue alloc_result;
        if (env != NULL) {
            if (!g_neko_unsafe_allocate_instance_ready) {
                neko_ensure_unsafe_allocate_instance_njx_cache(env);
            }
            if (g_neko_unsafe_allocate_instance_ready
                && g_neko_unsafe_instance_global != NULL
                && g_neko_unsafe_allocate_instance_method != NULL
                && g_neko_unsafe_allocate_instance_entry != NULL) {
                alloc_arg.l = cls;
                alloc_result = neko_njx_V_L_L(thread, env,
                    g_neko_unsafe_allocate_instance_method,
                    g_neko_unsafe_allocate_instance_entry,
                    g_neko_unsafe_instance_global, &alloc_arg);
                if (alloc_result.l != NULL) return alloc_result.l;
            }
        }
        fprintf(stderr, "[neko-direct] NEW managed allocation unavailable thread=%p cls=%p raw=%d coh=%d klass_off=%d tlab=%d unsafe_ready=%d\\n",
            thread, (void*)cls,
            (int)((g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) != 0),
            (int)g_hotspot.use_compact_object_headers,
            (int)g_hotspot.klass_offset_bytes,
            (int)g_neko_tlab_alloc_ready,
            (int)g_neko_unsafe_allocate_instance_ready);
        abort();
    }
    if (g_neko_method_layout.off_klass_layout_helper < 0) {
        fprintf(stderr, "[neko-direct] Klass::_layout_helper offset unavailable for NEW\\n");
        abort();
    }
    klass = neko_class_mirror_to_klass(cls);
    if (klass == NULL) {
        fprintf(stderr, "[neko-direct] NEW class mirror did not resolve to Klass* cls=%p\\n", (void*)cls);
        abort();
    }
    layout_helper = *(jint*)((char*)klass + g_neko_method_layout.off_klass_layout_helper);
    if (layout_helper <= 0) {
        fprintf(stderr, "[neko-direct] NEW target is not an instance klass cls=%p klass=%p layout=%d\\n",
            (void*)cls, klass, (int)layout_helper);
        abort();
    }
    bytes = (size_t)layout_helper * sizeof(void*);
    klass_bits = neko_klass_header_bits(klass);
    if (klass_bits == 0 || bytes == 0) {
        fprintf(stderr, "[neko-direct] NEW klass bits/size unavailable cls=%p klass=%p bits=0x%llx bytes=%zu\\n",
            (void*)cls, klass, (unsigned long long)klass_bits, bytes);
        abort();
    }
    oop = (char*)neko_fast_tlab_alloc(thread, bytes);
    if (oop == NULL && env != NULL) {
        neko_refill_tlab_with_slow_byte_array(env, bytes > (size_t)INT32_MAX ? INT32_MAX : (jint)bytes);
        oop = (char*)neko_fast_tlab_alloc(thread, bytes);
    }
    if (oop == NULL) {
        /* TLAB-NULL fix: HotSpot's slow allocator retired our TLAB during
         * the previous JVM_NewArray refill; _top is now NULL. Fall back to
         * Unsafe.allocateInstance via NJX call_stub — runs Java bytecode
         * under HotSpot's normal _thread_in_java mode where TLAB lifecycle
         * is JVM-managed. NOT a JNI fallback (no JNI function-table call,
         * no thread-state ping-pong). */
        if (g_neko_unsafe_allocate_instance_ready
            && g_neko_unsafe_instance_global != NULL
            && cls != NULL && env != NULL) {
            jvalue alloc_arg;
            jvalue alloc_result;
            alloc_arg.l = cls;
            alloc_result = neko_njx_V_L_L(thread, env,
                g_neko_unsafe_allocate_instance_method,
                g_neko_unsafe_allocate_instance_entry,
                g_neko_unsafe_instance_global, &alloc_arg);
            if (alloc_result.l != NULL) return alloc_result.l;
        }
        fprintf(stderr, "[neko-direct] NEW TLAB allocation failed cls=%p klass=%p bytes=%zu unsafe_ready=%d\\n",
            (void*)cls, klass, bytes, (int)g_neko_unsafe_allocate_instance_ready);
        abort();
    }
    neko_init_oop_header(oop, klass_bits);
    return neko_direct_oop_to_handle_origin(thread, oop, NEKO_HANDLE_ORIGIN_OBJECT_ALLOC);
}

NEKO_FAST_INLINE void *neko_raw_oop_klass(char *oop) {
    uintptr_t bits;
    if (oop == NULL) return NULL;
    if (!g_hotspot.initialized || g_hotspot.klass_offset_bytes <= 0) {
        fprintf(stderr, "[neko-direct] object klass layout unavailable oop=%p\\n", oop);
        abort();
    }
    if (g_hotspot.use_compressed_klass_ptrs) {
        bits = (uintptr_t)(*(uint32_t*)(oop + g_hotspot.klass_offset_bytes));
    } else {
        bits = *(uintptr_t*)(oop + g_hotspot.klass_offset_bytes);
    }
    return neko_decode_klass_header_bits(bits);
}

NEKO_FAST_INLINE void *neko_objarray_element_klass(char *array_oop) {
    void *array_klass;
    if (g_neko_method_layout.off_objarrayklass_element_klass < 0) {
        fprintf(stderr, "[neko-direct] ObjArrayKlass::_element_klass offset unavailable\\n");
        abort();
    }
    array_klass = neko_raw_oop_klass(array_oop);
    if (array_klass == NULL) return NULL;
    return *(void**)((char*)array_klass + g_neko_method_layout.off_objarrayklass_element_klass);
}

NEKO_FAST_INLINE jboolean neko_klass_is_subtype_of(void *sub_klass, void *super_klass) {
    void *klass;
    if (sub_klass == NULL || super_klass == NULL) return JNI_FALSE;
    if (sub_klass == super_klass) return JNI_TRUE;
    if (g_neko_method_layout.off_klass_super < 0
        || g_neko_method_layout.off_klass_secondary_super_cache < 0
        || g_neko_method_layout.off_klass_secondary_supers < 0
        || g_neko_method_layout.off_array_length < 0
        || g_neko_method_layout.off_array_data < 0) {
        fprintf(stderr, "[neko-direct] Klass subtype-check layout unavailable\\n");
        abort();
    }
    klass = sub_klass;
    for (int depth = 0; klass != NULL && depth < 256; depth++) {
        if (klass == super_klass) return JNI_TRUE;
        klass = *(void**)((char*)klass + g_neko_method_layout.off_klass_super);
    }
    {
        void *cached = *(void**)((char*)sub_klass + g_neko_method_layout.off_klass_secondary_super_cache);
        if (cached == super_klass) return JNI_TRUE;
    }
    {
        void *secondary = *(void**)((char*)sub_klass + g_neko_method_layout.off_klass_secondary_supers);
        if (secondary != NULL) {
            int len = *(int*)((char*)secondary + g_neko_method_layout.off_array_length);
            void **data = (void**)((char*)secondary + g_neko_method_layout.off_array_data);
            for (int i = 0; i < len; i++) {
                if (data[i] == super_klass) return JNI_TRUE;
            }
        }
    }
    return JNI_FALSE;
}

NEKO_FAST_INLINE jboolean neko_fast_is_instance_of(JNIEnv *env, jobject obj, jclass cls) {
    void *value_oop;
    void *value_klass;
    void *target_klass;
    (void)env;
    if (obj == NULL) return JNI_FALSE;
    if (cls == NULL) {
        fprintf(stderr, "[neko-direct] INSTANCEOF/CHECKCAST missing target class\\n");
        abort();
    }
    value_oop = neko_handle_oop(obj);
    if (value_oop == NULL) {
        fprintf(stderr, "[neko-direct] INSTANCEOF/CHECKCAST object handle did not resolve obj=%p\\n", (void*)obj);
        abort();
    }
    value_klass = neko_raw_oop_klass((char*)value_oop);
    target_klass = neko_class_mirror_to_klass(cls);
    if (target_klass == NULL) {
        fprintf(stderr, "[neko-direct] INSTANCEOF/CHECKCAST target mirror did not map to Klass* cls=%p\\n", (void*)cls);
        abort();
    }
    return neko_klass_is_subtype_of(value_klass, target_klass);
}

__attribute__((visibility("hidden"))) jboolean neko_exception_handler_matches(JNIEnv *env, jthrowable exc, jclass cls) {
    if (cls == NULL) return JNI_TRUE;
    return neko_fast_is_instance_of(env, exc, cls);
}

__attribute__((visibility("hidden"))) jboolean neko_exception_handler_matches_ref(JNIEnv *env, jthrowable exc, const neko_class_ref *ref) {
    if (ref == NULL || ref->class_slot == NULL) {
        fprintf(stderr, "[neko-direct] exception handler ref metadata unavailable ref=%p\\n", (void*)ref);
        abort();
    }
    return neko_exception_handler_matches(env, exc, neko_bound_class(env, *(ref->class_slot), ref->owner));
}


#define NEKO_MONITOR_RECORD_BYTES 64u

typedef struct {
    unsigned char basic_object_lock[NEKO_MONITOR_RECORD_BYTES];
    jobject handle;
} neko_monitor_record;

NEKO_FAST_INLINE void neko_call_runtime1_monitorenter(void *entry, void *thread, void *lock_record, void *obj_oop) {
#if defined(__x86_64__)
    __asm__ __volatile__(
        "pushq %%r15\\n\\t"
        "movq %[entry], %%r11\\n\\t"
        "movq %[thread], %%r15\\n\\t"
        "subq $24, %%rsp\\n\\t"
        "movq %[lock_record], (%%rsp)\\n\\t"
        "movq %[obj_oop], 8(%%rsp)\\n\\t"
        "call *%%r11\\n\\t"
        "addq $24, %%rsp\\n\\t"
        "popq %%r15\\n\\t"
        :
        : [entry] "r" (entry),
          [thread] "r" (thread),
          [lock_record] "r" (lock_record),
          [obj_oop] "r" (obj_oop)
        : "memory", "cc",
          "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
#else
    (void)entry;
    (void)thread;
    (void)lock_record;
    (void)obj_oop;
    fprintf(stderr, "[neko-direct] Runtime1 monitor stubs unsupported on this architecture\\n");
    abort();
#endif
}

NEKO_FAST_INLINE void neko_call_runtime1_monitorexit(void *entry, void *thread, void *lock_record) {
#if defined(__x86_64__)
    __asm__ __volatile__(
        "pushq %%r15\\n\\t"
        "movq %[entry], %%r11\\n\\t"
        "movq %[thread], %%r15\\n\\t"
        "subq $8, %%rsp\\n\\t"
        "movq %[lock_record], (%%rsp)\\n\\t"
        "call *%%r11\\n\\t"
        "addq $8, %%rsp\\n\\t"
        "popq %%r15\\n\\t"
        :
        : [entry] "r" (entry),
          [thread] "r" (thread),
          [lock_record] "r" (lock_record)
        : "memory", "cc",
          "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
#else
    (void)entry;
    (void)thread;
    (void)lock_record;
    fprintf(stderr, "[neko-direct] Runtime1 monitor stubs unsupported on this architecture\\n");
    abort();
#endif
}

NEKO_FAST_INLINE void *neko_monitor_record_lock_addr(neko_monitor_record *rec) {
    return (void*)(rec->basic_object_lock + g_neko_off_basicobjectlock_lock);
}

NEKO_FAST_INLINE void neko_prepare_monitor_record(neko_monitor_record *rec, jobject obj, void *raw_oop) {
    void *lock_addr;
    uintptr_t mark_bits;
    if (rec == NULL || raw_oop == NULL) {
        fprintf(stderr, "[neko-direct] monitor record/object unavailable rec=%p obj=%p\\n", (void*)rec, raw_oop);
        abort();
    }
    if (!g_neko_monitor_stub_ready
        || g_neko_sizeof_basicobjectlock == 0
        || g_neko_sizeof_basicobjectlock > NEKO_MONITOR_RECORD_BYTES
        || g_neko_off_basicobjectlock_lock < 0
        || g_neko_off_basicobjectlock_obj < 0
        || g_neko_off_basiclock_displaced_header < 0
        || g_hotspot.klass_offset_bytes <= 0
        || g_hotspot.use_compact_object_headers) {
        fprintf(stderr, "[neko-direct] monitor layout unavailable ready=%d enter=%p exit=%p bol_size=%zu lock=%td obj=%td disp=%td klass_off=%d coh=%d\\n",
            (int)g_neko_monitor_stub_ready,
            g_neko_runtime1_monitorenter_entry,
            g_neko_runtime1_monitorexit_entry,
            g_neko_sizeof_basicobjectlock,
            g_neko_off_basicobjectlock_lock,
            g_neko_off_basicobjectlock_obj,
            g_neko_off_basiclock_displaced_header,
            (int)g_hotspot.klass_offset_bytes,
            (int)g_hotspot.use_compact_object_headers);
        abort();
    }
    memset(rec->basic_object_lock, 0, sizeof(rec->basic_object_lock));
    rec->handle = obj;
    *(void**)(rec->basic_object_lock + g_neko_off_basicobjectlock_obj) = raw_oop;
    lock_addr = neko_monitor_record_lock_addr(rec);
    mark_bits = (*(uintptr_t*)raw_oop) | (uintptr_t)1u;
    *(uintptr_t*)((char*)lock_addr + g_neko_off_basiclock_displaced_header) = mark_bits;
}

NEKO_FAST_INLINE void neko_fast_monitor_enter(void *thread, jobject obj, neko_monitor_record *rec) {
    void *raw_oop;
    if (thread == NULL) {
        fprintf(stderr, "[neko-direct] MONITORENTER missing JavaThread\\n");
        abort();
    }
    if (obj == NULL) {
        fprintf(stderr, "[neko-direct] MONITORENTER null object\\n");
        abort();
    }
    raw_oop = neko_handle_oop(obj);
    if (raw_oop == NULL) {
        fprintf(stderr, "[neko-direct] MONITORENTER handle did not resolve obj=%p\\n", (void*)obj);
        abort();
    }
    neko_prepare_monitor_record(rec, obj, raw_oop);
    neko_call_runtime1_monitorenter(g_neko_runtime1_monitorenter_entry, thread, rec->basic_object_lock, raw_oop);
}

NEKO_FAST_INLINE void neko_fast_monitor_exit(void *thread, jobject obj, neko_monitor_record *rec) {
    void *raw_oop;
    void *entered_oop;
    if (thread == NULL) {
        fprintf(stderr, "[neko-direct] MONITOREXIT missing JavaThread\\n");
        abort();
    }
    if (rec == NULL || rec->handle == NULL) {
        fprintf(stderr, "[neko-direct] MONITOREXIT missing active monitor record\\n");
        abort();
    }
    raw_oop = neko_handle_oop(obj);
    entered_oop = neko_handle_oop(rec->handle);
    if (raw_oop == NULL || entered_oop == NULL || raw_oop != entered_oop) {
        fprintf(stderr, "[neko-direct] MONITOREXIT monitor object mismatch obj=%p entered=%p raw=%p entered_raw=%p\\n",
            (void*)obj, (void*)rec->handle, raw_oop, entered_oop);
        abort();
    }
    *(void**)(rec->basic_object_lock + g_neko_off_basicobjectlock_obj) = raw_oop;
    neko_call_runtime1_monitorexit(g_neko_runtime1_monitorexit_entry, thread, rec->basic_object_lock);
    memset(rec->basic_object_lock, 0, sizeof(rec->basic_object_lock));
    rec->handle = NULL;
}

static void __attribute__((cold, noinline)) neko_abort_aastore_value_unresolved(jobject val) {
    fprintf(stderr, "[neko-direct] AASTORE value handle did not resolve val=%p\\n", (void*)val);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_aastore_type_check_failed(void *value_klass, void *element_klass) {
    fprintf(stderr, "[neko-direct] AASTORE array-store check failed value_klass=%p element_klass=%p\\n",
        value_klass, element_klass);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_fast_aastore_unavailable(jobjectArray arr, jint idx, char *debug_oop, jint debug_len) {
    fprintf(stderr, "[neko-direct] AASTORE direct path unavailable arr=%p idx=%d oop=%p len=%d baseI=%d use_zgc=%d fast=0x%llx\\n",
        (void*)arr, (int)idx, debug_oop, (int)debug_len,
        (int)neko_const_prim_array_base(NEKO_PRIM_I),
        (int)neko_const_use_zgc(),
        (unsigned long long)neko_const_fast_bits());
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_fast_aaload_unavailable(void *thread, jobjectArray arr, jint idx) {
    void *dbg_block = thread != NULL && g_neko_off_thread_active_handles > 0 ? *(void**)((char*)thread + g_neko_off_thread_active_handles) : NULL;
    int32_t dbg_top = dbg_block != NULL ? *(int32_t*)((char*)dbg_block + g_neko_off_jnih_block_top) : -1;
    void *dbg_oop = arr != NULL ? neko_handle_oop((jobject)arr) : NULL;
    jint dbg_len = dbg_oop != NULL ? *(jint*)((char*)dbg_oop + g_hotspot.primitive_array_base_offsets[NEKO_PRIM_I] - 4) : -1;
    fprintf(stderr, "[neko-direct] AALOAD direct path unavailable arr=%p idx=%d thread=%p init=%d bits=0x%x base=%d push=%d block=%p top=%d oop=%p len=%d\\n",
        (void*)arr, (int)idx, thread, (int)g_hotspot.initialized, (unsigned)g_hotspot.fast_bits,
        (int)g_hotspot.primitive_array_base_offsets[NEKO_PRIM_I], (int)g_neko_handle_push_ready,
        dbg_block, (int)dbg_top, dbg_oop, (int)dbg_len);
    abort();
}

NEKO_FAST_INLINE void neko_array_store_check(char *array_oop, jobject val) {
    void *value_oop;
    void *value_klass;
    void *element_klass;
    if (val == NULL) return;
    value_oop = neko_handle_oop(val);
    if (value_oop == NULL) {
        neko_abort_aastore_value_unresolved(val);
    }
    element_klass = neko_objarray_element_klass(array_oop);
    value_klass = neko_raw_oop_klass((char*)value_oop);
    if (!neko_klass_is_subtype_of(value_klass, element_klass)) {
        neko_abort_aastore_type_check_failed(value_klass, element_klass);
    }
}

NEKO_HOT_INLINE void *neko_load_object_array_slot(char *array_oop, size_t base, jint idx, size_t ref_size) {
    void *raw_oop;
    char *addr = array_oop + base + ((size_t)idx * ref_size);
    if (neko_const_compressed_oops_enabled()) {
        uint32_t narrow = *(uint32_t*)addr;
        raw_oop = narrow == 0u ? NULL : (void*)((uintptr_t)((uintptr_t)narrow << neko_const_compressed_oops_shift())
                   + (uintptr_t)neko_const_compressed_oops_base());
    } else {
        raw_oop = *(void**)addr;
    }
    return neko_barrier_load_oop_array(addr, raw_oop);
}

NEKO_HOT_INLINE void neko_fast_aastore(void *thread, JNIEnv *env, jobjectArray arr, jint idx, jobject val) {
    (void)env;
    char *__debug_oop = NULL;
    jint __debug_len = -1;
    if (NEKO_LIKELY(neko_const_initialized()
        && ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) != 0 || neko_const_use_zgc())
        && neko_const_prim_array_base(NEKO_PRIM_I) >= 0
        && arr != NULL)) {
        char *oop = (char*)neko_handle_oop((jobject)arr);
        __debug_oop = oop;
        if (NEKO_LIKELY(oop != NULL)) {
            size_t ref_size = neko_const_oop_ref_size();
            size_t base = (size_t)neko_const_prim_array_base(NEKO_PRIM_I);
            jint arrayLen = *(jint*)(oop + base - 4u);
            __debug_len = arrayLen;
            if (NEKO_LIKELY(idx >= 0 && idx < arrayLen)) {
                char *element_addr = oop + base + ((size_t)idx * ref_size);
                void *old_oop = neko_const_use_zgc() ? NULL : neko_load_object_array_slot(oop, base, idx, ref_size);
                void *value_oop = val == NULL ? NULL : neko_handle_oop(val);
                neko_array_store_check(oop, val);
                neko_barrier_pre_store_oop_field(thread, element_addr, old_oop);
                neko_store_oop_raw(oop, (jlong)(base + ((size_t)idx * ref_size)), value_oop);
                neko_barrier_post_store_oop_field(thread, element_addr);
                return;
            }
        }
    }
    neko_abort_fast_aastore_unavailable(arr, idx, __debug_oop, __debug_len);
}



NEKO_HOT_INLINE jobject neko_fast_aaload(void *thread, JNIEnv *env, jobjectArray arr, jint idx) {
    (void)env;
    if (NEKO_LIKELY(neko_const_initialized()
        && ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) != 0 || neko_const_use_zgc())
        && neko_const_prim_array_base(NEKO_PRIM_I) >= 0
        && arr != NULL)) {
        char *oop = (char*)neko_handle_oop((jobject)arr);
        if (NEKO_LIKELY(oop != NULL)) {
            jint arrayLen = *(jint*)(oop + neko_const_prim_array_base(NEKO_PRIM_I) - 4);
            if (NEKO_LIKELY(idx >= 0 && idx < arrayLen)) {
                void *element_oop;
                element_oop = neko_load_object_array_slot(
                    oop,
                    (size_t)neko_const_prim_array_base(NEKO_PRIM_I),
                    idx,
                    neko_const_oop_ref_size());
                return neko_direct_oop_to_handle_origin(thread, element_oop, NEKO_HANDLE_ORIGIN_AALOAD);
            }
        }
    }
    neko_abort_fast_aaload_unavailable(thread, arr, idx);
}

""");
        appendFusedAALoadHelpers(sb);
        appendObjectFieldFastHelpers(sb);
    }

    /**
     * Fast paths for object field reads (GETFIELD / GETSTATIC of L-types).
     * Skips the per-call JNI GetObjectField / GetStaticObjectField round-trip
     * by reading the field's narrow / wide oop slot directly off the receiver
     * (or static-base mirror) and inline-pushing the raw oop into the active
     * JNIHandleBlock — same trick the AALOAD fast path uses.
     *
     * Object writes use the same direct offset metadata, then run the
     * selected field store barrier for the active GC.
     */
    private static void appendObjectFieldFastHelpers(StringBuilder sb) {
        sb.append("""
static void __attribute__((cold, noinline)) neko_abort_object_getfield_unavailable(jobject obj, jlong offset, void *thread) {
    fprintf(stderr, "[neko-direct] object GETFIELD direct path unavailable obj=%p offset=%lld thread=%p\\n",
        (void*)obj, (long long)offset, thread);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_object_getstatic_unavailable(void *thread, jclass cls, jobject staticBase, jlong offset) {
    void *dbg_block = thread != NULL ? *(void**)((char*)thread + g_neko_off_thread_active_handles) : NULL;
    int32_t dbg_top = dbg_block != NULL ? *(int32_t*)((char*)dbg_block + g_neko_off_jnih_block_top) : -1;
    char *dbg_cls_oop = (char*)neko_static_base_oop((jobject)cls);
    char *dbg_base_oop = (char*)neko_static_base_oop(staticBase);
    uint32_t dbg_narrow = dbg_cls_oop != NULL && offset > 0 ? *(uint32_t*)(dbg_cls_oop + offset) : 0;
    void *dbg_wide = dbg_cls_oop != NULL && offset > 0 ? *(void**)(dbg_cls_oop + offset) : NULL;
    fprintf(stderr, "[neko-direct] object GETSTATIC direct path unavailable cls=%p base=%p offset=%lld thread=%p init=%d push=%d block=%p top=%d cap=%d cls_oop=%p base_oop=%p narrow=0x%x wide=%p compressed=%d\\n",
        (void*)cls, (void*)staticBase, (long long)offset, thread, (int)g_hotspot.initialized, (int)g_neko_handle_push_ready,
        dbg_block, (int)dbg_top, (int)g_neko_jnih_block_capacity, (void*)dbg_cls_oop, (void*)dbg_base_oop,
        (unsigned)dbg_narrow, dbg_wide, (int)g_hotspot.compressed_oops_enabled);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_object_putfield_unavailable(jobject obj, jlong offset, void *thread) {
    fprintf(stderr, "[neko-direct] object PUTFIELD direct path unavailable obj=%p offset=%lld thread=%p\\n",
        (void*)obj, (long long)offset, thread);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_object_putstatic_unavailable(jclass cls, jobject staticBase, jlong offset, void *thread) {
    fprintf(stderr, "[neko-direct] object PUTSTATIC direct path unavailable cls=%p base=%p offset=%lld thread=%p\\n",
        (void*)cls, (void*)staticBase, (long long)offset, thread);
    abort();
}

NEKO_FAST_INLINE jobject neko_fast_get_object_field(void *thread, JNIEnv *env, jobject obj, jfieldID fid, jlong offset) {
    (void)env; (void)fid;
    if (g_hotspot.initialized
        && offset > 0
        && obj != NULL) {
        char *receiver_oop = (char*)neko_handle_oop(obj);
        if (receiver_oop != NULL) {
            void *element_oop;
            char *field_addr = receiver_oop + offset;
            if (g_hotspot.compressed_oops_enabled) {
                element_oop = neko_decode_narrow_oop(*(uint32_t*)field_addr);
            } else {
                element_oop = *(void**)field_addr;
            }
            element_oop = neko_barrier_load_oop_field(field_addr, element_oop);
            return neko_direct_oop_to_handle_origin(thread, element_oop, NEKO_HANDLE_ORIGIN_OBJECT_FIELD);
        }
    }
    neko_abort_object_getfield_unavailable(obj, offset, thread);
}

NEKO_FAST_INLINE jobject neko_fast_get_static_object_field(void *thread, JNIEnv *env, jclass cls, jfieldID fid, jobject staticBase, jlong offset) {
    (void)env; (void)cls; (void)fid;
    if (g_hotspot.initialized
        && offset > 0
        && staticBase != NULL) {
        char *base_oop = (char*)neko_static_base_oop((jobject)cls);
        if (base_oop == NULL) base_oop = (char*)neko_static_base_oop(staticBase);
        if (base_oop != NULL) {
            void *element_oop;
            char *field_addr = base_oop + offset;
            if (g_hotspot.compressed_oops_enabled) {
                element_oop = neko_decode_narrow_oop(*(uint32_t*)field_addr);
            } else {
                element_oop = *(void**)field_addr;
            }
            element_oop = neko_barrier_load_oop_field(field_addr, element_oop);
            return neko_direct_oop_to_handle_origin(thread, element_oop, NEKO_HANDLE_ORIGIN_STATIC_OBJECT_FIELD);
        }
    }
    neko_abort_object_getstatic_unavailable(thread, cls, staticBase, offset);
}

NEKO_FAST_INLINE jobject neko_fast_get_static_object_field_ref(void *thread, JNIEnv *env, const neko_static_field_ref *ref) {
    jclass cls = neko_static_field_ref_class(env, ref);
    jfieldID fid = neko_static_field_ref_field(env, ref);
    return neko_fast_get_static_object_field(thread, env, cls, fid, *(ref->static_base_slot), *(ref->static_offset_slot));
}

NEKO_HOT_INLINE jint neko_fast_string_length(jstring str, jlong valueOffset, jlong coderOffset) {
    char *string_oop;
    char *value_addr;
    void *value_oop;
    jint byte_len;
    jbyte coder;
    if (NEKO_UNLIKELY(!neko_const_initialized()
        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())
        || neko_const_array_length_offset() < 0
        || valueOffset <= 0
        || coderOffset <= 0
        || str == NULL)) {
        fprintf(stderr, "[neko-direct] String.length direct path unavailable str=%p valueOffset=%lld coderOffset=%lld\\n",
            (void*)str, (long long)valueOffset, (long long)coderOffset);
        abort();
    }
    string_oop = (char*)neko_handle_oop((jobject)str);
    if (NEKO_UNLIKELY(string_oop == NULL)) {
        fprintf(stderr, "[neko-direct] String.length receiver handle unresolved str=%p\\n", (void*)str);
        abort();
    }
    value_addr = string_oop + valueOffset;
    if (g_hotspot.compressed_oops_enabled) {
        value_oop = neko_decode_narrow_oop(*(uint32_t*)value_addr);
    } else {
        value_oop = *(void**)value_addr;
    }
    value_oop = neko_barrier_load_oop_field(value_addr, value_oop);
    if (NEKO_UNLIKELY(value_oop == NULL)) {
        fprintf(stderr, "[neko-direct] String.length value array unresolved str=%p\\n", (void*)str);
        abort();
    }
    byte_len = *(jint*)((char*)value_oop + neko_const_array_length_offset());
    coder = *(jbyte*)(string_oop + coderOffset);
    return byte_len >> ((jint)((uint8_t)coder) & 1);
}

NEKO_FAST_INLINE void neko_fast_set_object_field(void *thread, JNIEnv *env, jobject obj, jfieldID fid, jlong offset, jobject val) {
    (void)env; (void)fid;
    if (g_hotspot.initialized
        && offset > 0
        && obj != NULL) {
        char *receiver_oop = (char*)neko_handle_oop(obj);
        if (receiver_oop != NULL) {
            void *old_oop;
            void *value_oop = val == NULL ? NULL : neko_handle_oop(val);
            char *field_addr = receiver_oop + offset;
            if (g_hotspot.compressed_oops_enabled) {
                old_oop = neko_decode_narrow_oop(*(uint32_t*)field_addr);
            } else {
                old_oop = *(void**)field_addr;
            }
            neko_barrier_pre_store_oop_field(thread, field_addr, old_oop);
            neko_store_oop_raw(receiver_oop, offset, value_oop);
            neko_barrier_post_store_oop_field(thread, field_addr);
            return;
        }
    }
    neko_abort_object_putfield_unavailable(obj, offset, thread);
}

NEKO_FAST_INLINE void neko_fast_set_static_object_field(void *thread, JNIEnv *env, jclass cls, jfieldID fid, jobject staticBase, jlong offset, jobject val) {
    (void)env; (void)cls; (void)fid;
    if (g_hotspot.initialized
        && offset > 0
        && staticBase != NULL) {
        char *base_oop = (char*)neko_static_base_oop((jobject)cls);
        if (base_oop == NULL) base_oop = (char*)neko_static_base_oop(staticBase);
        if (base_oop != NULL) {
            void *old_oop;
            void *value_oop = val == NULL ? NULL : neko_handle_oop(val);
            char *field_addr = base_oop + offset;
            if (g_hotspot.compressed_oops_enabled) {
                old_oop = neko_decode_narrow_oop(*(uint32_t*)field_addr);
            } else {
                old_oop = *(void**)field_addr;
            }
            neko_barrier_pre_store_oop_field(thread, field_addr, old_oop);
            neko_store_oop_raw(base_oop, offset, value_oop);
            neko_barrier_post_store_oop_field(thread, field_addr);
            return;
        }
    }
    neko_abort_object_putstatic_unavailable(cls, staticBase, offset, thread);
}


""");
    }

    /**
     * Fused AALOAD + primitive *ALOAD helper: skips the JNIHandle allocation
     * for the intermediate inner-array reference, since the inner oop is only
     * used immediately within this single inline function.
     *
     * Hot path for matrix-style nested arrays (a[i][k]) — eliminates 100% of
     * per-iteration handle allocs in the inner loop.
     */
    private static void appendFusedAALoadHelpers(StringBuilder sb) {
        sb.append("""
#define NEKO_FAST_ARRAY_OK 0
#define NEKO_FAST_ARRAY_OUTER_NULL 1
#define NEKO_FAST_ARRAY_OUTER_BOUNDS 2
#define NEKO_FAST_ARRAY_INNER_NULL 3
#define NEKO_FAST_ARRAY_INNER_BOUNDS 4

static void __attribute__((cold, noinline)) neko_abort_checked_aaload_layout(jobjectArray arr, jint idx, void *thread) {
    fprintf(stderr, "[neko-direct] checked AALOAD layout unavailable arr=%p idx=%d thread=%p\\n", (void*)arr, (int)idx, thread);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_checked_aaload_handle(jobjectArray arr, jint idx) {
    fprintf(stderr, "[neko-direct] checked AALOAD handle unresolved arr=%p idx=%d\\n", (void*)arr, (int)idx);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_checked_aastore_layout(jobjectArray arr, jint idx, void *thread) {
    fprintf(stderr, "[neko-direct] checked AASTORE layout unavailable arr=%p idx=%d thread=%p\\n", (void*)arr, (int)idx, thread);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_checked_aastore_handle(jobjectArray arr, jint idx) {
    fprintf(stderr, "[neko-direct] checked AASTORE handle unresolved arr=%p idx=%d\\n", (void*)arr, (int)idx);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_fused_aaload_aaload_layout(jobjectArray outer, jint idx1, jint idx2, void *thread) {
    fprintf(stderr, "[neko-direct] AALOAD+AALOAD layout unavailable outer=%p idx1=%d idx2=%d thread=%p\\n", (void*)outer, (int)idx1, (int)idx2, thread);
    abort();
}

static void __attribute__((cold, noinline)) neko_abort_fused_aaload_aaload_outer_handle(jobjectArray outer) {
    fprintf(stderr, "[neko-direct] AALOAD+AALOAD outer handle unresolved outer=%p\\n", (void*)outer);
    abort();
}

NEKO_HOT_INLINE jboolean neko_checked_aaload(void *thread, JNIEnv *env, jobjectArray arr, jint idx, jobject *out, int *reason) {
    (void)env;
    if (out != NULL) *out = NULL;
    if (arr == NULL) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_NULL; return JNI_FALSE; }
    if (NEKO_UNLIKELY(!neko_const_initialized()
        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())
        || neko_const_prim_array_base(NEKO_PRIM_I) < 0
        || thread == NULL)) {
        neko_abort_checked_aaload_layout(arr, idx, thread);
    }
    char *oop = (char*)neko_handle_oop((jobject)arr);
    if (NEKO_UNLIKELY(oop == NULL)) {
        neko_abort_checked_aaload_handle(arr, idx);
    }
    size_t base = (size_t)neko_const_prim_array_base(NEKO_PRIM_I);
    jint len = *(jint*)(oop + base - 4u);
    if (NEKO_UNLIKELY(idx < 0 || idx >= len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_BOUNDS; return JNI_FALSE; }
    void *element_oop = neko_load_object_array_slot(oop, base, idx, neko_const_oop_ref_size());
    if (out != NULL) *out = neko_direct_oop_to_handle_origin(thread, element_oop, NEKO_HANDLE_ORIGIN_CHECKED_AALOAD);
    return JNI_TRUE;
}

NEKO_HOT_INLINE jboolean neko_checked_aastore(void *thread, JNIEnv *env, jobjectArray arr, jint idx, jobject val, int *reason) {
    (void)env;
    if (arr == NULL) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_NULL; return JNI_FALSE; }
    if (NEKO_UNLIKELY(!neko_const_initialized()
        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())
        || neko_const_prim_array_base(NEKO_PRIM_I) < 0
        || thread == NULL)) {
        neko_abort_checked_aastore_layout(arr, idx, thread);
    }
    char *oop = (char*)neko_handle_oop((jobject)arr);
    if (NEKO_UNLIKELY(oop == NULL)) {
        neko_abort_checked_aastore_handle(arr, idx);
    }
    size_t ref_size = neko_const_oop_ref_size();
    size_t base = (size_t)neko_const_prim_array_base(NEKO_PRIM_I);
    jint len = *(jint*)(oop + base - 4u);
    if (NEKO_UNLIKELY(idx < 0 || idx >= len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_BOUNDS; return JNI_FALSE; }
    char *element_addr = oop + base + ((size_t)idx * ref_size);
    void *old_oop = neko_const_use_zgc() ? NULL : neko_load_object_array_slot(oop, base, idx, ref_size);
    void *value_oop = val == NULL ? NULL : neko_handle_oop(val);
    neko_array_store_check(oop, val);
    neko_barrier_pre_store_oop_field(thread, element_addr, old_oop);
    neko_store_oop_raw(oop, (jlong)(base + ((size_t)idx * ref_size)), value_oop);
    neko_barrier_post_store_oop_field(thread, element_addr);
    return JNI_TRUE;
}

""");
        appendCheckedPrimArrayLoad(sb, "b", "jbyte",  "NEKO_PRIM_B", "jbyteArray");
        appendCheckedPrimArrayLoad(sb, "c", "jchar",  "NEKO_PRIM_C", "jcharArray");
        appendCheckedPrimArrayLoad(sb, "s", "jshort", "NEKO_PRIM_S", "jshortArray");
        appendCheckedPrimArrayLoad(sb, "i", "jint",   "NEKO_PRIM_I", "jintArray");
        appendCheckedPrimArrayLoad(sb, "l", "jlong",  "NEKO_PRIM_J", "jlongArray");
        appendCheckedPrimArrayLoad(sb, "f", "jfloat", "NEKO_PRIM_F", "jfloatArray");
        appendCheckedPrimArrayLoad(sb, "d", "jdouble","NEKO_PRIM_D", "jdoubleArray");
        appendCheckedPrimArrayStore(sb, "b", "jbyte",  "NEKO_PRIM_B", "jbyteArray");
        appendCheckedPrimArrayStore(sb, "c", "jchar",  "NEKO_PRIM_C", "jcharArray");
        appendCheckedPrimArrayStore(sb, "s", "jshort", "NEKO_PRIM_S", "jshortArray");
        appendCheckedPrimArrayStore(sb, "i", "jint",   "NEKO_PRIM_I", "jintArray");
        appendCheckedPrimArrayStore(sb, "l", "jlong",  "NEKO_PRIM_J", "jlongArray");
        appendCheckedPrimArrayStore(sb, "f", "jfloat", "NEKO_PRIM_F", "jfloatArray");
        appendCheckedPrimArrayStore(sb, "d", "jdouble","NEKO_PRIM_D", "jdoubleArray");
        appendFusedAALoadPrim(sb, "b", "jbyte",  "NEKO_PRIM_B", "byte",   "jbyteArray");
        appendFusedAALoadPrim(sb, "c", "jchar",  "NEKO_PRIM_C", "char",   "jcharArray");
        appendFusedAALoadPrim(sb, "s", "jshort", "NEKO_PRIM_S", "short",  "jshortArray");
        appendFusedAALoadPrim(sb, "i", "jint",   "NEKO_PRIM_I", "int",    "jintArray");
        appendFusedAALoadPrim(sb, "l", "jlong",  "NEKO_PRIM_J", "long",   "jlongArray");
        appendFusedAALoadPrim(sb, "f", "jfloat", "NEKO_PRIM_F", "float",  "jfloatArray");
        appendFusedAALoadPrim(sb, "d", "jdouble","NEKO_PRIM_D", "double", "jdoubleArray");
        sb.append("""
NEKO_HOT_INLINE jobject neko_fast_aaload_aaload(void *thread, JNIEnv *env, jobjectArray outer, jint idx1, jint idx2, int *reason) {
    (void)env;
    if (NEKO_UNLIKELY(!neko_const_initialized()
        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())
        || neko_const_prim_array_base(NEKO_PRIM_I) < 0
        || thread == NULL)) {
        neko_abort_fused_aaload_aaload_layout(outer, idx1, idx2, thread);
    }
    if (outer == NULL) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_NULL; return NULL; }
    char *outer_oop = (char*)neko_handle_oop((jobject)outer);
    if (NEKO_UNLIKELY(outer_oop == NULL)) {
        neko_abort_fused_aaload_aaload_outer_handle(outer);
    }
    jint outer_len = *(jint*)(outer_oop + neko_const_prim_array_base(NEKO_PRIM_I) - 4);
    if (NEKO_UNLIKELY(idx1 < 0 || idx1 >= outer_len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_BOUNDS; return NULL; }
    char *inner_oop = (char*)neko_load_object_array_slot(outer_oop, (size_t)neko_const_prim_array_base(NEKO_PRIM_I), idx1, neko_const_oop_ref_size());
    if (NEKO_UNLIKELY(inner_oop == NULL)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_INNER_NULL; return NULL; }
    jint inner_len = *(jint*)(inner_oop + neko_const_prim_array_base(NEKO_PRIM_I) - 4);
    if (NEKO_UNLIKELY(idx2 < 0 || idx2 >= inner_len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_INNER_BOUNDS; return NULL; }
    void *element_oop;
    element_oop = neko_load_object_array_slot(
        inner_oop,
        (size_t)neko_const_prim_array_base(NEKO_PRIM_I),
        idx2,
        neko_const_oop_ref_size());
    return neko_direct_oop_to_handle_origin(thread, element_oop, NEKO_HANDLE_ORIGIN_FUSED_AALOAD_AALOAD);
}

/* Cold + noinline: the fused-aaload error dispatch is only reached on a
 * NULL outer/inner array or out-of-bounds index. Keeping the dispatcher
 * out-of-line lets the hot AALOAD+XALOAD chain stay tight. */
__attribute__((cold, noinline))
static void neko_raise_fast_array_reason(void *thread, JNIEnv *env, int reason,
    jclass npe_cls, void *npe_method, void *npe_entry, neko_njx_dispatcher_t npe_dispatcher,
    jclass aioobe_cls, void *aioobe_method, void *aioobe_entry, neko_njx_dispatcher_t aioobe_dispatcher) {
    if (reason == NEKO_FAST_ARRAY_OUTER_NULL || reason == NEKO_FAST_ARRAY_INNER_NULL) {
        neko_raise_implicit_exception(thread, env, npe_cls, npe_method, npe_entry, npe_dispatcher, "java/lang/NullPointerException");
    } else if (reason == NEKO_FAST_ARRAY_OUTER_BOUNDS || reason == NEKO_FAST_ARRAY_INNER_BOUNDS) {
        neko_raise_implicit_exception(thread, env, aioobe_cls, aioobe_method, aioobe_entry, aioobe_dispatcher, "java/lang/ArrayIndexOutOfBoundsException");
    } else {
        fprintf(stderr, "[neko-direct] unexpected fast array failure reason=%d\\n", reason);
        abort();
    }
}

""");
    }

    private static void appendCheckedPrimArrayLoad(StringBuilder sb, String prefix, String cType, String elemKind, String jArrayType) {
        sb.append("__attribute__((visibility(\"hidden\"))) jboolean neko_checked_").append(prefix)
            .append("aload(void *thread, JNIEnv *env, ").append(jArrayType).append(" arr, jint idx, ")
            .append(cType).append(" *out, int *reason) {\n")
            .append("    (void)thread;\n")
            .append("    (void)env;\n")
            .append("    if (arr == NULL) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_NULL; return JNI_FALSE; }\n")
            .append("    if (NEKO_UNLIKELY(!neko_const_initialized()\n")
            .append("        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())\n")
            .append("        || neko_const_array_length_offset() < 0\n")
            .append("        || neko_const_prim_array_base(").append(elemKind).append(") < 0\n")
            .append("        || neko_const_prim_array_scale(").append(elemKind).append(") <= 0)) {\n")
            .append("        fprintf(stderr, \"[neko-direct] checked ").append(prefix).append("ALOAD layout unavailable arr=%p idx=%d\\n\", (void*)arr, (int)idx); abort();\n")
            .append("    }\n")
            .append("    char *oop = (char*)neko_handle_oop((jobject)arr);\n")
            .append("    if (NEKO_UNLIKELY(oop == NULL)) { fprintf(stderr, \"[neko-direct] checked ").append(prefix).append("ALOAD handle unresolved arr=%p idx=%d\\n\", (void*)arr, (int)idx); abort(); }\n")
            .append("    jint len = *(jint*)(oop + neko_const_array_length_offset());\n")
            .append("    if (NEKO_UNLIKELY(idx < 0 || idx >= len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_BOUNDS; return JNI_FALSE; }\n")
            .append("    char *addr = oop + neko_const_prim_array_base(").append(elemKind).append(") + ((jlong)idx * neko_const_prim_array_scale(").append(elemKind).append("));\n")
            .append("    *out = *(").append(cType).append("*)addr;\n")
            .append("    return JNI_TRUE;\n")
            .append("}\n\n");
    }

    private static void appendCheckedPrimArrayStore(StringBuilder sb, String prefix, String cType, String elemKind, String jArrayType) {
        sb.append("NEKO_HOT_INLINE jboolean neko_checked_").append(prefix)
            .append("astore(void *thread, JNIEnv *env, ").append(jArrayType).append(" arr, jint idx, ")
            .append(cType).append(" value, int *reason) {\n")
            .append("    (void)thread;\n")
            .append("    (void)env;\n")
            .append("    if (arr == NULL) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_NULL; return JNI_FALSE; }\n")
            .append("    if (NEKO_UNLIKELY(!neko_const_initialized()\n")
            .append("        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())\n")
            .append("        || neko_const_array_length_offset() < 0\n")
            .append("        || neko_const_prim_array_base(").append(elemKind).append(") < 0\n")
            .append("        || neko_const_prim_array_scale(").append(elemKind).append(") <= 0)) {\n")
            .append("        fprintf(stderr, \"[neko-direct] checked ").append(prefix).append("ASTORE layout unavailable arr=%p idx=%d\\n\", (void*)arr, (int)idx); abort();\n")
            .append("    }\n")
            .append("    char *oop = (char*)neko_handle_oop((jobject)arr);\n")
            .append("    if (NEKO_UNLIKELY(oop == NULL)) { fprintf(stderr, \"[neko-direct] checked ").append(prefix).append("ASTORE handle unresolved arr=%p idx=%d\\n\", (void*)arr, (int)idx); abort(); }\n")
            .append("    jint len = *(jint*)(oop + neko_const_array_length_offset());\n")
            .append("    if (NEKO_UNLIKELY(idx < 0 || idx >= len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_BOUNDS; return JNI_FALSE; }\n")
            .append("    char *addr = oop + neko_const_prim_array_base(").append(elemKind).append(") + ((jlong)idx * neko_const_prim_array_scale(").append(elemKind).append("));\n")
            .append("    *(").append(cType).append("*)addr = value;\n")
            .append("    return JNI_TRUE;\n")
            .append("}\n\n");
    }

    private static void appendFusedAALoadPrim(
        StringBuilder sb, String prefix, String cType, String elemKind, String wrapperStem, String jArrayType
    ) {
        sb.append("NEKO_HOT_INLINE ").append(cType).append(" neko_fast_aaload_").append(prefix)
            .append("aload(void *thread, JNIEnv *env, jobjectArray outer, jint idx1, jint idx2, int *reason) {\n")
            .append("    (void)thread;\n")
            .append("    (void)env;\n")
            .append("    if (NEKO_UNLIKELY(!neko_const_initialized()\n")
            .append("        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())\n")
            .append("        || neko_const_prim_array_base(NEKO_PRIM_I) < 0)) {\n")
            .append("        fprintf(stderr, \"[neko-direct] AALOAD+").append(prefix).append("ALOAD layout unavailable outer=%p idx1=%d idx2=%d\\n\", (void*)outer, (int)idx1, (int)idx2); abort();\n")
            .append("    }\n")
            .append("    if (outer == NULL) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_NULL; return (").append(cType).append(")0; }\n")
            .append("    char *outer_oop = (char*)neko_handle_oop((jobject)outer);\n")
            .append("    if (NEKO_UNLIKELY(outer_oop == NULL)) { fprintf(stderr, \"[neko-direct] AALOAD+").append(prefix).append("ALOAD outer handle unresolved outer=%p\\n\", (void*)outer); abort(); }\n")
            .append("    jint outer_len = *(jint*)(outer_oop + neko_const_prim_array_base(NEKO_PRIM_I) - 4);\n")
            .append("    if (NEKO_UNLIKELY(idx1 < 0 || idx1 >= outer_len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_BOUNDS; return (").append(cType).append(")0; }\n")
            .append("    char *inner_oop = (char*)neko_load_object_array_slot(outer_oop, (size_t)neko_const_prim_array_base(NEKO_PRIM_I), idx1, neko_const_oop_ref_size());\n")
            .append("    if (NEKO_UNLIKELY(inner_oop == NULL)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_INNER_NULL; return (").append(cType).append(")0; }\n")
            .append("    jint inner_len = *(jint*)(inner_oop + neko_const_prim_array_base(").append(elemKind).append(") - 4);\n")
            .append("    if (NEKO_UNLIKELY(idx2 < 0 || idx2 >= inner_len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_INNER_BOUNDS; return (").append(cType).append(")0; }\n")
            .append("    char *addr = inner_oop + neko_const_prim_array_base(").append(elemKind).append(") + ((jlong)idx2 * neko_const_prim_array_scale(").append(elemKind).append("));\n")
            .append("    return *(").append(cType).append("*)addr;\n")
            .append("}\n\n");
        sb.append("NEKO_HOT_INLINE ").append(cType).append(" neko_fast_raw_aaload_").append(prefix)
            .append("aload(void *outer_raw_oop, jint idx1, jint idx2, int *reason) {\n")
            .append("    if (NEKO_UNLIKELY(!neko_const_initialized()\n")
            .append("        || ((neko_const_fast_bits() & NEKO_FAST_PRIM_ARRAY) == 0 && !neko_const_use_zgc())\n")
            .append("        || neko_const_prim_array_base(NEKO_PRIM_I) < 0)) {\n")
            .append("        fprintf(stderr, \"[neko-direct] raw AALOAD+").append(prefix).append("ALOAD layout unavailable outer=%p idx1=%d idx2=%d\\n\", outer_raw_oop, (int)idx1, (int)idx2); abort();\n")
            .append("    }\n")
            .append("    if (outer_raw_oop == NULL) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_NULL; return (").append(cType).append(")0; }\n")
            .append("    char *outer_oop = (char*)neko_zgc_good_oop(outer_raw_oop);\n")
            .append("    jint outer_len = *(jint*)(outer_oop + neko_const_prim_array_base(NEKO_PRIM_I) - 4);\n")
            .append("    if (NEKO_UNLIKELY(idx1 < 0 || idx1 >= outer_len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_OUTER_BOUNDS; return (").append(cType).append(")0; }\n")
            .append("    char *inner_oop = (char*)neko_load_object_array_slot(outer_oop, (size_t)neko_const_prim_array_base(NEKO_PRIM_I), idx1, neko_const_oop_ref_size());\n")
            .append("    if (NEKO_UNLIKELY(inner_oop == NULL)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_INNER_NULL; return (").append(cType).append(")0; }\n")
            .append("    jint inner_len = *(jint*)(inner_oop + neko_const_prim_array_base(").append(elemKind).append(") - 4);\n")
            .append("    if (NEKO_UNLIKELY(idx2 < 0 || idx2 >= inner_len)) { if (reason != NULL) *reason = NEKO_FAST_ARRAY_INNER_BOUNDS; return (").append(cType).append(")0; }\n")
            .append("    char *addr = inner_oop + neko_const_prim_array_base(").append(elemKind).append(") + ((jlong)idx2 * neko_const_prim_array_scale(").append(elemKind).append("));\n")
            .append("    return *(").append(cType).append("*)addr;\n")
            .append("}\n\n");
    }


}
