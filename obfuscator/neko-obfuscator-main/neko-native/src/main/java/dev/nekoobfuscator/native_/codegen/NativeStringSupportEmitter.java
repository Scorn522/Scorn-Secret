package dev.nekoobfuscator.native_.codegen;

/**
 * Emits native StringTable intern and String.concat direct-call cache support.
 */
final class NativeStringSupportEmitter {
    private NativeStringSupportEmitter() {}

    /**
     * TLAB-NULL fix — emit the String.concat NJX cache helper. Lives
     * outside renderBindSupport because that text block already approaches
     * the JVM 65535-byte string-literal constant pool limit; appending
     * here directly would exceed it. The helper calls into resolvers
     * defined in renderBindSupport (neko_resolve_method,
     * neko_bound_method_i_entry) which are visible by the time this
     * render method is appended.
     */
    static String renderStringTableInternSupport() {
        return """
static void *neko_intern_string_without_raw_heap(void *thread, JNIEnv *env, const char *modutf, size_t len) {
    typedef void *(*neko_stringtable_intern_utf8_t)(const char*, void*);
    void *interned_oop;
    void *string_klass;
    jclass string_mirror;
    neko_field_resolution_t value_field;
    neko_field_resolution_t coder_field;
    neko_utf8_shape_t shape;
    size_t payload_bytes;
    jarray local_array;
    char *array_oop;
    char *string_oop;
    jstring local_string;
    jstring interned;
    neko_handle_save_t handle_window;
    jvalue alloc_arg;
    jvalue alloc_result;
    void *ctor_method;
    jvalue ctor_args[2];
    if (thread == NULL || env == NULL || modutf == NULL) {
        fprintf(stderr, "[neko-bind] raw-disabled string intern missing input thread=%p env=%p modutf=%p\\n",
            thread, (void*)env, (const void*)modutf);
        abort();
    }
    if (!g_hotspot.initialized || g_hotspot.use_compact_object_headers) {
        fprintf(stderr, "[neko-bind] raw-disabled string intern layout unavailable init=%d coh=%d len=%zu\\n",
            (int)g_hotspot.initialized, (int)g_hotspot.use_compact_object_headers, len);
        abort();
    }
    if (g_neko_method_layout.sym_stringtable_intern_utf8 != NULL) {
        interned_oop = ((neko_stringtable_intern_utf8_t)g_neko_method_layout.sym_stringtable_intern_utf8)(
            modutf, thread);
        if (interned_oop == NULL || neko_exception_check(env)) {
            if (neko_exception_check(env)) neko_exception_clear_direct(env);
            fprintf(stderr, "[neko-bind] StringTable::intern UTF-8 failed for string literal len=%zu\\n", len);
            abort();
        }
        return neko_zgc_good_oop(interned_oop);
    }
    if (g_neko_method_layout.sym_jvm_intern_string == NULL) {
        fprintf(stderr, "[neko-bind] raw-disabled string intern symbols unavailable stringtable_utf8=0 jvm_intern=0 len=%zu\\n", len);
        abort();
    }
    if (g_hotspot.primitive_array_base_offsets[NEKO_PRIM_B] < 0) {
        fprintf(stderr, "[neko-bind] raw-disabled string intern byte[] layout unavailable base=%d len=%zu\\n",
            (int)g_hotspot.primitive_array_base_offsets[NEKO_PRIM_B], len);
        abort();
    }
    shape = neko_utf8_shape((const uint8_t*)modutf, len);
    payload_bytes = shape.latin1 ? shape.latin1_bytes : shape.utf16_units * 2u;
    if (payload_bytes > (size_t)INT32_MAX) {
        fprintf(stderr, "[neko-bind] string literal too large for raw-disabled intern len=%zu payload=%zu\\n", len, payload_bytes);
        abort();
    }
    neko_handle_window_begin(thread, &handle_window);
    string_mirror = neko_resolve_class_mirror_with_env(env, "java/lang/String", NULL, &string_klass);
    if (string_mirror == NULL || string_klass == NULL) {
        fprintf(stderr, "[neko-bind] raw-disabled string intern String mirror unavailable len=%zu\\n", len);
        abort();
    }
    value_field = neko_resolve_field(string_klass, "value", "[B", JNI_FALSE);
    coder_field = neko_resolve_field(string_klass, "coder", "B", JNI_FALSE);
    if (!value_field.found || !coder_field.found || value_field.offset == 0 || coder_field.offset == 0) {
        fprintf(stderr, "[neko-bind] raw-disabled string intern String value/coder metadata unavailable value=%d/%u coder=%d/%u\\n",
            (int)value_field.found, value_field.offset, (int)coder_field.found, coder_field.offset);
        abort();
    }
    neko_ensure_string_concat_njx_cache(env, string_klass);
    if (!g_neko_unsafe_allocate_instance_ready) {
        neko_ensure_unsafe_allocate_instance_njx_cache(env);
    }
    if (!g_neko_unsafe_allocate_instance_ready
        || g_neko_unsafe_instance_global == NULL
        || g_neko_unsafe_allocate_instance_method == NULL
        || g_neko_unsafe_allocate_instance_entry == NULL) {
        fprintf(stderr, "[neko-bind] raw-disabled string intern Unsafe.allocateInstance cache unavailable ready=%d unsafe=%p method=%p entry=%p\\n",
            (int)g_neko_unsafe_allocate_instance_ready, (void*)g_neko_unsafe_instance_global,
            g_neko_unsafe_allocate_instance_method, g_neko_unsafe_allocate_instance_entry);
        abort();
    }
    alloc_arg.l = (jobject)string_mirror;
    alloc_result = neko_njx_V_L_L(thread, env,
        g_neko_unsafe_allocate_instance_method,
        g_neko_unsafe_allocate_instance_entry,
        g_neko_unsafe_instance_global, &alloc_arg);
    if (alloc_result.l == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] raw-disabled string intern Unsafe.allocateInstance failed len=%zu\\n", len);
        abort();
    }
    local_string = (jstring)alloc_result.l;
    local_array = NULL;
    array_oop = neko_alloc_jbyte_array_oop_slow(env, (jint)payload_bytes, &local_array);
    string_oop = (char*)neko_handle_oop((jobject)local_string);
    if (array_oop == NULL || string_oop == NULL || local_array == NULL) {
        fprintf(stderr, "[neko-bind] raw-disabled string intern allocation handle unresolved array=%p local_array=%p string=%p local_string=%p len=%zu\\n",
            (void*)array_oop, (void*)local_array, (void*)string_oop, (void*)local_string, len);
        abort();
    }
    neko_fill_string_bytes((uint8_t*)array_oop + g_hotspot.primitive_array_base_offsets[NEKO_PRIM_B],
        (const uint8_t*)modutf, len, shape.latin1);
    if (!g_neko_string_byte_coder_ctor_ready
        || g_neko_string_byte_coder_ctor_method == NULL
        || g_neko_string_byte_coder_ctor_entry == NULL) {
        neko_link_class_methods(env, string_mirror, "java/lang/String", "<init>", "([BB)V");
        ctor_method = neko_resolve_method(string_klass, "<init>", "([BB)V");
        if (ctor_method == NULL) {
            fprintf(stderr, "[neko-bind] raw-disabled string intern String(byte[],byte) constructor unavailable len=%zu\\n", len);
            abort();
        }
        g_neko_string_byte_coder_ctor_method = ctor_method;
        g_neko_string_byte_coder_ctor_entry = neko_bound_method_i_entry(ctor_method,
            &g_neko_string_byte_coder_ctor_entry, "java/lang/String", "<init>", "([BB)V");
        if (g_neko_string_byte_coder_ctor_entry == NULL) {
            fprintf(stderr, "[neko-bind] raw-disabled string intern String(byte[],byte) entry unavailable len=%zu\\n", len);
            abort();
        }
        g_neko_string_byte_coder_ctor_ready = JNI_TRUE;
    }
    ctor_args[0].l = (jobject)local_array;
    ctor_args[1].i = shape.latin1 ? 0 : 1;
    (void)neko_njx_V_V_LI(thread, env,
        g_neko_string_byte_coder_ctor_method,
        g_neko_string_byte_coder_ctor_entry,
        local_string, ctor_args);
    if (neko_exception_check(env)) {
        neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] raw-disabled string intern String(byte[],byte) constructor failed len=%zu\\n", len);
        abort();
    }
    interned = ((neko_jvm_intern_string_t)g_neko_method_layout.sym_jvm_intern_string)(env, local_string);
    if (interned == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] JVM_InternString failed for raw-disabled string literal len=%zu\\n", len);
        abort();
    }
    interned_oop = neko_prepare_return_oop(thread, interned, "intern_string_without_raw_heap");
    neko_handle_window_end(&handle_window);
    return interned_oop;
}
""";
    }

    static String renderStringConcatNjxCache() {
        return """
static void neko_ensure_string_concat_njx_cache(JNIEnv *env, void *string_klass) {
    if (g_neko_string_concat_ready) return;
    if (string_klass == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: String Klass unavailable for concat NJX cache\\n");
        abort();
    }
    void *concat_method = neko_resolve_method(string_klass, "concat",
        "(Ljava/lang/String;)Ljava/lang/String;");
    if (concat_method == NULL) {
        fprintf(stderr, "[neko-bind] String.concat(String) Method* unavailable\\n");
        abort();
    }
    g_neko_string_concat_method = concat_method;
    g_neko_string_concat_entry = neko_bound_method_i_entry(concat_method,
        &g_neko_string_concat_entry, "java/lang/String", "concat",
        "(Ljava/lang/String;)Ljava/lang/String;");
    if (g_neko_string_concat_entry == NULL) {
        fprintf(stderr, "[neko-bind] String.concat(String) entry pointer unavailable\\n");
        abort();
    }
    (void)env;
    g_neko_string_concat_ready = JNI_TRUE;
    if (getenv("NEKO_PATCH_DEBUG") != NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: String.concat NJX cache ready method=%p entry=%p\\n",
            g_neko_string_concat_method, g_neko_string_concat_entry);
    }
}

/* TLAB-NULL fix for NEW: cache jdk.internal.misc.Unsafe.allocateInstance
 * (Class<?>)Object — bare-instance allocation that delegates to HotSpot's
 * managed allocator. theInternalUnsafe is read from the static slot via
 * the same direct-static-field machinery T4.2c uses for IMPL_LOOKUP. */
static void neko_ensure_unsafe_allocate_instance_njx_cache(JNIEnv *env) {
    if (g_neko_unsafe_allocate_instance_ready) return;
    if (env == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: Unsafe NJX cache requires JNIEnv*\\n");
        abort();
    }
    /* Resolve jdk.internal.misc.Unsafe class and the theInternalUnsafe
     * static field. */
    void *unsafe_klass = neko_resolve_class_with_env(env,
        "jdk/internal/misc/Unsafe", NULL);
    if (unsafe_klass == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: jdk.internal.misc.Unsafe Klass unavailable\\n");
        abort();
    }
    neko_ensure_class_initialized(env,
        (jclass)neko_klass_java_mirror_handle(neko_jni_env_to_thread(env), unsafe_klass),
        "jdk/internal/misc/Unsafe");
    neko_field_resolution_t the_unsafe = neko_resolve_field(unsafe_klass,
        "theUnsafe", "Ljdk/internal/misc/Unsafe;", JNI_TRUE);
    if (!the_unsafe.found || !the_unsafe.is_static || the_unsafe.offset == 0u) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: Unsafe.theUnsafe field unavailable (found=%d static=%d off=%u)\\n",
            (int)the_unsafe.found, (int)the_unsafe.is_static, the_unsafe.offset);
        abort();
    }
    /* Read the static field through the wrapper Class oop's static area.
     * jclass mirror reuses the deferred handle path. */
    void *thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: thread unavailable for Unsafe field read\\n");
        abort();
    }
    jobject unsafe_mirror = neko_klass_java_mirror_handle(thread, unsafe_klass);
    if (unsafe_mirror == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: Unsafe mirror handle failed\\n");
        abort();
    }
    jobject unsafe_local = neko_fast_get_static_object_field(thread, env,
        (jclass)unsafe_mirror, NULL, unsafe_mirror, (jlong)the_unsafe.offset);
    if (unsafe_local == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: Unsafe.theUnsafe value NULL\\n");
        abort();
    }
    /* Promote to global ref so it survives across impl_fn frames. */
    g_neko_unsafe_instance_global = g_neko_jni_new_global_ref_fn(env, unsafe_local);
    if (g_neko_unsafe_instance_global == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: Unsafe global ref failed\\n");
        abort();
    }
    /* Resolve allocateInstance(Class)Object Method* + entry. */
    void *alloc_method = neko_resolve_method(unsafe_klass, "allocateInstance",
        "(Ljava/lang/Class;)Ljava/lang/Object;");
    if (alloc_method == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: Unsafe.allocateInstance Method* unavailable\\n");
        abort();
    }
    g_neko_unsafe_allocate_instance_method = alloc_method;
    g_neko_unsafe_allocate_instance_entry = neko_bound_method_i_entry(alloc_method,
        &g_neko_unsafe_allocate_instance_entry, "jdk/internal/misc/Unsafe",
        "allocateInstance", "(Ljava/lang/Class;)Ljava/lang/Object;");
    if (g_neko_unsafe_allocate_instance_entry == NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: Unsafe.allocateInstance entry unavailable\\n");
        abort();
    }
    g_neko_unsafe_allocate_instance_ready = JNI_TRUE;
    if (getenv("NEKO_PATCH_DEBUG") != NULL) {
        fprintf(stderr, "[neko-bind] TLAB-NULL fix: Unsafe.allocateInstance NJX cache ready unsafe=%p method=%p entry=%p\\n",
            (void*)g_neko_unsafe_instance_global,
            g_neko_unsafe_allocate_instance_method,
            g_neko_unsafe_allocate_instance_entry);
    }
}

""";
    }

}
