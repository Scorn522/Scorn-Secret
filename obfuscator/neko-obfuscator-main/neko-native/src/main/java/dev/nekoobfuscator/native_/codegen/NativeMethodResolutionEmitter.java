package dev.nekoobfuscator.native_.codegen;

/**
 * Emits strict HotSpot Method* and jmethodID resolution helpers.
 */
final class NativeMethodResolutionEmitter {
    private NativeMethodResolutionEmitter() {}

    /**
     * T4.2b — convenience helper that mirrors the
     * {@code neko_get_method_id} / {@code neko_get_static_method_id} call
     * shape but routes through the libjvm-internal
     * {@code neko_resolve_method} (Klass-based scan) followed by
     * {@code neko_make_native_method_id} (Method* → synthetic jmethodID).
     * The same helper covers static and instance methods because
     * {@code neko_resolve_method} does not distinguish based on access
     * flags — it scans the InstanceKlass {@code _methods} array by
     * (name, signature) and walks superclasses / interfaces. The strict
     * abort-on-missing behavior matches the {@code R-negative} gate
     * inherited from T2.3. Emitted in its own method to keep
     * renderBindSupport's text block under the 65535-byte string-literal
     * constant pool limit.
     */
    static String renderResolveJMethodID() {
        return """
static uint32_t neko_method_access_flags(void *method) {
    size_t width;
    void *flag_addr;
    if (method == NULL) return 0u;
    if (g_neko_method_layout.off_method_access_flags < 0) {
        fprintf(stderr, "[neko-bind] Method::_access_flags layout unavailable\\n");
        abort();
    }
    width = g_neko_method_layout.access_flags_size == 0
        ? sizeof(uint32_t) : g_neko_method_layout.access_flags_size;
    flag_addr = (void*)((char*)method + g_neko_method_layout.off_method_access_flags);
    if (width == 4) return *(uint32_t*)flag_addr;
    if (width == 2) return (uint32_t)*(uint16_t*)flag_addr;
    return *(uint32_t*)flag_addr;
}

static jboolean neko_method_matches_static_kind(void *method, jboolean is_static) {
    uint32_t flags = neko_method_access_flags(method);
    return (((flags & NEKO_JVM_ACC_STATIC) != 0u) == (is_static ? JNI_TRUE : JNI_FALSE))
        ? JNI_TRUE : JNI_FALSE;
}

static jboolean neko_method_is_instance_default(void *method) {
    uint32_t flags = neko_method_access_flags(method);
    return (flags & (NEKO_JVM_ACC_STATIC | NEKO_JVM_ACC_ABSTRACT)) == 0u ? JNI_TRUE : JNI_FALSE;
}

static jboolean neko_descriptor_has_reference_return_utf8(const char *sig_utf8) {
    const char *close;
    if (sig_utf8 == NULL) return JNI_FALSE;
    close = strchr(sig_utf8, ')');
    if (close == NULL || close[1] == '\\0') return JNI_FALSE;
    return (close[1] == 'L' || close[1] == '[') ? JNI_TRUE : JNI_FALSE;
}

static jboolean neko_signature_symbol_has_reference_return(void *sig_symbol) {
    uint16_t len;
    const char *body;
    const char *close;
    if (sig_symbol == NULL) return JNI_FALSE;
    if (g_neko_method_layout.off_symbol_length < 0 || g_neko_method_layout.off_symbol_body < 0) {
        fprintf(stderr, "[neko-bind] Symbol layout unavailable for method signature comparison\\n");
        abort();
    }
    len = *(uint16_t*)((char*)sig_symbol + g_neko_method_layout.off_symbol_length);
    body = (const char*)sig_symbol + g_neko_method_layout.off_symbol_body;
    close = memchr(body, ')', len);
    if (close == NULL || (size_t)(close - body + 1) >= (size_t)len) return JNI_FALSE;
    return (close[1] == 'L' || close[1] == '[') ? JNI_TRUE : JNI_FALSE;
}

static jboolean neko_signature_symbol_matches_parameters(void *sig_symbol, const char *sig_utf8) {
    uint16_t len;
    const char *body;
    const char *symbol_close;
    const char *utf8_close;
    size_t symbol_params_len;
    size_t utf8_params_len;
    if (sig_symbol == NULL || sig_utf8 == NULL) return JNI_FALSE;
    if (g_neko_method_layout.off_symbol_length < 0 || g_neko_method_layout.off_symbol_body < 0) {
        fprintf(stderr, "[neko-bind] Symbol layout unavailable for method parameter comparison\\n");
        abort();
    }
    len = *(uint16_t*)((char*)sig_symbol + g_neko_method_layout.off_symbol_length);
    body = (const char*)sig_symbol + g_neko_method_layout.off_symbol_body;
    symbol_close = memchr(body, ')', len);
    utf8_close = strchr(sig_utf8, ')');
    if (symbol_close == NULL || utf8_close == NULL) return JNI_FALSE;
    symbol_params_len = (size_t)(symbol_close - body + 1);
    utf8_params_len = (size_t)(utf8_close - sig_utf8 + 1);
    return symbol_params_len == utf8_params_len
        && memcmp(body, sig_utf8, symbol_params_len) == 0 ? JNI_TRUE : JNI_FALSE;
}

static void *neko_resolve_declared_covariant_ref_method(void *instance_klass, const char *name_utf8, const char *sig_utf8) {
    void *methods_array;
    int method_count;
    void **method_data;
    void *candidate = NULL;
    if (!neko_descriptor_has_reference_return_utf8(sig_utf8)) return NULL;
    if (g_neko_method_layout.off_instanceklass_methods < 0
        || g_neko_method_layout.off_array_length < 0
        || g_neko_method_layout.off_array_data < 0
        || g_neko_method_layout.off_constmethod_constants < 0
        || g_neko_method_layout.off_constmethod_name_index < 0
        || g_neko_method_layout.off_constmethod_signature_index < 0) {
        fprintf(stderr, "[neko-bind] InstanceKlass method layout unavailable\\n");
        abort();
    }
    methods_array = *(void**)((char*)instance_klass + g_neko_method_layout.off_instanceklass_methods);
    if (methods_array == NULL) return NULL;
    method_count = *(int*)((char*)methods_array + g_neko_method_layout.off_array_length);
    method_data = (void**)((char*)methods_array + g_neko_method_layout.off_array_data);
    for (int i = 0; i < method_count; i++) {
        void *method = method_data[i];
        void *const_method = neko_method_constmethod(method);
        void *constant_pool;
        uint16_t name_index;
        uint16_t sig_index;
        void *name_symbol;
        void *sig_symbol;
        if (const_method == NULL || !neko_method_is_instance_default(method)) continue;
        constant_pool = *(void**)((char*)const_method + g_neko_method_layout.off_constmethod_constants);
        name_index = *(uint16_t*)((char*)const_method + g_neko_method_layout.off_constmethod_name_index);
        sig_index = *(uint16_t*)((char*)const_method + g_neko_method_layout.off_constmethod_signature_index);
        name_symbol = neko_constantpool_symbol_at(constant_pool, name_index);
        sig_symbol = neko_constantpool_symbol_at(constant_pool, sig_index);
        if (!neko_symbol_equals_utf8(name_symbol, name_utf8)
            || !neko_signature_symbol_matches_parameters(sig_symbol, sig_utf8)
            || !neko_signature_symbol_has_reference_return(sig_symbol)) {
            continue;
        }
        if (candidate != NULL && candidate != method) {
            fprintf(stderr, "[neko-bind] ambiguous covariant reference method resolution: %s%s\\n",
                name_utf8, sig_utf8);
            abort();
        }
        candidate = method;
    }
    return candidate;
}

static void *neko_resolve_interface_declared_method(void *instance_klass, const char *name_utf8, const char *sig_utf8, jboolean is_static) {
    void *interfaces_array;
    int interface_count;
    void **interface_data;
    if (instance_klass == NULL) return NULL;
    if (g_neko_method_layout.off_instanceklass_transitive_interfaces < 0) {
        fprintf(stderr, "[neko-bind] InstanceKlass::_transitive_interfaces layout unavailable\\n");
        abort();
    }
    interfaces_array = *(void**)((char*)instance_klass + g_neko_method_layout.off_instanceklass_transitive_interfaces);
    if (interfaces_array == NULL) return NULL;
    interface_count = *(int*)((char*)interfaces_array + g_neko_method_layout.off_array_length);
    interface_data = (void**)((char*)interfaces_array + g_neko_method_layout.off_array_data);
    for (int i = 0; i < interface_count; i++) {
        void *method = neko_resolve_declared_method(interface_data[i], name_utf8, sig_utf8);
        if (method != NULL && neko_method_matches_static_kind(method, is_static)) return method;
    }
    return NULL;
}

static void *neko_resolve_method_declaration_with_kind(void *instance_klass, const char *name_utf8, const char *sig_utf8, jboolean is_static) {
    void *klass;
    if (instance_klass == NULL || name_utf8 == NULL || sig_utf8 == NULL) {
        fprintf(stderr, "[neko-bind] declaration method resolution requested with null input\\n");
        abort();
    }
    if (g_neko_method_layout.off_klass_super < 0) {
        fprintf(stderr, "[neko-bind] Klass::_super layout unavailable\\n");
        abort();
    }
    klass = instance_klass;
    for (int depth = 0; klass != NULL && depth < 256; depth++) {
        void *method = neko_resolve_declared_method(klass, name_utf8, sig_utf8);
        if (method != NULL && neko_method_matches_static_kind(method, is_static)) return method;
        klass = *(void**)((char*)klass + g_neko_method_layout.off_klass_super);
    }
    klass = instance_klass;
    for (int depth = 0; klass != NULL && depth < 256; depth++) {
        void *method = neko_resolve_interface_declared_method(klass, name_utf8, sig_utf8, is_static);
        if (method != NULL) return method;
        klass = *(void**)((char*)klass + g_neko_method_layout.off_klass_super);
    }
    fprintf(stderr, "[neko-bind] native declaration method resolution failed (is_static=%d): %s%s\\n",
        (int)is_static, name_utf8, sig_utf8);
    abort();
}

static void *neko_resolve_interface_default_method(void *instance_klass, const char *name_utf8, const char *sig_utf8) {
    void *interfaces_array;
    int interface_count;
    void **interface_data;
    if (instance_klass == NULL) return NULL;
    if (g_neko_method_layout.off_instanceklass_transitive_interfaces < 0) {
        fprintf(stderr, "[neko-bind] InstanceKlass::_transitive_interfaces layout unavailable\\n");
        abort();
    }
    interfaces_array = *(void**)((char*)instance_klass + g_neko_method_layout.off_instanceklass_transitive_interfaces);
    if (interfaces_array == NULL) return NULL;
    interface_count = *(int*)((char*)interfaces_array + g_neko_method_layout.off_array_length);
    interface_data = (void**)((char*)interfaces_array + g_neko_method_layout.off_array_data);
    for (int i = 0; i < interface_count; i++) {
        void *method = neko_resolve_declared_method(interface_data[i], name_utf8, sig_utf8);
        if (method != NULL && neko_method_is_instance_default(method)) return method;
        method = neko_resolve_declared_covariant_ref_method(interface_data[i], name_utf8, sig_utf8);
        if (method != NULL && neko_method_is_instance_default(method)) return method;
    }
    return NULL;
}

static const char *neko_method_holder_name_utf8(void *method, int *len_out) {
    void *const_method;
    void *constant_pool;
    void *holder;
    void *name_symbol;
    if (len_out != NULL) *len_out = 1;
    if (method == NULL
        || g_neko_method_layout.off_constmethod_constants < 0
        || g_neko_method_layout.off_constantpool_pool_holder < 0
        || g_neko_method_layout.off_klass_name < 0
        || g_neko_method_layout.off_symbol_length < 0
        || g_neko_method_layout.off_symbol_body < 0) {
        return "?";
    }
    const_method = neko_method_constmethod(method);
    if (const_method == NULL) return "?";
    constant_pool = *(void**)((char*)const_method + g_neko_method_layout.off_constmethod_constants);
    if (constant_pool == NULL) return "?";
    holder = *(void**)((char*)constant_pool + g_neko_method_layout.off_constantpool_pool_holder);
    if (holder == NULL) return "?";
    name_symbol = *(void**)((char*)holder + g_neko_method_layout.off_klass_name);
    if (name_symbol == NULL) return "?";
    if (len_out != NULL) *len_out = (int)*(uint16_t*)((char*)name_symbol + g_neko_method_layout.off_symbol_length);
    return (const char*)name_symbol + g_neko_method_layout.off_symbol_body;
}

/* T4.2b helper: resolve (name, sig) on a jclass to a synthetic jmethodID.
 *
 * `is_static` selects between the JNI GetMethodID and GetStaticMethodID
 * semantics: when set we walk superclasses scanning declared methods AND
 * filter out methods missing ACC_STATIC; when unset we filter out methods
 * with ACC_STATIC. This matches what HotSpot's JNI bridge does; relaxing
 * the filter is unsafe because a class hierarchy may declare a static and
 * an instance method with the same (name, sig) at different inheritance
 * depths and JNI's static-vs-instance distinction picks different Method*
 * pointers. The synthetic jmethodID is the same Method**-cell shape used
 * by neko_make_native_method_id elsewhere in the bind path. */
static jmethodID neko_resolve_jmethodID_with_kind(JNIEnv *env, jclass cls, const char *name, const char *sig, jboolean is_static) {
    void *klass;
    void *method;
    void *current_klass;
    uint32_t want_static_mask;
    (void)env;
    if (cls == NULL) {
        fprintf(stderr, "[neko-bind] T4.2b method resolution missing jclass: %s%s\\n",
            name == NULL ? "<null>" : name,
            sig == NULL ? "<null>" : sig);
        abort();
    }
    if (name == NULL || sig == NULL) {
        fprintf(stderr, "[neko-bind] T4.2b method resolution missing name/sig\\n");
        abort();
    }
    klass = neko_class_mirror_to_klass(cls);
    if (klass == NULL) {
        fprintf(stderr, "[neko-bind] T4.2b cannot extract Klass from jclass: %s%s\\n", name, sig);
        abort();
    }
    if (g_neko_method_layout.off_method_access_flags < 0
        || g_neko_method_layout.off_klass_super < 0) {
        fprintf(stderr, "[neko-bind] T4.2b method access-flag layout unavailable\\n");
        abort();
    }
    want_static_mask = is_static ? NEKO_JVM_ACC_STATIC : 0u;
    current_klass = klass;
    for (int depth = 0; current_klass != NULL && depth < 256; depth++) {
        method = neko_resolve_declared_method(current_klass, name, sig);
        if (method != NULL) {
            uint32_t flags;
            size_t width = g_neko_method_layout.access_flags_size == 0
                ? sizeof(uint32_t) : g_neko_method_layout.access_flags_size;
            void *flag_addr = (void*)((char*)method + g_neko_method_layout.off_method_access_flags);
            if (width == 4) flags = *(uint32_t*)flag_addr;
            else if (width == 2) flags = (uint32_t)*(uint16_t*)flag_addr;
            else flags = *(uint32_t*)flag_addr;
            if ((flags & NEKO_JVM_ACC_STATIC) == want_static_mask) {
                return neko_make_native_method_id(method, "<T4.2b>", name, sig);
            }
            /* declared method exists but kind doesn't match — JNI's
             * Get(Static)MethodID would skip it and continue walking the
             * hierarchy, so we do the same. */
        }
        current_klass = *(void**)((char*)current_klass + g_neko_method_layout.off_klass_super);
    }
    /* For non-static methods JNI also walks default-method interfaces.
     * neko_resolve_method's interface-default path already covers that case;
     * we mirror it here only for the !is_static branch. */
    if (!is_static) {
        current_klass = klass;
        for (int depth = 0; current_klass != NULL && depth < 256; depth++) {
            method = neko_resolve_interface_default_method(current_klass, name, sig);
            if (method != NULL) {
                uint32_t flags;
                size_t width = g_neko_method_layout.access_flags_size == 0
                    ? sizeof(uint32_t) : g_neko_method_layout.access_flags_size;
                void *flag_addr = (void*)((char*)method + g_neko_method_layout.off_method_access_flags);
                if (width == 4) flags = *(uint32_t*)flag_addr;
                else if (width == 2) flags = (uint32_t)*(uint16_t*)flag_addr;
                else flags = *(uint32_t*)flag_addr;
                if ((flags & NEKO_JVM_ACC_STATIC) == 0u) {
                    return neko_make_native_method_id(method, "<T4.2b>", name, sig);
                }
            }
            current_klass = *(void**)((char*)current_klass + g_neko_method_layout.off_klass_super);
        }
    }
    fprintf(stderr, "[neko-bind] T4.2b method resolution failed (is_static=%d): %s%s on klass=%p\\n",
        (int)is_static, name, sig, klass);
    abort();
}

/* Default-instance variant for the call sites that previously used
 * neko_get_method_id (instance methods only). */
static jmethodID neko_resolve_jmethodID(JNIEnv *env, jclass cls, const char *name, const char *sig) {
    return neko_resolve_jmethodID_with_kind(env, cls, name, sig, JNI_FALSE);
}

/* T4.2c — IMPL_LOOKUP read via libjvm-internal static-field machinery.
 * Replaces the previous neko_get_static_field_id (function-table 144) +
 * GetStaticObjectField (function-table 145) pair. */
static jobject neko_read_impl_lookup_direct(JNIEnv *env) {
    jclass lookupClass;
    void *klass;
    neko_field_resolution_t field;
    void *thread;
    lookupClass = neko_resolve_class_mirror_with_env(env, "java/lang/invoke/MethodHandles$Lookup", NULL, NULL);
    if (lookupClass == NULL) {
        fprintf(stderr, "[neko-bind] T4.2c lookup class missing\\n");
        abort();
    }
    /* JNI Get(Static)FieldID has the documented side effect of triggering
     * class init; mirror that here. */
    neko_ensure_class_initialized(env, lookupClass, "java/lang/invoke/MethodHandles$Lookup");
    klass = neko_class_mirror_to_klass(lookupClass);
    if (klass == NULL) {
        fprintf(stderr, "[neko-bind] T4.2c cannot extract Klass from MethodHandles$Lookup mirror\\n");
        abort();
    }
    field = neko_resolve_field(klass, "IMPL_LOOKUP", "Ljava/lang/invoke/MethodHandles$Lookup;", JNI_TRUE);
    if (!field.found || !field.is_static || field.offset == 0u) {
        fprintf(stderr, "[neko-bind] T4.2c IMPL_LOOKUP field metadata invalid (found=%d static=%d off=%u)\\n",
            (int)field.found, (int)field.is_static, field.offset);
        abort();
    }
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] T4.2c thread unavailable for IMPL_LOOKUP read\\n");
        abort();
    }
    return neko_fast_get_static_object_field(thread, env, lookupClass, NULL, lookupClass, (jlong)field.offset);
}

static jobject neko_impl_lookup(JNIEnv *env) {
    jobject localLookup;
    if (getenv("NEKO_NATIVE_DIAG_FAIL_IMPL_LOOKUP_SLOT") != NULL) {
        fprintf(stderr, "[neko-bind] IMPL_LOOKUP direct local handle unavailable\\n");
        abort();
    }
    localLookup = neko_read_impl_lookup_direct(env);
    if (localLookup == NULL) {
        fprintf(stderr, "[neko-bind] IMPL_LOOKUP direct read returned null\\n");
        abort();
    }
    return localLookup;
}

/* Method*-returning variant for paths that don't need a JNI jmethodID at
 * all (the manifest patcher pipes the result straight into
 * neko_patch_method_entry). Skips the synthetic Method**-cell allocation
 * neko_make_native_method_id would do, so each manifest patch costs zero
 * heap allocations. Same kind-aware filter as neko_resolve_jmethodID_with_kind. */
static void *neko_resolve_method_star_with_kind(JNIEnv *env, jclass cls, const char *name, const char *sig, jboolean is_static) {
    void *klass;
    void *method;
    void *current_klass;
    uint32_t want_static_mask;
    (void)env;
    if (cls == NULL) {
        fprintf(stderr, "[neko-bind] T4.2b method resolution missing jclass: %s%s\\n",
            name == NULL ? "<null>" : name,
            sig == NULL ? "<null>" : sig);
        abort();
    }
    if (name == NULL || sig == NULL) {
        fprintf(stderr, "[neko-bind] T4.2b method resolution missing name/sig\\n");
        abort();
    }
    klass = neko_class_mirror_to_klass(cls);
    if (klass == NULL) {
        fprintf(stderr, "[neko-bind] T4.2b cannot extract Klass from jclass: %s%s\\n", name, sig);
        abort();
    }
    if (g_neko_method_layout.off_method_access_flags < 0
        || g_neko_method_layout.off_klass_super < 0) {
        fprintf(stderr, "[neko-bind] T4.2b method access-flag layout unavailable\\n");
        abort();
    }
    want_static_mask = is_static ? NEKO_JVM_ACC_STATIC : 0u;
    current_klass = klass;
    for (int depth = 0; current_klass != NULL && depth < 256; depth++) {
        method = neko_resolve_declared_method(current_klass, name, sig);
        if (method != NULL) {
            uint32_t flags;
            size_t width = g_neko_method_layout.access_flags_size == 0
                ? sizeof(uint32_t) : g_neko_method_layout.access_flags_size;
            void *flag_addr = (void*)((char*)method + g_neko_method_layout.off_method_access_flags);
            if (width == 4) flags = *(uint32_t*)flag_addr;
            else if (width == 2) flags = (uint32_t)*(uint16_t*)flag_addr;
            else flags = *(uint32_t*)flag_addr;
            if ((flags & NEKO_JVM_ACC_STATIC) == want_static_mask) {
                return method;
            }
        }
        current_klass = *(void**)((char*)current_klass + g_neko_method_layout.off_klass_super);
    }
    if (!is_static) {
        current_klass = klass;
        for (int depth = 0; current_klass != NULL && depth < 256; depth++) {
            method = neko_resolve_interface_default_method(current_klass, name, sig);
            if (method != NULL) {
                uint32_t flags;
                size_t width = g_neko_method_layout.access_flags_size == 0
                    ? sizeof(uint32_t) : g_neko_method_layout.access_flags_size;
                void *flag_addr = (void*)((char*)method + g_neko_method_layout.off_method_access_flags);
                if (width == 4) flags = *(uint32_t*)flag_addr;
                else if (width == 2) flags = (uint32_t)*(uint16_t*)flag_addr;
                else flags = *(uint32_t*)flag_addr;
                if ((flags & NEKO_JVM_ACC_STATIC) == 0u) {
                    return method;
                }
            }
            current_klass = *(void**)((char*)current_klass + g_neko_method_layout.off_klass_super);
        }
    }
    fprintf(stderr, "[neko-bind] T4.2b method resolution failed (is_static=%d): %s%s on klass=%p\\n",
        (int)is_static, name, sig, klass);
    abort();
}

""";
    }

    /**
     * T4.2a — emit the *tolerant* class-mirror resolver. Identical to
     * {@code neko_resolve_class_mirror_with_env} (rendered above by
     * {@code renderBindSupport}) except it returns NULL when the class is
     * not yet loaded / not findable through any of the libjvm-internal
     * symbols (JVM_FindClassFromBootLoader / JVM_FindClassFromClass /
     * loaded-class graph walk).
     *
     * Required by {@code ManifestEmitter.neko_manifest_discover_and_patch}
     * which iterates ALL owner names at JNI_OnLoad: classes that have not
     * yet triggered their static initializer (and thus are not loaded yet)
     * get a deferred patch via {@code neko_manifest_patch_defined_class}
     * on the defineClass hook instead of an immediate JNI_OnLoad-time
     * patch. The strict resolver keeps abort-on-missing semantics for
     * every other call site (T4.4 / T4.3 / T4.5 / T4.10 inherits T2.2
     * R-negative).
     *
     * Kept in its own emit method to avoid pushing renderBindSupport's
     * already-1500-line text block over the JVM 65535-byte string-literal
     * constant pool limit.
     */
}
