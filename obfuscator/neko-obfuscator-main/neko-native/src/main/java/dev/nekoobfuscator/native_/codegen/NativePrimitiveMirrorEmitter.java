package dev.nekoobfuscator.native_.codegen;

/**
 * Emits primitive descriptor to java.lang.Class mirror resolution support.
 */
final class NativePrimitiveMirrorEmitter {
    private NativePrimitiveMirrorEmitter() {}

    /**
     * T4.1 — Primitive descriptor → mirror table population + read.
     *
     * Emitted AFTER `renderBindSupport()` because the init function reuses
     * the bind-time `neko_resolve_class_with_env` and `neko_resolve_field`
     * resolvers (and their `neko_field_resolution_t` typedef) defined there.
     * The hot-path read uses the `g_hotspot.compressed_oops_enabled` flag and
     * the `neko_decode_narrow_oop` / `neko_barrier_load_oop_field` helpers
     * from `renderHotSpotSupport` (already emitted earlier).
     *
     * The table itself (`g_neko_primitive_mirror_table`) is declared in
     * `renderRuntimeSupport` so the inline `neko_class_for_descriptor` switch
     * arms can reference it without cross-block extern hoops. The init
     * function resolves the wrapper InstanceKlass for each primitive via
     * `neko_resolve_class_with_env` and the static `TYPE` field's offset via
     * `neko_resolve_field`. `neko_primitive_mirror_for_char` dereferences the
     * wrapper Klass's `_java_mirror` OopHandle to reach the wrapper Class oop,
     * reads TYPE through compressed-oops decode plus the active GC's load
     * barrier, and pushes the resulting primitive mirror oop into the calling
     * thread's local handle block. No JNI function-table indices are consumed;
     * failure of any per-entry derivation aborts (no skip-on-error fallback).
     */
    static String renderPrimitiveMirrorSupport() {
        return """
static void neko_primitive_mirror_table_init(JNIEnv *env) {
    static const char * const wrapper_names[9] = {
        "java/lang/Boolean",
        "java/lang/Byte",
        "java/lang/Character",
        "java/lang/Short",
        "java/lang/Integer",
        "java/lang/Long",
        "java/lang/Float",
        "java/lang/Double",
        "java/lang/Void"
    };
    const char *diag_missing_tag = getenv("NEKO_NATIVE_DIAG_FAIL_PRIMITIVE_MIRROR_TAG");
    int kind;
    if (g_neko_primitive_mirror_ready) return;
    if (env == NULL) {
        fprintf(stderr, "[neko-bind] T4.1 primitive mirror init missing JNIEnv\\n");
        abort();
    }
    if (g_neko_method_layout.off_klass_java_mirror < 0) {
        fprintf(stderr, "[neko-bind] T4.1 primitive mirror init missing Klass::_java_mirror offset\\n");
        abort();
    }
    if (!g_neko_native_resolution_ready) {
        fprintf(stderr, "[neko-bind] T4.1 primitive mirror init requires native_resolution_ready\\n");
        abort();
    }
    for (kind = 0; kind < 9; kind++) {
        const char *name = wrapper_names[kind];
        void *klass;
        neko_field_resolution_t type_field;
        klass = neko_resolve_class_with_env(env, name, NULL);
        if (diag_missing_tag != NULL
            && diag_missing_tag[0] == g_neko_primitive_mirror_table[kind].tag
            && diag_missing_tag[1] == '\\0') {
            klass = NULL;
        }
        if (klass == NULL) {
            fprintf(stderr, "[neko-bind] T4.1 missing wrapper-class mirror for %s (kind=%d tag=%c)\\n",
                name, kind, g_neko_primitive_mirror_table[kind].tag);
            abort();
        }
        type_field = neko_resolve_field(klass, "TYPE", "Ljava/lang/Class;", JNI_TRUE);
        if (!type_field.found || !type_field.is_static || type_field.offset == 0u) {
            fprintf(stderr, "[neko-bind] T4.1 missing TYPE static field on %s (found=%d static=%d off=%u)\\n",
                name, (int)type_field.found, (int)type_field.is_static, type_field.offset);
            abort();
        }
        g_neko_primitive_mirror_table[kind].wrapper_klass = klass;
        g_neko_primitive_mirror_table[kind].type_static_offset = type_field.offset;
        g_neko_primitive_mirror_table[kind].ready = JNI_TRUE;
    }
    g_neko_primitive_mirror_ready = JNI_TRUE;
    if (getenv("NEKO_PATCH_DEBUG") != NULL) {
        fprintf(stderr, "[neko-bind] T4.1 primitive mirror table populated:");
        for (kind = 0; kind < 9; kind++) {
            fprintf(stderr, " %c=(klass=%p,off=%u)",
                g_neko_primitive_mirror_table[kind].tag,
                g_neko_primitive_mirror_table[kind].wrapper_klass,
                (unsigned)g_neko_primitive_mirror_table[kind].type_static_offset);
        }
        fprintf(stderr, "\\n");
    }
}

NEKO_FAST_INLINE jclass neko_primitive_mirror_for_char(JNIEnv *env, char tag) {
    int kind = neko_primitive_mirror_kind_from_descriptor_char(tag);
    neko_primitive_mirror_entry_t *entry;
    void *thread;
    void *mirror_handle_addr;
    void *mirror_oop_handle;
    void *wrapper_class_oop;
    char *field_addr;
    void *type_oop;
    if (kind < 0 || kind >= 9) {
        fprintf(stderr, "[neko-bind] T4.1 primitive mirror requested for non-primitive tag '%c'\\n", tag);
        abort();
    }
    entry = &g_neko_primitive_mirror_table[kind];
    if (!g_neko_primitive_mirror_ready || !entry->ready
        || entry->wrapper_klass == NULL || entry->type_static_offset == 0u) {
        fprintf(stderr, "[neko-bind] T4.1 primitive mirror table not ready for tag '%c' (table_ready=%d entry_ready=%d klass=%p off=%u)\\n",
            tag, (int)g_neko_primitive_mirror_ready, (int)entry->ready,
            entry->wrapper_klass, (unsigned)entry->type_static_offset);
        abort();
    }
    /* Klass::_java_mirror lives at the wrapper Klass; reading via the OopHandle
     * indirection picks up GC relocation transparently across all collectors
     * (the GC updates the OopHandle slot value, not just the underlying oop). */
    mirror_handle_addr = (void*)((char*)entry->wrapper_klass + g_neko_method_layout.off_klass_java_mirror);
    mirror_oop_handle = *(void**)mirror_handle_addr;
    if (mirror_oop_handle == NULL) {
        fprintf(stderr, "[neko-bind] T4.1 wrapper Klass::_java_mirror OopHandle empty for tag '%c'\\n", tag);
        abort();
    }
    wrapper_class_oop = *(void**)mirror_oop_handle;
    if (wrapper_class_oop == NULL) {
        fprintf(stderr, "[neko-bind] T4.1 wrapper Class oop NULL for tag '%c'\\n", tag);
        abort();
    }
    /* Read TYPE static field (compressed oop or full oop) and apply the active
     * GC's load barrier. The field is statically declared `Class<X>` so its
     * value is always either NULL or a Class oop; here it must be the
     * primitive's mirror, which is created very early in JVM bootstrap. */
    field_addr = (char*)wrapper_class_oop + entry->type_static_offset;
    if (g_hotspot.compressed_oops_enabled) {
        type_oop = neko_decode_narrow_oop(*(uint32_t*)field_addr);
    } else {
        type_oop = *(void**)field_addr;
    }
    type_oop = neko_barrier_load_oop_field(field_addr, type_oop);
    if (type_oop == NULL) {
        fprintf(stderr, "[neko-bind] T4.1 primitive TYPE oop NULL for tag '%c' (wrapper_class_oop=%p offset=%u)\\n",
            tag, wrapper_class_oop, (unsigned)entry->type_static_offset);
        abort();
    }
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] T4.1 thread unavailable for primitive mirror handle '%c'\\n", tag);
        abort();
    }
    return (jclass)neko_handle_push(thread, type_oop);
}

""";
    }

}
