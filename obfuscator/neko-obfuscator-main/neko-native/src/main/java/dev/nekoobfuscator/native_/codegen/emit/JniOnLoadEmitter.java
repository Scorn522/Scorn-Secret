package dev.nekoobfuscator.native_.codegen.emit;

/**
 * Emits {@code JNI_OnLoad}. The Java runtime loader only calls
 * {@code System.load}; all HotSpot probing and manifest discovery happen from
 * native initialization and no Java bootstrap method is registered or exported.
 */
public final class JniOnLoadEmitter {

    public String renderRegistrationTable() {
        StringBuilder sb = new StringBuilder();
        sb.append("/* === No Java native bridge: NekoNativeLoader only calls System.load === */\n\n");
        return sb.toString();
    }

    public String renderJniOnLoadAndBootstrap() {
        return """
__attribute__((visibility("hidden"))) extern void *g_neko_jni_onload_thread_reg;
__attribute__((visibility("hidden"))) extern void *g_neko_jni_functions_table;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    /* Capture HotSpot's thread register IMMEDIATELY, before any compiler-
     * generated prologue / register reuse. r15 (x86_64) / x28 (AArch64)
     * holds the current JavaThread* across the JNI call into us. We use
     * this snapshot at neko_method_layout_init time to derive the
     * _jni_environment offset (which VMStructs does not expose unless
     * JVMCI is on). */
#if defined(__x86_64__)
    __asm__ volatile ("movq %%r15, %0" : "=m"(g_neko_jni_onload_thread_reg));
#elif defined(__aarch64__)
    __asm__ volatile ("str x28, %0" : "=m"(g_neko_jni_onload_thread_reg));
#endif
    JNIEnv *env = NULL;
    (void)reserved;
    g_neko_java_vm = vm;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    if (env == NULL) return JNI_ERR;
    g_neko_jni_functions_table = *(void**)env;
    if (g_neko_jni_functions_table == NULL) return JNI_ERR;
    if (!neko_method_layout_init(env)) {
        fprintf(stderr, "[neko-bootstrap] native layout initialization failed\\n");
        abort();
    }
    neko_hotspot_init(env);
    neko_refresh_hotspot_vmstruct_state();
    /* Pre-existing TEST #3 String concat fix: derive the fast-string
     * allocation Klass bits AFTER neko_hotspot_init has populated
     * g_hotspot. The same call from neko_method_layout_init always
     * skipped because g_hotspot was zero at that point (the layout init
     * runs BEFORE hotspot init). Without the bits set here, the
     * per-.so g_neko_fast_string_alloc_ready stays false unless the
     * .so happens to call neko_intern_string later (LDC String literal),
     * and Test #3's String.concat call site aborts because the fast
     * path is the only path after T3.19. */
    if (g_hotspot.initialized
        && (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) != 0
        && !g_hotspot.use_compact_object_headers
        && g_hotspot.klass_offset_bytes > 0
        && g_neko_tlab_alloc_ready
        && g_hotspot.primitive_array_klass_bits[NEKO_PRIM_B] != 0) {
        neko_ensure_string_alloc_bits(env);
    }
    /* TLAB-NULL fix: cache jdk.internal.misc.Unsafe.allocateInstance NJX
     * dispatch metadata for the NEW-allocation fallback path. Independent
     * of fast-string init: even if the fast-string fast path isn't
     * applicable (e.g. ZGC), NEW still needs a fallback when TLAB
     * suddenly returns NULL on certain threads. */
    neko_ensure_unsafe_allocate_instance_njx_cache(env);
    /* T4.1: populate the descriptor → primitive-mirror table. Must run AFTER
     * neko_hotspot_init (which publishes compressed-oops shift/base into
     * g_hotspot) and AFTER neko_method_layout_init (called above; publishes
     * Klass::_java_mirror offset and the native-resolution capability bit
     * neko_resolve_class / neko_resolve_field both rely on). Failure to
     * resolve any of the eight wrapper InstanceKlasses or their TYPE static
     * field aborts inside the helper — there is no fallback path back into
     * neko_find_class / neko_get_static_field_id. */
    neko_primitive_mirror_table_init(env);
    neko_boxing_cache_init(env);
    neko_bootstrap_owner_discovery(env);
    return JNI_VERSION_1_6;
}

static void neko_bootstrap_owner_discovery(JNIEnv *env) {
    if (env == NULL) return;
    if (!neko_manifest_discover_and_patch(env)) abort();
}

""";
    }
}
