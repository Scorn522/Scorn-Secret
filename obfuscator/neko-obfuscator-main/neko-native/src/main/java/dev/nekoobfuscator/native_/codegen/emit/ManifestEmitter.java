package dev.nekoobfuscator.native_.codegen.emit;

import dev.nekoobfuscator.native_.codegen.CStringLiteral;
import dev.nekoobfuscator.native_.translator.NativeTranslator.NativeMethodBinding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Emits the {@code NekoManifestMethod} struct, the data table populated from
 * {@link NativeMethodBinding}s, and the parallel {@code g_neko_manifest_method_stars}
 * array that the trampoline scans to map a HotSpot {@code Method*} to a manifest index.
 *
 * Also emits the discovery driver {@code neko_manifest_discover_and_patch} that:
 *   - groups manifest entries by owner internal name,
 *   - {@code FindClass}'es each owner once,
 *   - resolves each method's {@code jmethodID} and derives the Method* via
 *     {@code *(Method**)mid},
 *   - calls {@code neko_patch_method_entry} (defined in {@link MethodPatcherEmitter}).
 *
 * No JVM-side helpers are used: the discovery driver uses only standard JNI primitives
 * and HotSpot's stable {@code jmethodID -> Method*} representation.
 */
public final class ManifestEmitter {

    public String renderStructAndForwardDecls() {
        StringBuilder sb = new StringBuilder();
        sb.append("static void neko_bootstrap_owner_discovery(JNIEnv *env);\n");
        sb.append("static jboolean neko_manifest_discover_and_patch(JNIEnv *env);\n");
        sb.append("__attribute__((visibility(\"hidden\"))) jboolean neko_manifest_patch_defined_class(JNIEnv *env, jclass owner_cls);\n");
        sb.append("typedef struct NekoManifestMethod NekoManifestMethod;\n");
        sb.append("struct NekoManifestMethod {\n");
        sb.append("    const char *owner_internal;   /* +0 */\n");
        sb.append("    const char *method_name;      /* +8 */\n");
        sb.append("    const char *method_desc;      /* +16 */\n");
        sb.append("    void *impl_fn;                /* +24 */\n");
        sb.append("    uint32_t signature_id;        /* +32 */\n");
        sb.append("    uint8_t is_static;            /* +36 */\n");
        sb.append("    uint8_t patch_state;          /* +37 */\n");
        sb.append("    uint8_t _pad0;                /* +38 */\n");
        sb.append("    uint8_t _pad1;                /* +39 */\n");
        /* Stable jclass for static dispatch. Populated once at JNI_OnLoad
         * time (NewGlobalRef on FindClass) so the per-call dispatcher does
         * not need to cross the JNI boundary. The value here is a JNI global
         * reference (a pointer into HotSpot's JNI global handle table); the
         * impl_fn treats it like any other jclass. */
        sb.append("    void *owner_class_global_ref; /* +40 */\n");
        sb.append("};\n");
        sb.append("_Static_assert(sizeof(struct NekoManifestMethod) == ")
            .append(PatcherLayoutConstants.MANIFEST_METHOD_SIZE)
            .append(", \"NekoManifestMethod size mismatch with PatcherLayoutConstants\");\n");
        sb.append("#define NEKO_PATCH_STATE_NONE     0u\n");
        sb.append("#define NEKO_PATCH_STATE_APPLIED  1u\n");
        sb.append("#define NEKO_PATCH_STATE_FAILED   2u\n\n");
        return sb.toString();
    }

    public String renderTables(List<NativeMethodBinding> bindings, SignaturePlan plan) {
        /* These globals are referenced from naked-asm trampolines via direct
         * RIP-relative loads. Using `static` triggers ld.lld PIC complaints
         * because the inline asm references them as if they were external
         * symbols. Mark them with hidden visibility instead — the linker
         * sees a defined symbol in this module and is happy. */
        StringBuilder sb = new StringBuilder();
        sb.append("/* === Manifest tables (hidden visibility for asm RIP-rel access) === */\n");
        sb.append("__attribute__((visibility(\"hidden\"))) struct NekoManifestMethod g_neko_manifest_methods[] = {\n");
        for (int i = 0; i < bindings.size(); i++) {
            NativeMethodBinding b = bindings.get(i);
            int sigId = plan.signatureIdFor(i);
            sb.append("    { \"")
                .append(CStringLiteral.escape(b.ownerInternalName())).append("\", \"")
                .append(CStringLiteral.escape(b.methodName())).append("\", \"")
                .append(CStringLiteral.escape(b.descriptor())).append("\", (void*)&")
                .append(b.rawFunctionName()).append(", ")
                .append(sigId).append("u, ")
                .append(b.isStatic() ? '1' : '0').append(", NEKO_PATCH_STATE_NONE, 0, 0, NULL },\n");
        }
        if (bindings.isEmpty()) {
            sb.append("    { NULL, NULL, NULL, NULL, 0, 0, NEKO_PATCH_STATE_NONE, 0, 0, NULL }\n");
        }
        sb.append("};\n");
        sb.append("__attribute__((visibility(\"hidden\"))) const uint32_t g_neko_manifest_method_count = ")
            .append(bindings.size()).append("u;\n");
        sb.append("/* Parallel array of Method* values, populated by the discovery pass.\n");
        sb.append(" * Trampolines scan this to map HotSpot Method* -> manifest index. */\n");
        sb.append("__attribute__((visibility(\"hidden\"))) void *g_neko_manifest_method_stars[")
            .append(Math.max(1, bindings.size()))
            .append("] = {0};\n\n");
        sb.append("#define NEKO_METHOD_ALIAS_CAPACITY ")
            .append(Math.max(1, bindings.size() * 4))
            .append("u\n");
        sb.append("__attribute__((visibility(\"hidden\"))) void *g_neko_manifest_alias_method_stars[NEKO_METHOD_ALIAS_CAPACITY] = {0};\n");
        sb.append("__attribute__((visibility(\"hidden\"))) uint32_t g_neko_manifest_alias_indices[NEKO_METHOD_ALIAS_CAPACITY] = {0};\n");
        sb.append("__attribute__((visibility(\"hidden\"))) struct NekoManifestMethod g_neko_manifest_alias_entries[NEKO_METHOD_ALIAS_CAPACITY];\n");
        sb.append("__attribute__((visibility(\"hidden\"))) void *g_neko_manifest_alias_entry_ptrs[NEKO_METHOD_ALIAS_CAPACITY] = {0};\n");
        sb.append("__attribute__((visibility(\"hidden\"))) uint32_t g_neko_manifest_alias_count = 0u;\n\n");
        return sb.toString();
    }

    public String renderDiscoveryDriver(List<NativeMethodBinding> bindings, Map<String, Integer> ownerBindIds) {
        Map<String, List<Integer>> byOwner = new LinkedHashMap<>();
        for (int i = 0; i < bindings.size(); i++) {
            byOwner.computeIfAbsent(bindings.get(i).ownerInternalName(), ignored -> new ArrayList<>()).add(i);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("/* === Discovery + patch driver === */\n");
        sb.append("static jboolean neko_manifest_has_method_star(uint32_t idx, void *method_star) {\n");
        sb.append("    uint32_t i;\n");
        sb.append("    if (idx >= g_neko_manifest_method_count || method_star == NULL) return JNI_FALSE;\n");
        sb.append("    if (g_neko_manifest_method_stars[idx] == method_star) return JNI_TRUE;\n");
        sb.append("    for (i = 0u; i < g_neko_manifest_alias_count; i++) {\n");
        sb.append("        if (g_neko_manifest_alias_indices[i] == idx && g_neko_manifest_alias_method_stars[i] == method_star) return JNI_TRUE;\n");
        sb.append("    }\n");
        sb.append("    return JNI_FALSE;\n");
        sb.append("}\n\n");
        sb.append("static NekoManifestMethod *neko_manifest_registered_entry(uint32_t idx, void *method_star) {\n");
        sb.append("    uint32_t i;\n");
        sb.append("    if (idx >= g_neko_manifest_method_count || method_star == NULL) return NULL;\n");
        sb.append("    if (g_neko_manifest_method_stars[idx] == method_star) return &g_neko_manifest_methods[idx];\n");
        sb.append("    for (i = 0u; i < g_neko_manifest_alias_count; i++) {\n");
        sb.append("        if (g_neko_manifest_alias_indices[i] == idx && g_neko_manifest_alias_method_stars[i] == method_star) {\n");
        sb.append("            return (NekoManifestMethod*)g_neko_manifest_alias_entry_ptrs[i];\n");
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("    return NULL;\n");
        sb.append("}\n\n");
        sb.append("static void *neko_manifest_owner_global_ref(JNIEnv *env, jclass owner_cls) {\n");
        sb.append("    jobject owner_global;\n");
        sb.append("    if (env == NULL || owner_cls == NULL) return NULL;\n");
        sb.append("    owner_global = g_neko_jni_new_global_ref_fn(env, owner_cls);\n");
        sb.append("    if (owner_global == NULL || neko_exception_check(env)) {\n");
        sb.append("        if (neko_exception_check(env)) neko_exception_clear_direct(env);\n");
        sb.append("        return NULL;\n");
        sb.append("    }\n");
        sb.append("    return (void*)owner_global;\n");
        sb.append("}\n\n");
        sb.append("static NekoManifestMethod *neko_manifest_prepare_patch_entry(JNIEnv *env, uint32_t idx, void *method_star, jclass owner_cls) {\n");
        sb.append("    NekoManifestMethod *entry;\n");
        sb.append("    NekoManifestMethod *registered;\n");
        sb.append("    uint32_t slot;\n");
        sb.append("    void *owner_global;\n");
        sb.append("    if (idx >= g_neko_manifest_method_count || method_star == NULL) return NULL;\n");
        sb.append("    entry = &g_neko_manifest_methods[idx];\n");
        sb.append("    registered = neko_manifest_registered_entry(idx, method_star);\n");
        sb.append("    if (registered != NULL) return registered;\n");
        sb.append("    if (g_neko_manifest_method_stars[idx] == NULL || g_neko_manifest_method_stars[idx] == method_star) {\n");
        sb.append("        if (entry->owner_class_global_ref == NULL && owner_cls != NULL) {\n");
        sb.append("            owner_global = neko_manifest_owner_global_ref(env, owner_cls);\n");
        sb.append("            if (owner_global != NULL) __atomic_store_n((void**)&entry->owner_class_global_ref, owner_global, __ATOMIC_RELEASE);\n");
        sb.append("        }\n");
        sb.append("        g_neko_manifest_method_stars[idx] = method_star;\n");
        sb.append("        return entry;\n");
        sb.append("    }\n");
        sb.append("    slot = __atomic_fetch_add(&g_neko_manifest_alias_count, 1u, __ATOMIC_ACQ_REL);\n");
        sb.append("    if (slot >= NEKO_METHOD_ALIAS_CAPACITY) {\n");
        sb.append("        __atomic_store_n(&g_neko_manifest_alias_count, NEKO_METHOD_ALIAS_CAPACITY, __ATOMIC_RELEASE);\n");
        sb.append("        return NULL;\n");
        sb.append("    }\n");
        sb.append("    g_neko_manifest_alias_entries[slot] = *entry;\n");
        sb.append("    owner_global = neko_manifest_owner_global_ref(env, owner_cls);\n");
        sb.append("    if (owner_global != NULL) {\n");
        sb.append("        g_neko_manifest_alias_entries[slot].owner_class_global_ref = owner_global;\n");
        sb.append("    }\n");
        sb.append("    g_neko_manifest_alias_entries[slot].patch_state = NEKO_PATCH_STATE_NONE;\n");
        sb.append("    g_neko_manifest_alias_indices[slot] = idx;\n");
        sb.append("    g_neko_manifest_alias_entry_ptrs[slot] = &g_neko_manifest_alias_entries[slot];\n");
        sb.append("    __atomic_store_n(&g_neko_manifest_alias_method_stars[slot], method_star, __ATOMIC_RELEASE);\n");
        sb.append("    return &g_neko_manifest_alias_entries[slot];\n");
        sb.append("}\n\n");
        sb.append("static void neko_manifest_abort_patch_failure(const NekoManifestMethod *entry, const char *phase) {\n");
        sb.append("    fprintf(stderr, \"[neko-patch] required method patch failed during %s: %s.%s%s\\n\",\n");
        sb.append("        phase != NULL ? phase : \"manifest discovery\",\n");
        sb.append("        entry != NULL && entry->owner_internal != NULL ? entry->owner_internal : \"?\",\n");
        sb.append("        entry != NULL && entry->method_name != NULL ? entry->method_name : \"?\",\n");
        sb.append("        entry != NULL && entry->method_desc != NULL ? entry->method_desc : \"?\");\n");
        sb.append("    abort();\n");
        sb.append("}\n\n");
        sb.append("static jboolean neko_manifest_resolve_one(JNIEnv *env, uint32_t idx, jclass owner_cls) {\n");
        sb.append("    NekoManifestMethod *entry;\n");
        sb.append("    NekoManifestMethod *patch_entry;\n");
        sb.append("    jmethodID mid;\n");
        sb.append("    void *method_star;\n");
        sb.append("    if (env == NULL || idx >= g_neko_manifest_method_count) return JNI_FALSE;\n");
        sb.append("    entry = &g_neko_manifest_methods[idx];\n");
        // T4.2b: route both static and instance method-id lookups through
        // the libjvm-internal neko_resolve_method_star_with_kind helper.
        // The patcher only needs Method*; neko_jmethodid_to_method_star and
        // the synthetic Method**-cell allocation are skipped entirely.
        // is_static is preserved so the resolver mirrors JNI
        // GetStaticMethodID / GetMethodID class-hierarchy walk semantics
        // (declared methods first, then superclasses; static-vs-instance
        // filter applied per Method::access_flags).
        //
        // Ensure the owner class is initialized first because JNI's
        // Get(Static)MethodID has the documented side effect of triggering
        // class init. Skipping init here causes Method::is_compiled() and
        // related state to be inconsistent at runtime, which surfaced as
        // Test 1.5/1.7/2.4-2.7 ERRORs in the implementation cycle that
        // tried the bare neko_resolve_method swap. neko_ensure_class_initialized
        // calls JVM_FindClassFromClass(init=true) which is idempotent for
        // already-initialized classes.
        sb.append("    (void)mid;\n");
        sb.append("    neko_ensure_class_initialized(env, owner_cls, entry->owner_internal);\n");
        sb.append("    method_star = neko_resolve_method_star_with_kind(env, owner_cls, entry->method_name, entry->method_desc, entry->is_static);\n");
        sb.append("    if (method_star == NULL) {\n");
        sb.append("        entry->patch_state = NEKO_PATCH_STATE_FAILED;\n");
        sb.append("        return JNI_FALSE;\n");
        sb.append("    }\n");
        sb.append("    patch_entry = neko_manifest_registered_entry(idx, method_star);\n");
        sb.append("    if (patch_entry != NULL) {\n");
        sb.append("        patch_entry->patch_state = NEKO_PATCH_STATE_APPLIED;\n");
        sb.append("        return JNI_TRUE;\n");
        sb.append("    }\n");
        sb.append("    patch_entry = neko_manifest_prepare_patch_entry(env, idx, method_star, owner_cls);\n");
        sb.append("    if (patch_entry == NULL || patch_entry->owner_class_global_ref == NULL) {\n");
        sb.append("        entry->patch_state = NEKO_PATCH_STATE_FAILED;\n");
        sb.append("        return JNI_FALSE;\n");
        sb.append("    }\n");
        sb.append("    if (!neko_patch_method_entry(method_star, patch_entry)) {\n");
        sb.append("        entry->patch_state = NEKO_PATCH_STATE_FAILED;\n");
        sb.append("        patch_entry->patch_state = NEKO_PATCH_STATE_FAILED;\n");
        sb.append("        return JNI_FALSE;\n");
        sb.append("    }\n");
        sb.append("    patch_entry->patch_state = NEKO_PATCH_STATE_APPLIED;\n");
        sb.append("    return JNI_TRUE;\n");
        sb.append("}\n\n");
        // T4.10: collapse the Class.getName() round-trip
        // (FindClass + GetMethodID + CallObjectMethodA + GetStringUTFChars +
        // ReleaseStringUTFChars — function-table indices 6/33/36/169/170)
        // into a Klass-direct read. owner_cls maps to a Klass via
        // neko_class_mirror_to_klass; Klass::_name is a Symbol*; Symbol::_body
        // is the UTF-8 internal name (already slash-form, no '.' translation
        // needed). All offsets (off_klass_name, off_symbol_length,
        // off_symbol_body) were collected at T0.1.
        sb.append("static jboolean neko_manifest_internal_name(JNIEnv *env, jclass owner_cls, char *out, size_t out_size) {\n");
        sb.append("    void *klass;\n");
        sb.append("    void *name_symbol;\n");
        sb.append("    uint16_t name_len;\n");
        sb.append("    const char *body;\n");
        sb.append("    size_t i;\n");
        sb.append("    (void)env;\n");
        sb.append("    if (owner_cls == NULL || out == NULL || out_size == 0u) return JNI_FALSE;\n");
        sb.append("    out[0] = '\\0';\n");
        sb.append("    if (g_neko_method_layout.off_klass_name < 0\n");
        sb.append("        || g_neko_method_layout.off_symbol_length < 0\n");
        sb.append("        || g_neko_method_layout.off_symbol_body < 0) {\n");
        sb.append("        fprintf(stderr, \"[neko-bind] T4.10 Symbol layout unavailable (klass_name=%td sym_len=%td sym_body=%td)\\n\",\n");
        sb.append("            g_neko_method_layout.off_klass_name,\n");
        sb.append("            g_neko_method_layout.off_symbol_length,\n");
        sb.append("            g_neko_method_layout.off_symbol_body);\n");
        sb.append("        abort();\n");
        sb.append("    }\n");
        sb.append("    klass = neko_class_mirror_to_klass(owner_cls);\n");
        sb.append("    if (klass == NULL) {\n");
        sb.append("        fprintf(stderr, \"[neko-bind] T4.10 cannot resolve Klass from jclass=%p\\n\", (void*)owner_cls);\n");
        sb.append("        abort();\n");
        sb.append("    }\n");
        sb.append("    name_symbol = *(void**)((char*)klass + g_neko_method_layout.off_klass_name);\n");
        sb.append("    if (name_symbol == NULL) return JNI_FALSE;\n");
        sb.append("    name_len = *(uint16_t*)((char*)name_symbol + g_neko_method_layout.off_symbol_length);\n");
        sb.append("    body = (const char*)name_symbol + g_neko_method_layout.off_symbol_body;\n");
        sb.append("    for (i = 0; i < (size_t)name_len && i + 1u < out_size; i++) out[i] = body[i];\n");
        sb.append("    out[i] = '\\0';\n");
        sb.append("    return out[0] != '\\0' ? JNI_TRUE : JNI_FALSE;\n");
        sb.append("}\n\n");
        sb.append("__attribute__((visibility(\"hidden\"))) jboolean neko_manifest_patch_defined_class(JNIEnv *env, jclass owner_cls) {\n");
        sb.append("    char owner_name[512];\n");
        sb.append("    if (env == NULL || owner_cls == NULL || g_neko_manifest_method_count == 0u) return JNI_TRUE;\n");
        sb.append("    if (!neko_manifest_internal_name(env, owner_cls, owner_name, sizeof(owner_name))) return JNI_FALSE;\n");
        for (Map.Entry<String, List<Integer>> e : byOwner.entrySet()) {
            sb.append("    if (strcmp(owner_name, \"").append(CStringLiteral.escape(e.getKey())).append("\") == 0) {\n");
            Integer bindId = ownerBindIds.get(e.getKey());
            if (bindId != null) {
                sb.append("        neko_bind_owner_").append(bindId).append("(env, owner_cls);\n");
            }
            for (int idx : e.getValue()) {
                sb.append("        if (!neko_manifest_resolve_one(env, ").append(idx).append("u, owner_cls))\n");
                sb.append("            neko_manifest_abort_patch_failure(&g_neko_manifest_methods[").append(idx).append("u], \"defineClass\");\n");
            }
            sb.append("        return JNI_TRUE;\n");
            sb.append("    }\n");
        }
        sb.append("    return JNI_TRUE;\n");
        sb.append("}\n\n");
        sb.append("static jboolean neko_manifest_discover_and_patch(JNIEnv *env) {\n");
        sb.append("    void *thread;\n");
        sb.append("    neko_handle_save_t manifest_window;\n");
        sb.append("    neko_handle_save_t owner_window;\n");
        sb.append("    jclass owner_cls;\n");
        sb.append("    jclass anchor_cls = NULL;\n");
        sb.append("    if (env == NULL || g_neko_manifest_method_count == 0u) return JNI_TRUE;\n");
        sb.append("    thread = neko_jni_env_to_thread(env);\n");
        sb.append("    if (thread == NULL) {\n");
        sb.append("        fprintf(stderr, \"[neko-bind] T4.6b manifest discovery has no JavaThread\\n\");\n");
        sb.append("        abort();\n");
        sb.append("    }\n");
        sb.append("    neko_handle_window_begin(thread, &manifest_window);\n");
        sb.append("    /* T4.2a discovery model: replace JNI FindClass (which uses the calling\n");
        sb.append("     * thread's classloader to trigger class loading) with a two-pass approach\n");
        sb.append("     * over libjvm-internal symbols.\n");
        sb.append("     *  Pass 1: walk the loaded-class graph (neko_try_resolve_class_mirror_with_env\n");
        sb.append("     *          with NULL from_class) to find any owner that is already loaded.\n");
        sb.append("     *          The first one becomes our anchor — by construction, the obfuscated\n");
        sb.append("     *          class whose <clinit> drove System.load is loaded.\n");
        sb.append("     *  Pass 2: for each owner, call the strict resolver with the anchor as\n");
        sb.append("     *          from_class. JVM_FindClassFromClass uses the anchor's defining\n");
        sb.append("     *          loader, which actively loads the class (mirrors what JNI FindClass\n");
        sb.append("     *          did via the calling thread's classloader). Per the T2.2 R-negative\n");
        sb.append("     *          gate inherited by T4.2a, missing class resolution aborts. */\n");
        for (Map.Entry<String, List<Integer>> e : byOwner.entrySet()) {
            if (e.getKey().contains("$NekoLambda$")) {
                continue;
            }
            sb.append("    if (anchor_cls == NULL) {\n");
            sb.append("        anchor_cls = neko_try_resolve_class_mirror_with_env(env, \"")
                .append(CStringLiteral.escape(e.getKey())).append("\", NULL);\n");
            sb.append("        if (neko_exception_check(env)) neko_exception_clear_direct(env);\n");
            sb.append("    }\n");
        }
        sb.append("    if (anchor_cls == NULL) {\n");
        sb.append("        fprintf(stderr, \"[neko-bind] T4.2a manifest discovery: no owner class loaded at JNI_OnLoad — cannot anchor classloader\\n\");\n");
        sb.append("        abort();\n");
        sb.append("    }\n");
        for (Map.Entry<String, List<Integer>> e : byOwner.entrySet()) {
            sb.append("    neko_handle_window_begin(thread, &owner_window);\n");
            sb.append("    owner_cls = neko_resolve_class_mirror_with_env(env, \"").append(CStringLiteral.escape(e.getKey())).append("\", anchor_cls, NULL);\n");
            sb.append("    if (owner_cls == NULL || neko_exception_check(env)) {\n");
            sb.append("        if (neko_exception_check(env)) neko_exception_clear_direct(env);\n");
            sb.append("    } else {\n");
            Integer bindId = ownerBindIds.get(e.getKey());
            if (bindId != null) {
                sb.append("        /* Bind this owner's per-class JNI cache (formerly via bindClass). */\n");
                sb.append("        neko_bind_owner_").append(bindId).append("(env, owner_cls);\n");
            }
            for (int idx : e.getValue()) {
                sb.append("        if (!neko_manifest_resolve_one(env, ").append(idx).append("u, owner_cls))\n");
                sb.append("            neko_manifest_abort_patch_failure(&g_neko_manifest_methods[").append(idx).append("u], \"JNI_OnLoad\");\n");
            }
            sb.append("    }\n");
            sb.append("    neko_handle_window_end(&owner_window);\n");
        }
        sb.append("    neko_handle_window_end(&manifest_window);\n");
        sb.append("    return JNI_TRUE;\n");
        sb.append("}\n\n");
        return sb.toString();
    }

}
