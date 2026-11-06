package dev.nekoobfuscator.native_.codegen.emit;

/**
 * Emits bootstrap initialization for resolved method layout and patcher state.
 */
final class MethodPatcherBootstrapEmitter {
    private MethodPatcherBootstrapEmitter() {}

    static String render() {
        return """
static jboolean neko_method_layout_init(JNIEnv *env) {
    if (g_neko_method_layout.initialized) return g_neko_method_layout.usable;
    g_neko_method_layout.initialized = JNI_TRUE;
    g_neko_method_layout.usable = JNI_FALSE;
    g_neko_method_layout.off_method_access_flags = -1;
    g_neko_method_layout.off_method_code = -1;
    g_neko_method_layout.off_method_i2i_entry = -1;
    g_neko_method_layout.off_method_from_interpreted_entry = -1;
    g_neko_method_layout.off_method_from_compiled_entry = -1;
    g_neko_method_layout.off_method_flags_status = -1;
    g_neko_method_layout.off_method_intrinsic_id = -1;
    g_neko_method_layout.off_method_vtable_index = -1;
    g_neko_method_layout.off_method_constMethod = -1;
    g_neko_method_layout.off_frame_anchor_sp = -1;
    g_neko_method_layout.off_frame_anchor_fp = -1;
    g_neko_method_layout.off_frame_anchor_pc = -1;
    g_neko_method_layout.off_jcw_anchor = -1;
    g_neko_method_layout.off_zglobals_address_offset_mask = -1;
    g_neko_method_layout.off_zglobals_pointer_load_good_mask = -1;
    g_neko_method_layout.off_zglobals_pointer_load_bad_mask = -1;
    g_neko_method_layout.off_zglobals_pointer_store_good_mask = -1;
    g_neko_method_layout.off_zglobals_pointer_store_bad_mask = -1;
    g_neko_method_layout.off_zglobals_pointer_load_shift = -1;
    g_neko_method_layout.off_z_thread_address_bad_mask = -1;
    g_neko_method_layout.off_basicobjectlock_lock = -1;
    g_neko_method_layout.off_basicobjectlock_obj = -1;
    g_neko_method_layout.off_basiclock_displaced_header = -1;
    g_neko_method_layout.off_thread_tlab = -1;
    g_neko_method_layout.off_tlab_top = -1;
    g_neko_method_layout.off_tlab_end = -1;
    g_neko_method_layout.off_instanceklass_methods = -1;
    g_neko_method_layout.off_instanceklass_fieldinfo_stream = -1;
    g_neko_method_layout.off_instanceklass_fields = -1;
    g_neko_method_layout.off_instanceklass_constants = -1;
    g_neko_method_layout.off_instanceklass_local_interfaces = -1;
    g_neko_method_layout.off_instanceklass_transitive_interfaces = -1;
    g_neko_method_layout.off_instanceklass_java_fields_count = -1;
    g_neko_method_layout.off_klass_super_check_offset = -1;
    g_neko_method_layout.off_klass_secondary_super_cache = -1;
    g_neko_method_layout.off_klass_secondary_supers = -1;
    g_neko_method_layout.off_klass_primary_supers_0 = -1;
    g_neko_method_layout.off_klass_layout_helper = -1;
    g_neko_method_layout.off_klass_java_mirror = -1;
    g_neko_method_layout.off_klass_super = -1;
    g_neko_method_layout.off_klass_subklass = -1;
    g_neko_method_layout.off_klass_next_link = -1;
    g_neko_method_layout.off_klass_name = -1;
    g_neko_method_layout.off_objarrayklass_element_klass = -1;
    g_neko_method_layout.off_java_lang_class_klass = -1;
    g_neko_method_layout.off_classloaderdata_next = -1;
    g_neko_method_layout.off_classloaderdata_klasses = -1;
    g_neko_method_layout.off_constantpool_tags = -1;
    g_neko_method_layout.off_constantpool_cache = -1;
    g_neko_method_layout.off_constantpool_pool_holder = -1;
    g_neko_method_layout.off_constantpool_operands = -1;
    g_neko_method_layout.off_constantpool_resolved_klasses = -1;
    g_neko_method_layout.off_constantpool_length = -1;
    g_neko_method_layout.off_constantpool_base = -1;
    g_neko_method_layout.sizeof_ConstantPool = 0;
    g_neko_method_layout.off_constmethod_constants = -1;
    g_neko_method_layout.off_constmethod_name_index = -1;
    g_neko_method_layout.off_constmethod_signature_index = -1;
    g_neko_method_layout.off_symbol_length = -1;
    g_neko_method_layout.off_symbol_body = -1;
    g_neko_method_layout.off_array_length = -1;
    g_neko_method_layout.off_array_data = -1;
    g_neko_method_layout.off_array_u1_data = -1;
    g_neko_method_layout.off_array_u2_data = -1;
    g_neko_method_layout.off_barrierset_fake_rtti = -1;
    g_neko_method_layout.off_barrierset_fakertti_concrete_tag = -1;
    g_neko_method_layout.off_cardtablebarrierset_card_table = -1;
    g_neko_method_layout.off_cardtable_byte_map_base = -1;
    g_neko_method_layout.vmconst_barrierset_modref = -1;
    g_neko_method_layout.vmconst_barrierset_cardtable = -1;
    g_neko_method_layout.vmconst_barrierset_g1 = -1;
    g_neko_method_layout.vmconst_barrierset_z = -1;
    g_neko_method_layout.vmconst_barrierset_shenandoah = -1;
    g_neko_method_layout.vmconst_cardtable_clean_card = -1;
    g_neko_method_layout.vmconst_cardtable_dirty_card = -1;
    g_neko_method_layout.vmconst_g1_young_card = -1;
    g_neko_method_layout.java_spec_version = 0;
    void *jvm = neko_resolve_libjvm_handle();
    jboolean jnihandles_symbols_ready = JNI_FALSE;
    NEKO_PATCH_LOG("layout_init: jdk=%d libjvm=%p", g_neko_method_layout.java_spec_version, jvm);
    if (jvm == NULL) return JNI_FALSE;
    neko_resolve_native_resolution_symbols(jvm);
    neko_resolve_gc_barrier_symbols(jvm);
    if (!neko_walk_vm_structs(jvm)) { NEKO_PATCH_LOG("walk_vm_structs failed"); return JNI_FALSE; }
    (void)neko_walk_vm_types(jvm);
    neko_walk_vm_int_constants(jvm);
    neko_walk_vm_long_constants(jvm);
    neko_walk_jvmci_vm_structs(jvm);
    neko_walk_jvmci_vm_constants(jvm);
    neko_scan_stripped_jvmci_vmstructs();
    if (g_neko_method_layout.access_not_c1_compilable == 0u) g_neko_method_layout.access_not_c1_compilable = NEKO_ACC_NOT_C1_COMPILABLE_FALLBACK;
    if (g_neko_method_layout.access_not_c2_compilable == 0u) g_neko_method_layout.access_not_c2_compilable = NEKO_ACC_NOT_C2_COMPILABLE_FALLBACK;
    if (g_neko_method_layout.access_not_osr_compilable == 0u) g_neko_method_layout.access_not_osr_compilable = NEKO_ACC_NOT_OSR_COMPILABLE_FALLBACK;
    /* MethodFlags::_status bit positions on JDK 21+ (not exposed via
     * VMIntConstants, but stable in OpenJDK source). Bit 0 = NOT_C1_COMPILABLE,
     * bit 1 = NOT_C2_COMPILABLE, bit 2 = NOT_C1_OSR_COMPILABLE,
     * bit 3 = NOT_C2_OSR_COMPILABLE. */
    if (g_neko_method_layout.method_flag_not_c1_compilable == 0u)  g_neko_method_layout.method_flag_not_c1_compilable  = 0x1u;
    if (g_neko_method_layout.method_flag_not_c2_compilable == 0u)  g_neko_method_layout.method_flag_not_c2_compilable  = 0x2u;
    if (g_neko_method_layout.method_flag_not_osr_compilable == 0u) g_neko_method_layout.method_flag_not_osr_compilable = 0x4u | 0x8u;
    if (g_neko_method_layout.off_frame_anchor_sp < 0
        && g_neko_method_layout.off_frame_anchor_pc == 8) {
        g_neko_method_layout.off_frame_anchor_sp = 0;
    }
    if (g_neko_method_layout.off_frame_anchor_fp < 0
        && g_neko_method_layout.off_frame_anchor_sp == 0
        && g_neko_method_layout.off_frame_anchor_pc == 8) {
        g_neko_method_layout.off_frame_anchor_fp = 16;
    }
    if (g_neko_method_layout.off_jcw_anchor < 0) {
        g_neko_method_layout.off_jcw_anchor = 32;
    }
    /* JDK 21+ does not expose Method::_flags via VMStructs. The actual layout
     * (verified against openjdk-21.0.10 method.hpp) is:
     *   ... _access_flags (u4) | _vtable_index (i4) | _intrinsic_id (u2) | _flags (u2) ...
     * So _flags is _intrinsic_id + 2. The earlier "intrinsic_id - 4" guess
     * pointed at unknown bytes (likely method identity/index padding) and
     * silently corrupted state. */
    if (g_neko_method_layout.off_method_flags_status < 0
        && g_neko_method_layout.off_method_intrinsic_id > 0) {
        g_neko_method_layout.off_method_flags_status =
            g_neko_method_layout.off_method_intrinsic_id + (ptrdiff_t)2;
    }
    jnihandles_symbols_ready = neko_resolve_jnihandles(jvm);
    if (g_neko_method_layout.off_method_access_flags < 0
        || g_neko_method_layout.off_method_code < 0
        || g_neko_method_layout.off_method_i2i_entry < 0
        || g_neko_method_layout.off_method_from_interpreted_entry < 0
        || g_neko_method_layout.off_method_from_compiled_entry < 0) {
        NEKO_PATCH_LOG("missing required Method offset; patcher disabled");
        return JNI_FALSE;
    }
    /* VMStructs only registers JavaThread::_jni_environment under JVMCI.
     * Without it, the dispatcher cannot recover JNIEnv* without a JNI
     * GetEnv() round-trip — which violates the no-runtime-JNI rule. Derive
     * the offset directly: r15 holds JavaThread* on x86_64 SysV (HotSpot
     * convention), env is a pointer to the embedded _jni_environment field,
     * so off = (char*)env - (char*)r15. Done once at JNI_OnLoad. */
    if (g_neko_method_layout.off_thread_jni_environment <= 0 && env != NULL) {
        /* Use the thread-register snapshot captured at JNI_OnLoad entry.
         * Reading r15 here would be unreliable: clang freely reassigns r15
         * to local variables once we are deep in the C code. */
        void *jt = g_neko_jni_onload_thread_reg;
        if (jt != NULL) {
            ptrdiff_t derived = (ptrdiff_t)((char*)env - (char*)jt);
            if (derived > 0 && derived < 0x10000) {
                g_neko_method_layout.off_thread_jni_environment = derived;
                NEKO_PATCH_LOG("derived off_thread_jni_environment=%td via thread_reg=%p env=%p",
                    derived, jt, (void*)env);
            } else {
                NEKO_PATCH_LOG("derived off_thread_jni_environment unreasonable: derived=%td jt=%p env=%p",
                    derived, jt, (void*)env);
            }
        }
    }
    NEKO_PATCH_LOG("offsets: af=%td code=%td i2i=%td fi=%td fc=%td flags=%td af_sz=%zu",
        g_neko_method_layout.off_method_access_flags,
        g_neko_method_layout.off_method_code,
        g_neko_method_layout.off_method_i2i_entry,
        g_neko_method_layout.off_method_from_interpreted_entry,
        g_neko_method_layout.off_method_from_compiled_entry,
        g_neko_method_layout.off_method_flags_status,
        g_neko_method_layout.access_flags_size);
    NEKO_PATCH_LOG("thread: state_off=%td poll_off=%td in_java=%d in_native=%d in_native_trans=%d",
        g_neko_method_layout.off_thread_state,
        g_neko_method_layout.off_thread_polling_word,
        g_neko_method_layout.thread_state_in_java,
        g_neko_method_layout.thread_state_in_native,
        g_neko_method_layout.thread_state_in_native_trans);
    /* Publish thread-state info to the asm-visible globals. */
    g_neko_off_thread_state             = g_neko_method_layout.off_thread_state;
    g_neko_thread_state_in_java         = g_neko_method_layout.thread_state_in_java;
    g_neko_thread_state_in_native       = g_neko_method_layout.thread_state_in_native;
    g_neko_thread_state_in_native_trans = g_neko_method_layout.thread_state_in_native_trans;
    g_neko_off_thread_polling_word      = g_neko_method_layout.off_thread_polling_word;
    g_neko_thread_state_ready =
        (g_neko_method_layout.off_thread_state != 0
         && g_neko_method_layout.thread_state_in_java != g_neko_method_layout.thread_state_in_native)
        ? JNI_TRUE : JNI_FALSE;
    /* Resolve frame-anchor final offsets: direct fields take priority,
     * else compute from anchor + sub-offset. */
    if (g_neko_method_layout.off_thread_last_Java_sp_direct > 0) {
        g_neko_off_last_Java_sp = g_neko_method_layout.off_thread_last_Java_sp_direct;
    } else if (g_neko_method_layout.off_thread_anchor > 0) {
        g_neko_off_last_Java_sp = g_neko_method_layout.off_thread_anchor + g_neko_method_layout.off_frame_anchor_sp;
    }
    if (g_neko_method_layout.off_thread_last_Java_fp_direct > 0) {
        g_neko_off_last_Java_fp = g_neko_method_layout.off_thread_last_Java_fp_direct;
    } else if (g_neko_method_layout.off_thread_anchor > 0) {
        g_neko_off_last_Java_fp = g_neko_method_layout.off_thread_anchor + g_neko_method_layout.off_frame_anchor_fp;
    }
    if (g_neko_method_layout.off_thread_last_Java_pc_direct > 0) {
        g_neko_off_last_Java_pc = g_neko_method_layout.off_thread_last_Java_pc_direct;
    } else if (g_neko_method_layout.off_thread_anchor > 0) {
        g_neko_off_last_Java_pc = g_neko_method_layout.off_thread_anchor + g_neko_method_layout.off_frame_anchor_pc;
    }
    g_neko_frame_anchor_ready = (g_neko_off_last_Java_sp > 0) ? JNI_TRUE : JNI_FALSE;
    NEKO_PATCH_LOG("anchor: sp=%td fp=%td pc=%td ready=%d",
        g_neko_off_last_Java_sp, g_neko_off_last_Java_fp, g_neko_off_last_Java_pc,
        (int)g_neko_frame_anchor_ready);
    g_neko_off_jcw_anchor = g_neko_method_layout.off_jcw_anchor;
    NEKO_PATCH_LOG("call_stub: entry=%p ret_slot=%p ret=%p jcw_anchor=%td jcw_size=%zu",
        g_neko_call_stub_entry,
        g_neko_method_layout.addr_call_stub_return_address,
        g_neko_call_stub_return_address,
        g_neko_off_jcw_anchor,
        g_neko_method_layout.sizeof_JavaCallWrapper);
    g_neko_off_thread_active_handles = g_neko_method_layout.off_thread_active_handles;
    g_neko_off_jnih_block_top        = g_neko_method_layout.off_jnih_block_top;
    g_neko_off_jnih_block_handles    = g_neko_method_layout.off_jnih_block_handles;
    g_neko_off_thread_pending_exception = g_neko_method_layout.off_thread_pending_exception;
    g_neko_handle_push_ready =
        (g_neko_off_thread_active_handles > 0
         && g_neko_off_jnih_block_top >= 0
         && g_neko_off_jnih_block_handles >= 0)
        ? JNI_TRUE : JNI_FALSE;
    if (!jnihandles_symbols_ready && !g_neko_handle_push_ready) {
        NEKO_PATCH_LOG("JNIHandles symbols and JNIHandleBlock layout unavailable; aborting native layout initialization");
        return JNI_FALSE;
    }
    if (!jnihandles_symbols_ready) {
        NEKO_PATCH_LOG("JNIHandles symbols not resolvable; using VMStruct JNIHandleBlock local handles");
    }
    g_neko_off_thread_tlab = g_neko_method_layout.off_thread_tlab;
    g_neko_off_tlab_top = g_neko_method_layout.off_tlab_top;
    g_neko_off_tlab_end = g_neko_method_layout.off_tlab_end;
    g_neko_tlab_alloc_ready =
        (g_neko_off_thread_tlab > 0
         && g_neko_off_tlab_top >= 0
         && g_neko_off_tlab_end > 0)
        ? JNI_TRUE : JNI_FALSE;
    NEKO_PATCH_LOG("handles: th_active=%td blk_top=%td blk_handles=%td blk_size=%zu pend_exc=%td ready=%d tlab=%td top=%td end=%td tlab_ready=%d",
        g_neko_off_thread_active_handles, g_neko_off_jnih_block_top,
        g_neko_off_jnih_block_handles, g_neko_method_layout.sizeof_JNIHandleBlock,
        g_neko_off_thread_pending_exception,
        (int)g_neko_handle_push_ready,
        g_neko_off_thread_tlab, g_neko_off_tlab_top, g_neko_off_tlab_end,
        (int)g_neko_tlab_alloc_ready);
    NEKO_PATCH_LOG("jni env: off=%td", g_neko_method_layout.off_thread_jni_environment);
    g_neko_method_layout.native_resolution_ready = neko_native_resolution_layout_ready();
    g_neko_native_resolution_ready = g_neko_method_layout.native_resolution_ready;
    g_neko_addr_compressed_oops_base = g_neko_method_layout.addr_compressed_oops_base;
    g_neko_addr_compressed_oops_shift = g_neko_method_layout.addr_compressed_oops_shift;
    g_neko_addr_compressed_klass_base = g_neko_method_layout.addr_compressed_klass_base;
    g_neko_addr_compressed_klass_shift = g_neko_method_layout.addr_compressed_klass_shift;
    NEKO_PATCH_LOG("native resolution: ready=%d ik_methods=%td ik_fields=%td ik_fieldinfo=%td ik_java_fields=%td ik_constants=%td klass_mirror=%td class_klass=%td klass_super=%td klass_supers=%td cp_tags=%td cp_holder=%td cp_len=%td cp_base=%td cp_size=%zu method_const=%td cm_name=%td cm_sig=%td symbol_len=%td symbol_body=%td array_len=%td array_data=%td array_u1_data=%td array_u2_data=%td universe_heap=%p bs=%p bs_rtti=%td bs_tag=%td jvm_find_loaded=%p boot_find=%p class_find=%p jvm_intern=%p jvm_prim=%p jvm_array=%p/%p string_intern=%p/%p oopfactory=%p/%p",
        (int)g_neko_native_resolution_ready,
        g_neko_method_layout.off_instanceklass_methods,
        g_neko_method_layout.off_instanceklass_fields,
        g_neko_method_layout.off_instanceklass_fieldinfo_stream,
        g_neko_method_layout.off_instanceklass_java_fields_count,
        g_neko_method_layout.off_instanceklass_constants,
        g_neko_method_layout.off_klass_java_mirror,
        g_neko_method_layout.off_java_lang_class_klass,
        g_neko_method_layout.off_klass_super,
        g_neko_method_layout.off_klass_secondary_supers,
        g_neko_method_layout.off_constantpool_tags,
        g_neko_method_layout.off_constantpool_pool_holder,
        g_neko_method_layout.off_constantpool_length,
        g_neko_method_layout.off_constantpool_base,
        g_neko_method_layout.sizeof_ConstantPool,
        g_neko_method_layout.off_method_constMethod,
        g_neko_method_layout.off_constmethod_name_index,
        g_neko_method_layout.off_constmethod_signature_index,
        g_neko_method_layout.off_symbol_length,
        g_neko_method_layout.off_symbol_body,
        g_neko_method_layout.off_array_length,
        g_neko_method_layout.off_array_data,
        g_neko_method_layout.off_array_u1_data,
        g_neko_method_layout.off_array_u2_data,
        g_neko_method_layout.addr_universe_collected_heap,
        g_neko_method_layout.addr_barrierset_barrier_set,
        g_neko_method_layout.off_barrierset_fake_rtti,
        g_neko_method_layout.off_barrierset_fakertti_concrete_tag,
        g_neko_method_layout.sym_jvm_find_loaded_class,
        g_neko_method_layout.sym_jvm_find_class_from_boot_loader,
        g_neko_method_layout.sym_jvm_find_class_from_class,
        g_neko_method_layout.sym_jvm_intern_string,
        g_neko_method_layout.sym_jvm_find_primitive_class,
        g_neko_method_layout.sym_jvm_new_array,
        g_neko_method_layout.sym_jvm_new_multi_array,
        g_neko_method_layout.sym_stringtable_intern_symbol,
        g_neko_method_layout.sym_stringtable_intern_utf8,
        g_neko_method_layout.sym_oopfactory_new_type_array,
        g_neko_method_layout.sym_oopfactory_new_obj_array);
    NEKO_PATCH_LOG("codecache layout: heaps=%p ga_len=%td ga_data=%td ch_mem=%td ch_seg=%td ch_log2=%td vs_low=%td vs_high=%td blob_name=%td blob_size=%td blob_code_begin=%td",
        g_neko_method_layout.addr_codecache_heaps,
        g_neko_method_layout.off_growable_array_len,
        g_neko_method_layout.off_growable_array_data,
        g_neko_method_layout.off_codeheap_memory,
        g_neko_method_layout.off_codeheap_segmap,
        g_neko_method_layout.off_codeheap_log2_segment_size,
        g_neko_method_layout.off_virtualspace_low,
        g_neko_method_layout.off_virtualspace_high,
        g_neko_method_layout.off_codeblob_name,
        g_neko_method_layout.off_codeblob_size,
        g_neko_method_layout.off_codeblob_code_begin);
    /* Private CodeHeap entry is mandatory. The codecache walk harvests the
     * AdapterBlob/BufferBlob vtable used by our synthetic blobs; if any part
     * of that setup fails, native entry patching must fail instead of leaving
     * the original JVM entry active. */
    if (!neko_codecache_walk()) {
        NEKO_PATCH_LOG("private CodeHeap setup failed: codecache walk did not harvest a vtable");
        return JNI_FALSE;
    }
    if (!neko_priv_heap_init()) {
        NEKO_PATCH_LOG("private CodeHeap setup failed: init failed");
        return JNI_FALSE;
    }
    if (!neko_priv_heap_register()) {
        NEKO_PATCH_LOG("private CodeHeap setup failed: registration failed");
        return JNI_FALSE;
    }
    /* Native→Java direct invoke now enters through HotSpot call_stub. */
    neko_njx_init_wrappers();
    /* T4.0: Publish JNIEnv->JavaThread distance EAGERLY before
     * neko_method_layout_init returns. The hot-path neko_exception_check
     * (renderHotSpotSupport region) reads this via a single non-atomic
     * load + pointer arithmetic + _pending_exception read; it no longer
     * contains a fallback resolver branch, so missing publication here
     * must abort layout init. Source order:
     *   1. VMStructs path: production HotSpot redacts off_thread_jni_environment
     *      from gHotSpotVMStructs, but JVMCI / debug builds expose it. Use
     *      the harvested offset directly when available.
     *   2. Memory-walk fallback: for production HotSpot, scan once with
     *      the bootstrap JNIEnv. The resolver function
     *      neko_exception_check_resolve_env_offset() is defined earlier
     *      in this translation unit (renderHotSpotSupport) and is marked
     *      cold/noinline so it is unreachable from the hot path.
     *   3. Both fail → return JNI_FALSE so JNI_OnLoad aborts. The hot
     *      path never has to derive the offset; the cold __builtin_expect
     *      abort in neko_exception_check exists only as a defensive guard
     *      for tear-down races. */
    if (getenv("NEKO_NATIVE_DIAG_FAIL_ENV_OFFSET_PUBLICATION") != NULL) {
        g_neko_off_thread_jni_environment_for_check = 0;
        g_neko_method_layout.off_thread_jni_environment = -1;
        NEKO_PATCH_LOG("eager env-offset publication forced missing by diagnostic gate; refusing to enter translated native path");
        return JNI_FALSE;
    }
    if (g_neko_method_layout.off_thread_jni_environment > 0) {
        g_neko_off_thread_jni_environment_for_check =
            g_neko_method_layout.off_thread_jni_environment;
        g_neko_env_offset_publication_kind = 1;
    }
    if (g_neko_off_thread_jni_environment_for_check <= 0) {
        if (env == NULL) {
            NEKO_PATCH_LOG("eager env-offset publication blocked: bootstrap JNIEnv is NULL");
            return JNI_FALSE;
        }
        if (g_neko_jni_functions_table == NULL) {
            NEKO_PATCH_LOG("eager env-offset publication blocked: jni_functions_table not captured");
            return JNI_FALSE;
        }
        if (g_neko_off_thread_pending_exception <= 0) {
            NEKO_PATCH_LOG("eager env-offset publication blocked: pending_exception offset unavailable (off=%td)",
                g_neko_off_thread_pending_exception);
            return JNI_FALSE;
        }
        if (!neko_exception_check_resolve_env_offset(env)) {
            NEKO_PATCH_LOG("eager env-offset publication failed (functions_table=%p pending_off=%td); hot-path neko_exception_check would have aborted on first translated method dispatch",
                g_neko_jni_functions_table, g_neko_off_thread_pending_exception);
            return JNI_FALSE;
        }
        /* Mirror the just-derived offset into method_layout so the inline
         * dispatcher helper neko_thread_jni_env() fast-paths from the very
         * first call (otherwise its slow-path scan would still fire once
         * per process). The offset is direction-symmetric: the resolver
         * scans env→thread, neko_thread_jni_env scans thread→env, both
         * derive the same K such that thread = env - K = env_addr at
         * (thread + K). */
        if (g_neko_off_thread_jni_environment_for_check > 0
            && g_neko_method_layout.off_thread_jni_environment <= 0) {
            g_neko_method_layout.off_thread_jni_environment =
                g_neko_off_thread_jni_environment_for_check;
        }
        if (g_neko_env_offset_publication_kind == 2) {
            NEKO_PATCH_LOG("eager env-offset publication via process cache: off=%td",
                g_neko_off_thread_jni_environment_for_check);
        } else {
            NEKO_PATCH_LOG("eager env-offset publication via memory walk: off=%td (VMStructs did not expose JavaThread::_jni_environment)",
                g_neko_off_thread_jni_environment_for_check);
        }
    } else {
        NEKO_PATCH_LOG("eager env-offset publication via VMStructs: off=%td",
            g_neko_off_thread_jni_environment_for_check);
    }
    g_neko_basictype_void    = g_neko_method_layout.basictype_void;
    g_neko_basictype_boolean = g_neko_method_layout.basictype_boolean;
    g_neko_basictype_byte    = g_neko_method_layout.basictype_byte;
    g_neko_basictype_char    = g_neko_method_layout.basictype_char;
    g_neko_basictype_short   = g_neko_method_layout.basictype_short;
    g_neko_basictype_int     = g_neko_method_layout.basictype_int;
    g_neko_basictype_long    = g_neko_method_layout.basictype_long;
    g_neko_basictype_float   = g_neko_method_layout.basictype_float;
    g_neko_basictype_double  = g_neko_method_layout.basictype_double;
    g_neko_basictype_object  = g_neko_method_layout.basictype_object;
    g_neko_basictype_array   = g_neko_method_layout.basictype_array;
    g_neko_runtime1_monitorenter_entry = g_neko_method_layout.runtime1_monitorenter_entry;
    g_neko_runtime1_monitorexit_entry = g_neko_method_layout.runtime1_monitorexit_entry;
    g_neko_off_basicobjectlock_lock = g_neko_method_layout.off_basicobjectlock_lock;
    g_neko_off_basicobjectlock_obj = g_neko_method_layout.off_basicobjectlock_obj;
    g_neko_off_basiclock_displaced_header = g_neko_method_layout.off_basiclock_displaced_header;
    g_neko_sizeof_basicobjectlock = g_neko_method_layout.sizeof_BasicObjectLock;
    g_neko_sizeof_basiclock = g_neko_method_layout.sizeof_BasicLock;
    g_neko_monitor_stub_ready =
        (g_neko_runtime1_monitorenter_entry != NULL
         && g_neko_runtime1_monitorexit_entry != NULL
         && g_neko_off_basicobjectlock_lock >= 0
         && g_neko_off_basicobjectlock_obj >= 0
         && g_neko_off_basiclock_displaced_header >= 0
         && g_neko_sizeof_basicobjectlock > 0
         && g_neko_sizeof_basiclock > 0)
        ? JNI_TRUE : JNI_FALSE;
    NEKO_PATCH_LOG("monitor stubs: enter=%p exit=%p bol_lock=%td bol_obj=%td block_hdr=%td bol_size=%zu block_size=%zu ready=%d",
        g_neko_runtime1_monitorenter_entry,
        g_neko_runtime1_monitorexit_entry,
        g_neko_off_basicobjectlock_lock,
        g_neko_off_basicobjectlock_obj,
        g_neko_off_basiclock_displaced_header,
        g_neko_sizeof_basicobjectlock,
        g_neko_sizeof_basiclock,
        (int)g_neko_monitor_stub_ready);
    /* Publish the heap base value (for %r12 setup before Java calls). On
     * zero-based compressed oops this is NULL; with non-zero base we must
     * publish the actual base. Read from the harvested CompressedOops slot
     * if available, else fall back to whatever neko_hotspot_init resolved. */
    if (g_neko_method_layout.addr_compressed_oops_base != NULL) {
        g_neko_heap_base = *(void**)g_neko_method_layout.addr_compressed_oops_base;
    } else if (g_hotspot.compressed_oops_enabled) {
        g_neko_heap_base = (void*)(uintptr_t)g_hotspot.compressed_oops_base;
    } else {
        g_neko_heap_base = NULL;
    }
    NEKO_PATCH_LOG("heap base: %p", g_neko_heap_base);
    /* Direct-invoke readiness: we need the compiled-entry offset (for
     * Method* → entry pointer extraction at the call site), the thread-state
     * machinery (for the in_native ↔ in_Java transition around the call),
     * the frame-anchor offsets (for GC stack walking), and the
     * active-handles slot (for ref arg/return marshalling). */
    g_neko_direct_invoke_ready =
        (g_neko_method_layout.off_method_from_interpreted_entry > 0
         && g_neko_thread_state_ready
         && g_neko_off_last_Java_sp > 0
         && g_neko_off_last_Java_fp > 0
         && g_neko_off_last_Java_pc > 0
         && g_neko_off_thread_active_handles > 0
         && g_neko_call_stub_entry != NULL
         && g_neko_off_jcw_anchor > 0)
        ? JNI_TRUE : JNI_FALSE;
    NEKO_PATCH_LOG("direct invoke: centry_off=%td ientry_off=%td thread_ready=%d anchor_ok=%d call_stub=%p ready=%d",
        g_neko_method_layout.off_method_from_compiled_entry,
        g_neko_method_layout.off_method_from_interpreted_entry,
        (int)g_neko_thread_state_ready, (int)(g_neko_off_last_Java_sp > 0),
        g_neko_call_stub_entry,
        (int)g_neko_direct_invoke_ready);
    /* Pull compressed-oops state directly from VMStructs. */
    if (g_neko_method_layout.addr_compressed_oops_shift != NULL) {
        int shift = *(int*)g_neko_method_layout.addr_compressed_oops_shift;
        void *base = (g_neko_method_layout.addr_compressed_oops_base != NULL)
            ? *(void**)g_neko_method_layout.addr_compressed_oops_base
            : NULL;
        /* HotSpot keeps shift = 0 when compressed oops are disabled OR when
         * the heap is small enough to fit below 4GB unshifted. In both
         * variants oops still occupy 4-byte slots in compressed mode, so
         * we treat any presence of the symbol as "compressed oops on" and
         * use the published shift verbatim. */
        g_hotspot.compressed_oops_enabled = JNI_TRUE;
        g_hotspot.compressed_oops_shift = shift;
        g_hotspot.compressed_oops_base = (jlong)(uintptr_t)base;
        NEKO_PATCH_LOG("vmstructs coop: shift=%d base=%p", shift, base);
    }
    if (g_neko_method_layout.addr_zglobals_address_offset_mask != NULL
        && g_neko_method_layout.addr_zglobals_pointer_load_good_mask != NULL
        && g_neko_method_layout.addr_zglobals_pointer_load_bad_mask != NULL
        && g_neko_method_layout.addr_zglobals_pointer_store_good_mask != NULL
        && g_neko_method_layout.addr_zglobals_pointer_store_bad_mask != NULL
        && g_neko_method_layout.addr_zglobals_pointer_load_shift != NULL) {
        uintptr_t *addr_mask_p = *(uintptr_t**)g_neko_method_layout.addr_zglobals_address_offset_mask;
        uintptr_t *load_good_p = *(uintptr_t**)g_neko_method_layout.addr_zglobals_pointer_load_good_mask;
        uintptr_t *load_bad_p = *(uintptr_t**)g_neko_method_layout.addr_zglobals_pointer_load_bad_mask;
        uintptr_t *store_good_p = *(uintptr_t**)g_neko_method_layout.addr_zglobals_pointer_store_good_mask;
        uintptr_t *store_bad_p = *(uintptr_t**)g_neko_method_layout.addr_zglobals_pointer_store_bad_mask;
        size_t *load_shift_p = *(size_t**)g_neko_method_layout.addr_zglobals_pointer_load_shift;
        if (addr_mask_p != NULL && load_good_p != NULL && load_bad_p != NULL && store_good_p != NULL && store_bad_p != NULL && load_shift_p != NULL
            && *addr_mask_p != 0 && (*load_good_p != 0 || *load_bad_p != 0)) {
            g_hotspot.use_zgc = JNI_TRUE;
            g_hotspot.compressed_oops_enabled = JNI_FALSE;
            g_hotspot.compressed_oops_shift = 0;
            g_hotspot.compressed_oops_base = 0;
            g_hotspot.z_address_offset_mask = *addr_mask_p;
            g_hotspot.z_pointer_load_good_mask = *load_good_p;
            g_hotspot.z_pointer_load_bad_mask = *load_bad_p;
            g_hotspot.z_pointer_store_good_mask = *store_good_p;
            g_hotspot.z_pointer_store_bad_mask = *store_bad_p;
            g_hotspot.z_pointer_load_shift = *load_shift_p;
            g_hotspot.fast_bits &= ~(NEKO_HOTSPOT_FAST_RAW_HEAP | NEKO_FAST_RECEIVER_KEY);
            NEKO_PATCH_LOG("zgc vmstructs(static): offset_mask=0x%llx load_good=0x%llx load_bad=0x%llx store_good=0x%llx shift=%zu",
                (unsigned long long)g_hotspot.z_address_offset_mask,
                (unsigned long long)g_hotspot.z_pointer_load_good_mask,
                (unsigned long long)g_hotspot.z_pointer_load_bad_mask,
                (unsigned long long)g_hotspot.z_pointer_store_good_mask,
                g_hotspot.z_pointer_load_shift);
        }
    }
    /* Publish live mask pointers so the inline ZGC barrier in
     * CCodeGenerator can read fresh values per call. The pointer-to-
     * mask layout matches modern generational ZGC (JDK 21+) where each
     * mask lives at a stable address but its value changes per GC
     * cycle. Even when the early mask probe sees zero values at OnLoad,
     * the pointers themselves are valid and readable. */
    if (g_neko_method_layout.addr_zglobals_instance_p != NULL) {
        void *zg = *(void**)g_neko_method_layout.addr_zglobals_instance_p;
        if (zg != NULL) {
            if (g_neko_method_layout.off_zglobals_address_offset_mask >= 0) {
                g_hotspot.z_zglobals_addr_mask_p =
                    *(void**)((char*)zg + g_neko_method_layout.off_zglobals_address_offset_mask);
            }
            if (g_neko_method_layout.off_zglobals_pointer_load_bad_mask >= 0) {
                g_hotspot.z_zglobals_load_bad_mask_p =
                    *(void**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_load_bad_mask);
            }
            if (g_neko_method_layout.off_zglobals_pointer_load_good_mask >= 0) {
                g_hotspot.z_zglobals_load_good_mask_p =
                    *(void**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_load_good_mask);
            }
            if (g_neko_method_layout.off_zglobals_pointer_store_good_mask >= 0) {
                g_hotspot.z_zglobals_store_good_mask_p =
                    *(void**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_store_good_mask);
            }
            if (g_neko_method_layout.off_zglobals_pointer_store_bad_mask >= 0) {
                g_hotspot.z_zglobals_store_bad_mask_p =
                    *(void**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_store_bad_mask);
            }
        }
    }
    if (g_hotspot.z_address_offset_mask == 0 && g_neko_method_layout.addr_zglobals_instance_p != NULL) {
        void *zg = *(void**)g_neko_method_layout.addr_zglobals_instance_p;
        if (zg != NULL
            && g_neko_method_layout.off_zglobals_address_offset_mask >= 0
            && g_neko_method_layout.off_zglobals_pointer_load_good_mask >= 0
            && g_neko_method_layout.off_zglobals_pointer_load_bad_mask >= 0
            && g_neko_method_layout.off_zglobals_pointer_store_good_mask >= 0
            && g_neko_method_layout.off_zglobals_pointer_store_bad_mask >= 0
            && g_neko_method_layout.off_zglobals_pointer_load_shift >= 0) {
            uintptr_t *addr_mask_p = *(uintptr_t**)((char*)zg + g_neko_method_layout.off_zglobals_address_offset_mask);
            uintptr_t *load_good_p = *(uintptr_t**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_load_good_mask);
            uintptr_t *load_bad_p = *(uintptr_t**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_load_bad_mask);
            uintptr_t *store_good_p = *(uintptr_t**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_store_good_mask);
            uintptr_t *store_bad_p = *(uintptr_t**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_store_bad_mask);
            size_t *load_shift_p = *(size_t**)((char*)zg + g_neko_method_layout.off_zglobals_pointer_load_shift);
            uintptr_t addr_mask = addr_mask_p != NULL ? *addr_mask_p : 0;
            uintptr_t load_good = load_good_p != NULL ? *load_good_p : 0;
            uintptr_t load_bad = load_bad_p != NULL ? *load_bad_p : 0;
            uintptr_t store_good = store_good_p != NULL ? *store_good_p : 0;
            uintptr_t store_bad = store_bad_p != NULL ? *store_bad_p : 0;
            size_t load_shift = load_shift_p != NULL ? *load_shift_p : 0;
            NEKO_PATCH_LOG("zgc vmstructs(instance raw): zg=%p offset_mask_p=%p load_good_p=%p load_bad_p=%p store_good_p=%p shift_p=%p",
                zg, (void*)addr_mask_p, (void*)load_good_p, (void*)load_bad_p, (void*)store_good_p, (void*)load_shift_p);
            NEKO_PATCH_LOG("zgc vmstructs(instance val): offset_mask=0x%llx load_good=0x%llx load_bad=0x%llx store_good=0x%llx shift=%zu",
                (unsigned long long)addr_mask,
                (unsigned long long)load_good,
                (unsigned long long)load_bad,
                (unsigned long long)store_good,
                load_shift);
            if (addr_mask != 0 && (load_good != 0 || load_bad != 0)) {
                g_hotspot.use_zgc = JNI_TRUE;
                g_hotspot.compressed_oops_enabled = JNI_FALSE;
                g_hotspot.compressed_oops_shift = 0;
                g_hotspot.compressed_oops_base = 0;
                g_hotspot.z_address_offset_mask = addr_mask;
                g_hotspot.z_pointer_load_good_mask = load_good;
                g_hotspot.z_pointer_load_bad_mask = load_bad;
                g_hotspot.z_pointer_store_good_mask = store_good;
                g_hotspot.z_pointer_store_bad_mask = store_bad;
                g_hotspot.z_pointer_load_shift = load_shift;
                g_hotspot.fast_bits &= ~(NEKO_HOTSPOT_FAST_RAW_HEAP | NEKO_FAST_RECEIVER_KEY);
                NEKO_PATCH_LOG("zgc vmstructs: offset_mask=0x%llx load_good=0x%llx load_bad=0x%llx store_good=0x%llx shift=%zu",
                    (unsigned long long)g_hotspot.z_address_offset_mask,
                    (unsigned long long)g_hotspot.z_pointer_load_good_mask,
                    (unsigned long long)g_hotspot.z_pointer_load_bad_mask,
                    (unsigned long long)g_hotspot.z_pointer_store_good_mask,
                    g_hotspot.z_pointer_load_shift);
            }
        }
    }
    if (JNI_FALSE && g_hotspot.z_address_offset_mask == 0
        && g_hotspot.compressed_oops_shift == 0
        && g_neko_handle_sample_oop != 0) {
        uintptr_t sample = g_neko_handle_sample_oop;
        int bit = (int)(sizeof(uintptr_t) * 8u) - 1;
        while (bit >= 44 && ((sample & ((uintptr_t)1u << bit)) == 0)) bit--;
        if (bit >= 44 && bit <= (int)(sizeof(uintptr_t) * 8u) - 4) {
            uintptr_t metadata_mask = ((uintptr_t)0xfu) << bit;
            uintptr_t good_mask = sample & metadata_mask;
            uintptr_t offset_mask = ((uintptr_t)1u << bit) - 1u;
            if (good_mask != 0 && (sample & offset_mask) != 0) {
                g_hotspot.use_zgc = JNI_TRUE;
                g_hotspot.compressed_oops_enabled = JNI_FALSE;
                g_hotspot.compressed_oops_shift = 0;
                g_hotspot.compressed_oops_base = 0;
                g_hotspot.z_address_offset_mask = offset_mask;
                g_hotspot.z_pointer_load_good_mask = good_mask;
                g_hotspot.z_pointer_load_bad_mask = metadata_mask & ~good_mask;
                g_hotspot.z_pointer_store_good_mask = good_mask;
                g_hotspot.z_pointer_load_shift = 0;
                g_hotspot.fast_bits &= ~(NEKO_HOTSPOT_FAST_RAW_HEAP | NEKO_FAST_RECEIVER_KEY);
                NEKO_PATCH_LOG("zgc handle-sample: sample=%p offset_mask=0x%llx good=0x%llx bad=0x%llx",
                    (void*)sample,
                    (unsigned long long)g_hotspot.z_address_offset_mask,
                    (unsigned long long)g_hotspot.z_pointer_load_good_mask,
                    (unsigned long long)g_hotspot.z_pointer_load_bad_mask);
            }
        }
    }
    neko_detect_current_gc_barrier();
    g_neko_method_layout.gc_barrier_ready = neko_gc_barrier_layout_ready();
    g_neko_gc_barrier_ready = g_neko_method_layout.gc_barrier_ready;
    g_neko_gc_barrier_kind = g_neko_method_layout.current_barrier_kind;
    g_neko_barrier_load_oop_field_preloaded =
        (g_neko_method_layout.current_barrier_kind == NEKO_GC_BARRIER_SHENANDOAH)
        ? g_neko_method_layout.sym_shenandoah_load_reference_barrier_strong
        : g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded;
    g_neko_barrier_load_oop_array = g_neko_method_layout.sym_z_load_barrier_on_oop_array;
    g_neko_barrier_store_oop_field = g_neko_method_layout.sym_z_store_barrier_on_oop_field_with_healing;
    g_neko_barrier_write_ref_array_pre =
        (g_neko_method_layout.current_barrier_kind == NEKO_GC_BARRIER_SHENANDOAH)
        ? g_neko_method_layout.sym_shenandoah_arraycopy_barrier_oop_entry
        : g_neko_method_layout.sym_g1_write_ref_array_pre_oop_entry;
    g_neko_barrier_write_ref_field_pre =
        (g_neko_method_layout.current_barrier_kind == NEKO_GC_BARRIER_SHENANDOAH)
        ? g_neko_method_layout.sym_shenandoah_write_ref_field_pre_entry
        : g_neko_method_layout.sym_g1_write_ref_field_pre_entry;
    g_neko_barrier_write_ref_field_post = g_neko_method_layout.sym_g1_write_ref_field_post_entry;
    g_neko_card_table_byte_map_base = g_neko_method_layout.card_table_byte_map_base;
    g_neko_card_table_dirty_card = g_neko_method_layout.vmconst_cardtable_dirty_card;
    g_neko_card_table_clean_card = g_neko_method_layout.vmconst_cardtable_clean_card;
    g_neko_g1_young_card = g_neko_method_layout.vmconst_g1_young_card;
    NEKO_PATCH_LOG("gc barrier: ready=%d kind=%d bs=%p card_table=%p byte_map_base=%p card_clean=%d card_dirty=%d g1_young=%d g1_pre=%p g1_post=%p z_lrb=%p z_array=%p z_store=%p z_bad_off=%td sh_lrb=%p sh_lrb_narrow=%p sh_pre=%p sh_array=%p/%p",
        (int)g_neko_gc_barrier_ready,
        g_neko_gc_barrier_kind,
        g_neko_method_layout.current_barrier_set,
        g_neko_method_layout.current_card_table,
        g_neko_card_table_byte_map_base,
        g_neko_card_table_clean_card,
        g_neko_card_table_dirty_card,
        g_neko_g1_young_card,
        g_neko_method_layout.sym_g1_write_ref_field_pre_entry,
        g_neko_method_layout.sym_g1_write_ref_field_post_entry,
        g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded,
        g_neko_method_layout.sym_z_load_barrier_on_oop_array,
        g_neko_method_layout.sym_z_store_barrier_on_oop_field_with_healing,
        g_neko_method_layout.off_z_thread_address_bad_mask,
        g_neko_method_layout.sym_shenandoah_load_reference_barrier_strong,
        g_neko_method_layout.sym_shenandoah_load_reference_barrier_strong_narrow,
        g_neko_method_layout.sym_shenandoah_write_ref_field_pre_entry,
        g_neko_method_layout.sym_shenandoah_arraycopy_barrier_oop_entry,
        g_neko_method_layout.sym_shenandoah_arraycopy_barrier_narrow_oop_entry);
    if (!g_neko_gc_barrier_ready) {
        NEKO_PATCH_LOG("gc barrier path not ready for kind=%d; aborting native layout initialization",
            g_neko_gc_barrier_kind);
        return JNI_FALSE;
    }
    /* T4.8: capture NewGlobalRef + DeleteGlobalRef function-table entries
     * once at bootstrap. The bind-time class/string slot path uses these
     * captured pointers instead of the inline JNI function-table 21 /
     * `[22]` indexing. Failure to capture aborts inside the helper. */
    neko_capture_global_ref_fns();
    /* T4.3 / T4.4 / T4.5: capture the bind-time JNI function-table entries
     * (NewStringUTF, Call*MethodA, NewObjectA, GetArrayLength,
     * NewObjectArray, Set/GetObjectArrayElement) used by the MethodType /
     * MethodHandles.lookup / Throwable.getStackTrace pipelines. Production
     * HotSpot 21 strips the corresponding C++ symbols, so capture-once
     * is the equivalent libjvm-internal entry point. The grep gate
     * (T4.12) sees only the captured-pointer call sites afterwards. */
    neko_capture_bind_time_jni_fns();
    /* T4.7: deleted neko_fast_string_runtime_init (JNI probe via
     * NewStringUTF / NewByteArray, indices 167 + 176). The fast string
     * allocator path is gated on the receiver-key + raw-heap fast bits
     * (cleared under ZGC / Shenandoah) AND on g_hotspot being initialized.
     * In production HotSpot, neko_method_layout_init runs BEFORE
     * neko_hotspot_init so g_hotspot.fast_bits is still 0 at this point;
     * the original probe would skip silently in that state and the bits
     * were derived on demand from neko_intern_string the first time the
     * obfuscated code touched a string literal. We preserve that
     * "skip early, derive on demand" behavior here — wrapping the call
     * in the same precondition the deleted probe used. The "invariants
     * not satisfied → abort" gate the T4.7 plan note specifies fires
     * inside neko_ensure_string_alloc_bits when the fast path IS supposed
     * to be live but the derivation fails (missing String Klass /
     * byte-array Klass bits). */
    if (g_hotspot.initialized
        && (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) != 0
        && !g_hotspot.use_compact_object_headers
        && g_hotspot.klass_offset_bytes > 0
        && g_neko_tlab_alloc_ready
        && g_hotspot.primitive_array_klass_bits[NEKO_PRIM_B] != 0) {
        neko_ensure_string_alloc_bits(env);
    }
    g_neko_method_layout.usable = JNI_TRUE;
    return JNI_TRUE;
}

/* === JNIHandleBlock push/pop helpers ===
 * Push raw oop into the thread's _active_handles and return its handle slot
 * pointer. Missing handle layout is fatal; there is no raw-cast fallback.
 * neko_handle_save / neko_handle_restore bracket a dispatcher invocation so
 * its pushes are popped on return.
 * The typedef neko_handle_save_t is forward-declared in the prelude. */

/* These per-call helpers are static inline so the per-signature dispatcher
 * (emitted later in this same translation unit) can fold them into its body.
 * Going from extern call → inline saves two register saves + two ret + the
 * stall on the indirect call edge per dispatch, which adds up across hot
 * loops in obfusjack microbenches. */

#define NEKO_JNIH_RECYCLE_MAX 64
#define NEKO_JNIH_BATCH_BLOCKS 64
typedef struct neko_jnih_slab_header {
    struct neko_jnih_slab_header *next;
    char *block_start;
    char *block_end;
} neko_jnih_slab_header_t;
__attribute__((visibility("hidden"))) __thread void *g_neko_recycled_jnih_blocks = NULL;
__attribute__((visibility("hidden"))) __thread int32_t g_neko_recycled_jnih_block_count = 0;
__attribute__((visibility("hidden"))) __thread neko_handle_save_t *g_neko_current_handle_scope = NULL;

static inline __attribute__((always_inline))
void *neko_take_recycled_jnih_block(void) {
    void *block;
    void *next;
    if (g_neko_method_layout.sizeof_JNIHandleBlock <= 0
        || g_neko_method_layout.off_jnih_block_next <= 0) {
        return NULL;
    }
    block = g_neko_recycled_jnih_blocks;
    if (block == NULL) return NULL;
    next = *(void**)((char*)block + g_neko_method_layout.off_jnih_block_next);
    g_neko_recycled_jnih_blocks = next;
    if (g_neko_recycled_jnih_block_count > 0) {
        g_neko_recycled_jnih_block_count--;
    }
    memset(block, 0, g_neko_method_layout.sizeof_JNIHandleBlock);
    return block;
}

static inline __attribute__((always_inline))
void neko_recycle_jnih_block(void *block) {
    if (block == NULL) return;
    if (g_neko_method_layout.sizeof_JNIHandleBlock <= 0
        || g_neko_method_layout.off_jnih_block_next <= 0
        || g_neko_recycled_jnih_block_count >= NEKO_JNIH_RECYCLE_MAX) {
        free(block);
        return;
    }
    memset(block, 0, g_neko_method_layout.sizeof_JNIHandleBlock);
    *(void**)((char*)block + g_neko_method_layout.off_jnih_block_next) =
        g_neko_recycled_jnih_blocks;
    g_neko_recycled_jnih_blocks = block;
    g_neko_recycled_jnih_block_count++;
}

static inline __attribute__((always_inline))
size_t neko_jnih_slab_header_size(void) {
    return (sizeof(neko_jnih_slab_header_t) + sizeof(void*) - 1u) & ~(sizeof(void*) - 1u);
}

static inline __attribute__((always_inline))
void neko_free_scoped_jnih_slabs(neko_handle_save_t *scope) {
    neko_jnih_slab_header_t *slab;
    if (scope == NULL) return;
    slab = (neko_jnih_slab_header_t*)scope->scope_slabs;
    while (slab != NULL) {
        neko_jnih_slab_header_t *next = slab->next;
        free(slab);
        slab = next;
    }
    scope->scope_slabs = NULL;
    scope->scope_cursor = NULL;
    scope->scope_end = NULL;
}

static inline __attribute__((always_inline))
void *neko_alloc_jnih_block(jboolean *new_allocation) {
    size_t block_size;
    neko_handle_save_t *scope;
    if (new_allocation != NULL) *new_allocation = JNI_FALSE;
    if (g_neko_method_layout.sizeof_JNIHandleBlock <= 0
        || g_neko_method_layout.off_jnih_block_next <= 0) {
        return NULL;
    }
    block_size = (size_t)g_neko_method_layout.sizeof_JNIHandleBlock;
    scope = g_neko_current_handle_scope;
    if (scope != NULL) {
        char *cursor = scope->scope_cursor;
        if (cursor == NULL || cursor + block_size > scope->scope_end) {
            size_t header_size = neko_jnih_slab_header_size();
            size_t payload_size = block_size * (size_t)NEKO_JNIH_BATCH_BLOCKS;
            neko_jnih_slab_header_t *slab = (neko_jnih_slab_header_t*)calloc(1, header_size + payload_size);
            if (slab == NULL) return NULL;
            slab->next = (neko_jnih_slab_header_t*)scope->scope_slabs;
            slab->block_start = (char*)slab + header_size;
            slab->block_end = slab->block_start + payload_size;
            scope->scope_slabs = slab;
            scope->scope_cursor = slab->block_start;
            scope->scope_end = slab->block_end;
            cursor = scope->scope_cursor;
            if (new_allocation != NULL) *new_allocation = JNI_TRUE;
        }
        scope->scope_cursor = cursor + block_size;
        return cursor;
    }

    {
        void *block = neko_take_recycled_jnih_block();
        if (block != NULL) return block;
        block = calloc(1, block_size);
        if (block != NULL && new_allocation != NULL) *new_allocation = JNI_TRUE;
        return block;
    }
}

static inline __attribute__((always_inline))
void neko_handle_save(void *thread, neko_handle_save_t *save) {
    save->thread = thread;
    save->block = NULL;
    save->saved_next = NULL;
    save->saved_last = NULL;
    save->saved_top = 0;
    save->prev_scope = g_neko_current_handle_scope;
    save->scope_slabs = NULL;
    save->scope_cursor = NULL;
    save->scope_end = NULL;
    g_neko_current_handle_scope = save;
    if (!g_neko_handle_push_ready || thread == NULL) return;
    void *block = *(void**)((char*)thread + g_neko_off_thread_active_handles);
    if (block == NULL) return;
    save->block = block;
    save->saved_top = *(int32_t*)((char*)block + g_neko_off_jnih_block_top);
    if (g_neko_method_layout.off_jnih_block_next > 0) {
        ptrdiff_t off_last = g_neko_method_layout.off_jnih_block_next + 8;
        save->saved_next = *(void**)((char*)block + g_neko_method_layout.off_jnih_block_next);
        save->saved_last = *(void**)((char*)block + off_last);
    }
}

static inline __attribute__((always_inline))
void neko_handle_restore(neko_handle_save_t *save) {
    void *thread;
    void *active;
    if (save->block == NULL) {
        neko_free_scoped_jnih_slabs(save);
        g_neko_current_handle_scope = (neko_handle_save_t*)save->prev_scope;
        return;
    }
    thread = save->thread;
    if (thread != NULL && g_neko_off_thread_active_handles > 0 && g_neko_method_layout.off_jnih_block_next > 0) {
        active = *(void**)((char*)thread + g_neko_off_thread_active_handles);
        *(void**)((char*)thread + g_neko_off_thread_active_handles) = save->block;
        while (active != NULL && active != save->block) {
            void *next = *(void**)((char*)active + g_neko_method_layout.off_jnih_block_next);
            if (save->scope_slabs == NULL) {
                neko_recycle_jnih_block(active);
            }
            active = next;
        }
    }
    if (g_neko_method_layout.off_jnih_block_next > 0) {
        void *next = *(void**)((char*)save->block + g_neko_method_layout.off_jnih_block_next);
        while (next != NULL && next != save->saved_next) {
            void *after = *(void**)((char*)next + g_neko_method_layout.off_jnih_block_next);
            if (save->scope_slabs == NULL) {
                neko_recycle_jnih_block(next);
            }
            next = after;
        }
        *(void**)((char*)save->block + g_neko_method_layout.off_jnih_block_next) = save->saved_next;
    }
    *(int32_t*)((char*)save->block + g_neko_off_jnih_block_top) = save->saved_top;
    if (g_neko_method_layout.off_jnih_block_next > 0) {
        ptrdiff_t off_last = g_neko_method_layout.off_jnih_block_next + 8;
        *(void**)((char*)save->block + off_last) = save->saved_last != NULL ? save->saved_last : save->block;
    }
    neko_free_scoped_jnih_slabs(save);
    g_neko_current_handle_scope = (neko_handle_save_t*)save->prev_scope;
}

static inline __attribute__((always_inline))
JNIEnv *neko_thread_jni_env(void *thread) {
    if (thread != NULL && g_neko_method_layout.off_thread_jni_environment > 0) {
        return (JNIEnv*)((char*)thread + g_neko_method_layout.off_thread_jni_environment);
    }
    if (thread != NULL && g_neko_jni_functions_table != NULL) {
        for (ptrdiff_t off = 0; off < 0x4000; off += (ptrdiff_t)sizeof(void*)) {
            JNIEnv *candidate = (JNIEnv*)((char*)thread + off);
            if (*(void**)candidate == g_neko_jni_functions_table) {
                g_neko_method_layout.off_thread_jni_environment = off;
                g_neko_off_thread_jni_environment_for_check = off;
                return candidate;
            }
        }
    }
    fprintf(stderr, "[neko-direct] JavaThread::_jni_environment offset unavailable thread=%p\\n", thread);
    abort();
}

static inline __attribute__((always_inline))
void *neko_jni_env_to_thread(JNIEnv *env) {
    if (env == NULL || g_neko_method_layout.off_thread_jni_environment <= 0) return NULL;
    return (void*)((char*)env - g_neko_method_layout.off_thread_jni_environment);
}

static inline __attribute__((always_inline))
void *neko_handle_push(void *thread, void *raw_oop) {
    if (raw_oop == NULL) return NULL;
    if (!g_neko_handle_push_ready || thread == NULL) {
        fprintf(stderr, "[neko-direct] JNIHandleBlock push unavailable thread=%p raw=%p\\n", thread, raw_oop);
        abort();
    }
    void *block = *(void**)((char*)thread + g_neko_off_thread_active_handles);
    if (block == NULL) {
        fprintf(stderr, "[neko-direct] JNIHandleBlock active block missing thread=%p raw=%p\\n", thread, raw_oop);
        abort();
    }
    int32_t *top_ptr = (int32_t*)((char*)block + g_neko_off_jnih_block_top);
    int32_t top = *top_ptr;
    if (top >= g_neko_jnih_block_capacity) {
        if (g_neko_method_layout.sizeof_JNIHandleBlock > 0 && g_neko_method_layout.off_jnih_block_next > 0) {
            void *new_block = neko_alloc_jnih_block(NULL);
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
                return &new_handles[0];
            }
        }
        fprintf(stderr, "[neko-direct] JNIHandleBlock chain allocation failed thread=%p raw=%p\\n", thread, raw_oop);
        abort();
    }
    void **handles = (void**)((char*)block + g_neko_off_jnih_block_handles);
    handles[top] = raw_oop;
    *top_ptr = top + 1;
    /* Publish _last = block so HotSpot's later allocate_handle does not
     * dereference a NULL _last when it sees _top != 0. VMStructs does not
     * export _last; in JDK 21 the field order after _next is
     *   _last : JNIHandleBlock*       (= _next + 8)
     *   _pop_frame_link : JNIHandleBlock*
     *   _free_list : uintptr_t*
     * so we only touch _last (writing _pop_frame_link or _free_list would
     * break PushLocalFrame / PopLocalFrame / handle reclamation). */
    if (g_neko_method_layout.off_jnih_block_next > 0) {
        ptrdiff_t off_last = g_neko_method_layout.off_jnih_block_next + 8;
        *(void**)((char*)block + off_last) = block;
    }
    return &handles[top];
}

static jboolean neko_apply_no_compile_flags(void *method_star) {
    /* JVM_ACC_NOT_C[12]_COMPILABLE bits in Method::_access_flags (well-defined
     * across JDKs). */
    {
        uint32_t mask = g_neko_method_layout.access_not_c1_compilable
            | g_neko_method_layout.access_not_c2_compilable
            | g_neko_method_layout.access_not_osr_compilable;
        size_t width = g_neko_method_layout.access_flags_size == 0 ? sizeof(uint32_t) : g_neko_method_layout.access_flags_size;
        void *addr = (uint8_t*)method_star + g_neko_method_layout.off_method_access_flags;
        if (width == 4) __atomic_fetch_or((uint32_t*)addr, mask, __ATOMIC_SEQ_CST);
        else if (width == 2) __atomic_fetch_or((uint16_t*)addr, (uint16_t)mask, __ATOMIC_SEQ_CST);
    }
    /* DontInline: rely on bytecode inflation in NativeCompilationStage to
     * lift the LinkageError-stub past MaxInlineSize, instead of poking
     * Method::_flags. JIT-compiled callers' inline-cache resolution reads
     * _flags during resolve_virtual_call, and a wrong-shaped write there
     * trips a libjvm-internal SIGSEGV (saw at libjvm+0x2f5167) on
     * ForkJoin-pool-driven hot loops. The bytecode-size route is robust
     * across JDKs and doesn't depend on getting the bit layout right. */
    return JNI_TRUE;
}

static inline __attribute__((always_inline)) void neko_cpu_relax(void) {
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ __volatile__("pause" ::: "memory");
#elif defined(__aarch64__)
    __asm__ __volatile__("yield" ::: "memory");
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

static inline __attribute__((always_inline)) void *neko_current_thread_register(void) {
#if defined(__x86_64__) || defined(_M_X64)
    void *thread;
    __asm__ __volatile__("movq %%r15, %0" : "=r"(thread));
    return thread;
#elif defined(__aarch64__)
    void *thread;
    __asm__ __volatile__("mov %0, x28" : "=r"(thread));
    return thread;
#else
    return NULL;
#endif
}

__attribute__((visibility("hidden"))) void neko_safepoint_poll_thread(void *thread) {
    if (thread == NULL || g_neko_off_thread_polling_word <= 0) return;
    volatile uintptr_t *poll = (volatile uintptr_t*)((char*)thread + g_neko_off_thread_polling_word);
    uint32_t spins = 0;
    while (*poll != 0) {
        __sync_synchronize();
        neko_cpu_relax();
        if (++spins == 0) break;
    }
}

__attribute__((visibility("hidden"))) void neko_refresh_hotspot_vmstruct_state(void) {
    if (g_neko_method_layout.addr_compressed_oops_shift != NULL) {
        int shift = *(int*)g_neko_method_layout.addr_compressed_oops_shift;
        void *base = (g_neko_method_layout.addr_compressed_oops_base != NULL)
            ? *(void**)g_neko_method_layout.addr_compressed_oops_base
            : NULL;
        g_hotspot.compressed_oops_enabled = JNI_TRUE;
        g_hotspot.compressed_oops_shift = shift;
        g_hotspot.compressed_oops_base = (jlong)(uintptr_t)base;
        NEKO_PATCH_LOG("vmstructs coop refresh: shift=%d base=%p", shift, base);
    }
    if (g_neko_method_layout.addr_compressed_oops_base != NULL) {
        g_neko_heap_base = *(void**)g_neko_method_layout.addr_compressed_oops_base;
    } else if (g_hotspot.compressed_oops_enabled) {
        g_neko_heap_base = (void*)(uintptr_t)g_hotspot.compressed_oops_base;
    } else {
        g_neko_heap_base = NULL;
    }
    NEKO_PATCH_LOG("heap base refresh: %p", g_neko_heap_base);
}

__attribute__((visibility("hidden"))) void neko_transition_native_to_java(void *thread) {
    if (thread == NULL || g_neko_off_thread_state <= 0) return;
    *(int32_t*)((char*)thread + g_neko_off_thread_state) = g_neko_thread_state_in_native_trans;
    __sync_synchronize();
    neko_safepoint_poll_thread(thread);
    *(int32_t*)((char*)thread + g_neko_off_thread_state) = g_neko_thread_state_in_java;
}

__attribute__((visibility("hidden"))) void neko_transition_java_to_native(void *thread) {
    if (thread == NULL || g_neko_off_thread_state <= 0) return;
    *(int32_t*)((char*)thread + g_neko_off_thread_state) = g_neko_thread_state_in_native_trans;
    __sync_synchronize();
    neko_safepoint_poll_thread(thread);
    *(int32_t*)((char*)thread + g_neko_off_thread_state) = g_neko_thread_state_in_native;
}

/* Called from naked-asm trampolines when the polling word indicates a safepoint
 * is requested. This must not cross the JNI function table: the JavaThread is
 * recovered from HotSpot's thread register and we wait directly on the
 * VMStructs-published polling word while the thread is in native_trans. */
__attribute__((visibility("hidden"))) void neko_handle_safepoint_poll(void) {
    neko_safepoint_poll_thread(neko_current_thread_register());
}

static jboolean neko_patch_method_entry(void *method_star, void *manifest_entry) {
    NekoManifestMethod *entry = (NekoManifestMethod*)manifest_entry;
    if (!g_neko_method_layout.usable || method_star == NULL || entry == NULL) return JNI_FALSE;
    if (entry->signature_id >= g_neko_sig_table_count) {
        NEKO_PATCH_LOG("patch refused: bad signature_id=%u for %s.%s%s",
            entry->signature_id, entry->owner_internal, entry->method_name, entry->method_desc);
        return JNI_FALSE;
    }
    void *compiled_code = __atomic_load_n((void**)((uint8_t*)method_star + g_neko_method_layout.off_method_code), __ATOMIC_ACQUIRE);
    if (compiled_code != NULL) {
        NEKO_PATCH_LOG("patch refused: %s.%s%s already JIT-compiled", entry->owner_internal, entry->method_name, entry->method_desc);
        return JNI_FALSE;
    }
    (void)neko_apply_no_compile_flags(method_star);
    void *real_i2i = g_neko_sig_table[entry->signature_id].i2i;
    void *real_c2i = g_neko_sig_table[entry->signature_id].c2i;
    if (real_i2i == NULL || real_c2i == NULL) {
        NEKO_PATCH_LOG("patch refused: missing trampoline for sig=%u %s.%s%s",
            entry->signature_id, entry->owner_internal, entry->method_name, entry->method_desc);
        return JNI_FALSE;
    }
    /* Three Method entry-point fields, three private-CodeHeap thunks:
     *   _from_compiled_entry     -> t_c2i, the Java-ABI compiled-entry stub.
     *   _from_interpreted_entry  -> t_i2i_interp, the interpreter-entry stub
     *       that consumes HotSpot's interpreter stack layout and returns by
     *       the normal interpreter protocol.
     *   _i2i_entry               -> t_i2i_path2 when HotSpot's shared c2i
     *       adapter tail-jumps to _i2i_entry after reserving extraspace;
     *       otherwise it reuses the normal interpreted-entry thunk.
     *
     * The shared c2i adapter path is still an adapter connection into our
     * native method entry, but the installed target must be one of our new
     * Java-thread-in-java stubs. Missing a required path2 variant is a patch
     * failure, not permission to keep the original JVM entry active.
     */
    if (!g_neko_priv_heap.registered) {
        NEKO_PATCH_LOG("patch refused: private CodeHeap not registered for %s.%s%s",
            entry->owner_internal, entry->method_name, entry->method_desc);
        return JNI_FALSE;
    }
    int extraspace_words = (int)g_neko_sig_extraspace_words[entry->signature_id];
    void *real_i2i_path2 = (extraspace_words > 0) ? g_neko_sig_i2i_path2[entry->signature_id] : NULL;
    if (extraspace_words > 0 && real_i2i_path2 == NULL) {
        NEKO_PATCH_LOG("patch refused: missing i2i path2 trampoline for sig=%u extraspace=%d %s.%s%s",
            entry->signature_id, extraspace_words,
            entry->owner_internal, entry->method_name, entry->method_desc);
        return JNI_FALSE;
    }
    /* Per-method thunks: the entry pointer is baked into each thunk's r10
     * preload so the per-signature naked function does not need to scan the
     * manifest. Three thunk variants per Method* (interp i2i, path-2 i2i, c2i)
     * are dedup'd against (trampoline, frame_size, entry); since each entry
     * is unique to its Method* the only meaningful dedup is for re-entrant
     * patching from defineClass alias resolution. */
    void *t_i2i_interp = neko_priv_get_thunk(real_i2i, 3, entry);
    void *t_i2i_path2  = (extraspace_words > 0)
        ? neko_priv_get_thunk(real_i2i_path2, 3 + extraspace_words, entry)
        : t_i2i_interp;
    void *t_c2i        = neko_priv_get_thunk(real_c2i, 3, entry);
    if (t_i2i_interp == NULL || t_i2i_path2 == NULL || t_c2i == NULL) {
        NEKO_PATCH_LOG("patch refused: thunk allocation failed for sig=%u %s.%s%s",
            entry->signature_id, entry->owner_internal, entry->method_name, entry->method_desc);
        return JNI_FALSE;
    }
    __atomic_store_n((void**)((uint8_t*)method_star + g_neko_method_layout.off_method_i2i_entry), t_i2i_path2, __ATOMIC_RELEASE);
    __atomic_store_n((void**)((uint8_t*)method_star + g_neko_method_layout.off_method_from_interpreted_entry), t_i2i_interp, __ATOMIC_RELEASE);
    __atomic_store_n((void**)((uint8_t*)method_star + g_neko_method_layout.off_method_from_compiled_entry), t_c2i, __ATOMIC_RELEASE);
    NEKO_PATCH_LOG("patched %s.%s%s sig=%u method=%p from_compiled=%p from_interpreted=%p i2i=%p extraspace_words=%d path2=%p",
        entry->owner_internal, entry->method_name, entry->method_desc,
        entry->signature_id, method_star, t_c2i, t_i2i_interp, t_i2i_path2,
        extraspace_words, real_i2i_path2);
    return JNI_TRUE;
}

""";
    }
}
