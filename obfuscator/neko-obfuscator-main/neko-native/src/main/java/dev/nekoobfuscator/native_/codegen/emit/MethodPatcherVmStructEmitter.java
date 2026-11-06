package dev.nekoobfuscator.native_.codegen.emit;

/**
 * Emits VMStruct walking code for discovering HotSpot field offsets and constants.
 */
final class MethodPatcherVmStructEmitter {
    private MethodPatcherVmStructEmitter() {}

    static String render() {
        return String.join("", """
static jboolean neko_walk_vm_structs(void *jvm) {
    void *vmstructs = neko_dlsym(jvm, "gHotSpotVMStructs");
    int *type_off  = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryTypeNameOffset");
    int *field_off = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryFieldNameOffset");
    int *offset_off = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryOffsetOffset");
    int *isstatic_off = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryIsStaticOffset");
    int *address_off = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryAddressOffset");
    int *stride_p   = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryArrayStride");
    if (vmstructs == NULL || type_off == NULL || field_off == NULL || offset_off == NULL || stride_p == NULL) {
        return JNI_FALSE;
    }
    const uint8_t *base = *(const uint8_t* const*)vmstructs;
    int stride = *stride_p;
    if (base == NULL || stride <= 0) return JNI_FALSE;
    int zcap_matches = 0;
    int compilertovm_zcap_matches = 0;
    for (const uint8_t *e = base; ; e += stride) {
        const char *type_name = *(const char* const*)(e + *type_off);
        const char *field_name = *(const char* const*)(e + *field_off);
        uintptr_t off_value = *(const uintptr_t*)(e + *offset_off);
        int32_t is_static = (isstatic_off != NULL) ? *(const int32_t*)(e + *isstatic_off) : 0;
        void *static_addr = (is_static && address_off != NULL) ? *(void* const*)(e + *address_off) : NULL;
        if (type_name == NULL && field_name == NULL) break;
        if (NEKO_PATCH_DEBUG && neko_streq_safe(type_name, "Method")) {
            fprintf(stderr, "[neko-patch] vmstructs Method::%s @+%zu\\n", field_name ? field_name : "?", (size_t)off_value);
        }
        if (NEKO_PATCH_DEBUG && field_name != NULL
            && (neko_streq_safe(field_name, "_jni_environment")
             || neko_streq_safe(field_name, "_pending_exception"))) {
            fprintf(stderr, "[neko-patch] vmstructs %s::%s @+%zu\\n",
                type_name ? type_name : "?", field_name, (size_t)off_value);
        }
        if (NEKO_PATCH_DEBUG && (neko_strstr_safe(type_name, "ZGlobals")
             || neko_strstr_safe(type_name, "CompilerToVM")
             || neko_strstr_safe(field_name, "ZAddress")
             || neko_strstr_safe(field_name, "ZPointer")
             || neko_strstr_safe(field_name, "ZBarrierSetRuntime")
             || neko_strstr_safe(field_name, "thread_address"))) {
            zcap_matches++;
            fprintf(stderr, "[neko-patch] vmstructs zcap %s::%s @+%zu static=%d addr=%p\\n",
                type_name ? type_name : "?",
                field_name ? field_name : "?",
                (size_t)off_value, (int)is_static, static_addr);
        }
        if (neko_streq_safe(field_name, "_instance_p")) {
            if (is_static && static_addr != NULL) {
                g_neko_method_layout.addr_zglobals_instance_p = static_addr;
            }
        } else if (neko_streq_safe(field_name, "_ZAddressOffsetMask")) {
            if (is_static && static_addr != NULL) g_neko_method_layout.addr_zglobals_address_offset_mask = static_addr;
            g_neko_method_layout.off_zglobals_address_offset_mask = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(field_name, "_ZPointerLoadGoodMask")) {
            if (is_static && static_addr != NULL) g_neko_method_layout.addr_zglobals_pointer_load_good_mask = static_addr;
            g_neko_method_layout.off_zglobals_pointer_load_good_mask = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(field_name, "_ZPointerLoadBadMask")) {
            if (is_static && static_addr != NULL) g_neko_method_layout.addr_zglobals_pointer_load_bad_mask = static_addr;
            g_neko_method_layout.off_zglobals_pointer_load_bad_mask = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(field_name, "_ZPointerStoreGoodMask")) {
            if (is_static && static_addr != NULL) g_neko_method_layout.addr_zglobals_pointer_store_good_mask = static_addr;
            g_neko_method_layout.off_zglobals_pointer_store_good_mask = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(field_name, "_ZPointerStoreBadMask")) {
            if (is_static && static_addr != NULL) g_neko_method_layout.addr_zglobals_pointer_store_bad_mask = static_addr;
            g_neko_method_layout.off_zglobals_pointer_store_bad_mask = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(field_name, "_ZPointerLoadShift")) {
            if (is_static && static_addr != NULL) g_neko_method_layout.addr_zglobals_pointer_load_shift = static_addr;
            g_neko_method_layout.off_zglobals_pointer_load_shift = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "CompilerToVM::Data") && is_static && static_addr != NULL) {
            void *entry = *(void**)static_addr;
            if (NEKO_PATCH_DEBUG && (neko_strstr_safe(field_name, "ZBarrierSetRuntime")
                 || neko_strstr_safe(field_name, "thread_address"))) {
                compilertovm_zcap_matches++;
                fprintf(stderr, "[neko-patch] compilertovm data %s entry=%p slot=%p\\n",
                    field_name ? field_name : "?", entry, static_addr);
            }
            if (entry != NULL && neko_streq_safe(field_name, "ZBarrierSetRuntime_load_barrier_on_oop_field_preloaded")) {
                g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded = entry;
            } else if (entry != NULL && neko_streq_safe(field_name, "ZBarrierSetRuntime_load_barrier_on_oop_array")) {
                g_neko_method_layout.sym_z_load_barrier_on_oop_array = entry;
            }
        }
        /* Field-name fallback for inherited Thread fields. VMStructs splits
         * across the Thread / ThreadShadow / JavaThread chain, and some are
         * only in the JVMCI sub-table. Match by field name when the
         * type-aware branch missed it; the field names are unique. */
        if (g_neko_method_layout.off_thread_jni_environment <= 0
            && neko_streq_safe(field_name, "_jni_environment")) {
            g_neko_method_layout.off_thread_jni_environment = (ptrdiff_t)off_value;
        }
        if (g_neko_method_layout.off_thread_pending_exception <= 0
            && neko_streq_safe(field_name, "_pending_exception")) {
            g_neko_method_layout.off_thread_pending_exception = (ptrdiff_t)off_value;
        }
        if (neko_streq_safe(type_name, "Method")) {
            if (neko_streq_safe(field_name, "_access_flags")) g_neko_method_layout.off_method_access_flags = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_code")) g_neko_method_layout.off_method_code = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_i2i_entry")) g_neko_method_layout.off_method_i2i_entry = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_from_interpreted_entry")) g_neko_method_layout.off_method_from_interpreted_entry = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_from_compiled_entry")) g_neko_method_layout.off_method_from_compiled_entry = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_flags") || neko_streq_safe(field_name, "_flags._status") || neko_streq_safe(field_name, "_flags._flags")) {
                g_neko_method_layout.off_method_flags_status = (ptrdiff_t)off_value;
            }
            else if (neko_streq_safe(field_name, "_intrinsic_id")) g_neko_method_layout.off_method_intrinsic_id = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_vtable_index")) g_neko_method_layout.off_method_vtable_index = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_constMethod")) g_neko_method_layout.off_method_constMethod = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "ConstMethod")) {
            if (neko_streq_safe(field_name, "_constants")) g_neko_method_layout.off_constmethod_constants = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_name_index")) g_neko_method_layout.off_constmethod_name_index = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_signature_index")) g_neko_method_layout.off_constmethod_signature_index = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "InstanceKlass")) {
""", """
            if (neko_streq_safe(field_name, "_methods")) g_neko_method_layout.off_instanceklass_methods = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_fieldinfo_stream")) g_neko_method_layout.off_instanceklass_fieldinfo_stream = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_fields")) g_neko_method_layout.off_instanceklass_fields = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_constants")) g_neko_method_layout.off_instanceklass_constants = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_local_interfaces")) g_neko_method_layout.off_instanceklass_local_interfaces = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_transitive_interfaces")) g_neko_method_layout.off_instanceklass_transitive_interfaces = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_java_fields_count")) g_neko_method_layout.off_instanceklass_java_fields_count = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "Klass")) {
            if (neko_streq_safe(field_name, "_super_check_offset")) g_neko_method_layout.off_klass_super_check_offset = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_secondary_super_cache")) g_neko_method_layout.off_klass_secondary_super_cache = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_secondary_supers")) g_neko_method_layout.off_klass_secondary_supers = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_primary_supers[0]")) g_neko_method_layout.off_klass_primary_supers_0 = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_layout_helper")) g_neko_method_layout.off_klass_layout_helper = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_java_mirror")) g_neko_method_layout.off_klass_java_mirror = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_super")) g_neko_method_layout.off_klass_super = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_subklass")) g_neko_method_layout.off_klass_subklass = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_next_link")) g_neko_method_layout.off_klass_next_link = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_name")) g_neko_method_layout.off_klass_name = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "ObjArrayKlass")) {
            if (neko_streq_safe(field_name, "_element_klass")) g_neko_method_layout.off_objarrayklass_element_klass = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "java_lang_Class")) {
            if (neko_streq_safe(field_name, "_klass_offset") && is_static && static_addr != NULL) {
                g_neko_method_layout.off_java_lang_class_klass = (ptrdiff_t)(*(int*)static_addr);
            } else if (neko_streq_safe(field_name, "_klass")) {
                g_neko_method_layout.off_java_lang_class_klass = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "ClassLoaderDataGraph")) {
            if (neko_streq_safe(field_name, "_head") && is_static && static_addr != NULL) {
                g_neko_method_layout.addr_classloaderdatagraph_head = static_addr;
            }
        } else if (neko_streq_safe(type_name, "ClassLoaderData")) {
            if (neko_streq_safe(field_name, "_next")) g_neko_method_layout.off_classloaderdata_next = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_klasses")) g_neko_method_layout.off_classloaderdata_klasses = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "ConstantPool")) {
            if (neko_streq_safe(field_name, "_tags")) g_neko_method_layout.off_constantpool_tags = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_cache")) g_neko_method_layout.off_constantpool_cache = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_pool_holder")) g_neko_method_layout.off_constantpool_pool_holder = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_operands")) g_neko_method_layout.off_constantpool_operands = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_resolved_klasses")) g_neko_method_layout.off_constantpool_resolved_klasses = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_length")) g_neko_method_layout.off_constantpool_length = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_base") || neko_streq_safe(field_name, "_base[0]")) g_neko_method_layout.off_constantpool_base = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "Symbol")) {
""", """
            if (neko_streq_safe(field_name, "_length")) g_neko_method_layout.off_symbol_length = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_body") || neko_streq_safe(field_name, "_body[0]")) g_neko_method_layout.off_symbol_body = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "Array<Method*>")
                || neko_streq_safe(type_name, "Array<Klass*>")
                || neko_streq_safe(type_name, "Array<u1>")
                || neko_streq_safe(type_name, "Array<u2>")
                || neko_streq_safe(type_name, "Array<int>")) {
            if (neko_streq_safe(field_name, "_length")) {
                g_neko_method_layout.off_array_length = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_data")
                    || neko_streq_safe(field_name, "_data[0]")) {
                if (neko_streq_safe(type_name, "Array<u1>")) {
                    g_neko_method_layout.off_array_u1_data = (ptrdiff_t)off_value;
                } else if (neko_streq_safe(type_name, "Array<u2>")) {
                    g_neko_method_layout.off_array_u2_data = (ptrdiff_t)off_value;
                } else {
                    g_neko_method_layout.off_array_data = (ptrdiff_t)off_value;
                }
            }
        } else if (neko_streq_safe(type_name, "BarrierSet")) {
            if (neko_streq_safe(field_name, "_barrier_set") && is_static) {
                g_neko_method_layout.addr_barrierset_barrier_set = static_addr;
            } else if (neko_streq_safe(field_name, "_fake_rtti")) {
                g_neko_method_layout.off_barrierset_fake_rtti = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "BarrierSet::FakeRtti")) {
            if (neko_streq_safe(field_name, "_concrete_tag")) {
                g_neko_method_layout.off_barrierset_fakertti_concrete_tag = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "CardTableBarrierSet")) {
            if (neko_streq_safe(field_name, "_card_table")) {
                g_neko_method_layout.off_cardtablebarrierset_card_table = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "CardTable")) {
            if (neko_streq_safe(field_name, "_byte_map_base")) {
                g_neko_method_layout.off_cardtable_byte_map_base = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "Universe")) {
            if (is_static && neko_streq_safe(field_name, "_collectedHeap")) {
                g_neko_method_layout.addr_universe_collected_heap = static_addr;
            }
        } else if (neko_streq_safe(type_name, "Thread")
                || neko_streq_safe(type_name, "JavaThread")
                || neko_streq_safe(type_name, "ThreadShadow")) {
            if (neko_streq_safe(field_name, "_thread_state")) {
                if (g_neko_method_layout.off_thread_state == 0
                    || neko_streq_safe(type_name, "JavaThread")) {
                    g_neko_method_layout.off_thread_state = (ptrdiff_t)off_value;
                }
            } else if (neko_streq_safe(field_name, "_polling_word")
                    || neko_streq_safe(field_name, "_polling_page")) {
                g_neko_method_layout.off_thread_polling_word = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_anchor")) {
                g_neko_method_layout.off_thread_anchor = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_active_handles")) {
                g_neko_method_layout.off_thread_active_handles = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_tlab")) {
                g_neko_method_layout.off_thread_tlab = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_anchor._last_Java_sp")
                    || neko_streq_safe(field_name, "_last_Java_sp")) {
                g_neko_method_layout.off_thread_last_Java_sp_direct = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_anchor._last_Java_fp")
                    || neko_streq_safe(field_name, "_last_Java_fp")) {
                g_neko_method_layout.off_thread_last_Java_fp_direct = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_anchor._last_Java_pc")
                    || neko_streq_safe(field_name, "_last_Java_pc")) {
                g_neko_method_layout.off_thread_last_Java_pc_direct = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_jni_environment")) {
                g_neko_method_layout.off_thread_jni_environment = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_pending_exception")) {
                g_neko_method_layout.off_thread_pending_exception = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "JNIHandleBlock")) {
            if (neko_streq_safe(field_name, "_top")) {
                g_neko_method_layout.off_jnih_block_top = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_handles")) {
                g_neko_method_layout.off_jnih_block_handles = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_next")) {
                g_neko_method_layout.off_jnih_block_next = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "ThreadLocalAllocBuffer")) {
            if (neko_streq_safe(field_name, "_top")) {
                g_neko_method_layout.off_tlab_top = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_end")) {
                g_neko_method_layout.off_tlab_end = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "JavaFrameAnchor")) {
            if (neko_streq_safe(field_name, "_last_Java_sp")) {
                g_neko_method_layout.off_frame_anchor_sp = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_last_Java_fp")) {
                g_neko_method_layout.off_frame_anchor_fp = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_last_Java_pc")) {
                g_neko_method_layout.off_frame_anchor_pc = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "JavaCallWrapper")) {
            if (neko_streq_safe(field_name, "_anchor")) {
                g_neko_method_layout.off_jcw_anchor = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "BasicObjectLock")) {
            if (neko_streq_safe(field_name, "_lock")) {
                g_neko_method_layout.off_basicobjectlock_lock = (ptrdiff_t)off_value;
            } else if (neko_streq_safe(field_name, "_obj")) {
                g_neko_method_layout.off_basicobjectlock_obj = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "BasicLock")) {
            if (neko_streq_safe(field_name, "_displaced_header")) {
                g_neko_method_layout.off_basiclock_displaced_header = (ptrdiff_t)off_value;
            }
        } else if (neko_streq_safe(type_name, "StubRoutines")) {
            if (is_static && neko_streq_safe(field_name, "_call_stub_return_address")) {
                g_neko_method_layout.addr_call_stub_return_address = static_addr;
            }
        } else if (neko_streq_safe(type_name, "CodeCache")) {
            if (neko_streq_safe(field_name, "_heaps") && is_static) {
                g_neko_method_layout.addr_codecache_heaps = static_addr;
            }
        } else if (neko_streq_safe(type_name, "CompressedOops")) {
            if (is_static && neko_streq_safe(field_name, "_narrow_oop._base")) {
                g_neko_method_layout.addr_compressed_oops_base = static_addr;
            } else if (is_static && neko_streq_safe(field_name, "_narrow_oop._shift")) {
                g_neko_method_layout.addr_compressed_oops_shift = static_addr;
            }
        } else if (neko_streq_safe(type_name, "CompressedKlassPointers")) {
            if (is_static && neko_streq_safe(field_name, "_narrow_klass._base")) {
                g_neko_method_layout.addr_compressed_klass_base = static_addr;
            } else if (is_static && neko_streq_safe(field_name, "_narrow_klass._shift")) {
                g_neko_method_layout.addr_compressed_klass_shift = static_addr;
            }
        } else if (neko_streq_safe(type_name, "CodeHeap")) {
            if (neko_streq_safe(field_name, "_memory")) g_neko_method_layout.off_codeheap_memory = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_segmap")) g_neko_method_layout.off_codeheap_segmap = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_log2_segment_size")) g_neko_method_layout.off_codeheap_log2_segment_size = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "VirtualSpace")) {
            if (neko_streq_safe(field_name, "_low_boundary")) g_neko_method_layout.off_virtualspace_low_boundary = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_high_boundary")) g_neko_method_layout.off_virtualspace_high_boundary = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_low")) g_neko_method_layout.off_virtualspace_low = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_high")) g_neko_method_layout.off_virtualspace_high = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "GrowableArrayBase")) {
            if (neko_streq_safe(field_name, "_len")) g_neko_method_layout.off_growable_array_len = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_capacity")) g_neko_method_layout.off_growable_array_capacity = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "GrowableArray<int>")) {
            if (neko_streq_safe(field_name, "_data")) g_neko_method_layout.off_growable_array_data = (ptrdiff_t)off_value;
        } else if (neko_streq_safe(type_name, "CodeBlob")) {
            if (neko_streq_safe(field_name, "_name")) g_neko_method_layout.off_codeblob_name = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_size")) g_neko_method_layout.off_codeblob_size = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_header_size")) g_neko_method_layout.off_codeblob_header_size = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_frame_complete_offset")) g_neko_method_layout.off_codeblob_frame_complete_offset = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_data_offset")) g_neko_method_layout.off_codeblob_data_offset = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_frame_size")) g_neko_method_layout.off_codeblob_frame_size = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_code_begin")) g_neko_method_layout.off_codeblob_code_begin = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_code_end")) g_neko_method_layout.off_codeblob_code_end = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_content_begin")) g_neko_method_layout.off_codeblob_content_begin = (ptrdiff_t)off_value;
            else if (neko_streq_safe(field_name, "_data_end")) g_neko_method_layout.off_codeblob_data_end = (ptrdiff_t)off_value;
        }
    }
    NEKO_PATCH_LOG("vmstructs zcap matches=%d compilertovm_zcap_matches=%d",
        zcap_matches, compilertovm_zcap_matches);
    return JNI_TRUE;
}

""", """

static jboolean neko_walk_vm_types(void *jvm) {
    void *vmtypes = neko_dlsym(jvm, "gHotSpotVMTypes");
    int *name_off = (int*)neko_dlsym(jvm, "gHotSpotVMTypeEntryTypeNameOffset");
    int *size_off = (int*)neko_dlsym(jvm, "gHotSpotVMTypeEntrySizeOffset");
    int *stride_p = (int*)neko_dlsym(jvm, "gHotSpotVMTypeEntryArrayStride");
    if (vmtypes == NULL || name_off == NULL || size_off == NULL || stride_p == NULL) return JNI_FALSE;
    const uint8_t *base = *(const uint8_t* const*)vmtypes;
    int stride = *stride_p;
    if (base == NULL || stride <= 0) return JNI_FALSE;
    for (const uint8_t *e = base; ; e += stride) {
        const char *type_name = *(const char* const*)(e + *name_off);
        if (type_name == NULL) break;
        uint64_t sz = *(const uint64_t*)(e + *size_off);
        if (neko_streq_safe(type_name, "Method")) g_neko_method_layout.method_size = (size_t)sz;
        else if (neko_streq_safe(type_name, "AccessFlags")) g_neko_method_layout.access_flags_size = (size_t)sz;
        else if (neko_streq_safe(type_name, "CodeHeap")) g_neko_method_layout.sizeof_CodeHeap = (size_t)sz;
        else if (neko_streq_safe(type_name, "BufferBlob")) g_neko_method_layout.sizeof_BufferBlob = (size_t)sz;
        else if (neko_streq_safe(type_name, "VirtualSpace")) g_neko_method_layout.sizeof_VirtualSpace = (size_t)sz;
        else if (neko_streq_safe(type_name, "JNIHandleBlock")) g_neko_method_layout.sizeof_JNIHandleBlock = (size_t)sz;
        else if (neko_streq_safe(type_name, "JavaCallWrapper")) g_neko_method_layout.sizeof_JavaCallWrapper = (size_t)sz;
        else if (neko_streq_safe(type_name, "ConstantPool")) g_neko_method_layout.sizeof_ConstantPool = (size_t)sz;
        else if (neko_streq_safe(type_name, "BasicObjectLock")) g_neko_method_layout.sizeof_BasicObjectLock = (size_t)sz;
        else if (neko_streq_safe(type_name, "BasicLock")) g_neko_method_layout.sizeof_BasicLock = (size_t)sz;
    }
    return JNI_TRUE;
}

static void neko_walk_vm_int_constants(void *jvm) {
    void *constants = neko_dlsym(jvm, "gHotSpotVMIntConstants");
    int *name_off = (int*)neko_dlsym(jvm, "gHotSpotVMIntConstantEntryNameOffset");
    int *val_off = (int*)neko_dlsym(jvm, "gHotSpotVMIntConstantEntryValueOffset");
    int *stride_p = (int*)neko_dlsym(jvm, "gHotSpotVMIntConstantEntryArrayStride");
    if (constants == NULL || name_off == NULL || val_off == NULL || stride_p == NULL) return;
    const uint8_t *base = *(const uint8_t* const*)constants;
    int stride = *stride_p;
    if (base == NULL || stride <= 0) return;
    int zcap_matches = 0;
    for (const uint8_t *e = base; ; e += stride) {
        const char *name = *(const char* const*)(e + *name_off);
        if (name == NULL) break;
        int32_t value = *(const int32_t*)(e + *val_off);
        if (neko_strstr_safe(name, "thread_address")
            || neko_strstr_safe(name, "ZThreadLocalData")
            || neko_strstr_safe(name, "ZBarrierSetRuntime")
            || neko_strstr_safe(name, "ZAddress")
            || neko_strstr_safe(name, "ZPointer")) {
            zcap_matches++;
            NEKO_PATCH_LOG("vmint zcap %s = 0x%x", name, (unsigned)value);
        }
        if (NEKO_PATCH_DEBUG && (neko_strstr_safe(name, "compilable") || neko_strstr_safe(name, "_thread_in"))) {
            fprintf(stderr, "[neko-patch] vmconst %s = 0x%x\\n", name, (unsigned)value);
        }
        if (neko_streq_safe(name, "JVM_ACC_NOT_C1_COMPILABLE")) g_neko_method_layout.access_not_c1_compilable = (uint32_t)value;
        else if (neko_streq_safe(name, "JVM_ACC_NOT_C2_COMPILABLE")) g_neko_method_layout.access_not_c2_compilable = (uint32_t)value;
        else if (neko_streq_safe(name, "JVM_ACC_NOT_OSR_COMPILABLE")) g_neko_method_layout.access_not_osr_compilable = (uint32_t)value;
        else if (neko_strstr_safe(name, "not_c1_compilable")) g_neko_method_layout.method_flag_not_c1_compilable = (uint32_t)value;
        else if (neko_strstr_safe(name, "not_c2_compilable")) g_neko_method_layout.method_flag_not_c2_compilable = (uint32_t)value;
        else if (neko_strstr_safe(name, "not_c1_osr_compilable")) g_neko_method_layout.method_flag_not_osr_compilable = (uint32_t)value;
        /* JavaThreadState enum values — names are stable across JDKs. */
        else if (neko_streq_safe(name, "_thread_in_Java")) g_neko_method_layout.thread_state_in_java = (int32_t)value;
        else if (neko_streq_safe(name, "_thread_in_native")) g_neko_method_layout.thread_state_in_native = (int32_t)value;
        else if (neko_streq_safe(name, "_thread_in_native_trans")) g_neko_method_layout.thread_state_in_native_trans = (int32_t)value;
        /* BasicType enum values — used as the result_type argument to
         * StubRoutines::call_stub. HotSpot publishes them as VMIntConstants
         * named exactly the enum tag. */
        else if (neko_streq_safe(name, "T_VOID"))    g_neko_method_layout.basictype_void    = (int32_t)value;
        else if (neko_streq_safe(name, "T_BOOLEAN")) g_neko_method_layout.basictype_boolean = (int32_t)value;
        else if (neko_streq_safe(name, "T_BYTE"))    g_neko_method_layout.basictype_byte    = (int32_t)value;
        else if (neko_streq_safe(name, "T_CHAR"))    g_neko_method_layout.basictype_char    = (int32_t)value;
        else if (neko_streq_safe(name, "T_SHORT"))   g_neko_method_layout.basictype_short   = (int32_t)value;
        else if (neko_streq_safe(name, "T_INT"))     g_neko_method_layout.basictype_int     = (int32_t)value;
        else if (neko_streq_safe(name, "T_LONG"))    g_neko_method_layout.basictype_long    = (int32_t)value;
        else if (neko_streq_safe(name, "T_FLOAT"))   g_neko_method_layout.basictype_float   = (int32_t)value;
        else if (neko_streq_safe(name, "T_DOUBLE"))  g_neko_method_layout.basictype_double  = (int32_t)value;
        else if (neko_streq_safe(name, "T_OBJECT"))  g_neko_method_layout.basictype_object  = (int32_t)value;
        else if (neko_streq_safe(name, "T_ARRAY"))   g_neko_method_layout.basictype_array   = (int32_t)value;
        else if (neko_streq_safe(name, "BarrierSet::ModRef")) g_neko_method_layout.vmconst_barrierset_modref = (int32_t)value;
        else if (neko_streq_safe(name, "BarrierSet::CardTableBarrierSet")) g_neko_method_layout.vmconst_barrierset_cardtable = (int32_t)value;
        else if (neko_streq_safe(name, "BarrierSet::G1BarrierSet")) g_neko_method_layout.vmconst_barrierset_g1 = (int32_t)value;
        else if (neko_streq_safe(name, "BarrierSet::ZBarrierSet")) g_neko_method_layout.vmconst_barrierset_z = (int32_t)value;
        else if (neko_streq_safe(name, "BarrierSet::ShenandoahBarrierSet")) g_neko_method_layout.vmconst_barrierset_shenandoah = (int32_t)value;
        else if (neko_streq_safe(name, "CardTable::clean_card")) g_neko_method_layout.vmconst_cardtable_clean_card = (int32_t)value;
        else if (neko_streq_safe(name, "CardTable::dirty_card")) g_neko_method_layout.vmconst_cardtable_dirty_card = (int32_t)value;
        else if (neko_streq_safe(name, "G1CardTable::g1_young_gen")) g_neko_method_layout.vmconst_g1_young_card = (int32_t)value;
    }
    /* The default value for T_VOID in HotSpot's BasicType enum is 14 on JDK
     * 21+ but we won't trust any constant if T_INT didn't show up — that
     * would mean the VMIntConstants table didn't include the BasicType
     * group at all. Mark the resolution as ready only when we got T_INT. */
    g_neko_method_layout.basictypes_resolved = (g_neko_method_layout.basictype_int != 0) ? JNI_TRUE : JNI_FALSE;
    NEKO_PATCH_LOG("vmint zcap matches=%d", zcap_matches);
}

static void neko_walk_vm_long_constants(void *jvm) {
    void *constants = neko_dlsym(jvm, "gHotSpotVMLongConstants");
    int *name_off = (int*)neko_dlsym(jvm, "gHotSpotVMLongConstantEntryNameOffset");
    int *val_off = (int*)neko_dlsym(jvm, "gHotSpotVMLongConstantEntryValueOffset");
    int *stride_p = (int*)neko_dlsym(jvm, "gHotSpotVMLongConstantEntryArrayStride");
    int matches = 0;
    if (constants == NULL || name_off == NULL || val_off == NULL || stride_p == NULL) {
        NEKO_PATCH_LOG("vmlong constants unavailable: table=%p name_off=%p val_off=%p stride=%p",
            constants, (void*)name_off, (void*)val_off, (void*)stride_p);
        return;
    }
    const uint8_t *base = *(const uint8_t* const*)constants;
    int stride = *stride_p;
    if (base == NULL || stride <= 0) {
        NEKO_PATCH_LOG("vmlong constants invalid: base=%p stride=%d", base, stride);
        return;
    }
    for (const uint8_t *e = base; ; e += stride) {
        const char *name = *(const char* const*)(e + *name_off);
        if (name == NULL) break;
        int64_t value = *(const int64_t*)(e + *val_off);
        if (neko_strstr_safe(name, "thread_address")
            || neko_strstr_safe(name, "ZThreadLocalData")
            || neko_strstr_safe(name, "ZBarrierSetRuntime")
            || neko_strstr_safe(name, "ZAddress")
            || neko_strstr_safe(name, "ZPointer")) {
            matches++;
            NEKO_PATCH_LOG("vmlong zcap %s = 0x%llx",
                name, (unsigned long long)value);
        }
    }
    NEKO_PATCH_LOG("vmlong zcap matches=%d", matches);
}

static void neko_walk_jvmci_vm_structs(void *jvm) {
    void *vmstructs = neko_dlsym(jvm, "jvmciHotSpotVMStructs");
    int *type_off  = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryTypeNameOffset");
    int *field_off = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryFieldNameOffset");
    int *offset_off = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryOffsetOffset");
    int *isstatic_off = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryIsStaticOffset");
    int *address_off = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryAddressOffset");
    int *stride_p   = (int*)neko_dlsym(jvm, "gHotSpotVMStructEntryArrayStride");
    int matches = 0;
    int bound = 0;
    if (vmstructs == NULL || type_off == NULL || field_off == NULL
        || offset_off == NULL || isstatic_off == NULL
        || address_off == NULL || stride_p == NULL) {
        NEKO_PATCH_LOG("jvmci vmstructs unavailable: table=%p type=%p field=%p offset=%p static=%p addr=%p stride=%p",
            vmstructs, (void*)type_off, (void*)field_off, (void*)offset_off,
            (void*)isstatic_off, (void*)address_off, (void*)stride_p);
        return;
    }
    const uint8_t *base = *(const uint8_t* const*)vmstructs;
    int stride = *stride_p;
    if (base == NULL || stride <= 0) {
        NEKO_PATCH_LOG("jvmci vmstructs invalid: base=%p stride=%d", base, stride);
        return;
    }
    for (const uint8_t *e = base; ; e += stride) {
        const char *type_name = *(const char* const*)(e + *type_off);
        const char *field_name = *(const char* const*)(e + *field_off);
        uintptr_t off_value = *(const uintptr_t*)(e + *offset_off);
        int32_t is_static = *(const int32_t*)(e + *isstatic_off);
        void *static_addr = is_static ? *(void* const*)(e + *address_off) : NULL;
        if (type_name == NULL && field_name == NULL) break;
        if (!neko_streq_safe(type_name, "CompilerToVM::Data")) continue;
        if (!(neko_strstr_safe(field_name, "ZBarrierSetRuntime")
              || neko_streq_safe(field_name, "thread_address_bad_mask_offset"))) {
            continue;
        }
        matches++;
        NEKO_PATCH_LOG("jvmci vmstructs zcap %s::%s @+%zu static=%d addr=%p",
            type_name, field_name ? field_name : "?", (size_t)off_value,
            (int)is_static, static_addr);
        if (!is_static || static_addr == NULL) continue;
        if (neko_streq_safe(field_name, "thread_address_bad_mask_offset")) {
            int32_t value = *(int32_t*)static_addr;
            if (value >= 0) {
                g_neko_method_layout.off_z_thread_address_bad_mask = (ptrdiff_t)value;
                bound++;
                NEKO_PATCH_LOG("jvmci zcap bound thread_address_bad_mask_offset=%d", value);
            }
        } else if (neko_streq_safe(field_name, "ZBarrierSetRuntime_load_barrier_on_oop_field_preloaded")) {
            void *entry = *(void**)static_addr;
            if (entry != NULL) {
                g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded = entry;
                bound++;
            }
            NEKO_PATCH_LOG("jvmci zcap field_lrb entry=%p slot=%p", entry, static_addr);
        } else if (neko_streq_safe(field_name, "ZBarrierSetRuntime_load_barrier_on_oop_array")) {
            void *entry = *(void**)static_addr;
            NEKO_PATCH_LOG("jvmci zcap array_lrb entry=%p slot=%p not-bound=current ABI expects void*(void*)",
                entry, static_addr);
        }
    }
    NEKO_PATCH_LOG("jvmci vmstructs zcap matches=%d bound=%d", matches, bound);
}

static void neko_walk_jvmci_vm_constants(void *jvm) {
    void *int_constants = neko_dlsym(jvm, "jvmciHotSpotVMIntConstants");
    void *long_constants = neko_dlsym(jvm, "jvmciHotSpotVMLongConstants");
    int *int_name_off = (int*)neko_dlsym(jvm, "gHotSpotVMIntConstantEntryNameOffset");
    int *int_val_off = (int*)neko_dlsym(jvm, "gHotSpotVMIntConstantEntryValueOffset");
    int *int_stride_p = (int*)neko_dlsym(jvm, "gHotSpotVMIntConstantEntryArrayStride");
    int *long_name_off = (int*)neko_dlsym(jvm, "gHotSpotVMLongConstantEntryNameOffset");
    int *long_val_off = (int*)neko_dlsym(jvm, "gHotSpotVMLongConstantEntryValueOffset");
    int *long_stride_p = (int*)neko_dlsym(jvm, "gHotSpotVMLongConstantEntryArrayStride");
    int int_matches = 0;
    int long_matches = 0;
    if (int_constants != NULL && int_name_off != NULL && int_val_off != NULL && int_stride_p != NULL) {
        const uint8_t *base = *(const uint8_t* const*)int_constants;
        int stride = *int_stride_p;
        if (base != NULL && stride > 0) {
            for (const uint8_t *e = base; ; e += stride) {
                const char *name = *(const char* const*)(e + *int_name_off);
                if (name == NULL) break;
                int32_t value = *(const int32_t*)(e + *int_val_off);
                if (neko_strstr_safe(name, "thread_address")
                    || neko_strstr_safe(name, "ZBarrierSetRuntime")
                    || neko_strstr_safe(name, "ZAddress")
                    || neko_strstr_safe(name, "ZPointer")) {
                    int_matches++;
                    NEKO_PATCH_LOG("jvmci vmint zcap %s = 0x%x", name, (unsigned)value);
                }
            }
        }
    } else {
        NEKO_PATCH_LOG("jvmci vmint constants unavailable: table=%p", int_constants);
    }
    if (long_constants != NULL && long_name_off != NULL && long_val_off != NULL && long_stride_p != NULL) {
        const uint8_t *base = *(const uint8_t* const*)long_constants;
        int stride = *long_stride_p;
        if (base != NULL && stride > 0) {
            for (const uint8_t *e = base; ; e += stride) {
                const char *name = *(const char* const*)(e + *long_name_off);
                if (name == NULL) break;
                int64_t value = *(const int64_t*)(e + *long_val_off);
                if (neko_strstr_safe(name, "thread_address")
                    || neko_strstr_safe(name, "ZBarrierSetRuntime")
                    || neko_strstr_safe(name, "ZAddress")
                    || neko_strstr_safe(name, "ZPointer")) {
                    long_matches++;
                    NEKO_PATCH_LOG("jvmci vmlong zcap %s = 0x%llx",
                        name, (unsigned long long)value);
                }
            }
        }
    } else {
        NEKO_PATCH_LOG("jvmci vmlong constants unavailable: table=%p", long_constants);
    }
    NEKO_PATCH_LOG("jvmci constants zcap int_matches=%d long_matches=%d",
        int_matches, long_matches);
}

""", """

#if defined(__linux__)
typedef struct {
    uintptr_t start;
    uintptr_t end;
    int scan;
    int slot;
    int exec;
} neko_libjvm_range_t;

static void neko_add_libjvm_range(neko_libjvm_range_t *ranges, int cap, int *count,
                                  uintptr_t start, uintptr_t end, int scan, int slot, int exec) {
    if (ranges == NULL || count == NULL || cap <= 0 || start == 0 || end <= start) return;
    for (int i = 0; i < *count; i++) {
        if (ranges[i].start == start && ranges[i].end == end) {
            ranges[i].scan |= scan;
            ranges[i].slot |= slot;
            ranges[i].exec |= exec;
            return;
        }
    }
    if (*count >= cap) return;
    ranges[*count].start = start;
    ranges[*count].end = end;
    ranges[*count].scan = scan;
    ranges[*count].slot = slot;
    ranges[*count].exec = exec;
    (*count)++;
}

static int neko_read_libjvm_data_ranges(neko_libjvm_range_t *ranges, int cap) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[1024];
    uintptr_t previous_libjvm_data_end = 0;
    uintptr_t pending_anon_start = 0;
    uintptr_t pending_anon_end = 0;
    int count = 0;
    if (fp == NULL || ranges == NULL || cap <= 0) return 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[8] = {0};
        char path[768] = {0};
        int parsed = sscanf(line, "%llx-%llx %7s %*s %*s %*s %767s",
            &start, &end, perms, path);
        int readable = (parsed >= 3 && perms[0] == 'r');
        int executable = (readable && strchr(perms, 'x') != NULL);
        int readable_data = (readable && !executable);
        int libjvm_path = (parsed >= 4 && strstr(path, "libjvm.so") != NULL);
        int anonymous_path = (parsed < 4 || path[0] == '\\0');
        if (parsed < 3 || start == 0 || end <= start) {
            previous_libjvm_data_end = 0;
            pending_anon_start = 0;
            pending_anon_end = 0;
            continue;
        }
        if (libjvm_path && executable) {
            neko_add_libjvm_range(ranges, cap, &count, (uintptr_t)start, (uintptr_t)end, 0, 0, 1);
            previous_libjvm_data_end = 0;
            pending_anon_start = 0;
            pending_anon_end = 0;
            continue;
        }
        if (!readable_data) {
            previous_libjvm_data_end = 0;
            pending_anon_start = 0;
            pending_anon_end = 0;
            continue;
        }
        if (libjvm_path) {
            if (pending_anon_end == (uintptr_t)start) {
                neko_add_libjvm_range(ranges, cap, &count, pending_anon_start, pending_anon_end, 0, 1, 0);
            }
            neko_add_libjvm_range(ranges, cap, &count, (uintptr_t)start, (uintptr_t)end, 1, 1, 0);
            previous_libjvm_data_end = (uintptr_t)end;
            pending_anon_start = 0;
            pending_anon_end = 0;
        } else if (anonymous_path) {
            if (previous_libjvm_data_end == (uintptr_t)start) {
                neko_add_libjvm_range(ranges, cap, &count, (uintptr_t)start, (uintptr_t)end, 0, 1, 0);
                previous_libjvm_data_end = (uintptr_t)end;
            } else {
                pending_anon_start = (uintptr_t)start;
                pending_anon_end = (uintptr_t)end;
                previous_libjvm_data_end = 0;
            }
        } else {
            previous_libjvm_data_end = 0;
            pending_anon_start = 0;
            pending_anon_end = 0;
        }
    }
    fclose(fp);
    for (int i = 0; i < count; i++) {
        NEKO_PATCH_LOG("stripped jvmci range[%d]=[%p..%p) scan=%d slot=%d exec=%d",
            i, (void*)ranges[i].start, (void*)ranges[i].end, ranges[i].scan, ranges[i].slot, ranges[i].exec);
    }
    return count;
}

static int neko_addr_in_libjvm_ranges(uintptr_t addr, const neko_libjvm_range_t *ranges,
                                      int count, size_t width, int kind) {
    if (addr == 0 || ranges == NULL || count <= 0) return 0;
    for (int i = 0; i < count; i++) {
        if (kind == 1 && !ranges[i].scan) continue;
        if (kind == 2 && !ranges[i].exec) continue;
        if (kind == 0 && !ranges[i].slot) continue;
        if (addr >= ranges[i].start && addr + width >= addr && addr + width <= ranges[i].end) {
            return 1;
        }
    }
    return 0;
}

static const char *neko_find_libjvm_cstring(const char *needle, const neko_libjvm_range_t *ranges, int count) {
    size_t len;
    if (needle == NULL || ranges == NULL || count <= 0) return NULL;
    len = strlen(needle);
    if (len == 0) return NULL;
    for (int i = 0; i < count; i++) {
        if (!ranges[i].scan) continue;
        uintptr_t start = ranges[i].start;
        uintptr_t end = ranges[i].end;
        if (end <= start || (size_t)(end - start) <= len) continue;
        for (uintptr_t p = start; p + len < end; p++) {
            const char *s = (const char*)p;
            if (s[0] == needle[0] && memcmp(s, needle, len) == 0 && s[len] == '\\0') {
                return s;
            }
        }
    }
    return NULL;
}

static void neko_scan_stripped_jvmci_vmstructs(void) {
    neko_libjvm_range_t ranges[32];
    int count = neko_read_libjvm_data_ranges(ranges, 32);
    const char *type_compilertovm;
    const char *field_bad_mask;
    const char *field_lrb;
    const char *field_array;
    int matches = 0;
    int bound = 0;
    if (count <= 0) {
        NEKO_PATCH_LOG("stripped jvmci scan unavailable: no libjvm data ranges");
        return;
    }
    type_compilertovm = neko_find_libjvm_cstring("CompilerToVM::Data", ranges, count);
    field_bad_mask = neko_find_libjvm_cstring("thread_address_bad_mask_offset", ranges, count);
    field_lrb = neko_find_libjvm_cstring("ZBarrierSetRuntime_load_barrier_on_oop_field_preloaded", ranges, count);
    field_array = neko_find_libjvm_cstring("ZBarrierSetRuntime_load_barrier_on_oop_array", ranges, count);
    NEKO_PATCH_LOG("stripped jvmci scan strings: ranges=%d type=%p bad=%p lrb=%p array=%p",
        count, type_compilertovm, field_bad_mask, field_lrb, field_array);
    if (type_compilertovm == NULL || field_bad_mask == NULL || field_lrb == NULL) {
        NEKO_PATCH_LOG("stripped jvmci scan stopped: required strings missing");
        return;
    }
    for (int i = 0; i < count; i++) {
        uintptr_t start = (ranges[i].start + 7u) & ~(uintptr_t)7u;
        uintptr_t end = ranges[i].end;
        for (uintptr_t p = start; p + 48u <= end; p += 8u) {
            const char *type_name = *(const char* const*)p;
            const char *field_name = *(const char* const*)(p + 8u);
            const char *type_string = *(const char* const*)(p + 16u);
            int32_t is_static = *(const int32_t*)(p + 24u);
            uint64_t off_value = *(const uint64_t*)(p + 32u);
            void *static_addr = *(void* const*)(p + 40u);
            if (type_name != type_compilertovm || is_static != 1 || off_value != 0) continue;
            if (field_name == field_bad_mask) {
                matches++;
                if (neko_streq_safe(type_string, "int")
                    && neko_addr_in_libjvm_ranges((uintptr_t)static_addr, ranges, count, sizeof(int32_t), 0)) {
                    int32_t value = *(int32_t*)static_addr;
                    if (value >= 0) {
                        g_neko_method_layout.off_z_thread_address_bad_mask = (ptrdiff_t)value;
                        bound++;
                    }
                    NEKO_PATCH_LOG("stripped jvmci zcap bad_mask entry=%p slot=%p value=%d bound=%d",
                        (void*)p, static_addr, value, value >= 0);
                } else {
                    NEKO_PATCH_LOG("stripped jvmci zcap bad_mask rejected entry=%p type=%s slot=%p",
                        (void*)p, type_string ? type_string : "?", static_addr);
                }
            } else if (field_name == field_lrb) {
                matches++;
                if (neko_streq_safe(type_string, "address")
                    && neko_addr_in_libjvm_ranges((uintptr_t)static_addr, ranges, count, sizeof(void*), 0)) {
                    void *entry = *(void**)static_addr;
                    if (entry != NULL && neko_addr_in_libjvm_ranges((uintptr_t)entry, ranges, count, 1, 2)) {
                        g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded = entry;
                        bound++;
                    }
                    NEKO_PATCH_LOG("stripped jvmci zcap field_lrb entry=%p slot=%p value=%p bound=%d",
                        (void*)p, static_addr, entry,
                        entry != NULL && neko_addr_in_libjvm_ranges((uintptr_t)entry, ranges, count, 1, 2));
                } else {
                    NEKO_PATCH_LOG("stripped jvmci zcap field_lrb rejected entry=%p type=%s slot=%p",
                        (void*)p, type_string ? type_string : "?", static_addr);
                }
            } else if (field_array != NULL && field_name == field_array) {
                matches++;
                if (neko_streq_safe(type_string, "address")
                    && neko_addr_in_libjvm_ranges((uintptr_t)static_addr, ranges, count, sizeof(void*), 0)) {
                    void *entry = *(void**)static_addr;
                    if (entry != NULL && neko_addr_in_libjvm_ranges((uintptr_t)entry, ranges, count, 1, 2)) {
                        g_neko_method_layout.sym_z_load_barrier_on_oop_array = entry;
                        bound++;
                    }
                    NEKO_PATCH_LOG("stripped jvmci zcap array_lrb entry=%p slot=%p value=%p bound=%d abi=void(oop*,size_t)",
                        (void*)p, static_addr, entry,
                        entry != NULL && neko_addr_in_libjvm_ranges((uintptr_t)entry, ranges, count, 1, 2));
                } else {
                    NEKO_PATCH_LOG("stripped jvmci zcap array_lrb rejected entry=%p type=%s slot=%p",
                        (void*)p, type_string ? type_string : "?", static_addr);
                }
            }
        }
    }
    NEKO_PATCH_LOG("stripped jvmci zcap matches=%d bound=%d", matches, bound);
}
#else
static void neko_scan_stripped_jvmci_vmstructs(void) {
    NEKO_PATCH_LOG("stripped jvmci scan unavailable on this platform");
}
#endif

enum {
    NEKO_JDK21_BARRIERSET_SHENANDOAH_FALLBACK = 4,
    NEKO_JDK21_BARRIERSET_Z_FALLBACK = 5
};

static jboolean neko_barrierset_tag_is_shenandoah(int32_t tag) {
    if (tag == g_neko_method_layout.vmconst_barrierset_shenandoah) return JNI_TRUE;
    return (g_neko_method_layout.vmconst_barrierset_shenandoah < 0
            && tag == NEKO_JDK21_BARRIERSET_SHENANDOAH_FALLBACK)
        ? JNI_TRUE : JNI_FALSE;
}

static jboolean neko_barrierset_tag_is_zgc(int32_t tag) {
    if (tag == g_neko_method_layout.vmconst_barrierset_z) return JNI_TRUE;
    return (g_neko_method_layout.vmconst_barrierset_z < 0
            && tag == NEKO_JDK21_BARRIERSET_Z_FALLBACK)
        ? JNI_TRUE : JNI_FALSE;
}

static void neko_detect_current_gc_barrier(void) {
    void *bs;
    int32_t tag = -1;
    g_neko_method_layout.current_barrier_kind = NEKO_GC_BARRIER_UNKNOWN;
    g_neko_method_layout.current_barrier_set = NULL;
    g_neko_method_layout.current_card_table = NULL;
    g_neko_method_layout.card_table_byte_map_base = NULL;
    if (g_neko_method_layout.addr_barrierset_barrier_set == NULL
        || g_neko_method_layout.off_barrierset_fake_rtti < 0
        || g_neko_method_layout.off_barrierset_fakertti_concrete_tag < 0) {
        return;
    }
    bs = *(void**)g_neko_method_layout.addr_barrierset_barrier_set;
    if (bs == NULL) return;
    g_neko_method_layout.current_barrier_set = bs;
    tag = *(int32_t*)((char*)bs
        + g_neko_method_layout.off_barrierset_fake_rtti
        + g_neko_method_layout.off_barrierset_fakertti_concrete_tag);
    NEKO_PATCH_LOG("barrier-tag detected: tag=%d g1=%d cardtable=%d z=%d shen=%d use_zgc=%d use_shen=%d zg_instance=%p sh_lrb=%p",
        (int)tag,
        g_neko_method_layout.vmconst_barrierset_g1,
        g_neko_method_layout.vmconst_barrierset_cardtable,
        g_neko_method_layout.vmconst_barrierset_z,
        g_neko_method_layout.vmconst_barrierset_shenandoah,
        (int)g_hotspot.use_zgc,
        (int)g_hotspot.use_shenandoah_gc,
        g_neko_method_layout.addr_zglobals_instance_p,
        g_neko_method_layout.sym_shenandoah_load_reference_barrier_strong);
    if (neko_barrierset_tag_is_shenandoah(tag) || g_hotspot.use_shenandoah_gc) {
        g_neko_method_layout.current_barrier_kind = NEKO_GC_BARRIER_SHENANDOAH;
        g_hotspot.use_shenandoah_gc = JNI_TRUE;
    } else if (neko_barrierset_tag_is_zgc(tag) || g_hotspot.use_zgc) {
        g_neko_method_layout.current_barrier_kind = NEKO_GC_BARRIER_Z;
        /* The BarrierSet tag tells us this is ZGC even when the early
         * ZGlobals value probe sees zeros. Readiness below still requires
         * either callable runtime barriers or complete live mask values. */
        g_hotspot.use_zgc = JNI_TRUE;
    } else if (tag == g_neko_method_layout.vmconst_barrierset_g1) {
        g_neko_method_layout.current_barrier_kind = NEKO_GC_BARRIER_G1;
    } else if (tag == g_neko_method_layout.vmconst_barrierset_cardtable) {
        g_neko_method_layout.current_barrier_kind = NEKO_GC_BARRIER_CARDTABLE;
    }
    if (g_neko_method_layout.off_cardtablebarrierset_card_table >= 0) {
        void *ct = *(void**)((char*)bs + g_neko_method_layout.off_cardtablebarrierset_card_table);
        g_neko_method_layout.current_card_table = ct;
        if (ct != NULL && g_neko_method_layout.off_cardtable_byte_map_base >= 0) {
            g_neko_method_layout.card_table_byte_map_base =
                *(void**)((char*)ct + g_neko_method_layout.off_cardtable_byte_map_base);
        }
    }
}

static jboolean neko_gc_barrier_layout_ready(void) {
    jboolean card_table_ready =
        (g_neko_method_layout.card_table_byte_map_base != NULL
         && g_neko_method_layout.vmconst_cardtable_dirty_card >= 0)
        ? JNI_TRUE : JNI_FALSE;
    uintptr_t z_addr_mask = 0;
    uintptr_t z_load_good = 0;
    uintptr_t z_load_bad = 0;
    uintptr_t z_store_good = 0;
    uintptr_t z_store_bad = 0;
    if (g_hotspot.z_zglobals_addr_mask_p != NULL) z_addr_mask = *(uintptr_t*)g_hotspot.z_zglobals_addr_mask_p;
    if (z_addr_mask == 0) z_addr_mask = g_hotspot.z_address_offset_mask;
    if (g_hotspot.z_zglobals_load_good_mask_p != NULL) z_load_good = *(uintptr_t*)g_hotspot.z_zglobals_load_good_mask_p;
    if (z_load_good == 0) z_load_good = g_hotspot.z_pointer_load_good_mask;
    if (g_hotspot.z_zglobals_load_bad_mask_p != NULL) z_load_bad = *(uintptr_t*)g_hotspot.z_zglobals_load_bad_mask_p;
    if (z_load_bad == 0) z_load_bad = g_hotspot.z_pointer_load_bad_mask;
    if (g_hotspot.z_zglobals_store_good_mask_p != NULL) z_store_good = *(uintptr_t*)g_hotspot.z_zglobals_store_good_mask_p;
    if (z_store_good == 0) z_store_good = g_hotspot.z_pointer_store_good_mask;
    if (g_hotspot.z_zglobals_store_bad_mask_p != NULL) z_store_bad = *(uintptr_t*)g_hotspot.z_zglobals_store_bad_mask_p;
    if (z_store_bad == 0) z_store_bad = g_hotspot.z_pointer_store_bad_mask;
    /* For ZGC: readiness is a capability check. Metadata presence alone is
     * not enough; translated oop paths need either callable runtime barriers
     * or complete nonzero live masks for the inline path. */
    jboolean z_symbol_ready =
        (g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded != NULL
         && g_neko_method_layout.sym_z_load_barrier_on_oop_array != NULL
         && g_neko_method_layout.sym_z_store_barrier_on_oop_field_with_healing != NULL)
        ? JNI_TRUE : JNI_FALSE;
    jboolean z_instance_ready =
        (g_neko_method_layout.addr_zglobals_instance_p != NULL
         && g_neko_method_layout.off_zglobals_address_offset_mask >= 0
         && g_neko_method_layout.off_zglobals_pointer_load_good_mask >= 0
         && g_neko_method_layout.off_zglobals_pointer_load_bad_mask >= 0
         && g_neko_method_layout.off_zglobals_pointer_store_good_mask >= 0
         && g_neko_method_layout.off_zglobals_pointer_store_bad_mask >= 0
         && g_hotspot.z_zglobals_addr_mask_p != NULL
         && g_hotspot.z_zglobals_load_good_mask_p != NULL
         && g_hotspot.z_zglobals_load_bad_mask_p != NULL
         && g_hotspot.z_zglobals_store_good_mask_p != NULL
         && g_hotspot.z_zglobals_store_bad_mask_p != NULL
         && z_addr_mask != 0
         && z_load_good != 0
         && z_load_bad != 0
         && z_store_good != 0
         && z_store_bad != 0)
        ? JNI_TRUE : JNI_FALSE;
    switch (g_neko_method_layout.current_barrier_kind) {
        case NEKO_GC_BARRIER_G1:
            return card_table_ready ? JNI_TRUE : JNI_FALSE;
        case NEKO_GC_BARRIER_CARDTABLE:
            return card_table_ready ? JNI_TRUE : JNI_FALSE;
        case NEKO_GC_BARRIER_Z:
            if (z_symbol_ready || z_instance_ready) return JNI_TRUE;
            NEKO_PATCH_LOG("ZGC barrier capability missing: symbols field=%p array=%p store=%p masks addr=0x%llx load_good=0x%llx load_bad=0x%llx store_good=0x%llx store_bad=0x%llx",
                g_neko_method_layout.sym_z_load_barrier_on_oop_field_preloaded,
                g_neko_method_layout.sym_z_load_barrier_on_oop_array,
                g_neko_method_layout.sym_z_store_barrier_on_oop_field_with_healing,
                (unsigned long long)z_addr_mask,
                (unsigned long long)z_load_good,
                (unsigned long long)z_load_bad,
                (unsigned long long)z_store_good,
                (unsigned long long)z_store_bad);
            return JNI_FALSE;
        case NEKO_GC_BARRIER_SHENANDOAH:
            if (g_neko_method_layout.sym_shenandoah_load_reference_barrier_strong != NULL
                && g_neko_method_layout.sym_shenandoah_write_ref_field_pre_entry != NULL
                && g_neko_method_layout.sym_shenandoah_arraycopy_barrier_oop_entry != NULL) {
                return JNI_TRUE;
            }
            NEKO_PATCH_LOG("Shenandoah barrier capability missing: lrb=%p pre=%p array=%p",
                g_neko_method_layout.sym_shenandoah_load_reference_barrier_strong,
                g_neko_method_layout.sym_shenandoah_write_ref_field_pre_entry,
                g_neko_method_layout.sym_shenandoah_arraycopy_barrier_oop_entry);
            return JNI_FALSE;
        default:
            return JNI_FALSE;
    }
}

static jboolean neko_native_resolution_layout_ready(void) {
    jboolean field_stream_ready =
        (g_neko_method_layout.off_instanceklass_fieldinfo_stream >= 0
         || g_neko_method_layout.off_instanceklass_fields >= 0)
        ? JNI_TRUE : JNI_FALSE;
    jboolean metadata_ready =
        (g_neko_method_layout.off_instanceklass_methods >= 0
         && field_stream_ready
         && g_neko_method_layout.off_instanceklass_constants >= 0
         && g_neko_method_layout.off_instanceklass_transitive_interfaces >= 0
         && g_neko_method_layout.off_klass_super_check_offset >= 0
         && g_neko_method_layout.off_klass_secondary_supers >= 0
         && g_neko_method_layout.off_klass_java_mirror >= 0
         && g_neko_method_layout.off_klass_super >= 0
         && g_neko_method_layout.off_klass_next_link >= 0
         && g_neko_method_layout.off_klass_name >= 0
         && g_neko_method_layout.off_constantpool_tags >= 0
         && g_neko_method_layout.off_constantpool_pool_holder >= 0
         && g_neko_method_layout.off_constantpool_length >= 0
         && g_neko_method_layout.off_method_constMethod >= 0
         && g_neko_method_layout.off_constmethod_constants >= 0
         && g_neko_method_layout.off_constmethod_name_index >= 0
         && g_neko_method_layout.off_constmethod_signature_index >= 0
         && g_neko_method_layout.off_symbol_length >= 0
         && g_neko_method_layout.off_symbol_body >= 0
         && g_neko_method_layout.off_array_length >= 0
         && g_neko_method_layout.off_array_data > 0
         && (g_neko_method_layout.off_instanceklass_fieldinfo_stream < 0
             || g_neko_method_layout.off_array_u1_data > 0)
         && (g_neko_method_layout.off_instanceklass_fields < 0
             || g_neko_method_layout.off_array_u2_data > 0)
         && g_neko_method_layout.addr_universe_collected_heap != NULL
         && g_neko_method_layout.addr_classloaderdatagraph_head != NULL
         && g_neko_method_layout.off_classloaderdata_next >= 0
         && g_neko_method_layout.off_classloaderdata_klasses >= 0
         && g_neko_method_layout.addr_barrierset_barrier_set != NULL
         && g_neko_method_layout.off_barrierset_fake_rtti >= 0
         && g_neko_method_layout.off_barrierset_fakertti_concrete_tag >= 0)
        ? JNI_TRUE : JNI_FALSE;
    jboolean compressed_ready =
        (g_neko_method_layout.addr_compressed_oops_base != NULL
         && g_neko_method_layout.addr_compressed_oops_shift != NULL
         && g_neko_method_layout.addr_compressed_klass_base != NULL
         && g_neko_method_layout.addr_compressed_klass_shift != NULL)
        ? JNI_TRUE : JNI_FALSE;
    jboolean class_lookup_ready =
        (g_neko_method_layout.addr_classloaderdatagraph_head != NULL
         || g_neko_method_layout.sym_jvm_find_class_from_boot_loader != NULL
         || g_neko_method_layout.sym_jvm_find_class_from_class != NULL
         || g_neko_method_layout.sym_systemdictionary_find_instance_klass != NULL
         || g_neko_method_layout.sym_systemdictionary_find_instance_or_array_klass != NULL)
        ? JNI_TRUE : JNI_FALSE;
    jboolean string_ready =
        (g_neko_method_layout.sym_stringtable_intern_symbol != NULL
         || g_neko_method_layout.sym_stringtable_intern_utf8 != NULL
         || g_neko_method_layout.addr_stringtable_the_table != NULL
         || g_neko_method_layout.sym_jvm_intern_string != NULL)
        ? JNI_TRUE : JNI_FALSE;
    jboolean array_alloc_ready =
        ((g_neko_method_layout.sym_oopfactory_new_type_array != NULL
          && g_neko_method_layout.sym_oopfactory_new_obj_array != NULL)
         || (g_neko_method_layout.sym_jvm_find_primitive_class != NULL
             && g_neko_method_layout.sym_jvm_new_array != NULL
             && g_neko_method_layout.sym_jvm_new_multi_array != NULL))
        ? JNI_TRUE : JNI_FALSE;
    return (metadata_ready && compressed_ready && class_lookup_ready
            && string_ready && array_alloc_ready)
        ? JNI_TRUE : JNI_FALSE;
}

static void* neko_jmethodid_to_method_star(jmethodID mid) {
    if (mid == NULL) return NULL;
    return *(void**)mid;
}

/* === Phase 1: CodeCache discovery ===
 * Read-only walk of HotSpot's CodeCache::_heaps. Validates every layout
 * offset before any allocation. Also harvests a BufferBlob vtable pointer
 * from an existing blob (so we can construct our own BufferBlob in-place
 * later without dlsym'ing internal libjvm symbols, which JDK 21 strips).
 *
 * The segmap is a byte array indexed by segment number. A non-zero entry
 * means "this segment is N segments away from a block header" (with 0xFE
 * meaning "skip 254"). Following the trail to 0 lands on a HeapBlock.
 * For a forward walk we use HeapBlock::Header::_length (in segments) to
 * advance directly, which is simpler. */

static jboolean neko_codecache_layout_ready(void) {
    /* GrowableArrayBase::_len sits at offset 0 (no vtable on AnyObj base);
     * CodeHeap::_memory likewise at 0. All offsets must be non-negative
     * and the static-field address must be resolved. */
    return (g_neko_method_layout.addr_codecache_heaps != NULL
        && g_neko_method_layout.off_growable_array_len >= 0
        && g_neko_method_layout.off_growable_array_data > 0
        && g_neko_method_layout.off_codeheap_memory >= 0
        && g_neko_method_layout.off_codeheap_segmap > 0
        && g_neko_method_layout.off_codeheap_log2_segment_size > 0
        && g_neko_method_layout.off_virtualspace_low > 0
        && g_neko_method_layout.off_virtualspace_high > 0
        && g_neko_method_layout.off_codeblob_name > 0
        && g_neko_method_layout.off_codeblob_size > 0
        && g_neko_method_layout.off_codeblob_code_begin > 0
        && g_neko_method_layout.off_codeblob_code_end > 0)
        ? JNI_TRUE : JNI_FALSE;
}

static void* neko_virtualspace_low(void *vspace) {
    return *(void**)((char*)vspace + g_neko_method_layout.off_virtualspace_low);
}
static void* neko_virtualspace_high(void *vspace) {
    return *(void**)((char*)vspace + g_neko_method_layout.off_virtualspace_high);
}

/* HeapBlock layout (matches hotspot/share/memory/heap.hpp):
 *   struct Header { size_t _length; bool _used; };
 *   union { Header _header; int64_t _padding[(sizeof(Header)+7)/8]; };
 *
 * On x86_64 with 8-byte size_t and 1-byte bool, the union is padded to
 * 16 bytes (2 int64_t slots). _length is at +0, _used at +8. */
typedef struct {
    size_t length;
    int    used;
} neko_heapblock_info_t;

static int neko_read_heapblock(void *block, neko_heapblock_info_t *out) {
    if (block == NULL) return 0;
    out->length = *(size_t*)block;
    /* HotSpot stores _used as a 1-byte bool. In a release JVM unused tail
     * memory is zero so reading past the last block gives _used==0 + length==0.
     * In a fastdebug JVM that tail is poisoned with 0xCC, which would parse
     * as length=0xCCCC..., used=0xCC and walk us off into noise. Reject any
     * "_used" byte that isn't a clean 0 or 1 so the caller can stop. */
    unsigned char raw = *(unsigned char*)((char*)block + sizeof(size_t));
    if (raw != 0 && raw != 1) {
        out->length = 0;
        out->used   = 0;
        return 0;
    }
    out->used = raw ? 1 : 0;
    return 1;
}

static const char *neko_codeblob_name(void *blob) {
    if (blob == NULL) return NULL;
    return *(const char**)((char*)blob + g_neko_method_layout.off_codeblob_name);
}
static int neko_codeblob_size(void *blob) {
    if (blob == NULL) return 0;
    return *(int*)((char*)blob + g_neko_method_layout.off_codeblob_size);
}
static void* neko_codeblob_code_begin(void *blob) {
    if (blob == NULL) return NULL;
    return *(void**)((char*)blob + g_neko_method_layout.off_codeblob_code_begin);
}
static void* neko_codeblob_code_end(void *blob) {
    if (blob == NULL || g_neko_method_layout.off_codeblob_code_end <= 0) return NULL;
    return *(void**)((char*)blob + g_neko_method_layout.off_codeblob_code_end);
}

/* Walk one CodeHeap's blocks. Each block starts with a HeapBlock header
 * (16 bytes on x86_64) followed by a CodeBlob (if used). Block size is
 * length * segment_size, where segment_size = 1 << _log2_segment_size. */
static void neko_walk_codeheap(void *heap, void (*visitor)(void *blob, const char *name, void *cookie), void *cookie) {
    void *vspace = (char*)heap + g_neko_method_layout.off_codeheap_memory;
    int log2_seg = *(int*)((char*)heap + g_neko_method_layout.off_codeheap_log2_segment_size);
    size_t seg_size = (size_t)1u << (log2_seg & 31);
    if (seg_size == 0) return;
    void *low = neko_virtualspace_low(vspace);
    void *high = neko_virtualspace_high(vspace);
    if (low == NULL || high == NULL || low >= high) return;
    /* HeapBlock header occupies 16 bytes (rounded up to 8-aligned slot pair).
     * CodeBlob immediately follows the header. */
    const size_t header_size = 16;
    char *p = (char*)low;
    size_t total_segments = ((size_t)((char*)high - (char*)low)) / seg_size;
    int safety_iter = 0;
    while (p < (char*)high && safety_iter++ < 1000000) {
        neko_heapblock_info_t info;
        if (!neko_read_heapblock(p, &info)) break;
        if (info.length == 0) break;
        /* Sanity: HotSpot does not export _next_segment via VMStructs, so
         * we don't know the allocation high-water mark directly. Treat any
         * length that exceeds the remaining committed segments as past the
         * end of the populated region — this catches both fastdebug 0xCC
         * poison and accidentally walking into the segmap area. */
        size_t cur_offset_segs = ((size_t)((char*)p - (char*)low)) / seg_size;
        if (info.length > total_segments - cur_offset_segs) break;
        size_t block_bytes = info.length * seg_size;
        if (info.used) {
            void *blob = (void*)(p + header_size);
            const char *name = neko_codeblob_name(blob);
            if (visitor) visitor(blob, name, cookie);
        }
        p += block_bytes;
    }
}

typedef struct {
    void *target_vtable;
    void *call_stub_return_pc;
    void *call_stub_entry;
    int   limit_logged;
} neko_blob_visit_ctx_t;

static void *neko_find_call_stub_entry(void *code_begin, void *return_pc) {
    if (code_begin == NULL || return_pc == NULL || code_begin >= return_pc) return NULL;
    const unsigned char *begin = (const unsigned char*)code_begin;
    const unsigned char *ret = (const unsigned char*)return_pc;
    const unsigned char pattern[] = {0x55, 0x48, 0x8b, 0xec, 0x48, 0x83, 0xec, 0x60};
    const size_t pattern_len = sizeof(pattern);
    const unsigned char *scan = ret;
    size_t max_back = (size_t)(ret - begin);
    if (max_back > 512u) max_back = 512u;
    for (size_t back = 0; back + pattern_len <= max_back; back++) {
        const unsigned char *p = ret - back;
        if (p < begin || p + pattern_len > ret) continue;
        if (memcmp(p, pattern, pattern_len) == 0) return (void*)p;
    }
    return NULL;
}

static void neko_blob_visit_log(void *blob, const char *name, void *cookie) {
    neko_blob_visit_ctx_t *ctx = (neko_blob_visit_ctx_t*)cookie;
    /* Always log anything that looks like an adapter / buffer / vtable / stub
     * so we can spot vtable-eligible candidates in the noise of nmethods. */
    int interesting = name != NULL && (strstr(name, "adapt") != NULL
                                    || strstr(name, "I2C/C2I") != NULL
                                    || strstr(name, "MethodHandle") != NULL
                                    || strstr(name, "vtable") != NULL
                                    || strstr(name, "stub") != NULL
                                    || strstr(name, "Stub") != NULL
                                    || strstr(name, "Buffer") != NULL);
    if (NEKO_PATCH_DEBUG && (interesting || ctx->limit_logged < 16)) {
        fprintf(stderr, "[neko-patch] blob %p name=%s size=%d code=%p\\n",
            blob, name ? name : "?", neko_codeblob_size(blob), neko_codeblob_code_begin(blob));
        ctx->limit_logged++;
    }
    if (ctx->call_stub_entry == NULL && ctx->call_stub_return_pc != NULL) {
        void *code_begin = neko_codeblob_code_begin(blob);
        void *code_end = neko_codeblob_code_end(blob);
        if (code_begin != NULL && code_end != NULL
            && code_begin <= ctx->call_stub_return_pc && ctx->call_stub_return_pc < code_end) {
            ctx->call_stub_entry = neko_find_call_stub_entry(code_begin, ctx->call_stub_return_pc);
            if (NEKO_PATCH_DEBUG) {
                fprintf(stderr, "[neko-patch] call_stub blob=%p name=%s ret=%p entry=%p code=[%p..%p)\\n",
                    blob, name ? name : "?", ctx->call_stub_return_pc, ctx->call_stub_entry, code_begin, code_end);
            }
        }
    }
    if (name != NULL) {
        if (g_neko_method_layout.runtime1_monitorenter_entry == NULL
            && strcmp(name, "monitorenter Runtime1 stub") == 0) {
            g_neko_method_layout.runtime1_monitorenter_entry = neko_codeblob_code_begin(blob);
            if (NEKO_PATCH_DEBUG) {
                fprintf(stderr, "[neko-patch] runtime1 monitorenter entry=%p blob=%p\\n",
                    g_neko_method_layout.runtime1_monitorenter_entry, blob);
            }
        } else if (g_neko_method_layout.runtime1_monitorexit_entry == NULL
            && strcmp(name, "monitorexit Runtime1 stub") == 0) {
            g_neko_method_layout.runtime1_monitorexit_entry = neko_codeblob_code_begin(blob);
            if (NEKO_PATCH_DEBUG) {
                fprintf(stderr, "[neko-patch] runtime1 monitorexit entry=%p blob=%p\\n",
                    g_neko_method_layout.runtime1_monitorexit_entry, blob);
            }
        }
    }
    /* Harvest vtable from the first BufferBlob/AdapterBlob we see. Adapter
     * blobs are created at JVM startup so they always exist by JNI_OnLoad. */
    if (ctx->target_vtable == NULL && name != NULL
        && (strstr(name, "I2C/C2I") != NULL || strstr(name, "adapter") != NULL)) {
        ctx->target_vtable = *(void**)blob;
        if (NEKO_PATCH_DEBUG) {
            fprintf(stderr, "[neko-patch] harvested vtable %p from blob %p (%s)\\n",
                ctx->target_vtable, blob, name);
        }
    }
}

/* === Phase 2: private CodeHeap allocator + registration ===
 * We construct a CodeHeap struct ourselves (in C-heap memory), back it with
 * a private mmap'd executable region + segmap, and append the CodeHeap* to
 * HotSpot's CodeCache::_heaps GrowableArray. After registration,
 * CodeCache::find_blob_at(pc) will scan our heap when given a PC inside
 * our exec region. Phase 3 then constructs CodeBlobs there.
 *
 * Layout offsets we DERIVE (not exposed by VMStructs but stable in
 * jdk-21.0.10 hotspot/share/memory/heap.hpp):
 *   _segment_size                   at log2_segment_size_offset - 8  (size_t before)
 *   _number_of_reserved_segments    at log2_segment_size_offset - 16
 *   _number_of_committed_segments   at log2_segment_size_offset - 24
 *   _next_segment                   at log2_segment_size_offset + 8  (skip 4 + 4 pad)
 *   _freelist                       at log2_segment_size_offset + 16 (a FreeBlock*)
 * If a future JDK reorders these, port maintenance per-version. */

#define NEKO_PRIV_HEAP_BYTES   (256 * 1024)  /* 256 KB exec area */
#define NEKO_PRIV_SEGMENT_BYTES 128

typedef struct {
    void   *codeheap;        /* C-heap allocated CodeHeap struct */
    void   *exec_region;     /* mmap PROT_RWX area */
    size_t  exec_size;
    void   *segmap_region;   /* mmap RW area, one byte per segment */
    size_t  segmap_size;
    size_t  segment_size;
    size_t  next_byte;       /* bump cursor inside exec_region */
    jboolean registered;
} neko_priv_codeheap_t;

static neko_priv_codeheap_t g_neko_priv_heap = {0};

static void *neko_alloc_exec_pages(size_t size) {
#if defined(__linux__) || defined(__APPLE__)
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
#else
    return NULL;
#endif
}

""");
    }

}
