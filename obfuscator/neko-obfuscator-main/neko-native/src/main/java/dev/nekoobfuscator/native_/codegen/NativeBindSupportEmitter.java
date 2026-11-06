package dev.nekoobfuscator.native_.codegen;

/**
 * Emits bind-time class/member cache helpers and tolerant class mirror resolution.
 */
final class NativeBindSupportEmitter {
    private NativeBindSupportEmitter() {}

    static String renderBindSupport() {
        return new StringBuilder("""
typedef jclass (*neko_jvm_find_class_boot_t)(JNIEnv*, const char*);
typedef jclass (*neko_jvm_find_class_from_class_t)(JNIEnv*, const char*, jboolean, jclass);
typedef jstring (*neko_jvm_intern_string_t)(JNIEnv*, jstring);
typedef jclass (*neko_jvm_find_primitive_class_t)(JNIEnv*, const char*);
typedef jarray (*neko_jvm_new_array_t)(JNIEnv*, jclass, jint);

typedef struct neko_class_klass_cache_node {
    jclass mirror;
    void *klass;
    struct neko_class_klass_cache_node *next;
} neko_class_klass_cache_node;

static neko_class_klass_cache_node *g_neko_class_klass_cache = NULL;

static void *neko_resolve_loaded_class_by_name(const char *utf8);

static void neko_remember_class_klass(jclass mirror, void *klass) {
    neko_class_klass_cache_node *node;
    if (mirror == NULL || klass == NULL) return;
    for (node = g_neko_class_klass_cache; node != NULL; node = node->next) {
        if (node->mirror == mirror) {
            node->klass = klass;
            return;
        }
    }
    node = (neko_class_klass_cache_node*)malloc(sizeof(*node));
    if (node == NULL) {
        fprintf(stderr, "[neko-bind] class cache allocation failed\\n");
        abort();
    }
    node->mirror = mirror;
    node->klass = klass;
    node->next = g_neko_class_klass_cache;
    g_neko_class_klass_cache = node;
}

static void *neko_class_mirror_to_klass(jclass mirror) {
    neko_class_klass_cache_node *node;
    void *mirror_oop;
    void *klass;
    if (mirror == NULL) return NULL;
    for (node = g_neko_class_klass_cache; node != NULL; node = node->next) {
        if (node->mirror == mirror) return node->klass;
    }
    if (g_neko_method_layout.off_java_lang_class_klass < 0) {
        fprintf(stderr, "[neko-bind] java.lang.Class::_klass offset unavailable\\n");
        abort();
    }
    mirror_oop = neko_handle_oop((jobject)mirror);
    if (mirror_oop == NULL) return NULL;
    klass = *(void**)((char*)mirror_oop + g_neko_method_layout.off_java_lang_class_klass);
    return klass;
}

static jobject neko_klass_java_mirror_handle(void *thread, void *klass) {
    void *mirror_handle;
    void *mirror_oop;
    if (klass == NULL) return NULL;
    if (g_neko_method_layout.off_klass_java_mirror < 0) {
        fprintf(stderr, "[neko-bind] Klass::_java_mirror offset unavailable\\n");
        abort();
    }
    mirror_handle = *(void**)((char*)klass + g_neko_method_layout.off_klass_java_mirror);
    if (mirror_handle == NULL) return NULL;
    mirror_oop = *(void**)mirror_handle;
    return mirror_oop != NULL ? neko_handle_push(thread, mirror_oop) : NULL;
}

static jclass neko_resolve_class_mirror_with_env(JNIEnv *env, const char *utf8, jclass from_class, void **klass_out) {
    jclass resolved = NULL;
    void *mirror_klass;
    void *klass;
    if (klass_out != NULL) *klass_out = NULL;
    if (env == NULL) {
        fprintf(stderr, "[neko-bind] native class resolution missing JNIEnv: %s\\n",
            utf8 == NULL ? "<null>" : utf8);
        abort();
    }
    if (utf8 == NULL || utf8[0] == '\\0') {
        fprintf(stderr, "[neko-bind] class resolution requested with empty name\\n");
        abort();
    }
    klass = neko_resolve_loaded_class_by_name(utf8);
    if (getenv("NEKO_PATCH_DEBUG") != NULL) {
        fprintf(stderr, "[neko-bind] class lookup start name=%s from=%p boot_sym=%p from_sym=%p\\n",
            utf8, (void*)from_class,
            g_neko_method_layout.sym_jvm_find_class_from_boot_loader,
            g_neko_method_layout.sym_jvm_find_class_from_class);
    }
    if (g_neko_method_layout.sym_jvm_find_class_from_boot_loader != NULL) {
        resolved = ((neko_jvm_find_class_boot_t)g_neko_method_layout.sym_jvm_find_class_from_boot_loader)(env, utf8);
        if (getenv("NEKO_PATCH_DEBUG") != NULL) {
            fprintf(stderr, "[neko-bind] class lookup boot result name=%s mirror=%p\\n", utf8, (void*)resolved);
        }
    }
    if (resolved == NULL && from_class != NULL && g_neko_method_layout.sym_jvm_find_class_from_class != NULL) {
        resolved = ((neko_jvm_find_class_from_class_t)g_neko_method_layout.sym_jvm_find_class_from_class)(
            env, utf8, JNI_FALSE, from_class);
        if (getenv("NEKO_PATCH_DEBUG") != NULL) {
            fprintf(stderr, "[neko-bind] class lookup from result name=%s mirror=%p\\n", utf8, (void*)resolved);
        }
    }
    if (resolved != NULL) {
        mirror_klass = NULL;
        if (g_neko_method_layout.off_java_lang_class_klass >= 0) {
            mirror_klass = neko_class_mirror_to_klass(resolved);
        }
        if (klass == NULL) {
            klass = mirror_klass;
        } else if (mirror_klass != NULL && mirror_klass != klass) {
            fprintf(stderr, "[neko-bind] native class mirror mismatch: %s loaded=%p mirror=%p\\n",
                utf8, klass, mirror_klass);
            abort();
        }
        if (klass == NULL) {
            fprintf(stderr, "[neko-bind] native class mirror did not map to Klass*: %s\\n", utf8);
            abort();
        }
        if (klass_out != NULL) *klass_out = klass;
        return resolved;
    }
    if (klass != NULL) {
        void *thread = neko_jni_env_to_thread(env);
        jclass mirror;
        if (thread == NULL) {
            fprintf(stderr, "[neko-bind] JavaThread unavailable for class mirror handle: %s\\n", utf8);
            abort();
        }
        mirror = (jclass)neko_klass_java_mirror_handle(thread, klass);
        if (mirror == NULL) {
            fprintf(stderr, "[neko-bind] native class mirror handle failed: %s\\n", utf8);
            abort();
        }
        if (klass_out != NULL) *klass_out = klass;
        return mirror;
    }
    fprintf(stderr, "[neko-bind] native class resolution failed: %s\\n", utf8);
    abort();
}
""").append("""
static void *neko_resolve_class_with_env(JNIEnv *env, const char *utf8, jclass from_class) {
    void *klass = NULL;
    (void)neko_resolve_class_mirror_with_env(env, utf8, from_class, &klass);
    return klass;
}

static void *neko_resolve_class_with_mirror(const char *utf8, jclass from_class) {
    void *thread = neko_current_thread_register();
    return neko_resolve_class_with_env(neko_thread_jni_env(thread), utf8, from_class);
}

static void *neko_resolve_class(const char *utf8) {
    return neko_resolve_class_with_mirror(utf8, NULL);
}

static void neko_ensure_class_initialized(JNIEnv *env, jclass cls, const char *owner) {
    void *thread;
    neko_handle_save_t handle_window;
    jclass initialized;
    if (env == NULL || cls == NULL || owner == NULL) {
        fprintf(stderr, "[neko-bind] class initialization missing input: %s cls=%p\\n",
            owner == NULL ? "<null>" : owner,
            (void*)cls);
        abort();
    }
    if (g_neko_method_layout.sym_jvm_find_class_from_class == NULL) {
        fprintf(stderr, "[neko-bind] class initialization symbol unavailable: %s\\n", owner);
        abort();
    }
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] class initialization has no JavaThread: %s\\n", owner);
        abort();
    }
    neko_handle_window_begin(thread, &handle_window);
    initialized = ((neko_jvm_find_class_from_class_t)g_neko_method_layout.sym_jvm_find_class_from_class)(
        env, owner, JNI_TRUE, cls);
    if (initialized == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] class initialization failed: %s\\n", owner);
        abort();
    }
    neko_handle_window_end(&handle_window);
}

__attribute__((visibility("hidden"))) void neko_ensure_class_initialized_once(JNIEnv *env, jclass cls, const char *owner, volatile jboolean *slot) {
    if (slot != NULL && *slot == JNI_TRUE) return;
    neko_ensure_class_initialized(env, cls, owner);
    if (slot != NULL) *slot = JNI_TRUE;
}

static uintptr_t neko_klass_header_bits(void *klass) {
    uintptr_t base;
    int shift;
    if (klass == NULL) return 0;
    if (g_hotspot.use_compressed_klass_ptrs) {
        if (g_neko_method_layout.addr_compressed_klass_base == NULL
            || g_neko_method_layout.addr_compressed_klass_shift == NULL) {
            fprintf(stderr, "[neko-bind] compressed Klass encoding layout unavailable\\n");
            abort();
        }
        base = (uintptr_t)(*(void**)g_neko_method_layout.addr_compressed_klass_base);
        shift = *(int*)g_neko_method_layout.addr_compressed_klass_shift;
        return (uintptr_t)(((uintptr_t)klass - base) >> shift);
    }
    return (uintptr_t)klass;
}

static void neko_ensure_string_alloc_bits(JNIEnv *env) {
    void *string_klass;
    jint layout_helper;
    if (g_neko_fast_string_alloc_ready) return;
    if (!g_hotspot.initialized
        || (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) == 0
        || g_hotspot.use_compact_object_headers
        || g_hotspot.klass_offset_bytes <= 0
        || !g_neko_tlab_alloc_ready
        || g_hotspot.primitive_array_klass_bits[NEKO_PRIM_B] == 0) {
        fprintf(stderr, "[neko-bind] direct String allocation layout unavailable\\n");
        abort();
    }
    string_klass = neko_resolve_class_with_env(env, "java/lang/String", NULL);
    if (g_neko_method_layout.off_klass_layout_helper < 0 || string_klass == NULL) {
        fprintf(stderr, "[neko-bind] direct String allocation layout helper unavailable klass=%p off=%td\\n",
            string_klass, g_neko_method_layout.off_klass_layout_helper);
        abort();
    }
    layout_helper = *(jint*)((char*)string_klass + g_neko_method_layout.off_klass_layout_helper);
    if (layout_helper <= 0) {
        fprintf(stderr, "[neko-bind] direct String allocation invalid layout helper klass=%p layout=%d\\n",
            string_klass, (int)layout_helper);
        abort();
    }
    if ((layout_helper & 1) != 0) {
        fprintf(stderr, "[neko-bind] direct String allocation requires slow path klass=%p layout=%d\\n",
            string_klass, (int)layout_helper);
        abort();
    }
    g_neko_string_klass_bits = neko_klass_header_bits(string_klass);
    g_neko_byte_array_klass_bits = g_hotspot.primitive_array_klass_bits[NEKO_PRIM_B];
    g_neko_string_instance_bytes = (size_t)(layout_helper & ~1);
    g_neko_fast_string_alloc_ready =
        (g_neko_string_klass_bits != 0 && g_neko_byte_array_klass_bits != 0 && g_neko_string_instance_bytes != 0) ? JNI_TRUE : JNI_FALSE;
    if (!g_neko_fast_string_alloc_ready) {
        fprintf(stderr, "[neko-bind] direct String allocation klass bits unavailable\\n");
        abort();
    }
    /* TLAB-NULL fix: cache String.concat NJX dispatch metadata. */
    neko_ensure_string_concat_njx_cache(env, string_klass);
}

static jboolean neko_symbol_equals_utf8(void *symbol, const char *utf8) {
    uint16_t len;
    const char *body;
    if (symbol == NULL || utf8 == NULL) return JNI_FALSE;
    if (g_neko_method_layout.off_symbol_length < 0 || g_neko_method_layout.off_symbol_body < 0) {
        fprintf(stderr, "[neko-bind] Symbol layout unavailable\\n");
        abort();
    }
    len = *(uint16_t*)((char*)symbol + g_neko_method_layout.off_symbol_length);
    body = (const char*)symbol + g_neko_method_layout.off_symbol_body;
    return strlen(utf8) == (size_t)len && memcmp(body, utf8, len) == 0 ? JNI_TRUE : JNI_FALSE;
}

static void *neko_resolve_loaded_class_by_name(const char *utf8) {
    void *head;
    void *cld;
    if (utf8 == NULL) return NULL;
    if (g_neko_method_layout.addr_classloaderdatagraph_head == NULL
        || g_neko_method_layout.off_classloaderdata_next < 0
        || g_neko_method_layout.off_classloaderdata_klasses < 0
        || g_neko_method_layout.off_klass_next_link < 0
        || g_neko_method_layout.off_klass_name < 0) {
        fprintf(stderr, "[neko-bind] ClassLoaderDataGraph layout unavailable for class resolution: head=%p cld_next=%td cld_klasses=%td klass_next=%td klass_name=%td\\n",
            g_neko_method_layout.addr_classloaderdatagraph_head,
            g_neko_method_layout.off_classloaderdata_next,
            g_neko_method_layout.off_classloaderdata_klasses,
            g_neko_method_layout.off_klass_next_link,
            g_neko_method_layout.off_klass_name);
        abort();
    }
    head = *(void**)g_neko_method_layout.addr_classloaderdatagraph_head;
    cld = head;
    for (uint32_t cldDepth = 0; cld != NULL && cldDepth < 65536u; cldDepth++) {
        void *klass = *(void**)((char*)cld + g_neko_method_layout.off_classloaderdata_klasses);
        for (uint32_t klassDepth = 0; klass != NULL && klassDepth < 1048576u; klassDepth++) {
            void *name = *(void**)((char*)klass + g_neko_method_layout.off_klass_name);
            if (neko_symbol_equals_utf8(name, utf8)) {
                return klass;
            }
            klass = *(void**)((char*)klass + g_neko_method_layout.off_klass_next_link);
        }
        cld = *(void**)((char*)cld + g_neko_method_layout.off_classloaderdata_next);
    }
    return NULL;
}

static ptrdiff_t neko_constantpool_base_offset(void) {
    if (g_neko_method_layout.off_constantpool_base >= 0) {
        return g_neko_method_layout.off_constantpool_base;
    }
    if (g_neko_method_layout.sizeof_ConstantPool > 0) {
        return (ptrdiff_t)g_neko_method_layout.sizeof_ConstantPool;
    }
    if (g_neko_method_layout.off_constantpool_length < 0) {
        fprintf(stderr, "[neko-bind] ConstantPool base layout unavailable\\n");
        abort();
    }
    fprintf(stderr, "[neko-bind] ConstantPool base layout unavailable\\n");
    abort();
}

static void *neko_constantpool_symbol_at(void *constant_pool, uint16_t index) {
    int length;
    void **base;
    if (constant_pool == NULL) return NULL;
    if (g_neko_method_layout.off_constantpool_length < 0) {
        fprintf(stderr, "[neko-bind] ConstantPool symbol layout unavailable\\n");
        abort();
    }
    length = *(int*)((char*)constant_pool + g_neko_method_layout.off_constantpool_length);
    if (index == 0 || index >= (uint16_t)length) return NULL;
    base = (void**)((char*)constant_pool + neko_constantpool_base_offset());
    return base[index];
}

static void *neko_method_constmethod(void *method) {
    if (method == NULL) return NULL;
    if (g_neko_method_layout.off_method_constMethod < 0) {
        fprintf(stderr, "[neko-bind] Method::_constMethod layout unavailable\\n");
        abort();
    }
    return *(void**)((char*)method + g_neko_method_layout.off_method_constMethod);
}

typedef struct {
    jboolean found;
    jboolean is_static;
    uint32_t offset;
    uint32_t access_flags;
    void *holder_klass;
} neko_field_resolution_t;

typedef struct {
    const uint8_t *data;
    int length;
    int position;
} neko_u5_reader_t;

#define NEKO_JVM_ACC_STATIC 0x0008u
#define NEKO_JVM_ACC_VOLATILE 0x0040u
#define NEKO_JVM_ACC_ABSTRACT 0x0400u
#define NEKO_FIELD_FLAG_INITIALIZED (1u << 0)
#define NEKO_FIELD_FLAG_INJECTED    (1u << 1)
#define NEKO_FIELD_FLAG_GENERIC     (1u << 2)
#define NEKO_FIELD_FLAG_CONTENDED   (1u << 4)
#define NEKO_FIELDINFO_LEGACY_SLOTS 6
#define NEKO_FIELDINFO_TAG_SIZE     2
#define NEKO_FIELDINFO_TAG_OFFSET   1u
#define NEKO_FIELDINFO_TAG_MASK     3u
""").append("""
static uint32_t neko_u5_next(neko_u5_reader_t *reader, const char *context) {
    uint32_t b0;
    uint32_t sum;
    int shift;
    if (reader == NULL || reader->data == NULL || reader->position < 0 || reader->position >= reader->length) {
        fprintf(stderr, "[neko-bind] truncated fieldinfo stream while reading %s\\n", context == NULL ? "<unknown>" : context);
        abort();
    }
    b0 = reader->data[reader->position];
    if (b0 < 1u) {
        fprintf(stderr, "[neko-bind] invalid unsigned5 zero byte while reading %s at %d\\n",
            context == NULL ? "<unknown>" : context, reader->position);
        abort();
    }
    sum = b0 - 1u;
    if (sum < 191u) {
        reader->position++;
        return sum;
    }
    shift = 6;
    for (int i = 1; i < 5; i++) {
        uint32_t bi;
        if (reader->position + i >= reader->length) {
            fprintf(stderr, "[neko-bind] truncated unsigned5 value while reading %s at %d\\n",
                context == NULL ? "<unknown>" : context, reader->position);
            abort();
        }
        bi = reader->data[reader->position + i];
        if (bi < 1u) {
            fprintf(stderr, "[neko-bind] invalid unsigned5 zero byte while reading %s at %d\\n",
                context == NULL ? "<unknown>" : context, reader->position + i);
            abort();
        }
        sum += (uint32_t)((bi - 1u) << shift);
        if (bi < 192u || i == 4) {
            reader->position += i + 1;
            return sum;
        }
        shift += 6;
    }
    fprintf(stderr, "[neko-bind] unsigned5 decode fell through while reading %s\\n", context == NULL ? "<unknown>" : context);
    abort();
}

static jboolean neko_match_field_symbols(void *constant_pool, uint32_t name_index, uint32_t sig_index, uint32_t field_flags, const char *name_utf8, const char *sig_utf8) {
    void *name_symbol;
    void *sig_symbol;
    if ((field_flags & NEKO_FIELD_FLAG_INJECTED) != 0) {
        return JNI_FALSE;
    }
    if (name_index > 0xffffu || sig_index > 0xffffu) {
        return JNI_FALSE;
    }
    name_symbol = neko_constantpool_symbol_at(constant_pool, (uint16_t)name_index);
    sig_symbol = neko_constantpool_symbol_at(constant_pool, (uint16_t)sig_index);
    return (neko_symbol_equals_utf8(name_symbol, name_utf8)
            && neko_symbol_equals_utf8(sig_symbol, sig_utf8))
        ? JNI_TRUE : JNI_FALSE;
}

static jboolean neko_resolve_declared_field_stream(void *instance_klass, const char *name_utf8, const char *sig_utf8, jboolean is_static, neko_field_resolution_t *out) {
    void *stream_array;
    void *constant_pool;
    int stream_length;
    uint32_t java_fields;
    uint32_t injected_fields;
    uint32_t total_fields;
    neko_u5_reader_t reader;
    if (instance_klass == NULL || out == NULL || g_neko_method_layout.off_instanceklass_fieldinfo_stream < 0) {
        return JNI_FALSE;
    }
    if (g_neko_method_layout.off_instanceklass_constants < 0
        || g_neko_method_layout.off_array_length < 0
        || g_neko_method_layout.off_array_u1_data < 0) {
        fprintf(stderr, "[neko-bind] InstanceKlass fieldinfo stream layout unavailable\\n");
        abort();
    }
    stream_array = *(void**)((char*)instance_klass + g_neko_method_layout.off_instanceklass_fieldinfo_stream);
    constant_pool = *(void**)((char*)instance_klass + g_neko_method_layout.off_instanceklass_constants);
    if (stream_array == NULL || constant_pool == NULL) {
        return JNI_FALSE;
    }
    stream_length = *(int*)((char*)stream_array + g_neko_method_layout.off_array_length);
    if (stream_length <= 0) {
        return JNI_FALSE;
    }
    reader.data = (const uint8_t*)stream_array + g_neko_method_layout.off_array_u1_data;
    reader.length = stream_length;
    reader.position = 0;
    java_fields = neko_u5_next(&reader, "java field count");
    injected_fields = neko_u5_next(&reader, "injected field count");
    total_fields = java_fields + injected_fields;
    if (total_fields > 65535u) {
        fprintf(stderr, "[neko-bind] unreasonable field count in fieldinfo stream: %u\\n", total_fields);
        abort();
    }
    for (uint32_t i = 0; i < total_fields; i++) {
        uint32_t name_index = neko_u5_next(&reader, "field name index");
        uint32_t sig_index = neko_u5_next(&reader, "field signature index");
        uint32_t offset = neko_u5_next(&reader, "field offset");
        uint32_t access_flags = neko_u5_next(&reader, "field access flags");
        uint32_t field_flags = neko_u5_next(&reader, "field flags");
        if ((field_flags & NEKO_FIELD_FLAG_INITIALIZED) != 0) (void)neko_u5_next(&reader, "field initializer index");
        if ((field_flags & NEKO_FIELD_FLAG_GENERIC) != 0) (void)neko_u5_next(&reader, "field generic signature index");
        if ((field_flags & NEKO_FIELD_FLAG_CONTENDED) != 0) (void)neko_u5_next(&reader, "field contention group");
        if (((access_flags & NEKO_JVM_ACC_STATIC) != 0) != (is_static == JNI_TRUE)) {
            continue;
        }
        if (neko_match_field_symbols(constant_pool, name_index, sig_index, field_flags, name_utf8, sig_utf8)) {
            out->found = JNI_TRUE;
            out->is_static = (access_flags & NEKO_JVM_ACC_STATIC) != 0 ? JNI_TRUE : JNI_FALSE;
            out->offset = offset;
            out->access_flags = access_flags;
            out->holder_klass = instance_klass;
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

static jboolean neko_resolve_declared_field_legacy(void *instance_klass, const char *name_utf8, const char *sig_utf8, jboolean is_static, neko_field_resolution_t *out) {
    void *fields_array;
    void *constant_pool;
    int shorts_length;
    uint16_t *fields_data;
    if (instance_klass == NULL || out == NULL || g_neko_method_layout.off_instanceklass_fields < 0) {
        return JNI_FALSE;
    }
    if (g_neko_method_layout.off_instanceklass_constants < 0
        || g_neko_method_layout.off_array_length < 0
        || g_neko_method_layout.off_array_u2_data < 0) {
        fprintf(stderr, "[neko-bind] legacy InstanceKlass field array layout unavailable\\n");
        abort();
    }
    fields_array = *(void**)((char*)instance_klass + g_neko_method_layout.off_instanceklass_fields);
    constant_pool = *(void**)((char*)instance_klass + g_neko_method_layout.off_instanceklass_constants);
    if (fields_array == NULL || constant_pool == NULL) {
        return JNI_FALSE;
    }
    shorts_length = *(int*)((char*)fields_array + g_neko_method_layout.off_array_length);
    fields_data = (uint16_t*)((char*)fields_array + g_neko_method_layout.off_array_u2_data);
    if (shorts_length <= 0 || shorts_length % NEKO_FIELDINFO_LEGACY_SLOTS != 0) {
        return JNI_FALSE;
    }
    for (int base = 0; base + (NEKO_FIELDINFO_LEGACY_SLOTS - 1) < shorts_length; base += NEKO_FIELDINFO_LEGACY_SLOTS) {
        uint32_t access_flags = fields_data[base + 0];
        uint32_t name_index = fields_data[base + 1];
        uint32_t sig_index = fields_data[base + 2];
        uint32_t packed = ((uint32_t)fields_data[base + 5] << 16) | fields_data[base + 4];
        uint32_t offset;
        if (((access_flags & NEKO_JVM_ACC_STATIC) != 0) != (is_static == JNI_TRUE)) {
            continue;
        }
        if ((packed & NEKO_FIELDINFO_TAG_MASK) != NEKO_FIELDINFO_TAG_OFFSET) {
            continue;
        }
        if (!neko_match_field_symbols(constant_pool, name_index, sig_index, 0, name_utf8, sig_utf8)) {
            continue;
        }
        offset = packed >> NEKO_FIELDINFO_TAG_SIZE;
        out->found = JNI_TRUE;
        out->is_static = (access_flags & NEKO_JVM_ACC_STATIC) != 0 ? JNI_TRUE : JNI_FALSE;
        out->offset = offset;
        out->access_flags = access_flags;
        out->holder_klass = instance_klass;
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

static jboolean neko_resolve_declared_field(void *instance_klass, const char *name_utf8, const char *sig_utf8, jboolean is_static, neko_field_resolution_t *out) {
    if (neko_resolve_declared_field_stream(instance_klass, name_utf8, sig_utf8, is_static, out)) {
        return JNI_TRUE;
    }
    return neko_resolve_declared_field_legacy(instance_klass, name_utf8, sig_utf8, is_static, out);
}

static jboolean neko_resolve_interface_field(void *instance_klass, const char *name_utf8, const char *sig_utf8, jboolean is_static, neko_field_resolution_t *out) {
    void *interfaces_array;
    int interface_count;
    void **interface_data;
    if (instance_klass == NULL) return JNI_FALSE;
    if (g_neko_method_layout.off_instanceklass_transitive_interfaces < 0) {
        fprintf(stderr, "[neko-bind] InstanceKlass::_transitive_interfaces layout unavailable for field resolution\\n");
        abort();
    }
    interfaces_array = *(void**)((char*)instance_klass + g_neko_method_layout.off_instanceklass_transitive_interfaces);
    if (interfaces_array == NULL) return JNI_FALSE;
    interface_count = *(int*)((char*)interfaces_array + g_neko_method_layout.off_array_length);
    interface_data = (void**)((char*)interfaces_array + g_neko_method_layout.off_array_data);
    for (int i = 0; i < interface_count; i++) {
        if (neko_resolve_declared_field(interface_data[i], name_utf8, sig_utf8, is_static, out)) {
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

static neko_field_resolution_t neko_resolve_field(void *instance_klass, const char *name_utf8, const char *sig_utf8, jboolean is_static) {
    neko_field_resolution_t out;
    void *klass;
    memset(&out, 0, sizeof(out));
    if (instance_klass == NULL || name_utf8 == NULL || sig_utf8 == NULL) {
        fprintf(stderr, "[neko-bind] field resolution requested with null input\\n");
        abort();
    }
    if (g_neko_method_layout.off_klass_super < 0) {
        fprintf(stderr, "[neko-bind] Klass::_super layout unavailable for field resolution\\n");
        abort();
    }
    klass = instance_klass;
    for (int depth = 0; klass != NULL && depth < 256; depth++) {
        if (neko_resolve_declared_field(klass, name_utf8, sig_utf8, is_static, &out)) {
            return out;
        }
        klass = *(void**)((char*)klass + g_neko_method_layout.off_klass_super);
    }
    klass = instance_klass;
    for (int depth = 0; klass != NULL && depth < 256; depth++) {
        if (neko_resolve_interface_field(klass, name_utf8, sig_utf8, is_static, &out)) {
            return out;
        }
        klass = *(void**)((char*)klass + g_neko_method_layout.off_klass_super);
    }
    fprintf(stderr, "[neko-bind] native field resolution failed: %s:%s static=%d\\n",
        name_utf8, sig_utf8, (int)is_static);
    abort();
}

typedef struct {
    jboolean latin1;
    size_t utf16_units;
    size_t latin1_bytes;
} neko_utf8_shape_t;

static uint32_t neko_utf8_next_codepoint(const uint8_t **cursor, const uint8_t *end) {
    const uint8_t *p = *cursor;
    uint32_t cp;
    if (p >= end) return 0;
    if (p[0] < 0x80u) {
        *cursor = p + 1;
        return p[0];
    }
    if ((p[0] & 0xe0u) == 0xc0u && p + 1 < end) {
        cp = ((uint32_t)(p[0] & 0x1fu) << 6) | (uint32_t)(p[1] & 0x3fu);
        if ((p[1] & 0xc0u) != 0x80u || cp < 0x80u) goto invalid;
        *cursor = p + 2;
        return cp;
    }
    if ((p[0] & 0xf0u) == 0xe0u && p + 2 < end) {
        cp = ((uint32_t)(p[0] & 0x0fu) << 12) | ((uint32_t)(p[1] & 0x3fu) << 6) | (uint32_t)(p[2] & 0x3fu);
        if ((p[1] & 0xc0u) != 0x80u || (p[2] & 0xc0u) != 0x80u || cp < 0x800u || (cp >= 0xd800u && cp <= 0xdfffu)) goto invalid;
        *cursor = p + 3;
        return cp;
    }
    if ((p[0] & 0xf8u) == 0xf0u && p + 3 < end) {
        cp = ((uint32_t)(p[0] & 0x07u) << 18) | ((uint32_t)(p[1] & 0x3fu) << 12)
            | ((uint32_t)(p[2] & 0x3fu) << 6) | (uint32_t)(p[3] & 0x3fu);
        if ((p[1] & 0xc0u) != 0x80u || (p[2] & 0xc0u) != 0x80u || (p[3] & 0xc0u) != 0x80u
            || cp < 0x10000u || cp > 0x10ffffu) goto invalid;
        *cursor = p + 4;
        return cp;
    }
invalid:
    fprintf(stderr, "[neko-bind] invalid UTF-8 string literal while interning\\n");
    abort();
}

static neko_utf8_shape_t neko_utf8_shape(const uint8_t *utf, size_t len) {
    neko_utf8_shape_t shape;
    const uint8_t *cursor = utf;
    const uint8_t *end = utf + len;
    memset(&shape, 0, sizeof(shape));
    shape.latin1 = JNI_TRUE;
    while (cursor < end) {
        uint32_t cp = neko_utf8_next_codepoint(&cursor, end);
        if (cp <= 0xffu) {
            shape.latin1_bytes++;
            shape.utf16_units++;
        } else if (cp <= 0xffffu) {
            shape.latin1 = JNI_FALSE;
            shape.utf16_units++;
        } else {
            shape.latin1 = JNI_FALSE;
            shape.utf16_units += 2u;
        }
    }
    return shape;
}

static void neko_put_utf16_unit_le(uint8_t *dst, size_t index, uint16_t value) {
    dst[index * 2u] = (uint8_t)(value & 0xffu);
    dst[index * 2u + 1u] = (uint8_t)(value >> 8);
}

static void neko_fill_string_bytes(uint8_t *dst, const uint8_t *utf, size_t len, jboolean latin1) {
    const uint8_t *cursor = utf;
    const uint8_t *end = utf + len;
    size_t out = 0;
    while (cursor < end) {
        uint32_t cp = neko_utf8_next_codepoint(&cursor, end);
        if (latin1) {
            dst[out++] = (uint8_t)cp;
        } else if (cp <= 0xffffu) {
            neko_put_utf16_unit_le(dst, out++, (uint16_t)cp);
        } else {
            cp -= 0x10000u;
            neko_put_utf16_unit_le(dst, out++, (uint16_t)(0xd800u + (cp >> 10)));
            neko_put_utf16_unit_le(dst, out++, (uint16_t)(0xdc00u + (cp & 0x3ffu)));
        }
    }
}

static char *neko_alloc_jbyte_array_oop_slow(JNIEnv *env, jint len, jarray *local_ref_out) {
    void *thread;
    void *array_raw;
    jarray returned_ref;
    neko_handle_save_t handle_window;
    jclass byte_class;
    jarray array;
    char *array_oop;
    if (local_ref_out != NULL) *local_ref_out = NULL;
    if (env == NULL || len < 0) {
        fprintf(stderr, "[neko-bind] invalid slow byte[] allocation request len=%d\\n", (int)len);
        abort();
    }
    if (g_neko_method_layout.sym_jvm_find_primitive_class == NULL
        || g_neko_method_layout.sym_jvm_new_array == NULL) {
        fprintf(stderr, "[neko-bind] JVM byte[] allocation symbols unavailable\\n");
        abort();
    }
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] slow byte[] allocation has no JavaThread len=%d\\n", (int)len);
        abort();
    }
    neko_handle_window_begin(thread, &handle_window);
    byte_class = ((neko_jvm_find_primitive_class_t)g_neko_method_layout.sym_jvm_find_primitive_class)(env, "byte");
    if (byte_class == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] JVM_FindPrimitiveClass(byte) failed\\n");
        abort();
    }
    array = ((neko_jvm_new_array_t)g_neko_method_layout.sym_jvm_new_array)(env, byte_class, len);
    if (array == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] JVM_NewArray(byte) failed len=%d\\n", (int)len);
        abort();
    }
    array_raw = neko_prepare_return_oop(thread, array, "slow_byte_array");
    array_oop = (char*)array_raw;
    if (array_oop == NULL) {
        fprintf(stderr, "[neko-bind] JVM_NewArray(byte) returned an unresolved handle len=%d\\n", (int)len);
        abort();
    }
    neko_handle_window_end(&handle_window);
    if (local_ref_out != NULL) {
        returned_ref = (jarray)neko_handle_push(thread, array_raw);
        if (returned_ref == NULL) {
            fprintf(stderr, "[neko-bind] slow byte[] return handle push failed len=%d\\n", (int)len);
            abort();
        }
        *local_ref_out = returned_ref;
    }
    return array_oop;
}

static void neko_refill_tlab_with_slow_byte_array(JNIEnv *env, jint min_payload_len) {
    if (min_payload_len < 0) min_payload_len = 0;
    (void)neko_alloc_jbyte_array_oop_slow(env, min_payload_len, NULL);
}

static const char *neko_primitive_name_for_kind(int kind) {
    switch (kind) {
        case NEKO_PRIM_Z: return "boolean";
        case NEKO_PRIM_C: return "char";
        case NEKO_PRIM_F: return "float";
        case NEKO_PRIM_D: return "double";
        case NEKO_PRIM_B: return "byte";
        case NEKO_PRIM_S: return "short";
        case NEKO_PRIM_I: return "int";
        case NEKO_PRIM_J: return "long";
        default: return NULL;
    }
}

static jarray neko_alloc_primitive_array_slow(JNIEnv *env, jint len, int kind) {
    void *thread;
    void *array_oop;
    jarray result;
    neko_handle_save_t handle_window;
    const char *primitive_name = neko_primitive_name_for_kind(kind);
    jclass primitive_class;
    jarray array;
    if (env == NULL || len < 0 || primitive_name == NULL) {
        fprintf(stderr, "[neko-bind] invalid slow primitive array allocation request len=%d kind=%d\\n", (int)len, kind);
        abort();
    }
    if (g_neko_method_layout.sym_jvm_find_primitive_class == NULL
        || g_neko_method_layout.sym_jvm_new_array == NULL) {
        fprintf(stderr, "[neko-bind] JVM primitive array allocation symbols unavailable kind=%d\\n", kind);
        abort();
    }
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] slow primitive array allocation has no JavaThread len=%d kind=%d\\n", (int)len, kind);
        abort();
    }
    neko_handle_window_begin(thread, &handle_window);
    primitive_class = ((neko_jvm_find_primitive_class_t)g_neko_method_layout.sym_jvm_find_primitive_class)(env, primitive_name);
    if (primitive_class == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] JVM_FindPrimitiveClass(%s) failed\\n", primitive_name);
        abort();
    }
    array = ((neko_jvm_new_array_t)g_neko_method_layout.sym_jvm_new_array)(env, primitive_class, len);
    if (array == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] JVM_NewArray(%s) failed len=%d\\n", primitive_name, (int)len);
        abort();
    }
    array_oop = neko_prepare_return_oop(thread, array, "slow_primitive_array");
    if (array_oop == NULL) {
        fprintf(stderr, "[neko-bind] JVM_NewArray(%s) returned an unresolved handle len=%d\\n", primitive_name, (int)len);
        abort();
    }
    neko_handle_window_end(&handle_window);
    result = (jarray)neko_handle_push(thread, array_oop);
    if (result == NULL) {
        fprintf(stderr, "[neko-bind] slow primitive array return handle push failed len=%d kind=%d\\n", (int)len, kind);
        abort();
    }
    return result;
}
""").append("""
static void *neko_intern_string(void *thread, JNIEnv *env, const uint8_t *modutf, size_t len) {
    void *string_klass;
    neko_field_resolution_t value_field;
    neko_field_resolution_t coder_field;
    neko_utf8_shape_t shape;
    char *array_oop;
    char *string_oop;
    jarray local_array;
    jstring local_string;
    jstring interned;
    void *interned_oop;
    neko_handle_save_t handle_window;
    size_t payload_bytes;
    size_t array_bytes;
    size_t string_bytes;
    size_t ref_size;
    if (env == NULL) {
        fprintf(stderr, "[neko-bind] null JNIEnv for string intern\\n");
        abort();
    }
    if (modutf == NULL) {
        fprintf(stderr, "[neko-bind] null string literal requested\\n");
        abort();
    }
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] JavaThread missing for native string intern\\n");
        abort();
    }
    if (!g_hotspot.initialized
        || (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) == 0
        || g_hotspot.use_compact_object_headers
        || g_hotspot.klass_offset_bytes <= 0
        || !g_neko_tlab_alloc_ready
        || g_hotspot.primitive_array_klass_bits[NEKO_PRIM_B] == 0) {
        return neko_intern_string_without_raw_heap(thread, env, (const char*)modutf, len);
    }
    if (g_neko_method_layout.sym_jvm_intern_string == NULL) {
        fprintf(stderr, "[neko-bind] JVM_InternString unavailable\\n");
        abort();
    }
    neko_ensure_string_alloc_bits(env);
    string_klass = neko_resolve_class_with_env(env, "java/lang/String", NULL);
    value_field = neko_resolve_field(string_klass, "value", "[B", JNI_FALSE);
    coder_field = neko_resolve_field(string_klass, "coder", "B", JNI_FALSE);
    if (!value_field.found || !coder_field.found || value_field.offset == 0 || coder_field.offset == 0) {
        fprintf(stderr, "[neko-bind] java/lang/String value/coder metadata unavailable\\n");
        abort();
    }
    shape = neko_utf8_shape(modutf, len);
    payload_bytes = shape.latin1 ? shape.latin1_bytes : shape.utf16_units * 2u;
    if (payload_bytes > (size_t)INT32_MAX) {
        fprintf(stderr, "[neko-bind] string literal too large to intern\\n");
        abort();
    }
    neko_handle_window_begin(thread, &handle_window);
    array_bytes = (size_t)g_hotspot.primitive_array_base_offsets[NEKO_PRIM_B] + payload_bytes;
    local_array = NULL;
    array_oop = (char*)neko_fast_tlab_alloc(thread, array_bytes);
    if (array_oop == NULL) {
        array_oop = neko_alloc_jbyte_array_oop_slow(env, (jint)payload_bytes, &local_array);
    } else {
        neko_init_oop_header(array_oop, g_neko_byte_array_klass_bits);
        *(jint*)(array_oop + g_hotspot.primitive_array_base_offsets[NEKO_PRIM_B] - 4) = (jint)payload_bytes;
    }
    neko_fill_string_bytes((uint8_t*)array_oop + g_hotspot.primitive_array_base_offsets[NEKO_PRIM_B], modutf, len, shape.latin1);
    ref_size = g_hotspot.compressed_oops_enabled ? 4u : sizeof(void*);
    string_bytes = g_neko_string_instance_bytes;
    if (string_bytes == 0
        || (size_t)value_field.offset + ref_size > string_bytes
        || (size_t)coder_field.offset + 1u > string_bytes) {
        fprintf(stderr, "[neko-bind] java/lang/String instance size too small bytes=%zu value=%u coder=%u\\n",
            string_bytes, value_field.offset, coder_field.offset);
        abort();
    }
    string_oop = (char*)neko_fast_tlab_alloc(thread, string_bytes);
    if (string_oop == NULL) {
        neko_refill_tlab_with_slow_byte_array(env, string_bytes > (size_t)INT32_MAX ? INT32_MAX : (jint)string_bytes);
        string_oop = (char*)neko_fast_tlab_alloc(thread, string_bytes);
    }
    if (string_oop == NULL) {
        fprintf(stderr, "[neko-bind] TLAB String allocation failed for string literal\\n");
        abort();
    }
    neko_init_oop_header(string_oop, g_neko_string_klass_bits);
    neko_store_oop_raw(string_oop, (jlong)value_field.offset, array_oop);
    *(jbyte*)(string_oop + coder_field.offset) = shape.latin1 ? 0 : 1;
    local_string = (jstring)neko_direct_oop_to_handle_origin(thread, string_oop, NEKO_HANDLE_ORIGIN_BOUND_STRING);
    interned = ((neko_jvm_intern_string_t)g_neko_method_layout.sym_jvm_intern_string)(env, local_string);
    if (interned == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] JVM_InternString failed for string literal\\n");
        abort();
    }
    interned_oop = neko_prepare_return_oop(thread, interned, "intern_string");
    neko_handle_window_end(&handle_window);
    return interned_oop;
}

static void *neko_resolve_declared_method(void *instance_klass, const char *name_utf8, const char *sig_utf8) {
    void *methods_array;
    int method_count;
    void **method_data;
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
    if (methods_array == NULL) {
        return NULL;
    }
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
        if (const_method == NULL) continue;
        constant_pool = *(void**)((char*)const_method + g_neko_method_layout.off_constmethod_constants);
        name_index = *(uint16_t*)((char*)const_method + g_neko_method_layout.off_constmethod_name_index);
        sig_index = *(uint16_t*)((char*)const_method + g_neko_method_layout.off_constmethod_signature_index);
        name_symbol = neko_constantpool_symbol_at(constant_pool, name_index);
        sig_symbol = neko_constantpool_symbol_at(constant_pool, sig_index);
        if (neko_symbol_equals_utf8(name_symbol, name_utf8)
            && neko_symbol_equals_utf8(sig_symbol, sig_utf8)) {
            return method;
        }
    }
    return NULL;
}

static uint32_t neko_method_access_flags(void *method);
static jboolean neko_method_is_instance_default(void *method);
static void *neko_resolve_declared_covariant_ref_method(void *instance_klass, const char *name_utf8, const char *sig_utf8);
static void *neko_resolve_method_declaration_with_kind(void *instance_klass, const char *name_utf8, const char *sig_utf8, jboolean is_static);
static void *neko_resolve_interface_default_method(void *instance_klass, const char *name_utf8, const char *sig_utf8);

static void *neko_resolve_method(void *instance_klass, const char *name_utf8, const char *sig_utf8) {
    void *klass;
    if (instance_klass == NULL || name_utf8 == NULL || sig_utf8 == NULL) {
        fprintf(stderr, "[neko-bind] method resolution requested with null input\\n");
        abort();
    }
    if (g_neko_method_layout.off_klass_super < 0) {
        fprintf(stderr, "[neko-bind] Klass::_super layout unavailable\\n");
        abort();
    }
    klass = instance_klass;
    for (int depth = 0; klass != NULL && depth < 256; depth++) {
        void *method = neko_resolve_declared_method(klass, name_utf8, sig_utf8);
        if (method != NULL) return method;
        method = neko_resolve_declared_covariant_ref_method(klass, name_utf8, sig_utf8);
        if (method != NULL) return method;
        klass = *(void**)((char*)klass + g_neko_method_layout.off_klass_super);
    }
    klass = instance_klass;
    for (int depth = 0; klass != NULL && depth < 256; depth++) {
        void *method = neko_resolve_interface_default_method(klass, name_utf8, sig_utf8);
        if (method != NULL) return method;
        klass = *(void**)((char*)klass + g_neko_method_layout.off_klass_super);
    }
    fprintf(stderr, "[neko-bind] native method resolution failed: %s%s\\n", name_utf8, sig_utf8);
    abort();
}

static jmethodID neko_make_native_method_id(void *method, const char *owner, const char *name, const char *desc) {
    void **cell;
    if (method == NULL) {
        fprintf(stderr, "[neko-bind] null Method* while creating native jmethodID: %s.%s%s\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    cell = (void**)malloc(sizeof(void*));
    if (cell == NULL) {
        fprintf(stderr, "[neko-bind] native jmethodID cell allocation failed: %s.%s%s\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    *cell = method;
    return (jmethodID)cell;
}

typedef struct {
    void *holder;
    void *next;
    int offset;
} neko_native_static_jniid;

static jfieldID neko_make_native_field_id(neko_field_resolution_t field, const char *owner, const char *name, const char *desc) {
    uintptr_t encoded;
    neko_native_static_jniid *static_id;
    if (!field.found || field.offset == 0) {
        fprintf(stderr, "[neko-bind] invalid native field metadata while creating jfieldID: %s.%s:%s\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    if (!field.is_static) {
        encoded = (((uintptr_t)field.offset) << 2u) | 0x2u;
        return (jfieldID)encoded;
    }
    if (field.holder_klass == NULL) {
        fprintf(stderr, "[neko-bind] static field holder missing while creating jfieldID: %s.%s:%s\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    static_id = (neko_native_static_jniid*)malloc(sizeof(*static_id));
    if (static_id == NULL) {
        fprintf(stderr, "[neko-bind] static jfieldID allocation failed: %s.%s:%s\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    static_id->holder = field.holder_klass;
    static_id->next = NULL;
    static_id->offset = (int)field.offset;
    return (jfieldID)static_id;
}

static void neko_bind_class_slot(JNIEnv *env, jclass *slot, const char *owner);
static void neko_bind_class_slot_from(JNIEnv *env, jclass *slot, const char *owner, jclass from_class);
static void neko_bind_primitive_class_slot(JNIEnv *env, jclass *slot, const char *desc);
static void neko_bind_string_slot(void *thread, JNIEnv *env, jstring *slot, const char *utf);

static jclass neko_ensure_class_slot(jclass *slot, JNIEnv *env, const char *name) {
    if (slot == NULL) {
        fprintf(stderr, "[neko-bind] class slot pointer missing for %s\\n", name == NULL ? "<null>" : name);
        abort();
    }
    if (*slot == NULL) {
        neko_bind_class_slot(env, slot, name);
    }
    return *slot;
}

static jstring neko_ensure_string_slot(jstring *slot, JNIEnv *env, const char *utf) {
    void *thread = neko_jni_env_to_thread(env);
    if (slot == NULL) {
        fprintf(stderr, "[neko-bind] string slot pointer missing for %s\\n", utf == NULL ? "<null>" : utf);
        abort();
    }
    if (*slot == NULL) {
        neko_bind_string_slot(thread, env, slot, utf);
    }
    return *slot;
}

static jmethodID neko_ensure_method_id_slot(jmethodID *slot, JNIEnv *env, jclass cls, const char *name, const char *desc, jboolean isStatic) {
    (void)isStatic;
    if (slot == NULL) {
        fprintf(stderr, "[neko-bind] method slot pointer missing: %s%s\\n",
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    if (*slot == NULL) {
        void *klass;
        void *method;
        if (env == NULL || cls == NULL || name == NULL || desc == NULL) {
            fprintf(stderr, "[neko-bind] method ensure missing input: %s%s\\n",
                name == NULL ? "<null>" : name,
                desc == NULL ? "<null>" : desc);
            abort();
        }
        klass = neko_class_mirror_to_klass(cls);
        method = neko_resolve_method(klass, name, desc);
        *slot = neko_make_native_method_id(method, "<ensure>", name, desc);
    }
    return *slot;
}

static jfieldID neko_ensure_field_id_slot(jfieldID *slot, JNIEnv *env, jclass cls, const char *name, const char *desc, jboolean isStatic) {
    if (slot == NULL) {
        fprintf(stderr, "[neko-bind] field slot pointer missing: %s:%s\\n",
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    if (*slot == NULL) {
        void *klass;
        neko_field_resolution_t field;
        if (env == NULL || cls == NULL || name == NULL || desc == NULL) {
            fprintf(stderr, "[neko-bind] field ensure missing input: %s:%s\\n",
                name == NULL ? "<null>" : name,
                desc == NULL ? "<null>" : desc);
            abort();
        }
        klass = neko_class_mirror_to_klass(cls);
        field = neko_resolve_field(klass, name, desc, isStatic);
        *slot = neko_make_native_field_id(field, "<ensure>", name, desc);
    }
    return *slot;
}

static void neko_bind_owner_class_slot(JNIEnv *env, jclass *slot, jclass self_class, const char *owner) {
    jobject globalRef;
    void *self_klass;
    void *resolved_klass;
    if (env == NULL || slot == NULL || *slot != NULL) return;
    if (self_class == NULL) {
        fprintf(stderr, "[neko-bind] owner class missing: %s\\n", owner == NULL ? "<null>" : owner);
        abort();
    }
    self_klass = neko_class_mirror_to_klass(self_class);
    resolved_klass = neko_resolve_class_with_env(env, owner, self_class);
    if (self_klass == NULL || resolved_klass == NULL || self_klass != resolved_klass) {
        fprintf(stderr, "[neko-bind] owner class native resolver mismatch: %s self=%p resolved=%p\\n",
            owner == NULL ? "<null>" : owner, self_klass, resolved_klass);
        abort();
    }
    globalRef = g_neko_jni_new_global_ref_fn(env, self_class);
    if (globalRef == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] owner class global-ref failed: %s\\n", owner == NULL ? "<null>" : owner);
        abort();
    }
    *slot = (jclass)globalRef;
    neko_remember_class_klass(*slot, resolved_klass);
}

static void neko_bind_class_slot(JNIEnv *env, jclass *slot, const char *owner) {
    neko_bind_class_slot_from(env, slot, owner, NULL);
}

static void neko_bind_class_slot_from(JNIEnv *env, jclass *slot, const char *owner, jclass from_class) {
    void *klass;
    jobject localClass;
    jobject globalRef;
    void *expected;
    if (env == NULL || slot == NULL || *slot != NULL || owner == NULL) return;
    localClass = neko_resolve_class_mirror_with_env(env, owner, from_class, &klass);
    globalRef = g_neko_jni_new_global_ref_fn(env, localClass);
    if (globalRef == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] class global-ref failed after native resolution: %s\\n", owner);
        abort();
    }
    expected = NULL;
    if (!__atomic_compare_exchange_n((void**)slot, &expected, (void*)globalRef, JNI_FALSE, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
        return;
    }
    neko_remember_class_klass((jclass)globalRef, klass);
    if (strstr(owner, "$NekoLambda$") != NULL) {
        if (!neko_manifest_patch_defined_class(env, (jclass)globalRef)) {
            fprintf(stderr, "[neko-bind] generated lambda manifest patch failed: %s\\n", owner);
            abort();
        }
    }
}

static const char *neko_primitive_descriptor_name(const char *desc) {
    if (desc == NULL || desc[0] == '\\0' || desc[1] != '\\0') return NULL;
    switch (desc[0]) {
        case 'Z': return "boolean";
        case 'B': return "byte";
        case 'C': return "char";
        case 'S': return "short";
        case 'I': return "int";
        case 'J': return "long";
        case 'F': return "float";
        case 'D': return "double";
        case 'V': return "void";
        default: return NULL;
    }
}

static void neko_bind_primitive_class_slot(JNIEnv *env, jclass *slot, const char *desc) {
    jclass localClass;
    jobject globalRef;
    if (env == NULL || slot == NULL || *slot != NULL) return;
    if (desc == NULL || desc[0] == '\\0' || desc[1] != '\\0'
        || neko_primitive_mirror_kind_from_descriptor_char(desc[0]) < 0) {
        fprintf(stderr, "[neko-bind] unsupported primitive class descriptor: %s\\n", desc == NULL ? "<null>" : desc);
        abort();
    }
    localClass = neko_primitive_mirror_for_char(env, desc[0]);
    if (localClass == NULL) {
        fprintf(stderr, "[neko-bind] primitive class resolution failed for descriptor %s\\n", desc);
        abort();
    }
    globalRef = g_neko_jni_new_global_ref_fn(env, localClass);
    if (globalRef == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] primitive class global-ref failed for descriptor %s\\n", desc);
        abort();
    }
    *slot = (jclass)globalRef;
}

static void neko_bind_method_slot(JNIEnv *env, jmethodID *slot, jclass cls, const char *owner, const char *name, const char *desc, jboolean isStatic) {
    void *klass;
    void *method;
    if (env == NULL || slot == NULL || *slot != NULL || cls == NULL || owner == NULL || name == NULL || desc == NULL) return;
    klass = neko_class_mirror_to_klass(cls);
    method = neko_resolve_method_declaration_with_kind(klass, name, desc, isStatic);
    *slot = neko_make_native_method_id(method, owner, name, desc);
}

/* Resolve the underlying HotSpot Method* and harvest cached entry pointers
 * from a JNI-resolved jmethodID. The Method::_from_compiled_entry and
 * _from_interpreted_entry fields contain the stable PC that JIT-compiled
 * callers and the interpreter (respectively) would jump to. We snapshot
 * them once at bind time so the hot dispatch path can issue a direct call
 * without any further JNI traffic.
 *
 * Caller must have already populated *midSlot via neko_bind_method_slot.
 * Holder slot caches the Method::method_holder() (an InstanceKlass*) so
 * callers can keep the holder reachable; on JDK 21+ Methods are kept alive
 * by their holder Klass so this is the right anchor for stability.
 *
 * No JNI on the resolution path here either (only memory reads off the
 * Method* whose layout offsets came from VMStructs at OnLoad time). */
typedef jint (*neko_jvm_get_class_methods_count_t)(JNIEnv*, jclass);
typedef jobjectArray (*neko_jvm_get_class_declared_members_t)(JNIEnv*, jclass, jboolean);

static void neko_link_class_methods(JNIEnv *env, jclass cls, const char *owner, const char *name, const char *desc) {
    void *thread;
    neko_handle_save_t handle_window;
    jobjectArray members = NULL;
    if (env == NULL || cls == NULL) return;
    if (g_neko_method_layout.sym_jvm_get_class_methods_count != NULL) {
        (void)((neko_jvm_get_class_methods_count_t)g_neko_method_layout.sym_jvm_get_class_methods_count)(env, cls);
    }
    thread = neko_jni_env_to_thread(env);
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] method materialization has no JavaThread: %s.%s%s\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    neko_handle_window_begin(thread, &handle_window);
    if (name != NULL && strcmp(name, "<init>") == 0) {
        if (g_neko_method_layout.sym_jvm_get_class_declared_constructors == NULL) {
            fprintf(stderr, "[neko-bind] constructor materialization symbol unavailable: %s.%s%s\\n",
                owner == NULL ? "<null>" : owner,
                name,
                desc == NULL ? "<null>" : desc);
            abort();
        }
        members = ((neko_jvm_get_class_declared_members_t)g_neko_method_layout.sym_jvm_get_class_declared_constructors)(env, cls, JNI_FALSE);
    } else {
        if (g_neko_method_layout.sym_jvm_get_class_declared_methods == NULL) {
            fprintf(stderr, "[neko-bind] method materialization symbol unavailable: %s.%s%s\\n",
                owner == NULL ? "<null>" : owner,
                name == NULL ? "<null>" : name,
                desc == NULL ? "<null>" : desc);
            abort();
        }
        members = ((neko_jvm_get_class_declared_members_t)g_neko_method_layout.sym_jvm_get_class_declared_methods)(env, cls, JNI_FALSE);
    }
    if (members == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] method materialization failed: %s.%s%s\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    neko_handle_window_end(&handle_window);
}

static void neko_bind_method_entry_slots(JNIEnv *env, jmethodID midSlot, jclass cls, const char *owner, const char *name, const char *desc, void **methodPtr, void **compiledEntry, void **interpretedEntry, void **holder) {
    void *klass;
    void *scanned;
    if (midSlot == NULL || cls == NULL || name == NULL || desc == NULL) {
        fprintf(stderr, "[neko-bind] method entry bind missing input: %s.%s%s\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
        abort();
    }
    if (!g_neko_method_layout.initialized || !g_neko_method_layout.usable) {
        fprintf(stderr, "[neko-bind] method layout not usable while binding: %s.%s%s\\n",
            owner == NULL ? "<null>" : owner, name, desc);
        abort();
    }
    void *m = neko_jmethodid_to_method_star(midSlot);
    if (m == NULL) {
        fprintf(stderr, "[neko-bind] jmethodID did not decode to Method*: %s.%s%s\\n",
            owner == NULL ? "<null>" : owner, name, desc);
        abort();
    }
    klass = neko_class_mirror_to_klass(cls);
    scanned = neko_resolve_method_declaration_with_kind(
        klass,
        name,
        desc,
        (neko_method_access_flags(m) & NEKO_JVM_ACC_STATIC) != 0u ? JNI_TRUE : JNI_FALSE);
    if (scanned != m) {
        fprintf(stderr, "[neko-bind] native method resolver mismatch: %s.%s%s jmethodID=%p scanned=%p\\n",
            owner == NULL ? "<null>" : owner, name, desc, m, scanned);
        abort();
    }
    if (methodPtr != NULL && *methodPtr == NULL) {
        *methodPtr = m;
    }
    if (compiledEntry != NULL && *compiledEntry == NULL
        && g_neko_method_layout.off_method_from_compiled_entry > 0) {
        *compiledEntry = *(void**)((char*)m + g_neko_method_layout.off_method_from_compiled_entry);
    }
    if (interpretedEntry != NULL && *interpretedEntry == NULL
        && g_neko_method_layout.off_method_from_interpreted_entry > 0) {
        *interpretedEntry = *(void**)((char*)m + g_neko_method_layout.off_method_from_interpreted_entry);
    }
    if (interpretedEntry != NULL && *interpretedEntry == NULL) {
        neko_link_class_methods(env, cls, owner, name, desc);
        if (compiledEntry != NULL && *compiledEntry == NULL
            && g_neko_method_layout.off_method_from_compiled_entry > 0) {
            *compiledEntry = *(void**)((char*)m + g_neko_method_layout.off_method_from_compiled_entry);
        }
        if (g_neko_method_layout.off_method_from_interpreted_entry > 0) {
            *interpretedEntry = *(void**)((char*)m + g_neko_method_layout.off_method_from_interpreted_entry);
        }
    }
    if (holder != NULL && *holder == NULL) {
        *holder = klass;
    }
}

static void *neko_bound_method_i_entry(void *methodPtr, void **entrySlot, const char *owner, const char *name, const char *desc) {
    void *entry;
    if (methodPtr == NULL || entrySlot == NULL) {
        fprintf(stderr, "[neko-bind] method i-entry missing input: %s.%s%s method=%p slot=%p\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc,
            methodPtr, (void*)entrySlot);
        abort();
    }
    entry = *entrySlot;
    if (entry == NULL && g_neko_method_layout.off_method_from_interpreted_entry > 0) {
        entry = *(void**)((char*)methodPtr + g_neko_method_layout.off_method_from_interpreted_entry);
        if (entry != NULL) {
            *entrySlot = entry;
        }
    }
    if (entry == NULL && g_neko_method_layout.off_method_i2i_entry > 0) {
        entry = *(void**)((char*)methodPtr + g_neko_method_layout.off_method_i2i_entry);
        if (entry != NULL) {
            *entrySlot = entry;
        }
    }
    if (entry == NULL) {
        fprintf(stderr, "[neko-bind] method i-entry unavailable: %s.%s%s method=%p\\n",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc,
            methodPtr);
        abort();
    }
    return entry;
}

static void neko_bind_field_slot(JNIEnv *env, jfieldID *slot, jclass cls, const char *owner, const char *name, const char *desc, jboolean isStatic) {
    void *klass;
    neko_field_resolution_t native_field;
    if (env == NULL || slot == NULL || *slot != NULL || cls == NULL || owner == NULL || name == NULL || desc == NULL) return;
    klass = neko_class_mirror_to_klass(cls);
    native_field = neko_resolve_field(klass, name, desc, isStatic);
    if (!native_field.found || native_field.offset == 0) {
        fprintf(stderr, "[neko-bind] native field resolver returned invalid metadata: %s.%s:%s static=%d offset=%u\\n",
            owner, name, desc, (int)isStatic, native_field.offset);
        abort();
    }
    *slot = neko_make_native_field_id(native_field, owner, name, desc);
}

static void neko_bind_string_slot(void *thread, JNIEnv *env, jstring *slot, const char *utf) {
    void *string_oop;
    jstring localString;
    jobject globalRef;
    jboolean restoreJavaState = JNI_FALSE;
    if (env == NULL || slot == NULL || *slot != NULL || utf == NULL) return;
    if (thread == NULL) {
        fprintf(stderr, "[neko-bind] JavaThread missing while binding string: %s\\n", utf);
        abort();
    }
    if (g_neko_off_thread_state > 0
        && g_neko_thread_state_in_java != 0
        && *(int32_t*)((char*)thread + g_neko_off_thread_state) == g_neko_thread_state_in_java) {
        neko_transition_java_to_native(thread);
        restoreJavaState = JNI_TRUE;
    }
    string_oop = neko_intern_string(thread, env, (const uint8_t*)utf, strlen(utf));
    localString = (jstring)neko_direct_oop_to_handle_origin(thread, string_oop, NEKO_HANDLE_ORIGIN_BOUND_STRING);
    globalRef = g_neko_jni_new_global_ref_fn(env, localString);
    if (globalRef == NULL || neko_exception_check(env)) {
        if (neko_exception_check(env)) neko_exception_clear_direct(env);
        fprintf(stderr, "[neko-bind] global-ref failed for native string literal: %s\\n", utf);
        abort();
    }
    if (restoreJavaState) {
        neko_transition_native_to_java(thread);
    }
    *slot = (jstring)globalRef;
}

static uintptr_t neko_array_klass_bits_for_descriptor(JNIEnv *env, const char *arrayDesc, jclass fromClass) {
    void *array_klass;
    if (env == NULL || arrayDesc == NULL || arrayDesc[0] != '[') {
        fprintf(stderr, "[neko-bind] invalid array descriptor for klass bits: %s\\n",
            arrayDesc == NULL ? "<null>" : arrayDesc);
        abort();
    }
    if (!g_hotspot.initialized
        || ((g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_RAW_HEAP) == 0 && !g_hotspot.use_zgc)
        || g_hotspot.use_compact_object_headers
        || g_hotspot.klass_offset_bytes <= 0) {
        fprintf(stderr, "[neko-bind] array klass bits layout unavailable for %s\\n", arrayDesc);
        abort();
    }
    array_klass = neko_resolve_class_with_env(env, arrayDesc, fromClass);
    return neko_klass_header_bits(array_klass);
}

static void neko_bind_object_array_klass_bits(JNIEnv *env, uintptr_t *slot, const char *arrayDesc, jclass fromClass) {
    if (env == NULL || slot == NULL || *slot != 0) return;
    *slot = neko_array_klass_bits_for_descriptor(env, arrayDesc, fromClass);
    if (*slot == 0) {
        fprintf(stderr, "[neko-bind] object array klass bits unavailable: %s\\n",
            arrayDesc == NULL ? "<null>" : arrayDesc);
        abort();
    }
}

__attribute__((visibility("hidden"))) jclass neko_bound_class(JNIEnv *env, jclass slot, const char *owner) {
    (void)env;
    if (slot != NULL) return slot;
    fprintf(stderr, "[neko-bind] unresolved bound class: %s\\n", owner == NULL ? "<null>" : owner);
    abort();
}

static void *neko_decode_klass_header_bits(uintptr_t bits) {
    uintptr_t base;
    int shift;
    if (bits == 0) return NULL;
    if (g_hotspot.use_compact_object_headers) {
        fprintf(stderr, "[neko-bind] compact object headers unavailable for current-owner Class LDC\\n");
        abort();
    }
    if (g_hotspot.use_compressed_klass_ptrs) {
        if (g_neko_method_layout.addr_compressed_klass_base == NULL
            || g_neko_method_layout.addr_compressed_klass_shift == NULL) {
            fprintf(stderr, "[neko-bind] compressed Klass decode layout unavailable\\n");
            abort();
        }
        base = (uintptr_t)(*(void**)g_neko_method_layout.addr_compressed_klass_base);
        shift = *(int*)g_neko_method_layout.addr_compressed_klass_shift;
        return (void*)(base + (bits << shift));
    }
    return (void*)bits;
}

static void *neko_object_handle_klass(jobject obj) {
    char *oop;
    uintptr_t bits;
    if (obj == NULL) return NULL;
    if (!g_hotspot.initialized || g_hotspot.klass_offset_bytes <= 0) {
        fprintf(stderr, "[neko-bind] object Klass offset unavailable for current-owner Class LDC\\n");
        abort();
    }
    oop = (char*)neko_handle_oop(obj);
    if (oop == NULL) return NULL;
    if (g_hotspot.use_compressed_klass_ptrs) {
        bits = (uintptr_t)(*(uint32_t*)(oop + g_hotspot.klass_offset_bytes));
    } else {
        bits = *(uintptr_t*)(oop + g_hotspot.klass_offset_bytes);
    }
    return neko_decode_klass_header_bits(bits);
}

static jclass neko_bound_current_owner_class(void *thread, JNIEnv *env, jclass slot, const char *owner, jobject self_or_class, jboolean isStatic) {
    void *current_klass;
    void *slot_klass;
    void *klass_name;
    jclass current_mirror;
    (void)env;
    if (thread == NULL || owner == NULL || self_or_class == NULL) {
        fprintf(stderr, "[neko-bind] current-owner Class LDC missing input: %s\\n", owner == NULL ? "<null>" : owner);
        abort();
    }
    if (isStatic) {
        current_mirror = (jclass)self_or_class;
        current_klass = neko_class_mirror_to_klass(current_mirror);
    } else {
        current_klass = neko_object_handle_klass(self_or_class);
        current_mirror = (jclass)neko_klass_java_mirror_handle(thread, current_klass);
    }
    if (current_klass == NULL || current_mirror == NULL) {
        fprintf(stderr, "[neko-bind] current-owner Class LDC mirror unavailable: %s\\n", owner);
        abort();
    }
    if (g_neko_method_layout.off_klass_name < 0) {
        fprintf(stderr, "[neko-bind] Klass::_name offset unavailable for current-owner Class LDC\\n");
        abort();
    }
    klass_name = *(void**)((char*)current_klass + g_neko_method_layout.off_klass_name);
    if (!neko_symbol_equals_utf8(klass_name, owner)) {
        fprintf(stderr, "[neko-bind] current-owner Class LDC owner mismatch: expected=%s klass=%p\\n", owner, current_klass);
        abort();
    }
    slot_klass = slot != NULL ? neko_class_mirror_to_klass(slot) : NULL;
    return slot_klass == current_klass ? slot : current_mirror;
}

static jmethodID neko_bound_method(JNIEnv *env, jmethodID slot, const char *owner, const char *name, const char *desc, jboolean isStatic) {
    (void)env;
    if (slot != NULL) return slot;
    fprintf(stderr, "[neko-bind] unresolved bound %s method: %s.%s%s\\n",
            isStatic ? "static" : "instance",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
    abort();
}

__attribute__((visibility("hidden"))) jfieldID neko_bound_field(JNIEnv *env, jfieldID slot, const char *owner, const char *name, const char *desc, jboolean isStatic) {
    (void)env;
    if (slot != NULL) return slot;
    fprintf(stderr, "[neko-bind] unresolved bound %s field: %s.%s:%s\\n",
            isStatic ? "static" : "instance",
            owner == NULL ? "<null>" : owner,
            name == NULL ? "<null>" : name,
            desc == NULL ? "<null>" : desc);
    abort();
}

static jstring neko_bound_string(void *thread, JNIEnv *env, jstring *slot, const char *utf) {
    (void)thread;
    (void)env;
    if (slot != NULL && *slot != NULL) return *slot;
    fprintf(stderr, "[neko-bind] unresolved bound string literal: %s\\n", utf == NULL ? "<null>" : utf);
    abort();
}

static jboolean neko_bind_primitive_field_metadata_enabled(void) {
    return g_hotspot.initialized
        && (g_hotspot.fast_bits & NEKO_HOTSPOT_FAST_FIELD_HELPERS) != 0
        && !g_hotspot.use_compact_object_headers;
}

static jlong neko_native_instance_field_offset(JNIEnv *env, jclass cls, const char *name, const char *desc) {
    void *klass;
    neko_field_resolution_t native_field;
    if (env == NULL || cls == NULL || name == NULL || desc == NULL) return -1;
    klass = neko_class_mirror_to_klass(cls);
    native_field = neko_resolve_field(klass, name, desc, JNI_FALSE);
    return native_field.found && !native_field.is_static && native_field.offset > 0 ? (jlong)native_field.offset : -1;
}

static jlong neko_native_static_field_offset(JNIEnv *env, jclass cls, const char *name, const char *desc) {
    void *klass;
    neko_field_resolution_t native_field;
    if (env == NULL || cls == NULL || name == NULL || desc == NULL) return -1;
    klass = neko_class_mirror_to_klass(cls);
    native_field = neko_resolve_field(klass, name, desc, JNI_TRUE);
    return native_field.found && native_field.is_static && native_field.offset > 0 ? (jlong)native_field.offset : -1;
}

static void neko_bind_instance_field_offset(JNIEnv *env, jlong *slot, uint32_t *accessSlot, jclass cls, jfieldID fid, const char *owner, const char *name, const char *desc, jboolean requireDirectOffset) {
    void *klass;
    neko_field_resolution_t native_field;
    (void)fid;
    (void)requireDirectOffset;
    if (!neko_bind_primitive_field_metadata_enabled() || env == NULL || slot == NULL || accessSlot == NULL || *slot > 0 || cls == NULL || owner == NULL || name == NULL || desc == NULL) return;
    klass = neko_class_mirror_to_klass(cls);
    native_field = neko_resolve_field(klass, name, desc, JNI_FALSE);
    if (!native_field.found || native_field.is_static || native_field.offset == 0) {
        fprintf(stderr, "[neko-bind] native instance field metadata invalid: %s.%s:%s offset=%lld\\n",
            owner, name, desc, (long long)(native_field.found ? native_field.offset : 0));
        abort();
    }
    *slot = (jlong)native_field.offset;
    *accessSlot = native_field.access_flags;
}

static void neko_bind_static_field_metadata(JNIEnv *env, jobject *baseSlot, jlong *offsetSlot, uint32_t *accessSlot, jclass cls, const char *owner, const char *name, const char *desc) {
    void *klass;
    neko_field_resolution_t native_field;
    if (!neko_bind_primitive_field_metadata_enabled() || env == NULL || baseSlot == NULL || offsetSlot == NULL || accessSlot == NULL
        || (*baseSlot != NULL && *offsetSlot > 0) || cls == NULL || owner == NULL || name == NULL || desc == NULL) return;
    klass = neko_class_mirror_to_klass(cls);
    native_field = neko_resolve_field(klass, name, desc, JNI_TRUE);
    if (!native_field.found || !native_field.is_static || native_field.offset == 0) {
        fprintf(stderr, "[neko-bind] native static field metadata invalid: %s.%s:%s offset=%lld\\n",
            owner, name, desc, (long long)(native_field.found ? native_field.offset : 0));
        abort();
    }
    *offsetSlot = (jlong)native_field.offset;
    *accessSlot = native_field.access_flags;
    *baseSlot = (jobject)cls;
}

""").toString();
    }

    static String renderTolerantClassResolver() {
        return """
static jclass neko_try_resolve_class_mirror_with_env(JNIEnv *env, const char *utf8, jclass from_class) {
    jclass resolved = NULL;
    void *klass;
    if (env == NULL || utf8 == NULL || utf8[0] == '\\0') return NULL;
    klass = neko_resolve_loaded_class_by_name(utf8);
    if (g_neko_method_layout.sym_jvm_find_class_from_boot_loader != NULL) {
        resolved = ((neko_jvm_find_class_boot_t)g_neko_method_layout.sym_jvm_find_class_from_boot_loader)(env, utf8);
    }
    if (resolved == NULL && from_class != NULL && g_neko_method_layout.sym_jvm_find_class_from_class != NULL) {
        resolved = ((neko_jvm_find_class_from_class_t)g_neko_method_layout.sym_jvm_find_class_from_class)(
            env, utf8, JNI_FALSE, from_class);
    }
    if (resolved != NULL) {
        return resolved;
    }
    if (klass != NULL) {
        void *thread = neko_jni_env_to_thread(env);
        if (thread == NULL) return NULL;
        return (jclass)neko_klass_java_mirror_handle(thread, klass);
    }
    return NULL;
}

""";
    }

}
