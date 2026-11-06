package dev.nekoobfuscator.native_.codegen;

/**
 * Emits primitive boxing support used by translated native bodies.
 */
final class NativeBoxingSupportEmitter {
    private NativeBoxingSupportEmitter() {}

    static String renderBoxingSupport() {
        return """
typedef struct {
    const char *owner;
    const char *value_sig;
    const char *valueof_sig;
    void *valueof_method;
    void *valueof_entry;
    jlong value_offset;
} neko_boxing_cache_t;

static neko_boxing_cache_t g_neko_box_boolean = {"java/lang/Boolean", "Z", "(Z)Ljava/lang/Boolean;", NULL, NULL, -1};
static neko_boxing_cache_t g_neko_box_byte = {"java/lang/Byte", "B", "(B)Ljava/lang/Byte;", NULL, NULL, -1};
static neko_boxing_cache_t g_neko_box_char = {"java/lang/Character", "C", "(C)Ljava/lang/Character;", NULL, NULL, -1};
static neko_boxing_cache_t g_neko_box_short = {"java/lang/Short", "S", "(S)Ljava/lang/Short;", NULL, NULL, -1};
static neko_boxing_cache_t g_neko_box_int = {"java/lang/Integer", "I", "(I)Ljava/lang/Integer;", NULL, NULL, -1};
static neko_boxing_cache_t g_neko_box_long = {"java/lang/Long", "J", "(J)Ljava/lang/Long;", NULL, NULL, -1};
static neko_boxing_cache_t g_neko_box_float = {"java/lang/Float", "F", "(F)Ljava/lang/Float;", NULL, NULL, -1};
static neko_boxing_cache_t g_neko_box_double = {"java/lang/Double", "D", "(D)Ljava/lang/Double;", NULL, NULL, -1};
static jboolean g_neko_boxing_cache_ready = JNI_FALSE;

static void neko_boxing_cache_init_one(JNIEnv *env, neko_boxing_cache_t *cache) {
    void *klass = NULL;
    jclass mirror;
    neko_field_resolution_t field;
    if (env == NULL || cache == NULL || cache->owner == NULL || cache->value_sig == NULL || cache->valueof_sig == NULL) {
        fprintf(stderr, "[neko-bind] boxing cache init missing input\\n");
        abort();
    }
    mirror = neko_resolve_class_mirror_with_env(env, cache->owner, NULL, &klass);
    if (mirror == NULL || klass == NULL) {
        fprintf(stderr, "[neko-bind] boxing class resolution failed: %s\\n", cache->owner);
        abort();
    }
    cache->valueof_method = neko_resolve_method(klass, "valueOf", cache->valueof_sig);
    cache->valueof_entry = neko_bound_method_i_entry(cache->valueof_method, &cache->valueof_entry, cache->owner, "valueOf", cache->valueof_sig);
    field = neko_resolve_field(klass, "value", cache->value_sig, JNI_FALSE);
    if (!field.found || field.offset == 0) {
        fprintf(stderr, "[neko-bind] boxing value field resolution failed: %s.value:%s\\n", cache->owner, cache->value_sig);
        abort();
    }
    cache->value_offset = (jlong)field.offset;
}

static void neko_boxing_cache_init(JNIEnv *env) {
    if (g_neko_boxing_cache_ready) return;
    neko_boxing_cache_init_one(env, &g_neko_box_boolean);
    neko_boxing_cache_init_one(env, &g_neko_box_byte);
    neko_boxing_cache_init_one(env, &g_neko_box_char);
    neko_boxing_cache_init_one(env, &g_neko_box_short);
    neko_boxing_cache_init_one(env, &g_neko_box_int);
    neko_boxing_cache_init_one(env, &g_neko_box_long);
    neko_boxing_cache_init_one(env, &g_neko_box_float);
    neko_boxing_cache_init_one(env, &g_neko_box_double);
    g_neko_boxing_cache_ready = JNI_TRUE;
}

static jobject neko_box_call(void *thread, JNIEnv *env, neko_boxing_cache_t *cache, jvalue arg, neko_njx_dispatcher_t dispatcher) {
    jvalue result;
    result.j = 0;
    if (!g_neko_boxing_cache_ready) neko_boxing_cache_init(env);
    if (thread == NULL) thread = neko_jni_env_to_thread(env);
    if (thread == NULL || cache == NULL || cache->valueof_method == NULL || dispatcher == NULL) {
        fprintf(stderr, "[neko-direct] boxing call_stub precondition failed owner=%s thread=%p method=%p dispatcher=%p\\n",
            cache == NULL ? "<null>" : cache->owner, thread, cache == NULL ? NULL : cache->valueof_method, (void*)dispatcher);
        abort();
    }
    result = dispatcher(thread, env, cache->valueof_method,
        neko_bound_method_i_entry(cache->valueof_method, &cache->valueof_entry, cache->owner, "valueOf", cache->valueof_sig),
        NULL, &arg);
    return result.l;
}

static char *neko_unbox_oop(void *thread, JNIEnv *env, jobject obj, neko_boxing_cache_t *cache) {
    char *oop;
    (void)thread;
    if (!g_neko_boxing_cache_ready) neko_boxing_cache_init(env);
    if (obj == NULL || cache == NULL || cache->value_offset <= 0) {
        fprintf(stderr, "[neko-direct] unbox precondition failed owner=%s obj=%p offset=%lld\\n",
            cache == NULL ? "<null>" : cache->owner, (void*)obj, (long long)(cache == NULL ? -1 : cache->value_offset));
        abort();
    }
    oop = (char*)neko_handle_oop(obj);
    if (oop == NULL) {
        fprintf(stderr, "[neko-direct] boxed object handle unresolved owner=%s obj=%p\\n", cache->owner, (void*)obj);
        abort();
    }
    return oop;
}

static jobject neko_box_boolean(void *thread, JNIEnv *env, jboolean v) { jvalue arg; arg.z = v; return neko_box_call(thread, env, &g_neko_box_boolean, arg, neko_njx_S_L_I); }
static jobject neko_box_byte(void *thread, JNIEnv *env, jbyte v) { jvalue arg; arg.b = v; return neko_box_call(thread, env, &g_neko_box_byte, arg, neko_njx_S_L_I); }
static jobject neko_box_char(void *thread, JNIEnv *env, jchar v) { jvalue arg; arg.c = v; return neko_box_call(thread, env, &g_neko_box_char, arg, neko_njx_S_L_I); }
static jobject neko_box_short(void *thread, JNIEnv *env, jshort v) { jvalue arg; arg.s = v; return neko_box_call(thread, env, &g_neko_box_short, arg, neko_njx_S_L_I); }
static jobject neko_box_int(void *thread, JNIEnv *env, jint v) { jvalue arg; arg.i = v; return neko_box_call(thread, env, &g_neko_box_int, arg, neko_njx_S_L_I); }
static jobject neko_box_long(void *thread, JNIEnv *env, jlong v) { jvalue arg; arg.j = v; return neko_box_call(thread, env, &g_neko_box_long, arg, neko_njx_S_L_J); }
static jobject neko_box_float(void *thread, JNIEnv *env, jfloat v) { jvalue arg; arg.f = v; return neko_box_call(thread, env, &g_neko_box_float, arg, neko_njx_S_L_F); }
static jobject neko_box_double(void *thread, JNIEnv *env, jdouble v) { jvalue arg; arg.d = v; return neko_box_call(thread, env, &g_neko_box_double, arg, neko_njx_S_L_D); }

static jboolean neko_unbox_boolean(void *thread, JNIEnv *env, jobject obj) { char *oop = neko_unbox_oop(thread, env, obj, &g_neko_box_boolean); return *(jboolean*)(oop + g_neko_box_boolean.value_offset); }
static jbyte neko_unbox_byte(void *thread, JNIEnv *env, jobject obj) { char *oop = neko_unbox_oop(thread, env, obj, &g_neko_box_byte); return *(jbyte*)(oop + g_neko_box_byte.value_offset); }
static jchar neko_unbox_char(void *thread, JNIEnv *env, jobject obj) { char *oop = neko_unbox_oop(thread, env, obj, &g_neko_box_char); return *(jchar*)(oop + g_neko_box_char.value_offset); }
static jshort neko_unbox_short(void *thread, JNIEnv *env, jobject obj) { char *oop = neko_unbox_oop(thread, env, obj, &g_neko_box_short); return *(jshort*)(oop + g_neko_box_short.value_offset); }
static jint neko_unbox_int(void *thread, JNIEnv *env, jobject obj) { char *oop = neko_unbox_oop(thread, env, obj, &g_neko_box_int); return *(jint*)(oop + g_neko_box_int.value_offset); }
static jlong neko_unbox_long(void *thread, JNIEnv *env, jobject obj) { char *oop = neko_unbox_oop(thread, env, obj, &g_neko_box_long); return *(jlong*)(oop + g_neko_box_long.value_offset); }
static jfloat neko_unbox_float(void *thread, JNIEnv *env, jobject obj) { char *oop = neko_unbox_oop(thread, env, obj, &g_neko_box_float); return *(jfloat*)(oop + g_neko_box_float.value_offset); }
static jdouble neko_unbox_double(void *thread, JNIEnv *env, jobject obj) { char *oop = neko_unbox_oop(thread, env, obj, &g_neko_box_double); return *(jdouble*)(oop + g_neko_box_double.value_offset); }

""";
    }

}
