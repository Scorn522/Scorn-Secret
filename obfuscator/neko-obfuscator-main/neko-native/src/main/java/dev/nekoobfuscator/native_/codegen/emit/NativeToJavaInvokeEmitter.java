package dev.nekoobfuscator.native_.codegen.emit;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Emits per-shape Java-state direct-call dispatchers. The hot path enters
 * Java through HotSpot's shared {@code StubRoutines::call_stub} with a
 * stack-local JavaCallWrapper mirror, so HotSpot's stack walker sees a real
 * entry frame and can return to the translated Java-ABI native body.
 *
 * <h2>HotSpot's compiled-Java calling convention (x86-64 SysV)</h2>
 *
 * Reference: hotspot/cpu/x86/sharedRuntime_x86_64.cpp
 * (SharedRuntime::java_calling_convention) and the j_rarg* register file
 * in hotspot/cpu/x86/register_x86.hpp.
 *
 * <ul>
 *   <li>{@code %rbx} = {@code Method*} (HotSpot's "method receiver" register)</li>
 *   <li>GP arg slots in order: {@code j_rarg0..j_rarg5} =
 *       {@code rsi, rdx, rcx, r8, r9, rdi}.
 *       Note j_rarg5 is {@code rdi} (swapped vs the C ABI's c_rarg0=rdi).
 *       For instance methods the receiver is {@code j_rarg0} = rsi.</li>
 *   <li>FP arg slots: {@code xmm0..xmm7} (same as SysV C).</li>
 *   <li>Args beyond the register set spill to the Java stack at
 *       {@code [rsp + i*8]} (caller pre-call rsp; the call instruction
 *       pushes its own return PC).</li>
 *   <li>{@code %r15} = {@code JavaThread*} (preserved across all Java
 *       calling-convention crossings).</li>
 *   <li>Return regs: {@code %rax} for int/long/object/ref, {@code %xmm0}
 *       for float/double.</li>
 * </ul>
 *
 * <h2>State-transition contract</h2>
 *
 * Translated methods are entered through patched {@code Method::_from_*_entry}
 * stubs, not JNI native wrappers, so their nested Java calls start and finish
 * in {@code _thread_in_java}. Bootstrap/native callers may still enter this
 * bridge from {@code _thread_in_native}; only that case performs an explicit
 * native-to-Java transition around HotSpot's call_stub.
 *
 * <ol>
 *   <li>Publishes the JavaFrameAnchor ({@code _last_Java_sp/fp/pc}) for the
 *       synthetic call_stub frame.</li>
 *   <li>Loads args into the Java calling convention registers + Java stack.</li>
 *   <li>{@code call *<entry>} (the Method's {@code _from_compiled_entry})
 *       while leaving Java-state callers in Java.</li>
 *   <li>On return clears the temporary anchor and returns the result via
 *       rax/xmm0 packed into
 *       {@code out_rax} / {@code out_xmm0}.</li>
 * </ol>
 *
 * <h2>Object-arg / return marshalling</h2>
 *
 * HotSpot compiled entries take and return raw oops, not JNI handles. The
 * C dispatcher recovers raw oops from {@code jobject} args via the standard
 * tag-mask + deref. Returned raw oops go through
 * {@code neko_direct_oop_to_handle} into the active JNIHandleBlock so the
 * caller sees a normal {@code jobject}.
 *
 * <h2>Architecture coverage</h2>
 *
 * x86-64 SysV (Linux + macOS) implemented. x86-64 Windows + AArch64 SysV
 * emit per-shape stubs that abort with a clear diagnostic until their
 * backends land. The runtime guard {@code g_neko_direct_invoke_ready}
 * ensures call sites only enter the dispatcher when the layout walker has
 * resolved every required offset.
 */
public final class NativeToJavaInvokeEmitter {

    private static final String RAW_OBJECT_LOCAL_STORE_SHAPE = "V:L:L";

    private final LinkedHashMap<String, SignaturePlan.Shape> shapes = new LinkedHashMap<>();

    public NativeToJavaInvokeEmitter() {}

    public static String shapeKey(SignaturePlan.Shape shape) {
        StringBuilder sb = new StringBuilder();
        sb.append(shape.isStatic() ? 'S' : 'V').append(':');
        sb.append(shape.returnKind()).append(':');
        for (char a : shape.argKinds()) sb.append(a);
        return sb.toString();
    }

    public String register(SignaturePlan.Shape shape) {
        String key = shapeKey(shape);
        shapes.putIfAbsent(key, shape);
        return dispatcherSymbol(key);
    }

    public boolean isEmpty() { return shapes.isEmpty(); }
    public Set<String> shapeKeys() { return new LinkedHashSet<>(shapes.keySet()); }
    public List<SignaturePlan.Shape> registeredShapes() { return List.copyOf(shapes.values()); }
    public boolean hasShape(SignaturePlan.Shape shape) { return shapes.containsKey(shapeKey(shape)); }

    public static String dispatcherSymbol(String key) {
        return "neko_njx_" + key.replace(':', '_');
    }

    public static String rawObjectDispatcherSymbol(String key) {
        return dispatcherSymbol(key) + "_raw_oop";
    }

    public String renderPrelude() {
        if (shapes.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("/* === Native→Java direct invoke (forward decls) === */\n");
        sb.append("typedef jvalue (*neko_njx_dispatcher_t)(void *thread, JNIEnv *env, void *method_ptr, void *entry_point, jobject receiver, const jvalue *args);\n");
        sb.append("typedef void (*neko_call_stub_t)(void*, intptr_t*, int32_t, void*, void*, intptr_t*, int32_t, void*);\n");
        sb.append("extern void *g_neko_call_stub_entry;\n");
        sb.append("extern ptrdiff_t g_neko_off_jcw_anchor;\n");
        for (Map.Entry<String, SignaturePlan.Shape> e : shapes.entrySet()) {
            String key = e.getKey();
            sb.append("static jvalue ").append(dispatcherSymbol(e.getKey()))
              .append("(void *thread, JNIEnv *env, void *method_ptr, void *entry_point, jobject receiver, const jvalue *args);\n");
            if (RAW_OBJECT_LOCAL_STORE_SHAPE.equals(key)) {
                sb.append("static void *").append(rawObjectDispatcherSymbol(key))
                  .append("(void *thread, JNIEnv *env, void *method_ptr, void *entry_point, jobject receiver, const jvalue *args);\n");
            }
        }
        sb.append('\n');
        return sb.toString();
    }


    /** Render a function that the JNI_OnLoad bootstrap invokes after native
     * metadata initialization. NJX currently uses call_stub dispatchers, so
     * there are no per-shape compiled-entry wrappers to allocate. */
    public String renderInitFunction() {
        if (shapes.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("static void neko_njx_init_wrappers(void) {\n");

        sb.append("    NEKO_DIRECT_LOG(\"njx call_stub dispatchers initialized: ").append(shapes.size()).append(" shapes\");\n");
        sb.append("}\n\n");
        return sb.toString();
    }

    public String renderBodies() {
        if (shapes.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("/* === Native→Java direct invoke implementations === */\n");
        sb.append(renderReturnShapeAuditSupport());
        sb.append(renderHelpers());
        sb.append(renderCallStubHandleHelpers());
        /* Per-shape naked trampolines + C dispatchers; per-arch sections. */
        sb.append("#if defined(__x86_64__) && (defined(__linux__) || defined(__APPLE__))\n");
        for (Map.Entry<String, SignaturePlan.Shape> e : shapes.entrySet()) {
            sb.append(renderShapeCallStub(e.getKey(), e.getValue(), false));
            if (RAW_OBJECT_LOCAL_STORE_SHAPE.equals(e.getKey())) {
                sb.append(renderShapeCallStub(e.getKey(), e.getValue(), true));
            }
        }
        sb.append("#else\n");
        for (Map.Entry<String, SignaturePlan.Shape> e : shapes.entrySet()) {
            sb.append(renderShapeUnsupported(e.getKey(), e.getValue()));
            if (RAW_OBJECT_LOCAL_STORE_SHAPE.equals(e.getKey())) {
                sb.append(renderShapeRawUnsupported(e.getKey()));
            }
        }
        sb.append("#endif\n\n");
        return sb.toString();
    }

    private String renderReturnShapeAuditSupport() {
        List<Map.Entry<String, SignaturePlan.Shape>> objectReturnShapes = shapes.entrySet().stream()
            .filter(e -> e.getValue().returnKind() == 'L')
            .toList();
        if (objectReturnShapes.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("#if NEKO_HANDLE_AUDIT\n");
        for (Map.Entry<String, SignaturePlan.Shape> e : objectReturnShapes) {
            sb.append("static volatile uint64_t g_neko_njx_return_shape_")
              .append(dispatcherSymbol(e.getKey())).append(" = 0;\n");
        }
        sb.append("static volatile int g_neko_njx_return_shape_stats_printed = 0;\n");
        sb.append("static void neko_njx_dump_return_shape_stats_at_exit(void) {\n");
        sb.append("    if (!neko_njx_debug()) return;\n");
        sb.append("    if (!__sync_bool_compare_and_swap(&g_neko_njx_return_shape_stats_printed, 0, 1)) return;\n");
        sb.append("    fprintf(stderr, \"[neko-direct] njx-return-shapes:");
        for (Map.Entry<String, SignaturePlan.Shape> e : objectReturnShapes) {
            sb.append(' ').append(e.getKey()).append("=%llu");
        }
        sb.append("\\n\"");
        for (Map.Entry<String, SignaturePlan.Shape> e : objectReturnShapes) {
            sb.append(",\n        (unsigned long long)__atomic_load_n(&g_neko_njx_return_shape_")
              .append(dispatcherSymbol(e.getKey())).append(", __ATOMIC_RELAXED)");
        }
        sb.append(");\n");
        sb.append("}\n");
        sb.append("__attribute__((constructor)) static void neko_njx_register_return_shape_atexit(void) {\n");
        sb.append("    atexit(neko_njx_dump_return_shape_stats_at_exit);\n");
        sb.append("}\n");
        sb.append("#endif\n\n");
        return sb.toString();
    }

    private String renderCallStubHandleHelpers() {
        return """
NEKO_FAST_INLINE void *neko_njx_install_java_handles(void *thread, void *stack_handles, size_t stack_handles_size) {
    void *java_handles = NULL;
    if (g_neko_off_thread_active_handles > 0
        && g_neko_method_layout.sizeof_JNIHandleBlock > 0
        && g_neko_method_layout.off_jnih_block_next > 0) {
        if (stack_handles != NULL && stack_handles_size >= g_neko_method_layout.sizeof_JNIHandleBlock) {
            java_handles = stack_handles;
            memset(java_handles, 0, g_neko_method_layout.sizeof_JNIHandleBlock);
        } else {
            java_handles = calloc(1, g_neko_method_layout.sizeof_JNIHandleBlock);
        }
        if (java_handles != NULL) {
            *(int32_t*)((char*)java_handles + g_neko_off_jnih_block_top) = 0;
            *(void**)((char*)java_handles + g_neko_method_layout.off_jnih_block_next) =
                *(void**)((char*)thread + g_neko_off_thread_active_handles);
            *(void**)((char*)java_handles + g_neko_method_layout.off_jnih_block_next + 8) = java_handles;
            *(void**)((char*)thread + g_neko_off_thread_active_handles) = java_handles;
        }
    }
    return java_handles;
}

NEKO_FAST_INLINE void neko_njx_restore_java_handles(void *thread, void *old_handles, void *java_handles, void *stack_handles) {
    void *active;
    if (g_neko_off_thread_active_handles > 0) {
        if (thread != NULL && g_neko_method_layout.off_jnih_block_next > 0) {
            active = *(void**)((char*)thread + g_neko_off_thread_active_handles);
            while (active != NULL && active != old_handles) {
                void *next = *(void**)((char*)active + g_neko_method_layout.off_jnih_block_next);
                if (active == old_handles) break;
                if (active != stack_handles) free(active);
                active = next;
            }
            java_handles = NULL;
        }
        *(void**)((char*)thread + g_neko_off_thread_active_handles) = old_handles;
    }
    if (java_handles != NULL && java_handles != stack_handles) free(java_handles);
}

typedef struct {
    void *stub;
    void *link;
    intptr_t *result;
    int32_t result_type;
    void *method;
    void *entry;
    intptr_t *params;
    int32_t size;
    void *thread;
} neko_call_stub_args_t;

#if defined(__x86_64__) && (defined(__linux__) || defined(__APPLE__))
__attribute__((naked, noinline, used))
static void neko_call_stub_guarded(neko_call_stub_args_t *a) {
    __asm__ volatile (
        "pushq %%rbp\\n"
        "movq  %%rsp, %%rbp\\n"

        "movq  %%rdi, %%r10\\n"
        "movq  64(%%r10), %%rax\\n"
        "pushq %%rax\\n"
        "movslq 56(%%r10), %%rax\\n"
        "pushq %%rax\\n"
        "movq  8(%%r10), %%rdi\\n"
        "movq  16(%%r10), %%rsi\\n"
        "movslq 24(%%r10), %%rdx\\n"
        "movq  32(%%r10), %%rcx\\n"
        "movq  40(%%r10), %%r8\\n"
        "movq  48(%%r10), %%r9\\n"
        "movq  0(%%r10), %%r11\\n"
        "call *%%r11\\n"
        "addq  $16, %%rsp\\n"
        "popq  %%rbp\\n"
        "ret\\n"
        :
        :
        : "memory"
    );
}
#else
static void neko_call_stub_guarded(neko_call_stub_args_t *a) {
    ((neko_call_stub_t)a->stub)(a->link, a->result, a->result_type, a->method,
        a->entry, a->params, a->size, a->thread);
}
#endif


""";
    }

    private String renderHelpers() {
        return """
/* Convert a jobject-like reference to its raw oop. This may already be a raw
 * oop when direct call_stub re-enters translated native code. */
NEKO_FAST_INLINE void *neko_njx_handle_to_oop(jobject handle) {
    return neko_handle_oop(handle);
}

/* Wrap a raw oop returned from compiled Java back into a jobject via the
 * active JNIHandleBlock. Reuses the AALOAD fast path's helper. */
NEKO_FAST_INLINE jobject neko_njx_oop_to_handle(void *thread, void *oop) {
    if (oop == NULL) return NULL;
    return neko_direct_oop_to_handle_origin(thread, oop, NEKO_HANDLE_ORIGIN_NJX_RETURN);
}

/* Resolve Method* + _from_interpreted_entry. HotSpot's call_stub builds an
 * interpreter-shaped argument stack, so direct calls must enter through
 * Method::_from_interpreted_entry. */
static int neko_njx_resolve_method_entry(void *m, void **out_method, void **out_entry) {
    if (m == NULL || out_method == NULL || out_entry == NULL) return 0;
    if (!g_neko_method_layout.initialized || !g_neko_method_layout.usable) {
        NEKO_DIRECT_LOG("resolve_entry: layout not ready (init=%d usable=%d)",
            (int)g_neko_method_layout.initialized, (int)g_neko_method_layout.usable);
        return 0;
    }
    if (g_neko_method_layout.off_method_from_interpreted_entry <= 0) {
        NEKO_DIRECT_LOG("resolve_entry: interpreted-entry offset unresolved");
        return 0;
    }
    void *e = *(void**)((char*)m + g_neko_method_layout.off_method_from_interpreted_entry);
    if (e == NULL) {
        NEKO_DIRECT_LOG("resolve_entry: Method* %p has NULL _from_interpreted_entry", m);
        return 0;
    }
    *out_method = m;
    *out_entry  = e;
    return 1;
}

/* Resolve from a native jmethodID cell created by neko_make_native_method_id. */
static int neko_njx_resolve_entry(jmethodID mid, void **out_method, void **out_entry) {
    if (mid == NULL || out_method == NULL || out_entry == NULL) return 0;
    void *m = *(void**)mid;
    if (m == NULL) {
        NEKO_DIRECT_LOG("resolve_entry: jmethodID %p deref to NULL Method*", mid);
        return 0;
    }
    return neko_njx_resolve_method_entry(m, out_method, out_entry);
}

""";
    }



    private static String resultBasicTypeExpr(char ret) {
        return switch (ret) {
            case 'J' -> "g_neko_basictype_long";
            case 'F' -> "g_neko_basictype_float";
            case 'D' -> "g_neko_basictype_double";
            case 'L' -> "g_neko_basictype_object";
            default -> "g_neko_basictype_int";
        };
    }


    private String renderShapeCallStub(String key, SignaturePlan.Shape shape, boolean rawObjectReturn) {
        char ret = shape.returnKind();
        char[] args = shape.argKinds();
        boolean isStatic = shape.isStatic();
        String fn = rawObjectReturn ? rawObjectDispatcherSymbol(key) : dispatcherSymbol(key);
        int javaSlots = isStatic ? 0 : 1;
        for (char a : args) javaSlots += (a == 'J' || a == 'D') ? 2 : 1;

        StringBuilder sb = new StringBuilder();
        sb.append("/* shape ").append(key).append(rawObjectReturn ? " raw-oop" : "").append(" specialized call_stub */\n");
        sb.append("static ").append(rawObjectReturn ? "void *" : "jvalue ").append(fn)
          .append("(void *thread, JNIEnv *env, void *method_ptr, void *entry_point, jobject receiver, const jvalue *args) {\n");
        if (!rawObjectReturn) {
            sb.append("    jvalue result; result.j = 0;\n");
        }
        sb.append("    (void)env;\n");
        sb.append("    if (!g_neko_direct_invoke_ready || method_ptr == NULL || entry_point == NULL || thread == NULL) {\n");
        sb.append("        fprintf(stderr, \"[neko-direct] precondition failed shape=").append(key)
          .append(" ready=%d m=%p e=%p t=%p\\n\", (int)g_neko_direct_invoke_ready, method_ptr, entry_point, thread); abort();\n");
        sb.append("    }\n");
        sb.append("    neko_njx_note_dispatch();\n");
        sb.append("    intptr_t call_params[").append(Math.max(javaSlots, 1)).append("];\n");
        sb.append("    int __njx_pos = 0;\n");
        if (!isStatic) {
            sb.append("    call_params[__njx_pos++] = (intptr_t)(uintptr_t)neko_njx_handle_to_oop(receiver);\n");
        }
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case 'L' -> sb.append("    call_params[__njx_pos++] = (intptr_t)(uintptr_t)neko_njx_handle_to_oop(args[").append(i).append("].l);\n");
                case 'J' -> sb.append("    call_params[__njx_pos] = 0; *(jlong*)(call_params + 1 + __njx_pos) = args[").append(i).append("].j; __njx_pos += 2;\n");
                case 'F' -> sb.append("    call_params[__njx_pos] = 0; *(jfloat*)(call_params + __njx_pos) = args[").append(i).append("].f; __njx_pos++;\n");
                case 'D' -> sb.append("    call_params[__njx_pos] = 0; *(jdouble*)(call_params + 1 + __njx_pos) = args[").append(i).append("].d; __njx_pos += 2;\n");
                default -> sb.append("    call_params[__njx_pos] = 0; *(jint*)(call_params + __njx_pos) = args[").append(i).append("].i; __njx_pos++;\n");
            }
        }
        sb.append("    int64_t out_rax = 0;\n");
        sb.append("    double  out_xmm0 = 0.0;\n");
        sb.append("    neko_handle_save_t __njx_hsave;\n");
        sb.append("    neko_handle_save(thread, &__njx_hsave);\n");
        sb.append("    void *__njx_old_handles = __njx_hsave.block;\n");
        sb.append("    uint8_t __njx_handle_buf[512] __attribute__((aligned(16)));\n");
        sb.append("    void *__njx_java_handles = neko_njx_install_java_handles(thread, __njx_handle_buf, sizeof(__njx_handle_buf));\n");
        sb.append("    if (__njx_java_handles == NULL) { fprintf(stderr, \"[neko-direct] Java handle block unavailable shape=").append(key).append("\\n\"); abort(); }\n");
        sb.append("    void *saved_sp = (g_neko_off_last_Java_sp > 0) ? *(void**)((char*)thread + g_neko_off_last_Java_sp) : NULL;\n");
        sb.append("    void *saved_pc = (g_neko_off_last_Java_pc > 0) ? *(void**)((char*)thread + g_neko_off_last_Java_pc) : NULL;\n");
        sb.append("    void *saved_fp = (g_neko_off_last_Java_fp > 0) ? *(void**)((char*)thread + g_neko_off_last_Java_fp) : NULL;\n");
        sb.append("    uint8_t __jcw_buf[256] __attribute__((aligned(16))); memset(__jcw_buf, 0, sizeof(__jcw_buf));\n");
        sb.append("    if (g_neko_call_stub_entry == NULL || g_neko_off_jcw_anchor <= 0\n")
          .append("        || g_neko_method_layout.off_frame_anchor_sp < 0\n")
          .append("        || g_neko_method_layout.off_frame_anchor_pc < 0\n")
          .append("        || g_neko_method_layout.off_frame_anchor_fp < 0\n")
          .append("        || (size_t)(g_neko_off_jcw_anchor + g_neko_method_layout.off_frame_anchor_fp + (ptrdiff_t)sizeof(void*)) > sizeof(__jcw_buf)) {\n")
          .append("        fprintf(stderr, \"[neko-direct] call_stub precondition failed shape=").append(key).append(" entry=%p jcw_anchor=%td\\n\", g_neko_call_stub_entry, g_neko_off_jcw_anchor); abort();\n")
          .append("    }\n");
        sb.append("    *(void**)(__jcw_buf + 0) = thread;\n");
        sb.append("    *(void**)(__jcw_buf + 8) = __njx_old_handles;\n");
        sb.append("    *(void**)(__jcw_buf + 16) = method_ptr;\n");
        sb.append("    *(void**)(__jcw_buf + 24) = ").append(isStatic ? "NULL" : "(void*)(uintptr_t)call_params[0]").append(";\n");
        sb.append("    char *__jcw_anchor = (char*)__jcw_buf + g_neko_off_jcw_anchor;\n");
        sb.append("    *(void**)(__jcw_anchor + g_neko_method_layout.off_frame_anchor_sp) = saved_sp;\n");
        sb.append("    *(void**)(__jcw_anchor + g_neko_method_layout.off_frame_anchor_pc) = saved_pc;\n");
        sb.append("    *(void**)(__jcw_anchor + g_neko_method_layout.off_frame_anchor_fp) = saved_fp;\n");
        sb.append("    if (g_neko_off_last_Java_sp > 0) *(void**)((char*)thread + g_neko_off_last_Java_sp) = NULL;\n");
        sb.append("    if (g_neko_off_last_Java_pc > 0) *(void**)((char*)thread + g_neko_off_last_Java_pc) = NULL;\n");
        sb.append("    if (g_neko_off_last_Java_fp > 0) *(void**)((char*)thread + g_neko_off_last_Java_fp) = NULL;\n");
        sb.append("    intptr_t __call_result[2]; __call_result[0] = 0; __call_result[1] = 0;\n");
        sb.append("    NEKO_DIRECT_LOG(\"  -> call_stub shape=").append(key).append(" slots=").append(javaSlots).append(" saved_sp=%p\", saved_sp);\n");
        sb.append("    jboolean __njx_restore_native_state = JNI_FALSE;\n");
        sb.append("    if (g_neko_off_thread_state > 0) {\n");
        sb.append("        int32_t __entry_state = *(int32_t*)((char*)thread + g_neko_off_thread_state);\n");
        sb.append("        if (__entry_state == g_neko_thread_state_in_native) { neko_transition_native_to_java(thread); __njx_restore_native_state = JNI_TRUE; }\n");
        sb.append("        else if (__entry_state != g_neko_thread_state_in_java) { fprintf(stderr, \"[neko-direct] call_stub entered in unsupported thread state shape=").append(key).append(" state=%d java=%d native=%d\\n\", __entry_state, g_neko_thread_state_in_java, g_neko_thread_state_in_native); abort(); }\n");
        sb.append("    }\n");
        sb.append("    {\n");
        sb.append("        neko_call_stub_args_t __stub_args = { g_neko_call_stub_entry, (void*)__jcw_buf, __call_result, ")
          .append(resultBasicTypeExpr(ret)).append(", method_ptr, entry_point, call_params, ")
          .append(javaSlots).append(", thread };\n");
        sb.append("        neko_call_stub_guarded(&__stub_args);\n");
        sb.append("    }\n");
        sb.append("    if (g_neko_off_thread_state > 0) { int32_t __state = *(int32_t*)((char*)thread + g_neko_off_thread_state); if (__njx_restore_native_state) { if (__state == g_neko_thread_state_in_java) { neko_transition_java_to_native(thread); } else if (__state != g_neko_thread_state_in_native) { fprintf(stderr, \"[neko-direct] call_stub returned in unsupported native-caller state shape=").append(key).append(" state=%d java=%d native=%d\\n\", __state, g_neko_thread_state_in_java, g_neko_thread_state_in_native); abort(); } } else { if (__state != g_neko_thread_state_in_java) { if (__state == g_neko_thread_state_in_native) { neko_transition_native_to_java(thread); __state = *(int32_t*)((char*)thread + g_neko_off_thread_state); } } if (__state != g_neko_thread_state_in_java) { fprintf(stderr, \"[neko-direct] call_stub returned outside _thread_in_java shape=").append(key).append(" state=%d expected=%d\\n\", __state, g_neko_thread_state_in_java); abort(); } } }\n");
        if (ret == 'F' || ret == 'D') {
            sb.append("    memcpy(&out_xmm0, __call_result, sizeof(out_xmm0));\n");
        } else if (ret != 'V') {
            sb.append("    out_rax = (int64_t)__call_result[0];\n");
        }
        sb.append("    NEKO_DIRECT_LOG(\"  <- call_stub shape=").append(key).append(" r=0x%llx xmm0=%g\", (unsigned long long)out_rax, out_xmm0);\n");
        sb.append("    neko_njx_restore_java_handles(thread, __njx_old_handles, __njx_java_handles, __njx_handle_buf);\n");
        sb.append("    if (g_neko_off_last_Java_sp > 0) *(void**)((char*)thread + g_neko_off_last_Java_sp) = saved_sp;\n");
        sb.append("    if (g_neko_off_last_Java_pc > 0) *(void**)((char*)thread + g_neko_off_last_Java_pc) = saved_pc;\n");
        sb.append("    if (g_neko_off_last_Java_fp > 0) *(void**)((char*)thread + g_neko_off_last_Java_fp) = saved_fp;\n");
        sb.append("    neko_handle_restore(&__njx_hsave);\n");
        switch (ret) {
            case 'V' -> { /* nothing */ }
            case 'I' -> sb.append("    result.i = (jint)(int32_t)out_rax;\n");
            case 'J' -> sb.append("    result.j = (jlong)out_rax;\n");
            case 'F' -> sb.append("    { float __f = (float)out_xmm0; result.f = __f; }\n");
            case 'D' -> sb.append("    result.d = (jdouble)out_xmm0;\n");
            case 'L' -> {
                sb.append("    if (out_rax != 0) NEKO_HANDLE_AUDIT_HIT(g_neko_njx_return_shape_")
                  .append(dispatcherSymbol(key)).append(");\n");
                if (rawObjectReturn) {
                    sb.append("    return (void*)(uintptr_t)out_rax;\n");
                } else {
                    sb.append("    result.l = neko_njx_oop_to_handle(thread, (void*)(uintptr_t)out_rax);\n");
                }
            }
        }
        if (!rawObjectReturn) {
            sb.append("    return result;\n");
        }
        sb.append("}\n\n");
        return sb.toString();
    }

    private String renderShapeUnsupported(String key, SignaturePlan.Shape shape) {
        String fn = dispatcherSymbol(key);
        StringBuilder sb = new StringBuilder();
        sb.append("static jvalue ").append(fn)
          .append("(void *thread, JNIEnv *env, void *method_ptr, void *entry_point, jobject receiver, const jvalue *args) {\n");
        sb.append("    (void)thread; (void)env; (void)method_ptr; (void)entry_point; (void)receiver; (void)args;\n");
        sb.append("    fprintf(stderr, \"[neko-direct-invoke] arch backend missing for shape=").append(key).append("\\n\"); abort();\n");
        sb.append("    jvalue r; r.j = 0; return r;\n");
        sb.append("}\n\n");
        return sb.toString();
    }

    private String renderShapeRawUnsupported(String key) {
        StringBuilder sb = new StringBuilder();
        sb.append("static void *").append(rawObjectDispatcherSymbol(key))
          .append("(void *thread, JNIEnv *env, void *method_ptr, void *entry_point, jobject receiver, const jvalue *args) {\n");
        sb.append("    (void)thread; (void)env; (void)method_ptr; (void)entry_point; (void)receiver; (void)args;\n");
        sb.append("    fprintf(stderr, \"[neko-direct-invoke] arch backend missing for raw object shape=").append(key).append("\\n\"); abort();\n");
        sb.append("    return NULL;\n");
        sb.append("}\n\n");
        return sb.toString();
    }
}
