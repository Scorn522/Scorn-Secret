package dev.nekoobfuscator.native_.codegen;

import dev.nekoobfuscator.core.ir.l3.CFunction;
import dev.nekoobfuscator.core.ir.l3.CStatement;
import dev.nekoobfuscator.core.ir.l3.CType;
import dev.nekoobfuscator.core.ir.l3.CVariable;
import dev.nekoobfuscator.native_.codegen.emit.JniHandlesShimEmitter;
import dev.nekoobfuscator.native_.codegen.emit.JniOnLoadEmitter;
import dev.nekoobfuscator.native_.codegen.emit.ManifestEmitter;
import dev.nekoobfuscator.native_.codegen.emit.MethodPatcherEmitter;
import dev.nekoobfuscator.native_.codegen.emit.NativeToJavaInvokeEmitter;
import dev.nekoobfuscator.native_.codegen.emit.SignatureDispatcherEmitter;
import dev.nekoobfuscator.native_.codegen.emit.SignaturePlan;
import dev.nekoobfuscator.native_.codegen.emit.TrampolineEmitter;
import dev.nekoobfuscator.native_.translator.NativeTranslator.NativeMethodBinding;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.objectweb.asm.Type;

public final class CCodeGenerator {

    private static final String IMPL_BEGIN_MARKER =
        "/* NEKO_TRANSLATED_IMPLS_BEGIN */";
    private static final String IMPL_END_MARKER =
        "/* NEKO_TRANSLATED_IMPLS_END */";
    private static final int MAX_FUNCTIONS_PER_IMPL_SOURCE = 1;
    private static final int MAX_IMPL_SOURCE_STATEMENTS = 1;
    private static final int MAX_FLATTEN_STATEMENTS = 128;
    private static final int MAX_DISPATCHERS_PER_SOURCE = 8;
    private static final int MAX_SUPPORT_HELPERS_PER_SOURCE = 24;
    private static final Pattern C_IDENTIFIER_PATTERN = Pattern.compile(
        "\\b[A-Za-z_]\\w*\\b"
    );
    private static final Pattern SLICED_CONTRACT_EXTERN_PATTERN =
        Pattern.compile(
            "\\b(?:g_(?:cls|obj_array_klass|cls_initialized|mid|mptr|mientry|fid|off|static_off|static_base|str)_\\d+|neko_bind_owner(?:_strings)?_\\d+|neko_native_impl_\\d+)\\b"
        );
    private static final Pattern SLICED_CONTRACT_DEFINE_PATTERN =
        Pattern.compile(
            "^#define\\s+((?:g_(?:class|static_field|field|method_id|method_entry|implicit_exception)_ref_\\d+)|(?:neko_icache(?:_meta)?_\\d+_\\d+_\\d+))\\b"
        );

    @SuppressWarnings("unused")
    private final SymbolTableGenerator symbols;

    private final ManifestEmitter manifestEmitter = new ManifestEmitter();
    private final SignatureDispatcherEmitter signatureDispatcherEmitter =
        new SignatureDispatcherEmitter();
    private final TrampolineEmitter trampolineEmitter = new TrampolineEmitter();
    private final MethodPatcherEmitter methodPatcherEmitter =
        new MethodPatcherEmitter();
    private final JniHandlesShimEmitter jniHandlesShimEmitter =
        new JniHandlesShimEmitter();
    private final JniOnLoadEmitter jniOnLoadEmitter = new JniOnLoadEmitter();
    private final NativeToJavaInvokeEmitter nativeToJavaInvokeEmitter =
        new NativeToJavaInvokeEmitter();
    private final LinkedHashMap<String, Integer> classSlotIndex =
        new LinkedHashMap<>();
    private final LinkedHashMap<String, Integer> methodSlotIndex =
        new LinkedHashMap<>();
    private final LinkedHashMap<String, Integer> fieldSlotIndex =
        new LinkedHashMap<>();
    private final LinkedHashMap<String, Integer> ownerBindIndex =
        new LinkedHashMap<>();
    private final LinkedHashMap<String, OwnerResolution> ownerResolutions =
        new LinkedHashMap<>();
    private final LinkedHashMap<String, Integer> icacheMethodIndex =
        new LinkedHashMap<>();
    private final LinkedHashMap<String, IcacheSiteRef> icacheSites =
        new LinkedHashMap<>();
    private final LinkedHashMap<String, IcacheDirectStubRef> icacheDirectStubs =
        new LinkedHashMap<>();
    private final LinkedHashMap<String, IcacheMetaRef> icacheMetas =
        new LinkedHashMap<>();
    private final LinkedHashMap<
        String,
        StaticFieldDescriptorRef
    > staticFieldDescriptorRefs = new LinkedHashMap<>();
    private final LinkedHashMap<
        String,
        FieldDescriptorRef
    > fieldDescriptorRefs = new LinkedHashMap<>();
    private final LinkedHashMap<
        String,
        ImplicitExceptionRef
    > implicitExceptionRefs = new LinkedHashMap<>();
    private final LinkedHashMap<
        String,
        ClassDescriptorRef
    > classDescriptorRefs = new LinkedHashMap<>();
    private final LinkedHashMap<
        String,
        MethodEntryDescriptorRef
    > methodEntryDescriptorRefs = new LinkedHashMap<>();
    private final LinkedHashMap<
        String,
        MethodIdDescriptorRef
    > methodIdDescriptorRefs = new LinkedHashMap<>();
    private int stringCacheCount;
    private boolean cachedFastArrayRaiseHelperRequired;
    private String cachedFastArrayRaiseDispatcherSymbol;

    public CCodeGenerator(long masterSeed) {
        this.symbols = new SymbolTableGenerator(masterSeed);
    }

    public void configureStringCacheCount(int stringCacheCount) {
        this.stringCacheCount = stringCacheCount;
    }

    public int internClass(String internalName) {
        return classSlotIndex.computeIfAbsent(internalName, ignored ->
            classSlotIndex.size()
        );
    }

    public int internMethod(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        String key = owner + "." + name + desc + "/" + (isStatic ? "S" : "V");
        return methodSlotIndex.computeIfAbsent(key, ignored ->
            methodSlotIndex.size()
        );
    }

    public int internField(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        String key = owner + "." + name + desc + "/" + (isStatic ? "S" : "I");
        return fieldSlotIndex.computeIfAbsent(key, ignored ->
            fieldSlotIndex.size()
        );
    }

    public String classSlotName(String internalName) {
        return "g_cls_" + internClass(internalName);
    }

    public String objectArrayKlassBitsSlotName(String internalName) {
        return "g_obj_array_klass_" + internClass(internalName);
    }

    public String classInitializedSlotName(String internalName) {
        return "g_cls_initialized_" + internClass(internalName);
    }

    public String methodSlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_mid_" + internMethod(owner, name, desc, isStatic);
    }

    public String methodPtrSlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_mptr_" + internMethod(owner, name, desc, isStatic);
    }

    public String methodCEntrySlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_mcentry_" + internMethod(owner, name, desc, isStatic);
    }

    public String methodIEntrySlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_mientry_" + internMethod(owner, name, desc, isStatic);
    }

    public String methodHolderSlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_mholder_" + internMethod(owner, name, desc, isStatic);
    }

    public String fieldSlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_fid_" + internField(owner, name, desc, isStatic);
    }

    public String fieldAccessFlagsSlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_access_" + internField(owner, name, desc, isStatic);
    }

    public String fieldOffsetSlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_off_" + internField(owner, name, desc, isStatic);
    }

    public String staticFieldOffsetSlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_static_off_" + internField(owner, name, desc, isStatic);
    }

    public String staticFieldBaseSlotName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        return "g_static_base_" + internField(owner, name, desc, isStatic);
    }

    public String staticFieldDescriptorRefName(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        if (!isStatic) {
            throw new IllegalArgumentException(
                "Static field descriptor requested for instance field: " +
                    owner +
                    "." +
                    name +
                    desc
            );
        }
        String key = owner + "." + name + desc + "/S";
        StaticFieldDescriptorRef ref =
            staticFieldDescriptorRefs.computeIfAbsent(key, ignored ->
                new StaticFieldDescriptorRef(
                    staticFieldDescriptorRefs.size(),
                    owner,
                    name,
                    desc,
                    classSlotName(owner),
                    classInitializedSlotName(owner),
                    fieldSlotName(owner, name, desc, true),
                    staticFieldBaseSlotName(owner, name, desc, true),
                    staticFieldOffsetSlotName(owner, name, desc, true),
                    fieldAccessFlagsSlotName(owner, name, desc, true)
                )
            );
        return ref.symbol();
    }

    public String fieldDescriptorRefName(
        String bindingOwner,
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        registerOwnerFieldReference(bindingOwner, owner, name, desc, isStatic);
        String key = owner + "." + name + desc + "/" + (isStatic ? "S" : "I");
        FieldDescriptorRef ref = fieldDescriptorRefs.computeIfAbsent(
            key,
            ignored ->
                new FieldDescriptorRef(
                    fieldDescriptorRefs.size(),
                    owner,
                    name,
                    desc,
                    isStatic,
                    fieldSlotName(owner, name, desc, isStatic),
                    fieldAccessFlagsSlotName(owner, name, desc, isStatic)
                )
        );
        return ref.symbol();
    }

    public String implicitExceptionRefName(String bindingOwner, String owner) {
        String ctorDesc = "(Ljava/lang/String;)V";
        registerOwnerMethodReference(
            bindingOwner,
            owner,
            "<init>",
            ctorDesc,
            false
        );
        String dispatcher = registerInvokeShape(false, 'V', new char[] { 'L' });
        ImplicitExceptionRef ref = implicitExceptionRefs.computeIfAbsent(
            owner,
            ignored ->
                new ImplicitExceptionRef(
                    implicitExceptionRefs.size(),
                    owner,
                    ctorDesc,
                    classSlotName(owner),
                    methodPtrSlotName(owner, "<init>", ctorDesc, false),
                    methodIEntrySlotName(owner, "<init>", ctorDesc, false),
                    dispatcher
                )
        );
        return ref.symbol();
    }

    public String classDescriptorRefName(
        String bindingOwner,
        String classOwner
    ) {
        registerOwnerClassReference(bindingOwner, classOwner);
        ClassDescriptorRef ref = classDescriptorRefs.computeIfAbsent(
            classOwner,
            ignored ->
                new ClassDescriptorRef(
                    classDescriptorRefs.size(),
                    classOwner,
                    classSlotName(classOwner)
                )
        );
        return ref.symbol();
    }

    public String methodEntryDescriptorRefName(
        String bindingOwner,
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        registerOwnerMethodReference(bindingOwner, owner, name, desc, isStatic);
        String key = owner + "." + name + desc + "/" + (isStatic ? "S" : "V");
        MethodEntryDescriptorRef ref =
            methodEntryDescriptorRefs.computeIfAbsent(key, ignored ->
                new MethodEntryDescriptorRef(
                    methodEntryDescriptorRefs.size(),
                    owner,
                    name,
                    desc,
                    methodPtrSlotName(owner, name, desc, isStatic),
                    methodIEntrySlotName(owner, name, desc, isStatic)
                )
            );
        return ref.symbol();
    }

    public String methodIdDescriptorRefName(
        String bindingOwner,
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        registerOwnerMethodReference(bindingOwner, owner, name, desc, isStatic);
        String key = owner + "." + name + desc + "/" + (isStatic ? "S" : "V");
        MethodIdDescriptorRef ref = methodIdDescriptorRefs.computeIfAbsent(
            key,
            ignored ->
                new MethodIdDescriptorRef(
                    methodIdDescriptorRefs.size(),
                    owner,
                    name,
                    desc,
                    isStatic,
                    methodSlotName(owner, name, desc, isStatic)
                )
        );
        return ref.symbol();
    }

    public void registerBindingOwner(String ownerInternalName) {
        ownerBindIndex.computeIfAbsent(ownerInternalName, ignored ->
            ownerBindIndex.size()
        );
        OwnerResolution resolution = ownerResolutions.computeIfAbsent(
            ownerInternalName,
            ignored -> new OwnerResolution()
        );
        resolution.classes.add(ownerInternalName);
        internClass(ownerInternalName);
    }

    public void registerOwnerClassReference(
        String bindingOwner,
        String classOwner
    ) {
        registerBindingOwner(bindingOwner);
        ownerResolutions.get(bindingOwner).classes.add(classOwner);
        internClass(classOwner);
    }

    public void registerOwnerMethodReference(
        String bindingOwner,
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        registerOwnerClassReference(bindingOwner, owner);
        ownerResolutions
            .get(bindingOwner)
            .methods.add(new MethodRef(owner, name, desc, isStatic));
        internMethod(owner, name, desc, isStatic);
    }

    public void registerOwnerFieldReference(
        String bindingOwner,
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {
        registerOwnerClassReference(bindingOwner, owner);
        ownerResolutions
            .get(bindingOwner)
            .fields.add(new FieldRef(owner, name, desc, isStatic));
        internField(owner, name, desc, isStatic);
    }

    public void registerOwnerStringReference(
        String bindingOwner,
        String value,
        String cacheVar
    ) {
        registerBindingOwner(bindingOwner);
        ownerResolutions
            .get(bindingOwner)
            .strings.add(new StringRef(cacheVar, value));
    }

    public void registerOwnerPrimitiveClassReference(
        String bindingOwner,
        String desc
    ) {
        registerBindingOwner(bindingOwner);
        ownerResolutions.get(bindingOwner).primitiveClasses.add(desc);
        internClass(primitiveClassSlotKey(desc));
    }

    public String ownerStringBindCall(String bindingOwner) {
        registerBindingOwner(bindingOwner);
        return (
            "neko_bind_owner_strings_" +
            ownerBindIndex.get(bindingOwner) +
            "(thread, env);"
        );
    }

    public String primitiveClassSlotName(String desc) {
        return classSlotName(primitiveClassSlotKey(desc));
    }

    public String reserveInvokeCacheSite(
        String bindingOwner,
        String methodKey,
        int siteIndex
    ) {
        String cacheMethodKey = bindingOwner + '#' + methodKey;
        String siteKey = cacheMethodKey + '#' + siteIndex;
        registerBindingOwner(bindingOwner);
        return icacheSites
            .computeIfAbsent(siteKey, ignored ->
                new IcacheSiteRef(
                    ownerBindIndex.get(bindingOwner),
                    icacheMethodIndex.computeIfAbsent(cacheMethodKey, key ->
                        icacheMethodIndex.size()
                    ),
                    siteIndex,
                    bindingOwner,
                    methodKey
                )
            )
            .symbol();
    }

    public String reserveInvokeCacheDirectStub(
        String bindingOwner,
        String methodKey,
        int siteIndex,
        NativeMethodBinding binding,
        Type[] args,
        Type returnType
    ) {
        String cacheMethodKey = bindingOwner + '#' + methodKey;
        String siteKey = cacheMethodKey + '#' + siteIndex;
        registerBindingOwner(bindingOwner);
        return icacheDirectStubs
            .computeIfAbsent(siteKey, ignored ->
                new IcacheDirectStubRef(
                    ownerBindIndex.get(bindingOwner),
                    icacheMethodIndex.computeIfAbsent(cacheMethodKey, key ->
                        icacheMethodIndex.size()
                    ),
                    siteIndex,
                    binding,
                    args.clone(),
                    returnType
                )
            )
            .symbol();
    }

    /** Register an invoke-callee shape with the native→Java dispatcher emitter.
     * Returns the C dispatcher symbol that call sites can use as a function
     * pointer. Idempotent across duplicate shapes. */
    public String registerInvokeShape(SignaturePlan.Shape shape) {
        return nativeToJavaInvokeEmitter.register(shape);
    }

    /** Returns the dispatcher symbol for the given (isStatic, ret, args)
     * tuple, registering it if not already present. Convenience for callers
     * that don't already have a SignaturePlan.Shape on hand. */
    public String registerInvokeShape(
        boolean isStatic,
        char returnKind,
        char[] argKinds
    ) {
        return nativeToJavaInvokeEmitter.register(
            SignaturePlan.Shape.of(returnKind, argKinds, isStatic)
        );
    }

    public String requireCachedFastArrayRaiseHelper(String bindingOwner) {
        String ctorDesc = "(Ljava/lang/String;)V";
        registerOwnerMethodReference(
            bindingOwner,
            "java/lang/NullPointerException",
            "<init>",
            ctorDesc,
            false
        );
        registerOwnerMethodReference(
            bindingOwner,
            "java/lang/ArrayIndexOutOfBoundsException",
            "<init>",
            ctorDesc,
            false
        );
        cachedFastArrayRaiseDispatcherSymbol = registerInvokeShape(
            false,
            'V',
            new char[] { 'L' }
        );
        cachedFastArrayRaiseHelperRequired = true;
        return "neko_raise_cached_fast_array_reason";
    }

    private void registerPrimitiveBoxingInvokeShapes() {
        registerInvokeShape(true, 'L', new char[] { 'I' });
        registerInvokeShape(true, 'L', new char[] { 'J' });
        registerInvokeShape(true, 'L', new char[] { 'F' });
        registerInvokeShape(true, 'L', new char[] { 'D' });
        /* TLAB-NULL fix: ensure neko_njx_V_L_L (instance, return L, args [L])
         * is always emitted so the String.concat NJX fallback path in
         * neko_require_fast_string_concat compiles even when obfuscated
         * bytecode happens not to need this shape on its own. */
        registerInvokeShape(false, 'L', new char[] { 'L' });
        /* Raw-disabled string literal binding uses VM-managed allocation plus
         * java.lang.String(byte[],byte) through NJX so ZGC/Shenandoah field
         * stores stay inside HotSpot's normal barriers. */
        registerInvokeShape(false, 'V', new char[] { 'L', 'I' });
        /* MethodType.fromMethodDescriptorString(String, ClassLoader) is
         * invoked from bootstrap metadata binding without JNI CallStatic*. */
        registerInvokeShape(true, 'L', new char[] { 'L', 'L' });
        /* MethodType.parameterArray() is an instance no-arg object return. */
        registerInvokeShape(false, 'L', new char[] {});
        /* Bootstrap reflection uses Class.getDeclaredMethod and Method.invoke
         * through instance object/object-array call-stub shapes. */
        registerInvokeShape(false, 'L', new char[] { 'L', 'L' });
        /* AccessibleObject.setAccessible(boolean) is a void instance call;
         * small primitive arguments use the collapsed integer NJX shape. */
        registerInvokeShape(false, 'V', new char[] { 'I' });
        /* StackTraceElement.<init>(String,String,String,int) is invoked from
         * the shadow stack trace intrinsic without JNI NewObjectA. */
        registerInvokeShape(false, 'V', new char[] { 'L', 'L', 'L', 'I' });
    }

    public String reserveInvokeCacheMeta(
        String bindingOwner,
        String methodKey,
        int siteIndex,
        String name,
        String desc,
        boolean isInterface,
        String translatedClassSlot,
        String translatedStubSymbol,
        String directDispatcherSymbol
    ) {
        String cacheMethodKey = bindingOwner + '#' + methodKey;
        String siteKey = cacheMethodKey + '#' + siteIndex;
        registerBindingOwner(bindingOwner);
        return icacheMetas
            .computeIfAbsent(siteKey, ignored ->
                new IcacheMetaRef(
                    ownerBindIndex.get(bindingOwner),
                    icacheMethodIndex.computeIfAbsent(cacheMethodKey, key ->
                        icacheMethodIndex.size()
                    ),
                    siteIndex,
                    name,
                    desc,
                    isInterface,
                    translatedClassSlot,
                    translatedStubSymbol,
                    directDispatcherSymbol
                )
            )
            .symbol();
    }

    public String generateHeader(List<NativeMethodBinding> bindings) {
        StringBuilder sb = new StringBuilder();
        sb.append("#ifndef NEKO_NATIVE_H\n");
        sb.append("#define NEKO_NATIVE_H\n\n");
        sb.append("#include <jni.h>\n\n");
        sb.append("\n#endif\n");
        return sb.toString();
    }

    public String generateSource(
        List<CFunction> functions,
        List<NativeMethodBinding> bindings
    ) {
        StringBuilder body = new StringBuilder();
        for (CFunction function : functions) {
            body.append(renderRawFunction(function)).append("\n");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("#define _POSIX_C_SOURCE 199309L\n");
        sb.append("#include \"neko_native.h\"\n");
        sb.append("#include <stddef.h>\n");
        sb.append("#include <stdint.h>\n");
        sb.append("#include <stdio.h>\n");
        sb.append("#include <stdlib.h>\n");
        sb.append("#include <string.h>\n");
        sb.append("#include <math.h>\n");
        sb.append("#include <time.h>\n\n");
        sb.append("static void neko_post_blocking_call_yield(void) {\n");
        sb.append("#if defined(_WIN32)\n");
        sb.append("    /* Windows backend does not use this helper yet. */\n");
        sb.append("#else\n");
        sb.append(
            "    struct timespec ts; ts.tv_sec = 0; ts.tv_nsec = 1000000L;\n"
        );
        sb.append("    nanosleep(&ts, NULL);\n");
        sb.append("#endif\n");
        sb.append("}\n\n");
        SignaturePlan signaturePlan = SignaturePlan.build(bindings);
        registerPrimitiveBoxingInvokeShapes();
        /* Forward decls + manifest struct first; everything below references them. */
        sb.append(manifestEmitter.renderStructAndForwardDecls());
        sb.append("/* Forward decls for trampoline ↔ patcher coupling. */\n");
        sb.append("struct neko_sig_entry { void *i2i; void *c2i; };\n");
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern const struct neko_sig_entry g_neko_sig_table[];\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern const uint32_t g_neko_sig_table_count;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern const uint32_t g_neko_sig_extraspace_words[];\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void * const g_neko_sig_i2i_path2[];\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern ptrdiff_t g_neko_off_thread_state;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern int32_t   g_neko_thread_state_in_java;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern int32_t   g_neko_thread_state_in_native;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern int32_t   g_neko_thread_state_in_native_trans;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern ptrdiff_t g_neko_off_thread_polling_word;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern jboolean  g_neko_thread_state_ready;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern ptrdiff_t g_neko_off_last_Java_sp;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern ptrdiff_t g_neko_off_last_Java_fp;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern ptrdiff_t g_neko_off_last_Java_pc;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern jboolean  g_neko_frame_anchor_ready;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern jboolean  g_neko_handle_push_ready;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern jboolean  g_neko_native_resolution_ready;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern jboolean  g_neko_gc_barrier_ready;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern int32_t   g_neko_gc_barrier_kind;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_addr_compressed_oops_base;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_addr_compressed_oops_shift;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_addr_compressed_klass_base;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_addr_compressed_klass_shift;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_barrier_load_oop_field_preloaded;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_barrier_load_oop_array;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_barrier_store_oop_field;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_barrier_write_ref_array_pre;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_barrier_write_ref_field_pre;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_barrier_write_ref_field_post;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void     *g_neko_card_table_byte_map_base;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern int32_t   g_neko_card_table_dirty_card;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern int32_t   g_neko_card_table_clean_card;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern int32_t   g_neko_g1_young_card;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern int32_t   g_neko_card_table_shift;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern ptrdiff_t g_neko_off_thread_pending_exception;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) void neko_handle_safepoint_poll(void);\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void neko_ensure_class_initialized_once(JNIEnv *env, jclass cls, const char *owner, volatile jboolean *slot);\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern jclass neko_bound_class(JNIEnv *env, jclass slot, const char *owner);\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern jfieldID neko_bound_field(JNIEnv *env, jfieldID slot, const char *owner, const char *name, const char *desc, jboolean isStatic);\n"
        );
        /* The save/restore/push helpers and neko_thread_jni_env / neko_jni_env_to_thread
         * are defined as `static inline __attribute__((always_inline))` further
         * down (inside the methodPatcherEmitter region). No extern declarations
         * here — extern would shadow the inline definitions and force the
         * dispatcher to make a real function call. */
        sb.append(
            "typedef struct { void *thread; void *block; void *saved_next; void *saved_last; int32_t saved_top; void *prev_scope; void *scope_slabs; char *scope_cursor; char *scope_end; } neko_handle_save_t;\n"
        );
        /* T4.6 — neko_handle_save / _restore are defined inline in
         * methodPatcherEmitter (rendered later). The T4.6 window primitives
         * in JniHandlesShimEmitter (rendered earlier) call into them, so
         * forward-declare here. */
        sb.append(
            "static inline __attribute__((always_inline)) void neko_handle_save(void *thread, neko_handle_save_t *save);\n"
        );
        sb.append(
            "static inline __attribute__((always_inline)) void neko_handle_restore(neko_handle_save_t *save);\n"
        );
        sb.append("static jboolean neko_resolve_jnihandles(void *jvm);\n");
        sb.append("static void *neko_dlsym(void *h, const char *name);\n");
        sb.append("static void *neko_class_mirror_to_klass(jclass mirror);\n");
        sb.append("static void *neko_object_handle_klass(jobject obj);\n");
        sb.append(
            "static void *neko_resolve_method(void *instance_klass, const char *name_utf8, const char *sig_utf8);\n"
        );
        sb.append(
            "static void *neko_bound_method_i_entry(void *methodPtr, void **entrySlot, const char *owner, const char *name, const char *desc);\n"
        );
        sb.append(
            "static void neko_ensure_class_initialized(JNIEnv *env, jclass cls, const char *owner);\n"
        );
        sb.append("static inline void *neko_jni_env_to_thread(JNIEnv *env);\n");
        sb.append(
            "static void *neko_intern_string(void *thread, JNIEnv *env, const uint8_t *modutf, size_t len);\n"
        );
        sb.append(
            "static void *neko_resolve_declared_covariant_ref_method(void *instance_klass, const char *name_utf8, const char *sig_utf8);\n"
        );
        sb.append(
            "static void neko_link_class_methods(JNIEnv *env, jclass cls, const char *owner, const char *name, const char *desc);\n"
        );
        sb.append(
            "static jobject neko_klass_java_mirror_handle(void *thread, void *klass);\n"
        );
        sb.append("static uintptr_t neko_klass_header_bits(void *klass);\n");
        sb.append(
            "static void *neko_decode_klass_header_bits(uintptr_t bits);\n"
        );
        sb.append("static void neko_njx_init_wrappers(void);\n\n");
        /* T4.7: neko_fast_string_runtime_init forward decl removed; the
         * probe function is deleted and neko_method_layout_init now drives
         * the VMStructs path neko_ensure_string_alloc_bits directly. */
        sb.append("static void neko_ensure_string_alloc_bits(JNIEnv *env);\n");
        /* TLAB-NULL fix: cache helper for the String.concat NJX fallback. */
        sb.append(
            "static void neko_ensure_string_concat_njx_cache(JNIEnv *env, void *string_klass);\n"
        );
        sb.append(
            "static void neko_ensure_unsafe_allocate_instance_njx_cache(JNIEnv *env);\n"
        );
        sb.append(
            "static void *neko_intern_string_without_raw_heap(void *thread, JNIEnv *env, const char *modutf, size_t len);\n"
        );
        /* T4.8: captured JNI NewGlobalRef / DeleteGlobalRef function pointers,
         * populated once at JNI_OnLoad (see JniHandlesShimEmitter). Bind-time
         * global-ref allocation/release routes through these typed pointers
         * instead of inline JNI function-table indexing for indices 21 / 22.
         * Production HotSpot 21 strips the C++ `JNIHandles::make_global`
         * symbol so plain dlsym is unavailable; capturing the function-table
         * entry once is the equivalent libjvm-internal entry point. */
        sb.append(
            "typedef jobject (*neko_jni_new_global_ref_fn_t)(JNIEnv*, jobject);\n"
        );
        sb.append(
            "typedef void    (*neko_jni_delete_global_ref_fn_t)(JNIEnv*, jobject);\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_new_global_ref_fn_t   g_neko_jni_new_global_ref_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_delete_global_ref_fn_t g_neko_jni_delete_global_ref_fn;\n"
        );
        sb.append("static void neko_capture_global_ref_fns(void);\n");
        /* T4.3 / T4.4 / T4.5 — captured pointers for the bind-time MethodType /
         * MethodHandles.lookup / Throwable.getStackTrace helpers (production
         * HotSpot 21 strips the C++ symbols, so dlsym is unreachable). The
         * actual pointer storage lives in JniHandlesShimEmitter. */
        sb.append(
            "typedef void      (*neko_jni_delete_local_ref_fn_t)(JNIEnv*, jobject);\n"
        );
        sb.append(
            "typedef jstring   (*neko_jni_new_string_utf_fn_t)(JNIEnv*, const char*);\n"
        );
        sb.append(
            "typedef jobject   (*neko_jni_call_object_method_a_fn_t)(JNIEnv*, jobject, jmethodID, const jvalue*);\n"
        );
        sb.append(
            "typedef void      (*neko_jni_call_void_method_a_fn_t)(JNIEnv*, jobject, jmethodID, const jvalue*);\n"
        );
        sb.append(
            "typedef jobject   (*neko_jni_call_static_object_method_a_fn_t)(JNIEnv*, jclass, jmethodID, const jvalue*);\n"
        );
        sb.append(
            "typedef jobject   (*neko_jni_new_object_a_fn_t)(JNIEnv*, jclass, jmethodID, const jvalue*);\n"
        );
        sb.append(
            "typedef jsize     (*neko_jni_get_array_length_fn_t)(JNIEnv*, jarray);\n"
        );
        sb.append(
            "typedef jobjectArray (*neko_jni_new_object_array_fn_t)(JNIEnv*, jsize, jclass, jobject);\n"
        );
        sb.append(
            "typedef void      (*neko_jni_set_object_array_element_fn_t)(JNIEnv*, jobjectArray, jsize, jobject);\n"
        );
        sb.append(
            "typedef jobject   (*neko_jni_get_object_array_element_fn_t)(JNIEnv*, jobjectArray, jsize);\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_delete_local_ref_fn_t            g_neko_jni_delete_local_ref_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_new_string_utf_fn_t              g_neko_jni_new_string_utf_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_call_object_method_a_fn_t        g_neko_jni_call_object_method_a_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_call_void_method_a_fn_t          g_neko_jni_call_void_method_a_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_call_static_object_method_a_fn_t g_neko_jni_call_static_object_method_a_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_new_object_a_fn_t                g_neko_jni_new_object_a_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_get_array_length_fn_t            g_neko_jni_get_array_length_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_new_object_array_fn_t            g_neko_jni_new_object_array_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_set_object_array_element_fn_t    g_neko_jni_set_object_array_element_fn;\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern neko_jni_get_object_array_element_fn_t    g_neko_jni_get_object_array_element_fn;\n"
        );
        sb.append("static void neko_capture_bind_time_jni_fns(void);\n");
        sb.append("static void neko_boxing_cache_init(JNIEnv *env);\n\n");
        /* T4.1: cross-block forward declarations for the primitive descriptor →
         * mirror table. Storage lives in renderRuntimeSupport (so the inline
         * neko_class_for_descriptor switch arms can read it without
         * cross-block extern hoops); the populating init function and the
         * wrapper-class TYPE-field read live in renderHotSpotFastAccessHelpers
         * where the g_hotspot compressed-oops state and the neko_decode_narrow_oop
         * / neko_barrier_load_oop_field helpers are visible. The init function is
         * driven by JniOnLoadEmitter once neko_hotspot_init has populated the
         * compressed-oops fields of g_hotspot. */
        sb.append(
            "static void neko_primitive_mirror_table_init(JNIEnv *env);\n"
        );
        sb.append(
            "static jclass neko_primitive_mirror_for_char(JNIEnv *env, char tag);\n\n"
        );
        sb.append(
            "static uintptr_t neko_array_klass_bits_for_descriptor(JNIEnv *env, const char *arrayDesc, jclass fromClass);\n"
        );
        sb.append(
            "static jobject neko_fast_alloc_object(void *thread, JNIEnv *env, jclass cls);\n"
        );
        sb.append(
            "static jobjectArray neko_fast_new_object_array(void *thread, JNIEnv *env, jint len, uintptr_t klass_bits, jobject init);\n"
        );
        sb.append(
            "static jarray neko_fast_new_primitive_array(void *thread, JNIEnv *env, jint len, int kind);\n"
        );
        sb.append(
            "static jint neko_fast_array_length(jarray arr);\n"
        );
        sb.append(
            "static jobject neko_fast_aaload(void *thread, JNIEnv *env, jobjectArray arr, jint idx);\n"
        );
        sb.append(
            "static void neko_fast_aastore(void *thread, JNIEnv *env, jobjectArray arr, jint idx, jobject val);\n\n"
        );
        sb.append(
            "static void neko_refill_tlab_with_slow_byte_array(JNIEnv *env, jint min_payload_len);\n"
        );
        sb.append(
            "static jarray neko_alloc_primitive_array_slow(JNIEnv *env, jint len, int kind);\n"
        );
        sb.append(
            "static char *neko_alloc_jbyte_array_oop_slow(JNIEnv *env, jint len, jarray *local_ref_out);\n\n"
        );
        sb.append(renderResolutionCaches());
        sb.append(renderRawFunctionPrototypes(bindings));
        sb.append(nativeToJavaInvokeEmitter.renderPrelude());
        sb.append(renderImplicitExceptionRefs());
        sb.append(NativeRuntimeSupportEmitter.renderRuntimeSupport());
        sb.append(NativeRuntimeSupportEmitter.renderHotSpotSupport());
        sb.append(
            NativeHotSpotFastAccessEmitter.renderHotSpotFastAccessHelpers()
        );
        sb.append(jniHandlesShimEmitter.render());
        sb.append(methodPatcherEmitter.render());
        /* Fast AALOAD helper: piggy-backs on methodPatcherEmitter's inline
         * neko_handle_push, so it has to come right after. Available to every
         * impl_fn / export wrapper / dispatcher emitted below. */
        sb.append(NativeFastObjectAccessEmitter.renderObjectArrayFastHelpers());
        /* Native→Java direct invoke dispatcher bodies — must come AFTER
         * methodPatcherEmitter (uses g_neko_call_stub_entry / g_neko_off_*
         * globals it publishes) and AFTER renderObjectArrayFastHelpers
         * (uses neko_direct_oop_to_handle for object-return marshalling). */
        sb.append(nativeToJavaInvokeEmitter.renderBodies());
        sb.append(nativeToJavaInvokeEmitter.renderInitFunction());
        sb.append(NativeBindSupportEmitter.renderBindSupport());
        sb.append(renderCachedFastArrayRaiseHelper());
        sb.append(renderImplicitExceptionRefHelper());
        sb.append(NativeStringSupportEmitter.renderStringTableInternSupport());
        /* T4.2a — emit the tolerant class-mirror resolver right after
         * renderBindSupport so it can reuse the resolver typedefs and
         * neko_resolve_loaded_class_by_name / neko_jni_env_to_thread /
         * neko_klass_java_mirror_handle helpers defined there.
         *
         * Kept in its own method to avoid pushing renderBindSupport's text
         * block over the JVM 65535-byte string-literal constant pool limit
         * (renderBindSupport is already ~1500 lines of inlined C). */
        sb.append(NativeBindSupportEmitter.renderTolerantClassResolver());
        /* TLAB-NULL fix: emit the String.concat NJX cache helper after
         * renderBindSupport so it can call neko_resolve_method and
         * neko_bound_method_i_entry directly. */
        sb.append(NativeStringSupportEmitter.renderStringConcatNjxCache());
        /* T4.2b — emit the strict klass-based jmethodID resolver in its
         * own helper; covers both static and instance methods because
         * neko_resolve_method does not distinguish by access flags. */
        sb.append(NativeMethodResolutionEmitter.renderResolveJMethodID());
        /* T4.1 — emit AFTER renderBindSupport so the init function can use
         * neko_resolve_class_with_env, neko_resolve_field, and the
         * neko_field_resolution_t typedef defined there. */
        sb.append(NativePrimitiveMirrorEmitter.renderPrimitiveMirrorSupport());
        sb.append(NativeBoxingSupportEmitter.renderBoxingSupport());
        sb.append(jniOnLoadEmitter.renderRegistrationTable());
        sb.append(renderBindOwnerFunctions());
        sb.append(renderIcacheDirectStubs());
        sb.append(renderIcacheMetas());
        sb.append(IMPL_BEGIN_MARKER).append('\n');
        sb.append(body);
        sb.append(IMPL_END_MARKER).append('\n');
        sb.append(manifestEmitter.renderTables(bindings, signaturePlan));
        sb.append(signatureDispatcherEmitter.render(signaturePlan));
        sb.append(trampolineEmitter.render(signaturePlan));
        sb.append(
            manifestEmitter.renderDiscoveryDriver(bindings, ownerBindIndex)
        );
        sb.append(jniOnLoadEmitter.renderJniOnLoadAndBootstrap());
        return sb.toString();
    }

    public GeneratedSourceSet generateSourceSet(
        List<CFunction> functions,
        List<NativeMethodBinding> bindings
    ) {
        String monolithic = generateSource(functions, bindings);
        int begin = monolithic.indexOf(IMPL_BEGIN_MARKER);
        int end = monolithic.indexOf(IMPL_END_MARKER);
        if (begin < 0 || end < begin) {
            throw new IllegalStateException(
                "Generated source is missing translated implementation markers"
            );
        }

        String prefix = monolithic.substring(
            0,
            begin + IMPL_BEGIN_MARKER.length() + 1
        );
        String suffix = monolithic.substring(end);
        Set<String> supportFunctionNames = topLevelSupportFunctionDefinitions(
            prefix
        );
        String baseSupportSource = exportSupportDefinitions(
            externalizeRawFunctionPrototypes(prefix),
            supportFunctionNames
        );
        String implPrelude = renderImplementationContractHeader(
            externalizeGlobalDefinitions(
                externalizeRawFunctionPrototypes(prefix)
            ),
            supportFunctionNames
        );
        String implHeaderSource =
            "#ifndef NEKO_NATIVE_IMPL_PRELUDE_H\n" +
            "#define NEKO_NATIVE_IMPL_PRELUDE_H\n" +
            "#define NEKO_NATIVE_IMPL_PRELUDE_LOADED 1\n" +
            implPrelude +
            "\n#endif\n";
        List<GeneratedSourceFile> baseSupportSources = splitBaseSupportSources(
            baseSupportSource
        );
        List<GeneratedSourceFile> lateSupportSources = splitLateSupportSources(
            suffix
        );
        List<GeneratedSourceFile> supportSources = new ArrayList<>();
        supportSources.addAll(
            baseSupportSources.subList(1, baseSupportSources.size())
        );
        supportSources.addAll(lateSupportSources);

        List<GeneratedSourceFile> implementationSources = new ArrayList<>();
        List<GeneratedSourceFile> implementationHeaders = new ArrayList<>();
        int chunkIndex = 0;
        for (int startIndex = 0; startIndex < functions.size(); ) {
            int finish = implementationChunkEnd(functions, startIndex);
            StringBuilder body = new StringBuilder();
            body.append("/* NEKO_IMPL_CHUNK ")
                .append(chunkIndex)
                .append(" methods ")
                .append(startIndex)
                .append("..")
                .append(finish - 1)
                .append(" */\n");
            for (int i = startIndex; i < finish; i++) {
                body.append(
                    externalizeRawFunctionDefinition(
                        renderRawFunction(functions.get(i))
                    )
                ).append('\n');
            }
            body.append(IMPL_END_MARKER).append('\n');

            String implHeaderName =
                "neko_native_impl_" + chunkIndex + "_prelude.h";
            implementationHeaders.add(
                new GeneratedSourceFile(
                    implHeaderName,
                    renderSlicedImplementationHeader(
                        implHeaderSource,
                        body.toString()
                    )
                )
            );

            StringBuilder impl = new StringBuilder(body.length() + 192);
            impl.append("#include \"").append(implHeaderName).append("\"\n");
            impl.append("#ifndef NEKO_NATIVE_IMPL_PRELUDE_LOADED\n");
            impl.append("#error \"")
                .append(implHeaderName)
                .append(
                    " must be included before this implementation unit\"\n"
                );
            impl.append("#endif\n");
            impl.append(body);
            implementationSources.add(
                new GeneratedSourceFile(
                    "neko_native_impl_" + chunkIndex + ".c",
                    impl.toString()
                )
            );
            chunkIndex++;
            startIndex = finish;
        }

        return new GeneratedSourceSet(
            baseSupportSources.get(0),
            supportSources,
            new GeneratedSourceFile(
                "neko_native_impl_prelude.h",
                implHeaderSource
            ),
            implementationHeaders,
            implementationSources,
            monolithic
        );
    }

    private String renderSlicedImplementationHeader(
        String fullHeaderSource,
        String implementationBody
    ) {
        List<String> headerLines = fullHeaderSource.lines().toList();
        Set<String> referencedIdentifiers = slicedContractReferences(
            headerLines,
            referencedIdentifiers(implementationBody)
        );
        StringBuilder out = new StringBuilder(fullHeaderSource.length());
        for (String line : fullHeaderSource.split("\\n", -1)) {
            if (
                !line.isEmpty() &&
                isUnusedSlicedContractLine(line, referencedIdentifiers)
            ) {
                continue;
            }
            out.append(line).append('\n');
        }
        return out.toString();
    }

    private Set<String> slicedContractReferences(
        List<String> headerLines,
        Set<String> initialReferences
    ) {
        Set<String> references = new LinkedHashSet<>(initialReferences);
        boolean changed;
        do {
            changed = false;
            for (String line : headerLines) {
                if (
                    line.isEmpty() ||
                    isUnusedSlicedContractLine(line, references)
                ) {
                    continue;
                }
                for (String identifier : referencedIdentifiers(line)) {
                    changed |= references.add(identifier);
                }
            }
        } while (changed);
        return references;
    }

    private Set<String> referencedIdentifiers(String source) {
        Set<String> identifiers = new LinkedHashSet<>();
        Matcher matcher = C_IDENTIFIER_PATTERN.matcher(source);
        while (matcher.find()) {
            identifiers.add(matcher.group());
        }
        return identifiers;
    }

    private boolean isUnusedSlicedContractLine(
        String line,
        Set<String> referencedIdentifiers
    ) {
        Matcher define = SLICED_CONTRACT_DEFINE_PATTERN.matcher(line);
        if (define.find()) {
            return !referencedIdentifiers.contains(define.group(1));
        }
        if (line.startsWith("#define")) {
            return false;
        }
        Matcher extern = SLICED_CONTRACT_EXTERN_PATTERN.matcher(line);
        boolean sawSlicedIdentifier = false;
        while (extern.find()) {
            sawSlicedIdentifier = true;
            if (referencedIdentifiers.contains(extern.group())) {
                return false;
            }
        }
        return sawSlicedIdentifier;
    }

    private List<GeneratedSourceFile> splitBaseSupportSources(String source) {
        String ownerMarker = "// === Bind-time owner resolution ===";
        String directIcacheMarker = "// === Inline-cache direct-call stubs ===";
        String metaIcacheMarker = "// === Inline-cache metadata ===";
        int ownerStart = source.indexOf(ownerMarker);
        int icacheStart = minPresent(
            source.indexOf(directIcacheMarker),
            source.indexOf(metaIcacheMarker)
        );
        int firstShardStart = minPresent(ownerStart, icacheStart);
        GlobalSupportSplit globalSplit = splitSupportGlobalDefinitions(
            source,
            firstShardStart >= 0 ? firstShardStart : source.length()
        );
        source = globalSplit.mainSource();
        ownerStart = source.indexOf(ownerMarker);
        icacheStart = minPresent(
            source.indexOf(directIcacheMarker),
            source.indexOf(metaIcacheMarker)
        );
        firstShardStart = minPresent(ownerStart, icacheStart);
        if (firstShardStart < 0) {
            SupportFunctionSplit functionSplit =
                splitSupportFunctionDefinitions(source);
            if (globalSplit.globalSource().isEmpty()) {
                List<GeneratedSourceFile> onlySources = new ArrayList<>();
                onlySources.add(
                    new GeneratedSourceFile(
                        "neko_native_support.c",
                        functionSplit.mainSource()
                    )
                );
                onlySources.addAll(functionSplit.helperSources());
                return List.copyOf(onlySources);
            }
            List<GeneratedSourceFile> onlySources = new ArrayList<>();
            onlySources.add(
                new GeneratedSourceFile(
                    "neko_native_support.c",
                    functionSplit.mainSource()
                )
            );
            onlySources.add(
                new GeneratedSourceFile(
                    "neko_native_globals.c",
                    supportShardSource(globalSplit.globalSource())
                )
            );
            onlySources.addAll(functionSplit.helperSources());
            return List.copyOf(onlySources);
        }

        List<GeneratedSourceFile> sources = new ArrayList<>();
        SupportFunctionSplit functionSplit = splitSupportFunctionDefinitions(
            source.substring(0, firstShardStart)
        );
        sources.add(
            new GeneratedSourceFile(
                "neko_native_support.c",
                functionSplit.mainSource()
            )
        );
        if (!globalSplit.globalSource().isEmpty()) {
            sources.add(
                new GeneratedSourceFile(
                    "neko_native_globals.c",
                    supportShardSource(globalSplit.globalSource())
                )
            );
        }
        sources.addAll(functionSplit.helperSources());
        if (ownerStart >= 0 && (icacheStart < 0 || ownerStart < icacheStart)) {
            int ownerEnd = icacheStart >= 0 ? icacheStart : source.length();
            String ownerShard = source.substring(ownerStart, ownerEnd);
            if (!ownerShard.isBlank()) {
                sources.add(
                    new GeneratedSourceFile(
                        "neko_native_owner_bindings.c",
                        supportShardSource(ownerShard)
                    )
                );
            }
        }
        if (icacheStart >= 0) {
            String icacheShard = source.substring(icacheStart);
            if (!icacheShard.isBlank()) {
                sources.add(
                    new GeneratedSourceFile(
                        "neko_native_icache_support.c",
                        supportShardSource(icacheShard)
                    )
                );
            }
        }
        return List.copyOf(sources);
    }

    private SupportFunctionSplit splitSupportFunctionDefinitions(
        String source
    ) {
        StringBuilder main = new StringBuilder(source.length());
        List<GeneratedSourceFile> helpers = new ArrayList<>();
        StringBuilder shard = new StringBuilder(source.length() / 4);
        int shardIndex = 0;
        int shardFunctions = 0;
        StringBuilder pendingSignature = null;
        StringBuilder pendingFunction = null;
        int functionBraceDepth = 0;
        int preprocessorDepth = 0;

        for (String line : source.lines().toList()) {
            if (pendingFunction != null) {
                pendingFunction.append('\n').append(line);
                functionBraceDepth += braceDelta(line);
                if (functionBraceDepth <= 0) {
                    shard.append(pendingFunction).append('\n');
                    shardFunctions++;
                    if (shardFunctions >= MAX_SUPPORT_HELPERS_PER_SOURCE) {
                        helpers.add(
                            new GeneratedSourceFile(
                                "neko_native_support_helpers_" +
                                    shardIndex++ +
                                    ".c",
                                supportShardSource(shard.toString())
                            )
                        );
                        shard.setLength(0);
                        shardFunctions = 0;
                    }
                    pendingFunction = null;
                }
                continue;
            }
            String trimmed = line.trim();
            if (isPreprocessorConditionDirective(trimmed)) {
                main.append(line).append('\n');
                preprocessorDepth = updatePreprocessorDepth(
                    trimmed,
                    preprocessorDepth
                );
                continue;
            }
            if (preprocessorDepth > 0) {
                main.append(line).append('\n');
                continue;
            }
            if (pendingSignature != null) {
                pendingSignature.append('\n').append(line);
                if (pendingSignature.indexOf("{") >= 0) {
                    String signature = pendingSignature.toString();
                    String declaration = hiddenSupportFunctionDeclaration(
                        signature
                    );
                    if (declaration != null) {
                        main.append(declaration).append('\n');
                        pendingFunction = new StringBuilder(signature);
                        functionBraceDepth = braceDelta(signature);
                        if (functionBraceDepth <= 0) {
                            shard.append(pendingFunction).append('\n');
                            shardFunctions++;
                            if (
                                shardFunctions >= MAX_SUPPORT_HELPERS_PER_SOURCE
                            ) {
                                helpers.add(
                                    new GeneratedSourceFile(
                                        "neko_native_support_helpers_" +
                                            shardIndex++ +
                                            ".c",
                                        supportShardSource(shard.toString())
                                    )
                                );
                                shard.setLength(0);
                                shardFunctions = 0;
                            }
                            pendingFunction = null;
                        }
                    } else {
                        main.append(signature).append('\n');
                    }
                    pendingSignature = null;
                } else if (line.contains(";")) {
                    main.append(pendingSignature).append('\n');
                    pendingSignature = null;
                }
                continue;
            }

            String functionName = topLevelSupportFunctionName(line);
            if (functionName != null) {
                if (line.contains("{")) {
                    String declaration = hiddenSupportFunctionDeclaration(line);
                    if (declaration != null) {
                        main.append(declaration).append('\n');
                        pendingFunction = new StringBuilder(line);
                        functionBraceDepth = braceDelta(line);
                        if (functionBraceDepth <= 0) {
                            shard.append(pendingFunction).append('\n');
                            shardFunctions++;
                            if (
                                shardFunctions >= MAX_SUPPORT_HELPERS_PER_SOURCE
                            ) {
                                helpers.add(
                                    new GeneratedSourceFile(
                                        "neko_native_support_helpers_" +
                                            shardIndex++ +
                                            ".c",
                                        supportShardSource(shard.toString())
                                    )
                                );
                                shard.setLength(0);
                                shardFunctions = 0;
                            }
                            pendingFunction = null;
                        }
                        continue;
                    }
                } else if (!line.contains(";")) {
                    pendingSignature = new StringBuilder(line);
                    continue;
                }
            }
            main.append(line).append('\n');
        }
        if (pendingSignature != null) {
            main.append(pendingSignature).append('\n');
        }
        if (pendingFunction != null) {
            shard.append(pendingFunction).append('\n');
            shardFunctions++;
        }
        if (shardFunctions > 0) {
            helpers.add(
                new GeneratedSourceFile(
                    "neko_native_support_helpers_" + shardIndex + ".c",
                    supportShardSource(shard.toString())
                )
            );
        }
        return new SupportFunctionSplit(main.toString(), List.copyOf(helpers));
    }

    private boolean isPreprocessorConditionDirective(String trimmedLine) {
        return (
            trimmedLine.startsWith("#if ") ||
            trimmedLine.startsWith("#if\t") ||
            trimmedLine.startsWith("#ifdef ") ||
            trimmedLine.startsWith("#ifdef\t") ||
            trimmedLine.startsWith("#ifndef ") ||
            trimmedLine.startsWith("#ifndef\t") ||
            trimmedLine.startsWith("#elif ") ||
            trimmedLine.startsWith("#elif\t") ||
            trimmedLine.equals("#else") ||
            trimmedLine.startsWith("#else ") ||
            trimmedLine.equals("#endif") ||
            trimmedLine.startsWith("#endif ")
        );
    }

    private int updatePreprocessorDepth(String trimmedLine, int currentDepth) {
        if (
            trimmedLine.startsWith("#if ") ||
            trimmedLine.startsWith("#if\t") ||
            trimmedLine.startsWith("#ifdef ") ||
            trimmedLine.startsWith("#ifdef\t") ||
            trimmedLine.startsWith("#ifndef ") ||
            trimmedLine.startsWith("#ifndef\t")
        ) {
            return currentDepth + 1;
        }
        if (trimmedLine.equals("#endif") || trimmedLine.startsWith("#endif ")) {
            return Math.max(0, currentDepth - 1);
        }
        return currentDepth;
    }

    private GlobalSupportSplit splitSupportGlobalDefinitions(
        String source,
        int scanEnd
    ) {
        StringBuilder main = new StringBuilder(source.length());
        StringBuilder globals = new StringBuilder(source.length() / 4);
        int index = 0;
        while (index < source.length()) {
            int lineEnd = source.indexOf('\n', index);
            if (lineEnd < 0) {
                lineEnd = source.length();
            }
            String line = source.substring(index, lineEnd);
            String extern =
                index < scanEnd ? movableSupportGlobalDeclaration(line) : null;
            if (extern != null) {
                main.append(extern).append('\n');
                globals.append(line).append('\n');
            } else {
                main.append(line);
                if (lineEnd < source.length()) {
                    main.append('\n');
                }
            }
            index = lineEnd + 1;
        }
        return new GlobalSupportSplit(main.toString(), globals.toString());
    }

    private String movableSupportGlobalDeclaration(String line) {
        if (
            !line.startsWith("__attribute__((visibility(\"hidden\"))) ") ||
            !line.contains(" g_") ||
            !line.contains("=") ||
            !line.contains(";")
        ) {
            return null;
        }
        if (
            line.contains("{") ||
            line.contains("}") ||
            declarationHead(line).contains("(")
        ) {
            return null;
        }
        return externGlobalDeclaration(line);
    }

    private int minPresent(int... values) {
        int min = -1;
        for (int value : values) {
            if (value >= 0 && (min < 0 || value < min)) {
                min = value;
            }
        }
        return min;
    }

    private List<GeneratedSourceFile> splitLateSupportSources(String suffix) {
        String dispatcherMarker =
            "/* === Per-signature direct-C dispatchers === */";
        String trampolineMarker = "/* === Per-signature trampolines === */";
        String discoveryMarker = "/* === Discovery + patch driver === */";
        int dispatcherStart = suffix.indexOf(dispatcherMarker);
        int trampolineStart = suffix.indexOf(trampolineMarker);
        int discoveryStart = suffix.indexOf(discoveryMarker);
        if (
            dispatcherStart < 0 ||
            trampolineStart < dispatcherStart ||
            discoveryStart < trampolineStart
        ) {
            return List.of(
                new GeneratedSourceFile(
                    "neko_native_late_support.c",
                    lateSupportSource(suffix)
                )
            );
        }

        String manifestTables = suffix.substring(0, dispatcherStart);
        String dispatchers = suffix.substring(dispatcherStart, trampolineStart);
        String trampolines = suffix.substring(trampolineStart, discoveryStart);
        String bootstrap = suffix.substring(discoveryStart);
        List<GeneratedSourceFile> sources = new ArrayList<>();
        sources.add(
            new GeneratedSourceFile(
                "neko_native_manifest.c",
                lateSupportSource(manifestTables + bootstrap)
            )
        );
        sources.addAll(splitDispatcherSources(dispatchers));
        sources.add(
            new GeneratedSourceFile(
                "neko_native_trampolines.c",
                lateSupportSource(trampolines)
            )
        );
        return List.copyOf(sources);
    }

    private List<GeneratedSourceFile> splitDispatcherSources(
        String dispatchers
    ) {
        String dispatcherMarker =
            "/* === Per-signature direct-C dispatchers === */";
        int bodyStart = dispatchers.indexOf("typedef ");
        if (bodyStart < 0) {
            return List.of(
                new GeneratedSourceFile(
                    "neko_native_dispatchers.c",
                    lateSupportSource(dispatchers)
                )
            );
        }

        String header = dispatchers.substring(0, bodyStart);
        String body = dispatchers.substring(bodyStart);
        List<String> groups = splitDispatcherGroups(body);
        if (groups.size() <= MAX_DISPATCHERS_PER_SOURCE) {
            return List.of(
                new GeneratedSourceFile(
                    "neko_native_dispatchers.c",
                    lateSupportSource(dispatchers)
                )
            );
        }

        List<GeneratedSourceFile> sources = new ArrayList<>();
        int shard = 0;
        for (
            int start = 0;
            start < groups.size();
            start += MAX_DISPATCHERS_PER_SOURCE
        ) {
            int end = Math.min(
                groups.size(),
                start + MAX_DISPATCHERS_PER_SOURCE
            );
            StringBuilder source = new StringBuilder(
                header.length() + (end - start) * 2048
            );
            if (shard == 0) {
                source.append(header);
            } else {
                source.append(dispatcherMarker).append('\n');
            }
            for (int i = start; i < end; i++) {
                source.append(groups.get(i));
            }
            sources.add(
                new GeneratedSourceFile(
                    "neko_native_dispatchers_" + shard + ".c",
                    lateSupportSource(source.toString())
                )
            );
            shard++;
        }
        return List.copyOf(sources);
    }

    private List<String> splitDispatcherGroups(String body) {
        List<String> groups = new ArrayList<>();
        int groupStart = 0;
        while (groupStart < body.length()) {
            int next = body.indexOf("\ntypedef ", groupStart + 1);
            if (next < 0) {
                groups.add(body.substring(groupStart));
                break;
            }
            groups.add(body.substring(groupStart, next + 1));
            groupStart = next + 1;
        }
        return groups;
    }

    private String lateSupportSource(String body) {
        return (
            "#include \"neko_native_impl_prelude.h\"\n" +
            "#ifndef NEKO_NATIVE_IMPL_PRELUDE_LOADED\n" +
            "#error \"neko_native_impl_prelude.h must be included before generated late support\"\n" +
            "#endif\n" +
            body
        );
    }

    private String supportShardSource(String body) {
        return lateSupportSource(body);
    }

    private String externalizeRawFunctionPrototypes(String source) {
        return source.replaceAll(
            "(?m)^static (\\S+\\s+neko_native_impl_\\d+(?:_body)?\\([^;]+;)$",
            "extern $1"
        );
    }

    private String externalizeRawFunctionDefinition(String source) {
        return source
            .replaceAll(
                "NEKO_FLATTEN NEKO_HOT static (\\S+\\s+neko_native_impl_\\d+(?:_body)?\\()",
                "NEKO_FLATTEN NEKO_HOT $1"
            )
            .replaceAll(
                "NEKO_HOT static (\\S+\\s+neko_native_impl_\\d+(?:_body)?\\()",
                "NEKO_HOT $1"
            );
    }

    private int implementationChunkEnd(List<CFunction> functions, int start) {
        CFunction first = functions.get(start);
        if (isLargeImplementation(first)) {
            return start + 1;
        }
        int finish = start;
        int statements = 0;
        while (
            finish < functions.size() &&
            finish - start < MAX_FUNCTIONS_PER_IMPL_SOURCE
        ) {
            CFunction next = functions.get(finish);
            int nextStatements = next.body().size();
            if (
                finish > start &&
                (isLargeImplementation(next) ||
                    statements + nextStatements > MAX_IMPL_SOURCE_STATEMENTS)
            ) {
                break;
            }
            statements += nextStatements;
            finish++;
        }
        return Math.max(start + 1, finish);
    }

    private boolean isLargeImplementation(CFunction fn) {
        return fn.body().size() > MAX_FLATTEN_STATEMENTS;
    }

    private String externalizeGlobalDefinitions(String source) {
        StringBuilder out = new StringBuilder(source.length());
        List<String> lines = source.lines().toList();
        boolean skippingInitializer = false;
        for (String line : lines) {
            if (skippingInitializer) {
                if (line.startsWith("};")) {
                    skippingInitializer = false;
                }
                continue;
            }
            String declaration = externGlobalDeclaration(line);
            if (declaration != null) {
                out.append(declaration).append('\n');
                if (!line.contains(";")) {
                    skippingInitializer = true;
                }
                continue;
            }
            out.append(line).append('\n');
        }
        return out.toString();
    }

    private String renderImplementationContractHeader(
        String source,
        Set<String> supportFunctionNames
    ) {
        StringBuilder out = new StringBuilder(source.length() / 3);
        List<String> lines = source.lines().toList();
        boolean skippingInitializer = false;
        int skippedFunctionBraceDepth = 0;
        String pendingSupportFunctionName = null;
        StringBuilder pendingSupportSignature = null;
        for (String line : lines) {
            if (skippingInitializer) {
                if (line.startsWith("};")) {
                    skippingInitializer = false;
                }
                continue;
            }
            if (skippedFunctionBraceDepth > 0) {
                skippedFunctionBraceDepth += braceDelta(line);
                continue;
            }
            if (pendingSupportFunctionName != null) {
                pendingSupportSignature.append('\n').append(line);
                if (pendingSupportSignature.indexOf("{") >= 0) {
                    String declaration = hiddenSupportFunctionDeclaration(
                        pendingSupportSignature.toString()
                    );
                    if (declaration != null) {
                        out.append(declaration).append('\n');
                        skippedFunctionBraceDepth = Math.max(
                            0,
                            braceDelta(pendingSupportSignature.toString())
                        );
                        pendingSupportFunctionName = null;
                        pendingSupportSignature = null;
                        continue;
                    }
                }
                if (line.contains(";")) {
                    out.append(pendingSupportSignature).append('\n');
                    pendingSupportFunctionName = null;
                    pendingSupportSignature = null;
                }
                continue;
            }

            String functionName = topLevelSupportFunctionName(line);
            if (
                functionName != null &&
                supportFunctionNames.contains(functionName)
            ) {
                if (!line.contains("{") && !line.contains(";")) {
                    pendingSupportFunctionName = functionName;
                    pendingSupportSignature = new StringBuilder(line);
                    continue;
                }
                String declaration = hiddenSupportFunctionDeclaration(line);
                if (declaration != null) {
                    out.append(declaration).append('\n');
                    if (line.contains("{")) {
                        skippedFunctionBraceDepth = Math.max(
                            0,
                            braceDelta(line)
                        );
                    }
                    continue;
                }
            }

            String staticGlobalDeclaration = staticGlobalDeclaration(line);
            if (staticGlobalDeclaration != null) {
                out.append(staticGlobalDeclaration).append('\n');
                if (line.contains("=") && !line.contains(";")) {
                    skippingInitializer = true;
                }
                continue;
            }

            String declaration = externGlobalDeclaration(line);
            if (declaration != null) {
                out.append(declaration).append('\n');
                if (!line.contains(";")) {
                    skippingInitializer = true;
                }
                continue;
            }
            out.append(line).append('\n');
        }
        return out.toString();
    }

    private String exportGlobalDefinitions(String source) {
        StringBuilder out = new StringBuilder(source.length());
        for (String line : source.lines().toList()) {
            String declaration = exportedGlobalDefinition(line);
            out.append(declaration != null ? declaration : line).append('\n');
        }
        return out.toString();
    }

    private String exportSupportDefinitions(
        String source,
        Set<String> supportFunctionNames
    ) {
        StringBuilder out = new StringBuilder(source.length());
        for (String line : source.lines().toList()) {
            String functionName = topLevelStaticFunctionName(line);
            if (
                functionName != null &&
                supportFunctionNames.contains(functionName)
            ) {
                String declaration =
                    hiddenSupportFunctionDefinitionOrDeclaration(line);
                if (declaration != null) {
                    out.append(declaration).append('\n');
                    continue;
                }
            }
            String staticGlobalDefinition = hiddenSupportGlobalDefinition(line);
            if (staticGlobalDefinition != null) {
                out.append(staticGlobalDefinition).append('\n');
                continue;
            }
            String declaration = exportedGlobalDefinition(line);
            out.append(declaration != null ? declaration : line).append('\n');
        }
        return out.toString();
    }

    private Set<String> topLevelSupportFunctionDefinitions(String source) {
        Set<String> names = new LinkedHashSet<>();
        String pendingFunctionName = null;
        StringBuilder pendingSignature = null;
        for (String line : source.lines().toList()) {
            if (pendingFunctionName != null) {
                pendingSignature.append('\n').append(line);
                if (pendingSignature.indexOf("{") >= 0) {
                    names.add(pendingFunctionName);
                    pendingFunctionName = null;
                    pendingSignature = null;
                } else if (line.contains(";")) {
                    pendingFunctionName = null;
                    pendingSignature = null;
                }
                continue;
            }
            String name = topLevelSupportFunctionName(line);
            if (name != null) {
                if (line.contains("{")) {
                    names.add(name);
                } else if (!line.contains(";")) {
                    pendingFunctionName = name;
                    pendingSignature = new StringBuilder(line);
                }
            }
        }
        return names;
    }

    private String topLevelSupportFunctionName(String line) {
        String staticName = topLevelStaticFunctionName(line);
        if (staticName != null) {
            return staticName;
        }
        String prefix = "__attribute__((visibility(\"hidden\"))) ";
        if (
            line.startsWith(" ") ||
            line.startsWith("\t") ||
            !line.startsWith(prefix) ||
            line.startsWith(prefix + "extern ")
        ) {
            return null;
        }
        return topLevelFunctionNameFromSignature(
            line.substring(prefix.length())
        );
    }

    private String topLevelFunctionNameFromSignature(String signature) {
        int open = signature.indexOf('(');
        if (open < 0) {
            return null;
        }
        int equals = signature.indexOf('=');
        if (equals >= 0 && equals < open) {
            return null;
        }
        String before = signature.substring(0, open).trim();
        int space = Math.max(before.lastIndexOf(' '), before.lastIndexOf('*'));
        if (space < 0 || space + 1 >= before.length()) {
            return null;
        }
        return before.substring(space + 1);
    }

    private String topLevelStaticFunctionName(String line) {
        if (
            line.startsWith(" ") ||
            line.startsWith("\t") ||
            !line.startsWith("static ") ||
            line.startsWith("static inline ")
        ) {
            return null;
        }
        return topLevelFunctionNameFromSignature(line);
    }

    private String hiddenSupportFunctionDeclaration(String line) {
        String withoutBody = line;
        int openBrace = withoutBody.indexOf('{');
        if (openBrace >= 0) {
            withoutBody = withoutBody.substring(0, openBrace).trim();
        } else {
            withoutBody = withoutBody.trim();
            if (withoutBody.endsWith(";")) {
                withoutBody = withoutBody
                    .substring(0, withoutBody.length() - 1)
                    .trim();
            }
        }
        if (!withoutBody.startsWith("static ")) {
            String prefix = "__attribute__((visibility(\"hidden\"))) ";
            if (!withoutBody.startsWith(prefix)) {
                return null;
            }
            return (
                prefix +
                "extern " +
                withoutBody.substring(prefix.length()) +
                ";"
            );
        }
        return (
            "__attribute__((visibility(\"hidden\"))) extern " +
            withoutBody.substring("static ".length()) +
            ";"
        );
    }

    private String hiddenSupportFunctionDefinitionOrDeclaration(String line) {
        if (!line.startsWith("static ") || line.startsWith("static inline ")) {
            return null;
        }
        return (
            "__attribute__((visibility(\"hidden\"))) " +
            line.substring("static ".length())
        );
    }

    private String staticGlobalDeclaration(String line) {
        if (
            line.startsWith(" ") ||
            line.startsWith("\t") ||
            !line.startsWith("static ") ||
            line.startsWith("static inline ")
        ) {
            return null;
        }
        int equals = line.indexOf('=');
        int end = equals >= 0 ? equals : line.indexOf(';');
        if (end < 0) {
            return null;
        }
        String left = line.substring("static ".length(), end).trim();
        if (declarationHead(left).contains("(")) {
            return null;
        }
        return "__attribute__((visibility(\"hidden\"))) extern " + left + ";";
    }

    private String hiddenSupportGlobalDefinition(String line) {
        if (
            line.startsWith(" ") ||
            line.startsWith("\t") ||
            !line.startsWith("static ") ||
            line.startsWith("static inline ")
        ) {
            return null;
        }
        int equals = line.indexOf('=');
        int end = equals >= 0 ? equals : line.indexOf(';');
        if (end < 0) {
            return null;
        }
        String left = line.substring("static ".length(), end).trim();
        if (declarationHead(left).contains("(")) {
            return null;
        }
        return (
            "__attribute__((visibility(\"hidden\"))) " +
            line.substring("static ".length())
        );
    }

    private int braceDelta(String line) {
        int delta = 0;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '{') {
                delta++;
            } else if (c == '}') {
                delta--;
            }
        }
        return delta;
    }

    private String externGlobalDeclaration(String line) {
        if (
            line.startsWith(" ") ||
            line.startsWith("\t") ||
            !line.contains("g_")
        ) {
            return null;
        }
        String trimmed = line.trim();
        if (trimmed.startsWith("static inline ")) {
            return null;
        }
        int equals = line.indexOf('=');
        int end = equals >= 0 ? equals : line.indexOf(';');
        if (end < 0) {
            return null;
        }
        String left = line.substring(0, end).trim();
        left = left.replaceAll(
            "\\s+__attribute__\\(\\(alias\\(\"[^\"]+\"\\)\\)\\)",
            ""
        );
        if (declarationHead(left).contains("(")) {
            return null;
        }
        left = left.replaceFirst(
            "^__attribute__\\(\\(aligned\\(64\\)\\)\\)\\s+static\\s+",
            "extern "
        );
        left = left.replaceFirst("^static\\s+", "extern ");
        left = left.replaceFirst(
            "^__attribute__\\(\\(visibility\\(\"hidden\"\\)\\)\\)\\s+(?!extern\\b)",
            "__attribute__((visibility(\"hidden\"))) extern "
        );
        if (
            !left.startsWith("extern ") &&
            !left.startsWith("__attribute__((visibility(\"hidden\"))) extern ")
        ) {
            return null;
        }
        return left + ";";
    }

    private String exportedGlobalDefinition(String line) {
        if (
            line.startsWith(" ") ||
            line.startsWith("\t") ||
            !line.contains("g_")
        ) {
            return null;
        }
        String trimmed = line.trim();
        if (trimmed.startsWith("static inline ")) {
            return null;
        }
        int equals = line.indexOf('=');
        int end = equals >= 0 ? equals : line.indexOf(';');
        if (end < 0) {
            return null;
        }
        String left = line.substring(0, end).trim();
        if (declarationHead(left).contains("(")) {
            return null;
        }
        left = left.replaceFirst(
            "^__attribute__\\(\\(aligned\\(64\\)\\)\\)\\s+static\\s+",
            "__attribute__((visibility(\"hidden\"))) __attribute__((aligned(64))) "
        );
        left = left.replaceFirst(
            "^static\\s+",
            "__attribute__((visibility(\"hidden\"))) "
        );
        left = left.replaceFirst(
            "^__attribute__\\(\\(visibility\\(\"hidden\"\\)\\)\\)\\s+",
            "__attribute__((visibility(\"hidden\"))) "
        );
        if (!left.startsWith("__attribute__((visibility(\"hidden\"))) ")) {
            return null;
        }
        return equals >= 0 ? left + line.substring(equals) : left + ";";
    }

    private String declarationHead(String left) {
        String head = left;
        head = head.replaceFirst(
            "^__attribute__\\(\\(visibility\\(\"hidden\"\\)\\)\\)\\s+",
            ""
        );
        head = head.replaceFirst(
            "^__attribute__\\(\\(aligned\\(64\\)\\)\\)\\s+",
            ""
        );
        return head;
    }

    private String renderRawFunction(CFunction fn) {
        StringBuilder sb = new StringBuilder();
        String bodyName = fn.name() + "_body";
        /* `flatten` recursively inlines all `static inline` callees into normal
         * sized impl bodies. Pathological JVM methods can otherwise force one
         * translation unit into a long single-threaded optimizer tail; those
         * keep `hot` and the global -O3 pipeline without the recursive flatten
         * attribute. The threshold is structural, not owner/name based. */
        boolean flatten = fn.body().size() <= MAX_FLATTEN_STATEMENTS;
        sb.append("NEKO_HOT static ")
            .append(fn.returnType().jniName())
            .append(' ')
            .append(fn.name())
            .append('(');
        appendRenderedParams(sb, fn);
        sb.append(") {\n");
        sb.append("    neko_hotspot_fast_require(thread, env);\n");
        if (fn.returnType() == CType.VOID) {
            sb.append("    ").append(bodyName).append('(');
            appendParamNames(sb, fn);
            sb.append(");\n");
            sb.append("    return;\n");
        } else {
            sb.append("    return ").append(bodyName).append('(');
            appendParamNames(sb, fn);
            sb.append(");\n");
        }
        sb.append("}\n");
        sb.append(
            flatten ? "NEKO_FLATTEN NEKO_HOT static " : "NEKO_HOT static "
        )
            .append(fn.returnType().jniName())
            .append(' ')
            .append(bodyName)
            .append('(');
        appendRenderedParams(sb, fn);
        sb.append(") {\n");
        sb.append("    neko_slot stack[")
            .append(fn.maxStack() + 16)
            .append("];\n");
        sb.append("    int sp = 0;\n");
        if (fn.usesMonitors()) {
            sb.append("    neko_monitor_record monitors[")
                .append(fn.maxStack() + 16)
                .append("];\n");
            sb.append("    int monitor_sp = 0;\n");
        }
        /* Locals are uninitialized at function entry (Java spec requires
         * every local be assigned before read). Skipping the memset saves
         * 26+ qword-stores per call on every translated method. The stack
         * slots are also uninitialized — POP only ever returns previously
         * PUSH'd values per JVM verifier guarantees. */
        sb.append("    neko_slot locals[")
            .append(fn.maxLocals() + 8)
            .append("];\n");
        sb.append("    neko_hotspot_fast_assume(thread);\n");
        for (CStatement statement : fn.body()) {
            sb.append(renderStatement(statement));
        }
        sb.append("}\n");
        return sb.toString();
    }

    private void appendRenderedParams(StringBuilder sb, CFunction fn) {
        for (int i = 0; i < fn.params().size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(renderParam(fn.params().get(i)));
        }
    }

    private void appendParamNames(StringBuilder sb, CFunction fn) {
        for (int i = 0; i < fn.params().size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(fn.params().get(i).name());
        }
    }

    private String renderRawFunctionPrototypes(
        List<NativeMethodBinding> bindings
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("// === Raw translated-body prototypes ===\n");
        for (NativeMethodBinding binding : bindings) {
            sb.append("static ")
                .append(jniType(Type.getReturnType(binding.descriptor())))
                .append(' ')
                .append(binding.rawFunctionName())
                .append("(void *thread, JNIEnv *env, jclass clazz");
            if (!binding.isStatic()) {
                sb.append(", jobject self");
            }
            Type[] args = Type.getArgumentTypes(binding.descriptor());
            for (int i = 0; i < args.length; i++) {
                sb.append(", ").append(jniType(args[i])).append(" p").append(i);
            }
            sb.append(");\n");
            sb.append("static ")
                .append(jniType(Type.getReturnType(binding.descriptor())))
                .append(' ')
                .append(binding.rawFunctionName())
                .append("_body(void *thread, JNIEnv *env, jclass clazz");
            if (!binding.isStatic()) {
                sb.append(", jobject self");
            }
            for (int i = 0; i < args.length; i++) {
                sb.append(", ").append(jniType(args[i])).append(" p").append(i);
            }
            sb.append(");\n");
        }
        sb.append('\n');
        return sb.toString();
    }

    private String renderStatement(CStatement statement) {
        if (statement instanceof CStatement.RawC raw) {
            return "    " + raw.code() + "\n";
        }
        if (statement instanceof CStatement.Label label) {
            return label.name() + ": ;\n";
        }
        if (statement instanceof CStatement.Goto go) {
            return "    goto " + go.label() + ";\n";
        }
        if (statement instanceof CStatement.ReturnVoid) {
            return "    return;\n";
        }
        if (statement instanceof CStatement.Return ret) {
            return "    return " + ret.value() + ";\n";
        }
        if (statement instanceof CStatement.Comment comment) {
            return "    /* " + comment.text() + " */\n";
        }
        throw new IllegalStateException(
            "Unsupported C statement in generator: " +
                statement.getClass().getSimpleName()
        );
    }

    private String renderResolutionCaches() {
        StringBuilder sb = new StringBuilder();
        sb.append("// === Global resolution caches ===\n");
        sb.append("#define NEKO_ICACHE_PIC_SIZE 4u\n");
        sb.append("typedef struct neko_icache_site {\n");
        sb.append("    uintptr_t receiver_key[NEKO_ICACHE_PIC_SIZE];\n");
        sb.append("    void* target[NEKO_ICACHE_PIC_SIZE];\n");
        sb.append("    void* target2[NEKO_ICACHE_PIC_SIZE];\n");
        sb.append("    uint8_t target_kind[NEKO_ICACHE_PIC_SIZE];\n");
        sb.append("    uint8_t next_slot;\n");
        sb.append("    uint16_t miss_count;\n");
        sb.append(
            "    /* legacy icache field names: receiver_key; target; target_kind; */\n"
        );
        /* For NEKO_ICACHE_DIRECT_NJX: target = HotSpot Method* (resolved
         * from the receiver-class-specific jmethodID), target2 = the
         * cached _from_compiled_entry pointer. The dispatcher itself
         * comes from neko_icache_meta::direct_dispatcher (shape-specific,
         * known at codegen time). */
        sb.append("} neko_icache_site;\n\n");
        sb.append("#define NEKO_ICACHE_EMPTY 0u\n");
        sb.append("#define NEKO_ICACHE_DIRECT_C 1u\n");
        sb.append("#define NEKO_ICACHE_MEGA 3u\n");
        sb.append("#define NEKO_ICACHE_DIRECT_NJX 4u\n");
        sb.append("#define NEKO_ICACHE_MEGA_THRESHOLD 16u\n\n");
        for (Map.Entry<String, Integer> entry : classSlotIndex.entrySet()) {
            sb.append("static jclass g_cls_")
                .append(entry.getValue())
                .append(" = NULL;   // ")
                .append(entry.getKey())
                .append("\n");
            sb.append("static uintptr_t g_obj_array_klass_")
                .append(entry.getValue())
                .append(" = 0;\n");
            sb.append("static volatile jboolean g_cls_initialized_")
                .append(entry.getValue())
                .append(" = JNI_FALSE;\n");
        }
        for (Map.Entry<String, Integer> entry : methodSlotIndex.entrySet()) {
            sb.append("static jmethodID g_mid_")
                .append(entry.getValue())
                .append(" = NULL;   // ")
                .append(entry.getKey())
                .append("\n");
            /* HotSpot Method* + cached entry pointers — populated at JNI_OnLoad
             * by neko_bind_method_slot once the layout walker has resolved the
             * Method::_from_compiled_entry / _from_interpreted_entry offsets.
             * Reads on the hot path are direct memory loads; writes are
             * single-pointer stores so torn reads are impossible on x86-64
             * and AArch64 (8-byte aligned, naturally atomic). */
            sb.append("static void* g_mptr_")
                .append(entry.getValue())
                .append(" = NULL;\n");
            sb.append("static void* g_mcentry_")
                .append(entry.getValue())
                .append(" = NULL;\n");
            sb.append("static void* g_mientry_")
                .append(entry.getValue())
                .append(" = NULL;\n");
            sb.append("static void* g_mholder_")
                .append(entry.getValue())
                .append(" = NULL;\n");
        }
        for (Map.Entry<String, Integer> entry : fieldSlotIndex.entrySet()) {
            sb.append("static jfieldID g_fid_")
                .append(entry.getValue())
                .append(" = NULL;   // ")
                .append(entry.getKey())
                .append("\n");
            sb.append("static jlong g_off_")
                .append(entry.getValue())
                .append(" = -1;\n");
            sb.append("static jlong g_static_off_")
                .append(entry.getValue())
                .append(" = -1;\n");
            sb.append("static uint32_t g_access_")
                .append(entry.getValue())
                .append(" = 0;\n");
            sb.append("static jobject g_static_base_")
                .append(entry.getValue())
                .append(" = NULL;\n");
        }
        sb.append("typedef struct neko_class_ref {\n");
        sb.append("    jclass *class_slot;\n");
        sb.append("    const char *owner;\n");
        sb.append("} neko_class_ref;\n");
        if (!classDescriptorRefs.isEmpty()) {
            sb.append("static const neko_class_ref g_class_refs[")
                .append(classDescriptorRefs.size())
                .append("] = {\n");
            for (ClassDescriptorRef ref : classDescriptorRefs.values()) {
                sb.append("    {&")
                    .append(ref.classSlot())
                    .append(", \"")
                    .append(CStringLiteral.escape(ref.owner()))
                    .append("\"},   // ")
                    .append(ref.symbol())
                    .append('\n');
            }
            sb.append("};\n");
            int classRefIndex = 0;
            for (ClassDescriptorRef ref : classDescriptorRefs.values()) {
                sb.append("#define ")
                    .append(ref.symbol())
                    .append(" (g_class_refs[")
                    .append(classRefIndex++)
                    .append("])\n");
            }
        }
        sb.append(
            "#define neko_bound_class_ref(env, ref) neko_bound_class((env), *((ref)->class_slot), (ref)->owner)\n"
        );
        sb.append("typedef struct neko_static_field_ref {\n");
        sb.append("    jclass *class_slot;\n");
        sb.append("    volatile jboolean *class_init_slot;\n");
        sb.append("    jfieldID *field_slot;\n");
        sb.append("    jobject *static_base_slot;\n");
        sb.append("    jlong *static_offset_slot;\n");
        sb.append("    uint32_t *access_flags_slot;\n");
        sb.append("    const char *owner;\n");
        sb.append("    const char *name;\n");
        sb.append("    const char *desc;\n");
        sb.append("} neko_static_field_ref;\n");
        if (!staticFieldDescriptorRefs.isEmpty()) {
            sb.append("static const neko_static_field_ref g_static_field_refs[")
                .append(staticFieldDescriptorRefs.size())
                .append("] = {\n");
            for (StaticFieldDescriptorRef ref : staticFieldDescriptorRefs.values()) {
                sb.append("    {&")
                    .append(ref.classSlot())
                    .append(", &")
                    .append(ref.classInitSlot())
                    .append(", &")
                    .append(ref.fieldSlot())
                    .append(", &")
                    .append(ref.staticBaseSlot())
                    .append(", &")
                    .append(ref.staticOffsetSlot())
                    .append(", &")
                    .append(ref.accessFlagsSlot())
                    .append(", \"")
                    .append(CStringLiteral.escape(ref.owner()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(ref.name()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(ref.desc()))
                    .append("\"},   // ")
                    .append(ref.symbol())
                    .append('\n');
            }
            sb.append("};\n");
            int staticFieldRefIndex = 0;
            for (StaticFieldDescriptorRef ref : staticFieldDescriptorRefs.values()) {
                sb.append("#define ")
                    .append(ref.symbol())
                    .append(" (g_static_field_refs[")
                    .append(staticFieldRefIndex++)
                    .append("])\n");
            }
        }
        sb.append("typedef struct neko_field_ref {\n");
        sb.append("    jfieldID *field_slot;\n");
        sb.append("    uint32_t *access_flags_slot;\n");
        sb.append("    const char *owner;\n");
        sb.append("    const char *name;\n");
        sb.append("    const char *desc;\n");
        sb.append("    jboolean is_static;\n");
        sb.append("} neko_field_ref;\n");
        if (!fieldDescriptorRefs.isEmpty()) {
            sb.append("static const neko_field_ref g_field_refs[")
                .append(fieldDescriptorRefs.size())
                .append("] = {\n");
            for (FieldDescriptorRef ref : fieldDescriptorRefs.values()) {
                sb.append("    {&")
                    .append(ref.fieldSlot())
                    .append(", &")
                    .append(ref.accessFlagsSlot())
                    .append(", \"")
                    .append(CStringLiteral.escape(ref.owner()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(ref.name()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(ref.desc()))
                    .append("\", ")
                    .append(ref.isStatic() ? "JNI_TRUE" : "JNI_FALSE")
                    .append("},   // ")
                    .append(ref.symbol())
                    .append('\n');
            }
            sb.append("};\n");
            int fieldRefIndex = 0;
            for (FieldDescriptorRef ref : fieldDescriptorRefs.values()) {
                sb.append("#define ")
                    .append(ref.symbol())
                    .append(" (g_field_refs[")
                    .append(fieldRefIndex++)
                    .append("])\n");
            }
        }
        sb.append(
            "#define neko_bound_field_ref(env, ref) neko_bound_field((env), *((ref)->field_slot), (ref)->owner, (ref)->name, (ref)->desc, (ref)->is_static)\n"
        );
        if (
            fieldSlotIndex.containsKey("java/lang/String.value[B/I") &&
            fieldSlotIndex.containsKey("java/lang/String.coderB/I")
        ) {
            sb.append(
                "#define neko_concat_accumulate_string(thread, env, acc, rhs) "
            )
                .append(
                    "neko_concat_accumulate((thread), (env), (acc), (rhs), "
                )
                .append(
                    fieldOffsetSlotName(
                        "java/lang/String",
                        "value",
                        "[B",
                        false
                    )
                )
                .append(", ")
                .append(
                    fieldOffsetSlotName("java/lang/String", "coder", "B", false)
                )
                .append(")\n");
        }
        sb.append("typedef struct neko_implicit_exception_ref {\n");
        sb.append("    jclass *class_slot;\n");
        sb.append("    void **method_slot;\n");
        sb.append("    void **ientry_slot;\n");
        sb.append(
            "    jvalue (*dispatcher)(void*, JNIEnv*, void*, void*, jobject, const jvalue*);\n"
        );
        sb.append("    const char *owner;\n");
        sb.append("    const char *name;\n");
        sb.append("    const char *desc;\n");
        sb.append("} neko_implicit_exception_ref;\n");
        sb.append("typedef struct neko_method_id_ref {\n");
        sb.append("    jmethodID *method_slot;\n");
        sb.append("    const char *owner;\n");
        sb.append("    const char *name;\n");
        sb.append("    const char *desc;\n");
        sb.append("    jboolean is_static;\n");
        sb.append("} neko_method_id_ref;\n");
        if (!methodIdDescriptorRefs.isEmpty()) {
            sb.append("static const neko_method_id_ref g_method_id_refs[")
                .append(methodIdDescriptorRefs.size())
                .append("] = {\n");
            for (MethodIdDescriptorRef ref : methodIdDescriptorRefs.values()) {
                sb.append("    {&")
                    .append(ref.methodSlot())
                    .append(", \"")
                    .append(CStringLiteral.escape(ref.owner()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(ref.name()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(ref.desc()))
                    .append("\", ")
                    .append(ref.isStatic() ? "JNI_TRUE" : "JNI_FALSE")
                    .append("},   // ")
                    .append(ref.symbol())
                    .append('\n');
            }
            sb.append("};\n");
            int methodIdRefIndex = 0;
            for (MethodIdDescriptorRef ref : methodIdDescriptorRefs.values()) {
                sb.append("#define ")
                    .append(ref.symbol())
                    .append(" (g_method_id_refs[")
                    .append(methodIdRefIndex++)
                    .append("])\n");
            }
        }
        sb.append(
            "#define neko_bound_method_ref(env, ref) neko_bound_method((env), *((ref)->method_slot), (ref)->owner, (ref)->name, (ref)->desc, (ref)->is_static)\n"
        );
        sb.append("typedef struct neko_method_entry_ref {\n");
        sb.append("    void **method_slot;\n");
        sb.append("    void **ientry_slot;\n");
        sb.append("    const char *owner;\n");
        sb.append("    const char *name;\n");
        sb.append("    const char *desc;\n");
        sb.append("} neko_method_entry_ref;\n");
        if (!methodEntryDescriptorRefs.isEmpty()) {
            sb.append("static const neko_method_entry_ref g_method_entry_refs[")
                .append(methodEntryDescriptorRefs.size())
                .append("] = {\n");
            for (MethodEntryDescriptorRef ref : methodEntryDescriptorRefs.values()) {
                sb.append("    {&")
                    .append(ref.methodPtrSlot())
                    .append(", &")
                    .append(ref.methodIEntrySlot())
                    .append(", \"")
                    .append(CStringLiteral.escape(ref.owner()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(ref.name()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(ref.desc()))
                    .append("\"},   // ")
                    .append(ref.symbol())
                    .append('\n');
            }
            sb.append("};\n");
            int methodEntryRefIndex = 0;
            for (MethodEntryDescriptorRef ref : methodEntryDescriptorRefs.values()) {
                sb.append("#define ")
                    .append(ref.symbol())
                    .append(" (g_method_entry_refs[")
                    .append(methodEntryRefIndex++)
                    .append("])\n");
            }
        }
        sb.append(
            "#define neko_bound_method_i_entry_ref(ref) (*((ref)->method_slot) != NULL && *((ref)->ientry_slot) != NULL ? *((ref)->ientry_slot) : neko_bound_method_i_entry(*((ref)->method_slot), (ref)->ientry_slot, (ref)->owner, (ref)->name, (ref)->desc))\n"
        );
        for (int i = 0; i < stringCacheCount; i++) {
            sb.append("static jstring g_str_").append(i).append(" = NULL;\n");
        }
        for (Map.Entry<String, Integer> entry : ownerBindIndex.entrySet()) {
            sb.append("static jboolean g_owner_bound_")
                .append(entry.getValue())
                .append(" = JNI_FALSE;   // ")
                .append(entry.getKey())
                .append("\n");
            sb.append("static jboolean g_owner_strings_bound_")
                .append(entry.getValue())
                .append(" = JNI_FALSE;   // ")
                .append(entry.getKey())
                .append("\n");
        }
        if (!icacheSites.isEmpty()) {
            sb.append("static neko_icache_site neko_icache_sites[")
                .append(icacheSites.size())
                .append("] = {0};\n");
            int icacheSiteIndex = 0;
            for (IcacheSiteRef site : icacheSites.values()) {
                sb.append("#define ")
                    .append(site.symbol())
                    .append(" (neko_icache_sites[")
                    .append(icacheSiteIndex++)
                    .append("])   // ")
                    .append(site.bindingOwner())
                    .append(" :: ")
                    .append(site.methodKey())
                    .append(" [site ")
                    .append(site.siteIndex())
                    .append("]\n");
            }
        }
        sb.append("\n");
        sb.append(
            "static jclass neko_ensure_class_slot(jclass *slot, JNIEnv *env, const char *name);\n"
        );
        sb.append(
            "static jstring neko_ensure_string_slot(jstring *slot, JNIEnv *env, const char *utf);\n"
        );
        sb.append(
            "static jmethodID neko_ensure_method_id_slot(jmethodID *slot, JNIEnv *env, jclass cls, const char *name, const char *desc, jboolean isStatic);\n"
        );
        sb.append(
            "static jfieldID neko_ensure_field_id_slot(jfieldID *slot, JNIEnv *env, jclass cls, const char *name, const char *desc, jboolean isStatic);\n"
        );
        sb.append(
            "static jclass neko_resolve_class_mirror_with_env(JNIEnv *env, const char *utf8, jclass from_class, void **klass_out);\n"
        );
        sb.append(
            "static jclass neko_try_resolve_class_mirror_with_env(JNIEnv *env, const char *utf8, jclass from_class);\n"
        );
        sb.append(
            "static jmethodID neko_resolve_jmethodID(JNIEnv *env, jclass cls, const char *name, const char *sig);\n"
        );
        sb.append(
            "static jmethodID neko_resolve_jmethodID_with_kind(JNIEnv *env, jclass cls, const char *name, const char *sig, jboolean is_static);\n"
        );
        sb.append(
            "static void *neko_resolve_method_star_with_kind(JNIEnv *env, jclass cls, const char *name, const char *sig, jboolean is_static);\n"
        );
        sb.append(
            "static const char *neko_method_holder_name_utf8(void *method, int *len_out);\n"
        );
        /* T4.2c — the new neko_impl_lookup body lives in NativeMethodResolutionEmitter.renderResolveJMethodID()
         * (alongside the T4.2b helpers); the forward declaration in
         * renderRuntimeSupport keeps the existing in-block neko_lookup_for_jclass
         * call site resolving. */
        sb.append(
            "#define NEKO_ENSURE_CLASS(slot, env, name) neko_ensure_class_slot(&(slot), (env), (name))\n"
        );
        sb.append(
            "#define NEKO_ENSURE_STRING(slot, env, utf) neko_ensure_string_slot(&(slot), (env), (utf))\n"
        );
        sb.append(
            "#define NEKO_ENSURE_METHOD_ID(slot, env, cls, name, desc) neko_ensure_method_id_slot(&(slot), (env), (cls), (name), (desc), JNI_FALSE)\n"
        );
        sb.append(
            "#define NEKO_ENSURE_STATIC_METHOD_ID(slot, env, cls, name, desc) neko_ensure_method_id_slot(&(slot), (env), (cls), (name), (desc), JNI_TRUE)\n"
        );
        sb.append(
            "#define NEKO_ENSURE_FIELD_ID(slot, env, cls, name, desc) neko_ensure_field_id_slot(&(slot), (env), (cls), (name), (desc), JNI_FALSE)\n"
        );
        sb.append(
            "#define NEKO_ENSURE_STATIC_FIELD_ID(slot, env, cls, name, desc) neko_ensure_field_id_slot(&(slot), (env), (cls), (name), (desc), JNI_TRUE)\n\n"
        );
        return sb.toString();
    }

    private String renderImplicitExceptionRefs() {
        StringBuilder sb = new StringBuilder();
        if (!implicitExceptionRefs.isEmpty()) {
            sb.append(
                "static const neko_implicit_exception_ref g_implicit_exception_refs["
            )
                .append(implicitExceptionRefs.size())
                .append("] = {\n");
            for (ImplicitExceptionRef ref : implicitExceptionRefs.values()) {
                sb.append("    {&")
                    .append(ref.classSlot())
                    .append(", &")
                    .append(ref.methodPtrSlot())
                    .append(", &")
                    .append(ref.methodIEntrySlot())
                    .append(", ")
                    .append(ref.dispatcher())
                    .append(", \"")
                    .append(CStringLiteral.escape(ref.owner()))
                    .append("\", \"<init>\", \"")
                    .append(CStringLiteral.escape(ref.ctorDesc()))
                    .append("\"},   // ")
                    .append(ref.symbol())
                    .append('\n');
            }
            sb.append("};\n");
            int index = 0;
            for (ImplicitExceptionRef ref : implicitExceptionRefs.values()) {
                sb.append("#define ")
                    .append(ref.symbol())
                    .append(" (g_implicit_exception_refs[")
                    .append(index++)
                    .append("])\n");
            }
        }
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern void neko_raise_implicit_exception_ref(void *thread, JNIEnv *env, const neko_implicit_exception_ref *ref);\n"
        );
        sb.append(
            "__attribute__((visibility(\"hidden\"))) extern jboolean neko_exception_handler_matches_ref(JNIEnv *env, jthrowable exc, const neko_class_ref *ref);\n"
        );
        return sb.toString();
    }

    private String renderCachedFastArrayRaiseHelper() {
        if (!cachedFastArrayRaiseHelperRequired) {
            return "";
        }
        String ctorDesc = "(Ljava/lang/String;)V";
        String npeOwner = "java/lang/NullPointerException";
        String aioobeOwner = "java/lang/ArrayIndexOutOfBoundsException";
        String dispatcher = cachedFastArrayRaiseDispatcherSymbol;
        if (dispatcher == null) {
            throw new IllegalStateException(
                "Cached fast-array raise helper requested without dispatcher"
            );
        }
        String npeMethodPtr = methodPtrSlotName(
            npeOwner,
            "<init>",
            ctorDesc,
            false
        );
        String npeIEntry = methodIEntrySlotName(
            npeOwner,
            "<init>",
            ctorDesc,
            false
        );
        String aioobeMethodPtr = methodPtrSlotName(
            aioobeOwner,
            "<init>",
            ctorDesc,
            false
        );
        String aioobeIEntry = methodIEntrySlotName(
            aioobeOwner,
            "<init>",
            ctorDesc,
            false
        );
        return """
        /* Cold wrapper for checked array helper failures. The success path stays in
         * the generated opcode statement; this only centralizes the repeated
         * exception metadata binding used after a checked helper reports failure. */
        __attribute__((cold, noinline))
        static void neko_raise_cached_fast_array_reason(void *thread, JNIEnv *env, int reason) {
            neko_raise_fast_array_reason(thread, env, reason,
                neko_bound_class(env, %s, "%s"),
                %s,
                neko_bound_method_i_entry(%s, &%s, "%s", "<init>", "%s"),
                %s,
                neko_bound_class(env, %s, "%s"),
                %s,
                neko_bound_method_i_entry(%s, &%s, "%s", "<init>", "%s"),
                %s);
        }

        """.formatted(
            classSlotName(npeOwner),
            CStringLiteral.escape(npeOwner),
            npeMethodPtr,
            npeMethodPtr,
            npeIEntry,
            CStringLiteral.escape(npeOwner),
            CStringLiteral.escape(ctorDesc),
            dispatcher,
            classSlotName(aioobeOwner),
            CStringLiteral.escape(aioobeOwner),
            aioobeMethodPtr,
            aioobeMethodPtr,
            aioobeIEntry,
            CStringLiteral.escape(aioobeOwner),
            CStringLiteral.escape(ctorDesc),
            dispatcher
        );
    }

    private String renderImplicitExceptionRefHelper() {
        return """
        __attribute__((cold, noinline))
        static void neko_raise_implicit_exception_ref(void *thread, JNIEnv *env, const neko_implicit_exception_ref *ref) {
            jclass cls;
            void *ctor_method;
            void *ctor_entry;
            if (ref == NULL || ref->class_slot == NULL || ref->method_slot == NULL || ref->ientry_slot == NULL || ref->dispatcher == NULL) {
                fprintf(stderr, "[neko-direct] implicit exception ref metadata unavailable ref=%p\\n", (void*)ref);
                abort();
            }
            cls = neko_bound_class(env, *(ref->class_slot), ref->owner);
            ctor_method = *(ref->method_slot);
            ctor_entry = neko_bound_method_i_entry(ctor_method, ref->ientry_slot, ref->owner, ref->name, ref->desc);
            neko_raise_implicit_exception(thread, env, cls, ctor_method, ctor_entry, ref->dispatcher, ref->owner);
        }

        """;
    }

    private String renderBindOwnerFunctions() {
        StringBuilder sb = new StringBuilder();
        if (ownerBindIndex.isEmpty()) {
            return "";
        }
        sb.append("// === Bind-time owner resolution ===\n");
        for (Map.Entry<String, Integer> entry : ownerBindIndex.entrySet()) {
            String owner = entry.getKey();
            int ownerId = entry.getValue();
            OwnerResolution resolution = ownerResolutions.get(owner);
            sb.append("static void neko_bind_owner_")
                .append(ownerId)
                .append("(JNIEnv *env, jclass self_class) {\n");
            sb.append("    if (env == NULL || g_owner_bound_")
                .append(ownerId)
                .append(") return;\n");
            sb.append("    g_owner_bound_")
                .append(ownerId)
                .append(" = JNI_TRUE;\n");
            sb.append("    neko_bind_owner_class_slot(env, &")
                .append(classSlotName(owner))
                .append(", self_class, \"")
                .append(CStringLiteral.escape(owner))
                .append("\");\n");
            sb.append("    neko_bind_object_array_klass_bits(env, &")
                .append(objectArrayKlassBitsSlotName(owner))
                .append(", \"")
                .append(CStringLiteral.escape(objectArrayDescriptor(owner)))
                .append("\", self_class);\n");
            for (String classOwner : resolution.classes) {
                if (owner.equals(classOwner)) {
                    continue;
                }
                sb.append("    neko_bind_class_slot_from(env, &")
                    .append(classSlotName(classOwner))
                    .append(", \"")
                    .append(CStringLiteral.escape(classOwner))
                    .append("\", self_class);\n");
                sb.append("    neko_bind_object_array_klass_bits(env, &")
                    .append(objectArrayKlassBitsSlotName(classOwner))
                    .append(", \"")
                    .append(
                        CStringLiteral.escape(objectArrayDescriptor(classOwner))
                    )
                    .append("\", self_class);\n");
            }
            for (String primitiveDesc : resolution.primitiveClasses) {
                sb.append("    neko_bind_primitive_class_slot(env, &")
                    .append(primitiveClassSlotName(primitiveDesc))
                    .append(", \"")
                    .append(CStringLiteral.escape(primitiveDesc))
                    .append("\");\n");
            }
            for (MethodRef methodRef : resolution.methods) {
                String midSlot = methodSlotName(
                    methodRef.owner(),
                    methodRef.name(),
                    methodRef.desc(),
                    methodRef.isStatic()
                );
                String mptrSlot = methodPtrSlotName(
                    methodRef.owner(),
                    methodRef.name(),
                    methodRef.desc(),
                    methodRef.isStatic()
                );
                String mcentrySlot = methodCEntrySlotName(
                    methodRef.owner(),
                    methodRef.name(),
                    methodRef.desc(),
                    methodRef.isStatic()
                );
                String mientrySlot = methodIEntrySlotName(
                    methodRef.owner(),
                    methodRef.name(),
                    methodRef.desc(),
                    methodRef.isStatic()
                );
                String mholderSlot = methodHolderSlotName(
                    methodRef.owner(),
                    methodRef.name(),
                    methodRef.desc(),
                    methodRef.isStatic()
                );
                sb.append("    neko_bind_method_slot(env, &")
                    .append(midSlot)
                    .append(", ")
                    .append(classSlotName(methodRef.owner()))
                    .append(", \"")
                    .append(CStringLiteral.escape(methodRef.owner()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(methodRef.name()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(methodRef.desc()))
                    .append("\", ")
                    .append(methodRef.isStatic() ? "JNI_TRUE" : "JNI_FALSE")
                    .append(");\n");
                /* Snapshot Method* and HotSpot entry pointers for the direct
                 * native→Java dispatcher. Reads happen straight off the Method*
                 * using VMStructs-published offsets — no JNI here. */
                sb.append("    neko_bind_method_entry_slots(env, ")
                    .append(midSlot)
                    .append(", ")
                    .append(classSlotName(methodRef.owner()))
                    .append(", \"")
                    .append(CStringLiteral.escape(methodRef.owner()))
                    .append("\"")
                    .append(", \"")
                    .append(CStringLiteral.escape(methodRef.name()))
                    .append("\"")
                    .append(", \"")
                    .append(CStringLiteral.escape(methodRef.desc()))
                    .append("\"")
                    .append(", &")
                    .append(mptrSlot)
                    .append(", &")
                    .append(mcentrySlot)
                    .append(", &")
                    .append(mientrySlot)
                    .append(", &")
                    .append(mholderSlot)
                    .append(");\n");
            }
            for (FieldRef fieldRef : resolution.fields) {
                sb.append("    neko_bind_field_slot(env, &")
                    .append(
                        fieldSlotName(
                            fieldRef.owner(),
                            fieldRef.name(),
                            fieldRef.desc(),
                            fieldRef.isStatic()
                        )
                    )
                    .append(", ")
                    .append(classSlotName(fieldRef.owner()))
                    .append(", \"")
                    .append(CStringLiteral.escape(fieldRef.owner()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(fieldRef.name()))
                    .append("\", \"")
                    .append(CStringLiteral.escape(fieldRef.desc()))
                    .append("\", ")
                    .append(fieldRef.isStatic() ? "JNI_TRUE" : "JNI_FALSE")
                    .append(");\n");
                /* Resolve byte-offset metadata for both primitive AND object
                 * fields through the native field metadata scanner. T2.6 will
                 * remove the remaining Unsafe static-base handle path. */
                if (fieldRef.isStatic()) {
                    sb.append("    neko_bind_static_field_metadata(env, &")
                        .append(
                            staticFieldBaseSlotName(
                                fieldRef.owner(),
                                fieldRef.name(),
                                fieldRef.desc(),
                                true
                            )
                        )
                        .append(", &")
                        .append(
                            staticFieldOffsetSlotName(
                                fieldRef.owner(),
                                fieldRef.name(),
                                fieldRef.desc(),
                                true
                            )
                        )
                        .append(", &")
                        .append(
                            fieldAccessFlagsSlotName(
                                fieldRef.owner(),
                                fieldRef.name(),
                                fieldRef.desc(),
                                true
                            )
                        )
                        .append(", ")
                        .append(classSlotName(fieldRef.owner()))
                        .append(", \"")
                        .append(CStringLiteral.escape(fieldRef.owner()))
                        .append("\", \"")
                        .append(CStringLiteral.escape(fieldRef.name()))
                        .append("\", \"")
                        .append(CStringLiteral.escape(fieldRef.desc()))
                        .append("\");\n");
                } else {
                    sb.append("    neko_bind_instance_field_offset(env, &")
                        .append(
                            fieldOffsetSlotName(
                                fieldRef.owner(),
                                fieldRef.name(),
                                fieldRef.desc(),
                                false
                            )
                        )
                        .append(", &")
                        .append(
                            fieldAccessFlagsSlotName(
                                fieldRef.owner(),
                                fieldRef.name(),
                                fieldRef.desc(),
                                false
                            )
                        )
                        .append(", ")
                        .append(classSlotName(fieldRef.owner()))
                        .append(", ")
                        .append(
                            fieldSlotName(
                                fieldRef.owner(),
                                fieldRef.name(),
                                fieldRef.desc(),
                                false
                            )
                        )
                        .append(", \"")
                        .append(CStringLiteral.escape(fieldRef.owner()))
                        .append("\", \"")
                        .append(CStringLiteral.escape(fieldRef.name()))
                        .append("\", \"")
                        .append(CStringLiteral.escape(fieldRef.desc()))
                        .append("\", ")
                        .append("JNI_TRUE")
                        .append(");\n");
                }
            }
            sb.append("}\n\n");
            sb.append("static void neko_bind_owner_strings_")
                .append(ownerId)
                .append("(void *thread, JNIEnv *env) {\n");
            sb.append("    if (g_owner_strings_bound_")
                .append(ownerId)
                .append(") return;\n");
            if (resolution.strings.isEmpty()) {
                sb.append("    (void)thread;\n");
                sb.append("    (void)env;\n");
                sb.append("    g_owner_strings_bound_")
                    .append(ownerId)
                    .append(" = JNI_TRUE;\n");
            } else {
                sb.append("    if (thread == NULL || env == NULL) {\n");
                sb.append(
                    "        fprintf(stderr, \"[neko-bind] owner string bind missing thread/env: "
                )
                    .append(CStringLiteral.escape(owner))
                    .append("\\n\");\n");
                sb.append("        abort();\n");
                sb.append("    }\n");
                for (StringRef stringRef : resolution.strings) {
                    sb.append("    neko_bind_string_slot(thread, env, &")
                        .append(stringRef.cacheVar())
                        .append(", \"")
                        .append(CStringLiteral.escape(stringRef.value()))
                        .append("\");\n");
                }
                sb.append("    g_owner_strings_bound_")
                    .append(ownerId)
                    .append(" = JNI_TRUE;\n");
            }
            sb.append("}\n\n");
        }
        return sb.toString();
    }

    private boolean requiresLocalCapacity(CFunction fn) {
        for (CStatement statement : fn.body()) {
            if (statement instanceof CStatement.RawC raw) {
                String code = raw.code();
                if (
                    code.contains("neko_new_") ||
                    code.contains("neko_call_") ||
                    code.contains("neko_get_object_array_element") ||
                    code.contains("neko_set_object_array_element") ||
                    code.contains("neko_get_object_class") ||
                    code.contains("NEKO_ENSURE_STRING") ||
                    code.contains("neko_string_concat") ||
                    code.contains("neko_class_for_descriptor") ||
                    code.contains("neko_resolve_constant_dynamic")
                ) {
                    return true;
                }
            }
        }
        return false;
    }

    private String renderIcacheDirectStubs() {
        if (icacheDirectStubs.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("// === Inline-cache direct-call stubs ===\n");
        for (IcacheDirectStubRef stub : icacheDirectStubs.values()) {
            sb.append(renderIcacheDirectStub(stub));
        }
        sb.append('\n');
        return sb.toString();
    }

    private String renderIcacheMetas() {
        if (icacheMetas.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("// === Inline-cache metadata ===\n");
        sb.append("static const neko_icache_meta neko_icache_metas[")
            .append(icacheMetas.size())
            .append("] = {\n");
        int icacheMetaIndex = 0;
        for (IcacheMetaRef meta : icacheMetas.values()) {
            sb.append("    {\"")
                .append(CStringLiteral.escape(meta.name()))
                .append("\", \"")
                .append(CStringLiteral.escape(meta.desc()))
                .append("\", ")
                .append(
                    meta.translatedClassSlot() == null
                        ? "NULL"
                        : "&" + meta.translatedClassSlot()
                )
                .append(", ")
                .append(
                    meta.translatedStubSymbol() == null
                        ? "NULL"
                        : meta.translatedStubSymbol()
                )
                .append(", ")
                .append(meta.isInterface() ? "JNI_TRUE" : "JNI_FALSE")
                .append(", ")
                .append(
                    meta.directDispatcherSymbol() == null
                        ? "NULL"
                        : meta.directDispatcherSymbol()
                )
                .append("},   // ")
                .append(meta.symbol())
                .append('\n');
            icacheMetaIndex++;
        }
        sb.append("};\n");
        icacheMetaIndex = 0;
        for (IcacheMetaRef meta : icacheMetas.values()) {
            sb.append("#define ")
                .append(meta.symbol())
                .append(" (neko_icache_metas[")
                .append(icacheMetaIndex++)
                .append("])\n");
        }
        sb.append('\n');
        return sb.toString();
    }

    private String renderIcacheDirectStub(IcacheDirectStubRef stub) {
        StringBuilder sb = new StringBuilder();
        sb.append("static jvalue ")
            .append(stub.symbol())
            .append(
                "(void *thread, JNIEnv *env, jobject receiver, const jvalue *args) {\n"
            );
        sb.append("    jvalue result = {0};\n");
        if (stub.returnType().getSort() != Type.VOID) {
            sb.append("    result")
                .append(jvalueAccessor(stub.returnType()))
                .append(" = ");
        } else {
            sb.append("    ");
        }
        sb.append(stub.binding().rawFunctionName())
            .append("(thread, env, neko_bound_class(env, ")
            .append(classSlotName(stub.binding().ownerInternalName()))
            .append(", \"")
            .append(CStringLiteral.escape(stub.binding().ownerInternalName()))
            .append("\"), receiver");
        for (int i = 0; i < stub.args().length; i++) {
            sb.append(", ");
            if (stub.args()[i].getSort() == Type.ARRAY) {
                sb.append("(jarray)");
            } else if (stub.args()[i].getSort() == Type.OBJECT) {
                sb.append("(jobject)");
            }
            sb.append("args[")
                .append(i)
                .append("]")
                .append(jvalueAccessor(stub.args()[i]));
        }
        sb.append(");\n");
        sb.append("    return result;\n");
        sb.append("}\n\n");
        return sb.toString();
    }

    private record FieldDescriptorRef(
        int index,
        String owner,
        String name,
        String desc,
        boolean isStatic,
        String fieldSlot,
        String accessFlagsSlot
    ) {
        String symbol() {
            return "g_field_ref_" + index;
        }
    }

    private record ClassDescriptorRef(
        int index,
        String owner,
        String classSlot
    ) {
        String symbol() {
            return "g_class_ref_" + index;
        }
    }

    private record MethodIdDescriptorRef(
        int index,
        String owner,
        String name,
        String desc,
        boolean isStatic,
        String methodSlot
    ) {
        String symbol() {
            return "g_method_id_ref_" + index;
        }
    }

    private record MethodEntryDescriptorRef(
        int index,
        String owner,
        String name,
        String desc,
        String methodPtrSlot,
        String methodIEntrySlot
    ) {
        String symbol() {
            return "g_method_entry_ref_" + index;
        }
    }

    private boolean isPrimitiveFieldDescriptor(String desc) {
        return (
            desc != null &&
            desc.length() == 1 &&
            "ZBCSIJFD".indexOf(desc.charAt(0)) >= 0
        );
    }

    private String jniType(Type type) {
        return switch (type.getSort()) {
            case Type.VOID -> "void";
            case Type.BOOLEAN -> "jboolean";
            case Type.CHAR -> "jchar";
            case Type.BYTE -> "jbyte";
            case Type.SHORT -> "jshort";
            case Type.INT -> "jint";
            case Type.FLOAT -> "jfloat";
            case Type.LONG -> "jlong";
            case Type.DOUBLE -> "jdouble";
            case Type.ARRAY -> "jarray";
            default -> "jobject";
        };
    }

    private String objectArrayDescriptor(String elementInternalName) {
        if (elementInternalName.startsWith("[")) {
            return "[" + elementInternalName;
        }
        return "[L" + elementInternalName + ";";
    }

    private String renderParam(CVariable variable) {
        if ("env".equals(variable.name())) {
            return "JNIEnv *env";
        }
        if ("thread".equals(variable.name())) {
            return "void *thread";
        }
        return variable.declaration();
    }

    public record GeneratedSourceSet(
        GeneratedSourceFile supportSource,
        List<GeneratedSourceFile> supportSources,
        GeneratedSourceFile implementationHeader,
        List<GeneratedSourceFile> implementationHeaders,
        List<GeneratedSourceFile> implementationSources,
        String monolithicSource
    ) {
        public GeneratedSourceSet {
            supportSources =
                supportSources == null
                    ? List.of()
                    : List.copyOf(supportSources);
            implementationHeaders =
                implementationHeaders == null
                    ? List.of()
                    : List.copyOf(implementationHeaders);
            implementationSources =
                implementationSources == null
                    ? List.of()
                    : List.copyOf(implementationSources);
        }

        public GeneratedSourceSet(
            GeneratedSourceFile supportSource,
            List<GeneratedSourceFile> implementationSources,
            String monolithicSource
        ) {
            this(
                supportSource,
                List.of(),
                null,
                List.of(),
                implementationSources,
                monolithicSource
            );
        }

        public List<GeneratedSourceFile> allSources() {
            List<GeneratedSourceFile> sources = new ArrayList<>(
                1 + supportSources.size() + implementationSources.size()
            );
            sources.add(supportSource);
            sources.addAll(supportSources);
            sources.addAll(implementationSources);
            return List.copyOf(sources);
        }

        public List<GeneratedSourceFile> allImplementationHeaders() {
            List<GeneratedSourceFile> headers = new ArrayList<>(
                1 + implementationHeaders.size()
            );
            if (implementationHeader != null) {
                headers.add(implementationHeader);
            }
            headers.addAll(implementationHeaders);
            return List.copyOf(headers);
        }
    }

    private record ImplicitExceptionRef(
        int index,
        String owner,
        String ctorDesc,
        String classSlot,
        String methodPtrSlot,
        String methodIEntrySlot,
        String dispatcher
    ) {
        String symbol() {
            return "g_implicit_exception_ref_" + index;
        }
    }

    public record GeneratedSourceFile(String fileName, String source) {}

    private record GlobalSupportSplit(String mainSource, String globalSource) {}

    private record SupportFunctionSplit(
        String mainSource,
        List<GeneratedSourceFile> helperSources
    ) {}

    private record MethodRef(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {}

    private record FieldRef(
        String owner,
        String name,
        String desc,
        boolean isStatic
    ) {}

    private record StaticFieldDescriptorRef(
        int index,
        String owner,
        String name,
        String desc,
        String classSlot,
        String classInitSlot,
        String fieldSlot,
        String staticBaseSlot,
        String staticOffsetSlot,
        String accessFlagsSlot
    ) {
        String symbol() {
            return "g_static_field_ref_" + index;
        }
    }

    private record StringRef(String cacheVar, String value) {}

    private static String primitiveClassSlotKey(String desc) {
        return "#primitive/" + desc;
    }

    private String jvalueAccessor(Type type) {
        return switch (type.getSort()) {
            case Type.BOOLEAN -> ".z";
            case Type.BYTE -> ".b";
            case Type.CHAR -> ".c";
            case Type.SHORT -> ".s";
            case Type.INT -> ".i";
            case Type.FLOAT -> ".f";
            case Type.LONG -> ".j";
            case Type.DOUBLE -> ".d";
            default -> ".l";
        };
    }

    private record IcacheSiteRef(
        int ownerId,
        int methodId,
        int siteIndex,
        String bindingOwner,
        String methodKey
    ) {
        private String symbol() {
            return "neko_icache_" + ownerId + '_' + methodId + '_' + siteIndex;
        }
    }

    private record IcacheDirectStubRef(
        int ownerId,
        int methodId,
        int siteIndex,
        NativeMethodBinding binding,
        Type[] args,
        Type returnType
    ) {
        private String symbol() {
            return (
                "neko_icache_stub_" + ownerId + '_' + methodId + '_' + siteIndex
            );
        }
    }

    private record IcacheMetaRef(
        int ownerId,
        int methodId,
        int siteIndex,
        String name,
        String desc,
        boolean isInterface,
        String translatedClassSlot,
        String translatedStubSymbol,
        String directDispatcherSymbol
    ) {
        private String symbol() {
            return (
                "neko_icache_meta_" + ownerId + '_' + methodId + '_' + siteIndex
            );
        }
    }

    private static final class OwnerResolution {

        private final Set<String> classes = new LinkedHashSet<>();
        private final Set<String> primitiveClasses = new LinkedHashSet<>();
        private final Set<MethodRef> methods = new LinkedHashSet<>();
        private final Set<FieldRef> fields = new LinkedHashSet<>();
        private final Set<StringRef> strings = new LinkedHashSet<>();
    }
}
