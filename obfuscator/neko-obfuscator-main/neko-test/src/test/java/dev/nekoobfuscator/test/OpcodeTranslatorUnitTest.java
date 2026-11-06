package dev.nekoobfuscator.test;

import dev.nekoobfuscator.core.ir.l3.CStatement;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.native_.translator.NativeTranslator;
import dev.nekoobfuscator.native_.translator.NativeTranslator.MethodSelection;
import dev.nekoobfuscator.native_.codegen.CCodeGenerator;
import dev.nekoobfuscator.native_.translator.OpcodeTranslator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpcodeTranslatorUnitTest {
    private static final String TARGET_LABEL = "L_target";

    @Test
    void opcodeTranslator_constantsEmitExpectedPushes() {
        OpcodeTranslator translator = translator();

        String iconst = render(translator.translate(new InsnNode(Opcodes.ICONST_0)));
        String bipush = render(translator.translate(new IntInsnNode(Opcodes.BIPUSH, 42)));
        String sipush = render(translator.translate(new IntInsnNode(Opcodes.SIPUSH, 32000)));
        String dconst = render(translator.translate(new InsnNode(Opcodes.DCONST_1)));
        String nullConst = render(translator.translate(new InsnNode(Opcodes.ACONST_NULL)));

        assertContains(iconst, "PUSH_I(0);");
        assertContains(bipush, "PUSH_I(42);");
        assertContains(sipush, "PUSH_I(32000);");
        assertContains(dconst, "PUSH_D(1.0);");
        assertContains(nullConst, "PUSH_O(NULL);");
    }

    @Test
    void opcodeTranslator_loadsReadFromLocals() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new VarInsnNode(Opcodes.ILOAD, 1)).getFirst(),
            translator.translate(new VarInsnNode(Opcodes.LLOAD, 2)).getFirst(),
            translator.translate(new VarInsnNode(Opcodes.DLOAD, 3)).getFirst(),
            translator.translate(new VarInsnNode(Opcodes.ALOAD, 4)).getFirst()
        ));

        assertContains(code, "PUSH_I(locals[1].i);", "PUSH_L(locals[2].j);", "PUSH_D(locals[3].d);", "PUSH_O(locals[4].o);");
    }

    @Test
    void opcodeTranslator_storesPopIntoLocals() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new VarInsnNode(Opcodes.ISTORE, 1)).getFirst(),
            translator.translate(new VarInsnNode(Opcodes.LSTORE, 2)).getFirst(),
            translator.translate(new VarInsnNode(Opcodes.ASTORE, 3)).getFirst()
        ));

        assertContains(code, "locals[1].i = POP_I();", "locals[2].j = POP_L();",
            "{ jobject __ref = POP_O(); locals[3].o = neko_store_local_oop_ref(thread, &__neko_local_roots[3], __ref); }");
    }

    @Test
    void opcodeTranslator_integerArithmeticUsesTwoPopsAndOnePush() {
        OpcodeTranslator translator = translator();
        translator.beginMethod("pkg/MathOwner", "demo", "()V", true);
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.IADD)).getFirst(),
            translator.translate(new InsnNode(Opcodes.IMUL)).getFirst(),
            translator.translate(new InsnNode(Opcodes.IDIV)).getFirst(),
            translator.translate(new InsnNode(Opcodes.IREM)).getFirst(),
            translator.translate(new InsnNode(Opcodes.INEG)).getFirst()
        ));

        assertContains(code,
            "jint b = POP_I(); jint a = POP_I(); PUSH_I(a + b);",
            "jint b = POP_I(); jint a = POP_I(); PUSH_I(a * b);",
            "jint b = POP_I(); jint a = POP_I(); if (b == 0) {",
            "neko_raise_implicit_exception_ref(thread, env, &g_implicit_exception_ref_",
            "PUSH_I(a / b);",
            "PUSH_I(a % b);",
            "PUSH_I(-POP_I());");
    }

    @Test
    void opcodeTranslator_longArithmeticAndShiftUseWidePopPushPatterns() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.LADD)).getFirst(),
            translator.translate(new InsnNode(Opcodes.LMUL)).getFirst(),
            translator.translate(new InsnNode(Opcodes.LSHL)).getFirst(),
            translator.translate(new InsnNode(Opcodes.IUSHR)).getFirst()
        ));

        assertContains(code,
            "jlong b = POP_L(); jlong a = POP_L(); PUSH_L(a + b);",
            "jlong b = POP_L(); jlong a = POP_L(); PUSH_L(a * b);",
            "jint __s = POP_I(); jlong __v = POP_L(); PUSH_L(__v << (__s & 0x3F));",
            "PUSH_I((jint)((uint32_t)a >> (b & 0x1f)));"
        );
    }

    @Test
    void opcodeTranslator_floatAndDoubleArithmeticUseMathHelpers() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.FADD)).getFirst(),
            translator.translate(new InsnNode(Opcodes.FREM)).getFirst(),
            translator.translate(new InsnNode(Opcodes.DADD)).getFirst(),
            translator.translate(new InsnNode(Opcodes.DREM)).getFirst()
        ));

        assertContains(code,
            "jfloat b = POP_F(); jfloat a = POP_F(); PUSH_F(a + b);",
            "PUSH_F(fmodf(a, b));",
            "jdouble b = POP_D(); jdouble a = POP_D(); PUSH_D(a + b);",
            "PUSH_D(fmod(a, b));"
        );
    }

    @Test
    void opcodeTranslator_bitwiseAndConversionsEmitExpectedCasts() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.IAND)).getFirst(),
            translator.translate(new InsnNode(Opcodes.IOR)).getFirst(),
            translator.translate(new InsnNode(Opcodes.IXOR)).getFirst(),
            translator.translate(new InsnNode(Opcodes.I2L)).getFirst(),
            translator.translate(new InsnNode(Opcodes.L2I)).getFirst(),
            translator.translate(new InsnNode(Opcodes.F2D)).getFirst(),
            translator.translate(new InsnNode(Opcodes.I2B)).getFirst()
        ));

        assertContains(code,
            "PUSH_I(a & b);",
            "PUSH_I(a | b);",
            "PUSH_I(a ^ b);",
            "PUSH_L((jlong)POP_I());",
            "PUSH_I((jint)POP_L());",
            "PUSH_D((jdouble)POP_F());",
            "PUSH_I((jbyte)POP_I());"
        );
    }

    @Test
    void opcodeTranslator_stackOpsManipulateSlotsDirectly() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.POP)).getFirst(),
            translator.translate(new InsnNode(Opcodes.POP2)).getFirst(),
            translator.translate(new InsnNode(Opcodes.DUP)).getFirst(),
            translator.translate(new InsnNode(Opcodes.DUP_X1)).getFirst(),
            translator.translate(new InsnNode(Opcodes.DUP_X2)).getFirst(),
            translator.translate(new InsnNode(Opcodes.SWAP)).getFirst()
        ));

        assertContains(code,
            "sp--;",
            "sp -= 2;",
            "stack[sp] = stack[sp-1]; sp++;",
            "stack[sp-1] = stack[sp-2];",
            "stack[sp-3] = v1;",
            "stack[sp-1] = stack[sp-2]; stack[sp-2] = t;"
        );
    }

    @Test
    void opcodeTranslator_comparisonsPushComparisonResults() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.LCMP)).getFirst(),
            translator.translate(new InsnNode(Opcodes.FCMPL)).getFirst(),
            translator.translate(new InsnNode(Opcodes.DCMPG)).getFirst()
        ));

        assertContains(code,
            "PUSH_I(a > b ? 1 : (a < b ? -1 : 0));",
            "PUSH_I(a > b ? 1 : (a < b ? -1 : (a == b ? 0 : -1)));",
            "PUSH_I(a > b ? 1 : (a < b ? -1 : (a == b ? 0 : 1)));"
        );
    }

    @Test
    void opcodeTranslator_jumpsEmitTargetLabels() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translateJump(new JumpInsnNode(Opcodes.IFEQ, new LabelNode()), TARGET_LABEL),
            translator.translateJump(new JumpInsnNode(Opcodes.IF_ICMPNE, new LabelNode()), TARGET_LABEL),
            translator.translateJump(new JumpInsnNode(Opcodes.IFNULL, new LabelNode()), TARGET_LABEL)
        ));

        assertContains(code,
            "if (POP_I() == 0) goto " + TARGET_LABEL + ';',
            "jint b = POP_I(); jint a = POP_I(); if (a != b) goto " + TARGET_LABEL + ';',
            "if (POP_O() == NULL) goto " + TARGET_LABEL + ';'
        );
    }

    @Test
    void opcodeTranslator_returnsAndNoopEmitTerminalStatements() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.IRETURN)).getFirst(),
            translator.translate(new InsnNode(Opcodes.LRETURN)).getFirst(),
            translator.translate(new InsnNode(Opcodes.RETURN)).getFirst(),
            translator.translate(new InsnNode(Opcodes.NOP)).getFirst(),
            translator.translate(new IincInsnNode(4, 3)).getFirst()
        ));

        assertContains(code,
            "{ jint __ret = POP_I(); neko_shadow_pop(); return __ret; }",
            "{ jlong __ret = POP_L(); neko_shadow_pop(); return __ret; }",
            "neko_shadow_pop(); return;",
            "/* nop */",
            "locals[4].i += 3;"
        );
    }

    @Test
    void opcodeTranslator_monitorOpsUseRuntime1StubHelpers() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.MONITORENTER)).getFirst(),
            translator.translate(new InsnNode(Opcodes.MONITOREXIT)).getFirst()
        ));

        assertContains(code,
            "neko_fast_monitor_enter(thread, __mon, &monitors[monitor_sp++]);",
            "neko_fast_monitor_exit(thread, __mon, &monitors[--monitor_sp]);"
        );
        assertFalse(code.contains("neko_monitor_enter(env,"), code);
        assertFalse(code.contains("neko_monitor_exit(env,"), code);
    }

    @Test
    void opcodeTranslator_arrayOpsUseDirectArrayHelpers() {
        OpcodeTranslator translator = translator();
        translator.beginMethod("pkg/ArrayOwner", "demo", "()V", true);
        String code = render(List.of(
            translator.translate(new InsnNode(Opcodes.IALOAD)).getFirst(),
            translator.translate(new InsnNode(Opcodes.IASTORE)).getFirst(),
            translator.translate(new InsnNode(Opcodes.ARRAYLENGTH)).getFirst(),
            translator.translate(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT)).getFirst(),
            translator.translate(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String")).getFirst(),
            translator.translate(new MultiANewArrayInsnNode("[[I", 2)).getFirst()
        ));

        assertContains(code,
            "neko_checked_iaload(thread, env,",
            "neko_checked_iastore(thread, env,",
            "neko_raise_cached_fast_array_reason(thread, env,",
            "neko_raise_implicit_exception_ref(thread, env, &g_implicit_exception_ref_",
            "neko_fast_array_length(arr)",
            "PUSH_O(neko_fast_new_primitive_array(thread, env, len, NEKO_PRIM_I));",
            "PUSH_O(neko_fast_new_object_array(thread, env, len,",
            "PUSH_O(neko_multi_new_array(thread, env, 2, __dims, \"[[I\",",
            "neko_bound_class_ref(env, &g_class_ref_"
        );
        assertFalse(code.contains("neko_new_object_array(env,"), code);
        assertFalse(code.contains("neko_bound_class(env, g_cls_"), code);
    }

    @Test
    void opcodeTranslator_fieldOpsResolveFieldIdsAndAccessors() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new FieldInsnNode(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")).getFirst(),
            translator.translate(new FieldInsnNode(Opcodes.PUTFIELD, "java/lang/String", "value", "[B")).getFirst()
        ));

        assertContains(code,
            "neko_fast_get_static_object_field_ref(thread, env, &g_static_field_ref_",
            "PUSH_O(",
            "jobject obj = POP_O();",
            "jfieldID fid = neko_bound_field_ref(env, &g_field_ref_",
            "neko_fast_set_object_field(thread, env, obj, fid,"
        );
        assertFalse(code.contains("neko_set_object_field("), code);
    }

    @Test
    void primitiveFieldFastPath() {
        for (char primitive : primitiveFieldTypes()) {
            String desc = String.valueOf(primitive);

            String instanceGetBody = translatedBodySection(translateSingleMethod(
                primitiveFieldOwner("FieldGet" + primitive, "value", desc, 0, primitiveReturnInsn(primitive), false)
            ));
            assertTrue(instanceGetBody.contains("neko_fast_get_" + primitive + "_field("), instanceGetBody);
            assertFalse(instanceGetBody.contains(jniFieldGetterName(primitive) + "(env,"), instanceGetBody);

            String instancePutBody = translatedBodySection(translateSingleMethod(
                primitiveFieldOwner("FieldPut" + primitive, "value", desc, primitiveLoadOpcode(primitive), Opcodes.RETURN, false)
            ));
            assertTrue(instancePutBody.contains("neko_fast_set_" + primitive + "_field("), instancePutBody);
            assertFalse(instancePutBody.contains(jniFieldSetterName(primitive) + "(env,"), instancePutBody);
            assertTrue(instanceGetBody.contains("jfieldID fid = neko_bound_field_ref(env, &g_field_ref_"), instanceGetBody);
            assertTrue(instancePutBody.contains("jfieldID fid = neko_bound_field_ref(env, &g_field_ref_"), instancePutBody);

            String staticGetBody = translatedBodySection(translateSingleMethod(
                primitiveFieldOwner("FieldGetStatic" + primitive, "value", desc, 0, primitiveReturnInsn(primitive), true)
            ));
            assertTrue(staticGetBody.contains("neko_fast_get_static_" + primitive + "_field_ref(env, &g_static_field_ref_"), staticGetBody);
            assertFalse(staticGetBody.contains("neko_ensure_class_initialized_once(env, cls,"), staticGetBody);
            assertFalse(staticGetBody.contains(jniStaticFieldGetterName(primitive) + "(env,"), staticGetBody);

            String staticPutBody = translatedBodySection(translateSingleMethod(
                primitiveFieldOwner("FieldPutStatic" + primitive, "value", desc, primitiveLoadOpcode(primitive), Opcodes.RETURN, true)
            ));
            assertTrue(staticPutBody.contains("neko_ensure_class_initialized_once(env, cls,"), staticPutBody);
            assertTrue(staticPutBody.contains("neko_fast_set_static_" + primitive + "_field("), staticPutBody);
            assertFalse(staticPutBody.contains(jniStaticFieldSetterName(primitive) + "(env,"), staticPutBody);
            assertTrue(staticPutBody.contains("jfieldID fid = neko_bound_field_ref(env, &g_field_ref_"), staticPutBody);
        }
    }

    @Test
    void primitiveArrayScalarFastPath() {
        for (ArrayFastCase testCase : primitiveArrayFastCases()) {
            String loadBody = translatedBodySection(translateSingleMethod(primitiveArrayLoadOwner(testCase)));
            assertTrue(loadBody.contains("neko_checked_" + testCase.helperPrefix() + "aload(thread, env,"), loadBody);
            assertFalse(loadBody.contains("neko_checked_" + testCase.helperPrefix() + "aload(env,"), loadBody);
            assertFalse(loadBody.contains(testCase.jniGetHelper() + "(env,"), loadBody);

            String storeBody = translatedBodySection(translateSingleMethod(primitiveArrayStoreOwner(testCase)));
            assertTrue(storeBody.contains("neko_checked_" + testCase.helperPrefix() + "astore(thread, env,"), storeBody);
            assertFalse(storeBody.contains("neko_checked_" + testCase.helperPrefix() + "astore(env,"), storeBody);
            assertFalse(storeBody.contains(testCase.jniSetHelper() + "(env,"), storeBody);
        }
    }

    @Test
    void objectArrayOpcodesUseFastAaloadPath() {
        /* AALOAD now goes through neko_fast_aaload, which reads the narrow-oop
         * element directly from the array layout (decoded via VMStructs-derived
         * compressed-oops base/shift) and pushes it into the active
         * JNIHandleBlock without crossing the JNI handle-allocation path. */
        String aaloadBody = translatedBodySection(translateSingleMethod(objectArrayLoadOwner()));
        assertContains(aaloadBody, "neko_checked_aaload(thread, env,");
        assertContains(aaloadBody, "neko_raise_cached_fast_array_reason(thread, env,");
        assertFalse(aaloadBody.contains("neko_get_object_array_element"), aaloadBody);

        String aastoreBody = translatedBodySection(translateSingleMethod(objectArrayStoreOwner()));
        assertContains(aastoreBody, "neko_checked_aastore(thread, env,");
        assertContains(aastoreBody, "neko_raise_cached_fast_array_reason(thread, env,");
        assertFalse(aastoreBody.contains("neko_set_object_array_element("), aastoreBody);
    }

    @Test
    void opcodeTranslator_invokeOpsBuildJniCallSequences() {
        OpcodeTranslator translator = translator();
        String code = render(List.of(
            translator.translate(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "abs", "(I)I", false)).getFirst(),
            translator.translate(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "hashCode", "()I", false)).getFirst()
        ));

        assertContains(code,
            "jclass cls =",
            "jmethodID mid =",
            "__args",
            "POP_O();"
        );
    }

    @Test
    void opcodeTranslator_objectOpsAllocateAndCheckTypes() {
        OpcodeTranslator translator = translator();
        translator.beginMethod("pkg/Owner", "demo", "()V", true);
        String code = render(List.of(
            translator.translate(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder")).getFirst(),
            translator.translate(new TypeInsnNode(Opcodes.INSTANCEOF, "java/lang/String")).getFirst(),
            translator.translate(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String")).getFirst(),
            translator.translate(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false)).getFirst()
        ));

        assertContains(code,
            "neko_fast_alloc_object(thread, env, cls)",
            "neko_fast_is_instance_of(env, obj, cls)",
            "neko_icache_dispatch(thread, env, &neko_icache_",
            "neko_raise_implicit_exception_ref(thread, env, &g_implicit_exception_ref_",
            "goto __neko_exception_exit;"
        );
        assertFalse(code.contains("neko_alloc_object(env,"), code);
        assertFalse(code.contains("neko_is_instance_of(env,"), code);
        assertFalse(code.contains("neko_get_object_class(env,"), code);
    }

    @Test
    void opcodeTranslator_athrowWritesPendingExceptionDirectly() {
        OpcodeTranslator translator = translator();
        translator.beginMethod("pkg/ThrowOwner", "demo", "()V", true);
        String code = render(translator.translate(new InsnNode(Opcodes.ATHROW)));

        assertContains(code,
            "jthrowable __athrow = (jthrowable)POP_O();",
            "neko_raise_implicit_exception_ref(thread, env, &g_implicit_exception_ref_",
            "neko_set_pending_exception(thread, __athrow);"
        );
        assertFalse(code.contains("neko_throw(env"), code);
        assertFalse(code.contains("neko_throw_new(env"), code);
    }

    @Test
    void nativeTranslator_exceptionDispatchUsesPendingExceptionDirectly() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/CatchOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()I", null, null);
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/NullPointerException"));
        method.instructions.add(start);
        method.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
        method.instructions.add(new InsnNode(Opcodes.ARRAYLENGTH));
        method.instructions.add(end);
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(handler);
        method.instructions.add(new InsnNode(Opcodes.POP));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 0;
        classNode.methods.add(method);

        String source = translateSingleMethod(classNode);
        String body = translatedBodySection(source);
        int manifestStart = body.indexOf("\n\n/* === Manifest tables");
        String methodBody = manifestStart >= 0 ? body.substring(0, manifestStart) : body;

        assertContains(methodBody,
            "jthrowable __exc = neko_take_pending_exception(thread);",
            "neko_exception_handler_matches_ref(env, __exc, &g_class_ref_",
            "neko_set_pending_exception(thread, __exc);"
        );
        assertFalse(methodBody.contains("neko_exception_occurred(env)"), methodBody);
        assertFalse(methodBody.contains("neko_exception_clear(env)"), methodBody);
        assertFalse(methodBody.contains("neko_find_class(env, \"java/lang/NullPointerException\")"), methodBody);
        assertFalse(methodBody.contains("neko_is_instance_of(env, __exc"), methodBody);
    }

    @Test
    void stringConcatFallbackAvoidsStringBuilderAndBoxingFallback() {
        OpcodeTranslator translator = translator();
        translator.beginMethod("pkg/ConcatOwner", "run", "()V", true);
        Handle bootstrap = new Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        );

        String code = render(translator.translate(new InvokeDynamicInsnNode(
            "makeConcatWithConstants",
            "(DI)Ljava/lang/String;",
            bootstrap,
            "area=\u0001 count=\u0001"
        )));

        assertContains(code, "neko_bound_method_i_entry_ref(&g_method_entry_ref_", "neko_concat_accumulate_string");
        assertFalse(code.contains("neko_concat_accumulate(thread, env, __acc"), code);
        assertFalse(code.contains("java/lang/StringBuilder"), code);
        assertFalse(code.contains("java/lang/StringConcatHelper"), code);
        assertFalse(code.contains("simpleConcat"), code);
        assertFalse(code.contains("java/lang/String\", \"concat\""), code);
        assertFalse(code.contains("neko_box_"), code);
        assertFalse(code.contains("neko_new_object_a(env"), code);
    }

    @Test
    void stringConcatFullSourceDeclaresMacroAndStringOffsets() {
        String source = translateSingleMethod(stringConcatInvokeDynamicOwner());
        String body = translatedBodySection(source);

        assertContains(source,
            "#define neko_concat_accumulate_string(thread, env, acc, rhs)",
            "g_off_"
        );
        assertContains(body, "neko_concat_accumulate_string(thread, env, __acc");
        assertFalse(body.contains("neko_concat_accumulate(thread, env, __acc"), body);
        assertFalse(source.contains("NEKO_JNI_FN_PTR"), source);
        assertFalse(source.contains("(*env)->"), source);
        assertFalse(source.contains("env->"), source);
    }

    @Test
    void stringBuilderConcatPatternUsesRequiredFastConcatOnly() {
        String source = translateSingleMethod(stringBuilderConcatOwner());
        String body = translatedBodySection(source);

        assertContains(body, "neko_bind_string_slot(thread, env", "neko_concat_append_inline");
        assertFalse(body.contains("neko_concat_append(thread, env"), body);
        assertFalse(body.contains("java/lang/StringConcatHelper"), body);
        assertFalse(body.contains("simpleConcat"), body);
        assertFalse(body.contains("neko_new_string_utf(env, \"!\""), body);
        assertFalse(body.contains("java/lang/String\", \"concat\""), body);
        assertFalse(body.contains("neko_box_"), body);
    }

    @Test
    void stringBuilderConcatImmediateAstoreUsesRawLocalPublication() {
        String source = translateSingleMethod(stringBuilderConcatImmediateStoreOwner());
        String body = translatedBodySection(source);

        assertContains(body,
            "neko_concat_append_inline_store_local(thread, env, &__neko_local_roots[1]",
            "locals[1].o = __fastConcat"
        );
        assertFalse(body.contains("PUSH_O(__fastConcat);"), body);
        assertFalse(body.contains("jobject __ref = POP_O(); locals[1].o"), body);
    }

    @Test
    void stringBuilderConcatLengthRecurrenceScalarizesWhenLocalDiesAtReturn() {
        String source = translateSingleMethod(stringBuilderConcatLengthRecurrenceOwner(false));
        String body = translatedBodySection(source);

        assertContains(body, "scalarized same-local StringBuilder concat recurrence", "__neko_scalar_concat_len_");
        assertContains(body, "neko_fast_set_static_I_field");
        assertFalse(body.contains("neko_concat_append_inline_store_local"), body);
        assertFalse(body.contains("neko_build_raw_string_graph_store_local"), body);
    }

    @Test
    void stringBuilderConcatLengthRecurrenceKeepsConcatWhenLocalEscapesAfterExit() {
        String source = translateSingleMethod(stringBuilderConcatLengthRecurrenceOwner(true));
        String body = translatedBodySection(source);

        assertFalse(body.contains("scalarized same-local StringBuilder concat recurrence"), body);
        assertContains(body, "neko_concat_append_inline_store_local(thread, env, &__neko_local_roots[0]");
    }

    @Test
    void methodHandleExactBridgeNoArrayAlloc() {
        for (boolean invokeExact : List.of(false, true)) {
            TranslationArtifact artifact = translateSingleMethodArtifact(methodHandleBridgeOwner(invokeExact));
            String body = translatedBodySection(artifact.source());

            assertTrue(body.contains("neko_bound_method_ref(env, &g_method_id_ref_"), body);
            assertTrue(body.contains("neko_bound_method_i_entry_ref(&g_method_entry_ref_"), body);
            assertFalse(body.contains("neko_call_static_int_method_a("), body);

            int mhLoad = body.indexOf("jobject __mh = POP_O();");
            assertTrue(mhLoad >= 0, body);
            String bridgePath = body.substring(mhLoad);
            assertFalse(bridgePath.contains("neko_new_object_array("), bridgePath);
            assertFalse(bridgePath.contains("neko_set_object_array_element("), bridgePath);

            MethodNode bridge = artifact.classNode().methods.stream()
                .filter(candidate -> candidate.name.startsWith("neko$mh$"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing MethodHandle bridge method"));
            assertTrue(bridge.desc.startsWith("(Ljava/lang/invoke/MethodHandle;I)I"), bridge.desc);
        }
    }

    @Test
    void methodHandleUnknownDescriptorRejectsWithoutFallback() {
        for (boolean invokeExact : List.of(false, true)) {
            OpcodeTranslator translator = translator();
            translator.beginMethod("pkg/FallbackMh", "run", "(Ljava/lang/invoke/MethodHandle;I)I", true);

            IllegalStateException error = assertThrows(IllegalStateException.class, () -> translator.translate(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodHandle",
                invokeExact ? "invokeExact" : "invoke",
                "(I)I",
                false
            )));

            assertTrue(error.getMessage().contains("Unsupported MethodHandle invoke without native call-stub bridge"), error::getMessage);
        }
    }

    @Test
    void invokeVirtualUsesReceiverKeyCache() {
        String source = translateSingleMethod(virtualInvokeOwner());
        String body = translatedBodySection(source);

        assertContains(body, "neko_icache_dispatch(", "&neko_icache_", "jmethodID mid = neko_bound_method_ref(env, &g_method_id_ref_");
        assertFalse(body.contains("neko_bound_method(env, g_mid_"), body);
        assertTrue(source.contains("receiverKey = (uintptr_t)receiverKlass;"), source);
        assertFalse(Pattern.compile("neko_call_(?:static_|nonvirtual_)?\\w+_method_a\\(").matcher(source).find(), source);
    }

    @Test
    void stringLengthVirtualInvokeUsesNativeIntrinsic() {
        String source = translateSingleMethod(stringLengthOwner());
        String body = translatedBodySection(source);

        assertContains(body,
            "neko_fast_string_length(",
            "neko_raise_implicit_exception_ref(thread, env, &g_implicit_exception_ref_",
            "PUSH_I(");
        assertFalse(body.contains("neko_icache_dispatch("), body);
        assertFalse(body.contains("neko_bound_method_ref(env"), body);
        assertFalse(body.contains("NEKO_JNI_FN_PTR"), body);
        assertFalse(Pattern.compile("neko_call_(?:static_|nonvirtual_)?\\w+_method_a\\(").matcher(body).find(), body);
    }

    @Test
    void invokeInterfaceUsesReceiverKeyCache() {
        String source = translateSingleMethod(interfaceInvokeOwner());
        String body = translatedBodySection(source);

        assertContains(body, "neko_icache_dispatch(", "JNI_TRUE", "&neko_icache_", "jmethodID mid = neko_bound_method_ref(env, &g_method_id_ref_");
        assertFalse(body.contains("neko_bound_method(env, g_mid_"), body);
        assertTrue(source.contains("receiverKey = (uintptr_t)receiverKlass;"), source);
        assertFalse(Pattern.compile("neko_call_(?:static_|nonvirtual_)?\\w+_method_a\\(").matcher(source).find(), source);
    }

    @Test
    void invokeStaticSpecialFinalUnchanged() {
        String source = translateMethods(
            multiTargetHelperClass(),
            multiTargetBaseClass(),
            multiTargetFinalClass(),
            multiTargetCallerClass()
        );
        String body = translatedBodySection(source, "pkg/MultiTargetCaller", "run", "(Lpkg/MultiTargetFinal;)I");

        assertContains(body,
            manifestImplName(source, "pkg/MultiTargetHelper", "staticValue", "()I"),
            manifestImplName(source, "pkg/MultiTargetBase", "baseValue", "()I"),
            manifestImplName(source, "pkg/MultiTargetFinal", "finalValue", "()I"));
        assertFalse(body.contains("neko_receiver_key("), body);
        assertFalse(body.contains("neko_icache_"), body);
    }

    @Test
    void nativeTranslatorCompactsSequentialIntArrayLiteralInitialization() {
        String source = translateSingleMethod(primitiveArrayLiteralOwner("pkg/IntLiteralArray", "()[I", Opcodes.T_INT, Opcodes.IASTORE));
        String body = translatedBodySection(source);

        assertContains(body,
            "static const jint __neko_primitive_array_literal_",
            "neko_fast_new_primitive_array(thread, env, 4, NEKO_PRIM_I)",
            "memcpy(__oop + neko_const_prim_array_base(NEKO_PRIM_I)",
            "PUSH_O(__a);");
        assertFalse(body.contains("neko_checked_iastore"), body);
    }

    @Test
    void nativeTranslatorCompactsSequentialDoubleArrayLiteralInitialization() {
        String source = translateSingleMethod(primitiveArrayLiteralOwner("pkg/DoubleLiteralArray", "()[D", Opcodes.T_DOUBLE, Opcodes.DASTORE));
        String body = translatedBodySection(source);

        assertContains(body,
            "static const uint64_t __neko_primitive_array_literal_",
            "neko_fast_new_primitive_array(thread, env, 4, NEKO_PRIM_D)",
            "memcpy(__oop + neko_const_prim_array_base(NEKO_PRIM_D)",
            "PUSH_O(__a);");
        assertFalse(body.contains("neko_checked_dastore"), body);
    }

    @Test
    void nativeTranslatorDoesNotCompactArrayLiteralAcrossLabelBoundary() {
        String source = translateSingleMethod(primitiveArrayLiteralOwner(
            "pkg/LabeledLiteralArray", "()[I", Opcodes.T_INT, Opcodes.IASTORE, true, false));
        String body = translatedBodySection(source);

        assertFalse(body.contains("__neko_primitive_array_literal_"), body);
        assertContains(body, "neko_checked_iastore");
    }

    @Test
    void nativeTranslatorDoesNotCompactNonSequentialArrayStores() {
        String source = translateSingleMethod(primitiveArrayLiteralOwner(
            "pkg/NonSequentialLiteralArray", "()[I", Opcodes.T_INT, Opcodes.IASTORE, false, true));
        String body = translatedBodySection(source);

        assertFalse(body.contains("__neko_primitive_array_literal_"), body);
        assertContains(body, "neko_checked_iastore");
    }

    @Test
    void nativeTranslatorScalarizesCountedDoubleArrayMultiplyAccumulateLoop() {
        String source = translateSingleMethod(countedDoubleArrayMultiplyAccumulateLoopOwner(1));
        String body = translatedBodySection(source);

        assertContains(body,
            "scalarized counted double[][] multiply-accumulate loop",
            "for (; __neko_mac_i_",
            "jdouble __neko_mac_l_",
            "jdouble __neko_mac_r_",
            "goto __neko_exception_exit",
            "locals[6].d = locals[6].d + (__neko_mac_l_");
        assertFalse(body.contains("jdouble b = POP_D(); jdouble a = POP_D(); PUSH_D(a * b);"), body);
        assertFalse(body.contains("jdouble b = POP_D(); jdouble a = POP_D(); PUSH_D(a + b);"), body);
        assertFalse(body.contains("locals[9].i += 1;"), body);
    }

    @Test
    void nativeTranslatorDoesNotScalarizeCountedDoubleArrayLoopWhenInductionStepDiffers() {
        String source = translateSingleMethod(countedDoubleArrayMultiplyAccumulateLoopOwner(2));
        String body = translatedBodySection(source);

        assertFalse(body.contains("scalarized counted double[][] multiply-accumulate loop"), body);
        assertContains(body, "locals[9].i += 2;");
    }

    @Test
    void nativeTranslatorKeepsTryDispatchForCompactedArrayLiteral() {
        String source = translateSingleMethod(primitiveArrayLiteralTryOwner());
        String body = translatedBodySection(source);

        assertContains(body,
            "__neko_primitive_array_literal_",
            "neko_take_pending_exception(thread)",
            "neko_exception_handler_matches_ref(env, __exc, &g_class_ref_",
            "PUSH_O(__exc); goto");
    }



    private static OpcodeTranslator translator() {
        return new OpcodeTranslator(new CCodeGenerator(12345L), Map.of());
    }

    private static List<Character> primitiveFieldTypes() {
        return List.of('Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D');
    }

    private static List<ArrayFastCase> primitiveArrayFastCases() {
        return List.of(
            new ArrayFastCase('Z', "b", Opcodes.BALOAD, Opcodes.BASTORE, "[Z", "neko_get_byte_array_region", "neko_set_byte_array_region"),
            new ArrayFastCase('B', "b", Opcodes.BALOAD, Opcodes.BASTORE, "[B", "neko_get_byte_array_region", "neko_set_byte_array_region"),
            new ArrayFastCase('C', "c", Opcodes.CALOAD, Opcodes.CASTORE, "[C", "neko_get_char_array_region", "neko_set_char_array_region"),
            new ArrayFastCase('S', "s", Opcodes.SALOAD, Opcodes.SASTORE, "[S", "neko_get_short_array_region", "neko_set_short_array_region"),
            new ArrayFastCase('I', "i", Opcodes.IALOAD, Opcodes.IASTORE, "[I", "neko_get_int_array_region", "neko_set_int_array_region"),
            new ArrayFastCase('J', "l", Opcodes.LALOAD, Opcodes.LASTORE, "[J", "neko_get_long_array_region", "neko_set_long_array_region"),
            new ArrayFastCase('F', "f", Opcodes.FALOAD, Opcodes.FASTORE, "[F", "neko_get_float_array_region", "neko_set_float_array_region"),
            new ArrayFastCase('D', "d", Opcodes.DALOAD, Opcodes.DASTORE, "[D", "neko_get_double_array_region", "neko_set_double_array_region")
        );
    }

    private static String translatedBodySection(String source) {
        Matcher matcher = Pattern.compile("static\\s+\\S+\\s+neko_native_impl_\\d+\\([^)]*\\) \\{").matcher(source);
        assertTrue(matcher.find(), () -> "Missing translated raw function in generated C.\n" + source);
        return source.substring(matcher.start());
    }

    private static String translatedBodySection(String source, String owner, String method, String desc) {
        String fn = manifestImplName(source, owner, method, desc);
        Matcher matcher = Pattern.compile("static\\s+\\S+\\s+" + Pattern.quote(fn) + "\\([^)]*\\) \\{").matcher(source);
        assertTrue(matcher.find(), () -> "Missing translated raw function `" + fn + "` in generated C.\n" + source);
        return source.substring(matcher.start());
    }

    private static String manifestImplName(String source, String owner, String method, String desc) {
        Matcher matcher = Pattern.compile("\\{\\s*\"" + Pattern.quote(owner) + "\",\\s*\"" + Pattern.quote(method)
            + "\",\\s*\"" + Pattern.quote(desc) + "\",\\s*\\(void\\*\\)&(neko_native_impl_\\d+)").matcher(source);
        assertTrue(matcher.find(), () -> "Missing manifest entry for `" + owner + "." + method + desc + "`.\n" + source);
        return matcher.group(1);
    }

    private static TranslationArtifact translateSingleMethodArtifact(ClassNode classNode) {
        L1Class owner = new L1Class(classNode);
        MethodNode method = classNode.methods.stream()
            .filter(candidate -> !"<init>".equals(candidate.name) && (candidate.access & Opcodes.ACC_NATIVE) == 0)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("No translated method found"));
        NativeTranslator translator = new NativeTranslator("unit", false, false, 12345L);
        String source = translator.translate(List.of(new MethodSelection(owner, owner.findMethod(method.name, method.desc)))).source();
        return new TranslationArtifact(source, classNode);
    }

    private static String translateSingleMethod(ClassNode classNode) {
        return translateSingleMethodArtifact(classNode).source();
    }

    private static String translateMethods(ClassNode... classNodes) {
        NativeTranslator translator = new NativeTranslator("unit", false, false, 12345L);
        List<MethodSelection> selections = new ArrayList<>();
        for (ClassNode classNode : classNodes) {
            L1Class owner = new L1Class(classNode);
            for (MethodNode method : classNode.methods) {
                if ((method.access & Opcodes.ACC_NATIVE) == 0 && !"<init>".equals(method.name)) {
                    selections.add(new MethodSelection(owner, owner.findMethod(method.name, method.desc)));
                }
            }
        }
        return translator.translate(selections).source();
    }

    private static ClassNode primitiveArrayLiteralTryOwner() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/TryLiteralArray";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()[I", null, null);
        method.instructions.add(start);
        appendPrimitiveArrayLiteral(method, Opcodes.T_INT, Opcodes.IASTORE, false);
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.instructions.add(end);
        method.instructions.add(handler);
        method.instructions.add(new InsnNode(Opcodes.POP));
        method.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/Throwable"));
        method.maxStack = 5;
        method.maxLocals = 0;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode countedDoubleArrayMultiplyAccumulateLoopOwner(int inductionStep) {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/CountedDoubleArrayMultiplyAccumulate" + inductionStep;
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        LabelNode loop = new LabelNode();
        LabelNode exit = new LabelNode();
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "([[D[[DII)D", null, null);
        method.instructions.add(new InsnNode(Opcodes.DCONST_0));
        method.instructions.add(new VarInsnNode(Opcodes.DSTORE, 6));
        method.instructions.add(new InsnNode(Opcodes.ICONST_0));
        method.instructions.add(new VarInsnNode(Opcodes.ISTORE, 9));
        method.instructions.add(loop);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 9));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 2));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPGE, exit));
        method.instructions.add(new VarInsnNode(Opcodes.DLOAD, 6));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 3));
        method.instructions.add(new InsnNode(Opcodes.AALOAD));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 9));
        method.instructions.add(new InsnNode(Opcodes.DALOAD));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 1));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 9));
        method.instructions.add(new InsnNode(Opcodes.AALOAD));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.DALOAD));
        method.instructions.add(new InsnNode(Opcodes.DMUL));
        method.instructions.add(new InsnNode(Opcodes.DADD));
        method.instructions.add(new VarInsnNode(Opcodes.DSTORE, 6));
        method.instructions.add(new IincInsnNode(9, inductionStep));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, loop));
        method.instructions.add(exit);
        method.instructions.add(new VarInsnNode(Opcodes.DLOAD, 6));
        method.instructions.add(new InsnNode(Opcodes.DRETURN));
        method.maxStack = 6;
        method.maxLocals = 10;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode primitiveArrayLiteralOwner(String owner, String descriptor, int newArrayType, int storeOpcode) {
        return primitiveArrayLiteralOwner(owner, descriptor, newArrayType, storeOpcode, false, false);
    }

    private static ClassNode primitiveArrayLiteralOwner(
        String owner,
        String descriptor,
        int newArrayType,
        int storeOpcode,
        boolean labelAfterNewArray,
        boolean nonSequentialIndex
    ) {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = owner;
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", descriptor, null, null);
        method.instructions.add(new InsnNode(Opcodes.ICONST_4));
        method.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, newArrayType));
        if (labelAfterNewArray) {
            method.instructions.add(new LabelNode());
        }
        appendPrimitiveArrayLiteralStores(method, storeOpcode, nonSequentialIndex);
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.maxStack = 5;
        method.maxLocals = 0;
        classNode.methods.add(method);
        return classNode;
    }

    private static void appendPrimitiveArrayLiteral(MethodNode method, int newArrayType, int storeOpcode, boolean nonSequentialIndex) {
        method.instructions.add(new InsnNode(Opcodes.ICONST_4));
        method.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, newArrayType));
        appendPrimitiveArrayLiteralStores(method, storeOpcode, nonSequentialIndex);
    }

    private static void appendPrimitiveArrayLiteralStores(MethodNode method, int storeOpcode, boolean nonSequentialIndex) {
        for (int i = 0; i < 4; i++) {
            method.instructions.add(new InsnNode(Opcodes.DUP));
            int index = nonSequentialIndex && i == 0 ? 1 : i;
            method.instructions.add(new InsnNode(Opcodes.ICONST_0 + index));
            if (storeOpcode == Opcodes.DASTORE) {
                method.instructions.add(new LdcInsnNode(10.25d + i));
            } else {
                method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 10 + i));
            }
            method.instructions.add(new InsnNode(storeOpcode));
        }
    }


    private static ClassNode stringConcatInvokeDynamicOwner() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/IndyConcat";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "run",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            null,
            null
        );
        Handle bootstrap = new Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        );
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 1));
        method.instructions.add(new InvokeDynamicInsnNode(
            "makeConcatWithConstants",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            bootstrap,
            "\u0001:\u0001"
        ));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode stringBuilderConcatOwner() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/StringBuilderConcat";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "run",
            "(Ljava/lang/String;)Ljava/lang/String;",
            null,
            null
        );
        method.instructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        method.instructions.add(new InsnNode(Opcodes.DUP));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StringBuilder",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            false
        ));
        method.instructions.add(new LdcInsnNode("!"));
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StringBuilder",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            false
        ));
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StringBuilder",
            "toString",
            "()Ljava/lang/String;",
            false
        ));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.maxStack = 3;
        method.maxLocals = 1;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode stringBuilderConcatImmediateStoreOwner() {
        ClassNode classNode = stringBuilderConcatOwner();
        MethodNode method = classNode.methods.getFirst();
        method.instructions.remove(method.instructions.getLast());
        method.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.maxLocals = 2;
        return classNode;
    }

    private static ClassNode stringBuilderConcatLengthRecurrenceOwner(boolean escapeAfterExit) {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/StringBuilderConcatLengthRecurrence" + (escapeAfterExit ? "Escape" : "Dead");
        classNode.superName = "java/lang/Object";
        classNode.fields = new ArrayList<>();
        classNode.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "count", "I", null, null));
        classNode.methods = new ArrayList<>();

        LabelNode loop = new LabelNode();
        LabelNode exit = new LabelNode();
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        method.instructions.add(new LdcInsnNode(""));
        method.instructions.add(new VarInsnNode(Opcodes.ASTORE, 0));
        method.instructions.add(loop);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false));
        method.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 101));
        method.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPGE, exit));
        method.instructions.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        method.instructions.add(new InsnNode(Opcodes.DUP));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StringBuilder",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            false
        ));
        method.instructions.add(new LdcInsnNode("ab"));
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StringBuilder",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
            false
        ));
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StringBuilder",
            "toString",
            "()Ljava/lang/String;",
            false
        ));
        method.instructions.add(new VarInsnNode(Opcodes.ASTORE, 0));
        method.instructions.add(new JumpInsnNode(Opcodes.GOTO, loop));
        method.instructions.add(exit);
        if (escapeAfterExit) {
            method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            method.instructions.add(new InsnNode(Opcodes.POP));
        }
        method.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, classNode.name, "count", "I"));
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IADD));
        method.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, "count", "I"));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 3;
        method.maxLocals = 1;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode methodHandleBridgeOwner(boolean invokeExact) {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V9;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/MhBridge" + (invokeExact ? "Exact" : "Invoke");
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "run",
            "(Ljava/lang/invoke/MethodHandle;I)I",
            null,
            new String[] {"java/lang/Throwable"}
        );
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/invoke/MethodHandle",
            invokeExact ? "invokeExact" : "invoke",
            "(I)I",
            false
        ));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode virtualInvokeOwner() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/VirtualInvokeOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "(Lpkg/VirtualDispatchTarget;)Ljava/lang/String;", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "pkg/VirtualDispatchTarget", "value", "()Ljava/lang/String;", false));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode interfaceInvokeOwner() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/InterfaceInvokeOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "(Lpkg/Greeter;)Ljava/lang/String;", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "pkg/Greeter", "greet", "()Ljava/lang/String;", true));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode multiTargetHelperClass() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/MultiTargetHelper";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "staticValue", "()I", null, null);
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 0;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode multiTargetBaseClass() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/MultiTargetBase";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "baseValue", "()I", null, null);
        method.instructions.add(new InsnNode(Opcodes.ICONST_2));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode multiTargetFinalClass() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL;
        classNode.name = "pkg/MultiTargetFinal";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, "finalValue", "()I", null, null);
        method.instructions.add(new InsnNode(Opcodes.ICONST_3));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode multiTargetCallerClass() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/MultiTargetCaller";
        classNode.superName = "pkg/MultiTargetBase";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "run", "(Lpkg/MultiTargetFinal;)I", null, null);
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "pkg/MultiTargetHelper", "staticValue", "()I", false));
        method.instructions.add(new InsnNode(Opcodes.POP));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "pkg/MultiTargetBase", "baseValue", "()I", false));
        method.instructions.add(new InsnNode(Opcodes.POP));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 1));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "pkg/MultiTargetFinal", "finalValue", "()I", false));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode primitiveFieldOwner(String ownerSuffix, String fieldName, String desc, int valueLoadOpcode, int returnOpcode, boolean isStaticField) {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/" + ownerSuffix;
        classNode.superName = "java/lang/Object";
        classNode.fields = new ArrayList<>();
        classNode.methods = new ArrayList<>();
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | (isStaticField ? Opcodes.ACC_STATIC : 0), fieldName, desc, null, null));

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "run", methodDescriptor(returnOpcode, desc), null, null);
        if (!isStaticField) {
            method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        }
        if (valueLoadOpcode != 0) {
            method.instructions.add(new VarInsnNode(valueLoadOpcode, isStaticField ? 1 : 1));
        }
        method.instructions.add(new FieldInsnNode(isStaticField
            ? (returnOpcode == Opcodes.RETURN ? Opcodes.PUTSTATIC : Opcodes.GETSTATIC)
            : (returnOpcode == Opcodes.RETURN ? Opcodes.PUTFIELD : Opcodes.GETFIELD), classNode.name, fieldName, desc));
        method.instructions.add(new InsnNode(returnOpcode));
        method.maxStack = 4;
        method.maxLocals = isStaticField
            ? (valueLoadOpcode == 0 ? 1 : 1 + Type.getType(desc).getSize())
            : (valueLoadOpcode == 0 ? 1 : 1 + Type.getType(desc).getSize());
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode primitiveArrayLoadOwner(ArrayFastCase testCase) {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/ArrayLoad" + testCase.descriptorChar();
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "(" + testCase.arrayDesc() + "I)" + arrayLoadReturnDesc(testCase.descriptorChar()), null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(testCase.loadOpcode()));
        method.instructions.add(new InsnNode(arrayLoadReturnOpcode(testCase.descriptorChar())));
        method.maxStack = 2;
        method.maxLocals = 2;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode primitiveArrayStoreOwner(ArrayFastCase testCase) {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/ArrayStore" + testCase.descriptorChar();
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        String valueDesc = arrayStoreValueDesc(testCase.descriptorChar());
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "(" + testCase.arrayDesc() + "I" + valueDesc + ")V", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new VarInsnNode(arrayStoreLoadOpcode(testCase.descriptorChar()), 2));
        method.instructions.add(new InsnNode(testCase.storeOpcode()));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = Type.getType(valueDesc).getSize() == 2 ? 4 : 3;
        method.maxLocals = 2 + Type.getType(valueDesc).getSize();
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode objectArrayLoadOwner() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/ObjectArrayLoad";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "([Ljava/lang/String;I)Ljava/lang/String;", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.AALOAD));
        method.instructions.add(new InsnNode(Opcodes.ARETURN));
        method.maxStack = 2;
        method.maxLocals = 2;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode objectArrayStoreOwner() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/ObjectArrayStore";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "([Ljava/lang/String;ILjava/lang/String;)V", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 2));
        method.instructions.add(new InsnNode(Opcodes.AASTORE));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 3;
        method.maxLocals = 3;
        classNode.methods.add(method);
        return classNode;
    }

    private static ClassNode stringLengthOwner() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/StringLengthOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "(Ljava/lang/String;)I", null, null);
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        classNode.methods.add(method);
        return classNode;
    }

    private static String methodDescriptor(int returnOpcode, String desc) {
        return returnOpcode == Opcodes.RETURN ? "(" + desc + ")V" : "()" + desc;
    }

    private static int primitiveReturnInsn(char primitive) {
        return switch (primitive) {
            case 'J' -> Opcodes.LRETURN;
            case 'F' -> Opcodes.FRETURN;
            case 'D' -> Opcodes.DRETURN;
            default -> Opcodes.IRETURN;
        };
    }

    private static int primitiveLoadOpcode(char primitive) {
        return switch (primitive) {
            case 'J' -> Opcodes.LLOAD;
            case 'F' -> Opcodes.FLOAD;
            case 'D' -> Opcodes.DLOAD;
            default -> Opcodes.ILOAD;
        };
    }

    private static String jniFieldGetterName(char primitive) {
        return switch (primitive) {
            case 'Z' -> "neko_get_boolean_field";
            case 'B' -> "neko_get_byte_field";
            case 'C' -> "neko_get_char_field";
            case 'S' -> "neko_get_short_field";
            case 'I' -> "neko_get_int_field";
            case 'J' -> "neko_get_long_field";
            case 'F' -> "neko_get_float_field";
            case 'D' -> "neko_get_double_field";
            default -> throw new IllegalArgumentException();
        };
    }

    private static String jniFieldSetterName(char primitive) {
        return jniFieldGetterName(primitive).replace("get", "set");
    }

    private static String jniStaticFieldGetterName(char primitive) {
        return switch (primitive) {
            case 'Z' -> "neko_get_static_boolean_field";
            case 'B' -> "neko_get_static_byte_field";
            case 'C' -> "neko_get_static_char_field";
            case 'S' -> "neko_get_static_short_field";
            case 'I' -> "neko_get_static_int_field";
            case 'J' -> "neko_get_static_long_field";
            case 'F' -> "neko_get_static_float_field";
            case 'D' -> "neko_get_static_double_field";
            default -> throw new IllegalArgumentException();
        };
    }

    private static String jniStaticFieldSetterName(char primitive) {
        return jniStaticFieldGetterName(primitive).replace("get", "set");
    }

    private static String arrayLoadReturnDesc(char primitive) {
        return switch (primitive) {
            case 'J' -> "J";
            case 'F' -> "F";
            case 'D' -> "D";
            default -> "I";
        };
    }

    private static int arrayLoadReturnOpcode(char primitive) {
        return switch (primitive) {
            case 'J' -> Opcodes.LRETURN;
            case 'F' -> Opcodes.FRETURN;
            case 'D' -> Opcodes.DRETURN;
            default -> Opcodes.IRETURN;
        };
    }

    private static String arrayStoreValueDesc(char primitive) {
        return switch (primitive) {
            case 'J' -> "J";
            case 'F' -> "F";
            case 'D' -> "D";
            default -> "I";
        };
    }

    private static int arrayStoreLoadOpcode(char primitive) {
        return switch (primitive) {
            case 'J' -> Opcodes.LLOAD;
            case 'F' -> Opcodes.FLOAD;
            case 'D' -> Opcodes.DLOAD;
            default -> Opcodes.ILOAD;
        };
    }

    private static String render(List<CStatement> statements) {
        StringBuilder builder = new StringBuilder();
        for (CStatement statement : statements) {
            if (statement instanceof CStatement.RawC rawC) {
                builder.append(rawC.code());
            } else if (statement instanceof CStatement.Goto go) {
                builder.append("goto ").append(go.label()).append(';');
            } else if (statement instanceof CStatement.Label label) {
                builder.append(label.name()).append(':');
            } else {
                builder.append(statement);
            }
            builder.append('\n');
        }
        return builder.toString();
    }

    private static void assertContains(String text, String... expectedParts) {
        for (String expectedPart : expectedParts) {
            assertTrue(text.contains(expectedPart), () -> "Expected C snippet to contain `" + expectedPart + "` but got:\n" + text);
        }
    }

    private record TranslationArtifact(String source, ClassNode classNode) {}

    private record ArrayFastCase(char descriptorChar, String helperPrefix, int loadOpcode, int storeOpcode, String arrayDesc,
                                 String jniGetHelper, String jniSetHelper) {}
}
