package dev.nekoobfuscator.test;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l3.CFunction;
import dev.nekoobfuscator.core.ir.l3.CStatement;
import dev.nekoobfuscator.core.ir.l3.CType;
import dev.nekoobfuscator.core.ir.l3.CVariable;
import dev.nekoobfuscator.native_.codegen.CCodeGenerator;
import dev.nekoobfuscator.native_.codegen.CStringLiteral;
import dev.nekoobfuscator.native_.translator.NativeTranslator;
import dev.nekoobfuscator.native_.translator.NativeTranslator.MethodSelection;
import dev.nekoobfuscator.native_.translator.NativeTranslator.NativeMethodBinding;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CCodeGeneratorTest {
    @Test
    void cStringLiteralEscapingIsCentralizedAndComplete() {
        assertEquals("plain/Owner", CStringLiteral.escape("plain/Owner"));
        assertEquals("\\\\", CStringLiteral.escape("\\"));
        assertEquals("\\\"", CStringLiteral.escape("\""));
        assertEquals("\\n", CStringLiteral.escape("\n"));
        assertEquals("\\r", CStringLiteral.escape("\r"));
        assertEquals("\\t", CStringLiteral.escape("\t"));
        assertEquals("\\b", CStringLiteral.escape("\b"));
        assertEquals("\\f", CStringLiteral.escape("\f"));
        assertEquals("a\\\\b\\\"c\\nd\\re\\tf\\bg\\f", CStringLiteral.escape("a\\b\"c\nd\re\tf\bg\f"));
    }

    @Test
    void primitiveOnlyStaticMethodsUseNoHandleDispatcherOnlyWhenBodyProofIsComplete() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/NoHandleOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode add = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I", null, null);
        add.maxStack = 2;
        add.maxLocals = 2;
        add.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        add.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        add.instructions.add(new InsnNode(Opcodes.IADD));
        add.instructions.add(new InsnNode(Opcodes.IRETURN));
        classNode.methods.add(add);

        MethodNode length = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "length", "(Ljava/lang/String;)I", null, null);
        length.maxStack = 1;
        length.maxLocals = 1;
        length.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        length.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false));
        length.instructions.add(new InsnNode(Opcodes.IRETURN));
        classNode.methods.add(length);

        MethodNode identity = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "identity", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        identity.maxStack = 1;
        identity.maxLocals = 1;
        identity.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        identity.instructions.add(new InsnNode(Opcodes.ARETURN));
        classNode.methods.add(identity);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("no-handle", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("add", "(II)I")),
            new MethodSelection(owner, owner.findMethod("length", "(Ljava/lang/String;)I")),
            new MethodSelection(owner, owner.findMethod("identity", "(Ljava/lang/String;)Ljava/lang/String;"))
        )).source();

        String primitiveDispatcher = functionSection(source, "neko_sig_0_dispatch");
        assertTrue(primitiveDispatcher.contains("no-handle dispatcher"), primitiveDispatcher);
        assertFalse(primitiveDispatcher.contains("neko_handle_save"), primitiveDispatcher);
        assertFalse(primitiveDispatcher.contains("neko_handle_restore"), primitiveDispatcher);

        String referenceDispatcher = functionSection(source, "neko_sig_1_dispatch");
        assertFalse(referenceDispatcher.contains("no-handle dispatcher"), referenceDispatcher);
        assertTrue(referenceDispatcher.contains("neko_handle_save"), referenceDispatcher);
        assertTrue(referenceDispatcher.contains("neko_handle_restore"), referenceDispatcher);

        String objectReturnDispatcher = functionSection(source, "neko_sig_2_dispatch");
        assertTrue(objectReturnDispatcher.contains("neko_prepare_return_oop(thread, __ret, \"sig2\")"), objectReturnDispatcher);
        int prepareReturnIndex = objectReturnDispatcher.indexOf("neko_prepare_return_oop(thread, __ret, \"sig2\")");
        int restoreAfterReturnIndex = objectReturnDispatcher.indexOf("neko_handle_restore(&__hsave);", prepareReturnIndex);
        assertTrue(
            prepareReturnIndex < restoreAfterReturnIndex,
            objectReturnDispatcher
        );
    }

    @Test
    void loweredLambdaClassesDirectInvokeTranslatedStaticTargets() {
        ClassNode ownerClass = new ClassNode();
        ownerClass.version = Opcodes.V1_8;
        ownerClass.access = Opcodes.ACC_PUBLIC;
        ownerClass.name = "pkg/LambdaOwner";
        ownerClass.superName = "java/lang/Object";
        ownerClass.methods = new ArrayList<>();

        MethodNode target = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "target", "(I)I", null, null);
        target.maxStack = 2;
        target.maxLocals = 1;
        target.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        target.instructions.add(new InsnNode(Opcodes.ICONST_1));
        target.instructions.add(new InsnNode(Opcodes.IADD));
        target.instructions.add(new InsnNode(Opcodes.IRETURN));
        ownerClass.methods.add(target);

        ClassNode lambdaClass = new ClassNode();
        lambdaClass.version = Opcodes.V1_8;
        lambdaClass.access = Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        lambdaClass.name = "pkg/LambdaOwner$NekoLambda$1";
        lambdaClass.superName = "java/lang/Object";
        lambdaClass.methods = new ArrayList<>();

        MethodNode apply = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
            "applyAsInt", "(I)I", null, null);
        apply.maxStack = 1;
        apply.maxLocals = 2;
        apply.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        apply.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "pkg/LambdaOwner", "target", "(I)I", false));
        apply.instructions.add(new InsnNode(Opcodes.IRETURN));
        lambdaClass.methods.add(apply);

        L1Class owner = new L1Class(ownerClass);
        L1Class lambda = new L1Class(lambdaClass);
        NativeTranslator translator = new NativeTranslator("lambda-direct", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("target", "(I)I")),
            new MethodSelection(lambda, lambda.findMethod("applyAsInt", "(I)I"))
        )).source();

        assertFalse(source.contains("neko_njx_S_I_I"), source);
        assertTrue(source.contains("target"), source);
    }

    @Test
    void sameOwnerStaticDirectCallsUseCurrentClazzWithoutNullGuard() {
        ClassNode sameOwnerClass = new ClassNode();
        sameOwnerClass.version = Opcodes.V1_8;
        sameOwnerClass.access = Opcodes.ACC_PUBLIC;
        sameOwnerClass.name = "pkg/SameOwner";
        sameOwnerClass.superName = "java/lang/Object";
        sameOwnerClass.methods = new ArrayList<>();

        MethodNode sameTarget = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "sameTarget", "(I)V", null, null);
        sameTarget.instructions.add(new InsnNode(Opcodes.RETURN));
        sameTarget.maxStack = 0;
        sameTarget.maxLocals = 1;
        sameOwnerClass.methods.add(sameTarget);

        MethodNode sameCaller = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "sameCaller", "()V", null, null);
        sameCaller.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        sameCaller.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, sameOwnerClass.name, "sameTarget", "(I)V", false));
        sameCaller.instructions.add(new InsnNode(Opcodes.RETURN));
        sameCaller.maxStack = 1;
        sameCaller.maxLocals = 0;
        sameOwnerClass.methods.add(sameCaller);

        ClassNode crossTargetClass = new ClassNode();
        crossTargetClass.version = Opcodes.V1_8;
        crossTargetClass.access = Opcodes.ACC_PUBLIC;
        crossTargetClass.name = "pkg/CrossTarget";
        crossTargetClass.superName = "java/lang/Object";
        crossTargetClass.methods = new ArrayList<>();

        MethodNode crossTarget = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "target", "()V", null, null);
        crossTarget.instructions.add(new InsnNode(Opcodes.RETURN));
        crossTarget.maxStack = 0;
        crossTarget.maxLocals = 0;
        crossTargetClass.methods.add(crossTarget);

        ClassNode crossCallerClass = new ClassNode();
        crossCallerClass.version = Opcodes.V1_8;
        crossCallerClass.access = Opcodes.ACC_PUBLIC;
        crossCallerClass.name = "pkg/CrossCaller";
        crossCallerClass.superName = "java/lang/Object";
        crossCallerClass.methods = new ArrayList<>();

        MethodNode crossCaller = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "call", "()V", null, null);
        crossCaller.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, crossTargetClass.name, "target", "()V", false));
        crossCaller.instructions.add(new InsnNode(Opcodes.RETURN));
        crossCaller.maxStack = 0;
        crossCaller.maxLocals = 0;
        crossCallerClass.methods.add(crossCaller);

        L1Class sameOwner = new L1Class(sameOwnerClass);
        L1Class crossTargetOwner = new L1Class(crossTargetClass);
        L1Class crossCallerOwner = new L1Class(crossCallerClass);
        NativeTranslator translator = new NativeTranslator("same-owner-static-direct", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(sameOwner, sameOwner.findMethod("sameTarget", "(I)V")),
            new MethodSelection(sameOwner, sameOwner.findMethod("sameCaller", "()V")),
            new MethodSelection(crossTargetOwner, crossTargetOwner.findMethod("target", "()V")),
            new MethodSelection(crossCallerOwner, crossCallerOwner.findMethod("call", "()V"))
        )).source();

        String sameCallerBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(sameCallerBody.contains("neko_native_impl_0_body(thread, env, (jclass)clazz, (jint)(7));"), () -> sameCallerBody);
        assertFalse(sameCallerBody.contains("jclass targetCls = (jclass)clazz"), () -> sameCallerBody);
        assertFalse(sameCallerBody.contains("targetCls != NULL"), () -> sameCallerBody);

        String crossCallerBody = lastFunctionSection(source, "neko_native_impl_3_body");
        assertTrue(crossCallerBody.contains("jclass targetCls = neko_bound_class_ref(env, &g_class_ref_"), () -> crossCallerBody);
        assertTrue(crossCallerBody.contains("if (targetCls != NULL) neko_native_impl_2_body(thread, env, targetCls);"), () -> crossCallerBody);
    }

    @Test
    void primitiveIntegerBranchProducersFuseInsideOneBasicBlockOnly() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/BranchOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        LabelNode zeroTarget = new LabelNode();
        MethodNode zeroBranch = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "zeroBranch", "(I)I", null, null);
        zeroBranch.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        zeroBranch.instructions.add(new JumpInsnNode(Opcodes.IFEQ, zeroTarget));
        zeroBranch.instructions.add(new InsnNode(Opcodes.ICONST_1));
        zeroBranch.instructions.add(new InsnNode(Opcodes.IRETURN));
        zeroBranch.instructions.add(zeroTarget);
        zeroBranch.instructions.add(new InsnNode(Opcodes.ICONST_0));
        zeroBranch.instructions.add(new InsnNode(Opcodes.IRETURN));
        zeroBranch.maxStack = 1;
        zeroBranch.maxLocals = 1;
        classNode.methods.add(zeroBranch);

        LabelNode compareTarget = new LabelNode();
        MethodNode compareBranch = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "compareBranch", "(I)I", null, null);
        compareBranch.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        compareBranch.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 10));
        compareBranch.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPGE, compareTarget));
        compareBranch.instructions.add(new InsnNode(Opcodes.ICONST_1));
        compareBranch.instructions.add(new InsnNode(Opcodes.IRETURN));
        compareBranch.instructions.add(compareTarget);
        compareBranch.instructions.add(new InsnNode(Opcodes.ICONST_0));
        compareBranch.instructions.add(new InsnNode(Opcodes.IRETURN));
        compareBranch.maxStack = 2;
        compareBranch.maxLocals = 1;
        classNode.methods.add(compareBranch);

        LabelNode boundary = new LabelNode();
        LabelNode blockedTarget = new LabelNode();
        MethodNode labelBlocked = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "labelBlocked", "(I)I", null, null);
        labelBlocked.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        labelBlocked.instructions.add(boundary);
        labelBlocked.instructions.add(new JumpInsnNode(Opcodes.IFEQ, blockedTarget));
        labelBlocked.instructions.add(new InsnNode(Opcodes.ICONST_1));
        labelBlocked.instructions.add(new InsnNode(Opcodes.IRETURN));
        labelBlocked.instructions.add(blockedTarget);
        labelBlocked.instructions.add(new InsnNode(Opcodes.ICONST_0));
        labelBlocked.instructions.add(new InsnNode(Opcodes.IRETURN));
        labelBlocked.maxStack = 1;
        labelBlocked.maxLocals = 1;
        classNode.methods.add(labelBlocked);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("primitive-branch-fusion", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("zeroBranch", "(I)I")),
            new MethodSelection(owner, owner.findMethod("compareBranch", "(I)I")),
            new MethodSelection(owner, owner.findMethod("labelBlocked", "(I)I"))
        )).source();

        String zeroBody = lastFunctionSection(source, "neko_native_impl_0_body");
        assertTrue(zeroBody.contains("if (locals[0].i == 0) goto "), () -> zeroBody);
        assertFalse(zeroBody.contains("PUSH_I(locals[0].i);"), () -> zeroBody);
        assertFalse(zeroBody.contains("if (POP_I() == 0)"), () -> zeroBody);

        String compareBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(compareBody.contains("{ jint a = locals[0].i; jint b = 10; if (a >= b) goto "), () -> compareBody);
        assertFalse(compareBody.contains("PUSH_I(locals[0].i);"), () -> compareBody);
        assertFalse(compareBody.contains("PUSH_I(10);"), () -> compareBody);

        String blockedBody = lastFunctionSection(source, "neko_native_impl_2_body");
        assertTrue(blockedBody.contains("PUSH_I(locals[0].i);"), () -> blockedBody);
        assertTrue(blockedBody.contains("if (POP_I() == 0) goto "), () -> blockedBody);
    }

    @Test
    void sameStaticIntAddUpdateFusesWithoutChangingFieldHelpers() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/StaticIntUpdateOwner";
        classNode.superName = "java/lang/Object";
        classNode.fields = new ArrayList<>();
        classNode.methods = new ArrayList<>();
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "COUNT", "I", null, null));
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "OTHER", "I", null, null));

        MethodNode sameField = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "sameField", "()V", null, null);
        sameField.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, classNode.name, "COUNT", "I"));
        sameField.instructions.add(new InsnNode(Opcodes.ICONST_1));
        sameField.instructions.add(new InsnNode(Opcodes.IADD));
        sameField.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, "COUNT", "I"));
        sameField.instructions.add(new InsnNode(Opcodes.RETURN));
        sameField.maxStack = 2;
        sameField.maxLocals = 0;
        classNode.methods.add(sameField);

        MethodNode differentField = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "differentField", "()V", null, null);
        differentField.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, classNode.name, "COUNT", "I"));
        differentField.instructions.add(new InsnNode(Opcodes.ICONST_1));
        differentField.instructions.add(new InsnNode(Opcodes.IADD));
        differentField.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, "OTHER", "I"));
        differentField.instructions.add(new InsnNode(Opcodes.RETURN));
        differentField.maxStack = 2;
        differentField.maxLocals = 0;
        classNode.methods.add(differentField);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("static-int-update-fusion", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("sameField", "()V")),
            new MethodSelection(owner, owner.findMethod("differentField", "()V"))
        )).source();

        String sameBody = lastFunctionSection(source, "neko_native_impl_0_body");
        assertTrue(sameBody.contains("jint val = neko_fast_get_static_I_field_ref(env, &g_static_field_ref_"), () -> sameBody);
        assertTrue(sameBody.contains("+ (jint)(1);"), () -> sameBody);
        assertTrue(sameBody.contains("neko_ensure_class_initialized_once(env, cls,"), () -> sameBody);
        assertTrue(sameBody.contains("neko_fast_set_static_I_field(env, cls, fid,"), () -> sameBody);
        assertFalse(sameBody.contains("PUSH_I(1);"), () -> sameBody);
        assertFalse(sameBody.contains("PUSH_I(a + b);"), () -> sameBody);

        String differentBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(differentBody.contains("PUSH_I(1);"), () -> differentBody);
        assertTrue(differentBody.contains("PUSH_I(a + b);"), () -> differentBody);
    }

    @Test
    void primitiveIntAddMulImmediateReturnsFuseWithoutCrossingLabels() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/IntReturnOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode add = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I", null, null);
        add.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        add.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        add.instructions.add(new InsnNode(Opcodes.IADD));
        add.instructions.add(new InsnNode(Opcodes.IRETURN));
        add.maxStack = 2;
        add.maxLocals = 2;
        classNode.methods.add(add);

        MethodNode mul = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "mul", "(II)I", null, null);
        mul.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        mul.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        mul.instructions.add(new InsnNode(Opcodes.IMUL));
        mul.instructions.add(new InsnNode(Opcodes.IRETURN));
        mul.maxStack = 2;
        mul.maxLocals = 2;
        classNode.methods.add(mul);

        LabelNode boundary = new LabelNode();
        MethodNode blocked = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "blocked", "(II)I", null, null);
        blocked.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        blocked.instructions.add(boundary);
        blocked.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        blocked.instructions.add(new InsnNode(Opcodes.IADD));
        blocked.instructions.add(new InsnNode(Opcodes.IRETURN));
        blocked.maxStack = 2;
        blocked.maxLocals = 2;
        classNode.methods.add(blocked);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("primitive-int-return-fusion", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("add", "(II)I")),
            new MethodSelection(owner, owner.findMethod("mul", "(II)I")),
            new MethodSelection(owner, owner.findMethod("blocked", "(II)I"))
        )).source();

        String addBody = lastFunctionSection(source, "neko_native_impl_0_body");
        assertTrue(addBody.contains("{ jint __ret = (jint)((locals[0].i) + (locals[1].i)); return __ret; }"), () -> addBody);
        assertFalse(addBody.contains("PUSH_I(a + b);"), () -> addBody);

        String mulBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(mulBody.contains("{ jint __ret = (jint)((locals[0].i) * (locals[1].i)); return __ret; }"), () -> mulBody);
        assertFalse(mulBody.contains("PUSH_I(a * b);"), () -> mulBody);

        String blockedBody = lastFunctionSection(source, "neko_native_impl_2_body");
        assertTrue(blockedBody.contains("PUSH_I(locals[0].i);"), () -> blockedBody);
        assertTrue(blockedBody.contains("PUSH_I(a + b);"), () -> blockedBody);
    }

    @Test
    void primitiveIntArithmeticSelfTailCallsFuseWithoutCrossingLabels() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/IntTailOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode decrement = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "decrement", "(I)V", null, null);
        decrement.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        decrement.instructions.add(new InsnNode(Opcodes.ICONST_1));
        decrement.instructions.add(new InsnNode(Opcodes.ISUB));
        decrement.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, "decrement", "(I)V", false));
        decrement.instructions.add(new LabelNode());
        decrement.instructions.add(new InsnNode(Opcodes.RETURN));
        decrement.maxStack = 2;
        decrement.maxLocals = 1;
        classNode.methods.add(decrement);

        MethodNode scale = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "scale", "(I)I", null, null);
        scale.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        scale.instructions.add(new InsnNode(Opcodes.ICONST_2));
        scale.instructions.add(new InsnNode(Opcodes.IMUL));
        scale.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, "scale", "(I)I", false));
        scale.instructions.add(new InsnNode(Opcodes.IRETURN));
        scale.maxStack = 2;
        scale.maxLocals = 1;
        classNode.methods.add(scale);

        LabelNode boundary = new LabelNode();
        MethodNode blocked = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "blocked", "(I)V", null, null);
        blocked.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        blocked.instructions.add(boundary);
        blocked.instructions.add(new InsnNode(Opcodes.ICONST_1));
        blocked.instructions.add(new InsnNode(Opcodes.ISUB));
        blocked.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, "blocked", "(I)V", false));
        blocked.instructions.add(new InsnNode(Opcodes.RETURN));
        blocked.maxStack = 2;
        blocked.maxLocals = 1;
        classNode.methods.add(blocked);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("primitive-int-tail-fusion", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("decrement", "(I)V")),
            new MethodSelection(owner, owner.findMethod("scale", "(I)I")),
            new MethodSelection(owner, owner.findMethod("blocked", "(I)V"))
        )).source();

        String decrementBody = lastFunctionSection(source, "neko_native_impl_0_body");
        assertTrue(decrementBody.contains("{ /* tail-call int arithmetic \u2192 goto L0 */ locals[0].i = (jint)((locals[0].i) - (1)); sp = 0; goto __neko_tco_entry; }"), () -> decrementBody);
        assertFalse(decrementBody.contains("PUSH_I(a - b);"), () -> decrementBody);

        String scaleBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(scaleBody.contains("{ /* tail-call int arithmetic \u2192 goto L0 */ locals[0].i = (jint)((locals[0].i) * (2)); sp = 0; goto __neko_tco_entry; }"), () -> scaleBody);
        assertFalse(scaleBody.contains("PUSH_I(a * b);"), () -> scaleBody);

        String blockedBody = lastFunctionSection(source, "neko_native_impl_2_body");
        assertTrue(blockedBody.contains("PUSH_I(locals[0].i);"), () -> blockedBody);
        assertTrue(blockedBody.contains("PUSH_I(a - b);"), () -> blockedBody);
        assertTrue(blockedBody.contains("{ /* tail-call \u2192 goto L0 */ jint __tco0 = POP_I(); locals[0].i = __tco0; sp = 0; goto __neko_tco_entry; }"), () -> blockedBody);
    }

    @Test
    void primitiveCompareResultsFuseIntoZeroBranchesWithoutCrossingLabels() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/CompareBranchOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        LabelNode longTarget = new LabelNode();
        MethodNode longLess = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "longLess", "(JJ)V", null, null);
        longLess.instructions.add(new VarInsnNode(Opcodes.LLOAD, 0));
        longLess.instructions.add(new VarInsnNode(Opcodes.LLOAD, 2));
        longLess.instructions.add(new InsnNode(Opcodes.LCMP));
        longLess.instructions.add(new JumpInsnNode(Opcodes.IFLT, longTarget));
        longLess.instructions.add(new InsnNode(Opcodes.RETURN));
        longLess.instructions.add(longTarget);
        longLess.instructions.add(new InsnNode(Opcodes.RETURN));
        longLess.maxStack = 4;
        longLess.maxLocals = 4;
        classNode.methods.add(longLess);

        LabelNode floatTarget = new LabelNode();
        MethodNode floatCmp = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "floatCmp", "(F)V", null, null);
        floatCmp.instructions.add(new VarInsnNode(Opcodes.FLOAD, 0));
        floatCmp.instructions.add(new InsnNode(Opcodes.FCONST_1));
        floatCmp.instructions.add(new InsnNode(Opcodes.FCMPL));
        floatCmp.instructions.add(new JumpInsnNode(Opcodes.IFNE, floatTarget));
        floatCmp.instructions.add(new InsnNode(Opcodes.RETURN));
        floatCmp.instructions.add(floatTarget);
        floatCmp.instructions.add(new InsnNode(Opcodes.RETURN));
        floatCmp.maxStack = 2;
        floatCmp.maxLocals = 1;
        classNode.methods.add(floatCmp);

        LabelNode doubleTarget = new LabelNode();
        MethodNode doubleCmp = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "doubleCmp", "(D)V", null, null);
        doubleCmp.instructions.add(new VarInsnNode(Opcodes.DLOAD, 0));
        doubleCmp.instructions.add(new LdcInsnNode(100.1d));
        doubleCmp.instructions.add(new InsnNode(Opcodes.DCMPG));
        doubleCmp.instructions.add(new JumpInsnNode(Opcodes.IFGE, doubleTarget));
        doubleCmp.instructions.add(new InsnNode(Opcodes.RETURN));
        doubleCmp.instructions.add(doubleTarget);
        doubleCmp.instructions.add(new InsnNode(Opcodes.RETURN));
        doubleCmp.maxStack = 4;
        doubleCmp.maxLocals = 2;
        classNode.methods.add(doubleCmp);

        LabelNode boundary = new LabelNode();
        LabelNode blockedTarget = new LabelNode();
        MethodNode blocked = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "blocked", "(F)V", null, null);
        blocked.instructions.add(new VarInsnNode(Opcodes.FLOAD, 0));
        blocked.instructions.add(boundary);
        blocked.instructions.add(new InsnNode(Opcodes.FCONST_1));
        blocked.instructions.add(new InsnNode(Opcodes.FCMPL));
        blocked.instructions.add(new JumpInsnNode(Opcodes.IFNE, blockedTarget));
        blocked.instructions.add(new InsnNode(Opcodes.RETURN));
        blocked.instructions.add(blockedTarget);
        blocked.instructions.add(new InsnNode(Opcodes.RETURN));
        blocked.maxStack = 2;
        blocked.maxLocals = 1;
        classNode.methods.add(blocked);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("primitive-compare-branch-fusion", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("longLess", "(JJ)V")),
            new MethodSelection(owner, owner.findMethod("floatCmp", "(F)V")),
            new MethodSelection(owner, owner.findMethod("doubleCmp", "(D)V")),
            new MethodSelection(owner, owner.findMethod("blocked", "(F)V"))
        )).source();

        String longBody = lastFunctionSection(source, "neko_native_impl_0_body");
        assertTrue(longBody.contains("{ jlong a = locals[0].j; jlong b = locals[2].j; jint __cmp = a > b ? 1 : (a < b ? -1 : 0); if (__cmp < 0) goto L"), () -> longBody);
        assertFalse(longBody.contains("PUSH_I(a > b ? 1 : (a < b ? -1 : 0));"), () -> longBody);

        String floatBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(floatBody.contains("{ jfloat a = locals[0].f; jfloat b = 1.0f; jint __cmp = a > b ? 1 : (a < b ? -1 : (a == b ? 0 : -1)); if (__cmp != 0) goto L"), () -> floatBody);
        assertFalse(floatBody.contains("PUSH_I(a > b ? 1 : (a < b ? -1 : (a == b ? 0 : -1)));"), () -> floatBody);

        String doubleBody = lastFunctionSection(source, "neko_native_impl_2_body");
        assertTrue(doubleBody.contains("{ jdouble a = locals[0].d; jdouble b = 100.1; jint __cmp = a > b ? 1 : (a < b ? -1 : (a == b ? 0 : 1)); if (__cmp >= 0) goto L"), () -> doubleBody);
        assertFalse(doubleBody.contains("PUSH_I(a > b ? 1 : (a < b ? -1 : (a == b ? 0 : 1)));"), () -> doubleBody);

        String blockedBody = lastFunctionSection(source, "neko_native_impl_3_body");
        assertTrue(blockedBody.contains("PUSH_F(locals[0].f);"), () -> blockedBody);
        assertTrue(blockedBody.contains("PUSH_I(a > b ? 1 : (a < b ? -1 : (a == b ? 0 : -1)));"), () -> blockedBody);
        assertTrue(blockedBody.contains("if (POP_I() != 0) goto L"), () -> blockedBody);
    }

    @Test
    void primitiveFloatDoubleSameLocalAddUpdatesFuseWithoutCrossingLabels() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/FloatingAddUpdateOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode floatSame = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "floatSame", "(F)V", null, null);
        floatSame.instructions.add(new VarInsnNode(Opcodes.FLOAD, 0));
        floatSame.instructions.add(new LdcInsnNode(1.3f));
        floatSame.instructions.add(new InsnNode(Opcodes.FADD));
        floatSame.instructions.add(new VarInsnNode(Opcodes.FSTORE, 0));
        floatSame.instructions.add(new InsnNode(Opcodes.RETURN));
        floatSame.maxStack = 2;
        floatSame.maxLocals = 1;
        classNode.methods.add(floatSame);

        MethodNode doubleSame = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "doubleSame", "(D)V", null, null);
        doubleSame.instructions.add(new VarInsnNode(Opcodes.DLOAD, 0));
        doubleSame.instructions.add(new LdcInsnNode(0.99d));
        doubleSame.instructions.add(new InsnNode(Opcodes.DADD));
        doubleSame.instructions.add(new VarInsnNode(Opcodes.DSTORE, 0));
        doubleSame.instructions.add(new InsnNode(Opcodes.RETURN));
        doubleSame.maxStack = 4;
        doubleSame.maxLocals = 2;
        classNode.methods.add(doubleSame);

        MethodNode differentLocal = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "differentLocal", "(FF)V", null, null);
        differentLocal.instructions.add(new VarInsnNode(Opcodes.FLOAD, 0));
        differentLocal.instructions.add(new LdcInsnNode(1.3f));
        differentLocal.instructions.add(new InsnNode(Opcodes.FADD));
        differentLocal.instructions.add(new VarInsnNode(Opcodes.FSTORE, 1));
        differentLocal.instructions.add(new InsnNode(Opcodes.RETURN));
        differentLocal.maxStack = 2;
        differentLocal.maxLocals = 2;
        classNode.methods.add(differentLocal);

        LabelNode boundary = new LabelNode();
        MethodNode blocked = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "blocked", "(D)V", null, null);
        blocked.instructions.add(new VarInsnNode(Opcodes.DLOAD, 0));
        blocked.instructions.add(boundary);
        blocked.instructions.add(new LdcInsnNode(0.99d));
        blocked.instructions.add(new InsnNode(Opcodes.DADD));
        blocked.instructions.add(new VarInsnNode(Opcodes.DSTORE, 0));
        blocked.instructions.add(new InsnNode(Opcodes.RETURN));
        blocked.maxStack = 4;
        blocked.maxLocals = 2;
        classNode.methods.add(blocked);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("floating-add-update-fusion", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("floatSame", "(F)V")),
            new MethodSelection(owner, owner.findMethod("doubleSame", "(D)V")),
            new MethodSelection(owner, owner.findMethod("differentLocal", "(FF)V")),
            new MethodSelection(owner, owner.findMethod("blocked", "(D)V"))
        )).source();

        String floatBody = lastFunctionSection(source, "neko_native_impl_0_body");
        assertTrue(floatBody.contains("{ locals[0].f = locals[0].f + 1.3f; }"), () -> floatBody);
        assertFalse(floatBody.contains("PUSH_F(a + b);"), () -> floatBody);

        String doubleBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(doubleBody.contains("{ locals[0].d = locals[0].d + 0.99; }"), () -> doubleBody);
        assertFalse(doubleBody.contains("PUSH_D(a + b);"), () -> doubleBody);

        String differentBody = lastFunctionSection(source, "neko_native_impl_2_body");
        assertTrue(differentBody.contains("PUSH_F(a + b);"), () -> differentBody);
        assertTrue(differentBody.contains("locals[1].f = POP_F();"), () -> differentBody);

        String blockedBody = lastFunctionSection(source, "neko_native_impl_3_body");
        assertTrue(blockedBody.contains("PUSH_D(locals[0].d);"), () -> blockedBody);
        assertTrue(blockedBody.contains("PUSH_D(a + b);"), () -> blockedBody);
        assertTrue(blockedBody.contains("locals[0].d = POP_D();"), () -> blockedBody);
    }

    @Test
    void primitiveConstantLocalStoresFuseWithoutCrossingLabels() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/ConstantStoreOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode constants = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "constants", "()V", null, null);
        constants.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        constants.instructions.add(new VarInsnNode(Opcodes.ISTORE, 0));
        constants.instructions.add(new LdcInsnNode(9L));
        constants.instructions.add(new VarInsnNode(Opcodes.LSTORE, 1));
        constants.instructions.add(new LdcInsnNode(1.5f));
        constants.instructions.add(new VarInsnNode(Opcodes.FSTORE, 3));
        constants.instructions.add(new LdcInsnNode(2.5d));
        constants.instructions.add(new VarInsnNode(Opcodes.DSTORE, 4));
        constants.instructions.add(new InsnNode(Opcodes.RETURN));
        constants.maxStack = 2;
        constants.maxLocals = 6;
        classNode.methods.add(constants);

        LabelNode boundary = new LabelNode();
        MethodNode blocked = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "blocked", "()V", null, null);
        blocked.instructions.add(new InsnNode(Opcodes.DCONST_0));
        blocked.instructions.add(boundary);
        blocked.instructions.add(new VarInsnNode(Opcodes.DSTORE, 0));
        blocked.instructions.add(new InsnNode(Opcodes.RETURN));
        blocked.maxStack = 2;
        blocked.maxLocals = 2;
        classNode.methods.add(blocked);

        MethodNode nonConstant = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "nonConstant", "(I)V", null, null);
        nonConstant.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        nonConstant.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        nonConstant.instructions.add(new InsnNode(Opcodes.RETURN));
        nonConstant.maxStack = 1;
        nonConstant.maxLocals = 2;
        classNode.methods.add(nonConstant);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("constant-local-store-fusion", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("constants", "()V")),
            new MethodSelection(owner, owner.findMethod("blocked", "()V")),
            new MethodSelection(owner, owner.findMethod("nonConstant", "(I)V"))
        )).source();

        String constantsBody = lastFunctionSection(source, "neko_native_impl_0_body");
        assertTrue(constantsBody.contains("{ locals[0].i = 7; }"), () -> constantsBody);
        assertTrue(constantsBody.contains("{ locals[1].j = 9LL; }"), () -> constantsBody);
        assertTrue(constantsBody.contains("{ locals[3].f = 1.5f; }"), () -> constantsBody);
        assertTrue(constantsBody.contains("{ locals[4].d = 2.5; }"), () -> constantsBody);
        assertFalse(constantsBody.contains("POP_I()"), () -> constantsBody);
        assertFalse(constantsBody.contains("POP_L()"), () -> constantsBody);
        assertFalse(constantsBody.contains("POP_F()"), () -> constantsBody);
        assertFalse(constantsBody.contains("POP_D()"), () -> constantsBody);

        String blockedBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(blockedBody.contains("PUSH_D(0.0);"), () -> blockedBody);
        assertTrue(blockedBody.contains("locals[0].d = POP_D();"), () -> blockedBody);

        String nonConstantBody = lastFunctionSection(source, "neko_native_impl_2_body");
        assertTrue(nonConstantBody.contains("PUSH_I(locals[0].i);"), () -> nonConstantBody);
        assertTrue(nonConstantBody.contains("locals[1].i = POP_I();"), () -> nonConstantBody);
    }

    @Test
    void singleIntProducersFuseIntoStaticTranslatedDirectCallsWithoutCrossingLabels() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/DirectIntInvokeOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode callee = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "callee", "(I)V", null, null);
        callee.instructions.add(new InsnNode(Opcodes.RETURN));
        callee.maxStack = 0;
        callee.maxLocals = 1;
        classNode.methods.add(callee);

        MethodNode caller = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "caller", "()V", null, null);
        caller.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        caller.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, "callee", "(I)V", false));
        caller.instructions.add(new InsnNode(Opcodes.RETURN));
        caller.maxStack = 1;
        caller.maxLocals = 0;
        classNode.methods.add(caller);

        LabelNode boundary = new LabelNode();
        MethodNode blocked = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "blocked", "()V", null, null);
        blocked.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        blocked.instructions.add(boundary);
        blocked.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, "callee", "(I)V", false));
        blocked.instructions.add(new InsnNode(Opcodes.RETURN));
        blocked.maxStack = 1;
        blocked.maxLocals = 0;
        classNode.methods.add(blocked);

        MethodNode nonTranslated = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "nonTranslated", "()V", null, null);
        nonTranslated.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        nonTranslated.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, "unselected", "(I)V", false));
        nonTranslated.instructions.add(new InsnNode(Opcodes.RETURN));
        nonTranslated.maxStack = 1;
        nonTranslated.maxLocals = 0;
        classNode.methods.add(nonTranslated);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("single-int-direct-invoke-fusion", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("callee", "(I)V")),
            new MethodSelection(owner, owner.findMethod("caller", "()V")),
            new MethodSelection(owner, owner.findMethod("blocked", "()V")),
            new MethodSelection(owner, owner.findMethod("nonTranslated", "()V"))
        )).source();

        String callerBody = lastFunctionSection(source, "neko_native_impl_1_body");
        assertTrue(callerBody.contains("neko_native_impl_0_body(thread, env, (jclass)clazz, (jint)(7));"), () -> callerBody);
        assertFalse(callerBody.contains("PUSH_I(7);"), () -> callerBody);
        assertFalse(callerBody.contains("arg0 = POP_I();"), () -> callerBody);

        String blockedBody = lastFunctionSection(source, "neko_native_impl_2_body");
        assertTrue(blockedBody.contains("PUSH_I(7);"), () -> blockedBody);
        assertTrue(blockedBody.contains("arg0 = POP_I();"), () -> blockedBody);

        String nonTranslatedBody = lastFunctionSection(source, "neko_native_impl_3_body");
        assertTrue(nonTranslatedBody.contains("PUSH_I(7);"), () -> nonTranslatedBody);
        assertTrue(nonTranslatedBody.contains("arg0 = POP_I();"), () -> nonTranslatedBody);
    }

    @Test
    void hotspotProbeEmitted() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/ProbeOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();
        classNode.methods.add(new MethodNode(Opcodes.ACC_PUBLIC, "demo", "()V", null, null));
        L1Class owner = new L1Class(classNode);

        CFunction function = new CFunction(
            "neko_native_impl_probe",
            CType.VOID,
            List.of(
                new CVariable("thread", CType.JOBJECT, 0),
                new CVariable("env", CType.JOBJECT, 1),
                new CVariable("self", CType.JOBJECT, 2)
            )
        );
        function.setMaxStack(0);
        function.setMaxLocals(1);
        function.addStatement(new CStatement.RawC(
            "neko_concat_accumulate_string(thread, env, NULL, NULL);"
        ));
        function.addStatement(new CStatement.ReturnVoid());

        NativeMethodBinding binding = new NativeMethodBinding(
            owner.name(),
            "demo",
            "()V",
            "neko_native_entry_probe",
            function.name(),
            "neko_binding_demo",
            "()V",
            false,
            false,
            false
        );

        String source = new CCodeGenerator(12345L).generateSource(List.of(function), List.of(binding));

        assertTrue(source.contains("neko_hotspot_init("), source);
        assertTrue(source.contains("g_hotspot"), source);
        assertTrue(source.contains("JNI_OnLoad") && source.contains("neko_hotspot_init(env);"), source);
        assertTrue(source.contains("jint array_length_offset;"), source);
        assertTrue(source.contains("NEKO_HOT_INLINE jint neko_fast_array_length(jarray arr)"), source);
        assertTrue(source.contains("NEKO_HOT_INLINE jint neko_fast_string_length(jstring str, jlong valueOffset, jlong coderOffset)"));
        assertTrue(source.contains("NEKO_FAST_INLINE jobject neko_build_raw_string_graph_store_local("));
        assertTrue(source.contains("NEKO_FAST_INLINE jboolean neko_raw_string_graph_prereq_enabled(void)"));
        assertTrue(source.contains("NEKO_RAW_STRING_GRAPH_PREREQ"));
        assertTrue(source.contains("g_neko_string_instance_bytes = (size_t)(layout_helper & ~1);"));
        assertTrue(source.contains("direct String allocation requires slow path"));
        assertTrue(source.contains("string_bytes = g_neko_string_instance_bytes;"));
        assertTrue(source.contains("raw String graph Unsafe.allocateInstance cache unavailable"));
        assertTrue(source.contains("array_handle = NULL;"));
        assertTrue(source.contains("raw String graph byte[] root publication failed before String slow allocation"));
        assertTrue(source.contains("if (array_handle != NULL) {"));
        assertTrue(source.contains("array_oop = (char*)neko_handle_oop(array_handle);"));
        assertTrue(source.contains("concat_result = neko_njx_V_L_L(thread, env,"));
        assertFalse(source.contains("neko_fast_array_length(JNIEnv *env"), source);
        assertTrue(source.contains("NEKO_HOT_INLINE jint neko_fast_iaload(jarray arr"), source);
        assertTrue(source.contains("NEKO_HOT_INLINE void neko_fast_iastore(jarray arr"), source);
        assertTrue(source.contains("NEKO_HOT_INLINE jboolean neko_checked_iastore(void *thread, JNIEnv *env, jintArray arr"), source);
        assertFalse(source.contains("neko_fast_iaload(JNIEnv *env"), source);
        assertFalse(source.contains("neko_fast_iastore(JNIEnv *env"), source);
        assertTrue(source.contains("neko_select_oop_array_load_barrier();"), source);
        assertTrue(source.contains("neko_barrier_load_oop_array("), source);
        assertTrue(source.contains("neko_array_store_check("), source);
        assertTrue(source.contains("NEKO_FAST_INLINE jboolean neko_fast_is_instance_of(JNIEnv *env, jobject obj, jclass cls)"), source);
        assertTrue(source.contains("return neko_klass_is_subtype_of(value_klass, target_klass);"), source);
        assertFalse(source.contains("neko_fast_get_object_class("));
        assertFalse(source.contains("neko_klass_java_mirror_handle(thread, value_klass)"));
        assertTrue(source.contains("g_neko_runtime1_monitorenter_entry"), source);
        assertTrue(source.contains("g_neko_runtime1_monitorexit_entry"), source);
        assertTrue(source.contains("NEKO_FAST_INLINE void neko_fast_monitor_enter(void *thread, jobject obj, neko_monitor_record *rec)"), source);
        assertTrue(source.contains("neko_call_runtime1_monitorenter(g_neko_runtime1_monitorenter_entry, thread"), source);
        assertTrue(source.contains("neko_monitor_record monitors["), source);
        assertFalse(source.contains("static inline jint neko_monitor_enter"), source);
        assertFalse(source.contains("static inline jint neko_monitor_exit"), source);
        assertTrue(source.contains("static inline void neko_set_pending_exception(void *thread, jthrowable exc)"), source);
        assertTrue(source.contains("static inline void *neko_pending_exception_oop(void *thread)"), source);
        assertTrue(source.contains("static inline void neko_clear_pending_exception(void *thread)"), source);
        assertTrue(source.contains("static inline jthrowable neko_take_pending_exception(void *thread)"), source);
        assertTrue(source.contains("#define NEKO_ENV_OFFSET_CACHE_NAME \"NEKO_NATIVE_JNI_ENV_OFFSET\""), source);
        assertTrue(source.contains("static jboolean neko_exception_check_validate_env_offset(JNIEnv *env, ptrdiff_t off"), source);
        assertTrue(source.contains("static jboolean neko_exception_check_load_process_env_offset(JNIEnv *env)"), source);
        assertTrue(source.contains("static jboolean neko_exception_check_publish_process_env_offset(ptrdiff_t off)"), source);
        assertTrue(source.contains("g_neko_env_offset_publication_kind = 2;"), source);
        assertTrue(source.contains("eager env-offset publication via process cache"), source);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_ENV_OFFSET_PUBLICATION"), source);
        assertTrue(source.contains("eager env-offset publication forced missing by diagnostic gate"), source);
        assertTrue(source.contains("#ifndef NEKO_HANDLE_AUDIT"), source);
        assertTrue(source.contains("handle_direct_overflow_alloc"), source);
        assertTrue(source.contains("NEKO_HANDLE_AUDIT_HIT(g_neko_handle_direct_total_count);"), source);
        assertTrue(source.contains("NEKO_HANDLE_AUDIT_ORIGIN(origin);"), source);
        assertTrue(source.contains("handle-origins:"), source);
        assertTrue(source.contains("njx-return-shapes:"), source);
        assertTrue(source.contains("concat-continuation:"), source);
        assertTrue(source.contains("stringbuilder-fast-concat:"), source);
        assertTrue(source.contains("NEKO_HANDLE_ORIGIN_AALOAD"), source);
        assertTrue(source.contains("NEKO_HANDLE_ORIGIN_OBJECT_FIELD"), source);
        assertTrue(source.contains("#define NEKO_JNIH_RECYCLE_MAX 64"), source);
        assertTrue(source.contains("#define NEKO_JNIH_BATCH_BLOCKS 64"), source);
        assertTrue(source.contains("void *neko_take_recycled_jnih_block(void)"), source);
        assertTrue(source.contains("void neko_recycle_jnih_block(void *block)"), source);
        assertTrue(source.contains("void *neko_alloc_jnih_block(jboolean *new_allocation)"), source);
        assertTrue(source.contains("static void neko_raise_implicit_exception(void *thread, JNIEnv *env, jclass cls, void *ctor_method, void *ctor_entry"));
        assertFalse(source.contains("static inline jint neko_throw("), source);
        assertFalse(source.contains("static inline jint neko_throw_new("), source);
        assertFalse(source.contains("NEKO_JNI_FN_PTR(env, 13, jint, jthrowable)"), source);
        assertFalse(source.contains("NEKO_JNI_FN_PTR(env, 14, jint, jclass, const char*)"), source);
        assertTrue(source.contains("off_objarrayklass_element_klass"), source);
        assertTrue(source.contains("NEKO_FAST_INLINE jobject neko_fast_alloc_object(void *thread, JNIEnv *env, jclass cls)"), source);
        assertTrue(source.contains("off_klass_layout_helper"), source);
        assertTrue(source.contains("static void neko_boxing_cache_init(JNIEnv *env)"), source);
        assertTrue(source.contains("neko_boxing_cache_init(env);"), source);
        assertTrue(source.contains("return neko_box_call(thread, env, &g_neko_box_int, arg, neko_njx_S_L_I);"), source);
        assertTrue(source.contains("static jint neko_unbox_int(void *thread, JNIEnv *env, jobject obj)"), source);
        assertFalse(source.contains("static jobject neko_box_int(JNIEnv *env"), source);
        assertFalse(source.contains("NEKO_ENSURE_STATIC_METHOD_ID(g_box_int_mid"), source);
        assertFalse(source.contains("neko_call_int_method_a("), source);
        assertFalse(source.contains("neko_call_object_method_a("), source);
        assertFalse(source.contains("neko_call_static_object_method_a("), source);
        assertFalse(source.contains("neko_call_nonvirtual_object_method_a("), source);
        assertTrue(source.contains("neko_array_klass_bits_for_descriptor(env,"), source);
        assertTrue(source.contains("neko_fast_new_primitive_array(thread, env,"), source);
        assertTrue(source.contains("__attribute__((visibility(\"hidden\"))) void neko_ensure_class_initialized_once(JNIEnv *env, jclass cls, const char *owner, volatile jboolean *slot)"), source);
        assertTrue(source.contains("memset(array_oop + base, 0, ((size_t)len * ref_size));"), source);
        assertTrue(source.contains("memset(array_oop + base, 0, ((size_t)len * scale));"), source);
        assertTrue(source.contains("neko_refill_tlab_with_slow_byte_array(env, bytes > (size_t)INT32_MAX ? INT32_MAX : (jint)bytes);"), source);
        assertTrue(source.contains("return neko_alloc_primitive_array_slow(env, len, kind);"), source);
        assertTrue(source.contains("static jarray neko_alloc_primitive_array_slow(JNIEnv *env, jint len, int kind)"), source);
        assertTrue(source.contains("JVM primitive array allocation symbols unavailable kind=%d"), source);
        assertTrue(source.contains("oop = (char*)neko_fast_tlab_alloc(thread, bytes);"), source);
        assertTrue(source.contains("if (oop == NULL && env != NULL) {"), source);
        assertTrue(source.contains("if (oop == NULL) {"), source);
        assertTrue(source.contains("NEW TLAB allocation failed cls=%p klass=%p bytes=%zu"), source);
        assertTrue(source.contains("primitive array allocation direct path unavailable len=%d kind=%d"), source);
        assertFalse(source.contains("neko_new_object_array(env, 0, elemClass"), source);
    }

    @Test
    void bindTimeResolved() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/BindOwner";
        classNode.superName = "java/lang/Object";
        classNode.fields = new ArrayList<>();
        classNode.methods = new ArrayList<>();
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "MESSAGE", "Ljava/lang/String;", null, null));
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "prefix", "Ljava/lang/String;", null, null));

        MethodNode virtualValue = new MethodNode(Opcodes.ACC_PUBLIC, "virtualValue", "()Ljava/lang/String;", null, null);
        virtualValue.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        virtualValue.instructions.add(new FieldInsnNode(Opcodes.GETFIELD, classNode.name, "prefix", "Ljava/lang/String;"));
        virtualValue.instructions.add(new InsnNode(Opcodes.ARETURN));
        virtualValue.maxStack = 1;
        virtualValue.maxLocals = 1;
        classNode.methods.add(virtualValue);

        MethodNode demo = new MethodNode(Opcodes.ACC_PUBLIC, "demo", "()Ljava/lang/String;", null, null);
        demo.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        demo.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, classNode.name, "virtualValue", "()Ljava/lang/String;", false));
        demo.instructions.add(new InsnNode(Opcodes.POP));
        demo.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, classNode.name, "MESSAGE", "Ljava/lang/String;"));
        demo.instructions.add(new InsnNode(Opcodes.POP));
        demo.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        demo.instructions.add(new FieldInsnNode(Opcodes.GETFIELD, classNode.name, "prefix", "Ljava/lang/String;"));
        demo.instructions.add(new InsnNode(Opcodes.POP));
        demo.instructions.add(new LdcInsnNode(Type.getObjectType(classNode.name)));
        demo.instructions.add(new InsnNode(Opcodes.POP));
        demo.instructions.add(new LdcInsnNode(Type.INT_TYPE));
        demo.instructions.add(new InsnNode(Opcodes.POP));
        demo.instructions.add(new LdcInsnNode(Type.getMethodType("(Ljava/lang/String;I)Ljava/lang/String;")));
        demo.instructions.add(new InsnNode(Opcodes.POP));
        demo.instructions.add(new LdcInsnNode("hello-bind"));
        demo.instructions.add(new InsnNode(Opcodes.ARETURN));
        demo.maxStack = 1;
        demo.maxLocals = 1;
        classNode.methods.add(demo);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("bind", false, false, 12345L);
        String source = translator.translate(List.of(new MethodSelection(owner, owner.findMethod("demo", "()Ljava/lang/String;")))).source();

        Matcher bindMatcher = Pattern.compile("neko_bind_owner_[A-Za-z0-9_]+\\s*\\(").matcher(source);
        assertTrue(bindMatcher.find(), () -> "Missing bind-owner initializer in generated C.\n" + source);

        String bodySection = translatedBodySection(source, "neko_native_impl_0");
        assertFalse(Pattern.compile("NEKO_ENSURE_CLASS\\(").matcher(bodySection).find(), () -> failure("NEKO_ENSURE_CLASS(", bodySection));
        assertFalse(Pattern.compile("NEKO_ENSURE_METHOD(?:_ID)?\\(").matcher(bodySection).find(), () -> failure("NEKO_ENSURE_METHOD", bodySection));
        assertFalse(Pattern.compile("NEKO_ENSURE_FIELD(?:_ID)?\\(").matcher(bodySection).find(), () -> failure("NEKO_ENSURE_FIELD", bodySection));
        assertFalse(Pattern.compile("NEKO_ENSURE_STRING\\(").matcher(bodySection).find(), () -> failure("NEKO_ENSURE_STRING(", bodySection));
        assertFalse(bodySection.contains("neko_get_object_class(env, self)"), () -> failure("neko_get_object_class(env, self)", bodySection));
        assertFalse(bodySection.contains("neko_class_for_descriptor(env"), () -> failure("neko_class_for_descriptor(env", bodySection));
        assertTrue(bodySection.contains("neko_bind_owner_strings_"), () -> bodySection);
        assertTrue(bodySection.contains("neko_bound_current_owner_class(thread, env,"), () -> bodySection);
        assertTrue(bodySection.contains("neko_fast_get_object_field(thread, env,"), () -> bodySection);
        assertTrue(bodySection.contains("neko_fast_get_static_object_field_ref(thread, env, &g_static_field_ref_"), () -> bodySection);
        assertFalse(bodySection.contains("if (cls != NULL && fid != NULL)"), () -> bodySection);
        assertFalse(bodySection.contains("if (fid != NULL)"), () -> bodySection);
        assertTrue(source.contains("neko_barrier_load_oop_field("), () -> source);
        assertTrue(source.contains("neko_select_oop_field_load_barrier();"), () -> source);
        assertFalse(source.contains("switch (g_neko_gc_barrier_kind)"), () -> source);
        assertFalse(source.contains("static inline jobject neko_get_object_field"), () -> source);
        assertTrue(source.contains("neko_bind_string_slot(thread, env, &g_str_0, \"hello-bind\");"), () -> source);
        assertTrue(source.contains("neko_bind_primitive_class_slot(env,"), () -> source);
        assertTrue(source.contains("localClass = neko_primitive_mirror_for_char(env, desc[0]);"), () -> source);
        assertTrue(source.contains("\"java/lang/Void\""), () -> source);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_PRIMITIVE_MIRROR_TAG"), () -> source);
        assertTrue(source.contains("T4.1 missing wrapper-class mirror for %s"), () -> source);
        assertFalse(source.contains("JVM_FindPrimitiveClass unavailable for LDC Class descriptor"), () -> source);
        int shadowStart = source.indexOf("static jstring neko_shadow_utf_string(void *thread, JNIEnv *env, const char *text) {");
        int shadowEnd = source.indexOf("static jclass neko_class_for_descriptor", shadowStart);
        assertTrue(shadowStart >= 0 && shadowEnd > shadowStart, () -> source);
        String shadowSection = source.substring(shadowStart, shadowEnd);
        assertTrue(shadowSection.contains("neko_intern_string(thread, env, (const uint8_t*)text, strlen(text));"), () -> shadowSection);
        assertTrue(shadowSection.contains("neko_handle_push(thread, string_oop);"), () -> shadowSection);
        assertTrue(shadowSection.contains("args[0].l = neko_shadow_dotted_string(thread, env, desc->owner);"), () -> shadowSection);
        assertTrue(shadowSection.contains("args[1].l = neko_shadow_utf_string(thread, env, desc->method);"), () -> shadowSection);
        assertTrue(shadowSection.contains("args[2].l = neko_shadow_utf_string(thread, env, desc->file);"), () -> shadowSection);
        assertFalse(shadowSection.contains("g_neko_jni_new_string_utf_fn"), () -> shadowSection);
        assertFalse(shadowSection.contains("NewStringUTF"), () -> shadowSection);
        assertTrue(source.contains("static void *g_neko_shadow_ste_ctor_method = NULL;"), () -> source);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_SHADOW_TRACE_ARRAY_ALLOC"), () -> source);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_SHADOW_STE_CTOR_ENTRY"), () -> source);
        assertTrue(source.contains("neko_njx_V_V_LLLI(thread, env,"), () -> source);
        assertTrue(shadowSection.contains("neko_ensure_class_initialized(env, ste_cls, \"java/lang/StackTraceElement\");"), () -> shadowSection);
        assertTrue(shadowSection.contains("neko_array_klass_bits_for_descriptor(env, \"[Ljava/lang/StackTraceElement;\", NULL);"), () -> shadowSection);
        assertTrue(shadowSection.contains("trace = neko_fast_new_object_array(thread, env, (jint)count, g_neko_shadow_ste_array_klass_bits, NULL);"), () -> shadowSection);
        assertTrue(shadowSection.contains("element = neko_fast_alloc_object(thread, env, ste_cls);"), () -> shadowSection);
        assertTrue(shadowSection.contains("neko_fast_aastore(thread, env, trace, (jint)i, element);"), () -> shadowSection);
        assertTrue(shadowSection.contains("neko_handle_window_begin(thread, &handle_window);"), () -> shadowSection);
        assertTrue(shadowSection.contains("trace_oop = neko_prepare_return_oop(thread, trace, \"shadow_stack_trace\");"), () -> shadowSection);
        assertTrue(shadowSection.contains("neko_handle_window_end(&handle_window);"), () -> shadowSection);
        assertTrue(shadowSection.contains("trace_result = (jobjectArray)neko_handle_push(thread, trace_oop);"), () -> shadowSection);
        int prepareTraceIndex = shadowSection.indexOf("trace_oop = neko_prepare_return_oop(thread, trace, \"shadow_stack_trace\");");
        int endWindowIndex = shadowSection.indexOf("neko_handle_window_end(&handle_window);", prepareTraceIndex);
        int pushReturnIndex = shadowSection.indexOf("trace_result = (jobjectArray)neko_handle_push(thread, trace_oop);", endWindowIndex);
        assertTrue(prepareTraceIndex >= 0 && prepareTraceIndex < endWindowIndex && endWindowIndex < pushReturnIndex, () -> shadowSection);
        assertFalse(source.contains("g_neko_jni_delete_local_ref_fn(env,"), () -> source);
        assertTrue(source.contains("array_raw = neko_prepare_return_oop(thread, array, \"slow_byte_array\");"), () -> source);
        assertTrue(source.contains("array_oop = neko_prepare_return_oop(thread, array, \"slow_primitive_array\");"), () -> source);
        assertTrue(source.contains("interned_oop = neko_prepare_return_oop(thread, interned, \"intern_string\");"), () -> source);
        assertTrue(source.contains("interned_oop = neko_prepare_return_oop(thread, interned, \"intern_string_without_raw_heap\");"), () -> source);
        assertTrue(source.contains("neko_handle_window_begin(thread, &icache_window);"), () -> source);
        assertFalse(shadowSection.contains("neko_resolve_jmethodID(env, ste_cls, \"<init>\""), () -> shadowSection);
        assertFalse(shadowSection.contains("g_neko_jni_new_object_array_fn"), () -> shadowSection);
        assertFalse(shadowSection.contains("g_neko_jni_new_object_a_fn"), () -> shadowSection);
        assertFalse(shadowSection.contains("g_neko_jni_set_object_array_element_fn"), () -> shadowSection);
        assertTrue(source.contains("neko_call_stub_guarded(&__stub_args);"), () -> source);
        assertTrue(source.contains("addq  $16, %%rsp"), () -> source);
        assertFalse(source.contains("addq  $24, %%rsp"), () -> source);
        assertTrue(source.contains("static void *g_neko_method_type_descriptor_method = NULL;"), () -> source);
        assertTrue(source.contains("mtClass = neko_resolve_class_mirror_with_env(env, \"java/lang/invoke/MethodType\", NULL, &mt_klass);"), () -> source);
        assertTrue(source.contains("neko_intern_string(thread, env, (const uint8_t*)desc, strlen(desc));"), () -> source);
        assertTrue(source.contains("result = neko_njx_S_L_LL(thread, env,"), () -> source);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_METHODTYPE_DESCRIPTOR_ENTRY"), () -> source);
        assertTrue(source.contains("PUSH_O(neko_method_type_from_descriptor(env, \"(Ljava/lang/String;I)Ljava/lang/String;\"));"), () -> source);
        assertFalse(source.contains("neko_class_for_descriptor(env, \"(Ljava/lang/String;I)Ljava/lang/String;\")"), () -> source);
        assertTrue(source.contains("static void *g_neko_method_type_parameter_array_method = NULL;"), () -> source);
        assertTrue(source.contains("result = neko_njx_V_L_(thread, env,"), () -> source);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_METHODTYPE_PARAMETER_ARRAY_ENTRY"), () -> source);
        assertFalse(source.contains("neko_resolve_jmethodID(env, mtClass, \"parameterArray\", \"()[Ljava/lang/Class;\")"), () -> source);
        assertFalse(source.contains("g_neko_jni_call_object_method_a_fn(env, mt, mid, NULL)"), () -> source);
        assertTrue(source.contains("static void *g_neko_bootstrap_get_declared_method_method = NULL;"), () -> source);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_BOOTSTRAP_GET_DECLARED_METHOD_ENTRY"), () -> source);
        assertTrue(source.contains("result = neko_njx_V_L_LL(thread, env,"), () -> source);
        assertTrue(source.contains("(void)neko_njx_V_V_I(thread, env,"), () -> source);
        assertFalse(source.contains("g_neko_jni_new_string_utf_fn(env, bsm_name)"), () -> source);
        assertFalse(source.contains("g_neko_jni_call_void_method_a_fn(env, method, setAccessible, accessibleArgs)"), () -> source);
        int condyStart = source.indexOf("static jobject neko_resolve_constant_dynamic(");
        int condyEnd = source.indexOf("static int neko_primitive_kind_from_descriptor_char", condyStart);
        assertTrue(condyStart >= 0 && condyEnd > condyStart, () -> source);
        String condySection = source.substring(condyStart, condyEnd);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_CONDY_OBJ_ARRAY_ALLOC"), () -> source);
        assertTrue(source.contains("return neko_fast_new_object_array(thread, env, len, objectArrayKlassBits, NULL);"), () -> source);
        assertTrue(condySection.contains("paramCount = neko_fast_array_length((jarray)paramTypes);"), () -> condySection);
        assertTrue(condySection.contains("invokeArgs = neko_condy_new_object_array(thread, env, paramCount);"), () -> condySection);
        assertTrue(condySection.contains("neko_intern_string(thread, env, (const uint8_t*)name, strlen(name));"), () -> condySection);
        assertTrue(condySection.contains("neko_fast_aaload(thread, env, static_args, i);"), () -> condySection);
        assertTrue(condySection.contains("neko_fast_aastore(thread, env, invokeArgs, i + 3, element);"), () -> condySection);
        assertFalse(condySection.contains("g_neko_jni_new_string_utf_fn(env, name)"), () -> condySection);
        assertFalse(condySection.contains("g_neko_jni_get_array_length_fn"), () -> condySection);
        assertFalse(condySection.contains("g_neko_jni_new_object_array_fn"), () -> condySection);
        assertFalse(condySection.contains("g_neko_jni_get_object_array_element_fn"), () -> condySection);
        assertFalse(condySection.contains("g_neko_jni_set_object_array_element_fn"), () -> condySection);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_IMPL_LOOKUP_SLOT"), () -> source);
        int implLookupStart = source.indexOf("static jobject neko_impl_lookup(JNIEnv *env) {");
        int implLookupEnd = source.indexOf("/* Method*-returning variant", implLookupStart);
        assertTrue(implLookupStart >= 0 && implLookupEnd > implLookupStart, () -> source);
        String implLookupSection = source.substring(implLookupStart, implLookupEnd);
        assertTrue(implLookupSection.contains("localLookup = neko_read_impl_lookup_direct(env);"), () -> implLookupSection);
        assertTrue(implLookupSection.contains("return localLookup;"), () -> implLookupSection);
        assertFalse(source.contains("static jobject g_neko_impl_lookup_global = NULL;"), () -> source);
        assertFalse(implLookupSection.contains("g_neko_impl_lookup_global"), () -> implLookupSection);
        assertFalse(implLookupSection.contains("g_neko_jni_new_global_ref_fn"), () -> implLookupSection);
        assertFalse(implLookupSection.contains("NewGlobalRef"), () -> implLookupSection);
        assertFalse(implLookupSection.contains("neko_resolve_field(klass, \"IMPL_LOOKUP\""), () -> implLookupSection);
        assertFalse(implLookupSection.contains("neko_fast_get_static_object_field("), () -> implLookupSection);
        assertTrue(source.contains("static void *g_neko_private_lookup_method = NULL;"), () -> source);
        assertTrue(source.contains("NEKO_NATIVE_DIAG_FAIL_PRIVATE_LOOKUP_ENTRY"), () -> source);
        int privateLookupStart = source.indexOf("static jobject neko_lookup_for_jclass(JNIEnv *env, jclass ownerClass) {");
        int privateLookupEnd = source.indexOf("static jboolean g_neko_method_type_descriptor_ready", privateLookupStart);
        assertTrue(privateLookupStart >= 0 && privateLookupEnd > privateLookupStart, () -> source);
        String privateLookupSection = source.substring(privateLookupStart, privateLookupEnd);
        assertTrue(privateLookupSection.contains("neko_ensure_private_lookup_cache(env);"), () -> privateLookupSection);
        assertTrue(privateLookupSection.contains("result = neko_njx_S_L_LL(thread, env,"), () -> privateLookupSection);
        assertFalse(privateLookupSection.contains("neko_resolve_jmethodID_with_kind(env, mhClass, \"privateLookupIn\""), () -> privateLookupSection);
        assertFalse(privateLookupSection.contains("g_neko_jni_call_static_object_method_a_fn"), () -> privateLookupSection);
        assertFalse(source.contains("g_neko_jni_new_string_utf_fn(env, desc)"), () -> source);
        assertFalse(source.contains("g_neko_jni_call_static_object_method_a_fn(env, mtClass, mid, args)"), () -> source);
        assertTrue(source.contains("static volatile jboolean g_cls_initialized_"), () -> source);
        assertTrue(source.contains("neko_ensure_class_initialized_once(env, cls,"), () -> source);
        assertTrue(source.contains("typedef struct neko_static_field_ref"), () -> source);
        assertTrue(source.contains("neko_static_field_ref_class(env,"), () -> source);
    }

    @Test
    void primitiveFieldsUseOnlyDirectOffsetHelpers() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/PrimitiveFields";
        classNode.superName = "java/lang/Object";
        classNode.fields = new ArrayList<>();
        classNode.methods = new ArrayList<>();
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "value", "I", null, null));
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "STATIC_VALUE", "I", null, null));

        MethodNode run = new MethodNode(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        run.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        run.instructions.add(new FieldInsnNode(Opcodes.GETFIELD, classNode.name, "value", "I"));
        run.instructions.add(new InsnNode(Opcodes.POP));
        run.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        run.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        run.instructions.add(new FieldInsnNode(Opcodes.PUTFIELD, classNode.name, "value", "I"));
        run.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, classNode.name, "STATIC_VALUE", "I"));
        run.instructions.add(new InsnNode(Opcodes.POP));
        run.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 9));
        run.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, "STATIC_VALUE", "I"));
        run.instructions.add(new InsnNode(Opcodes.RETURN));
        run.maxStack = 2;
        run.maxLocals = 1;
        classNode.methods.add(run);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("primitive-fields", false, false, 12345L);
        String source = translator.translate(List.of(new MethodSelection(owner, owner.findMethod("run", "()V")))).source();
        String bodySection = translatedBodySection(source, "neko_native_impl_0");

        assertTrue(bodySection.contains("neko_fast_get_I_field(env,"), () -> bodySection);
        assertTrue(bodySection.contains("neko_fast_set_I_field(env,"), () -> bodySection);
        assertTrue(bodySection.contains("neko_fast_get_static_I_field_ref(env, &g_static_field_ref_"), () -> bodySection);
        assertTrue(bodySection.contains("neko_fast_set_static_I_field(env,"), () -> bodySection);
        assertFalse(bodySection.contains("if (fid != NULL)"), () -> bodySection);
        assertFalse(bodySection.contains("if (cls != NULL && fid != NULL)"), () -> bodySection);
        assertFalse(source.contains("static inline jint neko_get_int_field"), () -> source);
        assertFalse(source.contains("static inline void neko_set_int_field"), () -> source);
        assertFalse(source.contains("static inline jint neko_get_static_int_field"), () -> source);
        assertFalse(source.contains("static inline void neko_set_static_int_field"), () -> source);
    }

    @Test
    void monitorStorageIsOnlyDeclaredForMonitorBytecodeMethods() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/MonitorStorageOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode noMonitor = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "noMonitor", "()V", null, null);
        noMonitor.instructions.add(new InsnNode(Opcodes.RETURN));
        noMonitor.maxStack = 0;
        noMonitor.maxLocals = 0;
        classNode.methods.add(noMonitor);

        MethodNode withMonitor = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "withMonitor", "(Ljava/lang/Object;)V", null, null);
        withMonitor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        withMonitor.instructions.add(new InsnNode(Opcodes.MONITORENTER));
        withMonitor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        withMonitor.instructions.add(new InsnNode(Opcodes.MONITOREXIT));
        withMonitor.instructions.add(new InsnNode(Opcodes.RETURN));
        withMonitor.maxStack = 1;
        withMonitor.maxLocals = 1;
        classNode.methods.add(withMonitor);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("monitor-storage", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("noMonitor", "()V")),
            new MethodSelection(owner, owner.findMethod("withMonitor", "(Ljava/lang/Object;)V"))
        )).source();

        String noMonitorBody = lastFunctionSection(source, "neko_native_impl_0_body");
        String withMonitorBody = lastFunctionSection(source, "neko_native_impl_1_body");

        assertFalse(noMonitorBody.contains("neko_monitor_record monitors["), () -> noMonitorBody);
        assertFalse(noMonitorBody.contains("int monitor_sp = 0;"), () -> noMonitorBody);
        assertTrue(withMonitorBody.contains("neko_monitor_record monitors["), () -> withMonitorBody);
        assertTrue(withMonitorBody.contains("int monitor_sp = 0;"), () -> withMonitorBody);
        assertTrue(withMonitorBody.contains("neko_fast_monitor_enter(thread, __mon, &monitors[monitor_sp++]);"), () -> withMonitorBody);
        assertTrue(withMonitorBody.contains("neko_fast_monitor_exit(thread, __mon, &monitors[--monitor_sp]);"), () -> withMonitorBody);
    }

    @Test
    void exceptionExitBlockIsOnlyDeclaredWhenReferenced() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/ExceptionExitOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode noExceptionExit = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "noExceptionExit", "()V", null, null);
        noExceptionExit.instructions.add(new InsnNode(Opcodes.RETURN));
        noExceptionExit.maxStack = 0;
        noExceptionExit.maxLocals = 0;
        classNode.methods.add(noExceptionExit);

        MethodNode referencedExceptionExit = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "referencedExceptionExit", "(Ljava/lang/Throwable;)V", null, null);
        referencedExceptionExit.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        referencedExceptionExit.instructions.add(new InsnNode(Opcodes.ATHROW));
        referencedExceptionExit.maxStack = 1;
        referencedExceptionExit.maxLocals = 1;
        classNode.methods.add(referencedExceptionExit);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("exception-exit", false, false, 12345L);
        String source = translator.translate(List.of(
            new MethodSelection(owner, owner.findMethod("noExceptionExit", "()V")),
            new MethodSelection(owner, owner.findMethod("referencedExceptionExit", "(Ljava/lang/Throwable;)V"))
        )).source();

        String noExitBody = lastFunctionSection(source, "neko_native_impl_0_body");
        String referencedExitBody = lastFunctionSection(source, "neko_native_impl_1_body");

        assertFalse(noExitBody.contains("__neko_exception_exit"), () -> noExitBody);
        assertTrue(referencedExitBody.contains("goto __neko_exception_exit"), () -> referencedExitBody);
        assertTrue(referencedExitBody.contains("__neko_exception_exit:"), () -> referencedExitBody);
    }

    @Test
    void objectFieldStoresUseBarrierAwareDirectHelpers() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/ObjectFields";
        classNode.superName = "java/lang/Object";
        classNode.fields = new ArrayList<>();
        classNode.methods = new ArrayList<>();
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "value", "Ljava/lang/String;", null, null));
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "STATIC_VALUE", "Ljava/lang/String;", null, null));

        MethodNode run = new MethodNode(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        run.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        run.instructions.add(new LdcInsnNode("field-value"));
        run.instructions.add(new FieldInsnNode(Opcodes.PUTFIELD, classNode.name, "value", "Ljava/lang/String;"));
        run.instructions.add(new LdcInsnNode("static-value"));
        run.instructions.add(new FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, "STATIC_VALUE", "Ljava/lang/String;"));
        run.instructions.add(new InsnNode(Opcodes.RETURN));
        run.maxStack = 2;
        run.maxLocals = 1;
        classNode.methods.add(run);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("object-fields", false, false, 12345L);
        String source = translator.translate(List.of(new MethodSelection(owner, owner.findMethod("run", "()V")))).source();
        String bodySection = translatedBodySection(source, "neko_native_impl_0");

        assertTrue(bodySection.contains("neko_fast_set_object_field(thread, env,"), () -> bodySection);
        assertTrue(bodySection.contains("neko_fast_set_static_object_field(thread, env,"), () -> bodySection);
        assertFalse(bodySection.contains("if (fid != NULL)"), () -> bodySection);
        assertFalse(bodySection.contains("if (cls != NULL && fid != NULL)"), () -> bodySection);
        assertTrue(source.contains("neko_select_oop_field_store_barrier();"), () -> source);
        assertTrue(source.contains("neko_barrier_pre_store_oop_field("), () -> source);
        assertTrue(source.contains("neko_barrier_post_store_oop_field("), () -> source);
        assertFalse(source.contains("static inline void neko_set_object_field"), () -> source);
        assertFalse(source.contains("static inline void neko_set_static_object_field"), () -> source);
    }

    @Test
    void strictGcBarrierDetectionUsesTagFallbacksBeforeCardTableFamilies() {
        CFunction function = new CFunction(
            "neko_native_entry_probe",
            CType.VOID,
            List.of(
                new CVariable("thread", CType.JOBJECT, 0),
                new CVariable("env", CType.JOBJECT, 1),
                new CVariable("self", CType.JOBJECT, 2)
            )
        );
        function.addStatement(new CStatement.ReturnVoid());

        NativeMethodBinding binding = new NativeMethodBinding(
            "pkg/GcProbe",
            "demo",
            "()V",
            "neko_native_entry_probe",
            function.name(),
            "neko_binding_gc_probe",
            "()V",
            false,
            false,
            false
        );

        String source = new CCodeGenerator(12345L).generateSource(List.of(function), List.of(binding));
        String detector = functionSection(source, "neko_detect_current_gc_barrier");
        String readiness = functionSection(source, "neko_gc_barrier_layout_ready");

        assertTrue(source.contains("NEKO_JDK21_BARRIERSET_SHENANDOAH_FALLBACK = 4"), () -> source);
        assertTrue(source.contains("NEKO_JDK21_BARRIERSET_Z_FALLBACK = 5"), () -> source);
        assertTrue(detector.indexOf("neko_barrierset_tag_is_shenandoah(tag)") < detector.indexOf("tag == g_neko_method_layout.vmconst_barrierset_g1"), () -> detector);
        assertTrue(detector.indexOf("neko_barrierset_tag_is_zgc(tag)") < detector.indexOf("tag == g_neko_method_layout.vmconst_barrierset_g1"), () -> detector);
        assertFalse(detector.contains("addr_zglobals_instance_p != NULL"), () -> detector);
        assertTrue(readiness.contains("g_hotspot.z_zglobals_addr_mask_p != NULL"), () -> readiness);
        assertTrue(readiness.contains("z_addr_mask != 0"), () -> readiness);
        assertTrue(readiness.contains("ZGC barrier capability missing"), () -> readiness);
        assertTrue(readiness.contains("Shenandoah barrier capability missing"), () -> readiness);
    }

    @Test
    void icacheScaffoldEmitted() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/IcacheOwner";
        classNode.superName = "java/lang/Object";
        classNode.fields = new ArrayList<>();
        classNode.methods = new ArrayList<>();
        classNode.fields.add(new FieldNode(Opcodes.ACC_PUBLIC, "prefix", "Ljava/lang/String;", null, null));

        MethodNode virtualValue = new MethodNode(Opcodes.ACC_PUBLIC, "virtualValue", "()Ljava/lang/String;", null, null);
        virtualValue.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        virtualValue.instructions.add(new FieldInsnNode(Opcodes.GETFIELD, classNode.name, "prefix", "Ljava/lang/String;"));
        virtualValue.instructions.add(new InsnNode(Opcodes.ARETURN));
        virtualValue.maxStack = 1;
        virtualValue.maxLocals = 1;
        classNode.methods.add(virtualValue);

        MethodNode demo = new MethodNode(Opcodes.ACC_PUBLIC, "demo", "()Ljava/lang/String;", null, null);
        demo.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        demo.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, classNode.name, "virtualValue", "()Ljava/lang/String;", false));
        demo.instructions.add(new InsnNode(Opcodes.ARETURN));
        demo.maxStack = 1;
        demo.maxLocals = 1;
        classNode.methods.add(demo);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("icache", false, false, 12345L);
        String source = translator.translate(List.of(new MethodSelection(owner, owner.findMethod("demo", "()Ljava/lang/String;")))).source();

        assertTrue(source.contains("typedef struct neko_icache_site") || source.contains("struct neko_icache_site"), source);
        assertTrue(source.contains("receiver_key;"), source);
        assertTrue(source.contains("target;"), source);
        assertTrue(source.contains("target_kind;"), source);
        assertTrue(source.contains("miss_count;"), source);
        assertFalse(source.contains("cached_class;"), source);
        assertFalse(source.contains("g_neko_jni_delete_global_ref_fn(env, site->cached_class"), source);
        assertTrue(source.contains("receiverKey = (uintptr_t)receiverKlass;"), source);
        assertTrue(source.contains("neko_receiver_key_supported("), source);
        assertTrue(source.contains("typedef jvalue (*neko_icache_direct_stub)") || source.contains("typedef jvalue(*neko_icache_direct_stub)"), source);
        assertTrue(source.contains("neko_icache_dispatch("), source);
        assertTrue(source.contains("#define NEKO_ICACHE_AUDIT 0"), source);
        assertTrue(source.contains("#if NEKO_ICACHE_AUDIT"), source);
        assertTrue(source.contains("g_neko_icache_direct_c_hit_count"), source);
        assertTrue(source.contains("g_neko_icache_direct_njx_hit_count"), source);
        assertTrue(source.contains("g_neko_icache_miss_count"), source);
        assertTrue(source.contains("NEKO_ICACHE_AUDIT_HIT(g_neko_icache_direct_c_hit_count);"), source);
        assertTrue(source.contains("icache_direct_c_hit=%llu"), source);
    }

    @Test
    void implementationPreludeDeclaresMultilineSupportDefinitionsOnce() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/SplitOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();
        classNode.methods.add(new MethodNode(Opcodes.ACC_PUBLIC, "demo", "()V", null, null));
        L1Class owner = new L1Class(classNode);

        CFunction function = new CFunction(
            "neko_native_impl_split",
            CType.VOID,
            List.of(
                new CVariable("thread", CType.JOBJECT, 0),
                new CVariable("env", CType.JOBJECT, 1),
                new CVariable("self", CType.JOBJECT, 2)
            )
        );
        function.setMaxStack(0);
        function.setMaxLocals(1);
        function.addStatement(new CStatement.ReturnVoid());

        NativeMethodBinding binding = new NativeMethodBinding(
            owner.name(),
            "demo",
            "()V",
            "neko_native_entry_split",
            function.name(),
            "neko_binding_split",
            "()V",
            false,
            false,
            false
        );

        CCodeGenerator generator = new CCodeGenerator(12345L);
        generator.reserveInvokeCacheSite("pkg/SplitOwner", "demo()V", 0);
        generator.reserveInvokeCacheMeta("pkg/SplitOwner", "demo()V", 0,
            "println", "(Ljava/lang/String;)V", false, "NULL", "NULL", "neko_njx_V_V_L");
        generator.requireCachedFastArrayRaiseHelper("pkg/SplitOwner");
        generator.classDescriptorRefName(owner.name(), "java/lang/Throwable");
        generator.methodEntryDescriptorRefName(owner.name(), "java/lang/String", "valueOf", "(I)Ljava/lang/String;", true);
        generator.methodIdDescriptorRefName(owner.name(), "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        generator.fieldDescriptorRefName(owner.name(), "java/lang/String", "value", "[B", false);
        generator.fieldOffsetSlotName("java/lang/String", "value", "[B", false);
        generator.fieldOffsetSlotName("java/lang/String", "coder", "B", false);
        CCodeGenerator.GeneratedSourceSet sourceSet = generator.generateSourceSet(List.of(function), List.of(binding));
        String header = sourceSet.implementationHeader().source();
        assertEquals(1, sourceSet.implementationHeaders().size());
        assertEquals(2, sourceSet.allImplementationHeaders().size());
        String slicedHeader = sourceSet.implementationHeaders().get(0).source();
        String implementation = sourceSet.implementationSources().get(0).source();
        assertTrue(implementation.contains("#include \"neko_native_impl_0_prelude.h\""), implementation);
        assertFalse(implementation.contains("#include \"neko_native_impl_prelude.h\""), implementation);
        assertTrue(slicedHeader.length() < header.length(), "sliced=" + slicedHeader.length() + " full=" + header.length());
        assertTrue(slicedHeader.contains("NEKO_NATIVE_IMPL_PRELUDE_LOADED"), slicedHeader);
        assertTrue(slicedHeader.contains("neko_hotspot_fast_require"), slicedHeader);
        assertTrue(slicedHeader.contains("#define neko_concat_accumulate_string"), slicedHeader);
        assertTrue(slicedHeader.contains("g_off_0;"), slicedHeader);
        assertTrue(slicedHeader.contains("g_off_1;"), slicedHeader);
        assertFalse(slicedHeader.contains("#define g_method_entry_ref_0 "), slicedHeader);
        assertFalse(slicedHeader.contains("#define g_method_id_ref_0 "), slicedHeader);
        assertFalse(slicedHeader.contains("#define g_field_ref_0 "), slicedHeader);
        assertFalse(slicedHeader.contains("#define neko_icache_0_0_0 "), slicedHeader);
        String support = sourceSet.supportSource().source();
        String supportHelpers = sourceSet.supportSources().stream()
            .filter(source -> source.fileName().startsWith("neko_native_support_helpers_"))
            .map(CCodeGenerator.GeneratedSourceFile::source)
            .reduce("", String::concat);
        String globalSupport = sourceSet.supportSources().stream()
            .filter(source -> source.fileName().equals("neko_native_globals.c"))
            .findFirst()
            .orElseThrow()
            .source();
        String ownerBindings = sourceSet.supportSources().stream()
            .filter(source -> source.fileName().equals("neko_native_owner_bindings.c"))
            .findFirst()
            .orElseThrow()
            .source();
        String icacheSupport = sourceSet.supportSources().stream()
            .filter(source -> source.fileName().equals("neko_native_icache_support.c"))
            .findFirst()
            .orElseThrow()
            .source();

        assertFalse(header.contains("static jvalue neko_icache_dispatch("), header);
        assertFalse(header.contains("static void neko_raise_fast_array_reason("), header);
        assertFalse(header.contains("static void neko_raise_cached_fast_array_reason("), header);
        assertFalse(header.contains("static jboolean neko_checked_iaload("), header);
        assertFalse(header.contains("static jvalue neko_njx_dispatch_generic("), header);
        assertFalse(header.contains("static neko_icache_site neko_icache_"), header);
        assertFalse(header.contains("static const neko_icache_meta neko_icache_meta_"), header);
        assertTrue(header.contains("return neko_require_fast_string_concat(thread, env, lhs, normalized_rhs"), header);
        assertFalse(header.contains("neko_fast_string_concat("));
        assertTrue(header.contains("NEKO_FAST_INLINE jobject neko_build_raw_string_graph_store_local("), header);
        assertTrue(header.contains("NEKO_FAST_INLINE jboolean neko_raw_string_graph_prereq_enabled(void)"), header);
        assertTrue(header.contains("getenv(\"NEKO_RAW_STRING_GRAPH_PREREQ\")"), header);
        assertTrue(header.contains("return neko_build_raw_string_graph_store_local(thread, env, slot_ref, left, right, valueOffset, coderOffset);"), header);
        assertTrue(header.contains("neko_copy_string_payload(array_oop, 0, result_coder, left_value, left_chars, left_coder);"), header);
        assertTrue(header.contains("if (array_handle != NULL) {"), header);
        assertTrue(header.contains("raw String graph input unresolved after byte[] allocation"), header);
        assertTrue(header.contains("raw String graph value array unresolved after byte[] allocation"), header);
        assertTrue(header.contains("raw String graph byte[] root publication failed before String slow allocation"), header);
        assertTrue(header.contains("raw String graph unrooted byte[] lost before String publication"), header);
        assertTrue(header.contains("alloc_arg.l = (jobject)string_mirror;"), header);
        assertTrue(header.contains("raw String graph Unsafe.allocateInstance failed"), header);
        assertTrue(header.contains("raw String graph byte[] unresolved after String allocation"), header);
        assertTrue(header.contains("return neko_store_local_oop_raw(thread, slot_ref, string_oop);"), header);
        assertTrue(header.contains("g_neko_string_instance_bytes"), header);
        assertTrue(header.contains("NEKO_HOT_INLINE jint neko_fast_string_length(jstring str, jlong valueOffset, jlong coderOffset)"), header);
        assertFalse(header.contains("neko_fast_get_object_class("));
        assertFalse(header.contains("neko_fast_atomic_long_add_and_get("));
        assertFalse(header.contains("neko_fast_atomic_int_add_and_get("));
        assertTrue(header.contains("__attribute__((visibility(\"hidden\"))) extern jvalue neko_icache_dispatch(\n"), header);
        assertTrue(header.contains("__attribute__((visibility(\"hidden\"))) extern void neko_raise_fast_array_reason("), header);
        assertTrue(header.contains("__attribute__((visibility(\"hidden\"))) extern void neko_raise_cached_fast_array_reason("), header);
        assertTrue(header.contains("__attribute__((visibility(\"hidden\"))) extern jboolean neko_checked_iaload("), header);
        assertTrue(header.contains("NEKO_HOT_INLINE jboolean neko_checked_iastore(void *thread, JNIEnv *env, jintArray arr"), header);
        assertFalse(header.contains("neko_njx_dispatch_generic("), header);
        assertTrue(header.contains("__attribute__((visibility(\"hidden\"))) extern neko_icache_site neko_icache_sites["), header);
        assertTrue(header.contains("__attribute__((visibility(\"hidden\"))) extern const neko_icache_meta neko_icache_metas["), header);
        assertTrue(header.contains("#define neko_icache_"), header);
        assertTrue(header.contains("#define neko_icache_meta_"), header);
        assertTrue(header.contains("__attribute__((visibility(\"hidden\"))) extern jobject neko_concat_append(\n"), header);
        assertTrue(header.contains("NEKO_FAST_INLINE jobject neko_concat_append_inline(\n"), header);
        assertTrue(header.contains("NEKO_FAST_INLINE jstring neko_concat_accumulate(\n"), header);
        assertTrue(header.contains("#define neko_concat_accumulate_string(thread, env, acc, rhs)"), header);

        assertTrue(header.contains("extern const neko_class_ref g_class_refs["), header);
        assertTrue(header.contains("__attribute__((visibility(\"hidden\"))) extern jboolean neko_exception_handler_matches_ref("), header);
        assertTrue(header.contains("#define neko_bound_class_ref(env, ref)"), header);
        assertTrue(header.contains("extern const neko_method_entry_ref g_method_entry_refs["), header);
        assertTrue(header.contains("#define neko_bound_method_i_entry_ref(ref)"), header);
        assertTrue(header.contains("*((ref)->method_slot) != NULL && *((ref)->ientry_slot) != NULL ? *((ref)->ientry_slot) : neko_bound_method_i_entry"), header);
        assertTrue(header.contains("extern const neko_method_id_ref g_method_id_refs["), header);
        assertTrue(header.contains("#define neko_bound_method_ref(env, ref)"), header);
        assertTrue(header.contains("extern const neko_field_ref g_field_refs["), header);
        assertTrue(header.contains("#define neko_bound_field_ref(env, ref)"), header);
        assertFalse(supportHelpers.isEmpty(), sourceSet.supportSources().toString());
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) extern jvalue neko_icache_dispatch(\n"), support);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) extern void neko_raise_fast_array_reason("), support);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) extern void neko_raise_cached_fast_array_reason("), support);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) extern jboolean neko_checked_iaload("), support);
        assertTrue(support.contains("NEKO_HOT_INLINE jboolean neko_checked_iastore(void *thread, JNIEnv *env, jintArray arr"), support);
        assertFalse(support.contains("neko_njx_dispatch_generic("), support);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) neko_icache_site neko_icache_sites["), support);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) extern jobject neko_concat_append(\n"), support);
        assertTrue(support.contains("NEKO_FAST_INLINE jobject neko_concat_append_inline(\n"), support);
        assertTrue(supportHelpers.contains("#include \"neko_native_impl_prelude.h\""), supportHelpers);
        assertTrue(supportHelpers.contains("__attribute__((visibility(\"hidden\"))) jvalue neko_icache_dispatch(\n"), supportHelpers);
        assertTrue(supportHelpers.contains("__attribute__((visibility(\"hidden\"))) jobject neko_concat_append(\n"), supportHelpers);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) extern jclass g_cls_"), support);
        assertFalse(support.contains("__attribute__((visibility(\"hidden\"))) jclass g_cls_"), support);
        assertTrue(globalSupport.contains("#include \"neko_native_impl_prelude.h\""), globalSupport);
        assertTrue(globalSupport.contains("__attribute__((visibility(\"hidden\"))) jclass g_cls_"), globalSupport);
        assertTrue(globalSupport.contains("__attribute__((visibility(\"hidden\"))) uintptr_t g_obj_array_klass_"), globalSupport);
        assertFalse(globalSupport.contains("__attribute__((visibility(\"hidden\"))) extern jclass g_cls_"), globalSupport);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) const neko_class_ref g_class_refs["), support);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) const neko_method_entry_ref g_method_entry_refs["), support);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) const neko_method_id_ref g_method_id_refs["), support);
        assertTrue(support.contains("__attribute__((visibility(\"hidden\"))) const neko_field_ref g_field_refs["), support);
        assertFalse(support.contains("// === Bind-time owner resolution ==="), support);
        assertFalse(support.contains("// === Inline-cache metadata ==="), support);
        assertTrue(ownerBindings.contains("#include \"neko_native_impl_prelude.h\""), ownerBindings);
        assertTrue(ownerBindings.contains("__attribute__((visibility(\"hidden\"))) void neko_bind_owner_"), ownerBindings);
        assertTrue(icacheSupport.contains("#include \"neko_native_impl_prelude.h\""), icacheSupport);
        assertTrue(icacheSupport.contains("// === Inline-cache metadata ==="), icacheSupport);
        assertTrue(icacheSupport.contains("__attribute__((visibility(\"hidden\"))) const neko_icache_meta neko_icache_metas["), icacheSupport);
    }

    @Test
    void largeSignatureDispatcherSectionSplitsOnWholeDispatcherGroups() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/DispatcherSplitOwner";
        classNode.superName = "java/lang/Object";
        L1Class owner = new L1Class(classNode);

        CFunction function = new CFunction(
            "neko_native_impl_dispatcher_split",
            CType.VOID,
            List.of(
                new CVariable("thread", CType.JOBJECT, 0),
                new CVariable("env", CType.JOBJECT, 1),
                new CVariable("self", CType.JOBJECT, 2)
            )
        );
        function.setMaxStack(0);
        function.setMaxLocals(1);
        function.addStatement(new CStatement.ReturnVoid());

        List<NativeMethodBinding> bindings = new ArrayList<>();
        String[] descriptors = {
            "()V",
            "()I",
            "()J",
            "()F",
            "()D",
            "()Ljava/lang/Object;",
            "(I)V",
            "(J)V",
            "(F)V",
            "(D)V",
            "(Ljava/lang/Object;)V"
        };
        for (int i = 0; i < descriptors.length; i++) {
            bindings.add(new NativeMethodBinding(
                owner.name(),
                "m" + i,
                descriptors[i],
                "neko_native_entry_dispatcher_split_" + i,
                function.name(),
                "neko_binding_dispatcher_split_" + i,
                descriptors[i],
                true,
                false,
                false
            ));
        }

        CCodeGenerator.GeneratedSourceSet sourceSet = new CCodeGenerator(12345L)
            .generateSourceSet(List.of(function), bindings);
        List<CCodeGenerator.GeneratedSourceFile> dispatcherSources = sourceSet.supportSources().stream()
            .filter(source -> source.fileName().startsWith("neko_native_dispatchers_"))
            .toList();

        assertEquals(2, dispatcherSources.size(), dispatcherSources.toString());
        assertTrue(dispatcherSources.stream().allMatch(source ->
            source.source().contains("#include \"neko_native_impl_prelude.h\"")), dispatcherSources.toString());
        for (CCodeGenerator.GeneratedSourceFile source : dispatcherSources) {
            int typedefs = countMatches(source.source(), "typedef ");
            int dispatchers = countRegex(source.source(), "neko_sig_\\d+_dispatch\\(");
            assertTrue(typedefs <= 8, source.source());
            assertEquals(typedefs, dispatchers, source.source());
        }
    }

    @Test
    void virtualInterfaceResolutionSkipsAbstractDeclarationsWhenDefaultMethodExists() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V1_8;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/InterfaceDefaultOwner";
        classNode.superName = "java/lang/Object";
        classNode.methods = new ArrayList<>();

        MethodNode demo = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "demo", "(Ljava/lang/AutoCloseable;)V", null, null);
        demo.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        demo.instructions.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, "java/lang/AutoCloseable", "close", "()V", true));
        demo.instructions.add(new InsnNode(Opcodes.RETURN));
        demo.maxStack = 1;
        demo.maxLocals = 1;
        classNode.methods.add(demo);

        L1Class owner = new L1Class(classNode);
        NativeTranslator translator = new NativeTranslator("interface-default", false, false, 12345L);
        String source = translator.translate(List.of(new MethodSelection(owner, owner.findMethod("demo", "(Ljava/lang/AutoCloseable;)V")))).source();

        assertTrue(source.contains("#define NEKO_JVM_ACC_ABSTRACT 0x0400u"), () -> source);
        assertTrue(source.contains("if (method != NULL && neko_method_is_instance_default(method)) return method;"), () -> source);
        assertTrue(source.contains("NEKO_JVM_ACC_STATIC | NEKO_JVM_ACC_ABSTRACT"), () -> source);
        assertTrue(source.contains("neko_resolve_method_declaration_with_kind"), () -> source);
        assertTrue(source.contains("neko_resolve_interface_declared_method"), () -> source);
        assertTrue(source.contains("neko_resolve_declared_covariant_ref_method"), () -> source);
        assertTrue(source.contains("ambiguous covariant reference method resolution"), () -> source);
        assertFalse(source.contains("static void *neko_resolve_interface_method("), () -> source);
    }

    private static String translatedBodySection(String source, String functionName) {
        Matcher matcher = Pattern.compile("static\\s+\\S+\\s+" + Pattern.quote(functionName) + "\\([^)]*\\) \\{").matcher(source);
        assertTrue(matcher.find(), () -> "Missing translated raw function `" + functionName + "` in generated C.\n" + source);
        return source.substring(matcher.start());
    }

    private static String functionSection(String source, String functionName) {
        int nameIndex = source.indexOf(functionName + "(");
        assertTrue(nameIndex >= 0, () -> "Missing generated C function `" + functionName + "`\n" + source);
        return functionSectionFrom(source, functionName, nameIndex);
    }

    private static String lastFunctionSection(String source, String functionName) {
        int nameIndex = source.lastIndexOf(functionName + "(");
        assertTrue(nameIndex >= 0, () -> "Missing generated C function `" + functionName + "`\n" + source);
        return functionSectionFrom(source, functionName, nameIndex);
    }

    private static String functionSectionFrom(String source, String functionName, int nameIndex) {
        int open = source.indexOf('{', nameIndex);
        assertTrue(open >= 0, () -> "Missing body for generated C function `" + functionName + "`\n" + source);
        int depth = 0;
        for (int i = open; i < source.length(); i++) {
            char c = source.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return source.substring(nameIndex, i + 1);
                }
            }
        }
        throw new AssertionError("Unterminated generated C function `" + functionName + "`");
    }

    private static String failure(String needle, String text) {
        int index = text.indexOf(needle.replace("(?:_ID)?", ""));
        if (index < 0) {
            Matcher matcher = Pattern.compile(needle).matcher(text);
            index = matcher.find() ? matcher.start() : -1;
        }
        return "Unexpected match for `" + needle + "` at line " + lineNumber(text, index) + ": " + context(text, index);
    }

    private static int lineNumber(String text, int index) {
        if (index < 0) {
            return -1;
        }
        int line = 1;
        for (int i = 0; i < index; i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }

    private static String context(String text, int index) {
        if (index < 0) {
            return "<no match context>";
        }
        int start = Math.max(0, index - 40);
        int end = Math.min(text.length(), index + 80);
        return text.substring(start, end).replace('\n', ' ');
    }

    private static int countMatches(String text, String needle) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(needle, index)) >= 0) {
            count++;
            index += needle.length();
        }
        return count;
    }

    private static int countRegex(String text, String regex) {
        int count = 0;
        Matcher matcher = Pattern.compile(regex).matcher(text);
        while (matcher.find()) {
            count++;
        }
        return count;
    }
}
