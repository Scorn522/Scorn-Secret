package dev.nekoobfuscator.test;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.native_.translator.NativeTranslationSafetyChecker;
import org.objectweb.asm.Handle;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeTranslationSafetyCheckerTest {
    @Test
    void rejectsApplicationCalleeMissingFromNativeManifest() {
        L1Method method = methodCalling("pkg/Caller", "pkg/Helper", "target");
        List<String> reasons = new ArrayList<>();

        boolean safe = new NativeTranslationSafetyChecker().isSafe(
            method,
            reasons,
            Set.of("pkg/Caller#run()V", "pkg/Helper#target()V"),
            Set.of("pkg/Caller#run()V")
        );

        assertFalse(safe);
        assertTrue(reasons.contains("callee not in native manifest: pkg/Helper#target()V"), reasons::toString);
    }

    @Test
    void allowsManifestAndExternalCallees() {
        L1Method manifestCallee = methodCalling("pkg/Caller", "pkg/Helper", "target");
        List<String> manifestReasons = new ArrayList<>();
        boolean manifestSafe = new NativeTranslationSafetyChecker().isSafe(
            manifestCallee,
            manifestReasons,
            Set.of("pkg/Caller#run()V", "pkg/Helper#target()V"),
            Set.of("pkg/Caller#run()V", "pkg/Helper#target()V")
        );
        assertTrue(manifestSafe, manifestReasons::toString);

        L1Method externalCallee = methodCalling("pkg/Caller", "java/lang/System", "gc");
        List<String> externalReasons = new ArrayList<>();
        boolean externalSafe = new NativeTranslationSafetyChecker().isSafe(
            externalCallee,
            externalReasons,
            Set.of("pkg/Caller#run()V"),
            Set.of("pkg/Caller#run()V")
        );
        assertTrue(externalSafe, externalReasons::toString);
    }

    @Test
    void rejectsUnsupportedInvokeDynamicBootstrapBeforeFallback() {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = "pkg/UnsupportedIndy";
        classNode.superName = "java/lang/Object";

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        method.instructions.add(new InvokeDynamicInsnNode(
            "dyn",
            "()V",
            new Handle(Opcodes.H_INVOKESTATIC, "pkg/Bootstrap", "bootstrap", "()V", false)
        ));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 0;
        method.maxLocals = 0;
        classNode.methods.add(method);

        List<String> reasons = new ArrayList<>();
        boolean safe = new NativeTranslationSafetyChecker().isSafe(new L1Class(classNode).findMethod("run", "()V"), reasons);

        assertFalse(safe);
        assertTrue(reasons.stream().anyMatch(reason -> reason.contains("unsupported invokedynamic bootstrap: pkg/Bootstrap.bootstrap()V")), reasons::toString);
    }

    private static L1Method methodCalling(String owner, String calleeOwner, String calleeName) {
        ClassNode classNode = new ClassNode();
        classNode.version = Opcodes.V17;
        classNode.access = Opcodes.ACC_PUBLIC;
        classNode.name = owner;
        classNode.superName = "java/lang/Object";

        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        method.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, calleeOwner, calleeName, "()V", false));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxStack = 0;
        method.maxLocals = 0;
        classNode.methods.add(method);

        return new L1Class(classNode).findMethod("run", "()V");
    }
}
