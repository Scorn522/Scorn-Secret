package dev.nekoobfuscator.transforms.jvm.invoke;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.jar.ClassHierarchy;
import dev.nekoobfuscator.core.pipeline.GeneratedHelperTargetMap;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import java.util.LinkedHashMap;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodNode;

final class JvmInvokeDynamicPayloadReconciliationTest {
    @Test
    void rewritesEncryptedGeneratedHelperPayloadToFinalComposedTarget() {
        PipelineContext ctx = context();
        long decodeSeed = 0x1234_5678_9ABC_DEF0L;
        long token = 0xCAFEBABE12345678L;
        long flow = 0x0F0E0D0C0B0A0908L;
        long resolverDescriptor = 0x7766_5544_3322_1100L;
        String oldPayload = JvmInvokeDynamicObfuscationPass.encryptedPayload(
            6,
            "pkg/Owner",
            "__neko_generated$0",
            "(IIJ)I",
            decodeSeed,
            token,
            flow,
            resolverDescriptor
        );
        InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(
            "dyn",
            "(IIJJJ)I",
            new Handle(
                Opcodes.H_INVOKESTATIC,
                "pkg/Owner",
                "__neko_indy_bsm",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;ILjava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;",
                false
            ),
            oldPayload,
            7,
            new Handle(Opcodes.H_GETSTATIC, "pkg/Owner", "carrier", "[Ljava/lang/Object;", false)
        );
        JvmInvokeDynamicObfuscationPass.recordPayloadSite(
            ctx,
            indy,
            6,
            "pkg/Owner",
            "__neko_generated$0",
            "(IIJ)I",
            decodeSeed,
            token,
            flow,
            resolverDescriptor
        );
        GeneratedHelperTargetMap.recordMethodRemap(
            ctx,
            "pkg/Owner",
            "__neko_generated$0",
            "(IIJ)I",
            "pkg/Owner",
            "qa",
            "(IIJ)I"
        );
        GeneratedHelperTargetMap.recordMethodRemap(
            ctx,
            "pkg/Owner",
            "qa",
            "(IIJ)I",
            "pkg/Relocated",
            "qa",
            "(IIJ)I"
        );
        L1Class owner = classWithIndy(indy);

        int rewritten = JvmInvokeDynamicObfuscationPass.reconcileGeneratedHelperPayloads(ctx, List.of(owner));

        String expected = JvmInvokeDynamicObfuscationPass.encryptedPayload(
            6,
            "pkg/Relocated",
            "qa",
            "(IIJ)I",
            decodeSeed,
            token,
            flow,
            resolverDescriptor
        );
        assertEquals(1, rewritten);
        assertEquals(expected, indy.bsmArgs[0]);
        assertNotEquals(oldPayload, indy.bsmArgs[0]);
    }

    private static L1Class classWithIndy(InvokeDynamicInsnNode indy) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V17;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = "pkg/Owner";
        node.superName = "java/lang/Object";
        MethodNode method = new MethodNode(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "entry",
            "()V",
            null,
            null
        );
        method.instructions.add(indy);
        method.instructions.add(new InsnNode(Opcodes.POP));
        method.instructions.add(new InsnNode(Opcodes.RETURN));
        method.maxLocals = 0;
        method.maxStack = 8;
        node.methods.add(method);
        return new L1Class(node);
    }

    private static PipelineContext context() {
        return new PipelineContext(
            new ObfuscationConfig(),
            new ClassHierarchy(),
            new LinkedHashMap<String, L1Class>()
        );
    }
}
