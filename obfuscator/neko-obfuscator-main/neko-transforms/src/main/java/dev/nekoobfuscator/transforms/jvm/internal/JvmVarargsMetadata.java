package dev.nekoobfuscator.transforms.jvm.internal;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.MethodNode;

public final class JvmVarargsMetadata {
    private JvmVarargsMetadata() {
    }

    public static void normalizeAfterDescriptorRewrite(MethodNode method) {
        if (method == null || (method.access & Opcodes.ACC_VARARGS) == 0) return;
        Type[] args = Type.getArgumentTypes(method.desc);
        if (args.length == 0 || args[args.length - 1].getSort() != Type.ARRAY) {
            method.access &= ~Opcodes.ACC_VARARGS;
        }
    }
}
