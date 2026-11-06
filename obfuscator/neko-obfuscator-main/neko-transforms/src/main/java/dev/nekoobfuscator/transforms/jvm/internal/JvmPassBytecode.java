package dev.nekoobfuscator.transforms.jvm.internal;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

public final class JvmPassBytecode {
    private JvmPassBytecode() {}

    public static void pushInt(InsnList insns, int value) {
        if (value >= -1 && value <= 5) {
            insns.add(new InsnNode(Opcodes.ICONST_0 + value));
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            insns.add(new IntInsnNode(Opcodes.BIPUSH, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            insns.add(new IntInsnNode(Opcodes.SIPUSH, value));
        } else {
            insns.add(new LdcInsnNode(value));
        }
    }

    public static void pushLong(InsnList insns, long value) {
        if (value == 0L) {
            insns.add(new InsnNode(Opcodes.LCONST_0));
        } else if (value == 1L) {
            insns.add(new InsnNode(Opcodes.LCONST_1));
        } else {
            insns.add(new LdcInsnNode(value));
        }
    }

    public static void pushDerivedIntMaterial(
        InsnList insns,
        int liveIntLocal,
        long siteSeed,
        long domain
    ) {
        long seed = mix(siteSeed, domain);
        insns.add(new VarInsnNode(Opcodes.ILOAD, liveIntLocal));
        pushInt(insns, nonZeroInt(mix(seed, 0x4E4D4154494E5431L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        pushInt(insns, derivedShift(seed, 7));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        pushInt(insns, nonZeroInt(mix(seed, 0x4E4D4154494E5432L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        pushInt(insns, derivedShift(seed, 19));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        pushInt(insns, nonZeroInt(mix(seed, 0x4E4D4154494E5433L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    public static void pushDerivedLongMaterial(
        InsnList insns,
        int liveIntLocal,
        long siteSeed,
        long domain
    ) {
        pushDerivedIntMaterial(insns, liveIntLocal, siteSeed, domain ^ 0x4E4D41544C4F4831L);
        insns.add(new InsnNode(Opcodes.I2L));
        pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        pushDerivedIntMaterial(insns, liveIntLocal, siteSeed, domain ^ 0x4E4D41544C4F4C31L);
        insns.add(new InsnNode(Opcodes.I2L));
        pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    public static long mix(long state, long value) {
        long z = state + value + 0x9E3779B97F4A7C15L;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    private static int derivedShift(long seed, int base) {
        return 1 + (int) ((seed >>> base) & 30L);
    }

    private static int nonZeroInt(long value) {
        int v = (int) value;
        return v == 0 ? 0x4E4D4154 : v;
    }
}
