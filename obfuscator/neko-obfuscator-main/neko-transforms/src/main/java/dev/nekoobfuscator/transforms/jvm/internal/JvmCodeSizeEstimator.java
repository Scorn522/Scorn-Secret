package dev.nekoobfuscator.transforms.jvm.internal;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

public final class JvmCodeSizeEstimator {
    private JvmCodeSizeEstimator() {
    }

    public static int estimateMethodBytes(MethodNode method) {
        if (method == null || method.instructions == null) return 0;
        return estimateInsnListBytes(method.instructions);
    }

    public static int estimateInsnListBytes(InsnList instructions) {
        if (instructions == null) return 0;
        int offset = 0;
        for (AbstractInsnNode insn = instructions.getFirst(); insn != null; insn = insn.getNext()) {
            offset += estimateInstructionBytes(insn, offset);
        }
        return offset;
    }

    private static int estimateInstructionBytes(AbstractInsnNode insn, int offset) {
        int opcode = insn.getOpcode();
        if (opcode < 0) return 0;
        if (insn instanceof VarInsnNode var) {
            return var.var > 255 ? 4 : 2;
        }
        if (insn instanceof IincInsnNode iinc) {
            return iinc.var > 255 || iinc.incr < Byte.MIN_VALUE || iinc.incr > Byte.MAX_VALUE ? 6 : 3;
        }
        if (insn instanceof IntInsnNode) {
            return opcode == Opcodes.SIPUSH ? 3 : 2;
        }
        if (insn instanceof LdcInsnNode) {
            return 3;
        }
        if (insn instanceof JumpInsnNode) {
            return opcode == 200 || opcode == 201 ? 5 : 3;
        }
        if (insn instanceof MethodInsnNode) {
            return opcode == Opcodes.INVOKEINTERFACE ? 5 : 3;
        }
        if (insn instanceof InvokeDynamicInsnNode) {
            return 5;
        }
        if (insn instanceof TypeInsnNode) {
            return 3;
        }
        if (insn instanceof MultiANewArrayInsnNode) {
            return 4;
        }
        if (insn instanceof TableSwitchInsnNode ts) {
            int padding = switchPadding(offset);
            return 1 + padding + 12 + ts.labels.size() * 4;
        }
        if (insn instanceof LookupSwitchInsnNode ls) {
            int padding = switchPadding(offset);
            return 1 + padding + 8 + ls.labels.size() * 8;
        }
        if (insn instanceof LabelNode) {
            return 0;
        }
        return switch (opcode) {
            case Opcodes.GETSTATIC, Opcodes.PUTSTATIC, Opcodes.GETFIELD, Opcodes.PUTFIELD,
                Opcodes.NEW, Opcodes.ANEWARRAY, Opcodes.CHECKCAST, Opcodes.INSTANCEOF -> 3;
            case Opcodes.NEWARRAY, Opcodes.BIPUSH -> 2;
            default -> 1;
        };
    }

    private static int switchPadding(int offset) {
        return (4 - ((offset + 1) & 3)) & 3;
    }
}
