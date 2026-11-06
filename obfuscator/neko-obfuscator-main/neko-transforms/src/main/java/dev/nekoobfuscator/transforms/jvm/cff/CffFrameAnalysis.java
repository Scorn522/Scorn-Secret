package dev.nekoobfuscator.transforms.jvm.cff;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

final class CffFrameAnalysis {
    private final MethodNode method;
    private final Frame<BasicValue>[] frames;
    private final Map<AbstractInsnNode, Integer> instructionIndex;

    private CffFrameAnalysis(
        MethodNode method,
        Frame<BasicValue>[] frames,
        Map<AbstractInsnNode, Integer> instructionIndex
    ) {
        this.method = method;
        this.frames = frames;
        this.instructionIndex = instructionIndex;
    }

    static CffFrameAnalysis analyze(String owner, MethodNode method) {
        try {
            Analyzer<BasicValue> analyzer = new Analyzer<>(new TypeTrackingInterpreter());
            Frame<BasicValue>[] frames = analyzer.analyze(owner, method);
            Map<AbstractInsnNode, Integer> index = new IdentityHashMap<>();
            AbstractInsnNode[] insns = method.instructions.toArray();
            for (int i = 0; i < insns.length; i++) {
                index.put(insns[i], i);
            }
            return new CffFrameAnalysis(method, frames, index);
        } catch (Exception e) {
            throw new IllegalStateException(
                "Cannot analyze verifier frames for " + owner + "." + method.name + method.desc,
                e
            );
        }
    }

    Set<LabelNode> zeroStackLabels() {
        Set<LabelNode> labels = new HashSet<>();
        for (
            AbstractInsnNode insn = method.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn instanceof LabelNode label && isZeroStack(label)) {
                labels.add(label);
            }
        }
        return labels;
    }

    boolean isZeroStack(AbstractInsnNode insn) {
        Frame<BasicValue> frame = frameAt(insn);
        return frame != null && frame.getStackSize() == 0;
    }

    List<BasicValue> stackValues(AbstractInsnNode insn) {
        Frame<BasicValue> frame = frameAt(insn);
        if (frame == null) {
            throw new IllegalStateException("CFF control target has no frame");
        }
        List<BasicValue> values = new ArrayList<>();
        for (int i = 0; i < frame.getStackSize(); i++) {
            values.add(frame.getStack(i));
        }
        return values;
    }

    List<BasicValue> localValues(LabelNode label) {
        Frame<BasicValue> frame = frameAt(label);
        if (frame == null) {
            throw new IllegalStateException(missingFrameMessage(label));
        }
        List<BasicValue> values = new ArrayList<>();
        for (int i = 0; i < frame.getLocals(); i++) {
            values.add(frame.getLocal(i));
        }
        return values;
    }

    String localDescriptor(AbstractInsnNode insn, int local) {
        Frame<BasicValue> frame = frameAt(insn);
        if (frame == null || local < 0 || local >= frame.getLocals()) {
            return null;
        }
        return valueDescriptor(frame.getLocal(local));
    }

    String localsSignature(LabelNode label) {
        Frame<BasicValue> frame = frameAt(label);
        if (frame == null) {
            throw new IllegalStateException(missingFrameMessage(label));
        }
        StringBuilder sb = new StringBuilder(frame.getLocals() * 3);
        for (int i = 0; i < frame.getLocals(); i++) {
            BasicValue value = frame.getLocal(i);
            if (value == null || value == BasicValue.UNINITIALIZED_VALUE) {
                sb.append('.');
            } else if (value == BasicValue.REFERENCE_VALUE) {
                sb.append("R#").append(i).append('@')
                    .append(System.identityHashCode(label));
            } else if (value.getType() == null) {
                sb.append(value);
            } else {
                sb.append(value.getType().getDescriptor());
            }
            sb.append(';');
        }
        return sb.toString();
    }

    private String valueDescriptor(BasicValue value) {
        if (value == null || value == BasicValue.UNINITIALIZED_VALUE) {
            return ".";
        }
        if (value == BasicValue.REFERENCE_VALUE) {
            return "Ljava/lang/Object;";
        }
        Type type = value.getType();
        return type == null ? String.valueOf(value) : type.getDescriptor();
    }

    private Frame<BasicValue> frameAt(AbstractInsnNode insn) {
        if (insn == null) return null;
        Integer index = instructionIndex.get(insn);
        if (index != null && index >= 0 && index < frames.length && frames[index] != null) {
            return frames[index];
        }
        if (insn instanceof LabelNode) {
            AbstractInsnNode real = nextReal(insn.getNext());
            index = real == null ? null : instructionIndex.get(real);
            if (index != null && index >= 0 && index < frames.length) {
                return frames[index];
            }
        }
        return null;
    }

    private String missingFrameMessage(LabelNode label) {
        AbstractInsnNode next = nextReal(label.getNext());
        AbstractInsnNode prev = previousReal(label.getPrevious());
        return "CFF island target has no frame: method=" + method.name + method.desc +
            " label=" + label.getLabel() +
            " prev=" + describe(prev) +
            " next=" + describe(next);
    }

    private static String describe(AbstractInsnNode insn) {
        if (insn == null) return "<none>";
        if (insn instanceof MethodInsnNode call) {
            return call.getOpcode() + ":" + call.owner + "." + call.name + call.desc;
        }
        if (insn instanceof TypeInsnNode type) {
            return type.getOpcode() + ":" + type.desc;
        }
        if (insn instanceof FieldInsnNode field) {
            return field.getOpcode() + ":" + field.owner + "." + field.name + field.desc;
        }
        if (insn instanceof IntInsnNode integer) {
            return integer.getOpcode() + ":" + integer.operand;
        }
        if (insn instanceof LdcInsnNode ldc) {
            return insn.getOpcode() + ":" + ldc.cst;
        }
        return String.valueOf(insn.getOpcode());
    }

    private static AbstractInsnNode nextReal(AbstractInsnNode start) {
        for (
            AbstractInsnNode insn = start;
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn.getOpcode() >= 0) return insn;
        }
        return null;
    }

    private static AbstractInsnNode previousReal(AbstractInsnNode start) {
        for (
            AbstractInsnNode insn = start;
            insn != null;
            insn = insn.getPrevious()
        ) {
            if (insn.getOpcode() >= 0) return insn;
        }
        return null;
    }

    private static final class TypeTrackingInterpreter extends BasicInterpreter {
        TypeTrackingInterpreter() {
            super(Opcodes.ASM9);
        }

        @Override
        public BasicValue newValue(Type type) {
            if (type == null) return BasicValue.UNINITIALIZED_VALUE;
            return switch (type.getSort()) {
                case Type.VOID -> null;
                case Type.BOOLEAN,
                    Type.CHAR,
                    Type.BYTE,
                    Type.SHORT,
                    Type.INT -> BasicValue.INT_VALUE;
                case Type.FLOAT -> BasicValue.FLOAT_VALUE;
                case Type.LONG -> BasicValue.LONG_VALUE;
                case Type.DOUBLE -> BasicValue.DOUBLE_VALUE;
                case Type.ARRAY, Type.OBJECT -> new BasicValue(type);
                default -> BasicValue.UNINITIALIZED_VALUE;
            };
        }

        @Override
        public BasicValue newOperation(AbstractInsnNode insn) throws AnalyzerException {
            int opcode = insn.getOpcode();

            if (opcode == Opcodes.NEW) {
                return newValue(Type.getObjectType(((TypeInsnNode) insn).desc));
            }
            if (opcode == Opcodes.GETSTATIC) {
                return newValue(Type.getType(((FieldInsnNode) insn).desc));
            }
            if (opcode == Opcodes.LDC && insn instanceof LdcInsnNode ldc) {
                Object cst = ldc.cst;
                if (cst instanceof Type type) {
                    int sort = type.getSort();
                    if (sort == Type.OBJECT || sort == Type.ARRAY) {
                        return BasicValue.REFERENCE_VALUE;
                    }
                    if (sort == Type.METHOD) {
                        return BasicValue.REFERENCE_VALUE;
                    }
                } else if (cst instanceof String) {
                    return newValue(Type.getType(String.class));
                }
            }
            return super.newOperation(insn);
        }

        @Override
        public BasicValue unaryOperation(
            AbstractInsnNode insn,
            BasicValue value
        ) throws AnalyzerException {
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.CHECKCAST) {
                String desc = ((TypeInsnNode) insn).desc;
                return newValue(
                    desc.startsWith("[")
                        ? Type.getType(desc)
                        : Type.getObjectType(desc)
                );
            }
            if (opcode == Opcodes.ANEWARRAY) {
                String desc = ((TypeInsnNode) insn).desc;
                Type element = desc.startsWith("[")
                    ? Type.getType(desc)
                    : Type.getObjectType(desc);
                return newValue(Type.getType("[" + element.getDescriptor()));
            }
            if (opcode == Opcodes.NEWARRAY && insn instanceof IntInsnNode array) {
                return newValue(primitiveArrayType(array.operand));
            }
            if (opcode == Opcodes.GETFIELD) {
                return newValue(Type.getType(((FieldInsnNode) insn).desc));
            }
            return super.unaryOperation(insn, value);
        }

        @Override
        public BasicValue naryOperation(
            AbstractInsnNode insn,
            List<? extends BasicValue> values
        ) throws AnalyzerException {
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.MULTIANEWARRAY) {
                return newValue(Type.getType(((MultiANewArrayInsnNode) insn).desc));
            }
            if (insn instanceof MethodInsnNode method) {
                return newValue(Type.getReturnType(method.desc));
            }
            if (insn instanceof InvokeDynamicInsnNode indy) {
                return newValue(Type.getReturnType(indy.desc));
            }
            return super.naryOperation(insn, values);
        }

        @Override
        public BasicValue merge(BasicValue left, BasicValue right) {
            if (left.equals(right)) return left;
            Type leftType = left.getType();
            Type rightType = right.getType();
            if (isReference(leftType) && isReference(rightType)) {
                return BasicValue.REFERENCE_VALUE;
            }
            return super.merge(left, right);
        }

        private boolean isReference(Type type) {
            return type != null &&
                (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY);
        }

        private Type primitiveArrayType(int operand) {
            return switch (operand) {
                case Opcodes.T_BOOLEAN -> Type.getType("[Z");
                case Opcodes.T_CHAR -> Type.getType("[C");
                case Opcodes.T_FLOAT -> Type.getType("[F");
                case Opcodes.T_DOUBLE -> Type.getType("[D");
                case Opcodes.T_BYTE -> Type.getType("[B");
                case Opcodes.T_SHORT -> Type.getType("[S");
                case Opcodes.T_INT -> Type.getType("[I");
                case Opcodes.T_LONG -> Type.getType("[J");
                default -> Type.getType("[Ljava/lang/Object;");
            };
        }
    }
}
