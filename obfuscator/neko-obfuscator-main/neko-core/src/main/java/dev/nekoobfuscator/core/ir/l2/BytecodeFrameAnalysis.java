package dev.nekoobfuscator.core.ir.l2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

/**
 * Verifier-frame view over an ASM method.
 *
 * <p>This is shared L2 analysis material: transforms can ask whether an
 * instruction is a zero-stack split point, or derive a local-frame signature,
 * without owning ASM analyzer plumbing themselves.</p>
 */
public final class BytecodeFrameAnalysis {
    private final MethodNode method;
    private final Frame<BasicValue>[] basicFrames;
    private final Frame<SourceValue>[] sourceFrames;
    private final Map<AbstractInsnNode, Integer> instructionIndex;

    private BytecodeFrameAnalysis(
        MethodNode method,
        Frame<BasicValue>[] basicFrames,
        Frame<SourceValue>[] sourceFrames,
        Map<AbstractInsnNode, Integer> instructionIndex
    ) {
        this.method = method;
        this.basicFrames = basicFrames;
        this.sourceFrames = sourceFrames;
        this.instructionIndex = instructionIndex;
    }

    public static BytecodeFrameAnalysis analyze(String owner, MethodNode method) {
        try {
            Analyzer<BasicValue> basicAnalyzer = new Analyzer<>(
                new BasicInterpreter()
            );
            Analyzer<SourceValue> analyzer = new Analyzer<>(
                new SourceInterpreter()
            );
            Frame<BasicValue>[] basicFrames = basicAnalyzer.analyze(
                owner,
                method
            );
            Frame<SourceValue>[] sourceFrames = analyzer.analyze(owner, method);
            return new BytecodeFrameAnalysis(
                method,
                basicFrames,
                sourceFrames,
                buildInstructionIndex(method)
            );
        } catch (Exception e) {
            throw new IllegalStateException(
                "Cannot analyze verifier frames for " +
                    owner +
                    "." +
                    method.name +
                    method.desc,
                e
            );
        }
    }

    public Frame<SourceValue>[] frames() {
        return sourceFrames;
    }

    public Map<AbstractInsnNode, Integer> instructionIndex() {
        return instructionIndex;
    }

    public Set<LabelNode> zeroStackLabels() {
        Set<LabelNode> labels = new HashSet<>();
        for (
            AbstractInsnNode insn = method.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn instanceof LabelNode label && isZeroStack(insn)) {
                labels.add(label);
            }
        }
        return labels;
    }

    public boolean isZeroStack(AbstractInsnNode insn) {
        Integer index = frameIndex(insn);
        return (
            index != null &&
            sourceFrames[index] != null &&
            sourceFrames[index].getStackSize() == 0
        );
    }

    public List<BasicValue> stackValues(AbstractInsnNode insn) {
        Integer index = frameIndex(insn);
        if (index == null) {
            return List.of();
        }
        Frame<BasicValue> frame = basicFrames[index];
        if (frame == null || frame.getStackSize() == 0) {
            return List.of();
        }
        List<BasicValue> values = new ArrayList<>(frame.getStackSize());
        for (int i = 0; i < frame.getStackSize(); i++) {
            values.add(frame.getStack(i));
        }
        return values;
    }

    public String localsSignature(LabelNode label) {
        Integer index = frameIndex(label);
        if (index == null) {
            throw new IllegalStateException(
                "No verifier frame for label: " + label.getLabel()
            );
        }
        Frame<BasicValue> basicFrame = basicFrames[index];
        Frame<SourceValue> sourceFrame = sourceFrames[index];
        StringBuilder sb = new StringBuilder(sourceFrame.getLocals() * 6);
        for (int i = 0; i < sourceFrame.getLocals(); i++) {
            BasicValue basic = i < basicFrame.getLocals()
                ? basicFrame.getLocal(i)
                : BasicValue.UNINITIALIZED_VALUE;
            SourceValue value = sourceFrame.getLocal(i);
            if (basic == null || basic == BasicValue.UNINITIALIZED_VALUE) {
                sb.append('.');
            } else {
                appendBasicValue(sb, basic);
            }
            sb.append(':');
            if (value == null) {
                sb.append("S0@").append(i);
            } else if (value.insns.isEmpty()) {
                sb.append('S').append(value.getSize()).append('@').append(i);
            } else {
                sb.append('S').append(value.getSize()).append('[');
                List<Integer> sources = new ArrayList<>(value.insns.size());
                for (AbstractInsnNode source : value.insns) {
                    Integer sourceIndex = instructionIndex.get(source);
                    sources.add(sourceIndex == null ? -1 : sourceIndex);
                }
                Collections.sort(sources);
                for (int j = 0; j < sources.size(); j++) {
                    if (j > 0) sb.append(',');
                    sb.append(sources.get(j));
                }
                sb.append(']');
            }
            sb.append(';');
        }
        return sb.toString();
    }

    private static void appendBasicValue(StringBuilder sb, BasicValue value) {
        if (value.getType() == null) {
            sb.append(value);
        } else {
            sb.append(value.getType().getDescriptor());
        }
    }

    public Integer frameIndex(LabelNode label) {
        return frameIndex((AbstractInsnNode) label);
    }

    public Integer frameIndex(AbstractInsnNode insn) {
        if (insn == null) {
            return null;
        }
        Integer index = instructionIndex.get(insn);
        if (index != null && sourceFrames[index] != null) {
            return index;
        }
        AbstractInsnNode real = nextReal(insn.getNext());
        index = real == null ? null : instructionIndex.get(real);
        if (index != null && sourceFrames[index] != null) {
            return index;
        }
        return null;
    }

    private static Map<AbstractInsnNode, Integer> buildInstructionIndex(
        MethodNode method
    ) {
        AbstractInsnNode[] insns = method.instructions.toArray();
        Map<AbstractInsnNode, Integer> index = new IdentityHashMap<>();
        for (int i = 0; i < insns.length; i++) {
            index.put(insns[i], i);
        }
        return index;
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
}
