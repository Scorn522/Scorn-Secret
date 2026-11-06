package dev.nekoobfuscator.transforms.jvm.cff;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Verifier-sensitive CFF helpers.
 *
 * <p>This class owns exception-handler bridge discovery and protected range
 * rebuilding so the main pass does not mix dispatcher rewriting with JVM
 * verifier range invariants.</p>
 */
final class ControlFlowFlatteningVerify {
    private ControlFlowFlatteningVerify() {}

    static List<ProtectedTryCatch> captureProtectedTryCatches(MethodNode mn) {
        if (mn.tryCatchBlocks == null || mn.tryCatchBlocks.isEmpty()) {
            return Collections.emptyList();
        }
        List<ProtectedTryCatch> protectedRanges = new ArrayList<>();
        for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
            Set<AbstractInsnNode> protectedInsns = Collections.newSetFromMap(
                new IdentityHashMap<>()
            );
            for (
                AbstractInsnNode insn = tcb.start;
                insn != null && insn != tcb.end;
                insn = insn.getNext()
            ) {
                if (insn.getOpcode() >= 0) protectedInsns.add(insn);
            }
            protectedRanges.add(new ProtectedTryCatch(tcb, protectedInsns));
        }
        return protectedRanges;
    }

    static void rebuildProtectedTryCatches(
        MethodNode mn,
        List<ProtectedTryCatch> protectedTryCatches
    ) {
        if (protectedTryCatches.isEmpty()) return;
        List<TryCatchBlockNode> rebuilt = new ArrayList<>();
        for (ProtectedTryCatch protectedTryCatch : protectedTryCatches) {
            AbstractInsnNode runStart = null;
            AbstractInsnNode runEnd = null;
            for (
                AbstractInsnNode insn = mn.instructions.getFirst();
                insn != null;
                insn = insn.getNext()
            ) {
                if (insn.getOpcode() < 0) continue;
                if (protectedTryCatch.instructions().contains(insn)) {
                    if (runStart == null) runStart = insn;
                    runEnd = insn;
                } else if (runStart != null) {
                    rebuilt.add(
                        copyTryCatchSegment(
                            mn,
                            protectedTryCatch.node(),
                            runStart,
                            runEnd
                        )
                    );
                    runStart = null;
                    runEnd = null;
                }
            }
            if (runStart != null) {
                rebuilt.add(
                    copyTryCatchSegment(
                        mn,
                        protectedTryCatch.node(),
                        runStart,
                        runEnd
                    )
                );
            }
        }
        mn.tryCatchBlocks = rebuilt;
    }

    static List<HandlerBridge> splitExceptionHandlers(MethodNode mn) {
        List<HandlerBridge> bridges = new ArrayList<>();
        Set<LabelNode> seen = new HashSet<>();
        if (mn.tryCatchBlocks == null) return bridges;
        for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
            if (!seen.add(tcb.handler)) continue;
            AbstractInsnNode catchStart = nextReal(tcb.handler.getNext());
            if (catchStart == null) continue;
            int catchLocal = -1;
            AbstractInsnNode bodyStart;
            if (
                catchStart instanceof VarInsnNode store &&
                store.getOpcode() == Opcodes.ASTORE
            ) {
                catchLocal = store.var;
                bodyStart = nextReal(catchStart.getNext());
            } else if (catchStart.getOpcode() == Opcodes.POP) {
                bodyStart = nextReal(catchStart.getNext());
            } else {
                throw new IllegalStateException(
                    "CFF exception handler must begin by consuming the exception"
                );
            }
            if (bodyStart == null) continue;
            bridges.add(
                new HandlerBridge(
                    tcb.handler,
                    ensureLabelBefore(mn, bodyStart),
                    catchLocal
                )
            );
        }
        return bridges;
    }

    static Set<LabelNode> handlerBodyLabels(List<HandlerBridge> bridges) {
        Set<LabelNode> labels = new HashSet<>();
        for (HandlerBridge bridge : bridges) {
            labels.add(bridge.body());
        }
        return labels;
    }

    private static TryCatchBlockNode copyTryCatchSegment(
        MethodNode mn,
        TryCatchBlockNode original,
        AbstractInsnNode startInsn,
        AbstractInsnNode endInsn
    ) {
        TryCatchBlockNode segment = new TryCatchBlockNode(
            ensureLabelBefore(mn, startInsn),
            ensureLabelAfter(mn, endInsn),
            original.handler,
            original.type
        );
        segment.visibleTypeAnnotations = original.visibleTypeAnnotations;
        segment.invisibleTypeAnnotations = original.invisibleTypeAnnotations;
        return segment;
    }

    private static LabelNode ensureLabelBefore(
        MethodNode mn,
        AbstractInsnNode node
    ) {
        for (
            AbstractInsnNode previous = node.getPrevious();
            previous != null && previous.getOpcode() < 0;
            previous = previous.getPrevious()
        ) {
            if (previous instanceof LabelNode label) return label;
        }
        LabelNode label = new LabelNode();
        mn.instructions.insertBefore(node, label);
        return label;
    }

    private static LabelNode ensureLabelAfter(
        MethodNode mn,
        AbstractInsnNode node
    ) {
        AbstractInsnNode next = node.getNext();
        if (next instanceof LabelNode label) return label;
        LabelNode label = new LabelNode();
        mn.instructions.insert(node, label);
        return label;
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

    record HandlerBridge(LabelNode handler, LabelNode body, int catchLocal) {}

    record ProtectedTryCatch(
        TryCatchBlockNode node,
        Set<AbstractInsnNode> instructions
    ) {}
}
