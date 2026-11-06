package dev.nekoobfuscator.core.jar;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.BasicVerifier;
import org.objectweb.asm.util.CheckClassAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.*;

/**
 * Writes L1 IR classes and resource entries back to a JAR file.
 */
public final class JarOutput {
    private static final Logger log = LoggerFactory.getLogger(JarOutput.class);

    private final ClassHierarchy hierarchy;

    public JarOutput(ClassHierarchy hierarchy) {
        this.hierarchy = hierarchy;
    }

    public void write(Path outputPath, List<L1Class> classes, List<ResourceEntry> resources,
                      Manifest manifest) throws IOException {
        write(outputPath.toFile(), classes, resources, manifest);
    }

    public void write(File outputFile, List<L1Class> classes, List<ResourceEntry> resources,
                      Manifest manifest) throws IOException {
        try (JarOutputStream jos = manifest != null
                ? new JarOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)), manifest)
                : new JarOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)))) {

            Set<String> written = new HashSet<>();

            for (L1Class l1 : classes) {
                String entryName = l1.asmNode().name + ".class";
                if (written.add(entryName)) {
                    byte[] bytecode = writeClass(l1);
                    JarEntry je = new JarEntry(entryName);
                    jos.putNextEntry(je);
                    jos.write(bytecode);
                    jos.closeEntry();
                    log.debug("Wrote class: {}", l1.name());
                }
            }

            for (ResourceEntry re : resources) {
                if (re.name().equals("META-INF/MANIFEST.MF")) continue;
                if (written.add(re.name())) {
                    JarEntry je = new JarEntry(re.name());
                    jos.putNextEntry(je);
                    jos.write(re.data());
                    jos.closeEntry();
                    log.debug("Wrote resource: {}", re.name());
                }
            }
        }
        log.info("Wrote {} classes and {} resources to {}", classes.size(), resources.size(), outputFile);
    }

    public static byte[] previewClassBytes(ClassHierarchy hierarchy, L1Class l1) {
        stripExistingFramesForWrite(l1);
        JarOutput diagnostics = new JarOutput(hierarchy);
        int repairedLocals = diagnostics.repairLoadedLocalDefaults(l1);
        if (repairedLocals > 0) {
            log.debug("Initialized {} verifier-local defaults in preview {}", repairedLocals, l1.name());
        }
        try {
            HierarchyClassWriter cw = new HierarchyClassWriter(hierarchy);
            l1.asmNode().accept(cw);
            return cw.toByteArray();
        } catch (Throwable e) {
            String methodDetails = diagnostics.diagnoseMethods(l1);
            if (!methodDetails.isBlank()) {
                log.error("Preview method diagnostics for {}:{}{}", l1.name(), System.lineSeparator(), methodDetails);
            }
            throw e;
        }
    }

    private byte[] writeClass(L1Class l1) {
        try {
            stripExistingFrames(l1);
            int repairedLocals = repairLoadedLocalDefaults(l1);
            if (repairedLocals > 0) {
                log.debug("Initialized {} verifier-local defaults in {}", repairedLocals, l1.name());
            }
            HierarchyClassWriter cw = new HierarchyClassWriter(hierarchy);
            l1.asmNode().accept(cw);
            byte[] bytecode = cw.toByteArray();
            bytecode = normalizeWrittenStackFrames(bytecode);
            validateWrittenClass(l1, bytecode);
            return bytecode;
        } catch (Throwable e) {
            log.error("Class write failure for {}", l1.name(), e);
            String verifierDetails = diagnoseFrameFailure(l1);
            if (!verifierDetails.isBlank()) {
                log.error("Verifier details for {}:{}{}", l1.name(), System.lineSeparator(), verifierDetails);
            }
            String methodDetails = diagnoseMethods(l1);
            if (!methodDetails.isBlank()) {
                log.error("Method frame details for {}:{}{}", l1.name(), System.lineSeparator(), methodDetails);
            }
            String sizeDetails = methodSizeSummary(l1);
            if (!sizeDetails.isBlank()) {
                log.error("Largest methods for {}:{}{}", l1.name(), System.lineSeparator(), sizeDetails);
            }
            throw new RuntimeException("Cannot write verifiable class " + l1.name()
                + " with COMPUTE_FRAMES; refusing COMPUTE_MAXS/-noverify fallback. Largest methods:"
                + System.lineSeparator() + sizeDetails, e);
        }
    }

    private String methodSizeSummary(L1Class l1) {
        List<MethodSize> sizes = new ArrayList<>();
        for (MethodNode method : l1.asmNode().methods) {
            if (method.instructions == null || method.instructions.size() == 0) continue;
            sizes.add(new MethodSize(method.name, method.desc, estimateMethodBytes(method)));
        }
        sizes.sort(Comparator.comparingInt(MethodSize::bytes).reversed());
        StringBuilder out = new StringBuilder();
        int limit = Math.min(8, sizes.size());
        for (int i = 0; i < limit; i++) {
            MethodSize size = sizes.get(i);
            out.append("  ")
                .append(size.bytes())
                .append(" bytes estimated  ")
                .append(size.name())
                .append(size.desc())
                .append(System.lineSeparator());
        }
        return out.toString().trim();
    }

    private String diagnoseMethods(L1Class l1) {
        StringBuilder out = new StringBuilder();
        for (MethodNode method : l1.asmNode().methods) {
            if (method.instructions == null || method.instructions.size() == 0) continue;
            try {
                Analyzer<BasicValue> analyzer = new Analyzer<>(new BasicVerifier());
                analyzer.analyze(l1.name(), method);
            } catch (Throwable t) {
                out.append("  analyzer ")
                    .append(method.name)
                    .append(method.desc)
                    .append(": ")
                    .append(t.getClass().getSimpleName())
                    .append(": ")
                    .append(t.getMessage())
                    .append(System.lineSeparator());
                if (t instanceof AnalyzerException analyzerException) {
                    appendInstructionWindow(out, method, analyzerException.node);
                    appendFailingLocalAccesses(out, method, analyzerException.node);
                }
            }
            try {
                ClassWriter cw = new HierarchyClassWriter(hierarchy);
                cw.visit(
                    l1.asmNode().version,
                    l1.asmNode().access,
                    l1.asmNode().name,
                    l1.asmNode().signature,
                    l1.asmNode().superName,
                    l1.asmNode().interfaces == null
                        ? null
                        : l1.asmNode().interfaces.toArray(String[]::new)
                );
                method.accept(cw);
                cw.visitEnd();
                cw.toByteArray();
            } catch (Throwable t) {
                out.append("  writer ")
                    .append(method.name)
                    .append(method.desc)
                    .append(": ")
                    .append(t.getClass().getSimpleName())
                    .append(": ")
                    .append(t.getMessage())
                    .append(System.lineSeparator());
            }
        }
        return out.toString().trim();
    }

    private void appendInstructionWindow(
        StringBuilder out,
        MethodNode method,
        AbstractInsnNode target
    ) {
        if (target == null) return;
        AbstractInsnNode[] insns = method.instructions.toArray();
        int index = -1;
        for (int i = 0; i < insns.length; i++) {
            if (insns[i] == target) {
                index = i;
                break;
            }
        }
        if (index < 0) return;
        int from = Math.max(0, index - 6);
        int to = Math.min(insns.length, index + 7);
        for (int i = from; i < to; i++) {
            out.append("    ")
                .append(i == index ? ">" : " ")
                .append(i)
                .append(": ")
                .append(insnSummary(insns[i]))
                .append(System.lineSeparator());
        }
        appendHandlerAndIncomingEvidence(out, method, target, insns);
    }

    private void appendFailingLocalAccesses(
        StringBuilder out,
        MethodNode method,
        AbstractInsnNode target
    ) {
        if (!(target instanceof VarInsnNode failingVar)) return;
        AbstractInsnNode[] insns = method.instructions.toArray();
        out.append("    failing-local-accesses local=")
            .append(failingVar.var)
            .append(" maxLocals=")
            .append(method.maxLocals)
            .append(" argLimit=")
            .append(argumentLocalLimit(method))
            .append(System.lineSeparator());
        int count = 0;
        List<AbstractInsnNode> conflictSamples = new ArrayList<>();
        for (int i = 0; i < insns.length; i++) {
            AbstractInsnNode insn = insns[i];
            if (insn instanceof VarInsnNode var && var.var == failingVar.var) {
                out.append("      ")
                    .append(i == instructionIndex(insns, target) ? ">" : " ")
                    .append(i)
                    .append(": ")
                    .append(insnSummary(insn))
                    .append(System.lineSeparator());
                if (conflictSamples.size() < 3 && var.getOpcode() != failingVar.getOpcode()) {
                    conflictSamples.add(var);
                }
                count++;
                if (count >= 80) {
                    out.append("      ... truncated").append(System.lineSeparator());
                    break;
                }
            }
        }
        for (AbstractInsnNode sample : conflictSamples) {
            out.append("    conflicting-access-window:")
                .append(System.lineSeparator());
            appendInstructionWindow(out, method, sample);
        }
    }

    private int instructionIndex(AbstractInsnNode[] insns, AbstractInsnNode target) {
        for (int i = 0; i < insns.length; i++) {
            if (insns[i] == target) return i;
        }
        return -1;
    }

    private void appendHandlerAndIncomingEvidence(
        StringBuilder out,
        MethodNode method,
        AbstractInsnNode target,
        AbstractInsnNode[] insns
    ) {
        Set<org.objectweb.asm.tree.LabelNode> labels = labelsImmediatelyBefore(target);
        if (labels.isEmpty()) return;
        out.append("    labels-before-target:");
        for (org.objectweb.asm.tree.LabelNode label : labels) {
            out.append(' ').append(labelId(label));
        }
        out.append(System.lineSeparator());
        if (method.tryCatchBlocks != null) {
            for (org.objectweb.asm.tree.TryCatchBlockNode tcb : method.tryCatchBlocks) {
                if (labels.contains(tcb.handler)) {
                    out.append("    try-catch-handler-entry: handler=")
                        .append(labelId(tcb.handler))
                        .append(" start=")
                        .append(labelId(tcb.start))
                        .append(" end=")
                        .append(labelId(tcb.end))
                        .append(" type=")
                        .append(tcb.type == null ? "any" : tcb.type)
                        .append(System.lineSeparator());
                }
                if (labels.contains(tcb.start)) {
                    out.append("    try-catch-range-start: start=")
                        .append(labelId(tcb.start))
                        .append(" end=")
                        .append(labelId(tcb.end))
                        .append(" handler=")
                        .append(labelId(tcb.handler))
                        .append(" type=")
                        .append(tcb.type == null ? "any" : tcb.type)
                        .append(System.lineSeparator());
                }
                if (labels.contains(tcb.end)) {
                    out.append("    try-catch-range-end: end=")
                        .append(labelId(tcb.end))
                        .append(" start=")
                        .append(labelId(tcb.start))
                        .append(" handler=")
                        .append(labelId(tcb.handler))
                        .append(" type=")
                        .append(tcb.type == null ? "any" : tcb.type)
                        .append(System.lineSeparator());
                }
            }
        }
        for (int i = 0; i < insns.length; i++) {
            AbstractInsnNode insn = insns[i];
            if (insn instanceof org.objectweb.asm.tree.JumpInsnNode jump && labels.contains(jump.label)) {
                out.append("    incoming-jump: ")
                    .append(i)
                    .append(": ")
                    .append(insnSummary(insn))
                    .append(System.lineSeparator());
                appendInstructionWindowAt(out, insns, i, 4, 3);
            } else if (insn instanceof org.objectweb.asm.tree.LookupSwitchInsnNode ls) {
                if (labels.contains(ls.dflt)) {
                    out.append("    incoming-lookup-default: ")
                        .append(i)
                        .append(System.lineSeparator());
                }
                for (int k = 0; k < ls.labels.size(); k++) {
                    if (labels.contains(ls.labels.get(k))) {
                        out.append("    incoming-lookup-case: ")
                            .append(i)
                            .append(" key=")
                            .append(ls.keys.get(k))
                            .append(System.lineSeparator());
                    }
                }
            } else if (insn instanceof org.objectweb.asm.tree.TableSwitchInsnNode ts) {
                if (labels.contains(ts.dflt)) {
                    out.append("    incoming-table-default: ")
                        .append(i)
                        .append(System.lineSeparator());
                }
                for (int k = 0; k < ts.labels.size(); k++) {
                    if (labels.contains(ts.labels.get(k))) {
                        out.append("    incoming-table-case: ")
                            .append(i)
                            .append(" key=")
                            .append(ts.min + k)
                            .append(System.lineSeparator());
                    }
                }
            }
        }
    }

    private void appendInstructionWindowAt(
        StringBuilder out,
        AbstractInsnNode[] insns,
        int index,
        int before,
        int after
    ) {
        int from = Math.max(0, index - before);
        int to = Math.min(insns.length, index + after + 1);
        for (int i = from; i < to; i++) {
            out.append("      ")
                .append(i == index ? ">" : " ")
                .append(i)
                .append(": ")
                .append(insnSummary(insns[i]))
                .append(System.lineSeparator());
        }
    }

    private Set<org.objectweb.asm.tree.LabelNode> labelsImmediatelyBefore(AbstractInsnNode target) {
        Set<org.objectweb.asm.tree.LabelNode> labels = Collections.newSetFromMap(new IdentityHashMap<>());
        for (
            AbstractInsnNode scan = target.getPrevious();
            scan != null && scan.getOpcode() < 0;
            scan = scan.getPrevious()
        ) {
            if (scan instanceof org.objectweb.asm.tree.LabelNode label) {
                labels.add(label);
            }
        }
        return labels;
    }

    private String labelId(org.objectweb.asm.tree.LabelNode label) {
        return "Label@" + Integer.toHexString(System.identityHashCode(label));
    }

    private String insnSummary(AbstractInsnNode insn) {
        if (insn == null) return "<null>";
        String name = opcodeName(insn.getOpcode());
        if (insn instanceof org.objectweb.asm.tree.LabelNode label) {
            return labelId(label);
        }
        if (insn instanceof org.objectweb.asm.tree.JumpInsnNode jump) {
            return name + " -> " + labelId(jump.label);
        }
        if (insn instanceof org.objectweb.asm.tree.VarInsnNode var) {
            return name + " " + var.var;
        }
        if (insn instanceof org.objectweb.asm.tree.MethodInsnNode method) {
            return name + " " + method.owner + "." + method.name + method.desc;
        }
        if (insn instanceof org.objectweb.asm.tree.FieldInsnNode field) {
            return name + " " + field.owner + "." + field.name + ":" + field.desc;
        }
        if (insn instanceof org.objectweb.asm.tree.LdcInsnNode ldc) {
            return name + " " + String.valueOf(ldc.cst);
        }
        if (insn instanceof org.objectweb.asm.tree.IntInsnNode intInsn) {
            return name + " " + intInsn.operand;
        }
        if (insn instanceof org.objectweb.asm.tree.IincInsnNode iinc) {
            return "IINC " + iinc.var + " " + iinc.incr;
        }
        if (insn instanceof org.objectweb.asm.tree.LookupSwitchInsnNode ls) {
            return "LOOKUPSWITCH keys=" + ls.keys.size();
        }
        if (insn instanceof org.objectweb.asm.tree.TableSwitchInsnNode ts) {
            return "TABLESWITCH " + ts.min + ".." + ts.max;
        }
        return name;
    }

    private String opcodeName(int opcode) {
        if (opcode < 0) return "META";
        String[] names = org.objectweb.asm.util.Printer.OPCODES;
        return opcode < names.length ? names[opcode] : "OP" + opcode;
    }

    private int repairLoadedLocalDefaults(L1Class l1) {
        int repaired = 0;
        for (MethodNode method : l1.asmNode().methods) {
            if (method.instructions == null || method.instructions.size() == 0) continue;
            repaired += repairLoadedLocalDefaults(l1.name(), method);
        }
        return repaired;
    }

    private int repairLoadedLocalDefaults(String owner, MethodNode method) {
        int repaired = 0;
        Set<Integer> repairedLocals = new HashSet<>();
        int limit = Math.max(8, method.maxLocals + 8);
        for (int pass = 0; pass < limit; pass++) {
            AnalyzerException failure = analyzeMethod(owner, method);
            if (failure == null) break;
            VarInsnNode load = verifierTopLocalLoad(failure);
            if (load == null) break;
            LocalAccessKind kind = localLoadKind(load.getOpcode());
            if (kind == null) break;
            String referenceType = null;
            if (kind == LocalAccessKind.REF) {
                referenceType = inferredReferenceLocalType(owner, method, load.var, load);
                if (referenceType == null) break;
            }
            if (load.var < argumentLocalLimit(method)) break;
            if (!isExclusiveCompatibleLocal(method, load.var, kind)) break;
            if (!repairedLocals.add(load.var)) break;
            insertLocalDefault(method, load.var, kind, referenceType);
            repaired++;
        }
        return repaired;
    }

    private AnalyzerException analyzeMethod(String owner, MethodNode method) {
        try {
            Analyzer<BasicValue> analyzer = new Analyzer<>(new BasicVerifier());
            analyzer.analyze(owner, method);
            return null;
        } catch (AnalyzerException e) {
            return e;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private VarInsnNode verifierTopLocalLoad(AnalyzerException failure) {
        if (!(failure.node instanceof VarInsnNode var)) return null;
        if (localLoadKind(var.getOpcode()) == null) return null;
        String message = failure.getMessage();
        if (message == null || !message.contains("found .")) return null;
        return var;
    }

    private boolean isExclusiveCompatibleLocal(MethodNode method, int local, LocalAccessKind kind) {
        for (AbstractInsnNode insn : method.instructions.toArray()) {
            if (!(insn instanceof VarInsnNode var)) continue;
            LocalAccessKind accessKind = localAccessKind(var.getOpcode());
            if (accessKind == null) continue;
            if (var.var == local && accessKind != kind) return false;
            if (var.var == local + 1 && kind.slots() == 2) return false;
            if (var.var + accessKind.slots() > local && var.var < local + kind.slots() && var.var != local) {
                return false;
            }
        }
        return true;
    }

    private void insertLocalDefault(MethodNode method, int local, LocalAccessKind kind, String referenceType) {
        InsnList init = new InsnList();
        switch (kind) {
            case INT -> {
                init.add(new InsnNode(Opcodes.ICONST_0));
                init.add(new VarInsnNode(Opcodes.ISTORE, local));
            }
            case LONG -> {
                init.add(new InsnNode(Opcodes.LCONST_0));
                init.add(new VarInsnNode(Opcodes.LSTORE, local));
            }
            case FLOAT -> {
                init.add(new InsnNode(Opcodes.FCONST_0));
                init.add(new VarInsnNode(Opcodes.FSTORE, local));
            }
            case DOUBLE -> {
                init.add(new InsnNode(Opcodes.DCONST_0));
                init.add(new VarInsnNode(Opcodes.DSTORE, local));
            }
            case REF -> {
                init.add(new InsnNode(Opcodes.ACONST_NULL));
                if (referenceType != null && !"java/lang/Object".equals(referenceType)) {
                    init.add(new TypeInsnNode(Opcodes.CHECKCAST, referenceType));
                }
                init.add(new VarInsnNode(Opcodes.ASTORE, local));
            }
        }
        AbstractInsnNode entry = methodEntryPoint(method);
        if (entry == null) {
            method.instructions.insert(init);
        } else {
            method.instructions.insertBefore(entry, init);
        }
        method.maxLocals = Math.max(method.maxLocals, local + kind.slots());
        method.maxStack = Math.max(method.maxStack, kind.slots());
    }

    private String inferredReferenceLocalType(String owner, MethodNode method, int local, VarInsnNode failingLoad) {
        String storedType = null;
        for (AbstractInsnNode insn : method.instructions.toArray()) {
            if (!(insn instanceof VarInsnNode var) || var.var != local || var.getOpcode() != Opcodes.ASTORE) continue;
            String stored = storedReferenceType(owner, method, var);
            if (stored == null) continue;
            storedType = mergeReferenceDefaultType(storedType, stored);
            if (storedType == null) {
                return null;
            }
        }
        if (storedType != null && !"java/lang/Object".equals(storedType)) return storedType;
        String type = storedType;
        for (AbstractInsnNode insn : method.instructions.toArray()) {
            if (!(insn instanceof VarInsnNode var) || var.var != local || var.getOpcode() != Opcodes.ALOAD) continue;
            String consumed = consumedReferenceType(var);
            if (consumed == null) continue;
            type = mergeReferenceDefaultType(type, consumed);
            if (type == null) {
                return null;
            }
        }
        for (AbstractInsnNode insn : method.instructions.toArray()) {
            String consumed = null;
            if (insn instanceof MethodInsnNode call) {
                consumed = consumedReferenceTypeFromInvocationBackslice(local, call);
            } else if (insn instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode indy) {
                consumed = consumedReferenceTypeFromInvokeDynamicBackslice(local, indy);
            }
            if (consumed == null) continue;
            type = mergeReferenceDefaultType(type, consumed);
            if (type == null) {
                return null;
            }
        }
        if (type != null) return type;
        return objectReferenceDefaultAllowed(failingLoad) ? "java/lang/Object" : null;
    }

    private String mergeReferenceDefaultType(String current, String next) {
        if (next == null || next.isBlank()) return current;
        if (current == null || "java/lang/Object".equals(current)) return next;
        if ("java/lang/Object".equals(next) || current.equals(next)) return current;
        return null;
    }

    private String storedReferenceType(String owner, MethodNode method, VarInsnNode store) {
        AbstractInsnNode producer = previousReal(store.getPrevious());
        if (producer == null) return null;
        if (producer instanceof TypeInsnNode typeInsn) {
            return switch (typeInsn.getOpcode()) {
                case Opcodes.CHECKCAST -> typeInsn.desc;
                case Opcodes.ANEWARRAY -> arrayTypeFromAnewarray(typeInsn.desc);
                case Opcodes.NEW -> typeInsn.desc;
                default -> null;
            };
        }
        if (producer instanceof org.objectweb.asm.tree.MultiANewArrayInsnNode multi) {
            return multi.desc;
        }
        if (producer instanceof MethodInsnNode call) {
            if (call.getOpcode() == Opcodes.INVOKESPECIAL && "<init>".equals(call.name)) {
                return call.owner;
            }
            return referenceTypeName(org.objectweb.asm.Type.getReturnType(call.desc));
        }
        if (producer instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode indy) {
            return referenceTypeName(org.objectweb.asm.Type.getReturnType(indy.desc));
        }
        if (producer instanceof org.objectweb.asm.tree.FieldInsnNode field
                && field.getOpcode() == Opcodes.GETSTATIC) {
            return referenceTypeName(org.objectweb.asm.Type.getType(field.desc));
        }
        if (producer instanceof org.objectweb.asm.tree.FieldInsnNode field
                && field.getOpcode() == Opcodes.GETFIELD) {
            return referenceTypeName(org.objectweb.asm.Type.getType(field.desc));
        }
        return storedReferenceTypeFromBackwardStack(owner, method, store);
    }

    private String storedReferenceTypeFromBackwardStack(String owner, MethodNode method, VarInsnNode store) {
        int needed = 1;
        for (AbstractInsnNode cursor = previousReal(store.getPrevious()); cursor != null; cursor = previousReal(cursor.getPrevious())) {
            StackEffect effect = simpleStackEffect(cursor);
            if (effect == null) return null;
            if (effect.pushed() > 0) {
                if (needed <= effect.pushed()) {
                    return producedReferenceType(owner, method, cursor);
                }
                needed -= effect.pushed();
            }
            needed += effect.consumed();
            if (needed <= 0 || needed > 64) return null;
        }
        return null;
    }

    private String producedReferenceType(String owner, MethodNode method, AbstractInsnNode producer) {
        if (producer instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
            if (var.var == 0 && (method.access & Opcodes.ACC_STATIC) == 0) {
                return owner;
            }
            return argumentReferenceType(method, var.var);
        }
        if (producer instanceof TypeInsnNode typeInsn) {
            return switch (typeInsn.getOpcode()) {
                case Opcodes.CHECKCAST -> typeInsn.desc;
                case Opcodes.ANEWARRAY -> arrayTypeFromAnewarray(typeInsn.desc);
                case Opcodes.NEW -> typeInsn.desc;
                default -> null;
            };
        }
        if (producer instanceof org.objectweb.asm.tree.MultiANewArrayInsnNode multi) {
            return multi.desc;
        }
        if (producer instanceof MethodInsnNode call) {
            if (call.getOpcode() == Opcodes.INVOKESPECIAL && "<init>".equals(call.name)) {
                return call.owner;
            }
            return referenceTypeName(org.objectweb.asm.Type.getReturnType(call.desc));
        }
        if (producer instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode indy) {
            return referenceTypeName(org.objectweb.asm.Type.getReturnType(indy.desc));
        }
        if (producer instanceof org.objectweb.asm.tree.FieldInsnNode field
                && (field.getOpcode() == Opcodes.GETSTATIC || field.getOpcode() == Opcodes.GETFIELD)) {
            return referenceTypeName(org.objectweb.asm.Type.getType(field.desc));
        }
        return null;
    }

    private String argumentReferenceType(MethodNode method, int local) {
        int cursor = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (org.objectweb.asm.Type arg : org.objectweb.asm.Type.getArgumentTypes(method.desc)) {
            if (cursor == local) {
                return referenceTypeName(arg);
            }
            cursor += arg.getSize();
        }
        return null;
    }

    private String arrayTypeFromAnewarray(String element) {
        if (element == null || element.isBlank()) return null;
        if (element.charAt(0) == '[') return "[" + element;
        return "[L" + element + ";";
    }

    private String referenceTypeName(org.objectweb.asm.Type type) {
        if (type == null) return null;
        return switch (type.getSort()) {
            case org.objectweb.asm.Type.OBJECT -> type.getInternalName();
            case org.objectweb.asm.Type.ARRAY -> type.getDescriptor();
            default -> null;
        };
    }

    private String consumedReferenceType(VarInsnNode load) {
        int depth = 1;
        for (AbstractInsnNode cursor = nextReal(load.getNext()); cursor != null; cursor = nextReal(cursor.getNext())) {
            int opcode = cursor.getOpcode();
            if (cursor instanceof TypeInsnNode typeInsn && opcode == Opcodes.CHECKCAST) {
                return typeInsn.desc;
            }
            if (cursor instanceof MethodInsnNode call) {
                return invocationOperandType(call, depth);
            }
            if (cursor instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode indy) {
                return invokeDynamicOperandType(indy, depth);
            }
            if (cursor instanceof org.objectweb.asm.tree.FieldInsnNode field) {
                return fieldOperandType(field, depth);
            }
            String arrayType = arrayOperandType(opcode, depth);
            if (arrayType != null) return arrayType;
            Integer delta = simpleStackDelta(cursor);
            if (delta == null) return null;
            depth += delta;
            if (depth <= 0 || depth > 32) return null;
        }
        return null;
    }

    private String invocationOperandType(MethodInsnNode call, int suffixSlots) {
        List<String> operands = new ArrayList<>();
        if (call.getOpcode() != Opcodes.INVOKESTATIC) {
            operands.add(call.owner);
        }
        for (org.objectweb.asm.Type arg : org.objectweb.asm.Type.getArgumentTypes(call.desc)) {
            appendOperandSlots(operands, arg);
        }
        return suffixOperandType(operands, suffixSlots);
    }

    private String consumedReferenceTypeFromInvocationBackslice(int local, MethodInsnNode call) {
        LinkedList<String> required = new LinkedList<>();
        List<String> operands = new ArrayList<>();
        if (call.getOpcode() != Opcodes.INVOKESTATIC) {
            operands.add(call.owner);
        }
        for (org.objectweb.asm.Type arg : org.objectweb.asm.Type.getArgumentTypes(call.desc)) {
            appendOperandSlots(operands, arg);
        }
        for (int i = operands.size() - 1; i >= 0; i--) {
            required.add(operands.get(i));
        }
        for (AbstractInsnNode cursor = previousReal(call.getPrevious()); cursor != null; cursor = previousReal(cursor.getPrevious())) {
            StackEffect effect = simpleStackEffect(cursor);
            if (effect == null || required.size() < effect.pushed()) return null;
            List<String> producedRequirements = new ArrayList<>();
            for (int i = 0; i < effect.pushed(); i++) {
                producedRequirements.add(required.removeFirst());
            }
            if (cursor instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD && var.var == local
                    && producedRequirements.size() == 1) {
                return producedRequirements.get(0);
            }
            for (int i = effect.consumed() - 1; i >= 0; i--) {
                required.addFirst(consumedRequirement(cursor, producedRequirements, i));
            }
            if (required.isEmpty()) return null;
            if (required.size() > 128) return null;
        }
        return null;
    }

    private String invokeDynamicOperandType(org.objectweb.asm.tree.InvokeDynamicInsnNode indy, int suffixSlots) {
        List<String> operands = new ArrayList<>();
        for (org.objectweb.asm.Type arg : org.objectweb.asm.Type.getArgumentTypes(indy.desc)) {
            appendOperandSlots(operands, arg);
        }
        return suffixOperandType(operands, suffixSlots);
    }

    private String consumedReferenceTypeFromInvokeDynamicBackslice(
        int local,
        org.objectweb.asm.tree.InvokeDynamicInsnNode indy
    ) {
        LinkedList<String> required = new LinkedList<>();
        List<String> operands = new ArrayList<>();
        for (org.objectweb.asm.Type arg : org.objectweb.asm.Type.getArgumentTypes(indy.desc)) {
            appendOperandSlots(operands, arg);
        }
        for (int i = operands.size() - 1; i >= 0; i--) {
            required.add(operands.get(i));
        }
        for (AbstractInsnNode cursor = previousReal(indy.getPrevious()); cursor != null; cursor = previousReal(cursor.getPrevious())) {
            StackEffect effect = simpleStackEffect(cursor);
            if (effect == null || required.size() < effect.pushed()) return null;
            List<String> producedRequirements = new ArrayList<>();
            for (int i = 0; i < effect.pushed(); i++) {
                producedRequirements.add(required.removeFirst());
            }
            if (cursor instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD && var.var == local
                    && producedRequirements.size() == 1) {
                return producedRequirements.get(0);
            }
            for (int i = effect.consumed() - 1; i >= 0; i--) {
                required.addFirst(consumedRequirement(cursor, producedRequirements, i));
            }
            if (required.isEmpty()) return null;
            if (required.size() > 128) return null;
        }
        return null;
    }

    private String consumedRequirement(AbstractInsnNode insn, List<String> producedRequirements, int consumedSlot) {
        if (insn instanceof TypeInsnNode typeInsn && typeInsn.getOpcode() == Opcodes.CHECKCAST) {
            return typeInsn.desc;
        }
        if (producedRequirements.size() == 1) {
            return producedRequirements.get(0);
        }
        return null;
    }

    private String fieldOperandType(org.objectweb.asm.tree.FieldInsnNode field, int suffixSlots) {
        List<String> operands = new ArrayList<>();
        org.objectweb.asm.Type fieldType = org.objectweb.asm.Type.getType(field.desc);
        switch (field.getOpcode()) {
            case Opcodes.GETFIELD -> operands.add(field.owner);
            case Opcodes.PUTFIELD -> {
                operands.add(field.owner);
                appendOperandSlots(operands, fieldType);
            }
            case Opcodes.PUTSTATIC -> appendOperandSlots(operands, fieldType);
            default -> {
                return null;
            }
        }
        return suffixOperandType(operands, suffixSlots);
    }

    private String arrayOperandType(int opcode, int suffixSlots) {
        return switch (opcode) {
            case Opcodes.AALOAD -> suffixSlots == 2 ? "[Ljava/lang/Object;" : null;
            case Opcodes.BALOAD -> suffixSlots == 2 ? "[B" : null;
            case Opcodes.CALOAD -> suffixSlots == 2 ? "[C" : null;
            case Opcodes.SALOAD -> suffixSlots == 2 ? "[S" : null;
            case Opcodes.IALOAD -> suffixSlots == 2 ? "[I" : null;
            case Opcodes.LALOAD -> suffixSlots == 2 ? "[J" : null;
            case Opcodes.FALOAD -> suffixSlots == 2 ? "[F" : null;
            case Opcodes.DALOAD -> suffixSlots == 2 ? "[D" : null;
            case Opcodes.ARRAYLENGTH -> suffixSlots == 1 ? "[Ljava/lang/Object;" : null;
            default -> null;
        };
    }

    private void appendOperandSlots(List<String> operands, org.objectweb.asm.Type type) {
        String reference = referenceTypeName(type);
        operands.add(reference);
        if (type.getSize() == 2) {
            operands.add(null);
        }
    }

    private String suffixOperandType(List<String> operands, int suffixSlots) {
        if (suffixSlots <= 0 || suffixSlots > operands.size()) return null;
        return operands.get(operands.size() - suffixSlots);
    }

    private Integer simpleStackDelta(AbstractInsnNode insn) {
        StackEffect effect = simpleStackEffect(insn);
        return effect == null ? null : effect.pushed() - effect.consumed();
    }

    private StackEffect simpleStackEffect(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode < 0) return new StackEffect(0, 0);
        if (insn instanceof VarInsnNode var) {
            return switch (var.getOpcode()) {
                case Opcodes.ILOAD, Opcodes.FLOAD, Opcodes.ALOAD -> new StackEffect(0, 1);
                case Opcodes.LLOAD, Opcodes.DLOAD -> new StackEffect(0, 2);
                case Opcodes.ISTORE, Opcodes.FSTORE, Opcodes.ASTORE -> new StackEffect(1, 0);
                case Opcodes.LSTORE, Opcodes.DSTORE -> new StackEffect(2, 0);
                default -> null;
            };
        }
        if (insn instanceof org.objectweb.asm.tree.LdcInsnNode ldc) {
            Object cst = ldc.cst;
            return new StackEffect(0, (cst instanceof Long || cst instanceof Double) ? 2 : 1);
        }
        if (insn instanceof org.objectweb.asm.tree.IntInsnNode) {
            return opcode == Opcodes.NEWARRAY ? new StackEffect(1, 1) : new StackEffect(0, 1);
        }
        if (insn instanceof TypeInsnNode typeInsn) {
            return switch (typeInsn.getOpcode()) {
                case Opcodes.NEW -> new StackEffect(0, 1);
                case Opcodes.ANEWARRAY -> new StackEffect(1, 1);
                case Opcodes.CHECKCAST, Opcodes.INSTANCEOF -> new StackEffect(1, 1);
                default -> null;
            };
        }
        if (insn instanceof org.objectweb.asm.tree.MultiANewArrayInsnNode multi) {
            return new StackEffect(multi.dims, 1);
        }
        if (insn instanceof org.objectweb.asm.tree.FieldInsnNode field) {
            int fieldSize = org.objectweb.asm.Type.getType(field.desc).getSize();
            return switch (field.getOpcode()) {
                case Opcodes.GETSTATIC -> new StackEffect(0, fieldSize);
                case Opcodes.PUTSTATIC -> new StackEffect(fieldSize, 0);
                case Opcodes.GETFIELD -> new StackEffect(1, fieldSize);
                case Opcodes.PUTFIELD -> new StackEffect(1 + fieldSize, 0);
                default -> null;
            };
        }
        if (insn instanceof MethodInsnNode call) {
            int consumed = call.getOpcode() == Opcodes.INVOKESTATIC ? 0 : 1;
            for (org.objectweb.asm.Type arg : org.objectweb.asm.Type.getArgumentTypes(call.desc)) {
                consumed += arg.getSize();
            }
            return new StackEffect(consumed, org.objectweb.asm.Type.getReturnType(call.desc).getSize());
        }
        if (insn instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode indy) {
            int consumed = 0;
            for (org.objectweb.asm.Type arg : org.objectweb.asm.Type.getArgumentTypes(indy.desc)) {
                consumed += arg.getSize();
            }
            return new StackEffect(consumed, org.objectweb.asm.Type.getReturnType(indy.desc).getSize());
        }
        return switch (opcode) {
            case Opcodes.ACONST_NULL,
                Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2,
                Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5,
                Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2 -> new StackEffect(0, 1);
            case Opcodes.LCONST_0, Opcodes.LCONST_1, Opcodes.DCONST_0, Opcodes.DCONST_1 -> new StackEffect(0, 2);
            case Opcodes.DUP -> new StackEffect(1, 2);
            case Opcodes.DUP2 -> new StackEffect(2, 4);
            case Opcodes.POP -> new StackEffect(1, 0);
            case Opcodes.POP2 -> new StackEffect(2, 0);
            case Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM,
                Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR,
                Opcodes.FADD, Opcodes.FSUB, Opcodes.FMUL, Opcodes.FDIV, Opcodes.FREM -> new StackEffect(2, 1);
            case Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL, Opcodes.LDIV, Opcodes.LREM,
                Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR,
                Opcodes.DADD, Opcodes.DSUB, Opcodes.DMUL, Opcodes.DDIV, Opcodes.DREM -> new StackEffect(4, 2);
            case Opcodes.AALOAD, Opcodes.BALOAD, Opcodes.CALOAD, Opcodes.SALOAD,
                Opcodes.IALOAD, Opcodes.FALOAD -> new StackEffect(2, 1);
            case Opcodes.LALOAD, Opcodes.DALOAD -> new StackEffect(2, 2);
            case Opcodes.AASTORE, Opcodes.BASTORE, Opcodes.CASTORE, Opcodes.SASTORE,
                Opcodes.IASTORE, Opcodes.FASTORE -> new StackEffect(3, 0);
            case Opcodes.LASTORE, Opcodes.DASTORE -> new StackEffect(4, 0);
            default -> null;
        };
    }

    private record StackEffect(int consumed, int pushed) {
    }

    private boolean objectReferenceDefaultAllowed(VarInsnNode load) {
        AbstractInsnNode[] window = nextRealWindow(load.getNext(), 8);
        for (int i = 0; i < window.length; i++) {
            AbstractInsnNode insn = window[i];
            if (insn == null) break;
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.AASTORE) return true;
            if (opcode == Opcodes.ARETURN) return true;
            if (opcode == Opcodes.POP || opcode == Opcodes.POP2) return true;
            if (opcode == Opcodes.CHECKCAST) return true;
            if (opcode == Opcodes.IFNULL || opcode == Opcodes.IFNONNULL) return true;
            if (opcode == Opcodes.IF_ACMPEQ || opcode == Opcodes.IF_ACMPNE) return true;
            if (insn instanceof MethodInsnNode || insn instanceof org.objectweb.asm.tree.FieldInsnNode) return false;
            if (opcode == Opcodes.AALOAD || opcode == Opcodes.ARRAYLENGTH) return false;
        }
        return false;
    }

    private AbstractInsnNode[] nextRealWindow(AbstractInsnNode start, int limit) {
        AbstractInsnNode[] window = new AbstractInsnNode[limit];
        int index = 0;
        for (AbstractInsnNode cursor = start; cursor != null && index < limit; cursor = cursor.getNext()) {
            if (cursor.getOpcode() < 0) continue;
            window[index++] = cursor;
        }
        return window;
    }

    private int argumentLocalLimit(MethodNode method) {
        int limit = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (org.objectweb.asm.Type arg : org.objectweb.asm.Type.getArgumentTypes(method.desc)) {
            limit += arg.getSize();
        }
        return limit;
    }

    private AbstractInsnNode methodEntryPoint(MethodNode method) {
        AbstractInsnNode first = nextReal(method.instructions.getFirst());
        if (!"<init>".equals(method.name)) return first;
        for (AbstractInsnNode insn = first; insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKESPECIAL
                    && "<init>".equals(call.name)) {
                return nextReal(call.getNext());
            }
        }
        return first;
    }

    private AbstractInsnNode nextReal(AbstractInsnNode insn) {
        for (AbstractInsnNode cursor = insn; cursor != null; cursor = cursor.getNext()) {
            if (cursor.getOpcode() >= 0) return cursor;
        }
        return null;
    }

    private AbstractInsnNode previousReal(AbstractInsnNode insn) {
        for (AbstractInsnNode cursor = insn; cursor != null; cursor = cursor.getPrevious()) {
            if (cursor.getOpcode() >= 0) return cursor;
        }
        return null;
    }

    private LocalAccessKind localAccessKind(int opcode) {
        LocalAccessKind load = localLoadKind(opcode);
        if (load != null) return load;
        return switch (opcode) {
            case Opcodes.ISTORE, Opcodes.IINC -> LocalAccessKind.INT;
            case Opcodes.LSTORE -> LocalAccessKind.LONG;
            case Opcodes.FSTORE -> LocalAccessKind.FLOAT;
            case Opcodes.DSTORE -> LocalAccessKind.DOUBLE;
            case Opcodes.ASTORE -> LocalAccessKind.REF;
            default -> null;
        };
    }

    private LocalAccessKind localLoadKind(int opcode) {
        return switch (opcode) {
            case Opcodes.ILOAD -> LocalAccessKind.INT;
            case Opcodes.LLOAD -> LocalAccessKind.LONG;
            case Opcodes.FLOAD -> LocalAccessKind.FLOAT;
            case Opcodes.DLOAD -> LocalAccessKind.DOUBLE;
            case Opcodes.ALOAD -> LocalAccessKind.REF;
            default -> null;
        };
    }

    private enum LocalAccessKind {
        INT(1),
        LONG(2),
        FLOAT(1),
        DOUBLE(2),
        REF(1);

        private final int slots;

        LocalAccessKind(int slots) {
            this.slots = slots;
        }

        int slots() {
            return slots;
        }
    }

    private void stripExistingFrames(L1Class l1) {
        stripExistingFramesForWrite(l1);
    }

    private static void stripExistingFramesForWrite(L1Class l1) {
        for (MethodNode method : l1.asmNode().methods) {
            if (method.instructions == null || method.instructions.size() == 0) continue;
            for (AbstractInsnNode insn : method.instructions.toArray()) {
                if (insn instanceof FrameNode) {
                    method.instructions.remove(insn);
                } else if (insn instanceof TypeInsnNode typeInsn) {
                    typeInsn.desc = normalizeObjectFrameType(typeInsn.desc);
                }
            }
        }
    }

    private static String normalizeObjectFrameType(String type) {
        if (type != null && type.length() > 2 && type.charAt(0) == 'L' && type.charAt(type.length() - 1) == ';') {
            return type.substring(1, type.length() - 1);
        }
        return type;
    }

    private byte[] normalizeWrittenStackFrames(byte[] bytecode) {
        try {
            ClassReader reader = new ClassReader(bytecode);
            ClassNode node = new ClassNode();
            reader.accept(node, ClassReader.EXPAND_FRAMES);
            boolean changed = false;
            for (MethodNode method : node.methods) {
                if (method.instructions == null) continue;
                for (AbstractInsnNode insn : method.instructions.toArray()) {
                    if (!(insn instanceof FrameNode frame)) continue;
                    changed |= normalizeFrameValues(frame.local);
                    changed |= normalizeFrameValues(frame.stack);
                }
            }
            if (!changed) return bytecode;
            ClassWriter writer = new ClassWriter(0);
            node.accept(writer);
            return writer.toByteArray();
        } catch (Throwable ignored) {
            return bytecode;
        }
    }

    private boolean normalizeFrameValues(List<Object> values) {
        if (values == null || values.isEmpty()) return false;
        boolean changed = false;
        for (int i = 0; i < values.size(); i++) {
            Object value = values.get(i);
            if (value instanceof String type) {
                String normalized = normalizeObjectFrameType(type);
                if (!normalized.equals(type)) {
                    values.set(i, normalized);
                    changed = true;
                }
            }
        }
        return changed;
    }

    private int estimateMethodBytes(MethodNode method) {
        int offset = 0;
        for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            offset += estimateInstructionBytes(insn, offset);
        }
        return offset;
    }

    private int estimateInstructionBytes(org.objectweb.asm.tree.AbstractInsnNode insn, int offset) {
        int opcode = insn.getOpcode();
        if (opcode < 0) return 0;
        if (insn instanceof org.objectweb.asm.tree.VarInsnNode var) {
            return var.var > 255 ? 4 : 2;
        }
        if (insn instanceof org.objectweb.asm.tree.IincInsnNode iinc) {
            return iinc.var > 255 || iinc.incr < Byte.MIN_VALUE || iinc.incr > Byte.MAX_VALUE ? 6 : 3;
        }
        if (insn instanceof org.objectweb.asm.tree.IntInsnNode) {
            return opcode == org.objectweb.asm.Opcodes.SIPUSH ? 3 : 2;
        }
        if (insn instanceof org.objectweb.asm.tree.LdcInsnNode) {
            return 3;
        }
        if (insn instanceof org.objectweb.asm.tree.JumpInsnNode) {
            return opcode == 200 || opcode == 201 ? 5 : 3;
        }
        if (insn instanceof org.objectweb.asm.tree.MethodInsnNode) {
            return opcode == org.objectweb.asm.Opcodes.INVOKEINTERFACE ? 5 : 3;
        }
        if (insn instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode) {
            return 5;
        }
        if (insn instanceof org.objectweb.asm.tree.TypeInsnNode) {
            return 3;
        }
        if (insn instanceof org.objectweb.asm.tree.MultiANewArrayInsnNode) {
            return 4;
        }
        if (insn instanceof org.objectweb.asm.tree.TableSwitchInsnNode tableSwitch) {
            return 1 + switchPadding(offset) + 12 + tableSwitch.labels.size() * 4;
        }
        if (insn instanceof org.objectweb.asm.tree.LookupSwitchInsnNode lookupSwitch) {
            return 1 + switchPadding(offset) + 8 + lookupSwitch.labels.size() * 8;
        }
        return switch (opcode) {
            case org.objectweb.asm.Opcodes.GETSTATIC, org.objectweb.asm.Opcodes.PUTSTATIC,
                org.objectweb.asm.Opcodes.GETFIELD, org.objectweb.asm.Opcodes.PUTFIELD,
                org.objectweb.asm.Opcodes.NEW, org.objectweb.asm.Opcodes.ANEWARRAY,
                org.objectweb.asm.Opcodes.CHECKCAST, org.objectweb.asm.Opcodes.INSTANCEOF -> 3;
            case org.objectweb.asm.Opcodes.NEWARRAY, org.objectweb.asm.Opcodes.BIPUSH -> 2;
            default -> 1;
        };
    }

    private int switchPadding(int offset) {
        return (4 - ((offset + 1) & 3)) & 3;
    }

    private record MethodSize(String name, String desc, int bytes) {
    }

    private String diagnoseFrameFailure(L1Class l1) {
        try {
            ClassWriter rawWriter = new ClassWriter(0);
            l1.asmNode().accept(rawWriter);

            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            CheckClassAdapter.verify(new ClassReader(rawWriter.toByteArray()), null, false, pw);
            pw.flush();
            return sw.toString().trim();
        } catch (Throwable diagnosticError) {
            return "<failed to run verifier diagnostics: " + diagnosticError.getMessage() + ">";
        }
    }

    private void validateWrittenClass(L1Class l1, byte[] bytecode) {
        try {
            ClassReader reader = new ClassReader(bytecode);
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            CheckClassAdapter.verify(reader, null, false, pw);
            pw.flush();
            String diagnostics = sw.toString().trim();
            if (!diagnostics.isBlank() && !containsOnlyClassNotFoundErrors(diagnostics)) {
                String writtenDetails = diagnoseWrittenClass(l1.name(), bytecode);
                if (!writtenDetails.isBlank()) {
                    log.error("Written bytecode verifier details for {}:{}{}", l1.name(), System.lineSeparator(), writtenDetails);
                }
                throw new IllegalStateException("ASM verifier rejected " + l1.name() + ":" + System.lineSeparator() + diagnostics);
            }
            if (scanRawBytecode(bytecode)) {
                throw new IllegalStateException("Raw bytecode scan found an illegal opcode in " + l1.name());
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("Failed to validate written class " + l1.name(), t);
        }
    }

    private String diagnoseWrittenClass(String expectedName, byte[] bytecode) {
        StringBuilder out = new StringBuilder();
        try {
            ClassNode node = new ClassNode();
            new ClassReader(bytecode).accept(node, ClassReader.EXPAND_FRAMES);
            String owner = node.name == null ? expectedName : node.name;
            for (MethodNode method : node.methods) {
                if (method.instructions == null || method.instructions.size() == 0) continue;
                try {
                    Analyzer<BasicValue> analyzer = new Analyzer<>(new BasicVerifier());
                    analyzer.analyze(owner, method);
                } catch (AnalyzerException e) {
                    out.append("  analyzer ")
                        .append(method.name)
                        .append(method.desc)
                        .append(": ")
                        .append(e.getMessage())
                        .append(System.lineSeparator());
                    appendInstructionWindow(out, method, e.node);
                    appendFailingLocalAccesses(out, method, e.node);
                }
            }
        } catch (Throwable t) {
            out.append("<failed to diagnose written bytecode: ")
                .append(t.getMessage())
                .append('>');
        }
        return out.toString().trim();
    }

    private static boolean containsOnlyClassNotFoundErrors(String diagnostics) {
        if (diagnostics.isBlank()) return true;
        String lower = diagnostics.toLowerCase(Locale.ROOT);
        if (lower.contains("bad instruction")
                || lower.contains("bad type on operand stack")
                || lower.contains("inconsistent stackmap")
                || lower.contains("expecting a stackmap frame")
                || lower.contains("expecting type")
                || lower.contains("get long/double overflows")
                || lower.contains("bad local variable type")
                || lower.contains("invalid opcode")) {
            return false;
        }
        if (diagnostics.contains("ClassNotFoundException")
                || diagnostics.contains("TypeNotPresentException")) {
            return true;
        }
        for (String line : diagnostics.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (trimmed.contains("AnalyzerException")
                    && (trimmed.contains("ClassNotFoundException") || trimmed.contains("not present"))) continue;
            if (trimmed.contains("TypeNotPresentException")) continue;
            if (trimmed.contains("ClassNotFoundException")) continue;
            if (trimmed.startsWith("at ")) continue;
            if (trimmed.startsWith("...")) continue;
            if (trimmed.startsWith("Caused by")
                    && (trimmed.contains("ClassNotFoundException") || trimmed.contains("TypeNotPresentException"))) continue;
            return false;
        }
        return true;
    }

    private static boolean scanRawBytecode(byte[] bytes) {
        try {
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(bytes);
            buf.getInt();
            buf.getShort();
            buf.getShort();
            int cpCount = buf.getShort() & 0xFFFF;
            String[] utf8 = new String[cpCount];
            int i = 1;
            while (i < cpCount) {
                int tag = buf.get() & 0xFF;
                switch (tag) {
                    case 1 -> {
                        int len = buf.getShort() & 0xFFFF;
                        byte[] str = new byte[len];
                        buf.get(str);
                        utf8[i] = new String(str, java.nio.charset.StandardCharsets.UTF_8);
                    }
                    case 3, 4, 9, 10, 11, 12, 17, 18 -> buf.position(buf.position() + 4);
                    case 5, 6 -> {
                        buf.position(buf.position() + 8);
                        i++;
                    }
                    case 7, 8, 16, 19, 20 -> buf.position(buf.position() + 2);
                    case 15 -> buf.position(buf.position() + 3);
                    default -> {
                        return true;
                    }
                }
                i++;
            }
            buf.position(buf.position() + 6);
            int ifaceCount = buf.getShort() & 0xFFFF;
            buf.position(buf.position() + ifaceCount * 2);
            skipMembers(buf);
            int methodCount = buf.getShort() & 0xFFFF;
            for (int m = 0; m < methodCount; m++) {
                buf.position(buf.position() + 6);
                int attrs = buf.getShort() & 0xFFFF;
                for (int a = 0; a < attrs; a++) {
                    int nameIndex = buf.getShort() & 0xFFFF;
                    int attrLen = buf.getInt();
                    String name = nameIndex < utf8.length ? utf8[nameIndex] : null;
                    if ("Code".equals(name)) {
                        int codeStart = buf.position();
                        buf.position(buf.position() + 4);
                        int codeLen = buf.getInt();
                        if (hasIllegalOpcode(bytes, buf.position(), codeLen)) return true;
                        buf.position(codeStart + attrLen);
                    } else {
                        buf.position(buf.position() + attrLen);
                    }
                }
            }
            return false;
        } catch (Throwable t) {
            return true;
        }
    }

    private static void skipMembers(java.nio.ByteBuffer buf) {
        int fieldCount = buf.getShort() & 0xFFFF;
        for (int f = 0; f < fieldCount; f++) {
            buf.position(buf.position() + 6);
            int attrs = buf.getShort() & 0xFFFF;
            for (int a = 0; a < attrs; a++) {
                buf.position(buf.position() + 2);
                int attrLen = buf.getInt();
                buf.position(buf.position() + attrLen);
            }
        }
    }

    private static boolean hasIllegalOpcode(byte[] bytes, int start, int len) {
        int end = start + len;
        int p = start;
        while (p < end) {
            int op = bytes[p] & 0xFF;
            if (op > 201 && op != 196) return true;
            p += opcodeLength(bytes, p, end, start);
        }
        return p != end;
    }

    private static int opcodeLength(byte[] bytes, int p, int end, int codeStart) {
        int op = bytes[p] & 0xFF;
        return switch (op) {
            case 16, 18, 21, 22, 23, 24, 25, 54, 55, 56, 57, 58, 169, 188 -> 2;
            case 17, 19, 20, 132, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
                 165, 166, 167, 168, 178, 179, 180, 181, 182, 183, 184, 187, 189, 192, 193,
                 198, 199 -> 3;
            case 185, 186, 200, 201 -> 5;
            case 197 -> 4;
            case 196 -> wideLength(bytes, p, end);
            case 170 -> tableSwitchLength(bytes, p, end, codeStart);
            case 171 -> lookupSwitchLength(bytes, p, end, codeStart);
            default -> 1;
        };
    }

    private static int wideLength(byte[] bytes, int p, int end) {
        if (p + 1 >= end) return end - p + 1;
        int widened = bytes[p + 1] & 0xFF;
        return widened == 132 ? 6 : 4;
    }

    private static int tableSwitchLength(byte[] bytes, int p, int end, int codeStart) {
        int rel = p - codeStart;
        int q = p + 1 + ((4 - ((rel + 1) & 3)) & 3);
        if (q + 12 > end) return end - p + 1;
        int low = readInt(bytes, q + 4);
        int high = readInt(bytes, q + 8);
        long count = (long) high - low + 1L;
        if (count < 0 || count > 1_000_000L) return end - p + 1;
        return (q - p) + 12 + (int) count * 4;
    }

    private static int lookupSwitchLength(byte[] bytes, int p, int end, int codeStart) {
        int rel = p - codeStart;
        int q = p + 1 + ((4 - ((rel + 1) & 3)) & 3);
        if (q + 8 > end) return end - p + 1;
        int pairs = readInt(bytes, q + 4);
        if (pairs < 0 || pairs > 1_000_000) return end - p + 1;
        return (q - p) + 8 + pairs * 8;
    }

    private static int readInt(byte[] bytes, int p) {
        return ((bytes[p] & 0xFF) << 24)
            | ((bytes[p + 1] & 0xFF) << 16)
            | ((bytes[p + 2] & 0xFF) << 8)
            | (bytes[p + 3] & 0xFF);
    }
    /**
     * ClassWriter that uses ClassHierarchy for common superclass computation.
     */
    private static final class HierarchyClassWriter extends ClassWriter {
        private final ClassHierarchy hierarchy;
        HierarchyClassWriter(ClassHierarchy hierarchy) {
            super(COMPUTE_FRAMES);
            this.hierarchy = hierarchy;
        }

        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            type1 = normalizeObjectFrameType(type1);
            type2 = normalizeObjectFrameType(type2);
            if (hierarchy != null) {
                String result = hierarchy.getCommonSuperClass(type1, type2);
                if (result != null && !result.equals("java/lang/Object")) {
                    return normalizeObjectFrameType(result);
                }
            }
            try {
                return super.getCommonSuperClass(type1, type2);
            } catch (Throwable t) {
                return "java/lang/Object";
            }
        }

    }
}
