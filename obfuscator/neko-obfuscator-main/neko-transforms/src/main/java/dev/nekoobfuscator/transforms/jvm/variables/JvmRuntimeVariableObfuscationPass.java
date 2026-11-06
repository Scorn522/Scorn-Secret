package dev.nekoobfuscator.transforms.jvm.variables;

import dev.nekoobfuscator.api.transform.IRLevel;
import dev.nekoobfuscator.api.transform.TransformContext;
import dev.nekoobfuscator.api.transform.TransformPass;
import dev.nekoobfuscator.api.transform.TransformPhase;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningPass;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;
import dev.nekoobfuscator.transforms.jvm.key.JvmKeyDispatchPass;
import dev.nekoobfuscator.transforms.jvm.validation.JvmValidationSinkHardeningPass;
import dev.nekoobfuscator.transforms.util.JvmObfuscationCoverage;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.Type;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
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
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

/**
 * Keeps protected application locals out of their original plaintext slots.
 *
 * <p>The pass runs after CFF and derives store-site masks from live CFF state.
 * Primitive values are kept in encrypted shadow locals and their masks are
 * recomputed transiently on the operand stack. Reference values remain on the
 * verifier-correct JVM local path instead of being moved to a plaintext frame.</p>
 */
public final class JvmRuntimeVariableObfuscationPass implements TransformPass {
    public static final String ID = "runtimeVariableObfuscation";

    private static final int MASK_A = 0x6D2B79F5;
    private static final int MASK_B = 0x1B873593;
    private static final int MASK_C = 0x85EBCA6B;
    private static final int MASK_D = 0xC2B2AE35;
    private static final String RUNTIME_MASK_HELPER_DESC = "(IJ)I";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "JVM Runtime Variable Obfuscation";
    }

    @Override
    public TransformPhase phase() {
        return TransformPhase.TRANSFORM;
    }

    @Override
    public IRLevel requiredLevel() {
        return IRLevel.L1;
    }

    @Override
    public Set<String> dependsOn() {
        return Set.of(ControlFlowFlatteningPass.ID, JvmValidationSinkHardeningPass.ID);
    }

    @Override
    public void transformClass(TransformContext ctx) {
    }

    @Override
    public void transformMethod(TransformContext ctx) {
        if (!(ctx instanceof PipelineContext pctx)) return;
        L1Class clazz = pctx.currentL1Class();
        L1Method method = pctx.currentL1Method();
        if (clazz == null || method == null || !method.hasCode()) return;
        if (TransformGuards.isRuntimeClass(clazz) || TransformGuards.isGeneratedMethod(method)) return;
        if (method.isAbstract() || method.isNative()) return;

        String methodKey = JvmKeyDispatchPass.coverageKey(clazz, method);
        ControlFlowFlatteningPass.CffMethodMetadata metadata =
            ControlFlowFlatteningPass.methodMetadata(pctx).get(methodKey);
        if (metadata == null || metadata.classKeyTable() == null) return;

        MethodNode mn = method.asmNode();
        Map<AbstractInsnNode, String> refLoadCasts = analyzeReferenceLoadCasts(clazz.name(), mn);
        Map<LocalKey, LocalShadow> shadows = planShadows(mn, metadata);
        if (shadows.isEmpty()) return;
        int directReferenceCasts = insertDirectReferenceLoadCasts(mn, metadata, refLoadCasts, shadows)
            + insertDirectReferenceProducerCasts(mn);
        RuntimeMaskHelper maskHelper = ensureRuntimeMaskHelper(pctx, clazz, metadata);

        allocateShadows(mn, shadows, metadata);
        int initialized = initializeShadowDefaults(pctx, mn, metadata, maskHelper, shadows);
        int rekeyed = rewriteKeyLocalUpdates(pctx, mn, metadata, maskHelper, shadows);
        int encodedBranches = rewriteEncodedZeroBranches(pctx, mn, metadata, maskHelper, shadows);
        int rewritten = rewriteLocalInstructions(pctx, mn, metadata, maskHelper, shadows, refLoadCasts);
        int decodedBranches = rewriteDecodedZeroBranches(pctx, mn, metadata, maskHelper, shadows);
        if (initialized + rekeyed + encodedBranches + rewritten + decodedBranches + directReferenceCasts == 0) return;

        mn.localVariables = null;
        mn.visibleLocalVariableAnnotations = null;
        mn.invisibleLocalVariableAnnotations = null;
        mn.maxStack = Math.max(mn.maxStack, 24);
        clazz.markDirty();
        pctx.invalidate(method);
        JvmObfuscationCoverage.get(ctx).full(
            id(),
            clazz.name(),
            method.name(),
            method.descriptor(),
            "cff-keyed-local-shadows-init-" + initialized +
                "-rekeys-" + rekeyed +
                "-branches-" + encodedBranches +
                "-decodedBranches-" + decodedBranches +
                "-sites-" + rewritten +
                "-directRefCasts-" + directReferenceCasts
        );
    }

    private int insertDirectReferenceLoadCasts(
        MethodNode mn,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        Map<AbstractInsnNode, String> refLoadCasts,
        Map<LocalKey, LocalShadow> shadows
    ) {
        int inserted = 0;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof VarInsnNode var) || var.getOpcode() != Opcodes.ALOAD) continue;
            String cast = refLoadCasts.get(insn);
            if (cast == null) {
                cast = linearReferenceConsumerCast(insn, mn);
            }
            if (cast == null) continue;
            if (metadata.applicationInstructions().contains(insn)
                    && shadows.containsKey(new LocalKey(var.var, LocalKind.REF))) continue;
            if (hasImmediateCheckcast(insn, cast)) continue;
            if (isUninitializedThisLoad(mn, var)) continue;
            mn.instructions.insert(insn, new TypeInsnNode(Opcodes.CHECKCAST, cast));
            inserted++;
        }
        return inserted;
    }

    private int insertDirectReferenceProducerCasts(MethodNode mn) {
        int inserted = 0;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (insn.getOpcode() != Opcodes.AALOAD) continue;
            String cast = linearReferenceConsumerCast(insn, mn);
            if (cast == null) continue;
            if (hasImmediateCheckcast(insn, cast)) continue;
            mn.instructions.insert(insn, new TypeInsnNode(Opcodes.CHECKCAST, cast));
            inserted++;
        }
        return inserted;
    }

    private boolean hasImmediateCheckcast(AbstractInsnNode load, String cast) {
        AbstractInsnNode next = nextReal(load.getNext());
        return next instanceof TypeInsnNode type
            && type.getOpcode() == Opcodes.CHECKCAST
            && cast.equals(type.desc);
    }

    private boolean isUninitializedThisLoad(MethodNode method, VarInsnNode load) {
        if (!"<init>".equals(method.name) || load.var != 0) return false;
        for (AbstractInsnNode insn = nextReal(method.instructions.getFirst()); insn != null; insn = nextReal(insn.getNext())) {
            if (insn == load) return true;
            if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKESPECIAL
                    && "<init>".equals(call.name)) {
                return false;
            }
        }
        return false;
    }

    private Map<LocalKey, LocalShadow> planShadows(
        MethodNode mn,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        Map<LocalKey, LocalShadow> shadows = new LinkedHashMap<>();
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!metadata.applicationInstructions().contains(insn)) continue;
            if (insn instanceof VarInsnNode var) {
                LocalKind kind = kindForVarOpcode(var.getOpcode());
                if (kind != null
                        && kind != LocalKind.REF
                        && isStoreOpcode(var.getOpcode())
                        && !isReservedLocal(var.var, metadata)) {
                    shadows.putIfAbsent(new LocalKey(var.var, kind), new LocalShadow(var.var, kind));
                }
            }
        }
        return shadows;
    }

    private void allocateShadows(
        MethodNode mn,
        Map<LocalKey, LocalShadow> shadows,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        int next = mn.maxLocals;
        Map<Integer, List<LocalKey>> originalSlotUse = originalSlotUse(shadows);
        int argumentLimit = argumentLocalLimit(mn);
        List<Map.Entry<LocalKey, LocalShadow>> ordered = new ArrayList<>(shadows.entrySet());
        ordered.sort(Comparator
            .comparingInt((Map.Entry<LocalKey, LocalShadow> e) -> e.getKey().var())
            .thenComparing(e -> e.getKey().kind().ordinal()));
        for (Map.Entry<LocalKey, LocalShadow> entry : ordered) {
            LocalShadow shadow = entry.getValue();
            if (canReuseOriginalSlotForShadow(shadow, originalSlotUse, argumentLimit, metadata)) {
                shadow.shadowLocal = shadow.var;
                shadow.reusedOriginalShadow = true;
            } else {
                shadow.shadowLocal = next;
                next += shadow.kind.shadowSize();
            }
        }
        mn.maxLocals = Math.max(mn.maxLocals, next);
    }

    private Map<Integer, List<LocalKey>> originalSlotUse(Map<LocalKey, LocalShadow> shadows) {
        Map<Integer, List<LocalKey>> use = new LinkedHashMap<>();
        for (LocalKey key : shadows.keySet()) {
            for (int i = 0; i < key.kind().shadowSize(); i++) {
                use.computeIfAbsent(key.var() + i, ignored -> new ArrayList<>()).add(key);
            }
        }
        return use;
    }

    private boolean canReuseOriginalSlotForShadow(
        LocalShadow shadow,
        Map<Integer, List<LocalKey>> originalSlotUse,
        int argumentLimit,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        if (shadow.kind == LocalKind.REF) return false;
        if (shadow.kind == LocalKind.FLOAT || shadow.kind == LocalKind.DOUBLE) return false;
        if (shadow.var < argumentLimit) return false;
        for (int i = 0; i < shadow.kind.shadowSize(); i++) {
            int local = shadow.var + i;
            if (isReservedLocal(local, metadata)) return false;
            List<LocalKey> users = originalSlotUse.get(local);
            if (users == null || users.isEmpty()) return false;
            for (LocalKey user : users) {
                if (user.var() != shadow.var) return false;
                if (user.kind().shadowSize() != shadow.kind.shadowSize()) return false;
            }
        }
        return true;
    }

    private int argumentLocalLimit(MethodNode mn) {
        int limit = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type arg : Type.getArgumentTypes(mn.desc)) {
            limit += arg.getSize();
        }
        return limit;
    }

    private int initializeShadowDefaults(
        PipelineContext pctx,
        MethodNode mn,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        Map<LocalKey, LocalShadow> shadows
    ) {
        int changed = 0;
        List<LocalShadow> ordered = shadows.values().stream()
            .sorted(Comparator.comparingInt(LocalShadow::var))
            .toList();
        InsnList init = new InsnList();
        InsnList maskInit = new InsnList();
        for (LocalShadow shadow : ordered) {
            emitDefaultShadow(init, shadow);
            if (shadow.reusedOriginalShadow) {
                emitInitialShadow(maskInit, metadata, maskHelper, shadow);
            } else {
                emitInitialShadow(maskInit, metadata, maskHelper, shadow);
                emitOriginalPoison(maskInit, shadow);
            }
            changed++;
        }
        if (changed > 0) {
            JvmKeyDispatchPass.markGenerated(pctx, init);
            JvmKeyDispatchPass.markGenerated(pctx, maskInit);
            mn.instructions.insert(init);
            AbstractInsnNode maskPoint = firstApplicationInstruction(mn, metadata);
            if (maskPoint == null) {
                mn.instructions.insert(maskInit);
            } else {
                mn.instructions.insertBefore(maskPoint, maskInit);
            }
        }
        return changed;
    }

    private int rewriteEncodedZeroBranches(
        PipelineContext pctx,
        MethodNode mn,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        Map<LocalKey, LocalShadow> shadows
    ) {
        int changed = 0;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof JumpInsnNode jump)) continue;
            if (!metadata.applicationInstructions().contains(insn)) continue;
            int opcode = jump.getOpcode();
            if (opcode != Opcodes.IFEQ && opcode != Opcodes.IFNE) continue;
            AbstractInsnNode previous = previousReal(insn.getPrevious());
            if (!(previous instanceof VarInsnNode load)) continue;
            if (load.getOpcode() != Opcodes.ILOAD || !metadata.applicationInstructions().contains(load)) continue;
            LocalShadow shadow = shadows.get(new LocalKey(load.var, LocalKind.INT));
            if (shadow == null || shadow.shadowLocal < 0) continue;

            InsnList replacement = new InsnList();
            replacement.add(new VarInsnNode(Opcodes.ILOAD, shadow.shadowLocal));
            emitStableMaskInt(replacement, metadata, maskHelper, shadow);
            replacement.add(new JumpInsnNode(opcode == Opcodes.IFEQ ? Opcodes.IF_ICMPEQ : Opcodes.IF_ICMPNE, jump.label));
            JvmKeyDispatchPass.markGenerated(pctx, replacement);
            mn.instructions.insertBefore(previous, replacement);
            mn.instructions.remove(previous);
            mn.instructions.remove(insn);
            changed++;
        }
        return changed;
    }

    private int rewriteKeyLocalUpdates(
        PipelineContext pctx,
        MethodNode mn,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        Map<LocalKey, LocalShadow> shadows
    ) {
        List<LocalShadow> primitiveShadows = shadows.values().stream()
            .filter(shadow -> shadow.kind.primitive() && shadow.shadowLocal >= 0)
            .sorted(Comparator.comparingInt(LocalShadow::var))
            .toList();
        if (primitiveShadows.isEmpty()) return 0;

        AbstractInsnNode protectedStart = firstApplicationInstruction(mn, metadata);
        int changed = 0;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof VarInsnNode store)) continue;
            if (store.getOpcode() != Opcodes.LSTORE || store.var != metadata.keyLocal()) continue;
            if (protectedStart != null && before(insn, protectedStart)) continue;

            InsnList rekey = new InsnList();
            for (LocalShadow shadow : primitiveShadows) {
                emitRekeyShadowForPendingKey(rekey, metadata, maskHelper, shadow);
            }
            JvmKeyDispatchPass.markGenerated(pctx, rekey);
            mn.instructions.insertBefore(insn, rekey);
            changed++;
        }
        return changed;
    }

    private int rewriteLocalInstructions(
        PipelineContext pctx,
        MethodNode mn,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        Map<LocalKey, LocalShadow> shadows,
        Map<AbstractInsnNode, String> refLoadCasts
    ) {
        int changed = 0;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!metadata.applicationInstructions().contains(insn)) continue;
            ControlFlowFlatteningPass.CffInstructionState state = metadata.instructionStates().get(insn);
            if (state == null) continue;
            if (insn instanceof VarInsnNode var) {
                LocalKind kind = kindForVarOpcode(var.getOpcode());
                if (kind == null) continue;
                LocalShadow shadow = shadows.get(new LocalKey(var.var, kind));
                if (shadow == null || shadow.shadowLocal < 0) continue;
                InsnList replacement = new InsnList();
                if (isLoadOpcode(var.getOpcode())) {
                    emitLoadFromShadow(replacement, metadata, maskHelper, shadow, refLoadCasts.get(insn));
                } else if (isStoreOpcode(var.getOpcode())) {
                    emitStoreShadowFromStack(replacement, metadata, maskHelper, shadow);
                } else {
                    continue;
                }
                JvmKeyDispatchPass.markGenerated(pctx, replacement);
                mn.instructions.insertBefore(insn, replacement);
                mn.instructions.remove(insn);
                changed++;
            } else if (insn instanceof IincInsnNode iinc) {
                LocalShadow shadow = shadows.get(new LocalKey(iinc.var, LocalKind.INT));
                if (shadow == null || shadow.shadowLocal < 0) continue;
                InsnList replacement = new InsnList();
                replacement.add(new VarInsnNode(Opcodes.ILOAD, shadow.shadowLocal));
                emitStableMaskInt(replacement, metadata, maskHelper, shadow);
                replacement.add(new InsnNode(Opcodes.IXOR));
                JvmPassBytecode.pushInt(replacement, iinc.incr);
                replacement.add(new InsnNode(Opcodes.IADD));
                emitStoreShadowFromStack(replacement, metadata, maskHelper, shadow);
                JvmKeyDispatchPass.markGenerated(pctx, replacement);
                mn.instructions.insertBefore(insn, replacement);
                mn.instructions.remove(insn);
                changed++;
            }
        }
        return changed;
    }

    private int rewriteDecodedZeroBranches(
        PipelineContext pctx,
        MethodNode mn,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        Map<LocalKey, LocalShadow> shadows
    ) {
        Map<Integer, LocalShadow> intShadowsByShadowLocal = new LinkedHashMap<>();
        for (LocalShadow shadow : shadows.values()) {
            if (shadow.kind == LocalKind.INT && shadow.shadowLocal >= 0) {
                intShadowsByShadowLocal.put(shadow.shadowLocal, shadow);
            }
        }
        if (intShadowsByShadowLocal.isEmpty()) return 0;

        int changed = 0;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof JumpInsnNode jump)) continue;
            int opcode = jump.getOpcode();
            if (opcode != Opcodes.IFEQ && opcode != Opcodes.IFNE) continue;

            AbstractInsnNode xor = previousReal(insn.getPrevious());
            if (xor == null || xor.getOpcode() != Opcodes.IXOR) continue;
            AbstractInsnNode maskCall = previousReal(xor.getPrevious());
            if (!isRuntimeMaskCall(maskCall, maskHelper)) continue;
            AbstractInsnNode seedLoad = previousReal(maskCall.getPrevious());
            if (!(seedLoad instanceof VarInsnNode seedVar)
                    || seedVar.getOpcode() != Opcodes.LLOAD
                    || seedVar.var != metadata.keyLocal()) {
                continue;
            }
            AbstractInsnNode seedConst = previousReal(seedLoad.getPrevious());
            if (seedConst == null) continue;
            AbstractInsnNode shadowLoad = previousReal(seedConst.getPrevious());
            if (!(shadowLoad instanceof VarInsnNode shadowVar) || shadowVar.getOpcode() != Opcodes.ILOAD) continue;
            LocalShadow shadow = intShadowsByShadowLocal.get(shadowVar.var);
            if (shadow == null) continue;

            InsnList replacement = new InsnList();
            replacement.add(new VarInsnNode(Opcodes.ILOAD, shadow.shadowLocal));
            emitStableMaskInt(replacement, metadata, maskHelper, shadow);
            replacement.add(new JumpInsnNode(opcode == Opcodes.IFEQ ? Opcodes.IF_ICMPEQ : Opcodes.IF_ICMPNE, jump.label));
            JvmKeyDispatchPass.markGenerated(pctx, replacement);
            mn.instructions.insertBefore(shadowLoad, replacement);
            mn.instructions.remove(shadowLoad);
            mn.instructions.remove(seedConst);
            mn.instructions.remove(seedLoad);
            mn.instructions.remove(maskCall);
            mn.instructions.remove(xor);
            mn.instructions.remove(insn);
            changed++;
        }
        return changed;
    }

    private void emitInitialShadow(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        LocalShadow shadow
    ) {
        switch (shadow.kind) {
            case INT, FLOAT -> {
                emitStableMaskInt(insns, metadata, maskHelper, shadow);
                insns.add(new VarInsnNode(Opcodes.ISTORE, shadow.shadowLocal));
            }
            case LONG, DOUBLE -> {
                emitStableMaskLong(insns, metadata, maskHelper, shadow);
                insns.add(new VarInsnNode(Opcodes.LSTORE, shadow.shadowLocal));
            }
            case REF -> throw new IllegalStateException("reference locals are not shadowed");
        }
    }

    private void emitDefaultShadow(InsnList insns, LocalShadow shadow) {
        if (shadow.kind == LocalKind.REF) {
            insns.add(new InsnNode(Opcodes.ICONST_0));
            insns.add(new VarInsnNode(Opcodes.ISTORE, shadow.shadowLocal));
            return;
        }
        emitDefaultShadowValue(insns, shadow.kind, shadow.shadowLocal);
    }

    private void emitDefaultShadowValue(InsnList insns, LocalKind kind, int local) {
        switch (kind) {
            case INT, FLOAT -> {
                insns.add(new InsnNode(Opcodes.ICONST_0));
                insns.add(new VarInsnNode(Opcodes.ISTORE, local));
            }
            case LONG, DOUBLE -> {
                insns.add(new InsnNode(Opcodes.LCONST_0));
                insns.add(new VarInsnNode(Opcodes.LSTORE, local));
            }
            case REF -> {
                insns.add(new InsnNode(Opcodes.ACONST_NULL));
                insns.add(new VarInsnNode(Opcodes.ASTORE, local));
            }
        }
    }

    private void emitOriginalPoison(InsnList insns, LocalShadow shadow) {
        switch (shadow.kind) {
            case INT -> {
                insns.add(new InsnNode(Opcodes.ICONST_0));
                insns.add(new VarInsnNode(Opcodes.ISTORE, shadow.var));
            }
            case LONG -> {
                insns.add(new InsnNode(Opcodes.LCONST_0));
                insns.add(new VarInsnNode(Opcodes.LSTORE, shadow.var));
            }
            case FLOAT -> {
                insns.add(new InsnNode(Opcodes.FCONST_0));
                insns.add(new VarInsnNode(Opcodes.FSTORE, shadow.var));
            }
            case DOUBLE -> {
                insns.add(new InsnNode(Opcodes.DCONST_0));
                insns.add(new VarInsnNode(Opcodes.DSTORE, shadow.var));
            }
            case REF -> {
                insns.add(new InsnNode(Opcodes.ACONST_NULL));
                insns.add(new VarInsnNode(Opcodes.ASTORE, shadow.var));
            }
        }
    }

    private void emitStoreShadowFromStack(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        LocalShadow shadow
    ) {
        switch (shadow.kind) {
            case INT -> {
                emitStableMaskInt(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ISTORE, shadow.shadowLocal));
            }
            case LONG -> {
                emitStableMaskLong(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.LXOR));
                insns.add(new VarInsnNode(Opcodes.LSTORE, shadow.shadowLocal));
            }
            case FLOAT -> {
                insns.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/Float",
                    "floatToRawIntBits",
                    "(F)I",
                    false
                ));
                emitStableMaskInt(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ISTORE, shadow.shadowLocal));
            }
            case DOUBLE -> {
                insns.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/Double",
                    "doubleToRawLongBits",
                    "(D)J",
                    false
                ));
                emitStableMaskLong(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.LXOR));
                insns.add(new VarInsnNode(Opcodes.LSTORE, shadow.shadowLocal));
            }
            case REF -> throw new IllegalStateException("reference locals are not shadowed");
        }
    }

    private void emitLoadFromShadow(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        LocalShadow shadow,
        String refCast
    ) {
        switch (shadow.kind) {
            case INT -> {
                insns.add(new VarInsnNode(Opcodes.ILOAD, shadow.shadowLocal));
                emitStableMaskInt(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.IXOR));
            }
            case LONG -> {
                insns.add(new VarInsnNode(Opcodes.LLOAD, shadow.shadowLocal));
                emitStableMaskLong(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.LXOR));
            }
            case FLOAT -> {
                insns.add(new VarInsnNode(Opcodes.ILOAD, shadow.shadowLocal));
                emitStableMaskInt(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/Float",
                    "intBitsToFloat",
                    "(I)F",
                    false
                ));
            }
            case DOUBLE -> {
                insns.add(new VarInsnNode(Opcodes.LLOAD, shadow.shadowLocal));
                emitStableMaskLong(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.LXOR));
                insns.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/Double",
                    "longBitsToDouble",
                    "(J)D",
                    false
                ));
            }
            case REF -> throw new IllegalStateException("reference locals are not shadowed");
        }
    }

    private AbstractInsnNode methodEntryPoint(MethodNode mn) {
        AbstractInsnNode first = nextReal(mn.instructions.getFirst());
        if (!"<init>".equals(mn.name)) return first;
        for (AbstractInsnNode insn = first; insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call &&
                call.getOpcode() == Opcodes.INVOKESPECIAL &&
                "<init>".equals(call.name)) {
                return nextReal(call.getNext());
            }
        }
        return first;
    }

    private AbstractInsnNode firstApplicationInstruction(
        MethodNode mn,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (metadata.applicationInstructions().contains(insn)) return insn;
        }
        return methodEntryPoint(mn);
    }

    private AbstractInsnNode nextReal(AbstractInsnNode insn) {
        for (AbstractInsnNode cursor = insn; cursor != null; cursor = cursor.getNext()) {
            if (cursor.getOpcode() >= 0) return cursor;
        }
        return null;
    }

    private boolean before(AbstractInsnNode left, AbstractInsnNode right) {
        for (AbstractInsnNode cursor = left; cursor != null; cursor = cursor.getNext()) {
            if (cursor == right) return true;
        }
        return false;
    }

    private void emitRekeyShadowForPendingKey(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        LocalShadow shadow
    ) {
        insns.add(new InsnNode(Opcodes.DUP2));
        switch (shadow.kind) {
            case INT, FLOAT -> {
                emitStableMaskIntFromStack(insns, metadata, maskHelper, shadow);
                insns.add(new VarInsnNode(Opcodes.ILOAD, shadow.shadowLocal));
                emitStableMaskInt(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ISTORE, shadow.shadowLocal));
            }
            case LONG, DOUBLE -> {
                emitStableMaskLongFromStack(insns, metadata, maskHelper, shadow);
                insns.add(new VarInsnNode(Opcodes.LLOAD, shadow.shadowLocal));
                emitStableMaskLong(insns, metadata, maskHelper, shadow);
                insns.add(new InsnNode(Opcodes.LXOR));
                insns.add(new InsnNode(Opcodes.LXOR));
                insns.add(new VarInsnNode(Opcodes.LSTORE, shadow.shadowLocal));
            }
            case REF -> throw new IllegalStateException("reference shadow cannot be primitive rekeyed");
        }
    }

    private void emitStableMaskLong(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        LocalShadow shadow
    ) {
        emitStableMaskInt(insns, metadata, maskHelper, shadow.withDomain(0x48494748));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        emitStableMaskInt(insns, metadata, maskHelper, shadow.withDomain(0x4C4F574B));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    private void emitStableMaskLongFromStack(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        LocalShadow shadow
    ) {
        insns.add(new InsnNode(Opcodes.DUP2));
        emitStableMaskIntFromStack(insns, metadata, maskHelper, shadow.withDomain(0x48494748));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.DUP2_X2));
        insns.add(new InsnNode(Opcodes.POP2));
        emitStableMaskIntFromStack(insns, metadata, maskHelper, shadow.withDomain(0x4C4F574B));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    private void emitStableMaskInt(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        LocalShadow shadow
    ) {
        long seed = JvmPassBytecode.mix(
            metadata.methodSeed() ^ 0x52564F4D41534B31L,
            ((long) shadow.var << 32) ^ maskKindDomain(shadow) ^ shadow.domain
        );
        JvmPassBytecode.pushInt(
            insns,
            (int) seed ^ Integer.rotateLeft((int) (seed >>> 32), 11)
        );
        insns.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            maskHelper.owner(),
            maskHelper.name(),
            RUNTIME_MASK_HELPER_DESC,
            maskHelper.interfaceOwner()
        ));
    }

    private void emitStableMaskIntFromStack(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        RuntimeMaskHelper maskHelper,
        LocalShadow shadow
    ) {
        long seed = JvmPassBytecode.mix(
            metadata.methodSeed() ^ 0x52564F4D41534B31L,
            ((long) shadow.var << 32) ^ maskKindDomain(shadow) ^ shadow.domain
        );
        JvmPassBytecode.pushInt(
            insns,
            (int) seed ^ Integer.rotateLeft((int) (seed >>> 32), 11)
        );
        insns.add(new InsnNode(Opcodes.DUP_X2));
        insns.add(new InsnNode(Opcodes.POP));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            maskHelper.owner(),
            maskHelper.name(),
            RUNTIME_MASK_HELPER_DESC,
            maskHelper.interfaceOwner()
        ));
    }

    private boolean isRuntimeMaskCall(AbstractInsnNode insn, RuntimeMaskHelper maskHelper) {
        return insn instanceof MethodInsnNode call
            && call.getOpcode() == Opcodes.INVOKESTATIC
            && call.owner.equals(maskHelper.owner())
            && call.name.equals(maskHelper.name())
            && call.desc.equals(RUNTIME_MASK_HELPER_DESC)
            && call.itf == maskHelper.interfaceOwner();
    }

    private RuntimeMaskHelper ensureRuntimeMaskHelper(
        PipelineContext pctx,
        L1Class clazz,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        String base = "__neko_rv_mask$" + Integer.toUnsignedString(
            (int) JvmPassBytecode.mix(
                metadata.classKeyTable().objectFieldName().hashCode(),
                metadata.classKeyTable().intHelperName().hashCode() ^ 0x52564D41534B48L
            ),
            36
        );
        String name = base;
        int suffix = 0;
        while (true) {
            MethodNode existing = findMethod(clazz, name, RUNTIME_MASK_HELPER_DESC);
            if (existing != null) {
                return new RuntimeMaskHelper(clazz.name(), name, clazz.isInterface());
            }
            if (findMethodByName(clazz, name) == null) break;
            name = base + "$" + (++suffix);
        }

        ControlFlowFlatteningPass.CffClassKeyTable table = metadata.classKeyTable();
        MethodNode helper = new MethodNode(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
            name,
            RUNTIME_MASK_HELPER_DESC,
            null,
            null
        );
        int seedLocal = 0;
        int keyLocal = 1;
        InsnList insns = helper.instructions;
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            table.owner(),
            table.objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        emitRuntimeMaskSeedMix(insns, seedLocal, 0x47554152);
        emitRuntimeMaskSeedMix(insns, seedLocal, 0x50415448);
        emitRuntimeMaskSeedMix(insns, seedLocal, 0x424C4F43);
        emitRuntimeMaskSeedMix(insns, seedLocal, 0x444F4D58);
        emitRuntimeMaskSeedMix(insns, seedLocal, 0x50434641);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        emitRuntimeMaskSeedMix(insns, seedLocal, 0x44494745);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            table.intHelperOwner(),
            table.intHelperName(),
            "([IIIIIII)I",
            table.intHelperInterfaceOwner()
        ));
        emitRuntimeMaskSeedMix(insns, seedLocal, 0x4D554C54);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        emitRuntimeMaskSeedMix(insns, seedLocal, 0x584F524D);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 3;
        helper.maxStack = 12;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        return new RuntimeMaskHelper(clazz.name(), name, clazz.isInterface());
    }

    private void emitRuntimeMaskSeedMix(
        InsnList insns,
        int seedLocal,
        int salt
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, seedLocal));
        JvmPassBytecode.pushInt(insns, salt);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, seedLocal));
        JvmPassBytecode.pushInt(insns, 13 + (salt & 15));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, seedLocal));
        JvmPassBytecode.pushInt(insns, 19 - (salt & 15));
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IOR));
        JvmPassBytecode.pushInt(insns, (MASK_B ^ salt) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, MASK_D ^ Integer.rotateLeft(salt, 11));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private int maskKindDomain(LocalShadow shadow) {
        return shadow.kind.ordinal();
    }

    private MethodNode findMethod(L1Class clazz, String name, String desc) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (name.equals(method.name) && desc.equals(method.desc)) return method;
        }
        return null;
    }

    private MethodNode findMethodByName(L1Class clazz, String name) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (name.equals(method.name)) return method;
        }
        return null;
    }

    private AbstractInsnNode previousReal(AbstractInsnNode insn) {
        for (AbstractInsnNode cursor = insn; cursor != null; cursor = cursor.getPrevious()) {
            if (cursor.getOpcode() >= 0) return cursor;
        }
        return null;
    }

    private Map<AbstractInsnNode, String> analyzeReferenceLoadCasts(String owner, MethodNode mn) {
        Map<AbstractInsnNode, String> casts = new java.util.IdentityHashMap<>();
        try {
            Analyzer<BasicValue> analyzer = new Analyzer<>(new RuntimeVariableTypeInterpreter());
            Frame<BasicValue>[] frames = analyzer.analyze(owner, mn);
            AbstractInsnNode[] insns = mn.instructions.toArray();
            for (int i = 0; i < insns.length; i++) {
                AbstractInsnNode insn = insns[i];
                if (!(insn instanceof VarInsnNode var) || var.getOpcode() != Opcodes.ALOAD) continue;
                Frame<BasicValue> frame = frames[i];
                if (frame == null || var.var >= frame.getLocals()) continue;
                BasicValue value = frame.getLocal(var.var);
                if (value == null) continue;
                String cast = referenceCast(value.getType());
                if (cast != null) casts.put(insn, cast);
            }
        } catch (AnalyzerException | RuntimeException ignored) {
            casts.clear();
        }
        try {
            Analyzer<SourceValue> analyzer = new Analyzer<>(new SourceInterpreter());
            Frame<SourceValue>[] frames = analyzer.analyze(owner, mn);
            AbstractInsnNode[] insns = mn.instructions.toArray();
            for (int i = 0; i < insns.length; i++) {
                AbstractInsnNode insn = insns[i];
                Frame<SourceValue> frame = frames[i];
                if (frame == null) continue;
                if (insn instanceof MethodInsnNode call) {
                    bindMethodConsumerCasts(casts, frame, call);
                } else if (insn instanceof InvokeDynamicInsnNode indy) {
                    bindDynamicConsumerCasts(casts, frame, indy);
                } else if (insn instanceof FieldInsnNode field) {
                    bindFieldConsumerCasts(casts, frame, field);
                } else {
                    bindArrayConsumerCasts(casts, frame, insn);
                }
            }
        } catch (AnalyzerException | RuntimeException ignored) {
        }
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                String cast = directReferenceConsumerCast(insn, mn);
                if (cast == null) {
                    cast = linearReferenceConsumerCast(insn, mn);
                }
                if (cast != null) casts.put(insn, cast);
            }
        }
        return casts;
    }

    private String directReferenceConsumerCast(AbstractInsnNode load, MethodNode mn) {
        AbstractInsnNode next = nextReal(load.getNext());
        if (next instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
            return null;
        }
        if (next instanceof MethodInsnNode call) {
            Type[] args = Type.getArgumentTypes(call.desc);
            if (args.length > 0) {
                return referenceCast(args[args.length - 1]);
            }
            return call.getOpcode() == Opcodes.INVOKESTATIC ? null : call.owner;
        }
        if (next instanceof InvokeDynamicInsnNode indy) {
            Type[] args = Type.getArgumentTypes(indy.desc);
            return args.length == 0 ? null : referenceCast(args[args.length - 1]);
        }
        if (next instanceof FieldInsnNode field) {
            return switch (field.getOpcode()) {
                case Opcodes.GETFIELD -> field.owner;
                case Opcodes.PUTFIELD -> referenceCast(Type.getType(field.desc));
                default -> null;
            };
        }
        String arrayCast = arrayLoadCast(next == null ? -1 : next.getOpcode());
        if (arrayCast != null) {
            return arrayCast;
        }
        if (next != null && next.getOpcode() == Opcodes.ARRAYLENGTH) {
            return "[Ljava/lang/Object;";
        }
        if (next != null && next.getOpcode() == Opcodes.ARETURN) {
            return referenceCast(Type.getReturnType(mn.desc));
        }
        return null;
    }

    private String linearReferenceConsumerCast(AbstractInsnNode load, MethodNode mn) {
        List<Boolean> stack = new ArrayList<>();
        stack.add(Boolean.TRUE);
        int steps = 0;
        for (AbstractInsnNode insn = nextReal(load.getNext()); insn != null && steps++ < 128; insn = nextReal(insn.getNext())) {
            if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST && topTracked(stack)) {
                return null;
            }
            String methodCast = linearMethodConsumerCast(stack, insn);
            if (methodCast != NO_CAST_SENTINEL) {
                return methodCast;
            }
            String fieldCast = linearFieldConsumerCast(stack, insn);
            if (fieldCast != NO_CAST_SENTINEL) {
                return fieldCast;
            }
            String arrayCast = linearArrayConsumerCast(stack, insn);
            if (arrayCast != NO_CAST_SENTINEL) {
                return arrayCast;
            }
            String terminalCast = linearTerminalConsumerCast(stack, insn, mn);
            if (terminalCast != NO_CAST_SENTINEL) {
                return terminalCast;
            }
            if (!applyLinearStackEffect(stack, insn)) {
                return null;
            }
            if (!stack.contains(Boolean.TRUE) || stack.size() > 64) {
                return null;
            }
        }
        return null;
    }

    private static final String NO_CAST_SENTINEL = "\u0000";

    private String linearMethodConsumerCast(List<Boolean> stack, AbstractInsnNode insn) {
        if (insn instanceof MethodInsnNode call) {
            List<String> operands = new ArrayList<>();
            if (call.getOpcode() != Opcodes.INVOKESTATIC) {
                operands.add(call.owner);
            }
            for (Type arg : Type.getArgumentTypes(call.desc)) {
                operands.add(referenceCast(arg));
            }
            int tracked = trackedConsumedIndex(stack, operands.size());
            if (tracked >= 0) {
                String cast = operands.get(tracked);
                return cast == null || "java/lang/Object".equals(cast) ? null : cast;
            }
        } else if (insn instanceof InvokeDynamicInsnNode indy) {
            Type[] args = Type.getArgumentTypes(indy.desc);
            List<String> operands = new ArrayList<>();
            for (Type arg : args) {
                operands.add(referenceCast(arg));
            }
            int tracked = trackedConsumedIndex(stack, operands.size());
            if (tracked >= 0) {
                String cast = operands.get(tracked);
                return cast == null || "java/lang/Object".equals(cast) ? null : cast;
            }
        }
        return NO_CAST_SENTINEL;
    }

    private String linearFieldConsumerCast(List<Boolean> stack, AbstractInsnNode insn) {
        if (!(insn instanceof FieldInsnNode field)) return NO_CAST_SENTINEL;
        int opcode = field.getOpcode();
        if (opcode == Opcodes.GETFIELD && trackedConsumedIndex(stack, 1) == 0) {
            return field.owner;
        }
        if (opcode == Opcodes.PUTFIELD) {
            int tracked = trackedConsumedIndex(stack, 2);
            if (tracked == 0) return field.owner;
            if (tracked == 1) {
                String cast = referenceCast(Type.getType(field.desc));
                return cast == null || "java/lang/Object".equals(cast) ? null : cast;
            }
        }
        if (opcode == Opcodes.PUTSTATIC && trackedConsumedIndex(stack, 1) == 0) {
            String cast = referenceCast(Type.getType(field.desc));
            return cast == null || "java/lang/Object".equals(cast) ? null : cast;
        }
        return NO_CAST_SENTINEL;
    }

    private String linearArrayConsumerCast(List<Boolean> stack, AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        String loadCast = arrayLoadCast(opcode);
        if (loadCast != null && trackedConsumedIndex(stack, 2) == 0) {
            return loadCast;
        }
        String storeCast = arrayStoreCast(opcode);
        if (storeCast != null && trackedConsumedIndex(stack, 3) == 0) {
            return storeCast;
        }
        if (opcode == Opcodes.ARRAYLENGTH && trackedConsumedIndex(stack, 1) == 0) {
            return "[Ljava/lang/Object;";
        }
        return NO_CAST_SENTINEL;
    }

    private String linearTerminalConsumerCast(List<Boolean> stack, AbstractInsnNode insn, MethodNode mn) {
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.ARETURN && trackedConsumedIndex(stack, 1) == 0) {
            String cast = referenceCast(Type.getReturnType(mn.desc));
            return cast == null || "java/lang/Object".equals(cast) ? null : cast;
        }
        if ((opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT || opcode == Opcodes.ATHROW)
                && trackedConsumedIndex(stack, 1) == 0) {
            return null;
        }
        return NO_CAST_SENTINEL;
    }

    private int trackedConsumedIndex(List<Boolean> stack, int consumed) {
        if (consumed <= 0 || stack.size() < consumed) return -1;
        int start = stack.size() - consumed;
        for (int i = 0; i < consumed; i++) {
            if (Boolean.TRUE.equals(stack.get(start + i))) return i;
        }
        return -1;
    }

    private boolean topTracked(List<Boolean> stack) {
        return !stack.isEmpty() && Boolean.TRUE.equals(stack.get(stack.size() - 1));
    }

    private boolean applyLinearStackEffect(List<Boolean> stack, AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode < 0) return true;
        if (insn instanceof MethodInsnNode call) {
            int consumed = Type.getArgumentTypes(call.desc).length
                + (call.getOpcode() == Opcodes.INVOKESTATIC ? 0 : 1);
            return popPush(stack, consumed, Type.getReturnType(call.desc).getSort() == Type.VOID ? 0 : 1);
        }
        if (insn instanceof InvokeDynamicInsnNode indy) {
            return popPush(stack, Type.getArgumentTypes(indy.desc).length,
                Type.getReturnType(indy.desc).getSort() == Type.VOID ? 0 : 1);
        }
        if (insn instanceof FieldInsnNode field) {
            return switch (field.getOpcode()) {
                case Opcodes.GETSTATIC -> popPush(stack, 0, 1);
                case Opcodes.PUTSTATIC -> popPush(stack, 1, 0);
                case Opcodes.GETFIELD -> popPush(stack, 1, 1);
                case Opcodes.PUTFIELD -> popPush(stack, 2, 0);
                default -> false;
            };
        }
        if (insn instanceof VarInsnNode var) {
            return switch (var.getOpcode()) {
                case Opcodes.ILOAD, Opcodes.FLOAD, Opcodes.ALOAD, Opcodes.LLOAD, Opcodes.DLOAD -> popPush(stack, 0, 1);
                case Opcodes.ISTORE, Opcodes.FSTORE, Opcodes.ASTORE, Opcodes.LSTORE, Opcodes.DSTORE -> popPush(stack, 1, 0);
                default -> false;
            };
        }
        if (insn instanceof LdcInsnNode || insn instanceof IntInsnNode) {
            return popPush(stack, 0, 1);
        }
        if (insn instanceof TypeInsnNode type) {
            return switch (type.getOpcode()) {
                case Opcodes.NEW -> popPush(stack, 0, 1);
                case Opcodes.ANEWARRAY, Opcodes.CHECKCAST, Opcodes.INSTANCEOF -> popPush(stack, 1, 1);
                default -> false;
            };
        }
        if (insn instanceof MultiANewArrayInsnNode multi) {
            return popPush(stack, multi.dims, 1);
        }
        if (insn instanceof JumpInsnNode || insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) {
            return false;
        }
        return switch (opcode) {
            case Opcodes.ACONST_NULL,
                Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2, Opcodes.ICONST_3,
                Opcodes.ICONST_4, Opcodes.ICONST_5, Opcodes.LCONST_0, Opcodes.LCONST_1,
                Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2, Opcodes.DCONST_0, Opcodes.DCONST_1 ->
                popPush(stack, 0, 1);
            case Opcodes.IALOAD, Opcodes.LALOAD, Opcodes.FALOAD, Opcodes.DALOAD, Opcodes.AALOAD,
                Opcodes.BALOAD, Opcodes.CALOAD, Opcodes.SALOAD -> popPush(stack, 2, 1);
            case Opcodes.IASTORE, Opcodes.LASTORE, Opcodes.FASTORE, Opcodes.DASTORE, Opcodes.AASTORE,
                Opcodes.BASTORE, Opcodes.CASTORE, Opcodes.SASTORE -> popPush(stack, 3, 0);
            case Opcodes.POP -> popPush(stack, 1, 0);
            case Opcodes.POP2 -> popPush(stack, 1, 0);
            case Opcodes.DUP -> duplicateTop(stack);
            case Opcodes.SWAP -> swapTop(stack);
            case Opcodes.IADD, Opcodes.LADD, Opcodes.FADD, Opcodes.DADD,
                Opcodes.ISUB, Opcodes.LSUB, Opcodes.FSUB, Opcodes.DSUB,
                Opcodes.IMUL, Opcodes.LMUL, Opcodes.FMUL, Opcodes.DMUL,
                Opcodes.IDIV, Opcodes.LDIV, Opcodes.FDIV, Opcodes.DDIV,
                Opcodes.IREM, Opcodes.LREM, Opcodes.FREM, Opcodes.DREM,
                Opcodes.ISHL, Opcodes.LSHL, Opcodes.ISHR, Opcodes.LSHR,
                Opcodes.IUSHR, Opcodes.LUSHR, Opcodes.IAND, Opcodes.LAND,
                Opcodes.IOR, Opcodes.LOR, Opcodes.IXOR, Opcodes.LXOR,
                Opcodes.LCMP, Opcodes.FCMPL, Opcodes.FCMPG, Opcodes.DCMPL, Opcodes.DCMPG ->
                popPush(stack, 2, 1);
            case Opcodes.INEG, Opcodes.LNEG, Opcodes.FNEG, Opcodes.DNEG,
                Opcodes.I2L, Opcodes.I2F, Opcodes.I2D, Opcodes.L2I, Opcodes.L2F, Opcodes.L2D,
                Opcodes.F2I, Opcodes.F2L, Opcodes.F2D, Opcodes.D2I, Opcodes.D2L, Opcodes.D2F,
                Opcodes.I2B, Opcodes.I2C, Opcodes.I2S, Opcodes.ARRAYLENGTH ->
                popPush(stack, 1, 1);
            case Opcodes.IRETURN, Opcodes.LRETURN, Opcodes.FRETURN, Opcodes.DRETURN,
                Opcodes.ARETURN, Opcodes.ATHROW, Opcodes.MONITORENTER, Opcodes.MONITOREXIT ->
                popPush(stack, 1, 0);
            case Opcodes.RETURN, Opcodes.NOP -> true;
            default -> false;
        };
    }

    private boolean popPush(List<Boolean> stack, int consumed, int pushed) {
        if (stack.size() < consumed) return false;
        for (int i = 0; i < consumed; i++) {
            stack.remove(stack.size() - 1);
        }
        for (int i = 0; i < pushed; i++) {
            stack.add(Boolean.FALSE);
        }
        return true;
    }

    private boolean duplicateTop(List<Boolean> stack) {
        if (stack.isEmpty()) return false;
        stack.add(stack.get(stack.size() - 1));
        return true;
    }

    private boolean swapTop(List<Boolean> stack) {
        if (stack.size() < 2) return false;
        int top = stack.size() - 1;
        Boolean value = stack.get(top);
        stack.set(top, stack.get(top - 1));
        stack.set(top - 1, value);
        return true;
    }

    private void bindMethodConsumerCasts(
        Map<AbstractInsnNode, String> casts,
        Frame<SourceValue> frame,
        MethodInsnNode call
    ) {
        Type[] args = Type.getArgumentTypes(call.desc);
        int stack = frame.getStackSize();
        for (int i = args.length - 1; i >= 0; i--) {
            Type arg = args[i];
            stack--;
            String cast = referenceCast(arg);
            if (cast != null && stack >= 0 && stack < frame.getStackSize()) {
                bindSourceCast(casts, frame.getStack(stack), cast);
            }
        }
        if (call.getOpcode() != Opcodes.INVOKESTATIC && stack > 0) {
            bindSourceCast(casts, frame.getStack(stack - 1), call.owner);
        }
    }

    private void bindDynamicConsumerCasts(
        Map<AbstractInsnNode, String> casts,
        Frame<SourceValue> frame,
        InvokeDynamicInsnNode indy
    ) {
        Type[] args = Type.getArgumentTypes(indy.desc);
        int stack = frame.getStackSize();
        for (int i = args.length - 1; i >= 0; i--) {
            Type arg = args[i];
            stack--;
            String cast = referenceCast(arg);
            if (cast != null && stack >= 0 && stack < frame.getStackSize()) {
                bindSourceCast(casts, frame.getStack(stack), cast);
            }
        }
    }

    private void bindFieldConsumerCasts(
        Map<AbstractInsnNode, String> casts,
        Frame<SourceValue> frame,
        FieldInsnNode field
    ) {
        int stack = frame.getStackSize();
        switch (field.getOpcode()) {
            case Opcodes.GETFIELD -> {
                if (stack > 0) {
                    bindSourceCast(casts, frame.getStack(stack - 1), field.owner);
                }
            }
            case Opcodes.PUTFIELD -> {
                if (stack > 1) {
                    bindSourceCast(casts, frame.getStack(stack - 2), field.owner);
                    bindSourceCast(casts, frame.getStack(stack - 1), referenceCast(Type.getType(field.desc)));
                }
            }
            case Opcodes.PUTSTATIC -> {
                if (stack > 0) {
                    bindSourceCast(casts, frame.getStack(stack - 1), referenceCast(Type.getType(field.desc)));
                }
            }
            default -> {
            }
        }
    }

    private void bindArrayConsumerCasts(
        Map<AbstractInsnNode, String> casts,
        Frame<SourceValue> frame,
        AbstractInsnNode insn
    ) {
        int opcode = insn.getOpcode();
        String loadCast = arrayLoadCast(opcode);
        int stack = frame.getStackSize();
        if (loadCast != null) {
            if (stack >= 2) {
                bindSourceCast(casts, frame.getStack(stack - 2), loadCast);
            }
            return;
        }
        String storeCast = arrayStoreCast(opcode);
        if (storeCast != null) {
            if (stack >= 3) {
                bindSourceCast(casts, frame.getStack(stack - 3), storeCast);
            }
            return;
        }
        if (opcode == Opcodes.ARRAYLENGTH && stack >= 1) {
            bindSourceCast(casts, frame.getStack(stack - 1), "[Ljava/lang/Object;");
        }
    }

    private String arrayLoadCast(int opcode) {
        return switch (opcode) {
            case Opcodes.IALOAD -> "[I";
            case Opcodes.LALOAD -> "[J";
            case Opcodes.FALOAD -> "[F";
            case Opcodes.DALOAD -> "[D";
            case Opcodes.AALOAD -> "[Ljava/lang/Object;";
            case Opcodes.BALOAD -> "[B";
            case Opcodes.CALOAD -> "[C";
            case Opcodes.SALOAD -> "[S";
            default -> null;
        };
    }

    private String arrayStoreCast(int opcode) {
        return switch (opcode) {
            case Opcodes.IASTORE -> "[I";
            case Opcodes.LASTORE -> "[J";
            case Opcodes.FASTORE -> "[F";
            case Opcodes.DASTORE -> "[D";
            case Opcodes.AASTORE -> "[Ljava/lang/Object;";
            case Opcodes.BASTORE -> "[B";
            case Opcodes.CASTORE -> "[C";
            case Opcodes.SASTORE -> "[S";
            default -> null;
        };
    }

    private void bindSourceCast(Map<AbstractInsnNode, String> casts, SourceValue value, String cast) {
        if (value == null || cast == null) return;
        for (AbstractInsnNode source : value.insns) {
            if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                casts.put(source, cast);
            }
        }
    }

    private String referenceCast(Type type) {
        if (type == null) return null;
        if (type.getSort() == Type.OBJECT) {
            String name = type.getInternalName();
            return "java/lang/Object".equals(name) ? null : name;
        }
        if (type.getSort() == Type.ARRAY) {
            return type.getDescriptor();
        }
        return null;
    }

    private boolean isReservedLocal(
        int local,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        return local == metadata.keyLocal()
            || local == metadata.keyLocal() + 1
            || local == metadata.guardLocal()
            || local == metadata.pathKeyLocal()
            || local == metadata.blockKeyLocal()
            || local == metadata.pcLocal()
            || local == metadata.domainLocal()
            || local == metadata.dataLocal();
    }

    private LocalKind kindForVarOpcode(int opcode) {
        return switch (opcode) {
            case Opcodes.ILOAD, Opcodes.ISTORE -> LocalKind.INT;
            case Opcodes.LLOAD, Opcodes.LSTORE -> LocalKind.LONG;
            case Opcodes.FLOAD, Opcodes.FSTORE -> LocalKind.FLOAT;
            case Opcodes.DLOAD, Opcodes.DSTORE -> LocalKind.DOUBLE;
            case Opcodes.ALOAD, Opcodes.ASTORE -> LocalKind.REF;
            default -> null;
        };
    }

    private LocalKind kindForLoadOpcode(int opcode) {
        return switch (opcode) {
            case Opcodes.ILOAD -> LocalKind.INT;
            case Opcodes.LLOAD -> LocalKind.LONG;
            case Opcodes.FLOAD -> LocalKind.FLOAT;
            case Opcodes.DLOAD -> LocalKind.DOUBLE;
            case Opcodes.ALOAD -> LocalKind.REF;
            default -> null;
        };
    }

    private boolean isLoadOpcode(int opcode) {
        return opcode == Opcodes.ILOAD
            || opcode == Opcodes.LLOAD
            || opcode == Opcodes.FLOAD
            || opcode == Opcodes.DLOAD
            || opcode == Opcodes.ALOAD;
    }

    private boolean isStoreOpcode(int opcode) {
        return opcode == Opcodes.ISTORE
            || opcode == Opcodes.LSTORE
            || opcode == Opcodes.FSTORE
            || opcode == Opcodes.DSTORE
            || opcode == Opcodes.ASTORE;
    }

    private int nonZeroInt(long value) {
        int v = (int) value;
        return v == 0 ? 0x52564F31 : v;
    }

    private enum LocalKind {
        INT(1, true),
        LONG(2, true),
        FLOAT(1, true),
        DOUBLE(2, true),
        REF(1, false);

        private final int shadowSize;
        private final boolean primitive;

        LocalKind(int shadowSize, boolean primitive) {
            this.shadowSize = shadowSize;
            this.primitive = primitive;
        }

        int shadowSize() {
            return shadowSize;
        }

        boolean primitive() {
            return primitive;
        }
    }

    private record LocalKey(int var, LocalKind kind) {}

    private record RuntimeMaskHelper(String owner, String name, boolean interfaceOwner) {}

    private static final class RuntimeVariableTypeInterpreter extends BasicInterpreter {
        RuntimeVariableTypeInterpreter() {
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
                if (cst instanceof String) {
                    return newValue(Type.getType(String.class));
                }
                if (cst instanceof Type type) {
                    int sort = type.getSort();
                    if (sort == Type.OBJECT || sort == Type.ARRAY || sort == Type.METHOD) {
                        return BasicValue.REFERENCE_VALUE;
                    }
                }
            }
            return super.newOperation(insn);
        }

        @Override
        public BasicValue unaryOperation(AbstractInsnNode insn, BasicValue value) throws AnalyzerException {
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.CHECKCAST) {
                String desc = ((TypeInsnNode) insn).desc;
                return newValue(desc.startsWith("[") ? Type.getType(desc) : Type.getObjectType(desc));
            }
            if (opcode == Opcodes.ANEWARRAY) {
                String desc = ((TypeInsnNode) insn).desc;
                Type element = desc.startsWith("[") ? Type.getType(desc) : Type.getObjectType(desc);
                return newValue(Type.getType("[" + element.getDescriptor()));
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
            if (insn instanceof MultiANewArrayInsnNode multi) {
                return newValue(Type.getType(multi.desc));
            }
            if (insn instanceof MethodInsnNode method) {
                return newValue(Type.getReturnType(method.desc));
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
            return type != null && (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY);
        }
    }

    private static final class LocalShadow {
        private final int var;
        private final LocalKind kind;
        private final int domain;
        private int shadowLocal = -1;
        private boolean reusedOriginalShadow;

        LocalShadow(int var, LocalKind kind) {
            this(var, kind, 0);
        }

        LocalShadow(int var, LocalKind kind, int domain) {
            this.var = var;
            this.kind = kind;
            this.domain = domain;
        }

        LocalShadow withDomain(int domain) {
            LocalShadow copy = new LocalShadow(var, kind, domain);
            copy.shadowLocal = shadowLocal;
            copy.reusedOriginalShadow = reusedOriginalShadow;
            return copy;
        }

        int var() {
            return var;
        }

    }
}
