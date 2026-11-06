package dev.nekoobfuscator.transforms.jvm.validation;

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
import dev.nekoobfuscator.transforms.util.JvmObfuscationCoverage;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Replaces compact validation sinks with CFF-live keyed staged checks.
 */
public final class JvmValidationSinkHardeningPass implements TransformPass {
    public static final String ID = "validationSinkHardening";
    private static final String HELPERS = "validationSinkHardening.helpers";
    private static final String PRIMITIVE_HELPERS = "validationSinkHardening.primitiveHelpers";
    private static final String PLACEHOLDERS = "validationSinkHardening.placeholders";
    private static final String VARIANT_COUNTERS = "validationSinkHardening.variantCounters";
    private static final long TAG_MUL = 0x100000001B3L;
    private static final long TAG_ADD = 0x9E3779B97F4A7C15L;
    private static final long LIVE_MASK_LOW_DOMAIN = 0x5653484D41534B32L;
    private static final String HELPER_DESC = "(Ljava/lang/String;JI)J";
    private static final String LENGTH_STAGE_DESC = "(Ljava/lang/String;I)I";
    private static final String SEED_STAGE_DESC = "(JII)J";
    private static final String CHAR_STAGE_DESC = "(Ljava/lang/String;JIII)J";
    private static final String FINAL_STAGE_DESC = "(JJI)Z";
    public static final String PRIMITIVE_ENTRY_PREFIX = "__neko_vsx";
    public static final String PRIMITIVE_ENTRY_DESC = "(IIJ)I";
    public static final String PRIMITIVE_FINAL_STAGE_PREFIX = "__neko_vsxend";
    public static final String PRIMITIVE_FINAL_STAGE_DESC = "(JJ)I";
    private static final String PRIMITIVE_VALUE_STAGE_DESC = "(IIJ)J";
    private static final String PRIMITIVE_GUARD_STAGE_DESC = "(J)J";
    private static final String PRIMITIVE_DATA_STAGE_DESC = "(J)I";
    private static final long LENGTH_STAGE_DOMAIN = 0x5653484C454E3031L;
    private static final long HASH_STAGE_DOMAIN = 0x5653484841534831L;
    private static final long PRIMITIVE_SEED_DOMAIN = 0x5653505345454431L;
    private static final long PRIMITIVE_PAIR_DOMAIN = 0x5653505041495231L;
    private static final long PRIMITIVE_FINAL_DOMAIN = 0x56535046494E3031L;
    private static final long PRIMITIVE_SIDE_MUL = 0xD6E8FEB86659FD93L;
    private static final long PRIMITIVE_SIDE_ADD = 0xA5A3564E27F2A9B1L;
    private static final int VARIANT_COUNT = 2;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "JVM Validation Sink Hardening";
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
        return Set.of(ControlFlowFlatteningPass.ID);
    }

    @Override
    public void transformClass(TransformContext ctx) {
    }

    @Override
    public void transformMethod(TransformContext ctx) {
        if (!(ctx instanceof PipelineContext pctx)) return;
        hardenPreparedPlaceholders(pctx, pctx.currentL1Class(), pctx.currentL1Method());
        hardenMethod(pctx, pctx.currentL1Class(), pctx.currentL1Method());
    }

    public static boolean preparePlaceholders(PipelineContext pctx, L1Class clazz, L1Method method) {
        return new JvmValidationSinkHardeningPass().preparePlaceholdersInternal(pctx, clazz, method);
    }

    public static boolean hardenPreparedPlaceholders(PipelineContext pctx, L1Class clazz, L1Method method) {
        return new JvmValidationSinkHardeningPass().hardenPreparedPlaceholdersInternal(pctx, clazz, method);
    }

    public static boolean hardenMethod(PipelineContext pctx, L1Class clazz, L1Method method) {
        return new JvmValidationSinkHardeningPass().hardenMethodInternal(pctx, clazz, method);
    }

    private boolean preparePlaceholdersInternal(PipelineContext pctx, L1Class clazz, L1Method method) {
        if (clazz == null || method == null || !method.hasCode()) return false;
        if (TransformGuards.isRuntimeClass(clazz)) return false;
        if (TransformGuards.isGeneratedMethod(method)) return false;

        MethodNode mn = method.asmNode();
        int transformed = 0;
        Map<MethodInsnNode, ValidationPlaceholder> placeholders = placeholders(pctx);
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!isStringEquals(insn)) continue;
            AbstractInsnNode previous = previousReal(insn.getPrevious());
            if (!(previous instanceof LdcInsnNode ldc) || !(ldc.cst instanceof String target)) continue;
            MethodInsnNode placeholder = new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/util/Objects",
                "nonNull",
                "(Ljava/lang/Object;)Z",
                false
            );
            mn.instructions.insertBefore(previous, placeholder);
            mn.instructions.remove(previous);
            mn.instructions.remove(insn);
            placeholders.put(placeholder, new ValidationPlaceholder(target, transformed++));
        }
        int hiddenKeyLocal = hiddenKeyLocal(mn);
        int primitiveOrdinal = 0;
        if (hiddenKeyLocal >= 0) {
            for (AbstractInsnNode insn : mn.instructions.toArray()) {
                if (!isPrimitiveTableAccumulatorXor(insn)) continue;
                int variant = nextVariant(pctx, clazz);
                long siteSeed = primitivePreCffSiteSeed(pctx.masterSeed(), clazz, method, primitiveOrdinal);
                PrimitiveValidationStages stages = ensurePrimitiveHelper(pctx, clazz, variant, siteSeed);
                InsnList replacement = new InsnList();
                replacement.add(new VarInsnNode(Opcodes.LLOAD, hiddenKeyLocal));
                replacement.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    clazz.name(),
                    stages.entry(),
                    PRIMITIVE_ENTRY_DESC,
                    clazz.isInterface()
                ));
                mn.instructions.insertBefore(insn, replacement);
                mn.instructions.remove(insn);
                primitiveOrdinal++;
                transformed++;
            }
        }
        if (transformed == 0) return false;
        if (primitiveOrdinal > 0) {
            markCoverage(pctx, clazz, method, 0, primitiveOrdinal);
        }
        clazz.markDirty();
        pctx.invalidate(method);
        return true;
    }

    private boolean hardenPreparedPlaceholdersInternal(PipelineContext pctx, L1Class clazz, L1Method method) {
        Map<MethodInsnNode, ValidationPlaceholder> placeholders = placeholders(pctx);
        if (placeholders.isEmpty()) return false;
        if (clazz == null || method == null || !method.hasCode()) return false;
        if (TransformGuards.isRuntimeClass(clazz)) return false;
        if (TransformGuards.isGeneratedMethod(method)) return false;

        String methodKey = JvmKeyDispatchPass.coverageKey(clazz, method);
        ControlFlowFlatteningPass.CffMethodMetadata metadata =
            ControlFlowFlatteningPass.methodMetadata(pctx).get(methodKey);
        if (metadata == null || metadata.classKeyTable() == null) return false;

        MethodNode mn = method.asmNode();
        int transformed = 0;
        int receiverLocal = -1;
        int liveMaskHighLocal = -1;
        int seedArgLocal = -1;
        int expectedArgLocal = -1;
        int dataWordArgLocal = -1;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof MethodInsnNode placeholderCall)) continue;
            ValidationPlaceholder placeholder = placeholders.get(placeholderCall);
            if (placeholder == null) continue;
            if (!metadata.applicationInstructions().contains(placeholderCall)) {
                throw new IllegalStateException(
                    "validationSinkHardening placeholder lost CFF application state for " + methodKey
                );
            }
            ControlFlowFlatteningPass.CffInstructionState state =
                metadata.instructionStates().get(placeholderCall);
            if (state == null) {
                throw new IllegalStateException(
                    "validationSinkHardening cannot bind placeholder CFF state for " + methodKey
                );
            }
            if (liveMaskHighLocal < 0) {
                receiverLocal = mn.maxLocals++;
                liveMaskHighLocal = mn.maxLocals++;
                seedArgLocal = mn.maxLocals;
                mn.maxLocals += 2;
                expectedArgLocal = mn.maxLocals;
                mn.maxLocals += 2;
                dataWordArgLocal = mn.maxLocals++;
            }
            long siteSeed = siteSeed(pctx.masterSeed(), clazz, method, state, placeholder.ordinal());
            insertReplacement(
                pctx,
                clazz,
                method,
                metadata,
                state,
                placeholder.target(),
                siteSeed,
                placeholderCall,
                receiverLocal,
                liveMaskHighLocal,
                seedArgLocal,
                expectedArgLocal,
                dataWordArgLocal
            );
            placeholders.remove(placeholderCall);
            transformed++;
        }
        if (transformed == 0) return false;
        markCoverage(pctx, clazz, method, transformed, 0);
        return true;
    }

    private boolean hardenMethodInternal(PipelineContext pctx, L1Class clazz, L1Method method) {
        if (clazz == null || method == null || !method.hasCode()) return false;
        if (TransformGuards.isRuntimeClass(clazz)) return false;
        if (TransformGuards.isGeneratedMethod(method)) return false;

        String methodKey = JvmKeyDispatchPass.coverageKey(clazz, method);
        ControlFlowFlatteningPass.CffMethodMetadata metadata =
            ControlFlowFlatteningPass.methodMetadata(pctx).get(methodKey);
        if (metadata == null || metadata.classKeyTable() == null) return false;

        MethodNode mn = method.asmNode();
        int transformed = 0;
        int ordinal = 0;
        int receiverLocal = -1;
        int liveMaskHighLocal = -1;
        int seedArgLocal = -1;
        int expectedArgLocal = -1;
        int dataWordArgLocal = -1;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!isStringEquals(insn)) continue;
            AbstractInsnNode previous = previousReal(insn.getPrevious());
            if (!(previous instanceof LdcInsnNode ldc) || !(ldc.cst instanceof String target)) continue;
            if (!metadata.applicationInstructions().contains(insn) ||
                !metadata.applicationInstructions().contains(previous)) {
                continue;
            }
            ControlFlowFlatteningPass.CffInstructionState state =
                metadata.instructionStates().get(insn);
            if (state == null) {
                state = metadata.instructionStates().get(previous);
            }
            if (state == null) {
                throw new IllegalStateException(
                    "validationSinkHardening cannot bind CFF state for " + methodKey
                );
            }
            int siteOrdinal = ordinal++;
            long siteSeed = siteSeed(pctx.masterSeed(), clazz, method, state, siteOrdinal);
            if (liveMaskHighLocal < 0) {
                receiverLocal = mn.maxLocals++;
                liveMaskHighLocal = mn.maxLocals++;
                seedArgLocal = mn.maxLocals;
                mn.maxLocals += 2;
                expectedArgLocal = mn.maxLocals;
                mn.maxLocals += 2;
                dataWordArgLocal = mn.maxLocals++;
            }
            insertReplacement(
                pctx,
                clazz,
                method,
                metadata,
                state,
                target,
                siteSeed,
                insn,
                receiverLocal,
                liveMaskHighLocal,
                seedArgLocal,
                expectedArgLocal,
                dataWordArgLocal
            );
            mn.instructions.remove(previous);
            transformed++;
        }

        if (transformed > 0) {
            markCoverage(pctx, clazz, method, transformed, 0);
            return true;
        }
        return false;
    }

    private void insertReplacement(
        PipelineContext pctx,
        L1Class clazz,
        L1Method method,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        String target,
        long siteSeed,
        AbstractInsnNode anchor,
        int receiverLocal,
        int liveMaskHighLocal,
        int seedArgLocal,
        int expectedArgLocal,
        int dataWordArgLocal
    ) {
        int variant = nextVariant(pctx, clazz);
        ValidationStages stages = ensureHelper(pctx, clazz, variant, siteSeed);
        long seedValue = tagSeed(target, siteSeed, variant);
        InsnList replacement = new InsnList();
        replacement.add(new VarInsnNode(Opcodes.ASTORE, receiverLocal));
        emitValidationDataWord(replacement, metadata, state, siteSeed);
        replacement.add(new VarInsnNode(Opcodes.ISTORE, dataWordArgLocal));
        emitEncodedLongArgument(replacement, metadata, state, siteSeed, dataWordArgLocal,
            0x5653485345454431L,
            seedValue);
        replacement.add(new VarInsnNode(Opcodes.LSTORE, seedArgLocal));
        emitEncodedLongArgument(replacement, metadata, state, siteSeed, dataWordArgLocal,
            0x5653485441473031L,
            tag(target, seedValue, variant));
        replacement.add(new VarInsnNode(Opcodes.LSTORE, expectedArgLocal));
        replacement.add(new VarInsnNode(Opcodes.ALOAD, receiverLocal));
        replacement.add(new VarInsnNode(Opcodes.LLOAD, seedArgLocal));
        replacement.add(new VarInsnNode(Opcodes.ILOAD, dataWordArgLocal));
        replacement.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            clazz.name(),
            stages.entry(),
            HELPER_DESC,
            clazz.isInterface()
        ));
        replacement.add(new VarInsnNode(Opcodes.LSTORE, seedArgLocal));
        replacement.add(new VarInsnNode(Opcodes.LLOAD, seedArgLocal));
        replacement.add(new VarInsnNode(Opcodes.LLOAD, expectedArgLocal));
        replacement.add(new VarInsnNode(Opcodes.ILOAD, dataWordArgLocal));
        MethodInsnNode finalCall = new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            clazz.name(),
            stages.finish(),
            FINAL_STAGE_DESC,
            clazz.isInterface()
        );
        replacement.add(finalCall);
        metadata.applicationInstructions().add(finalCall);
        metadata.instructionStates().put(finalCall, state);
        JvmKeyDispatchPass.markGenerated(pctx, replacement);
        method.asmNode().instructions.insertBefore(anchor, replacement);
        method.asmNode().instructions.remove(anchor);
        method.asmNode().maxStack = Math.max(method.asmNode().maxStack, 24);
        clazz.markDirty();
        pctx.invalidate(method);
    }

    private void markCoverage(
        PipelineContext pctx,
        L1Class clazz,
        L1Method method,
        int stringTransformed,
        int primitiveTransformed
    ) {
        JvmObfuscationCoverage.get(pctx).full(
            ID,
            clazz.name(),
            method.name(),
            method.descriptor(),
            "cff-keyed-validation-sinks-string-" + stringTransformed +
                "-primitive-" + primitiveTransformed
        );
    }

    @SuppressWarnings("unchecked")
    private Map<MethodInsnNode, ValidationPlaceholder> placeholders(PipelineContext pctx) {
        Map<MethodInsnNode, ValidationPlaceholder> placeholders = pctx.getPassData(PLACEHOLDERS);
        if (placeholders == null) {
            placeholders = new IdentityHashMap<>();
            pctx.putPassData(PLACEHOLDERS, placeholders);
        }
        return placeholders;
    }

    private boolean isStringEquals(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call &&
            call.getOpcode() == Opcodes.INVOKEVIRTUAL &&
            "java/lang/String".equals(call.owner) &&
            "equals".equals(call.name) &&
            "(Ljava/lang/Object;)Z".equals(call.desc);
    }

    private AbstractInsnNode previousReal(AbstractInsnNode insn) {
        for (AbstractInsnNode cursor = insn; cursor != null; cursor = cursor.getPrevious()) {
            if (cursor.getOpcode() >= 0) return cursor;
        }
        return null;
    }

    private AbstractInsnNode nextReal(AbstractInsnNode insn) {
        for (AbstractInsnNode cursor = insn; cursor != null; cursor = cursor.getNext()) {
            if (cursor.getOpcode() >= 0) return cursor;
        }
        return null;
    }

    private boolean isPrimitiveTableAccumulatorXor(AbstractInsnNode insn) {
        if (insn == null || insn.getOpcode() != Opcodes.IXOR) return false;
        AbstractInsnNode previous = previousReal(insn.getPrevious());
        if (previous == null || previous.getOpcode() != Opcodes.IALOAD) return false;
        AbstractInsnNode next = nextReal(insn.getNext());
        if (next == null || next.getOpcode() != Opcodes.IOR) return false;
        AbstractInsnNode afterOr = nextReal(next.getNext());
        return afterOr instanceof VarInsnNode store && store.getOpcode() == Opcodes.ISTORE;
    }

    private int hiddenKeyLocal(MethodNode mn) {
        Type[] args = Type.getArgumentTypes(mn.desc);
        if (args.length == 0 || args[args.length - 1] != Type.LONG_TYPE) return -1;
        int local = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (int i = 0; i < args.length - 1; i++) {
            local += args[i].getSize();
        }
        return local;
    }

    @SuppressWarnings("unchecked")
    private ValidationStages ensureHelper(PipelineContext pctx, L1Class clazz, int variant, long siteSeed) {
        Map<String, ValidationStages> helpers = pctx.getPassData(HELPERS);
        if (helpers == null) {
            helpers = new LinkedHashMap<>();
            pctx.putPassData(HELPERS, helpers);
        }
        String key = clazz.name() + '#' + variant + '#' + Long.toUnsignedString(siteSeed, 36);
        ValidationStages existing = helpers.get(key);
        if (existing != null) return existing;

        ValidationStages stages = new ValidationStages(
            uniqueMethodName(clazz, "__neko_vsink" + variant + "$"),
            uniqueMethodName(clazz, "__neko_vslen" + variant + "$"),
            uniqueMethodName(clazz, "__neko_vsseed" + variant + "$"),
            uniqueMethodName(clazz, "__neko_vschar" + variant + "$"),
            uniqueMethodName(clazz, "__neko_vsend" + variant + "$")
        );
        int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        access |= clazz.isInterface() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;

        MethodNode entry = new MethodNode(access, stages.entry(), HELPER_DESC, null, null);
        emitHelperBody(entry.instructions, stages, clazz.name(), clazz.isInterface());
        entry.maxLocals = 10;
        entry.maxStack = 24;

        MethodNode lengthStage = new MethodNode(access, stages.length(), LENGTH_STAGE_DESC, null, null);
        emitLengthStageBody(lengthStage.instructions);
        lengthStage.maxLocals = 2;
        lengthStage.maxStack = 8;

        MethodNode seedStage = new MethodNode(access, stages.seed(), SEED_STAGE_DESC, null, null);
        emitSeedStageBody(seedStage.instructions, variant);
        seedStage.maxLocals = 4;
        seedStage.maxStack = 16;

        MethodNode charStage = new MethodNode(access, stages.character(), CHAR_STAGE_DESC, null, null);
        emitCharStageBody(charStage.instructions, variant);
        charStage.maxLocals = 7;
        charStage.maxStack = 16;

        MethodNode finalStage = new MethodNode(access, stages.finish(), FINAL_STAGE_DESC, null, null);
        emitFinalStageBody(finalStage.instructions);
        finalStage.maxLocals = 5;
        finalStage.maxStack = 8;

        for (MethodNode generated : new MethodNode[] { entry, lengthStage, seedStage, charStage, finalStage }) {
            JvmKeyDispatchPass.markGenerated(pctx, generated.instructions);
            clazz.asmNode().methods.add(generated);
        }
        clazz.markDirty();
        helpers.put(key, stages);
        return stages;
    }

    @SuppressWarnings("unchecked")
    private PrimitiveValidationStages ensurePrimitiveHelper(
        PipelineContext pctx,
        L1Class clazz,
        int variant,
        long siteSeed
    ) {
        Map<String, PrimitiveValidationStages> helpers = pctx.getPassData(PRIMITIVE_HELPERS);
        if (helpers == null) {
            helpers = new LinkedHashMap<>();
            pctx.putPassData(PRIMITIVE_HELPERS, helpers);
        }
        String key = clazz.name() + '#' + variant + '#' + Long.toUnsignedString(siteSeed, 36);
        PrimitiveValidationStages existing = helpers.get(key);
        if (existing != null) return existing;

        PrimitiveValidationStages stages = new PrimitiveValidationStages(
            uniqueMethodName(clazz, "__neko_vsx" + variant + "$"),
            uniqueMethodName(clazz, "__neko_vsxval" + variant + "$"),
            uniqueMethodName(clazz, "__neko_vsxguard" + variant + "$"),
            uniqueMethodName(clazz, "__neko_vsxdata" + variant + "$"),
            uniqueMethodName(clazz, PRIMITIVE_FINAL_STAGE_PREFIX + variant + "$")
        );
        int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        access |= clazz.isInterface() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;

        MethodNode entry = new MethodNode(access, stages.entry(), PRIMITIVE_ENTRY_DESC, null, null);
        emitPrimitiveEntryBody(entry.instructions, stages, clazz.name(), clazz.isInterface(), siteSeed);
        entry.maxLocals = 11;
        entry.maxStack = 22;

        MethodNode valueStage = new MethodNode(access, stages.value(), PRIMITIVE_VALUE_STAGE_DESC, null, null);
        emitPrimitiveValueStageBody(valueStage.instructions, variant, siteSeed);
        valueStage.maxLocals = 4;
        valueStage.maxStack = 16;

        MethodNode guardStage = new MethodNode(access, stages.guard(), PRIMITIVE_GUARD_STAGE_DESC, null, null);
        emitPrimitiveGuardStageBody(guardStage.instructions, stages, clazz.name(), clazz.isInterface(), siteSeed);
        guardStage.maxLocals = 3;
        guardStage.maxStack = 16;

        MethodNode dataStage = new MethodNode(access, stages.data(), PRIMITIVE_DATA_STAGE_DESC, null, null);
        emitPrimitiveDataStageBody(dataStage.instructions, siteSeed);
        dataStage.maxLocals = 2;
        dataStage.maxStack = 10;

        MethodNode finalStage = new MethodNode(access, stages.finish(), PRIMITIVE_FINAL_STAGE_DESC, null, null);
        emitPrimitiveFinalStageBody(finalStage.instructions, stages, clazz.name(), clazz.isInterface(), siteSeed);
        finalStage.maxLocals = 7;
        finalStage.maxStack = 10;

        for (MethodNode generated : new MethodNode[] { entry, valueStage, guardStage, dataStage, finalStage }) {
            JvmKeyDispatchPass.markGenerated(pctx, generated.instructions);
            clazz.asmNode().methods.add(generated);
        }
        clazz.markDirty();
        helpers.put(key, stages);
        return stages;
    }

    private void emitHelperBody(InsnList insns, ValidationStages stages, String owner, boolean interfaceOwner) {
        int stringLocal = 0;
        int seedLocal = 1;
        int dataWordLocal = 3;
        int lengthLocal = 4;
        int indexLocal = 5;
        int hashLocal = 6;
        LabelNode loop = new LabelNode();
        LabelNode done = new LabelNode();

        insns.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, stages.length(),
            LENGTH_STAGE_DESC, interfaceOwner));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitValidationDataMaskFromTop(insns, LENGTH_STAGE_DOMAIN);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, lengthLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, stages.seed(),
            SEED_STAGE_DESC, interfaceOwner));
        insns.add(new VarInsnNode(Opcodes.LSTORE, hashLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));

        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, done));
        insns.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, hashLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner, stages.character(),
            CHAR_STAGE_DESC, interfaceOwner));
        insns.add(new VarInsnNode(Opcodes.LSTORE, hashLocal));
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));

        insns.add(done);
        insns.add(new VarInsnNode(Opcodes.LLOAD, hashLocal));
        insns.add(new InsnNode(Opcodes.LRETURN));
    }

    private void emitPrimitiveEntryBody(
        InsnList insns,
        PrimitiveValidationStages stages,
        String owner,
        boolean interfaceOwner,
        long siteSeed
    ) {
        int valueLocal = 0;
        int expectedLocal = 1;
        int keyLocal = 2;
        int dataWordLocal = 4;
        int leftLocal = 5;
        int rightLocal = 7;
        int pairLocal = 9;

        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            owner,
            stages.data(),
            PRIMITIVE_DATA_STAGE_DESC,
            interfaceOwner
        ));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dataWordLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            owner,
            stages.value(),
            PRIMITIVE_VALUE_STAGE_DESC,
            interfaceOwner
        ));
        insns.add(new VarInsnNode(Opcodes.LSTORE, leftLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, expectedLocal));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            owner,
            stages.value(),
            PRIMITIVE_VALUE_STAGE_DESC,
            interfaceOwner
        ));
        insns.add(new VarInsnNode(Opcodes.LSTORE, rightLocal));

        insns.add(new VarInsnNode(Opcodes.LLOAD, leftLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, rightLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitValidationDataLongMask(insns, dataWordLocal, PRIMITIVE_PAIR_DOMAIN);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, pairLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, pairLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            owner,
            stages.finish(),
            PRIMITIVE_FINAL_STAGE_DESC,
            interfaceOwner
        ));
        insns.add(new InsnNode(Opcodes.IRETURN));
    }

    private void emitPrimitiveGuardStageBody(
        InsnList insns,
        PrimitiveValidationStages stages,
        String owner,
        boolean interfaceOwner,
        long siteSeed
    ) {
        int keyLocal = 0;
        int dataWordLocal = 2;
        emitPrimitiveKeyDataWord(insns, keyLocal, siteSeed);
        insns.add(new VarInsnNode(Opcodes.ISTORE, dataWordLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            owner,
            stages.value(),
            PRIMITIVE_VALUE_STAGE_DESC,
            interfaceOwner
        ));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            owner,
            stages.value(),
            PRIMITIVE_VALUE_STAGE_DESC,
            interfaceOwner
        ));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitValidationDataLongMask(insns, dataWordLocal, PRIMITIVE_FINAL_DOMAIN);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LRETURN));
    }

    private void emitPrimitiveDataStageBody(InsnList insns, long siteSeed) {
        emitPrimitiveKeyDataWord(insns, 0, siteSeed);
        insns.add(new InsnNode(Opcodes.IRETURN));
    }

    private void emitPrimitiveValueStageBody(InsnList insns, int variant, long siteSeed) {
        int valueLocal = 0;
        int sideLocal = 1;
        int keyLocal = 2;

        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        emitPrimitiveKeyedSideGuard(insns, keyLocal, sideLocal, variant, siteSeed);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LRETURN));
    }

    private void emitPrimitiveFinalStageBody(
        InsnList insns,
        PrimitiveValidationStages stages,
        String owner,
        boolean interfaceOwner,
        long siteSeed
    ) {
        int pairLocal = 0;
        int keyLocal = 2;
        int dataWordLocal = 4;
        int guardLocal = 5;
        emitPrimitiveKeyDataWord(insns, keyLocal, siteSeed);
        insns.add(new VarInsnNode(Opcodes.ISTORE, dataWordLocal));
        emitDecodeLongArgument(insns, pairLocal, dataWordLocal, PRIMITIVE_PAIR_DOMAIN);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            owner,
            stages.guard(),
            PRIMITIVE_GUARD_STAGE_DESC,
            interfaceOwner
        ));
        insns.add(new VarInsnNode(Opcodes.LSTORE, guardLocal));
        emitDecodeLongArgument(insns, guardLocal, dataWordLocal, PRIMITIVE_FINAL_DOMAIN);
        insns.add(new VarInsnNode(Opcodes.LLOAD, pairLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IRETURN));
    }

    private void emitLengthStageBody(InsnList insns) {
        int stringLocal = 0;
        int dataWordLocal = 1;
        insns.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "length",
            "()I",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitValidationDataMaskFromTop(insns, LENGTH_STAGE_DOMAIN);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IRETURN));
    }

    private void emitSeedStageBody(InsnList insns, int variant) {
        int seedLocal = 0;
        int lengthLocal = 2;
        int dataWordLocal = 3;
        emitDecodeLongArgument(insns, seedLocal, dataWordLocal, 0x5653485345454431L);
        emitInitialHash(insns, seedLocal, lengthLocal, variant);
        emitValidationDataLongMask(insns, dataWordLocal, HASH_STAGE_DOMAIN);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LRETURN));
    }

    private void emitCharStageBody(InsnList insns, int variant) {
        int stringLocal = 0;
        int hashLocal = 1;
        int dataWordLocal = 3;
        int indexLocal = 4;
        int lengthLocal = 5;
        int charLocal = 6;
        emitDecodeLongArgument(insns, hashLocal, dataWordLocal, HASH_STAGE_DOMAIN);
        insns.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "charAt",
            "(I)C",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ISTORE, charLocal));
        emitHashStep(insns, hashLocal, charLocal, indexLocal, lengthLocal, variant);
        emitValidationDataLongMask(insns, dataWordLocal, HASH_STAGE_DOMAIN);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LRETURN));
    }

    private void emitFinalStageBody(InsnList insns) {
        int hashLocal = 0;
        int expectedLocal = 2;
        int dataWordLocal = 4;
        LabelNode match = new LabelNode();
        emitDecodeLongArgument(insns, hashLocal, dataWordLocal, HASH_STAGE_DOMAIN);
        emitDecodeLongArgument(insns, expectedLocal, dataWordLocal, 0x5653485441473031L);
        insns.add(new VarInsnNode(Opcodes.LLOAD, hashLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, expectedLocal));
        insns.add(new InsnNode(Opcodes.LCMP));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, match));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(match);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IRETURN));
    }

    private void emitInitialHash(InsnList insns, int seedLocal, int lengthLocal, int variant) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        if (variant == 0) {
            insns.add(new InsnNode(Opcodes.LXOR));
            JvmPassBytecode.pushLong(insns, TAG_ADD);
            insns.add(new InsnNode(Opcodes.LXOR));
            return;
        }
        JvmPassBytecode.pushLong(insns, TAG_MUL);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.LADD));
        JvmPassBytecode.pushLong(insns, TAG_ADD);
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitHashStep(
        InsnList insns,
        int hashLocal,
        int charLocal,
        int indexLocal,
        int lengthLocal,
        int variant
    ) {
        if (variant == 0) {
            insns.add(new VarInsnNode(Opcodes.LLOAD, hashLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, charLocal));
            insns.add(new InsnNode(Opcodes.I2L));
            insns.add(new InsnNode(Opcodes.LXOR));
            JvmPassBytecode.pushLong(insns, TAG_MUL);
            insns.add(new InsnNode(Opcodes.LMUL));
            insns.add(new VarInsnNode(Opcodes.LSTORE, hashLocal));
            insns.add(new VarInsnNode(Opcodes.LLOAD, hashLocal));
            insns.add(new VarInsnNode(Opcodes.LLOAD, hashLocal));
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LUSHR));
            insns.add(new InsnNode(Opcodes.LXOR));
            JvmPassBytecode.pushLong(insns, TAG_ADD);
            insns.add(new InsnNode(Opcodes.LADD));
            return;
        }

        insns.add(new VarInsnNode(Opcodes.LLOAD, hashLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, charLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 7);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, TAG_MUL);
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, 31);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/Long",
            "rotateLeft",
            "(JI)J",
            false
        ));
        JvmPassBytecode.pushLong(insns, TAG_ADD);
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitPrimitiveKeyedSideGuard(
        InsnList insns,
        int keyLocal,
        int sideLocal,
        int variant,
        long siteSeed
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushLong(insns, siteSeed ^ PRIMITIVE_SEED_DOMAIN);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 33);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, PRIMITIVE_SIDE_MUL | 1L);
        insns.add(new InsnNode(Opcodes.LMUL));
        JvmPassBytecode.pushLong(insns, PRIMITIVE_SIDE_ADD ^ ((long) variant << 32));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sideLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, PRIMITIVE_SIDE_MUL);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 17 + variant);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, TAG_MUL ^ ((long) (variant + 1) * 0x56535031L));
        insns.add(new InsnNode(Opcodes.LMUL));
        JvmPassBytecode.pushLong(insns, TAG_ADD ^ PRIMITIVE_SIDE_ADD);
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitPrimitiveKeyDataWord(InsnList insns, int keyLocal, long siteSeed) {
        long seed = JvmPassBytecode.mix(siteSeed ^ PRIMITIVE_PAIR_DOMAIN, PRIMITIVE_FINAL_DOMAIN);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushLong(insns, seed);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653504441544131L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 11));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653504441544132L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653504441544133L)));
        insns.add(new InsnNode(Opcodes.IADD));
    }

    private void emitDecodedLong(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed,
        int liveMaskHighLocal,
        int dataWordLocal,
        long domain,
        long value
    ) {
        long mask = liveMask(metadata, state, siteSeed, domain);
        emitLiveMask(insns, metadata, state, siteSeed, liveMaskHighLocal, dataWordLocal, domain);
        JvmPassBytecode.pushLong(insns, value ^ mask);
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitDecodedInt(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed,
        int liveMaskHighLocal,
        int dataWordLocal,
        long domain,
        int value
    ) {
        int mask = (int) liveMask(metadata, state, siteSeed, domain);
        emitLiveMask(insns, metadata, state, siteSeed, liveMaskHighLocal, dataWordLocal, domain);
        insns.add(new InsnNode(Opcodes.L2I));
        JvmPassBytecode.pushInt(insns, value ^ mask);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitEncodedLongArgument(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed,
        int dataWordLocal,
        long domain,
        long value
    ) {
        long mask = argumentKeyMask(state.methodKey(), siteSeed, domain);
        JvmPassBytecode.pushLong(insns, value ^ mask);
        emitArgumentKeyMask(insns, metadata.keyLocal(), siteSeed, dataWordLocal, domain);
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private long argumentKeyMask(long methodKey, long siteSeed, long domain) {
        long x = methodKey ^ JvmPassBytecode.mix(siteSeed ^ domain, 0x5653484152474D31L);
        x ^= x >>> 33;
        x *= 0xFF51AFD7ED558CCDL;
        x ^= x >>> 29;
        x *= 0xC4CEB9FE1A85EC53L;
        x ^= x >>> 32;
        return x;
    }

    private void emitArgumentKeyMask(
        InsnList insns,
        int keyLocal,
        long siteSeed,
        int dataWordLocal,
        long domain
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushLong(insns, JvmPassBytecode.mix(siteSeed ^ domain, 0x5653484152474D31L));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 33);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0xFF51AFD7ED558CCDL);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 29);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0xC4CEB9FE1A85EC53L);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitValidationDataLongMask(insns, dataWordLocal, domain);
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private long liveMask(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed,
        long domain
    ) {
        int wordA = liveWord(metadata, state, siteSeed, domain);
        int wordB = wordA ^ nonZeroInt(JvmPassBytecode.mix(siteSeed ^ domain, LIVE_MASK_LOW_DOMAIN));
        return ((long) wordA << 32) ^ (wordB & 0xFFFFFFFFL);
    }

    private int liveWord(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed,
        long domain
    ) {
        long seed = JvmPassBytecode.mix(siteSeed ^ domain, state.selectorSeed());
        int x = (state.guardKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484755415244L))) +
            state.pathKey();
        x ^= x >>> shift(seed, 5);
        x = (x + state.blockKey()) ^
            nonZeroInt(JvmPassBytecode.mix(seed, 0x565348424C4F434BL));
        x *= nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484D554C544BL)) | 1;
        x ^= derivedMethodKeyFold(state);
        x += state.pcToken() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x5653485043544F4BL));
        int idx = (x ^ state.state() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x5653485441424958L))) &
            (metadata.classKeyTable().values().length - 1);
        x ^= validationIndexWord(seed, idx) +
            nonZeroInt(JvmPassBytecode.mix(seed, 0x565348544142564CL));
        x += x >>> shift(seed, 19);
        return x ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x56534846494E414CL));
    }

    private int validationIndexWord(long seed, int idx) {
        int x = idx ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484944583031L));
        x ^= x >>> shift(seed, 13);
        x *= nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484944583032L)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484944583033L));
    }

    private void emitLiveMask(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed,
        int liveMaskHighLocal,
        int dataWordLocal,
        long domain
    ) {
        emitLiveWord(insns, metadata, state, siteSeed, dataWordLocal, domain);
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ISTORE, liveMaskHighLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitValidationDataMaskFromTop(insns, domain);
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(siteSeed ^ domain, LIVE_MASK_LOW_DOMAIN)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitValidationDataMaskFromTop(insns, domain ^ LIVE_MASK_LOW_DOMAIN);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new VarInsnNode(Opcodes.ILOAD, liveMaskHighLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitLiveWord(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed,
        int dataWordLocal,
        long domain
    ) {
        long seed = JvmPassBytecode.mix(siteSeed ^ domain, state.selectorSeed());
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484755415244L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 5));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x565348424C4F434BL)));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484D554C544BL)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        emitDerivedMethodKeyFold(insns, metadata, state);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pcLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653485043544F4BL)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, state.state());
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653485441424958L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, metadata.classKeyTable().values().length - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484944583031L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 13));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484944583032L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484944583033L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x565348544142564CL)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 19));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x56534846494E414CL)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitValidationDataMaskFromTop(insns, domain);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitValidationDataWord(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed
    ) {
        long seed = JvmPassBytecode.mix(
            siteSeed ^ state.methodSalt(),
            ((long) state.blockIndex() << 32) ^ state.state()
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.dataLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484441544131L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 7));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484441544132L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pcLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484441544133L)));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484441544134L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 19));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5653484441544135L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitDecodeLongArgument(
        InsnList insns,
        int argumentLocal,
        int dataWordLocal,
        long domain
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, argumentLocal));
        emitValidationDataLongMask(insns, dataWordLocal, domain);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, argumentLocal));
    }

    private void emitDecodeIntArgument(
        InsnList insns,
        int argumentLocal,
        int dataWordLocal,
        long domain
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, argumentLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitValidationDataMaskFromTop(insns, domain ^ LIVE_MASK_LOW_DOMAIN);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, argumentLocal));
    }

    private void emitValidationDataLongMask(
        InsnList insns,
        int dataWordLocal,
        long domain
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitValidationDataMaskFromTop(insns, domain);
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitValidationDataMaskFromTop(insns, domain ^ LIVE_MASK_LOW_DOMAIN);
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitValidationDataMaskFromTop(InsnList insns, long domain) {
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(domain, 0x565348444D41534BL)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(domain, 9));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(domain, 0x565348444D554C31L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(domain, 17));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(domain, 0x5653484446494E31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private int derivedMethodKeyFold(ControlFlowFlatteningPass.CffInstructionState state) {
        int x = (state.guardKey() ^ state.pathKey()) + state.blockKey();
        x ^= (int) state.methodSalt();
        x ^= (int) state.methodKey();
        return x;
    }

    private void emitDerivedMethodKeyFold(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, (int) state.methodSalt());
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    @SuppressWarnings("unchecked")
    private int nextVariant(PipelineContext pctx, L1Class clazz) {
        Map<String, Integer> counters = pctx.getPassData(VARIANT_COUNTERS);
        if (counters == null) {
            counters = new LinkedHashMap<>();
            pctx.putPassData(VARIANT_COUNTERS, counters);
        }
        int ordinal = counters.getOrDefault(clazz.name(), 0);
        counters.put(clazz.name(), ordinal + 1);
        return Math.floorMod(ordinal, VARIANT_COUNT);
    }

    private long tagSeed(String target, long siteSeed, int variant) {
        long seed = JvmPassBytecode.mix(siteSeed ^ 0x5653485441475344L, target.length());
        seed = JvmPassBytecode.mix(seed, variant);
        return nonZeroLong(JvmPassBytecode.mix(seed, 0x5653485345454432L));
    }

    private long tag(String value, long seed, int variant) {
        long h = initialHash(seed, value.length(), variant);
        for (int i = 0; i < value.length(); i++) {
            h = hashStep(h, value.charAt(i), i, value.length(), variant);
        }
        return nonZeroLong(h);
    }

    private long initialHash(long seed, int length, int variant) {
        if (variant == 0) {
            return (seed ^ length) ^ TAG_ADD;
        }
        return (seed + (length * TAG_MUL)) ^ TAG_ADD;
    }

    private long hashStep(long h, int ch, int index, int length, int variant) {
        if (variant == 0) {
            h ^= ch;
            h *= TAG_MUL;
            return (h ^ (h >>> 32)) + TAG_ADD;
        }
        h ^= ((long) ch) << ((index & 7) + 1);
        h = Long.rotateLeft(h + TAG_MUL, ((index ^ length) & 31) + 1);
        return h ^ TAG_ADD;
    }

    private long siteSeed(
        long masterSeed,
        L1Class clazz,
        L1Method method,
        ControlFlowFlatteningPass.CffInstructionState state,
        int ordinal
    ) {
        long h = JvmPassBytecode.mix(masterSeed ^ 0x5653484F42465331L, clazz.name().hashCode());
        h = JvmPassBytecode.mix(h, method.name().hashCode());
        h = JvmPassBytecode.mix(h, method.descriptor().hashCode());
        h = JvmPassBytecode.mix(h, state.blockIndex());
        h = JvmPassBytecode.mix(h, state.state());
        return JvmPassBytecode.mix(h, ordinal);
    }

    private long primitivePreCffSiteSeed(
        long masterSeed,
        L1Class clazz,
        L1Method method,
        int ordinal
    ) {
        long h = JvmPassBytecode.mix(masterSeed ^ 0x5653504F42465331L, clazz.name().hashCode());
        h = JvmPassBytecode.mix(h, method.name().hashCode());
        h = JvmPassBytecode.mix(h, method.descriptor().hashCode());
        return JvmPassBytecode.mix(h, ordinal);
    }

    private String uniqueMethodName(L1Class clazz, String base) {
        String candidate = base + Integer.toUnsignedString(clazz.asmNode().methods.size(), 36);
        int suffix = 0;
        while (hasMethod(clazz, candidate)) {
            candidate = base + Integer.toUnsignedString(clazz.asmNode().methods.size() + ++suffix, 36);
        }
        return candidate;
    }

    private boolean hasMethod(L1Class clazz, String name) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.name.equals(name)) return true;
        }
        return false;
    }

    private int shift(long seed, int base) {
        return 1 + (int) ((seed >>> base) & 30L);
    }

    private int nonZeroInt(long value) {
        int v = (int) value;
        return v == 0 ? 0x56534831 : v;
    }

    private long nonZeroLong(long value) {
        return value == 0L ? 0x5653484C4F4E4731L : value;
    }

    private record ValidationPlaceholder(String target, int ordinal) {}

    private record ValidationStages(
        String entry,
        String length,
        String seed,
        String character,
        String finish
    ) {}

    private record PrimitiveValidationStages(
        String entry,
        String value,
        String guard,
        String data,
        String finish
    ) {}
}
