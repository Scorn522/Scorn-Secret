package dev.nekoobfuscator.transforms.jvm.cff;

import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.*;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningVerify.*;

import dev.nekoobfuscator.api.transform.IRLevel;
import dev.nekoobfuscator.api.transform.TransformContext;
import dev.nekoobfuscator.api.transform.TransformPass;
import dev.nekoobfuscator.api.transform.TransformPhase;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.jar.ClassHierarchy;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.util.JvmObfuscationCoverage;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import dev.nekoobfuscator.transforms.jvm.internal.JvmCodeSizeEstimator;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;
import dev.nekoobfuscator.transforms.jvm.key.JvmKeyDispatchPass;
import dev.nekoobfuscator.transforms.jvm.strings.JvmStringObfuscationPass;
import dev.nekoobfuscator.transforms.jvm.constants.JvmConstantObfuscationPass;
import dev.nekoobfuscator.transforms.jvm.constants.JvmStaticArrayMaterial;
import dev.nekoobfuscator.transforms.jvm.parameters.JvmMethodParameterObfuscationPass;
import dev.nekoobfuscator.transforms.jvm.validation.JvmValidationSinkHardeningPass;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import org.objectweb.asm.Type;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Direct keyed control-flow flattening over the original method body.
 *
 * <p>The pass keeps bytecode in the original method and rewrites basic-block
 * exits to store an encoded state and return to a target-local dispatcher.
 * Constructors keep the mandatory this/super initialization prefix untouched;
 * flattening starts immediately after that prefix.</p>
 */
public final class ControlFlowFlatteningPass extends CffTransitionOutliner implements TransformPass {
    private static final String RECORD_BUDGETED_DIRECT_INLINE_STATS_PROPERTY =
        "neko.cff.recordBudgetedDirectInlineStats";
    private static final Map<String, BudgetedDirectInlineStats> BUDGETED_DIRECT_INLINE_STATS =
        new ConcurrentHashMap<>();

    record BudgetedDirectInlineStats(int candidates, int accepted, int rejected) {}

    static void clearBudgetedDirectInlineStatsForTesting() {
        BUDGETED_DIRECT_INLINE_STATS.clear();
    }

    static Map<String, BudgetedDirectInlineStats> budgetedDirectInlineStatsForTesting() {
        return Map.copyOf(BUDGETED_DIRECT_INLINE_STATS);
    }

    public static void emitDecodedSealedClassKeyWord(InsnList insns, int seal) {
        insns.add(new InsnNode(Opcodes.IALOAD));
        JvmPassBytecode.pushInt(insns, seal);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    public static void emitDecodedSealedClassKeyWordFromCarrier(InsnList insns, int carrierLocal) {
        emitDecodedSealedClassKeyWord(insns, CLASS_KEY_WORD_SEAL);
    }

    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "Control Flow Flattening";
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
        return Set.of(JvmKeyDispatchPass.ID);
    }

    public void finalizeOutput(PipelineContext pctx, List<L1Class> classes, ClassHierarchy hierarchy) {
        finalizeClassCodeIntegrity(pctx, classes, hierarchy);
    }

    @Override
    public void transformClass(TransformContext ctx) {
        if (!(ctx instanceof PipelineContext pctx)) return;
        L1Class clazz = pctx.currentL1Class();
        if (clazz != null && pctx.config().isTransformEnabled(JvmConstantObfuscationPass.ID)) {
            JvmStaticArrayMaterial.recordClass(pctx, clazz);
        }
        lowerStringConstantValuesForStringPass(pctx);
        prepareClassKeyTables(pctx);
        if (clazz != null && hasStaticNumericConstantValue(clazz)) {
            ensureClassKeyTable(pctx, clazz);
        }
    }

    @Override
    public void transformMethod(TransformContext ctx) {
        if (!(ctx instanceof PipelineContext pctx)) return;
        L1Class clazz = pctx.currentL1Class();
        L1Method method = pctx.currentL1Method();
        if (clazz == null || method == null || !method.hasCode()) return;
        if (!isApplicationMethod(pctx, clazz, method)) return;
        prepareClassKeyTables(pctx);
        activeKeyTable = ensureClassKeyTable(pctx, clazz);
        boolean externalEntrySeed = usesExternalEntrySeed(pctx, clazz, method);

        String methodKey = JvmKeyDispatchPass.coverageKey(clazz, method);
        MethodNode mn = method.asmNode();
        Integer recordedKeyLocal = JvmKeyDispatchPass.findMethodKeyLocal(
            pctx,
            methodKey
        );
        Long recordedMethodSeed = JvmKeyDispatchPass.findMethodSeed(pctx, methodKey);
        if (recordedKeyLocal == null || recordedMethodSeed == null) {
            int ensuredLocal = JvmKeyDispatchPass.ensureMethodKeyLocal(
                pctx,
                clazz,
                method
            );
            recordedKeyLocal = ensuredLocal >= 0 ? ensuredLocal : null;
            recordedMethodSeed = JvmKeyDispatchPass.findMethodSeed(pctx, methodKey);
        }
        if (recordedKeyLocal == null || recordedMethodSeed == null) {
            throw new IllegalStateException(
                "CFF cannot install a verified method key for " +
                    clazz.name() +
                    "." +
                    method.name() +
                    method.descriptor()
            );
        }
        int keyLocal = recordedKeyLocal;
        long methodSeed = recordedMethodSeed;
        int rewrittenCarrierIndexSites =
            JvmMethodParameterObfuscationPass.rewriteCarrierIndexDecodeSites(
                pctx,
                mn,
                activeKeyTable,
                keyLocal
            );
        if (rewrittenCarrierIndexSites > 0) {
            clazz.markDirty();
            pctx.invalidate(method);
        }
        if (pruneVerifierUnreachableInstructions(clazz.name(), mn)) {
            clazz.markDirty();
            pctx.invalidate(method);
        }
        LabelNode protectedStart = protectedStartLabel(
            clazz,
            method,
            mn,
            keyLocal
        );
        if (protectedStart == null) return;
        int splitLocals = splitMixedVerifierLocalShapes(clazz.name(), mn, protectedStart, keyLocal);
        if (splitLocals > 0) {
            log.debug(
                "Split {} mixed verifier local shapes in {}.{}{}",
                splitLocals,
                clazz.name(),
                method.name(),
                method.descriptor()
            );
        }
        installClassIntegrityEntryTicketConsume(pctx, clazz, mn, protectedStart, keyLocal, methodSeed);

        boolean validationSinkEnabled = pctx.config().isTransformEnabled(JvmValidationSinkHardeningPass.ID);
        if (validationSinkEnabled) {
            JvmValidationSinkHardeningPass.preparePlaceholders(pctx, clazz, method);
        }
        Set<LabelNode> injectedReflectionLeaders = rewriteInjectedMemberReflection(pctx, mn);
        List<ProtectedTryCatch> protectedTryCatches =
            captureProtectedTryCatches(mn);
        List<HandlerBridge> handlerBridges = splitExceptionHandlers(mn);
        Set<LabelNode> handlerBodies = handlerBodyLabels(handlerBridges);
        CffFrameAnalysis frames = CffFrameAnalysis.analyze(
            clazz.name(),
            mn
        );
        if (normalizeNonZeroStackControlTargets(pctx, mn, protectedStart, frames)) {
            frames = CffFrameAnalysis.analyze(clazz.name(), mn);
        }
        Set<LabelNode> zeroStackLabels = frames.zeroStackLabels();
        Set<LabelNode> linearLeaders = linearZeroStackLeaders(
            mn,
            protectedStart,
            frames
        );
        Set<LabelNode> extraLeaders = new HashSet<>(handlerBodies);
        extraLeaders.addAll(injectedReflectionLeaders);
        BlockPlan blockPlan = buildBlocks(
            mn,
            protectedStart,
            extraLeaders,
            zeroStackLabels,
            linearLeaders,
            frames
        );
        List<Block> blocks = blockPlan.blocks();
        if (blocks.isEmpty()) return;
        Map<LabelNode, LabelNode> blockAliases = new IdentityHashMap<>(
            blockPlan.aliases()
        );
        completeBlockLabelAliases(mn, protectedStart, blocks, blockAliases);

        int pcLocal = mn.maxLocals;
        int guardLocal = pcLocal + 1;
        int pathKeyLocal = pcLocal + 2;
        int blockKeyLocal = pcLocal + 3;
        int domainLocal = pcLocal + 4;
        int dataLocal = pcLocal + 5;
        int exceptionLocal = handlerBridges.isEmpty() ? -1 : pcLocal + 6;
        int keyTmpLocal = pcLocal + 6 + (handlerBridges.isEmpty() ? 0 : 1);
        int methodSeedLocal = handlerBridges.isEmpty() ? -1 : keyTmpLocal + 4;
        mn.maxLocals = keyTmpLocal + 4 + (handlerBridges.isEmpty() ? 0 : 2);
        int smallTokenDispatchCases = smallTokenDispatchCaseLimit(
            mn,
            blocks,
            handlerBridges
        );
        SyntheticNoiseBudget syntheticNoiseBudget = syntheticNoiseBudget(
            mn,
            blocks,
            handlerBridges
        );
        int outlinerCodePressure = estimatedOutlinerCodePressure(
            mn,
            blocks,
            handlerBridges
        );
        boolean outlineTransitions = useTransitionOutliner(
            mn,
            blocks,
            handlerBridges
        );
        boolean compactTransitionWrappers = useCompactTransitionWrappers(
            outlinerCodePressure,
            mn,
            blocks,
            handlerBridges
        );
        boolean outlineDispatchers = outlineTransitions;
        int transitionOutLocal = outlineDispatchers ? mn.maxLocals++ : -1;
        int compactTransitionStateLocal = outlineDispatchers && compactTransitionWrappers
            ? mn.maxLocals++
            : -1;
        int inlineDirectTransitionBudgetBytes = inlineDirectTransitionBudgetBytes(
            mn,
            blocks,
            handlerBridges,
            outlineTransitions
        );
        CffTransitionOutliner.TransitionOutliner dispatcherOutliner = outlineDispatchers
            ? new TransitionOutliner(
                pctx,
                clazz,
                transitionOutLocal,
                compactTransitionStateLocal,
                smallTokenDispatchCases,
                compactTransitionWrappers,
                inlineDirectTransitionBudgetBytes,
                syntheticNoiseBudget
            )
            : null;
        CffTransitionOutliner.TransitionOutliner transitionOutliner = outlineTransitions
            ? dispatcherOutliner
            : null;

        long salt = JvmPassBytecode.mix(
            pctx.masterSeed(),
            methodKey.hashCode()
        );
        int[] states = uniqueStates((int) (salt >>> 32), blocks.size());
        Map<LabelNode, Integer> stateByLabel = new IdentityHashMap<>();
        for (int i = 0; i < blocks.size(); i++) {
            stateByLabel.put(blocks.get(i).label(), states[i]);
        }
        // Dispatcher hubs are grouped by verifier frame shape. A transition may
        // jump to a hub only when every block behind that hub has compatible
        // locals and an empty stack.
        DispatchPlan dispatchPlan = buildDispatchPlan(
            blocks,
            frames,
            salt,
            stateByLabel,
            handlerReachableDomains(mn, blocks, blockAliases, handlerBodies),
            syntheticNoiseBudget
        );
        for (Map.Entry<LabelNode, LabelNode> alias : blockAliases.entrySet()) {
            LabelNode canonical = canonicalLabel(alias.getValue(), blockAliases);
            Integer aliasState = stateByLabel.get(canonical);
            DispatchTarget aliasTarget = dispatchPlan.targets().get(canonical);
            if (aliasState == null || aliasTarget == null) continue;
            stateByLabel.put(alias.getKey(), aliasState);
            dispatchPlan.targets().put(alias.getKey(), aliasTarget);
        }
        Map<LabelNode, CffBlockKeyState> keyStateByLabel =
            buildBlockKeyStates(blocks, blockAliases, stateByLabel, dispatchPlan.targets(), salt);
        installEntryKeyState(blocks, dispatchPlan, keyStateByLabel, methodSeed, externalEntrySeed);
        Map<DispatchTarget, Long> dispatchSeedByTarget =
            buildDispatchSeedByTarget(dispatchPlan, keyStateByLabel);
        Set<LabelNode> runtimeKeyLabels = runtimeKeyLabels(
            pctx,
            mn,
            blocks,
            blockAliases
        );
        insertPreProtectedKeyTransferStateInit(
            pctx,
            mn,
            protectedStart,
            blocks,
            dispatchPlan,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            keyTmpLocal,
            externalEntrySeed,
            methodSeed,
            stateByLabel,
            keyStateByLabel
        );
        rewriteKeyedCallTransfers(
            pctx,
            mn,
            blocks,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            keyTmpLocal,
            keyStateByLabel,
            salt
        );
        publishMethodMetadata(
            pctx,
            clazz,
            method,
            methodSeed,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            domainLocal,
            dataLocal,
            blocks,
            stateByLabel,
            dispatchPlan.targets(),
            keyStateByLabel,
            activeKeyTable
        );
        if (validationSinkEnabled) {
            JvmValidationSinkHardeningPass.hardenPreparedPlaceholders(pctx, clazz, method);
        }
        installPrimitiveDataDigestUpdates(
            pctx,
            mn,
            blocks,
            blockAliases,
            keyLocal,
            dataLocal,
            salt
        );

        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            if (block.handler()) continue;
            LabelNode next =
                i + 1 < blocks.size() && !blocks.get(i + 1).handler()
                    ? blocks.get(i + 1).label()
                    : null;
            rewriteBlockExit(
                mn,
                block,
                next,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                dataLocal,
                keyTmpLocal,
                keyLocal,
                stateByLabel,
                keyStateByLabel,
                dispatchPlan.targets(),
                dispatchSeedByTarget,
                runtimeKeyLabels,
                methodSeed,
                salt,
                transitionOutliner
            );
        }
        insertHandlerBridges(
            mn,
            handlerBridges,
            exceptionLocal,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            domainLocal,
            dataLocal,
            keyTmpLocal,
            methodSeedLocal,
            stateByLabel,
            keyStateByLabel,
            dispatchPlan.targets(),
            dispatchSeedByTarget,
            runtimeKeyLabels,
            methodSeed,
            salt,
            dispatcherOutliner,
            transitionOutliner
        );
        insertIslandDispatchers(
            mn,
            blocks,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            domainLocal,
            dataLocal,
            keyTmpLocal,
            methodSeedLocal,
            stateByLabel,
            keyStateByLabel,
            dispatchPlan,
            zeroStackLabels,
            exceptionLocal,
            JvmMethodParameterObfuscationPass.cffDataDigestExcludedArgumentLocals(
                pctx,
                clazz.name(),
                method.name(),
                method.descriptor()
            ),
            externalEntrySeed,
            methodSeed,
            salt,
            smallTokenDispatchCases,
            syntheticNoiseBudget,
            dispatcherOutliner,
            transitionOutliner
        );
        rebuildProtectedTryCatches(mn, protectedTryCatches);

        mn.localVariables = null;
        mn.visibleLocalVariableAnnotations = null;
        mn.invisibleLocalVariableAnnotations = null;
        mn.maxStack = Math.max(mn.maxStack + 16, 18);
        clazz.markDirty();
        pctx.invalidate(method);
        JvmObfuscationCoverage.get(ctx).full(
            id(),
            clazz.name(),
            method.name(),
            method.descriptor(),
            "direct-keyed-island-dispatchers-" + dispatchPlan.groups().size()
        );
        recordBudgetedDirectInlineStats(
            clazz.name() + "." + method.name() + method.descriptor(),
            transitionOutliner
        );
        logIslandDryRunMethodStats(
            pctx,
            clazz.name() + "." + method.name() + method.descriptor()
        );
    }

    private static void recordBudgetedDirectInlineStats(
        String methodKey,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        if (transitionOutliner == null) return;
        if (!Boolean.getBoolean(RECORD_BUDGETED_DIRECT_INLINE_STATS_PROPERTY)) return;
        BUDGETED_DIRECT_INLINE_STATS.put(
            methodKey,
            new BudgetedDirectInlineStats(
                transitionOutliner.inlineDirectTransitionCandidates(),
                transitionOutliner.inlineDirectTransitionAccepted(),
                transitionOutliner.inlineDirectTransitionRejected()
            )
        );
    }

    private void insertPreProtectedKeyTransferStateInit(
        PipelineContext pctx,
        MethodNode mn,
        LabelNode protectedStart,
        List<Block> blocks,
        DispatchPlan dispatchPlan,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int keyTmpLocal,
        boolean externalEntrySeed,
        long methodSeed,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel
    ) {
        AbstractInsnNode anchor = firstTargetSeededKeyLoadBeforeProtectedStart(pctx, mn, protectedStart);
        if (anchor == null) return;
        Block entry = firstNonHandler(blocks);
        if (entry == null) return;
        for (IslandGroup group : dispatchPlan.groups()) {
            if (!group.blocks().contains(entry)) continue;
            DispatchTarget entryTarget = requireTarget(
                entry.label(),
                dispatchPlan.targets().get(entry.label())
            );
            CffBlockKeyState entryKeys = requireBlockKey(
                entry.label(),
                keyStateByLabel.get(entry.label())
            );
            int preservedEntryKeyLocal = mn.maxLocals;
            mn.maxLocals = Math.max(mn.maxLocals, preservedEntryKeyLocal + 2);
            InsnList init = new InsnList();
            init.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            init.add(new VarInsnNode(Opcodes.LSTORE, preservedEntryKeyLocal));
            emitInitKeys(
                init,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                keyLocal,
                entryInitSeed(group.salt(), externalEntrySeed, methodSeed),
                keyTmpLocal
            );
            emitStorePc(
                init,
                pcLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                keyLocal,
                requireState(entry.label(), stateByLabel.get(entry.label())),
                entryKeys,
                methodSeed,
                entryTarget.selectorSeed(),
                keyTmpLocal
            );
            emitStoreMethodKey(
                init,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                entryKeys
            );
            JvmKeyDispatchPass.markGenerated(pctx, init);
            mn.instructions.insertBefore(anchor, init);

            InsnList restore = new InsnList();
            restore.add(new VarInsnNode(Opcodes.LLOAD, preservedEntryKeyLocal));
            restore.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
            JvmKeyDispatchPass.markGenerated(pctx, restore);
            mn.instructions.insertBefore(protectedStart, restore);
            return;
        }
    }

    private AbstractInsnNode firstTargetSeededKeyLoadBeforeProtectedStart(
        PipelineContext pctx,
        MethodNode mn,
        LabelNode protectedStart
    ) {
        Map<AbstractInsnNode, Long> targetSeeds = generatedKeyLoadTargetSeeds(pctx);
        if (targetSeeds.isEmpty()) return null;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null && insn != protectedStart; insn = insn.getNext()) {
            if (targetSeeds.containsKey(insn)) {
                return insn;
            }
        }
        return null;
    }

    private SyntheticNoiseBudget syntheticNoiseBudget(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        int pressure = estimatedOutlinerCodePressure(mn, blocks, handlerBridges);
        if (pressure >= 18_000) {
            return SyntheticNoiseBudget.CRITICAL;
        }
        if (pressure >= 8_000) {
            return SyntheticNoiseBudget.PRESSURE;
        }
        return SyntheticNoiseBudget.NORMAL;
    }

    private void installPrimitiveDataDigestUpdates(
        PipelineContext pctx,
        MethodNode mn,
        List<Block> blocks,
        Map<LabelNode, LabelNode> blockAliases,
        int keyLocal,
        int dataLocal,
        long salt
    ) {
        List<DataDigestObservation> observations = new ArrayList<>();
        Map<Integer, Integer> cyclicRegions = cyclicBlockRegions(mn, blocks, blockAliases);
        int ordinal = 0;
        for (int blockIndex = 0; blockIndex < blocks.size(); blockIndex++) {
            Block block = blocks.get(blockIndex);
            int cyclicRegion = cyclicRegions.getOrDefault(blockIndex, -1);
            for (
                AbstractInsnNode insn = block.label();
                insn != null && insn != block.endExclusive();
                insn = insn.getNext()
            ) {
                if (insn.getOpcode() < 0 || JvmKeyDispatchPass.isGeneratedNode(pctx, insn)) {
                    continue;
                }
                DataDigestObservation observation = primitiveDataDigestObservation(
                    insn,
                    keyLocal,
                    ordinal++,
                    salt,
                    blockIndex,
                    cyclicRegion
                );
                if (observation != null) {
                    observations.add(observation);
                }
            }
        }
        int budget = primitiveDataDigestObservationBudget(blocks);
        List<DataDigestObservation> selected = selectPrimitiveDataDigestObservations(observations, budget);
        if (selected.isEmpty()) return;
        int digestScratchLocal = mn.maxLocals;
        int digestMixLocal = digestScratchLocal + 2;
        mn.maxLocals = Math.max(mn.maxLocals, digestMixLocal + 1);
        for (DataDigestObservation observation : selected) {
            InsnList update = emitPrimitiveDataDigestUpdate(
                observation.kind(),
                dataLocal,
                observation.seed(),
                observation.local(),
                digestScratchLocal,
                digestMixLocal
            );
            JvmKeyDispatchPass.markGenerated(pctx, update);
            if (observation.after()) {
                mn.instructions.insert(observation.anchor(), update);
            } else {
                mn.instructions.insertBefore(observation.anchor(), update);
            }
        }
        mn.maxStack = Math.max(mn.maxStack + 6, 10);
    }

    private DataDigestObservation primitiveDataDigestObservation(
        AbstractInsnNode insn,
        int keyLocal,
        int ordinal,
        long salt,
        int blockIndex,
        int cyclicRegion
    ) {
        PrimitiveDigestKind kind = primitiveDigestKind(insn, keyLocal);
        if (kind == null) return null;
        if (beforeReferenceArrayConstructionStore(insn)) return null;
        if (insideReferenceArrayStoreSlice(insn)) return null;
        if (insideObjectArrayFieldReferenceStoreSlice(insn)) return null;
        boolean after = digestObservationAfter(insn);
        long seed = JvmPassBytecode.mix(
            salt ^ 0x44415441464C4F57L,
            (long) ordinal << 32 ^ insn.getOpcode() ^ kind.ordinal()
        );
        return new DataDigestObservation(
            insn,
            after,
            kind,
            digestObservationLocal(insn),
            seed,
            blockIndex,
            cyclicRegion,
            ordinal
        );
    }

    private Map<Integer, Integer> cyclicBlockRegions(
        MethodNode mn,
        List<Block> blocks,
        Map<LabelNode, LabelNode> blockAliases
    ) {
        if (blocks.size() < 2) return Map.of();
        Map<LabelNode, Integer> blockIndex = new IdentityHashMap<>();
        Map<LabelNode, LabelNode> nextByLabel = new IdentityHashMap<>();
        for (int i = 0; i < blocks.size(); i++) {
            blockIndex.put(blocks.get(i).label(), i);
            if (i + 1 < blocks.size()) {
                nextByLabel.put(blocks.get(i).label(), blocks.get(i + 1).label());
            }
        }
        List<LoopInterval> intervals = new ArrayList<>();
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            if (block.handler()) continue;
            for (LabelNode successor : blockSuccessors(mn, block, nextByLabel)) {
                Integer target = blockIndex.get(canonicalLabel(successor, blockAliases));
                if (target == null || target > i) continue;
                intervals.add(new LoopInterval(target, i));
            }
        }
        if (intervals.isEmpty()) return Map.of();
        intervals.sort((left, right) -> Integer.compare(left.start(), right.start()));
        List<LoopInterval> merged = new ArrayList<>();
        int start = intervals.get(0).start();
        int end = intervals.get(0).end();
        for (int i = 1; i < intervals.size(); i++) {
            LoopInterval interval = intervals.get(i);
            if (interval.start() <= end) {
                end = Math.max(end, interval.end());
            } else {
                merged.add(new LoopInterval(start, end));
                start = interval.start();
                end = interval.end();
            }
        }
        merged.add(new LoopInterval(start, end));

        Map<Integer, Integer> regionByBlock = new HashMap<>();
        for (int region = 0; region < merged.size(); region++) {
            LoopInterval interval = merged.get(region);
            for (int block = interval.start(); block <= interval.end(); block++) {
                regionByBlock.put(block, region);
            }
        }
        return regionByBlock;
    }

    private int digestObservationLocal(AbstractInsnNode insn) {
        return insn instanceof IincInsnNode iinc ? iinc.var : -1;
    }

    private boolean insideReferenceArrayStoreSlice(AbstractInsnNode insn) {
        if (!hasForwardReferenceArrayStore(insn)) return false;
        return hasBackwardReferenceArrayCarrier(insn);
    }

    private boolean beforeReferenceArrayConstructionStore(AbstractInsnNode insn) {
        int seen = 0;
        for (AbstractInsnNode scan = insn.getNext(); scan != null && seen < 32; scan = scan.getNext()) {
            int opcode = scan.getOpcode();
            if (opcode < 0) continue;
            seen++;
            if (scan instanceof TypeInsnNode type && type.getOpcode() == Opcodes.ANEWARRAY) {
                return referenceArrayConstructionFeedsStore(type);
            }
            if (endsLinearStackSlice(opcode)) return false;
        }
        return false;
    }

    private boolean referenceArrayConstructionFeedsStore(AbstractInsnNode arrayInsn) {
        int seen = 0;
        for (AbstractInsnNode scan = arrayInsn.getNext(); scan != null && seen < 160; scan = scan.getNext()) {
            int opcode = scan.getOpcode();
            if (opcode < 0) continue;
            seen++;
            if (opcode == Opcodes.AASTORE) return true;
            if (endsLinearStackSlice(opcode)) return false;
        }
        return false;
    }

    private boolean insideObjectArrayFieldReferenceStoreSlice(AbstractInsnNode insn) {
        if (!hasForwardReferenceArrayStore(insn)) return false;
        return hasBackwardObjectArrayFieldLoad(insn);
    }

    private boolean hasForwardReferenceArrayStore(AbstractInsnNode insn) {
        int seen = 0;
        for (AbstractInsnNode scan = insn.getNext(); scan != null && seen < 160; scan = scan.getNext()) {
            int opcode = scan.getOpcode();
            if (opcode < 0) continue;
            seen++;
            if (opcode == Opcodes.AASTORE) return true;
            if (endsLinearStackSlice(opcode)) return false;
        }
        return false;
    }

    private boolean hasBackwardReferenceArrayCarrier(AbstractInsnNode insn) {
        int seen = 0;
        for (AbstractInsnNode scan = insn.getPrevious(); scan != null && seen < 160; scan = scan.getPrevious()) {
            int opcode = scan.getOpcode();
            if (opcode < 0) continue;
            seen++;
            if (opcode == Opcodes.AASTORE) return false;
            if (opcode == Opcodes.DUP || opcode == Opcodes.ALOAD) return true;
            if (endsLinearStackSlice(opcode)) return false;
        }
        return false;
    }

    private boolean hasBackwardObjectArrayFieldLoad(AbstractInsnNode insn) {
        int seen = 0;
        for (AbstractInsnNode scan = insn.getPrevious(); scan != null && seen < 160; scan = scan.getPrevious()) {
            int opcode = scan.getOpcode();
            if (opcode < 0) continue;
            seen++;
            if (opcode == Opcodes.AASTORE) return false;
            if (scan instanceof FieldInsnNode field
                && field.getOpcode() == Opcodes.GETSTATIC
                && "[Ljava/lang/Object;".equals(field.desc)) {
                return true;
            }
            if (endsLinearStackSlice(opcode)) return false;
        }
        return false;
    }

    private boolean endsLinearStackSlice(int opcode) {
        return opcode == Opcodes.ATHROW
            || opcode == Opcodes.RET
            || (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN)
            || (opcode >= Opcodes.IFEQ && opcode <= Opcodes.JSR)
            || opcode == Opcodes.TABLESWITCH
            || opcode == Opcodes.LOOKUPSWITCH;
    }

    private static boolean pruneVerifierUnreachableInstructions(String owner, MethodNode mn) {
        if (mn.instructions == null || mn.instructions.size() == 0) return false;
        try {
            Analyzer<BasicValue> analyzer = new Analyzer<>(new BasicInterpreter());
            Frame<BasicValue>[] frames = analyzer.analyze(owner, mn);
            AbstractInsnNode[] insns = mn.instructions.toArray();
            boolean changed = false;
            for (int i = 0; i < insns.length && i < frames.length; i++) {
                if (frames[i] == null && insns[i].getOpcode() >= 0) {
                    mn.instructions.remove(insns[i]);
                    changed = true;
                }
            }
            return changed;
        } catch (Exception e) {
            throw new IllegalStateException(
                "Cannot prune verifier-unreachable instructions for " + owner + "." + mn.name + mn.desc,
                e
            );
        }
    }

    private PrimitiveDigestKind primitiveDigestKind(AbstractInsnNode insn, int keyLocal) {
        int opcode = insn.getOpcode();
        if (insn instanceof IincInsnNode iinc) {
            return overlapsKeyLocal(new LocalShape(iinc.var, LocalKind.INT), keyLocal)
                ? null
                : PrimitiveDigestKind.INT;
        }
        if (insn instanceof VarInsnNode var) {
            LocalKind localKind = localKind(var.getOpcode());
            if (localKind == null || localKind == LocalKind.REF) return null;
            if (overlapsKeyLocal(new LocalShape(var.var, localKind), keyLocal)) return null;
            return switch (var.getOpcode()) {
                case Opcodes.ILOAD, Opcodes.ISTORE -> PrimitiveDigestKind.INT;
                case Opcodes.LLOAD, Opcodes.LSTORE -> PrimitiveDigestKind.LONG;
                case Opcodes.FLOAD, Opcodes.FSTORE -> PrimitiveDigestKind.FLOAT;
                case Opcodes.DLOAD, Opcodes.DSTORE -> PrimitiveDigestKind.DOUBLE;
                default -> null;
            };
        }
        if (insn instanceof LdcInsnNode ldc) {
            Object cst = ldc.cst;
            if (cst instanceof Integer) return PrimitiveDigestKind.INT;
            if (cst instanceof Long) return PrimitiveDigestKind.LONG;
            if (cst instanceof Float) return PrimitiveDigestKind.FLOAT;
            if (cst instanceof Double) return PrimitiveDigestKind.DOUBLE;
            return null;
        }
        if (insn instanceof IntInsnNode) {
            return switch (opcode) {
                case Opcodes.BIPUSH, Opcodes.SIPUSH -> PrimitiveDigestKind.INT;
                default -> null;
            };
        }
        return switch (opcode) {
            case Opcodes.ICONST_M1,
                Opcodes.ICONST_0,
                Opcodes.ICONST_1,
                Opcodes.ICONST_2,
                Opcodes.ICONST_3,
                Opcodes.ICONST_4,
                Opcodes.ICONST_5,
                Opcodes.IADD,
                Opcodes.ISUB,
                Opcodes.IMUL,
                Opcodes.IDIV,
                Opcodes.IREM,
                Opcodes.IAND,
                Opcodes.IOR,
                Opcodes.IXOR,
                Opcodes.ISHL,
                Opcodes.ISHR,
                Opcodes.IUSHR,
                Opcodes.INEG,
                Opcodes.IALOAD,
                Opcodes.BALOAD,
                Opcodes.CALOAD,
                Opcodes.SALOAD,
                Opcodes.IASTORE,
                Opcodes.BASTORE,
                Opcodes.CASTORE,
                Opcodes.SASTORE -> PrimitiveDigestKind.INT;
            case Opcodes.LCONST_0,
                Opcodes.LCONST_1,
                Opcodes.LADD,
                Opcodes.LSUB,
                Opcodes.LMUL,
                Opcodes.LDIV,
                Opcodes.LREM,
                Opcodes.LAND,
                Opcodes.LOR,
                Opcodes.LXOR,
                Opcodes.LSHL,
                Opcodes.LSHR,
                Opcodes.LUSHR,
                Opcodes.LNEG,
                Opcodes.LALOAD,
                Opcodes.LASTORE -> PrimitiveDigestKind.LONG;
            case Opcodes.FCONST_0,
                Opcodes.FCONST_1,
                Opcodes.FCONST_2,
                Opcodes.FADD,
                Opcodes.FSUB,
                Opcodes.FMUL,
                Opcodes.FDIV,
                Opcodes.FREM,
                Opcodes.FNEG,
                Opcodes.FALOAD,
                Opcodes.FASTORE -> PrimitiveDigestKind.FLOAT;
            case Opcodes.DCONST_0,
                Opcodes.DCONST_1,
                Opcodes.DADD,
                Opcodes.DSUB,
                Opcodes.DMUL,
                Opcodes.DDIV,
                Opcodes.DREM,
                Opcodes.DNEG,
                Opcodes.DALOAD,
                Opcodes.DASTORE -> PrimitiveDigestKind.DOUBLE;
            default -> null;
        };
    }

    private boolean digestObservationAfter(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (insn instanceof IincInsnNode) return true;
        return switch (opcode) {
            case Opcodes.ISTORE,
                Opcodes.LSTORE,
                Opcodes.FSTORE,
                Opcodes.DSTORE,
                Opcodes.IASTORE,
                Opcodes.LASTORE,
                Opcodes.FASTORE,
                Opcodes.DASTORE,
                Opcodes.BASTORE,
                Opcodes.CASTORE,
                Opcodes.SASTORE -> false;
            default -> true;
        };
    }

    private int primitiveDataDigestObservationBudget(List<Block> blocks) {
        return Math.max(12, Math.min(96, blocks.size() * 3));
    }

    private List<DataDigestObservation> selectPrimitiveDataDigestObservations(
        List<DataDigestObservation> observations,
        int budget
    ) {
        boolean hasCyclicObservation = false;
        for (DataDigestObservation observation : observations) {
            if (observation.cyclic()) {
                hasCyclicObservation = true;
                break;
            }
        }
        if (observations.size() <= budget && !hasCyclicObservation) return observations;
        if (!hasCyclicObservation) {
            return selectUniformPrimitiveDataDigestObservations(observations, budget);
        }

        Map<Integer, DataDigestObservation> cyclicByRegion = new LinkedHashMap<>();
        List<DataDigestObservation> nonCyclic = new ArrayList<>();
        for (DataDigestObservation observation : observations) {
            if (!observation.cyclic()) {
                nonCyclic.add(observation);
                continue;
            }
            cyclicByRegion.merge(
                observation.cyclicRegion(),
                observation,
                this::preferredCyclicDataDigestObservation
            );
        }

        List<DataDigestObservation> selected = new ArrayList<>(budget);
        Set<DataDigestObservation> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        List<DataDigestObservation> cyclic = new ArrayList<>(cyclicByRegion.values());
        int cyclicBudget = Math.min(
            cyclic.size(),
            Math.max(1, Math.min(budget, (budget * 2) / 3))
        );
        addSelectedPrimitiveDataDigestObservations(
            selected,
            seen,
            selectUniformPrimitiveDataDigestObservations(cyclic, cyclicBudget)
        );
        int nonCyclicBudget = Math.min(
            budget - selected.size(),
            Math.min(nonCyclic.size(), Math.max(4, budget / 4))
        );
        addSelectedPrimitiveDataDigestObservations(
            selected,
            seen,
            selectRankedPrimitiveDataDigestObservations(nonCyclic, nonCyclicBudget)
        );
        selected.sort((left, right) -> Integer.compare(left.ordinal(), right.ordinal()));
        return selected;
    }

    private List<DataDigestObservation> selectUniformPrimitiveDataDigestObservations(
        List<DataDigestObservation> observations,
        int budget
    ) {
        if (budget <= 0 || observations.isEmpty()) return List.of();
        if (observations.size() <= budget) return observations;
        List<DataDigestObservation> selected = new ArrayList<>(budget);
        for (int i = 0; i < budget; i++) {
            int index = (int) (((long) i * observations.size()) / budget);
            selected.add(observations.get(index));
        }
        return selected;
    }

    private List<DataDigestObservation> selectRankedPrimitiveDataDigestObservations(
        List<DataDigestObservation> observations,
        int budget
    ) {
        if (budget <= 0 || observations.isEmpty()) return List.of();
        List<DataDigestObservation> ranked = new ArrayList<>(observations);
        ranked.sort((left, right) -> {
            int leftScore = cyclicDataDigestObservationScore(left);
            int rightScore = cyclicDataDigestObservationScore(right);
            if (leftScore != rightScore) {
                return Integer.compare(leftScore, rightScore);
            }
            return Integer.compare(left.ordinal(), right.ordinal());
        });
        if (ranked.size() > budget) {
            ranked = new ArrayList<>(ranked.subList(0, budget));
        }
        return ranked;
    }

    private void addSelectedPrimitiveDataDigestObservations(
        List<DataDigestObservation> selected,
        Set<DataDigestObservation> seen,
        List<DataDigestObservation> candidates
    ) {
        for (DataDigestObservation candidate : candidates) {
            if (seen.add(candidate)) {
                selected.add(candidate);
            }
        }
    }

    private DataDigestObservation preferredCyclicDataDigestObservation(
        DataDigestObservation left,
        DataDigestObservation right
    ) {
        int leftScore = cyclicDataDigestObservationScore(left);
        int rightScore = cyclicDataDigestObservationScore(right);
        if (leftScore != rightScore) {
            return leftScore <= rightScore ? left : right;
        }
        return left.ordinal() <= right.ordinal() ? left : right;
    }

    private int cyclicDataDigestObservationScore(DataDigestObservation observation) {
        AbstractInsnNode insn = observation.anchor();
        if (insn instanceof IincInsnNode) return 0;
        int base = switch (observation.kind()) {
            case INT -> 2;
            case LONG -> 8;
            case FLOAT -> 12;
            case DOUBLE -> 16;
        };
        if (insn instanceof VarInsnNode var) {
            return base + (isPrimitiveLocalLoad(var.getOpcode()) ? 0 : 1);
        }
        if (isPrimitiveArrayAccess(insn.getOpcode())) {
            return base + 4;
        }
        if (isPrimitiveConstant(insn)) {
            return base + 8;
        }
        return base + 6;
    }

    private boolean isPrimitiveLocalLoad(int opcode) {
        return opcode == Opcodes.ILOAD ||
            opcode == Opcodes.LLOAD ||
            opcode == Opcodes.FLOAD ||
            opcode == Opcodes.DLOAD;
    }

    private boolean isPrimitiveArrayAccess(int opcode) {
        return switch (opcode) {
            case Opcodes.IALOAD,
                Opcodes.LALOAD,
                Opcodes.FALOAD,
                Opcodes.DALOAD,
                Opcodes.BALOAD,
                Opcodes.CALOAD,
                Opcodes.SALOAD,
                Opcodes.IASTORE,
                Opcodes.LASTORE,
                Opcodes.FASTORE,
                Opcodes.DASTORE,
                Opcodes.BASTORE,
                Opcodes.CASTORE,
                Opcodes.SASTORE -> true;
            default -> false;
        };
    }

    private boolean isPrimitiveConstant(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (insn instanceof LdcInsnNode ldc) {
            return ldc.cst instanceof Number;
        }
        if (insn instanceof IntInsnNode) {
            return opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH;
        }
        return switch (opcode) {
            case Opcodes.ICONST_M1,
                Opcodes.ICONST_0,
                Opcodes.ICONST_1,
                Opcodes.ICONST_2,
                Opcodes.ICONST_3,
                Opcodes.ICONST_4,
                Opcodes.ICONST_5,
                Opcodes.LCONST_0,
                Opcodes.LCONST_1,
                Opcodes.FCONST_0,
                Opcodes.FCONST_1,
                Opcodes.FCONST_2,
                Opcodes.DCONST_0,
                Opcodes.DCONST_1 -> true;
            default -> false;
        };
    }

    private InsnList emitPrimitiveDataDigestUpdate(
        PrimitiveDigestKind kind,
        int dataLocal,
        long seed,
        int local,
        int scratchLocal,
        int mixLocal
    ) {
        InsnList update = new InsnList();
        if (local >= 0) {
            update.add(new VarInsnNode(Opcodes.ILOAD, local));
        } else {
            switch (kind) {
                case INT -> {
                    update.add(new VarInsnNode(Opcodes.ISTORE, scratchLocal));
                    update.add(new VarInsnNode(Opcodes.ILOAD, scratchLocal));
                }
                case LONG -> {
                    update.add(new VarInsnNode(Opcodes.LSTORE, scratchLocal));
                    update.add(new VarInsnNode(Opcodes.LLOAD, scratchLocal));
                    update.add(new MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        "java/lang/Long",
                        "hashCode",
                        "(J)I",
                        false
                    ));
                }
                case FLOAT -> {
                    update.add(new VarInsnNode(Opcodes.FSTORE, scratchLocal));
                    update.add(new VarInsnNode(Opcodes.FLOAD, scratchLocal));
                    update.add(new MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        "java/lang/Float",
                        "floatToRawIntBits",
                        "(F)I",
                        false
                    ));
                }
                case DOUBLE -> {
                    update.add(new VarInsnNode(Opcodes.DSTORE, scratchLocal));
                    update.add(new VarInsnNode(Opcodes.DLOAD, scratchLocal));
                    update.add(new MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        "java/lang/Double",
                        "hashCode",
                        "(D)I",
                        false
                    ));
                }
            }
        }
        emitFoldPrimitiveDataDigestValue(update, dataLocal, seed, mixLocal);
        if (local < 0) {
            switch (kind) {
                case INT -> update.add(new VarInsnNode(Opcodes.ILOAD, scratchLocal));
                case LONG -> update.add(new VarInsnNode(Opcodes.LLOAD, scratchLocal));
                case FLOAT -> update.add(new VarInsnNode(Opcodes.FLOAD, scratchLocal));
                case DOUBLE -> update.add(new VarInsnNode(Opcodes.DLOAD, scratchLocal));
            }
        }
        return update;
    }

    private void emitFoldPrimitiveDataDigestValue(
        InsnList insns,
        int dataLocal,
        long seed,
        int mixLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new InsnNode(Opcodes.SWAP));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4449474D554C31L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, mixLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, mixLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, mixLocal));
        JvmPassBytecode.pushInt(insns, shift(seed, 11));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x44494746494E31L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dataLocal));
    }

    private int splitMixedVerifierLocalShapes(String owner, MethodNode mn, LabelNode protectedStart, int keyLocal) {
        CffFrameAnalysis frames = CffFrameAnalysis.analyze(owner, mn);
        Map<VarInsnNode, String> referenceLoadDescriptors = referenceLoadDescriptors(frames, mn, protectedStart);
        Map<Integer, Set<LocalShape>> shapesBySlot = new HashMap<>();
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            LocalShape shape = localShape(insn);
            if (shape == null) continue;
            for (int slot = shape.var(); slot < shape.var() + shape.kind().slots(); slot++) {
                shapesBySlot.computeIfAbsent(slot, ignored -> new HashSet<>()).add(shape);
            }
        }

        Set<LocalShape> conflicting = new HashSet<>();
        for (Set<LocalShape> slotShapes : shapesBySlot.values()) {
            if (slotShapes.size() <= 1) continue;
            conflicting.addAll(slotShapes);
        }

        Map<Integer, LocalShape> argumentShapes = argumentShapes(mn);
        Map<LocalShape, Integer> remap = new LinkedHashMap<>();
        int nextLocal = mn.maxLocals;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            LocalShape shape = localShape(insn);
            if (shape == null || !conflicting.contains(shape)) continue;
            if (shape.equals(argumentShapes.get(shape.var()))) continue;
            if (overlapsKeyLocal(shape, keyLocal)) continue;
            if (!remap.containsKey(shape)) {
                remap.put(shape, nextLocal);
                nextLocal += shape.kind().slots();
            }
        }
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            LocalShape shape = localShape(insn);
            if (shape == null) continue;
            Integer newLocal = remap.get(shape);
            if (newLocal == null) continue;
            if (insn instanceof VarInsnNode var) {
                var.var = newLocal;
            } else if (insn instanceof IincInsnNode iinc) {
                iinc.var = newLocal;
            }
        }
        Map<LocalShape, Integer> defaultLocals = localDefaults(
            mn,
            remap,
            argumentLocalLimit(mn),
            keyLocal,
            protectedStart
        );
        InsnList defaultInsns = new InsnList();
        for (Map.Entry<LocalShape, Integer> entry : defaultLocals.entrySet()) {
            emitLocalDefault(defaultInsns, entry.getValue(), entry.getKey());
        }
        if (defaultLocals.size() > 0) {
            mn.instructions.insertBefore(protectedStart, defaultInsns);
        }
        insertReferenceLoadCasts(mn, referenceLoadDescriptors);
        mn.maxLocals = Math.max(mn.maxLocals, nextLocal);
        mn.maxStack = Math.max(mn.maxStack, 2);
        return remap.size();
    }

    private Map<VarInsnNode, String> referenceLoadDescriptors(
        CffFrameAnalysis frames,
        MethodNode mn,
        LabelNode protectedStart
    ) {
        Map<VarInsnNode, String> descriptors = new IdentityHashMap<>();
        boolean active = false;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn == protectedStart) active = true;
            if (!active) continue;
            if (!(insn instanceof VarInsnNode var) || var.getOpcode() != Opcodes.ALOAD) continue;
            String descriptor = frames.localDescriptor(var, var.var);
            String castType = referenceCastType(descriptor);
            if (castType == null && "Ljava/lang/Object;".equals(descriptor)) {
                castType = consumedReferenceCastType(var);
            }
            if (castType != null) {
                descriptors.put(var, castType);
            }
        }
        return descriptors;
    }

    private void insertReferenceLoadCasts(MethodNode mn, Map<VarInsnNode, String> descriptors) {
        for (Map.Entry<VarInsnNode, String> entry : descriptors.entrySet()) {
            VarInsnNode load = entry.getKey();
            if (load.getOpcode() != Opcodes.ALOAD) continue;
            mn.instructions.insert(load, new TypeInsnNode(Opcodes.CHECKCAST, entry.getValue()));
        }
    }

    private String referenceCastType(String descriptor) {
        if (descriptor == null
            || descriptor.isBlank()
            || descriptor.equals(".")
            || descriptor.equals("Lnull;")
            || "Ljava/lang/Object;".equals(descriptor)) {
            return null;
        }
        if (descriptor.charAt(0) == '[') {
            return descriptor;
        }
        if (descriptor.charAt(0) == 'L' && descriptor.charAt(descriptor.length() - 1) == ';') {
            return descriptor.substring(1, descriptor.length() - 1);
        }
        return null;
    }

    private String consumedReferenceCastType(VarInsnNode load) {
        int suffixSlots = 1;
        for (AbstractInsnNode cursor = nextReal(load.getNext()); cursor != null; cursor = nextReal(cursor.getNext())) {
            int opcode = cursor.getOpcode();
            if (cursor instanceof TypeInsnNode typeInsn && opcode == Opcodes.CHECKCAST) {
                return null;
            }
            if (cursor instanceof MethodInsnNode call) {
                return nonObjectReferenceCastType(invocationOperandType(call, suffixSlots));
            }
            if (cursor instanceof InvokeDynamicInsnNode indy) {
                return nonObjectReferenceCastType(invokeDynamicOperandType(indy, suffixSlots));
            }
            if (cursor instanceof FieldInsnNode field) {
                return nonObjectReferenceCastType(fieldOperandType(field, suffixSlots));
            }
            Integer delta = simpleStackDelta(cursor);
            if (delta == null) return null;
            suffixSlots += delta;
            if (suffixSlots <= 0 || suffixSlots > 32) return null;
        }
        return null;
    }

    private String invocationOperandType(MethodInsnNode call, int suffixSlots) {
        List<String> operands = new ArrayList<>();
        if (call.getOpcode() != Opcodes.INVOKESTATIC) {
            operands.add(call.owner);
        }
        for (Type arg : Type.getArgumentTypes(call.desc)) {
            appendOperandSlots(operands, arg);
        }
        return suffixOperandType(operands, suffixSlots);
    }

    private String invokeDynamicOperandType(InvokeDynamicInsnNode indy, int suffixSlots) {
        List<String> operands = new ArrayList<>();
        for (Type arg : Type.getArgumentTypes(indy.desc)) {
            appendOperandSlots(operands, arg);
        }
        return suffixOperandType(operands, suffixSlots);
    }

    private String fieldOperandType(FieldInsnNode field, int suffixSlots) {
        List<String> operands = new ArrayList<>();
        Type fieldType = Type.getType(field.desc);
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

    private void appendOperandSlots(List<String> operands, Type type) {
        operands.add(referenceTypeName(type));
        if (type.getSize() == 2) {
            operands.add(null);
        }
    }

    private String suffixOperandType(List<String> operands, int suffixSlots) {
        if (suffixSlots <= 0 || suffixSlots > operands.size()) return null;
        return operands.get(operands.size() - suffixSlots);
    }

    private String referenceTypeName(Type type) {
        if (type == null) return null;
        return switch (type.getSort()) {
            case Type.OBJECT -> type.getInternalName();
            case Type.ARRAY -> type.getDescriptor();
            default -> null;
        };
    }

    private String nonObjectReferenceCastType(String type) {
        if (type == null || type.isBlank() || "java/lang/Object".equals(type) || "Ljava/lang/Object;".equals(type)) {
            return null;
        }
        return type;
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
        if (insn instanceof LdcInsnNode ldc) {
            Object cst = ldc.cst;
            return new StackEffect(0, (cst instanceof Long || cst instanceof Double) ? 2 : 1);
        }
        if (insn instanceof IntInsnNode) {
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
        if (insn instanceof FieldInsnNode field) {
            int fieldSize = Type.getType(field.desc).getSize();
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
            for (Type arg : Type.getArgumentTypes(call.desc)) {
                consumed += arg.getSize();
            }
            return new StackEffect(consumed, Type.getReturnType(call.desc).getSize());
        }
        if (insn instanceof InvokeDynamicInsnNode indy) {
            int consumed = 0;
            for (Type arg : Type.getArgumentTypes(indy.desc)) {
                consumed += arg.getSize();
            }
            return new StackEffect(consumed, Type.getReturnType(indy.desc).getSize());
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

    private Map<LocalShape, Integer> localDefaults(
        MethodNode mn,
        Map<LocalShape, Integer> remap,
        int argumentLimit,
        int keyLocal,
        LabelNode protectedStart
    ) {
        Set<Integer> storedSlotsBeforeProtectedStart = storedSlotsBeforeProtectedStart(mn, protectedStart);
        Set<Integer> readBeforeStoreSlots = readBeforeStoreSlotsBeforeProtectedStart(mn, protectedStart);
        Map<LocalShape, Integer> defaults = new LinkedHashMap<>();
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!readsLocal(insn)) continue;
            LocalShape shape = localShape(insn);
            if (shape == null || shape.var() < argumentLimit || overlapsKeyLocal(shape, keyLocal)) continue;
            if (overlapsStoredSlot(shape, storedSlotsBeforeProtectedStart)
                && !overlapsStoredSlot(shape, readBeforeStoreSlots)) {
                continue;
            }
            Integer local = remap.get(shape);
            defaults.putIfAbsent(shape, local == null ? shape.var() : local);
        }
        return defaults;
    }

    private Set<Integer> storedSlotsBeforeProtectedStart(
        MethodNode mn,
        LabelNode protectedStart
    ) {
        Set<Integer> stored = new HashSet<>();
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn == protectedStart) break;
            if (!writesLocal(insn)) continue;
            LocalShape shape = localShape(insn);
            if (shape == null) continue;
            for (int slot = shape.var(); slot < shape.var() + shape.kind().slots(); slot++) {
                stored.add(slot);
            }
        }
        return stored;
    }

    private Set<Integer> readBeforeStoreSlotsBeforeProtectedStart(
        MethodNode mn,
        LabelNode protectedStart
    ) {
        Set<Integer> written = new HashSet<>();
        Set<Integer> readBeforeWrite = new HashSet<>();
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn == protectedStart) break;
            if (readsLocal(insn)) {
                LocalShape shape = localShape(insn);
                if (shape != null) {
                    for (int slot = shape.var(); slot < shape.var() + shape.kind().slots(); slot++) {
                        if (!written.contains(slot)) {
                            readBeforeWrite.add(slot);
                        }
                    }
                }
            }
            if (!writesLocal(insn)) continue;
            LocalShape shape = localShape(insn);
            if (shape == null) continue;
            for (int slot = shape.var(); slot < shape.var() + shape.kind().slots(); slot++) {
                written.add(slot);
            }
        }
        return readBeforeWrite;
    }

    private boolean overlapsStoredSlot(LocalShape shape, Set<Integer> storedSlots) {
        for (int slot = shape.var(); slot < shape.var() + shape.kind().slots(); slot++) {
            if (storedSlots.contains(slot)) return true;
        }
        return false;
    }

    private boolean writesLocal(AbstractInsnNode insn) {
        if (insn instanceof IincInsnNode) return true;
        if (!(insn instanceof VarInsnNode var)) return false;
        return switch (var.getOpcode()) {
            case Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE, Opcodes.ASTORE -> true;
            default -> false;
        };
    }

    private boolean readsLocal(AbstractInsnNode insn) {
        if (insn instanceof IincInsnNode) return true;
        if (!(insn instanceof VarInsnNode var)) return false;
        return switch (var.getOpcode()) {
            case Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD, Opcodes.ALOAD -> true;
            default -> false;
        };
    }

    private int argumentLocalLimit(MethodNode mn) {
        int local = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type type : Type.getArgumentTypes(mn.desc)) {
            local += type.getSize();
        }
        return local;
    }

    private boolean overlapsKeyLocal(LocalShape shape, int keyLocal) {
        int start = shape.var();
        int end = shape.var() + shape.kind().slots();
        return start < keyLocal + 2 && keyLocal < end;
    }

    private void emitLocalDefault(InsnList insns, int local, LocalShape shape) {
        switch (shape.kind()) {
            case INT -> {
                insns.add(new InsnNode(Opcodes.ICONST_0));
                insns.add(new VarInsnNode(Opcodes.ISTORE, local));
            }
            case LONG -> {
                insns.add(new InsnNode(Opcodes.LCONST_0));
                insns.add(new VarInsnNode(Opcodes.LSTORE, local));
            }
            case FLOAT -> {
                insns.add(new InsnNode(Opcodes.FCONST_0));
                insns.add(new VarInsnNode(Opcodes.FSTORE, local));
            }
            case DOUBLE -> {
                insns.add(new InsnNode(Opcodes.DCONST_0));
                insns.add(new VarInsnNode(Opcodes.DSTORE, local));
            }
            case REF -> {
                insns.add(new InsnNode(Opcodes.ACONST_NULL));
                insns.add(new VarInsnNode(Opcodes.ASTORE, local));
            }
        }
    }

    private Map<Integer, LocalShape> argumentShapes(MethodNode mn) {
        Map<Integer, LocalShape> shapes = new HashMap<>();
        int local = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        if ((mn.access & Opcodes.ACC_STATIC) == 0) {
            shapes.put(0, new LocalShape(0, LocalKind.REF));
        }
        for (Type type : Type.getArgumentTypes(mn.desc)) {
            LocalKind kind = localKind(type);
            if (kind != null) {
                shapes.put(local, new LocalShape(local, kind));
            }
            local += type.getSize();
        }
        return shapes;
    }

    private LocalShape localShape(AbstractInsnNode insn) {
        if (insn instanceof IincInsnNode iinc) {
            return new LocalShape(iinc.var, LocalKind.INT);
        }
        if (!(insn instanceof VarInsnNode var)) return null;
        LocalKind kind = localKind(var.getOpcode());
        return kind == null ? null : new LocalShape(var.var, kind);
    }

    private LocalKind localKind(Type type) {
        return switch (type.getSort()) {
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> LocalKind.INT;
            case Type.FLOAT -> LocalKind.FLOAT;
            case Type.LONG -> LocalKind.LONG;
            case Type.DOUBLE -> LocalKind.DOUBLE;
            case Type.ARRAY, Type.OBJECT -> LocalKind.REF;
            default -> null;
        };
    }

    private LocalKind localKind(int opcode) {
        return switch (opcode) {
            case Opcodes.ILOAD, Opcodes.ISTORE -> LocalKind.INT;
            case Opcodes.LLOAD, Opcodes.LSTORE -> LocalKind.LONG;
            case Opcodes.FLOAD, Opcodes.FSTORE -> LocalKind.FLOAT;
            case Opcodes.DLOAD, Opcodes.DSTORE -> LocalKind.DOUBLE;
            case Opcodes.ALOAD, Opcodes.ASTORE -> LocalKind.REF;
            default -> null;
        };
    }

    private enum LocalKind {
        INT(1),
        LONG(2),
        FLOAT(1),
        DOUBLE(2),
        REF(1);

        private final int slots;

        LocalKind(int slots) {
            this.slots = slots;
        }

        int slots() {
            return slots;
        }
    }

    private record LocalShape(int var, LocalKind kind) {}

    private record StackEffect(int consumed, int pushed) {}

    private enum PrimitiveDigestKind {
        INT,
        LONG,
        FLOAT,
        DOUBLE
    }

    private record DataDigestObservation(
        AbstractInsnNode anchor,
        boolean after,
        PrimitiveDigestKind kind,
        int local,
        long seed,
        int blockIndex,
        int cyclicRegion,
        int ordinal
    ) {
        boolean cyclic() {
            return cyclicRegion >= 0;
        }
    }

    private record LoopInterval(int start, int end) {}
}
