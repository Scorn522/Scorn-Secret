package dev.nekoobfuscator.transforms.jvm.cff;

import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.*;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningVerify.*;

import dev.nekoobfuscator.api.transform.IRLevel;
import dev.nekoobfuscator.api.transform.TransformContext;
import dev.nekoobfuscator.api.transform.TransformPass;
import dev.nekoobfuscator.api.transform.TransformPhase;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.util.JvmObfuscationCoverage;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import dev.nekoobfuscator.transforms.jvm.internal.JvmCodeSizeEstimator;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;
import dev.nekoobfuscator.transforms.jvm.key.JvmKeyDispatchPass;
import dev.nekoobfuscator.transforms.jvm.strings.JvmStringObfuscationPass;
import dev.nekoobfuscator.transforms.jvm.constants.JvmConstantObfuscationPass;
import dev.nekoobfuscator.transforms.jvm.parameters.JvmMethodParameterObfuscationPass;
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
import java.util.BitSet;
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
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


abstract class CffTransitionOutliner extends CffKeyTransferRewriter {

    static boolean isBudgetedDirectTransitionEligible(
        EdgeKind edgeKind,
        EdgeRole role,
        int budgetBytes
    ) {
        return edgeKind == EdgeKind.DIRECT_ISLAND &&
            role != EdgeRole.HANDLER &&
            role != EdgeRole.FAKE &&
            role != EdgeRole.POISON &&
            budgetBytes > 0;
    }

    static boolean shouldReloadPcForGroupResultRoute(
        boolean inlineSingleResultFallthrough,
        boolean denseResultRouter,
        boolean hasHubResult
    ) {
        return !inlineSingleResultFallthrough && (denseResultRouter || hasHubResult);
    }

    static boolean shouldReloadPcForIslandResultRoute(
        boolean denseResultRouter,
        int fakeCount
    ) {
        return denseResultRouter || fakeCount > 0;
    }

    static boolean useCompactSparseResultFirst(
        boolean compactDispatchState,
        boolean denseResultRouter
    ) {
        return compactDispatchState && !denseResultRouter;
    }

    static int compactSparsePoisonBranchOpcode(boolean zeroResultTokenIsValid) {
        return zeroResultTokenIsValid ? Opcodes.IFNE : Opcodes.IFEQ;
    }

    static boolean useSmallDomainRouterBranches(int domainCaseCount) {
        return domainCaseCount > 0 && domainCaseCount <= 2;
    }

    static boolean emitSmallDomainRouterBranches(
        InsnList insns,
        int domainLocal,
        LabelNode poisonCase,
        int[] keys,
        LabelNode[] labels
    ) {
        if (!useSmallDomainRouterBranches(keys.length)) {
            return false;
        }
        if (keys.length == 1) {
            insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
            JvmPassBytecode.pushInt(insns, keys[0]);
            insns.add(new JumpInsnNode(Opcodes.IF_ICMPNE, poisonCase));
            return true;
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
        JvmPassBytecode.pushInt(insns, keys[0]);
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, labels[0]));
        insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
        JvmPassBytecode.pushInt(insns, keys[1]);
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, labels[1]));
        insns.add(new JumpInsnNode(Opcodes.GOTO, poisonCase));
        return true;
    }

    static int generatedStaticHelperAccess(boolean interfaceOwner) {
        int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        return access | (interfaceOwner ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE);
    }

    protected final class TransitionOutliner {
        private static final String DESC = "(JIIIIII[J)J";
        private static final String COMPACT_DISPATCH_DESC = "(JIIIIII[I)J";
        private static final String COMPACT_TRANSITION_DESC = "(JIIII[J)J";
        private static final String COMPACT_STATE_TRANSITION_DESC = "(JIIII[J[I)J";
        private final PipelineContext pctx;
        private final L1Class clazz;
        private final String owner;
        private final boolean interfaceOwner;
        private final int outLocal;
        private final int compactStateOutLocal;
        private final int smallTokenDispatchCases;
        private final boolean compactTransitionWrappers;
        private int inlineDirectTransitionBudgetBytes;
        private int inlineDirectTransitionCandidates;
        private int inlineDirectTransitionAccepted;
        private int inlineDirectTransitionRejected;
        private final SyntheticNoiseBudget syntheticNoiseBudget;
        private final Map<IslandGroup, RouterState> routers = new IdentityHashMap<>();
        private final Map<IslandGroup, String> groupDispatchHelpers = new IdentityHashMap<>();
        private final Map<LabelNode, BitSet> directIslandEntries = new IdentityHashMap<>();
        private int counter;

        TransitionOutliner(
            PipelineContext pctx,
            L1Class clazz,
            int outLocal,
            int compactStateOutLocal,
            int smallTokenDispatchCases,
            boolean compactTransitionWrappers,
            int inlineDirectTransitionBudgetBytes,
            SyntheticNoiseBudget syntheticNoiseBudget
        ) {
            this.pctx = pctx;
            this.clazz = clazz;
            this.owner = clazz.asmNode().name;
            this.interfaceOwner = clazz.isInterface();
            this.outLocal = outLocal;
            this.compactStateOutLocal = compactStateOutLocal;
            this.smallTokenDispatchCases = smallTokenDispatchCases;
            this.compactTransitionWrappers = compactTransitionWrappers;
            this.inlineDirectTransitionBudgetBytes = Math.max(0, inlineDirectTransitionBudgetBytes);
            this.syntheticNoiseBudget = syntheticNoiseBudget;
        }

        int outLocal() {
            return outLocal;
        }

        boolean canInlineBudgetedDirectTransition(EdgeKind edgeKind, EdgeRole role) {
            boolean eligible = isBudgetedDirectTransitionEligible(
                edgeKind,
                role,
                inlineDirectTransitionBudgetBytes
            );
            if (eligible) {
                inlineDirectTransitionCandidates++;
            }
            return eligible;
        }

        boolean consumeBudgetedDirectTransition(InsnList inlineTransition) {
            int estimatedExtraBytes = Math.max(
                1,
                JvmCodeSizeEstimator.estimateInsnListBytes(inlineTransition) -
                    OUTLINED_TRANSITION_CALLSITE_ESTIMATED_BYTES
            );
            if (estimatedExtraBytes > inlineDirectTransitionBudgetBytes) {
                inlineDirectTransitionRejected++;
                return false;
            }
            inlineDirectTransitionBudgetBytes -= estimatedExtraBytes;
            inlineDirectTransitionAccepted++;
            return true;
        }

        int inlineDirectTransitionCandidates() {
            return inlineDirectTransitionCandidates;
        }

        int inlineDirectTransitionAccepted() {
            return inlineDirectTransitionAccepted;
        }

        int inlineDirectTransitionRejected() {
            return inlineDirectTransitionRejected;
        }

        void recordDirectIslandEntry(DispatchTarget target) {
            directIslandEntries
                .computeIfAbsent(target.hub(), ignored -> new BitSet())
                .set(target.island());
        }

        void emitInitOutLocals(InsnList insns) {
            emitInitTransitionOut(insns, outLocal);
            if (compactStateOutLocal >= 0) {
                JvmPassBytecode.pushInt(insns, 7);
                insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
                insns.add(new VarInsnNode(Opcodes.ASTORE, compactStateOutLocal));
                insns.add(new VarInsnNode(Opcodes.ALOAD, compactStateOutLocal));
                JvmPassBytecode.pushInt(insns, 6);
                insns.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/Thread",
                    "currentThread",
                    "()Ljava/lang/Thread;",
                    false
                ));
                insns.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/System",
                    "identityHashCode",
                    "(Ljava/lang/Object;)I",
                    false
                ));
                insns.add(new InsnNode(Opcodes.IASTORE));
            }
        }

        private boolean useCompactDispatchState() {
            return compactStateOutLocal >= 0;
        }

        private String dispatchHelperDesc() {
            return useCompactDispatchState() ? COMPACT_DISPATCH_DESC : DESC;
        }

        private int dispatchStateOutLocal() {
            return useCompactDispatchState() ? compactStateOutLocal : outLocal;
        }

        InsnList emitGroupDispatchCall(
            IslandGroup group,
            Map<LabelNode, Integer> stateByLabel,
            Map<LabelNode, CffBlockKeyState> keyStateByLabel,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int dataLocal,
            int keyTmpLocal,
            LabelNode poison,
            boolean allowSingleResultFallthrough,
            long methodSeed,
            long salt
        ) {
            String helperName = prepareGroupDispatchHelper(
                group,
                stateByLabel,
                keyStateByLabel,
                poison,
                methodSeed,
                salt
            );

            InsnList insns = new InsnList();
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
            insns.add(new VarInsnNode(Opcodes.ALOAD, dispatchStateOutLocal()));
            insns.add(
                new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    owner,
                    helperName,
                    dispatchHelperDesc(),
                    interfaceOwner
                )
            );
            insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
            RouterState router = router(group);
            boolean inlineSingleResultFallthrough =
                canInlineSingleResultFallthrough(group, router, allowSingleResultFallthrough);
            boolean compactSparseResultFirst = useCompactSparseResultFirst(router);
            if (compactSparseResultFirst) {
                emitCompactDispatchResultLoad(insns, compactStateOutLocal, keyTmpLocal);
                insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal));
                insns.add(new JumpInsnNode(
                    compactSparsePoisonBranchOpcode(router.resultCases.containsKey(0)),
                    poison
                ));
            }
            boolean includePc = shouldReloadPcForGroupResultRoute(
                inlineSingleResultFallthrough,
                router.denseResultRouter,
                routerHasHubResult(router, group.hub())
            );
            if (useCompactDispatchState()) {
                emitCompactDispatchStateLoads(
                    insns,
                    compactStateOutLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    keyTmpLocal,
                    includePc,
                    router.denseResultRouter,
                    !compactSparseResultFirst
                );
            } else {
                emitOutlinedDispatchLoads(
                    insns,
                    outLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    includePc,
                    router.denseResultRouter
                );
            }
            if (inlineSingleResultFallthrough) {
                if (compactSparseResultFirst) {
                    // The result-first branch above already rejected the poison token.
                } else if (useCompactDispatchState()) {
                    insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal));
                    insns.add(new JumpInsnNode(Opcodes.IFNE, poison));
                } else {
                    emitTransitionOutLowBranchNonZero(insns, outLocal, 2, poison);
                }
                router.inlineSingleResultFallthrough = true;
            } else {
                if (!useCompactDispatchState()) {
                    emitTransitionOutLowLoad(insns, outLocal, 2, keyTmpLocal);
                }
            }
            if (!inlineSingleResultFallthrough && hasGroupedIslandEntry(group)) {
                insns.add(new JumpInsnNode(Opcodes.GOTO, router.label));
            }
            JvmKeyDispatchPass.markGenerated(pctx, insns);
            return insns;
        }

        InsnList emitGroupedIslandEntry(
            IslandGroup group,
            int island,
            int domainLocal
        ) {
            InsnList insns = new InsnList();
            insns.add(group.islandLabels()[island]);
            JvmPassBytecode.pushInt(insns, directIslandDomainToken(group, island));
            insns.add(new VarInsnNode(Opcodes.ISTORE, domainLocal));
            insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
            JvmKeyDispatchPass.markGenerated(pctx, insns);
            return insns;
        }

        boolean needsGroupedIslandEntry(IslandGroup group, int island) {
            BitSet entries = directIslandEntries.get(group.hub());
            return entries != null && entries.get(island);
        }

        private boolean hasGroupedIslandEntry(IslandGroup group) {
            for (int island = 0; island < group.islandLabels().length; island++) {
                if (needsGroupedIslandEntry(group, island)) return true;
            }
            return false;
        }

        private boolean useCompactSparseResultFirst(RouterState router) {
            return CffTransitionOutliner.useCompactSparseResultFirst(
                useCompactDispatchState(),
                router.denseResultRouter
            );
        }

        private boolean routerHasHubResult(RouterState router, LabelNode hub) {
            for (LabelNode label : router.resultCases.values()) {
                if (label == hub) return true;
            }
            return false;
        }

        private boolean canInlineSingleResultFallthrough(
            IslandGroup group,
            RouterState router,
            boolean allowed
        ) {
            if (!allowed || router.denseResultRouter || hasGroupedIslandEntry(group)) return false;
            if (router.resultCases.size() != 1 || group.blocks().size() != 1) return false;
            Map.Entry<Integer, LabelNode> result = router.resultCases.firstEntry();
            return result != null &&
                result.getKey() == 0 &&
                result.getValue() == group.blocks().get(0).label();
        }

        private void emitTransitionOutLowBranchNonZero(
            InsnList insns,
            int outLocal,
            int index,
            LabelNode target
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
            JvmPassBytecode.pushInt(insns, index);
            insns.add(new InsnNode(Opcodes.LALOAD));
            insns.add(new InsnNode(Opcodes.L2I));
            insns.add(new JumpInsnNode(Opcodes.IFNE, target));
        }

        private void emitOutlinedDispatchLoads(
            InsnList insns,
            int outLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            boolean includePc,
            boolean includeDomain
        ) {
            emitTransitionOutPairLoad(insns, outLocal, 0, guardLocal, pathKeyLocal);
            if (includePc) {
                emitTransitionOutPairLoad(insns, outLocal, 1, blockKeyLocal, pcLocal);
            } else {
                emitTransitionOutHighLoad(insns, outLocal, 1, blockKeyLocal);
            }
            if (includeDomain) {
                emitTransitionOutHighLoad(insns, outLocal, 2, domainLocal);
            }
        }

        private void emitCompactDispatchStateLoads(
            InsnList insns,
            int stateOutLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int resultLocal,
            boolean includePc,
            boolean includeDomain
        ) {
            emitCompactDispatchStateLoads(
                insns,
                stateOutLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                resultLocal,
                includePc,
                includeDomain,
                true
            );
        }

        private void emitCompactDispatchStateLoads(
            InsnList insns,
            int stateOutLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int resultLocal,
            boolean includePc,
            boolean includeDomain,
            boolean includeResult
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            emitCompactTransitionStateLoad(insns, 0, guardLocal);
            emitCompactTransitionStateLoad(insns, 1, pathKeyLocal);
            emitCompactTransitionStateLoad(insns, 2, blockKeyLocal);
            if (includePc) {
                emitCompactTransitionStateLoad(insns, 3, pcLocal);
            }
            if (includeDomain) {
                emitCompactTransitionStateLoad(insns, 4, domainLocal);
            }
            if (includeResult) {
                emitCompactTransitionStateLoad(insns, 5, resultLocal);
            }
            insns.add(new InsnNode(Opcodes.POP));
        }

        private void emitCompactDispatchResultLoad(
            InsnList insns,
            int stateOutLocal,
            int resultLocal
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            JvmPassBytecode.pushInt(insns, 5);
            insns.add(new InsnNode(Opcodes.IALOAD));
            insns.add(new VarInsnNode(Opcodes.ISTORE, resultLocal));
        }

        InsnList emitIslandDispatchCall(
            IslandGroup group,
            int island,
            List<Block> islandBlocks,
            int firstState,
            int fakeCount,
            long dispatchSeed,
            Map<LabelNode, Integer> stateByLabel,
            Map<LabelNode, CffBlockKeyState> keyStateByLabel,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int dataLocal,
            int keyTmpLocal,
            LabelNode poison,
            long methodSeed,
            long salt
        ) {
            RouterState router = router(group);
            boolean denseResultRouter = useDenseResultRouter(group);
            router.denseResultRouter = denseResultRouter;
            Map<LabelNode, Integer> resultTokens = new IdentityHashMap<>();
            long resultMaskSeed = resultRouteMaskSeed(group);
            boolean singleSparseFallthrough = singleSparseFallthroughCandidate(
                group,
                islandBlocks,
                fakeCount,
                denseResultRouter
            );
            for (int i = 0; i < islandBlocks.size(); i++) {
                Block block = islandBlocks.get(i);
                int token = singleSparseFallthrough
                    ? addZeroResultCase(router, block.label())
                    : denseResultRouter
                    ? addResultCase(router, block.label())
                    : uniqueResultToken(
                        router,
                        resultMaskSeed ^ island,
                        block.label(),
                        requireState(block.label(), stateByLabel.get(block.label())) ^ i
                    );
                resultTokens.put(block.label(), token);
            }
            int bounceToken = fakeCount == 0 ? 0 : (
                denseResultRouter
                    ? addResultCase(router, group.hub())
                    : uniqueResultToken(
                        router,
                        resultMaskSeed ^ 0x424F554E43454B31L ^ island,
                        group.hub(),
                        fakeCount ^ firstState
                    )
            );
            int poisonToken = singleSparseFallthrough ? 1 : (denseResultRouter ? -1 : 0);
            IslandDispatchHelperPlan helperPlan = createIslandDispatchHelper(
                group,
                island,
                islandBlocks,
                firstState,
                fakeCount,
                dispatchSeed,
                stateByLabel,
                keyStateByLabel,
                resultTokens,
                bounceToken,
                poisonToken,
                methodSeed,
                salt,
                resultMaskSeed,
                denseResultRouter
            );
            String helperName = helperPlan.name();

            InsnList insns = new InsnList();
            insns.add(group.islandLabels()[island]);
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
            insns.add(new VarInsnNode(Opcodes.ALOAD, dispatchStateOutLocal()));
            insns.add(
                new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    owner,
                    helperName,
                    dispatchHelperDesc(),
                    interfaceOwner
                )
            );
            insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
            if (useCompactDispatchState()) {
                emitCompactDispatchStateLoads(
                    insns,
                    compactStateOutLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    keyTmpLocal,
                    shouldReloadPcForIslandResultRoute(denseResultRouter, fakeCount),
                    denseResultRouter
                );
            } else {
                emitOutlinedDispatchLoads(
                    insns,
                    outLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    shouldReloadPcForIslandResultRoute(denseResultRouter, fakeCount),
                    denseResultRouter
                );
                emitTransitionOutLowLoad(insns, outLocal, 2, keyTmpLocal);
            }
            insns.add(new JumpInsnNode(Opcodes.GOTO, router.label));
            JvmKeyDispatchPass.markGenerated(pctx, insns);
            recordIslandDryRun(
                islandBlocks.size(),
                fakeCount,
                denseResultRouter,
                resultTokens.size(),
                helperPlan.dispatchCases(),
                helperPlan.helperInstructions(),
                insns.size()
            );
            recordIslandMaterialOpDryRun(
                group,
                island,
                fakeCount,
                denseResultRouter,
                resultTokens.size(),
                salt
            );
            return insns;
        }

        String prepareGroupDispatchHelper(
            IslandGroup group,
            Map<LabelNode, Integer> stateByLabel,
            Map<LabelNode, CffBlockKeyState> keyStateByLabel,
            LabelNode poison,
            long methodSeed,
            long salt
        ) {
            String existing = groupDispatchHelpers.get(group);
            if (existing != null) return existing;
            RouterState router = router(group);
            boolean denseResultRouter = useDenseResultRouter(group);
            router.denseResultRouter = denseResultRouter;
            long resultMaskSeed = resultRouteMaskSeed(group);

            String groupHelperName = nextHelperName();
            int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            access |= interfaceOwner ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
            MethodNode helper = new MethodNode(
                access,
                groupHelperName,
                dispatchHelperDesc(),
                null,
                null
            );
            int helperKeyLocal = 0;
            int helperGuardLocal = 2;
            int helperPathLocal = 3;
            int helperBlockLocal = 4;
            int helperPcLocal = 5;
            int helperDomainLocal = 6;
            int helperDataLocal = 7;
            int helperOutLocal = 8;

            TreeMap<Integer, LabelNode> domainCases = new TreeMap<>();
            List<LabelNode> islandLabels = new ArrayList<>();
            List<String> islandHelpers = new ArrayList<>();
            int groupPoisonToken = denseResultRouter ? -1 : 0;
            for (int island = 0; island < group.islandLabels().length; island++) {
                List<Block> islandBlocks = blocksForIsland(group, island);
                if (islandBlocks.isEmpty()) continue;
                int firstState = requireState(
                    islandBlocks.get(0).label(),
                    stateByLabel.get(islandBlocks.get(0).label())
                );
                int fakeCount = fakeCaseCount(group.salt() ^ salt ^ island, syntheticNoiseBudget);
                long dispatchSeed = tokenDispatchSeed(group, island, keyStateByLabel);
                Map<LabelNode, Integer> resultTokens = new IdentityHashMap<>();
                for (int i = 0; i < islandBlocks.size(); i++) {
                    Block block = islandBlocks.get(i);
                    boolean singleSparseFallthrough = singleSparseFallthroughCandidate(
                        group,
                        islandBlocks,
                        fakeCount,
                        denseResultRouter
                    );
                    int token = singleSparseFallthrough
                        ? addZeroResultCase(router, block.label())
                        : denseResultRouter
                            ? addResultCase(router, block.label())
                            : uniqueResultToken(
                            router,
                            resultMaskSeed ^ island,
                            block.label(),
                            requireState(block.label(), stateByLabel.get(block.label())) ^ i
                        );
                    resultTokens.put(block.label(), token);
                }
                boolean singleSparseFallthrough = singleSparseFallthroughCandidate(
                    group,
                    islandBlocks,
                    fakeCount,
                    denseResultRouter
                );
                int bounceToken = fakeCount == 0 ? 0 : (
                    denseResultRouter
                        ? addResultCase(router, group.hub())
                        : uniqueResultToken(
                            router,
                            resultMaskSeed ^ 0x424F554E43454B31L ^ island,
                            group.hub(),
                            fakeCount ^ firstState
                        )
                );
                int poisonToken = singleSparseFallthroughCandidate(
                    group,
                    islandBlocks,
                    fakeCount,
                    denseResultRouter
                )
                    ? 1
                    : (denseResultRouter ? -1 : 0);
                groupPoisonToken = poisonToken;
                IslandDispatchHelperPlan helperPlan = createIslandDispatchHelper(
                    group,
                    island,
                    islandBlocks,
                    firstState,
                    fakeCount,
                    dispatchSeed,
                    stateByLabel,
                    keyStateByLabel,
                    resultTokens,
                    bounceToken,
                    poisonToken,
                    methodSeed,
                    salt,
                    resultMaskSeed,
                    denseResultRouter
                );
                LabelNode caseLabel = new LabelNode();
                islandLabels.add(caseLabel);
                islandHelpers.add(helperPlan.name());
                domainCases.put(domainToken(group.salt(), island), caseLabel);
                if (needsGroupedIslandEntry(group, island)) {
                    domainCases.put(directIslandDomainToken(group, island), caseLabel);
                }
                recordIslandDryRun(
                    islandBlocks.size(),
                    fakeCount,
                    denseResultRouter,
                    resultTokens.size(),
                    helperPlan.dispatchCases(),
                    helperPlan.helperInstructions(),
                    0
                );
                recordIslandMaterialOpDryRun(
                    group,
                    island,
                    fakeCount,
                    denseResultRouter,
                    resultTokens.size(),
                    salt
                );
            }

            LabelNode poisonCase = new LabelNode();
            int[] keys = new int[domainCases.size()];
            LabelNode[] labels = new LabelNode[domainCases.size()];
            int index = 0;
            for (Map.Entry<Integer, LabelNode> entry : domainCases.entrySet()) {
                keys[index] = entry.getKey();
                labels[index] = entry.getValue();
                index++;
            }
            emitGroupDomainRouter(
                helper.instructions,
                helperDomainLocal,
                poisonCase,
                keys,
                labels
            );
            for (int i = 0; i < islandLabels.size(); i++) {
                helper.instructions.add(islandLabels.get(i));
                helper.instructions.add(new VarInsnNode(Opcodes.LLOAD, helperKeyLocal));
                helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperGuardLocal));
                helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperPathLocal));
                helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperBlockLocal));
                helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperPcLocal));
                helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperDomainLocal));
                helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperDataLocal));
                helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, helperOutLocal));
                helper.instructions.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    owner,
                    islandHelpers.get(i),
                    dispatchHelperDesc(),
                    interfaceOwner
                ));
                helper.instructions.add(new InsnNode(Opcodes.LRETURN));
            }
            helper.instructions.add(poisonCase);
            if (useCompactSparseResultFirst(router)) {
                finishCompactSparseResultOnlyReturn(
                    helper.instructions,
                    helperKeyLocal,
                    helperOutLocal,
                    groupPoisonToken
                );
            } else {
                finishOutlinedDispatchReturn(
                    helper.instructions,
                    helperKeyLocal,
                    helperGuardLocal,
                    helperPathLocal,
                    helperBlockLocal,
                    helperPcLocal,
                    helperDomainLocal,
                    helperOutLocal,
                    groupPoisonToken,
                    resultMaskSeed,
                    denseResultRouter
                );
            }
            helper.maxLocals = 9;
            helper.maxStack = 16;
            JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
            clazz.asmNode().methods.add(helper);
            clazz.markDirty();
            publishGeneratedHelperFlowKey(
                pctx,
                owner,
                groupHelperName,
                dispatchHelperDesc(),
                helperKeyLocal
            );
            groupDispatchHelpers.put(group, groupHelperName);
            return groupHelperName;
        }

        private void emitGroupDomainRouter(
            InsnList insns,
            int domainLocal,
            LabelNode poisonCase,
            int[] keys,
            LabelNode[] labels
        ) {
            if (!emitSmallDomainRouterBranches(insns, domainLocal, poisonCase, keys, labels)) {
                insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
                insns.add(new LookupSwitchInsnNode(poisonCase, keys, labels));
            }
        }

        private int directIslandDomainToken(IslandGroup group, int island) {
            int islandCount = Math.max(1, group.islandLabels().length);
            int token = -1 - island;
            int attempt = 0;
            while (collidesWithIslandDomainToken(group, token)) {
                attempt++;
                token = -1 - island - (attempt * islandCount);
            }
            return token;
        }

        private boolean collidesWithIslandDomainToken(IslandGroup group, int token) {
            for (int island = 0; island < group.islandLabels().length; island++) {
                if (domainToken(group.salt(), island) == token) {
                    return true;
                }
            }
            return false;
        }

        private List<Block> blocksForIsland(IslandGroup group, int island) {
            List<Block> islandBlocks = new ArrayList<>();
            for (Block block : group.blocks()) {
                Integer blockIsland = group.islands().get(block.label());
                if (blockIsland != null && blockIsland == island) {
                    islandBlocks.add(block);
                }
            }
            return islandBlocks;
        }

        private RouterState router(IslandGroup group) {
            return routers.computeIfAbsent(group, ignored -> new RouterState());
        }

        private int addResultCase(RouterState router, LabelNode label) {
            int token = router.resultCases.size();
            router.resultCases.put(token, label);
            return token;
        }

        private int addZeroResultCase(RouterState router, LabelNode label) {
            if (router.resultCases.containsKey(0)) {
                throw new IllegalStateException("CFF zero result token collision");
            }
            router.resultCases.put(0, label);
            return 0;
        }

        private int uniqueResultToken(
            RouterState router,
            long seed,
            LabelNode label,
            int discriminator
        ) {
            int token = nonZeroInt(
                JvmPassBytecode.mix(
                    seed ^ System.identityHashCode(label),
                    discriminator ^ 0x52455431L
                )
            );
            int attempt = 0;
            while (router.resultCases.containsKey(token)) {
                token = nonZeroInt(
                    JvmPassBytecode.mix(token, ++attempt ^ 0x554E49515545L)
                );
            }
            router.resultCases.put(token, label);
            return token;
        }

        InsnList emitResultRouter(
            IslandGroup group,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int keyTmpLocal,
            LabelNode poison
        ) {
            InsnList insns = new InsnList();
            RouterState router = routers.get(group);
            if (router == null || router.resultCases.isEmpty()) return insns;
            if (router.inlineSingleResultFallthrough) return insns;
            insns.add(router.label);
            if (router.denseResultRouter) {
                LabelNode[] labels = new LabelNode[router.resultCases.size()];
                int index = 0;
                for (Map.Entry<Integer, LabelNode> entry : router.resultCases.entrySet()) {
                    labels[index] = entry.getValue();
                    index++;
                }
                insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal));
                emitResultRouteMask(
                    insns,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    resultRouteMaskSeed(group)
                );
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new TableSwitchInsnNode(0, labels.length - 1, poison, labels));
            } else if (router.resultCases.size() <= 6) {
                emitSmallSparseResultRouter(insns, keyTmpLocal, router, poison);
            } else {
                int[] keys = new int[router.resultCases.size()];
                LabelNode[] labels = new LabelNode[router.resultCases.size()];
                int index = 0;
                for (Map.Entry<Integer, LabelNode> entry : router.resultCases.entrySet()) {
                    keys[index] = entry.getKey();
                    labels[index] = entry.getValue();
                    index++;
                }
                insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal));
                insns.add(new LookupSwitchInsnNode(poison, keys, labels));
            }
            JvmKeyDispatchPass.markGenerated(pctx, insns);
            return insns;
        }

        private void emitSmallSparseResultRouter(
            InsnList insns,
            int keyTmpLocal,
            RouterState router,
            LabelNode poison
        ) {
            if (router.resultCases.size() == 1 && router.resultCases.firstKey() == 0) {
                LabelNode result = router.resultCases.firstEntry().getValue();
                insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal));
                insns.add(new JumpInsnNode(Opcodes.IFNE, poison));
                insns.add(new JumpInsnNode(Opcodes.GOTO, result));
                return;
            }
            int index = 0;
            int size = router.resultCases.size();
            for (Map.Entry<Integer, LabelNode> entry : router.resultCases.entrySet()) {
                insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal));
                JvmPassBytecode.pushInt(insns, entry.getKey());
                if (++index == size) {
                    insns.add(new JumpInsnNode(Opcodes.IF_ICMPNE, poison));
                    insns.add(new JumpInsnNode(Opcodes.GOTO, entry.getValue()));
                } else {
                    insns.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, entry.getValue()));
                }
            }
        }

        private long resultRouteMaskSeed(IslandGroup group) {
            return JvmPassBytecode.mix(
                group.salt() ^ 0x524553524F555445L,
                group.blocks().size()
            );
        }

        private boolean useDenseResultRouter(IslandGroup group) {
            return group.blocks().size() >= 32;
        }

        private boolean singleSparseFallthroughCandidate(
            IslandGroup group,
            List<Block> islandBlocks,
            int fakeCount,
            boolean denseResultRouter
        ) {
            return !denseResultRouter &&
                fakeCount == 0 &&
                group.blocks().size() == 1 &&
                islandBlocks.size() == 1 &&
                group.islandLabels().length == 1;
        }

        private IslandDispatchHelperPlan createIslandDispatchHelper(
            IslandGroup group,
            int island,
            List<Block> islandBlocks,
            int firstState,
            int fakeCount,
            long dispatchSeed,
            Map<LabelNode, Integer> stateByLabel,
            Map<LabelNode, CffBlockKeyState> keyStateByLabel,
            Map<LabelNode, Integer> resultTokens,
            int bounceToken,
            int poisonToken,
            long methodSeed,
            long salt,
            long resultMaskSeed,
            boolean denseResultRouter
        ) {
            String helperName = nextHelperName();
            MethodNode helper = new MethodNode(
                generatedStaticHelperAccess(interfaceOwner),
                helperName,
                dispatchHelperDesc(),
                null,
                null
            );
            int helperKeyLocal = 0;
            int helperGuardLocal = 2;
            int helperPathLocal = 3;
            int helperBlockLocal = 4;
            int helperPcLocal = 5;
            int helperDomainLocal = 6;
            int helperDataLocal = 7;
            int helperOutLocal = 8;
            int helperKeyTmpLocal = 9;
            int helperMaterialWordLocal = 12;
            int helperSourceLocal = 13;
            CffClassKeyTable stepTable = ensureClassKeyTable(pctx, clazz);

            TreeMap<Integer, LabelNode> cases = new TreeMap<>();
            List<LabelNode> realLabels = new ArrayList<>();
            List<Integer> realDispatchTokens = new ArrayList<>();
            for (Block block : islandBlocks) {
                LabelNode caseLabel = new LabelNode();
                realLabels.add(caseLabel);
                CffBlockKeyState blockKeys = requireBlockKey(
                    block.label(),
                    keyStateByLabel.get(block.label())
                );
                int realDispatchToken = maskedDispatchToken(
                    blockKeys.pcToken(),
                    blockKeys,
                    dispatchSeed
                );
                realDispatchTokens.add(realDispatchToken);
                cases.put(realDispatchToken, caseLabel);
            }
            List<Integer> fakeTokens = new ArrayList<>();
            List<Integer> fakeStates = new ArrayList<>();
            for (int fakeIndex = 0; fakeIndex < fakeCount; fakeIndex++) {
                int fakeState = fakeState(
                    salt,
                    firstState ^ island ^ (fakeIndex * 0x45D9F3B)
                );
                while (cases.containsKey(fakeState)) {
                    fakeState = fakeState(
                        salt ^ 0x9E3779B97F4A7C15L,
                        fakeState + fakeIndex + 1
                    );
                }
                int fakeToken = fakeDispatchToken(group.salt(), fakeState, island, fakeIndex);
                while (cases.containsKey(fakeToken)) {
                    fakeToken = nonZeroInt(JvmPassBytecode.mix(fakeToken, fakeIndex + 1L));
                }
                fakeStates.add(fakeState);
                fakeTokens.add(fakeToken);
            }
            List<Integer> realResultWordIndexes = new ArrayList<>();
            int islandMaterialCursor = registerCompressedIslandMaterialBlob(
                stepTable,
                compressedIslandMaterialWords(
                    group,
                    island,
                    islandBlocks,
                    firstState,
                    fakeCount,
                    dispatchSeed,
                    realDispatchTokens,
                    fakeTokens,
                    fakeStates,
                    keyStateByLabel,
                    resultTokens,
                    realResultWordIndexes,
                    bounceToken,
                    methodSeed,
                    salt,
                    resultMaskSeed,
                    denseResultRouter
                ),
                salt ^ dispatchSeed ^ methodSeed ^ resultMaskSeed ^ 0x494D415449534C31L
            );
            LabelNode dispatchMissLabel = new LabelNode();
            String coldMissHelperName = createIslandDispatchColdMissHelper(
                group,
                island,
                firstState,
                fakeCount,
                keyStateByLabel,
                methodSeed,
                salt,
                dispatchSeed,
                bounceToken,
                poisonToken,
                resultMaskSeed,
                denseResultRouter
            );
            if (useCompactDispatchState()) {
                emitCompactCffIslandCallsiteRuntimeSource(
                    helper.instructions,
                    helperKeyLocal,
                    helperGuardLocal,
                    helperPathLocal,
                    helperBlockLocal,
                    helperPcLocal,
                    helperDomainLocal,
                    helperOutLocal,
                    islandMaterialCursor
                );
            } else {
                emitCffIslandCallsiteRuntimeSource(
                    helper.instructions,
                    helperKeyLocal,
                    helperGuardLocal,
                    helperPathLocal,
                    helperBlockLocal,
                    helperPcLocal,
                    helperDomainLocal,
                    helperOutLocal,
                    islandMaterialCursor
                );
            }
            helper.instructions.add(new VarInsnNode(Opcodes.ISTORE, helperSourceLocal));
            emitTokenDispatch(
                helper.instructions,
                helperPcLocal,
                helperKeyLocal,
                helperGuardLocal,
                helperPathLocal,
                helperBlockLocal,
                helperDataLocal,
                cases,
                dispatchMissLabel,
                dispatchSeed,
                helperKeyTmpLocal,
                smallTokenDispatchCases
            );
            for (int i = 0; i < islandBlocks.size(); i++) {
                Block block = islandBlocks.get(i);
                helper.instructions.add(realLabels.get(i));
                emitCompressedIslandMaterialWordDecode(
                    helper.instructions,
                    stepTable,
                    helperKeyLocal,
                    helperGuardLocal,
                    helperPathLocal,
                    helperBlockLocal,
                    helperSourceLocal,
                    islandMaterialCursor,
                    realResultWordIndexes.get(i),
                    helperMaterialWordLocal
                );
                finishOutlinedDispatchReturnFromLocal(
                    helper.instructions,
                    helperKeyLocal,
                    helperGuardLocal,
                    helperPathLocal,
                    helperBlockLocal,
                    helperPcLocal,
                    helperDomainLocal,
                    helperOutLocal,
                    helperMaterialWordLocal,
                    resultMaskSeed,
                    denseResultRouter
                );
            }
            helper.instructions.add(dispatchMissLabel);
            emitIslandDispatchColdMissCall(
                helper.instructions,
                coldMissHelperName,
                helperKeyLocal,
                helperGuardLocal,
                helperPathLocal,
                helperBlockLocal,
                helperPcLocal,
                helperDomainLocal,
                helperDataLocal,
                helperOutLocal
            );
            helper.maxLocals = 15;
            helper.maxStack = 32;
            JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
            clazz.asmNode().methods.add(helper);
            clazz.markDirty();
            publishGeneratedHelperFlowKey(
                pctx,
                owner,
                helperName,
                dispatchHelperDesc(),
                helperKeyLocal
            );
            return new IslandDispatchHelperPlan(
                helperName,
                cases.size(),
                helper.instructions.size()
            );
        }

        private String createIslandDispatchColdMissHelper(
            IslandGroup group,
            int island,
            int firstState,
            int fakeCount,
            Map<LabelNode, CffBlockKeyState> keyStateByLabel,
            long methodSeed,
            long salt,
            long dispatchSeed,
            int bounceToken,
            int poisonToken,
            long resultMaskSeed,
            boolean denseResultRouter
        ) {
            String helperName = nextHelperName();
            MethodNode helper = new MethodNode(
                generatedStaticHelperAccess(interfaceOwner),
                helperName,
                dispatchHelperDesc(),
                null,
                null
            );
            int helperKeyLocal = 0;
            int helperGuardLocal = 2;
            int helperPathLocal = 3;
            int helperBlockLocal = 4;
            int helperPcLocal = 5;
            int helperDomainLocal = 6;
            int helperDataLocal = 7;
            int helperOutLocal = 8;
            int helperKeyTmpLocal = 9;
            int helperMaterialOutLocal = useCompactDispatchState() ? 10 : helperOutLocal;
            CffClassKeyTable stepTable = ensureClassKeyTable(pctx, clazz);
            if (useCompactDispatchState()) {
                JvmPassBytecode.pushInt(helper.instructions, 3);
                helper.instructions.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
                helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, helperMaterialOutLocal));
            }
            LabelNode poisonLabel = new LabelNode();
            List<LabelNode> fakeLabels = new ArrayList<>();
            for (int fakeIndex = 0; fakeIndex < fakeCount; fakeIndex++) {
                fakeLabels.add(new LabelNode());
            }
            if (!fakeLabels.isEmpty()) {
                emitDynamicFakeSourceRouter(
                    helper.instructions,
                    fakeLabels,
                    poisonLabel,
                    helperKeyLocal,
                    helperGuardLocal,
                    helperPathLocal,
                    helperBlockLocal,
                    helperPcLocal,
                    group.salt(),
                    island
                );
            }
            for (int fakeIndex = 0; fakeIndex < fakeLabels.size(); fakeIndex++) {
                helper.instructions.add(fakeLabels.get(fakeIndex));
                long fakeSeed = edgeSeed(
                    salt,
                    group.hub(),
                    group.islandLabels()[island],
                    0x46414B4549534C45L ^ island ^ fakeIndex
                );
                emitMaterializedStepKeys(
                    helper.instructions,
                    stepTable,
                    helperKeyLocal,
                    helperGuardLocal,
                    helperPathLocal,
                    helperBlockLocal,
                    helperMaterialOutLocal,
                    fakeSeed,
                    EdgeRole.FAKE
                );
                emitOutlinedFakeCaseBounce(
                    helper.instructions,
                    group,
                    island,
                    firstState,
                    keyStateByLabel,
                    helperKeyLocal,
                    helperGuardLocal,
                    helperPathLocal,
                    helperBlockLocal,
                    helperPcLocal,
                    helperDomainLocal,
                    helperDataLocal,
                    helperKeyTmpLocal,
                    helperOutLocal,
                    methodSeed,
                    fakeSeed,
                    dispatchSeed,
                    bounceToken,
                    resultMaskSeed,
                    denseResultRouter
                );
            }
            helper.instructions.add(poisonLabel);
            long poisonSeed = edgeSeed(
                salt,
                group.hub(),
                group.islandLabels()[island],
                0x4F5554504F49534FL ^ island
            );
            emitMaterializedStepKeys(
                helper.instructions,
                stepTable,
                helperKeyLocal,
                helperGuardLocal,
                helperPathLocal,
                helperBlockLocal,
                helperMaterialOutLocal,
                poisonSeed,
                EdgeRole.POISON
            );
            finishOutlinedDispatchReturn(
                helper.instructions,
                helperKeyLocal,
                helperGuardLocal,
                helperPathLocal,
                helperBlockLocal,
                helperPcLocal,
                helperDomainLocal,
                helperOutLocal,
                denseResultRouter ? Integer.MAX_VALUE : poisonToken,
                resultMaskSeed,
                denseResultRouter
            );
            helper.maxLocals = 15;
            helper.maxStack = 32;
            JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
            clazz.asmNode().methods.add(helper);
            clazz.markDirty();
            publishGeneratedHelperFlowKey(
                pctx,
                owner,
                helperName,
                dispatchHelperDesc(),
                helperKeyLocal
            );
            return helperName;
        }

        private void emitIslandDispatchColdMissCall(
            InsnList insns,
            String helperName,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int dataLocal,
            int outLocal
        ) {
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
            insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                owner,
                helperName,
                dispatchHelperDesc(),
                interfaceOwner
            ));
            insns.add(new InsnNode(Opcodes.LRETURN));
        }

        private void emitDynamicFakeSourceRouter(
            InsnList insns,
            List<LabelNode> fakeLabels,
            LabelNode poisonLabel,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            long groupSalt,
            int island
        ) {
            int bucketCount = 1;
            while (bucketCount < fakeLabels.size() + 1) {
                bucketCount <<= 1;
            }
            LabelNode outOfRange = new LabelNode();
            LabelNode[] labels = fakeLabels.toArray(new LabelNode[0]);
            insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new InsnNode(Opcodes.L2I));
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LUSHR));
            insns.add(new InsnNode(Opcodes.L2I));
            insns.add(new InsnNode(Opcodes.IADD));
            insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
            insns.add(new InsnNode(Opcodes.IADD));
            insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
            insns.add(new InsnNode(Opcodes.IXOR));
            JvmPassBytecode.pushInt(
                insns,
                nonZeroInt(JvmPassBytecode.mix(groupSalt ^ 0x46414B4553524331L, island))
            );
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, 16);
            insns.add(new InsnNode(Opcodes.IUSHR));
            insns.add(new InsnNode(Opcodes.IXOR));
            JvmPassBytecode.pushInt(insns, bucketCount - 1);
            insns.add(new InsnNode(Opcodes.IAND));
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, fakeLabels.size());
            insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, outOfRange));
            insns.add(new TableSwitchInsnNode(0, fakeLabels.size() - 1, poisonLabel, labels));
            insns.add(outOfRange);
            insns.add(new InsnNode(Opcodes.POP));
            insns.add(new JumpInsnNode(Opcodes.GOTO, poisonLabel));
        }

        private CompressedIslandMaterialBlob compressedIslandMaterialWords(
            IslandGroup group,
            int island,
            List<Block> islandBlocks,
            int firstState,
            int fakeCount,
            long dispatchSeed,
            List<Integer> realDispatchTokens,
            List<Integer> fakeTokens,
            List<Integer> fakeStates,
            Map<LabelNode, CffBlockKeyState> keyStateByLabel,
            Map<LabelNode, Integer> resultTokens,
            List<Integer> realResultWordIndexes,
            int bounceToken,
            long methodSeed,
            long salt,
            long resultMaskSeed,
            boolean denseResultRouter
        ) {
            List<Integer> words = new ArrayList<>();
            Map<Integer, CffBlockKeyState> decodeStates = new HashMap<>();
            words.add(0x4346494D);
            words.add(1);
            words.add(island);
            words.add(firstState);
            words.add(fakeCount);
            words.add(denseResultRouter ? 1 : 0);
            words.add(islandBlocks.size());
            words.add(resultTokens.size());
            words.add(bounceToken);
            addMaterialLong(words, dispatchSeed);
            addMaterialLong(words, methodSeed);
            addMaterialLong(words, salt);
            addMaterialLong(words, resultMaskSeed);
            addMaterialLong(words, group.salt());
            for (int i = 0; i < islandBlocks.size(); i++) {
                Block block = islandBlocks.get(i);
                CffBlockKeyState blockKeys = requireBlockKey(
                    block.label(),
                    keyStateByLabel.get(block.label())
                );
                words.add(1);
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    blockKeys,
                    realDispatchTokens.get(i)
                );
                addLiveDecodedMaterialWord(words, decodeStates, blockKeys, blockKeys.pcToken());
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    blockKeys,
                    nonZeroInt(JvmPassBytecode.mix(dispatchSeed, 0x44545041544831L))
                );
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    blockKeys,
                    nonZeroInt(JvmPassBytecode.mix(dispatchSeed, 0x4454424C4F434B31L)) | 1
                );
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    blockKeys,
                    nonZeroInt(JvmPassBytecode.mix(dispatchSeed, 0x44545043544F4B31L))
                );
                realResultWordIndexes.add(words.size());
                decodeStates.put(words.size(), blockKeys);
                words.add(resultTokens.get(block.label()));
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    blockKeys,
                    (int) resultMaskSeed
                );
                addMaterialKeyState(words, blockKeys);
            }
            CffBlockKeyState bounceKeys = firstIslandKeyState(
                group,
                island,
                keyStateByLabel
            );
            int bounceDomainToken = domainToken(group.salt(), island);
            long bounceDomainSeed = domainSeed(group);
            for (int fakeIndex = 0; fakeIndex < fakeCount; fakeIndex++) {
                long fakeSeed = edgeSeed(
                    salt,
                    group.hub(),
                    group.islandLabels()[island],
                    0x46414B4549534C45L ^ island ^ fakeIndex
                );
                words.add(2);
                words.add(fakeIndex);
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    bounceKeys,
                    fakeStates.get(fakeIndex)
                );
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    bounceKeys,
                    fakeTokens.get(fakeIndex)
                );
                words.add((int) ((fakeSeed >>> 37) & 3L));
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    bounceKeys,
                    firstState
                );
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    bounceKeys,
                    bounceToken
                );
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    bounceKeys,
                    bounceDomainToken
                );
                addLiveDecodedMaterialWord(
                    words,
                    decodeStates,
                    bounceKeys,
                    (int) resultMaskSeed
                );
                addMaterialLong(words, fakeSeed);
                addMaterialLong(words, bounceDomainSeed);
                addLiveMaterialKeyState(words, decodeStates, bounceKeys);
                addMaterialWords(words, stepMaterialValues(fakeSeed, EdgeRole.FAKE));
            }
            long poisonSeed = edgeSeed(
                salt,
                group.hub(),
                group.islandLabels()[island],
                0x4F5554504F49534FL ^ island
            );
            words.add(3);
            words.add(island);
            words.add((int) ((poisonSeed >>> 37) & 3L));
            addMaterialLong(words, poisonSeed);
            addMaterialWords(words, stepMaterialValues(poisonSeed, EdgeRole.POISON));
            for (Block block : islandBlocks) {
                CffBlockKeyState blockKeys = requireBlockKey(
                    block.label(),
                    keyStateByLabel.get(block.label())
                );
                words.add(4);
                words.add(resultTokens.get(block.label()));
                words.add(blockKeys.pcToken());
                words.add(blockKeys.guardKey());
                words.add(blockKeys.pathKey());
                words.add(blockKeys.blockKey());
            }
            int[] material = new int[words.size()];
            for (int i = 0; i < words.size(); i++) {
                material[i] = words.get(i);
            }
            CffBlockKeyState[] states = new CffBlockKeyState[material.length];
            for (Map.Entry<Integer, CffBlockKeyState> entry : decodeStates.entrySet()) {
                states[entry.getKey()] = entry.getValue();
            }
            return new CompressedIslandMaterialBlob(material, states);
        }

        private void recordIslandDryRun(
            int realBlocks,
            int fakeCount,
            boolean denseResultRouter,
            int resultTokens,
            int dispatchCases,
            int helperInstructions,
            int callSiteInstructions
        ) {
            CffIslandDryRunStats stats = cffIslandDryRunStats(pctx);
            boolean trivialCandidate = realBlocks == 1 && fakeCount == 0;
            int minimumCallerGrowthInstructions = Math.max(
                0,
                helperInstructions - callSiteInstructions
            );
            int dispatchRows = dispatchCases;
            int resultRows = resultTokens;
            int fakeBounceRows = fakeCount;
            int poisonRows = 1;
            int routerRows = Math.max(1, resultTokens);
            long materialWords =
                ((long) realBlocks * CFF_ISLAND_REAL_DISPATCH_ROW_WORDS) +
                    ((long) fakeCount * CFF_ISLAND_FAKE_DISPATCH_ROW_WORDS) +
                    ((long) resultTokens * CFF_ISLAND_RESULT_ROW_WORDS) +
                    ((long) fakeCount * CFF_ISLAND_FAKE_BOUNCE_ROW_WORDS) +
                    CFF_ISLAND_POISON_ROW_WORDS +
                    ((long) routerRows *
                        (denseResultRouter
                                ? CFF_ISLAND_DENSE_ROUTER_ROW_WORDS
                                : CFF_ISLAND_SPARSE_ROUTER_ROW_WORDS));
            long materialRows =
                (long) dispatchRows + resultRows + fakeBounceRows + poisonRows + routerRows;
            int projectedCallerDeltaInstructions =
                CFF_ISLAND_SHARED_CALLSITE_EXTRA_INSNS;
            int projectedSharedHelperInstructions =
                CFF_ISLAND_SHARED_HELPER_FIXED_INSNS +
                    (denseResultRouter
                            ? CFF_ISLAND_SHARED_DENSE_ROUTER_INSNS
                            : CFF_ISLAND_SHARED_SPARSE_ROUTER_INSNS);
            stats.record(
                currentMethodKey(),
                trivialCandidate,
                realBlocks,
                fakeCount,
                denseResultRouter,
                resultTokens,
                dispatchCases,
                helperInstructions,
                callSiteInstructions,
                minimumCallerGrowthInstructions,
                dispatchRows,
                resultRows,
                fakeBounceRows,
                poisonRows,
                routerRows,
                materialRows,
                materialWords,
                projectedCallerDeltaInstructions,
                projectedSharedHelperInstructions
            );
        }

        private void recordIslandMaterialOpDryRun(
            IslandGroup group,
            int island,
            int fakeCount,
            boolean denseResultRouter,
            int resultTokens,
            long salt
        ) {
            int fakeStepRows = fakeCount;
            int poisonStepRows = 1;
            int firstTinyUpdates = 0;
            int secondTinyUpdates = 0;
            int methodKeyUpdates = 0;
            int bouncePredicateRows = 0;
            for (int fakeIndex = 0; fakeIndex < fakeCount; fakeIndex++) {
                long fakeSeed = edgeSeed(
                    salt,
                    group.hub(),
                    group.islandLabels()[island],
                    0x46414B4549534C45L ^ island ^ fakeIndex
                );
                StepDryRun fakeStep = stepDryRun(fakeSeed, EdgeRole.FAKE);
                firstTinyUpdates += fakeStep.firstTinyUpdates();
                secondTinyUpdates += fakeStep.secondTinyUpdates();
                methodKeyUpdates += fakeStep.methodKeyUpdates();
                int bounceMode = (int) ((fakeSeed >>> 37) & 3L);
                if (bounceMode == 2 || bounceMode == 3) {
                    bouncePredicateRows++;
                }
            }
            long poisonSeed = edgeSeed(
                salt,
                group.hub(),
                group.islandLabels()[island],
                0x4F5554504F49534FL ^ island
            );
            StepDryRun poisonStep = stepDryRun(poisonSeed, EdgeRole.POISON);
            firstTinyUpdates += poisonStep.firstTinyUpdates();
            secondTinyUpdates += poisonStep.secondTinyUpdates();
            methodKeyUpdates += poisonStep.methodKeyUpdates();
            CffIslandMaterialOpDryRunStats stats = cffIslandMaterialOpDryRunStats(pctx);
            stats.record(
                currentMethodKey(),
                fakeStepRows,
                poisonStepRows,
                firstTinyUpdates,
                secondTinyUpdates,
                methodKeyUpdates,
                fakeCount,
                bouncePredicateRows,
                denseResultRouter ? resultTokens : 0,
                denseResultRouter ? 0 : resultTokens,
                1
            );
        }

        private String currentMethodKey() {
            String name = pctx.currentMethodName();
            String desc = pctx.currentMethodDesc();
            if (name == null || desc == null) {
                return owner + ".<class>";
            }
            return owner + "." + name + desc;
        }

        private void emitCompactCffIslandCallsiteRuntimeSource(
            InsnList insns,
            int keyLocal,
            int guardLocal,
            int pathLocal,
            int blockLocal,
            int pcLocal,
            int domainLocal,
            int stateOutLocal,
            int encodedCursor
        ) {
            int mode = encodedCursor >>> CFF_ISLAND_CURSOR_MODE_SHIFT;
            if (mode == CFF_ISLAND_RUNTIME_SOURCE_NONE) {
                JvmPassBytecode.pushInt(insns, 0);
                return;
            }
            int cursor = encodedCursor & CFF_ISLAND_CURSOR_INDEX_MASK;
            JvmPassBytecode.pushInt(
                insns,
                0x43464953 ^ (mode * 0x45D9F3B) ^ (cursor * 0x119DE1F3)
            );
            if ((mode & CFF_ISLAND_RUNTIME_SOURCE_THREAD) != 0) {
                insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
                JvmPassBytecode.pushInt(insns, 6);
                insns.add(new InsnNode(Opcodes.IALOAD));
                insns.add(new InsnNode(Opcodes.IXOR));
            }
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new InsnNode(Opcodes.L2I));
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LUSHR));
            insns.add(new InsnNode(Opcodes.L2I));
            insns.add(new InsnNode(Opcodes.IADD));
            insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
            insns.add(new InsnNode(Opcodes.IADD));
            insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
            insns.add(new InsnNode(Opcodes.IADD));
            insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, 16);
            insns.add(new InsnNode(Opcodes.IUSHR));
            insns.add(new InsnNode(Opcodes.IXOR));
        }

        private void emitOutlinedFakeCaseBounce(
            InsnList insns,
            IslandGroup group,
            int island,
            int state,
            Map<LabelNode, CffBlockKeyState> keyStateByLabel,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int dataLocal,
            int keyTmpLocal,
            int outLocal,
            long methodSeed,
            long seed,
            long dispatchSeed,
            int bounceToken,
            long resultMaskSeed,
            boolean denseResultRouter
        ) {
            LabelNode hop = new LabelNode();
            LabelNode pass = new LabelNode();
            LabelNode done = new LabelNode();
            CffBlockKeyState bounceKeys = firstIslandKeyState(
                group,
                island,
                keyStateByLabel
            );
            DispatchTarget bounceTarget = new DispatchTarget(
                group.hub(),
                group.islandLabels(),
                group.aliasHubs(),
                island,
                group.salt() ^ island,
                domainSeed(group),
                domainToken(group.salt(), island)
            );
            long domainSeed = domainSeed(group);
            switch ((int) ((seed >>> 37) & 3L)) {
                case 0 -> {
                    emitStorePc(
                        insns,
                        pcLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        state,
                        bounceKeys,
                        methodSeed,
                        bounceTarget.selectorSeed(),
                        keyTmpLocal
                    );
                    emitStoreMethodKey(
                        insns,
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        bounceKeys
                    );
                    emitBindDispatchPcToDataDigest(
                        insns,
                        pcLocal,
                        dataLocal,
                        dispatchSeed
                    );
                    emitStoreDomain(
                        insns,
                        domainLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        island,
                        bounceTarget.domainToken(),
                        bounceKeys,
                        methodSeed,
                        domainSeed,
                        keyTmpLocal
                    );
                }
                case 1 -> {
                    emitStorePc(
                        insns,
                        pcLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        state,
                        bounceKeys,
                        methodSeed,
                        bounceTarget.selectorSeed(),
                        keyTmpLocal
                    );
                    emitStoreMethodKey(
                        insns,
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        bounceKeys
                    );
                    emitBindDispatchPcToDataDigest(
                        insns,
                        pcLocal,
                        dataLocal,
                        dispatchSeed
                    );
                    insns.add(new JumpInsnNode(Opcodes.GOTO, hop));
                    insns.add(hop);
                    emitStoreDomain(
                        insns,
                        domainLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        island,
                        bounceTarget.domainToken(),
                        bounceKeys,
                        methodSeed,
                        domainSeed,
                        keyTmpLocal
                    );
                }
                case 2 -> {
                    emitStoreDomain(
                        insns,
                        domainLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        island,
                        bounceTarget.domainToken(),
                        bounceKeys,
                        methodSeed,
                        domainSeed,
                        keyTmpLocal
                    );
                    emitStorePc(
                        insns,
                        pcLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        state,
                        bounceKeys,
                        methodSeed,
                        bounceTarget.selectorSeed(),
                        keyTmpLocal
                    );
                    emitStoreMethodKey(
                        insns,
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        bounceKeys
                    );
                    emitBindDispatchPcToDataDigest(
                        insns,
                        pcLocal,
                        dataLocal,
                        dispatchSeed
                    );
                    emitKeyPredicate(
                        insns,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        seed
                    );
                    insns.add(new JumpInsnNode(Opcodes.IFNE, pass));
                    insns.add(new JumpInsnNode(Opcodes.GOTO, done));
                    insns.add(pass);
                    insns.add(new JumpInsnNode(Opcodes.GOTO, done));
                    insns.add(done);
                }
                default -> {
                    emitStorePc(
                        insns,
                        pcLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        state,
                        bounceKeys,
                        methodSeed,
                        bounceTarget.selectorSeed(),
                        keyTmpLocal
                    );
                    emitStoreMethodKey(
                        insns,
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        bounceKeys
                    );
                    emitBindDispatchPcToDataDigest(
                        insns,
                        pcLocal,
                        dataLocal,
                        dispatchSeed
                    );
                    emitKeyPredicate(
                        insns,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        seed ^ 0x504154484F504151L
                    );
                    insns.add(new JumpInsnNode(Opcodes.IFEQ, hop));
                    emitStoreDomain(
                        insns,
                        domainLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        island,
                        bounceTarget.domainToken(),
                        bounceKeys,
                        methodSeed,
                        domainSeed,
                        keyTmpLocal
                    );
                    insns.add(new JumpInsnNode(Opcodes.GOTO, done));
                    insns.add(hop);
                    emitStoreDomain(
                        insns,
                        domainLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        keyLocal,
                        island,
                        bounceTarget.domainToken(),
                        bounceKeys,
                        methodSeed,
                        domainSeed,
                        keyTmpLocal
                    );
                    insns.add(done);
                }
            }
            finishOutlinedDispatchReturn(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                outLocal,
                bounceToken,
                resultMaskSeed,
                denseResultRouter
            );
        }

        private void finishOutlinedDispatchReturn(
            InsnList insns,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int outLocal,
            int resultToken,
            long resultMaskSeed,
            boolean denseResultRouter
        ) {
            if (useCompactDispatchState()) {
                if (denseResultRouter) {
                    emitCompactDispatchStateStoresWithMaskedResult(
                        insns,
                        outLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        keyLocal,
                        resultToken,
                        resultMaskSeed
                    );
                } else {
                    emitCompactDispatchStateStoresWithResult(
                        insns,
                        outLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        resultToken
                    );
                }
            } else if (denseResultRouter) {
                emitTransitionOutStoresWithMaskedResult(
                    insns,
                    outLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    keyLocal,
                    resultToken,
                    resultMaskSeed
                );
            } else {
                emitTransitionOutStoresWithResult(
                    insns,
                    outLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    resultToken
                );
            }
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new InsnNode(Opcodes.LRETURN));
        }

        private void finishOutlinedDispatchReturnFromLocal(
            InsnList insns,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int outLocal,
            int resultLocal,
            long resultMaskSeed,
            boolean denseResultRouter
        ) {
            if (useCompactDispatchState()) {
                if (denseResultRouter) {
                    emitCompactDispatchStateStoresWithMaskedResultLocal(
                        insns,
                        outLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        keyLocal,
                        resultLocal,
                        resultMaskSeed
                    );
                } else {
                    emitCompactDispatchStateStoresWithResultLocal(
                        insns,
                        outLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        resultLocal
                    );
                }
            } else if (denseResultRouter) {
                emitTransitionOutStoresWithMaskedResultLocal(
                    insns,
                    outLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    keyLocal,
                    resultLocal,
                    resultMaskSeed
                );
            } else {
                emitTransitionOutStoresWithResultLocal(
                    insns,
                    outLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    resultLocal
                );
            }
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new InsnNode(Opcodes.LRETURN));
        }

        private void finishCompactSparseResultOnlyReturn(
            InsnList insns,
            int keyLocal,
            int outLocal,
            int resultToken
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
            emitCompactDispatchStateStoreConst(insns, 5, resultToken);
            insns.add(new InsnNode(Opcodes.POP));
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new InsnNode(Opcodes.LRETURN));
        }

        private void emitCompactDispatchStateStoresWithResult(
            InsnList insns,
            int stateOutLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int resultToken
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            emitCompactDispatchStateStore(insns, 0, guardLocal);
            emitCompactDispatchStateStore(insns, 1, pathKeyLocal);
            emitCompactDispatchStateStore(insns, 2, blockKeyLocal);
            emitCompactDispatchStateStore(insns, 3, pcLocal);
            emitCompactDispatchStateStore(insns, 4, domainLocal);
            emitCompactDispatchStateStoreConst(insns, 5, resultToken);
            insns.add(new InsnNode(Opcodes.POP));
        }

        private void emitCompactDispatchStateStoresWithResultLocal(
            InsnList insns,
            int stateOutLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int resultLocal
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            emitCompactDispatchStateStore(insns, 0, guardLocal);
            emitCompactDispatchStateStore(insns, 1, pathKeyLocal);
            emitCompactDispatchStateStore(insns, 2, blockKeyLocal);
            emitCompactDispatchStateStore(insns, 3, pcLocal);
            emitCompactDispatchStateStore(insns, 4, domainLocal);
            emitCompactDispatchStateStore(insns, 5, resultLocal);
            insns.add(new InsnNode(Opcodes.POP));
        }

        private void emitCompactDispatchStateStoresWithMaskedResult(
            InsnList insns,
            int stateOutLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int keyLocal,
            int resultOrdinal,
            long resultMaskSeed
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            emitCompactDispatchStateStore(insns, 0, guardLocal);
            emitCompactDispatchStateStore(insns, 1, pathKeyLocal);
            emitCompactDispatchStateStore(insns, 2, blockKeyLocal);
            emitCompactDispatchStateStore(insns, 3, pcLocal);
            emitCompactDispatchStateStore(insns, 4, domainLocal);
            emitCompactDispatchStateStoreMaskedResult(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                resultOrdinal,
                resultMaskSeed
            );
            insns.add(new InsnNode(Opcodes.POP));
        }

        private void emitCompactDispatchStateStoresWithMaskedResultLocal(
            InsnList insns,
            int stateOutLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int keyLocal,
            int resultLocal,
            long resultMaskSeed
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            emitCompactDispatchStateStore(insns, 0, guardLocal);
            emitCompactDispatchStateStore(insns, 1, pathKeyLocal);
            emitCompactDispatchStateStore(insns, 2, blockKeyLocal);
            emitCompactDispatchStateStore(insns, 3, pcLocal);
            emitCompactDispatchStateStore(insns, 4, domainLocal);
            emitCompactDispatchStateStoreMaskedResultLocal(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                resultLocal,
                resultMaskSeed
            );
            insns.add(new InsnNode(Opcodes.POP));
        }

        private void emitCompactDispatchStateStore(
            InsnList insns,
            int index,
            int local
        ) {
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, index);
            insns.add(new VarInsnNode(Opcodes.ILOAD, local));
            insns.add(new InsnNode(Opcodes.IASTORE));
        }

        private void emitCompactDispatchStateStoreConst(
            InsnList insns,
            int index,
            int value
        ) {
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, index);
            JvmPassBytecode.pushInt(insns, value);
            insns.add(new InsnNode(Opcodes.IASTORE));
        }

        private void emitCompactDispatchStateStoreMaskedResult(
            InsnList insns,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int resultOrdinal,
            long resultMaskSeed
        ) {
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, 5);
            JvmPassBytecode.pushInt(insns, resultOrdinal);
            emitResultRouteMask(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                resultMaskSeed
            );
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new InsnNode(Opcodes.IASTORE));
        }

        private void emitCompactDispatchStateStoreMaskedResultLocal(
            InsnList insns,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int resultLocal,
            long resultMaskSeed
        ) {
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, 5);
            insns.add(new VarInsnNode(Opcodes.ILOAD, resultLocal));
            emitResultRouteMask(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                resultMaskSeed
            );
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new InsnNode(Opcodes.IASTORE));
        }

        private void emitSubdispatchPackedToken(
            InsnList insns,
            int keyLocal,
            int resultToken,
            int tokenLocal
        ) {
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            JvmPassBytecode.pushLong(
                insns,
                JvmPassBytecode.mix(0x5355424449535031L, resultToken)
            );
            insns.add(new InsnNode(Opcodes.LXOR));
            insns.add(new InsnNode(Opcodes.DUP2));
            JvmPassBytecode.pushInt(insns, 29);
            insns.add(new InsnNode(Opcodes.LUSHR));
            insns.add(new InsnNode(Opcodes.LXOR));
            JvmPassBytecode.pushLong(insns, 0x9E3779B97F4A7C15L);
            insns.add(new InsnNode(Opcodes.LMUL));
            JvmPassBytecode.pushLong(
                insns,
                (Integer.toUnsignedLong(resultToken) << 32) ^
                    Integer.toUnsignedLong(resultToken * 0x45D9F3B)
            );
            insns.add(new InsnNode(Opcodes.LXOR));
            insns.add(new VarInsnNode(Opcodes.LSTORE, tokenLocal));
        }

        InsnList emitCall(
            int state,
            DispatchTarget target,
            EdgeKind edgeKind,
            LabelNode jumpTarget,
            int keyLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            int dataLocal,
            int keyTmpLocal,
            long targetDispatchSeed,
            CffBlockKeyState sourceKeys,
            CffBlockKeyState targetKeys,
            long methodSeed,
            long stepSeed,
            EdgeRole role
        ) {
            if (edgeKind == EdgeKind.DIRECT_ISLAND) {
                recordDirectIslandEntry(target);
            }
            boolean materialTransition = !compactTransitionWrappers;
            CffClassKeyTable table = null;
            int rowBase = -1;
            String helperName = null;
            table = ensureClassKeyTable(pctx, clazz);
            rowBase = registerTransitionMaterialRow(
                table,
                state,
                target,
                edgeKind,
                sourceKeys,
                targetKeys,
                methodSeed,
                stepSeed,
                targetDispatchSeed,
                role
            );
            if (!materialTransition) {
                helperName = createCompactTransitionWrapper(table, rowBase);
            }
            InsnList insns = new InsnList();
            insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
            if (materialTransition) {
                insns.add(new FieldInsnNode(
                    Opcodes.GETSTATIC,
                    table.owner(),
                    table.objectFieldName(),
                    "[Ljava/lang/Object;"
                ));
                JvmPassBytecode.pushInt(insns, rowBase);
            }
            insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
            if (!materialTransition) {
                insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
                if (compactStateOutLocal >= 0) {
                    insns.add(new VarInsnNode(Opcodes.ALOAD, compactStateOutLocal));
                }
                insns.add(
                    new MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        owner,
                        helperName,
                        compactStateOutLocal >= 0
                            ? COMPACT_STATE_TRANSITION_DESC
                            : COMPACT_TRANSITION_DESC,
                        interfaceOwner
                    )
                );
            } else {
                insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
                insns.add(
                    new MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        table.transitionMaterialHelperOwner(),
                        table.transitionMaterialHelperName(),
                        TRANSITION_MATERIAL_HELPER_DESC,
                        table.transitionMaterialHelperInterfaceOwner()
                    )
                );
            }
            insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
            if (!materialTransition && compactStateOutLocal >= 0) {
                emitCompactTransitionStateLoads(
                    insns,
                    compactStateOutLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    edgeKind != EdgeKind.DIRECT_ISLAND
                );
            } else {
                emitTransitionOutLoads(
                    insns,
                    outLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    edgeKind != EdgeKind.DIRECT_ISLAND
                );
            }
            insns.add(new JumpInsnNode(Opcodes.GOTO, jumpTarget));
            JvmKeyDispatchPass.markGenerated(pctx, insns);
            return insns;
        }

        private void emitCompactTransitionStateLoads(
            InsnList insns,
            int stateOutLocal,
            int guardLocal,
            int pathKeyLocal,
            int blockKeyLocal,
            int pcLocal,
            int domainLocal,
            boolean includeDomain
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            emitCompactTransitionStateLoad(insns, 0, guardLocal);
            emitCompactTransitionStateLoad(insns, 1, pathKeyLocal);
            emitCompactTransitionStateLoad(insns, 2, blockKeyLocal);
            emitCompactTransitionStateLoad(insns, 3, pcLocal);
            if (includeDomain) {
                emitCompactTransitionStateLoad(insns, 4, domainLocal);
            }
            insns.add(new InsnNode(Opcodes.POP));
        }

        private void emitCompactTransitionStateLoad(
            InsnList insns,
            int index,
            int local
        ) {
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, index);
            insns.add(new InsnNode(Opcodes.IALOAD));
            insns.add(new VarInsnNode(Opcodes.ISTORE, local));
        }

        private String createCompactTransitionWrapper(
            CffClassKeyTable table,
            int rowBase
        ) {
            String helperName = nextHelperName();
            int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            access |= interfaceOwner ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
            MethodNode helper = new MethodNode(
                access,
                helperName,
                compactStateOutLocal >= 0
                    ? COMPACT_STATE_TRANSITION_DESC
                    : COMPACT_TRANSITION_DESC,
                null,
                null
            );
            int helperKeyLocal = 0;
            int helperGuardLocal = 2;
            int helperPathLocal = 3;
            int helperBlockLocal = 4;
            int helperDataLocal = 5;
            int helperOutLocal = 6;
            int helperStateOutLocal = 7;
            int helperResultKeyLocal = compactStateOutLocal >= 0 ? 8 : -1;
            int helperPackedLocal = compactStateOutLocal >= 0 ? 10 : -1;
            helper.instructions.add(new VarInsnNode(Opcodes.LLOAD, helperKeyLocal));
            helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperGuardLocal));
            helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperPathLocal));
            helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperBlockLocal));
            helper.instructions.add(new FieldInsnNode(
                Opcodes.GETSTATIC,
                table.owner(),
                table.objectFieldName(),
                "[Ljava/lang/Object;"
            ));
            JvmPassBytecode.pushInt(helper.instructions, rowBase);
            helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperDataLocal));
            helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, helperOutLocal));
            helper.instructions.add(
                new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    table.transitionMaterialHelperOwner(),
                    table.transitionMaterialHelperName(),
                    TRANSITION_MATERIAL_HELPER_DESC,
                    table.transitionMaterialHelperInterfaceOwner()
                )
            );
            if (compactStateOutLocal >= 0) {
                helper.instructions.add(new VarInsnNode(Opcodes.LSTORE, helperResultKeyLocal));
                emitCompactTransitionStateStores(
                    helper.instructions,
                    helperOutLocal,
                    helperStateOutLocal,
                    helperPackedLocal
                );
                helper.instructions.add(new VarInsnNode(Opcodes.LLOAD, helperResultKeyLocal));
            }
            helper.instructions.add(new InsnNode(Opcodes.LRETURN));
            helper.maxLocals = compactStateOutLocal >= 0 ? 12 : 7;
            helper.maxStack = 32;
            JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
            clazz.asmNode().methods.add(helper);
            clazz.markDirty();
            publishGeneratedHelperFlowKey(
                pctx,
                owner,
                helperName,
                compactStateOutLocal >= 0
                    ? COMPACT_STATE_TRANSITION_DESC
                    : COMPACT_TRANSITION_DESC,
                helperKeyLocal
            );
            return helperName;
        }

        private void emitCompactTransitionStateStores(
            InsnList insns,
            int transitionOutLocal,
            int stateOutLocal,
            int packedLocal
        ) {
            emitCompactTransitionStatePairStore(insns, transitionOutLocal, stateOutLocal, packedLocal, 0, 0, 1);
            emitCompactTransitionStatePairStore(insns, transitionOutLocal, stateOutLocal, packedLocal, 1, 2, 3);
            emitCompactTransitionStateHighStore(insns, transitionOutLocal, stateOutLocal, 2, 4);
        }

        private void emitCompactTransitionStatePairStore(
            InsnList insns,
            int transitionOutLocal,
            int stateOutLocal,
            int packedLocal,
            int sourceIndex,
            int highIndex,
            int lowIndex
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, transitionOutLocal));
            JvmPassBytecode.pushInt(insns, sourceIndex);
            insns.add(new InsnNode(Opcodes.LALOAD));
            insns.add(new VarInsnNode(Opcodes.LSTORE, packedLocal));
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            JvmPassBytecode.pushInt(insns, highIndex);
            insns.add(new VarInsnNode(Opcodes.LLOAD, packedLocal));
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LUSHR));
            insns.add(new InsnNode(Opcodes.L2I));
            insns.add(new InsnNode(Opcodes.IASTORE));
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            JvmPassBytecode.pushInt(insns, lowIndex);
            insns.add(new VarInsnNode(Opcodes.LLOAD, packedLocal));
            insns.add(new InsnNode(Opcodes.L2I));
            insns.add(new InsnNode(Opcodes.IASTORE));
        }

        private void emitCompactTransitionStateHighStore(
            InsnList insns,
            int transitionOutLocal,
            int stateOutLocal,
            int sourceIndex,
            int highIndex
        ) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, stateOutLocal));
            JvmPassBytecode.pushInt(insns, highIndex);
            insns.add(new VarInsnNode(Opcodes.ALOAD, transitionOutLocal));
            JvmPassBytecode.pushInt(insns, sourceIndex);
            insns.add(new InsnNode(Opcodes.LALOAD));
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LUSHR));
            insns.add(new InsnNode(Opcodes.L2I));
            insns.add(new InsnNode(Opcodes.IASTORE));
        }

        private String createHelper(
            int state,
            DispatchTarget target,
            EdgeKind edgeKind,
            CffBlockKeyState sourceKeys,
            CffBlockKeyState targetKeys,
            long methodSeed,
            long stepSeed,
            long targetDispatchSeed,
            EdgeRole role
        ) {
            CffClassKeyTable table = ensureClassKeyTable(pctx, clazz);
            int rowBase = registerTransitionMaterialRow(
                table,
                state,
                target,
                edgeKind,
                sourceKeys,
                targetKeys,
                methodSeed,
                stepSeed,
                targetDispatchSeed,
                role
            );
            String helperName = nextHelperName();
            int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            access |= interfaceOwner ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
            MethodNode helper = new MethodNode(
                access,
                helperName,
                DESC,
                null,
                null
            );
            int helperKeyLocal = 0;
            int helperGuardLocal = 2;
            int helperPathLocal = 3;
            int helperBlockLocal = 4;
            int helperPcLocal = 5;
            int helperDomainLocal = 6;
            int helperDataLocal = 7;
            int helperOutLocal = 8;
            helper.instructions.add(new VarInsnNode(Opcodes.LLOAD, helperKeyLocal));
            helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperGuardLocal));
            helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperPathLocal));
            helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperBlockLocal));
            helper.instructions.add(new FieldInsnNode(
                Opcodes.GETSTATIC,
                table.owner(),
                table.objectFieldName(),
                "[Ljava/lang/Object;"
            ));
            JvmPassBytecode.pushInt(helper.instructions, rowBase);
            helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, helperDataLocal));
            helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, helperOutLocal));
            helper.instructions.add(
                new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    table.transitionMaterialHelperOwner(),
                    table.transitionMaterialHelperName(),
                    TRANSITION_MATERIAL_HELPER_DESC,
                    table.transitionMaterialHelperInterfaceOwner()
                )
            );
            helper.instructions.add(new InsnNode(Opcodes.LRETURN));
            helper.maxLocals = 9;
            helper.maxStack = 32;
            JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
            clazz.asmNode().methods.add(helper);
            clazz.markDirty();
            publishGeneratedHelperFlowKey(pctx, owner, helperName, DESC, helperKeyLocal);
            return helperName;
        }

        private final class RouterState {
            final LabelNode label = new LabelNode();
            final TreeMap<Integer, LabelNode> resultCases = new TreeMap<>();
            boolean denseResultRouter;
            boolean inlineSingleResultFallthrough;
        }

        private String nextHelperName() {
            String base = "__neko_cff$";
            String candidate;
            do {
                candidate = base + Integer.toUnsignedString(counter++, 36);
            } while (helperExists(candidate));
            return candidate;
        }

        private boolean helperExists(String name) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (name.equals(method.name)) {
                    return true;
                }
            }
            return false;
        }
    }
}
