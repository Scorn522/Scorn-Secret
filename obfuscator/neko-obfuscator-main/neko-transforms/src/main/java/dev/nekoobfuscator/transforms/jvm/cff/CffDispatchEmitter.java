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


abstract class CffDispatchEmitter extends CffBlockBuilder {

    protected void insertIslandDispatchers(
        MethodNode mn,
        List<Block> blocks,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        int keyTmpLocal,
        int methodSeedLocal,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        DispatchPlan dispatchPlan,
        Set<LabelNode> zeroStackLabels,
        int exceptionLocal,
        Set<Integer> dataDigestExcludedArgumentLocals,
        boolean externalEntrySeed,
        long methodSeed,
        long salt,
        int smallTokenDispatchCases,
        SyntheticNoiseBudget syntheticNoiseBudget,
        CffTransitionOutliner.TransitionOutliner dispatcherOutliner,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        List<IslandGroup> outlinedGroups = dispatchPlan.groups();
        Map<DispatchTarget, Long> dispatchSeedByTarget =
            buildDispatchSeedByTarget(dispatchPlan, keyStateByLabel);
        boolean sharedPoisonSink = !"<init>".equals(mn.name);
        LabelNode sharedPoison = sharedPoisonSink ? new LabelNode() : null;
        boolean sharedPoisonEmitted = false;
        long sharedPoisonSeed = JvmPassBytecode.mix(
            salt ^ methodSeed,
            0x504F49534F4E5348L
        );
        for (int groupIndex = 0; groupIndex < outlinedGroups.size(); groupIndex++) {
            IslandGroup group = outlinedGroups.get(groupIndex);
            Block entryBlock = group.blocks().get(0);
            InsnList insns = new InsnList();
            LabelNode poison = sharedPoisonSink ? sharedPoison : new LabelNode();

            if (entryBlock == firstNonHandler(blocks)) {
                if (dispatcherOutliner != null) {
                    dispatcherOutliner.emitInitOutLocals(insns);
                }
                if (exceptionLocal >= 0) {
                    insns.add(new InsnNode(Opcodes.ACONST_NULL));
                    insns.add(new VarInsnNode(Opcodes.ASTORE, exceptionLocal));
                }
                DispatchTarget entryTarget = requireTarget(
                    entryBlock.label(),
                    dispatchPlan.targets().get(entryBlock.label())
                );
                long entrySeed = entryInitSeed(
                    group.salt(),
                    externalEntrySeed,
                    methodSeed
                );
                emitInitKeys(
                    insns,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    keyLocal,
                    entrySeed,
                    keyTmpLocal
                );
                emitInitDataDigest(
                    insns,
                    mn,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    dataLocal,
                    dataDigestExcludedArgumentLocals,
                    entrySeed ^ 0x4441544144494731L
                );
                if (methodSeedLocal >= 0) {
                    insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
                    insns.add(new VarInsnNode(Opcodes.LSTORE, methodSeedLocal));
                }
                emitStorePc(
                    insns,
                    pcLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    keyLocal,
                    requireState(
                        entryBlock.label(),
                        stateByLabel.get(entryBlock.label())
                    ),
                    requireBlockKey(
                        entryBlock.label(),
                        keyStateByLabel.get(entryBlock.label())
                    ),
                    methodSeed,
                    entryTarget.selectorSeed(),
                    keyTmpLocal
                );
                CffBlockKeyState entryKeys = requireBlockKey(
                    entryBlock.label(),
                    keyStateByLabel.get(entryBlock.label())
                );
                emitStoreMethodKey(
                    insns,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    entryKeys
                );
                emitBindDispatchPcToDataDigest(
                    insns,
                    pcLocal,
                    dataLocal,
                    requireDispatchSeed(entryTarget, dispatchSeedByTarget)
                );
                emitStoreDomain(
                    insns,
                    domainLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    keyLocal,
                    entryTarget.island(),
                    entryTarget.domainToken(),
                    entryKeys,
                    methodSeed,
                    entryTarget.domainSeed(),
                    keyTmpLocal
                );
                if (dispatcherOutliner != null) {
                    insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
                } else if (entryTarget.islandLabels().length == 1) {
                    insns.add(
                        new JumpInsnNode(
                            Opcodes.GOTO,
                            entryTarget.islandLabels()[entryTarget.island()]
                        )
                    );
                } else {
                    insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
                }
            }

            for (int alias = 0; alias < group.aliasHubs().length; alias++) {
                insns.add(
                    aliasHub(
                        group,
                        alias,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal
                    )
                );
            }
            insns.add(group.hub());
            if (dispatcherOutliner != null) {
                dispatcherOutliner.prepareGroupDispatchHelper(
                    group,
                    stateByLabel,
                    keyStateByLabel,
                    poison,
                    methodSeed,
                    salt
                );
                insns.add(dispatcherOutliner.emitGroupDispatchCall(
                    group,
                    stateByLabel,
                    keyStateByLabel,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    poison,
                    sharedPoisonSink && sharedPoisonEmitted,
                    methodSeed,
                    salt
                ));
                for (
                    int island = 0;
                    island < group.islandLabels().length;
                    island++
                ) {
                    if (!dispatcherOutliner.needsGroupedIslandEntry(group, island)) {
                        continue;
                    }
                    insns.add(
                        dispatcherOutliner.emitGroupedIslandEntry(
                            group,
                            island,
                            domainLocal
                        )
                    );
                }
            } else {
                emitDomainDispatch(
                    insns,
                    domainLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    group,
                    poison
                );
                for (
                    int island = 0;
                    island < group.islandLabels().length;
                    island++
                ) {
                    insns.add(
                        buildIslandDispatcher(
                            group,
                            stateByLabel,
                            keyLocal,
                            guardLocal,
                            pathKeyLocal,
                            blockKeyLocal,
                            pcLocal,
                            domainLocal,
                            dataLocal,
                            keyTmpLocal,
                            poison,
                            island,
                            keyStateByLabel,
                            zeroStackLabels,
                            methodSeed,
                            salt,
                            smallTokenDispatchCases,
                            syntheticNoiseBudget,
                            dispatcherOutliner,
                            transitionOutliner
                        )
                    );
                }
            }
            if (dispatcherOutliner != null) {
                insns.add(
                    dispatcherOutliner.emitResultRouter(
                        group,
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        keyTmpLocal,
                        poison
                    )
                );
            }
            boolean emitPoisonBody = !sharedPoisonSink || !sharedPoisonEmitted;
            if (emitPoisonBody) {
                insns.add(poison);
                long poisonSeed = sharedPoisonSink
                    ? sharedPoisonSeed
                    : edgeSeed(
                        salt,
                        entryBlock.label(),
                        entryBlock.label(),
                        0x504F49534F4E4B31L
                    );
                emitStepKeys(
                    insns,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    poisonSeed,
                    EdgeRole.POISON
                );
                sharedPoisonEmitted |= sharedPoisonSink;
            }
            if ("<init>".equals(mn.name)) {
                emitPoisonDiversion(
                    insns,
                    group,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    stateByLabel,
                    keyStateByLabel,
                    methodSeed,
                    salt
                );
            } else if (emitPoisonBody) {
                emitPoisonMethodExit(
                    insns,
                    mn,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal
                );
            }
            mn.instructions.insertBefore(entryBlock.label(), insns);
        }
    }

    protected void emitInitDataDigest(
        InsnList insns,
        MethodNode mn,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int dataLocal,
        Set<Integer> excludedArgumentLocals,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        emitMixDataDigestTopInt(insns, seed ^ 0x454E5452594B4559L);
        insns.add(new VarInsnNode(Opcodes.ISTORE, dataLocal));

        int local = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        int argIndex = 0;
        for (Type arg : Type.getArgumentTypes(mn.desc)) {
            if (isDigestiblePrimitiveArgument(arg)
                && !excludedArgumentLocals.contains(local)
                && !overlapsDigestKeyLocal(local, arg.getSize(), keyLocal)) {
                emitPrimitiveArgumentDigestValue(insns, arg, local);
                emitFoldDataDigestValue(
                    insns,
                    dataLocal,
                    seed ^ 0x4152474449470000L ^ (argIndex * 0x9E3779B97F4A7C15L)
                );
            }
            local += arg.getSize();
            argIndex++;
        }
    }

    private void emitPrimitiveArgumentDigestValue(
        InsnList insns,
        Type arg,
        int local
    ) {
        switch (arg.getSort()) {
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT ->
                insns.add(new VarInsnNode(Opcodes.ILOAD, local));
            case Type.FLOAT -> {
                insns.add(new VarInsnNode(Opcodes.FLOAD, local));
                insns.add(
                    new MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        "java/lang/Float",
                        "floatToRawIntBits",
                        "(F)I",
                        false
                    )
                );
            }
            case Type.LONG -> {
                insns.add(new VarInsnNode(Opcodes.LLOAD, local));
                insns.add(
                    new MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        "java/lang/Long",
                        "hashCode",
                        "(J)I",
                        false
                    )
                );
            }
            case Type.DOUBLE -> {
                insns.add(new VarInsnNode(Opcodes.DLOAD, local));
                insns.add(
                    new MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        "java/lang/Double",
                        "hashCode",
                        "(D)I",
                        false
                    )
                );
            }
            default -> {
            }
        }
    }

    private boolean isDigestiblePrimitiveArgument(Type arg) {
        return switch (arg.getSort()) {
            case Type.BOOLEAN,
                Type.BYTE,
                Type.CHAR,
                Type.SHORT,
                Type.INT,
                Type.FLOAT,
                Type.LONG,
                Type.DOUBLE -> true;
            default -> false;
        };
    }

    private boolean overlapsDigestKeyLocal(int local, int slots, int keyLocal) {
        return local < keyLocal + 2 && keyLocal < local + slots;
    }

    private void emitFoldDataDigestValue(
        InsnList insns,
        int dataLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new InsnNode(Opcodes.SWAP));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitMixDataDigestTopInt(insns, seed);
        insns.add(new VarInsnNode(Opcodes.ISTORE, dataLocal));
    }

    private void emitMixDataDigestTopInt(InsnList insns, long seed) {
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4449474D554C31L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 11));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x44494746494E31L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
    }

    protected void rewriteBlockExit(
        MethodNode mn,
        Block block,
        LabelNode next,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        int keyTmpLocal,
        int keyLocal,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        Map<LabelNode, DispatchTarget> dispatchByLabel,
        Map<DispatchTarget, Long> dispatchSeedByTarget,
        Set<LabelNode> runtimeKeyLabels,
        long methodSeed,
        long salt,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        AbstractInsnNode last = lastRealBefore(mn, block.endExclusive());
        if (last == null || before(last, block.label())) return;
        int opcode = last.getOpcode();
        if (terminates(opcode)) return;

        if (last instanceof JumpInsnNode jump) {
            if (opcode == Opcodes.GOTO) {
                Integer targetState = labelValue(stateByLabel, jump.label);
                DispatchTarget target = labelValue(dispatchByLabel, jump.label);
                if (targetState == null || target == null) {
                    throw new IllegalStateException(
                        "CFF goto target has no dispatch state in " +
                            mn.name +
                            mn.desc +
                            ": " +
                            jump.label.getLabel()
                    );
                }
                mn.instructions.insertBefore(
                    last,
                    transition(
                        targetState,
                        target,
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        dataLocal,
                        keyTmpLocal,
                        requireDispatchSeed(target, dispatchSeedByTarget),
                        requireBlockKey(block.label(), keyStateByLabel.get(block.label())),
                        requireBlockKey(jump.label, labelValue(keyStateByLabel, jump.label)),
                        methodSeed,
                        edgeSeed(salt, block.label(), jump.label, opcode),
                        runtimeKeyLabels.contains(jump.label),
                        EdgeRole.GOTO,
                        transitionOutliner
                    )
                );
                mn.instructions.remove(last);
                return;
            }
            Integer targetState = labelValue(stateByLabel, jump.label);
            Integer fallthroughState =
                next == null ? null : labelValue(stateByLabel, next);
            DispatchTarget target = labelValue(dispatchByLabel, jump.label);
            DispatchTarget fallthrough =
                next == null ? null : labelValue(dispatchByLabel, next);
            if (next == null) {
                throw new IllegalStateException(
                    "CFF conditional block has no verifier-safe fallthrough target"
                );
            }
            long trueSeed = edgeSeed(
                salt,
                block.label(),
                jump.label,
                opcode ^ 0x54525545
            );
            long falseSeed = edgeSeed(
                salt,
                block.label(),
                next,
                opcode ^ 0x46534C53
            );
            if ((trueSeed & 1L) == 0L) {
                LabelNode taken = new LabelNode();
                mn.instructions.insertBefore(
                    last,
                    new JumpInsnNode(opcode, taken)
                );
                mn.instructions.insertBefore(
                    last,
                    transition(
                        requireState(next, fallthroughState),
                        requireTarget(next, fallthrough),
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        dataLocal,
                        keyTmpLocal,
                        requireDispatchSeed(requireTarget(next, fallthrough), dispatchSeedByTarget),
                        requireBlockKey(block.label(), keyStateByLabel.get(block.label())),
                        requireBlockKey(next, labelValue(keyStateByLabel, next)),
                        methodSeed,
                        falseSeed,
                        runtimeKeyLabels.contains(next),
                        EdgeRole.CONDITIONAL_FALSE,
                        transitionOutliner
                    )
                );
                mn.instructions.insertBefore(last, taken);
                mn.instructions.insertBefore(
                    last,
                    transition(
                        requireState(jump.label, targetState),
                        requireTarget(jump.label, target),
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        dataLocal,
                        keyTmpLocal,
                        requireDispatchSeed(requireTarget(jump.label, target), dispatchSeedByTarget),
                        requireBlockKey(block.label(), keyStateByLabel.get(block.label())),
                        requireBlockKey(jump.label, labelValue(keyStateByLabel, jump.label)),
                        methodSeed,
                        trueSeed,
                        runtimeKeyLabels.contains(jump.label),
                        EdgeRole.CONDITIONAL_TRUE,
                        transitionOutliner
                    )
                );
            } else {
                LabelNode fallthroughLabel = new LabelNode();
                mn.instructions.insertBefore(
                    last,
                    new JumpInsnNode(invertJumpOpcode(opcode), fallthroughLabel)
                );
                mn.instructions.insertBefore(
                    last,
                    transition(
                        requireState(jump.label, targetState),
                        requireTarget(jump.label, target),
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        dataLocal,
                        keyTmpLocal,
                        requireDispatchSeed(requireTarget(jump.label, target), dispatchSeedByTarget),
                        requireBlockKey(block.label(), keyStateByLabel.get(block.label())),
                        requireBlockKey(jump.label, labelValue(keyStateByLabel, jump.label)),
                        methodSeed,
                        trueSeed,
                        runtimeKeyLabels.contains(jump.label),
                        EdgeRole.CONDITIONAL_TRUE,
                        transitionOutliner
                    )
                );
                mn.instructions.insertBefore(last, fallthroughLabel);
                mn.instructions.insertBefore(
                    last,
                    transition(
                        requireState(next, fallthroughState),
                        requireTarget(next, fallthrough),
                        keyLocal,
                        guardLocal,
                        pathKeyLocal,
                        blockKeyLocal,
                        pcLocal,
                        domainLocal,
                        dataLocal,
                        keyTmpLocal,
                        requireDispatchSeed(requireTarget(next, fallthrough), dispatchSeedByTarget),
                        requireBlockKey(block.label(), keyStateByLabel.get(block.label())),
                        requireBlockKey(next, labelValue(keyStateByLabel, next)),
                        methodSeed,
                        falseSeed,
                        runtimeKeyLabels.contains(next),
                        EdgeRole.CONDITIONAL_FALSE,
                        transitionOutliner
                    )
                );
            }
            mn.instructions.remove(last);
            return;
        }
        if (last instanceof LookupSwitchInsnNode ls) {
            rewriteLookupSwitch(
                mn,
                ls,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                dataLocal,
                keyTmpLocal,
                stateByLabel,
                keyStateByLabel,
                dispatchByLabel,
                dispatchSeedByTarget,
                runtimeKeyLabels,
                block.label(),
                methodSeed,
                salt,
                transitionOutliner
            );
            return;
        }
        if (last instanceof TableSwitchInsnNode ts) {
            rewriteTableSwitch(
                mn,
                ts,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                dataLocal,
                keyTmpLocal,
                stateByLabel,
                keyStateByLabel,
                dispatchByLabel,
                dispatchSeedByTarget,
                runtimeKeyLabels,
                block.label(),
                methodSeed,
                salt,
                transitionOutliner
            );
            return;
        }
        if (next != null) {
            Integer nextState = labelValue(stateByLabel, next);
            DispatchTarget nextTarget = labelValue(dispatchByLabel, next);
            mn.instructions.insert(
                last,
                transition(
                    requireState(next, nextState),
                    requireTarget(next, nextTarget),
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    requireDispatchSeed(requireTarget(next, nextTarget), dispatchSeedByTarget),
                    requireBlockKey(block.label(), keyStateByLabel.get(block.label())),
                    requireBlockKey(next, labelValue(keyStateByLabel, next)),
                    methodSeed,
                    edgeSeed(salt, block.label(), next, 0x46414C4C),
                    runtimeKeyLabels.contains(next),
                    EdgeRole.FALLTHROUGH,
                    transitionOutliner
                )
            );
        }
    }

    protected void rewriteLookupSwitch(
        MethodNode mn,
        LookupSwitchInsnNode ls,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        int keyTmpLocal,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        Map<LabelNode, DispatchTarget> dispatchByLabel,
        Map<DispatchTarget, Long> dispatchSeedByTarget,
        Set<LabelNode> runtimeKeyLabels,
        LabelNode source,
        long methodSeed,
        long salt,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        LabelNode defaultSet = new LabelNode();
        List<LabelNode> setLabels = new ArrayList<>();
        for (int i = 0; i < ls.labels.size(); i++) setLabels.add(
            new LabelNode()
        );
        List<LabelNode> originalTargets = new ArrayList<>(ls.labels);
        LabelNode originalDefault = ls.dflt;
        ls.labels.clear();
        ls.labels.addAll(setLabels);
        ls.dflt = defaultSet;
        InsnList tail = new InsnList();
        tail.add(defaultSet);
        tail.add(
            transition(
                requireState(
                    originalDefault,
                    labelValue(stateByLabel, originalDefault)
                ),
                requireTarget(
                    originalDefault,
                    labelValue(dispatchByLabel, originalDefault)
                ),
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                dataLocal,
                keyTmpLocal,
                requireDispatchSeed(
                    requireTarget(originalDefault, labelValue(dispatchByLabel, originalDefault)),
                    dispatchSeedByTarget
                ),
                requireBlockKey(source, keyStateByLabel.get(source)),
                requireBlockKey(originalDefault, labelValue(keyStateByLabel, originalDefault)),
                methodSeed,
                edgeSeed(salt, source, originalDefault, 0x53574446),
                runtimeKeyLabels.contains(originalDefault),
                EdgeRole.SWITCH_DEFAULT,
                transitionOutliner
            )
        );
        for (int i = 0; i < setLabels.size(); i++) {
            LabelNode originalTarget = originalTargets.get(i);
            tail.add(setLabels.get(i));
            tail.add(
                transition(
                    requireState(
                        originalTarget,
                        labelValue(stateByLabel, originalTarget)
                    ),
                    requireTarget(
                        originalTarget,
                        labelValue(dispatchByLabel, originalTarget)
                    ),
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    requireDispatchSeed(
                        requireTarget(originalTarget, labelValue(dispatchByLabel, originalTarget)),
                        dispatchSeedByTarget
                    ),
                    requireBlockKey(source, keyStateByLabel.get(source)),
                    requireBlockKey(originalTarget, labelValue(keyStateByLabel, originalTarget)),
                    methodSeed,
                    edgeSeed(
                        salt,
                        source,
                        originalTarget,
                        ls.keys.get(i) ^ 0x53574C53
                    ),
                    runtimeKeyLabels.contains(originalTarget),
                    EdgeRole.SWITCH_CASE,
                    transitionOutliner
                )
            );
        }
        mn.instructions.insert(ls, tail);
    }

    protected void rewriteTableSwitch(
        MethodNode mn,
        TableSwitchInsnNode ts,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        int keyTmpLocal,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        Map<LabelNode, DispatchTarget> dispatchByLabel,
        Map<DispatchTarget, Long> dispatchSeedByTarget,
        Set<LabelNode> runtimeKeyLabels,
        LabelNode source,
        long methodSeed,
        long salt,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        LabelNode defaultSet = new LabelNode();
        List<LabelNode> setLabels = new ArrayList<>();
        for (int i = 0; i < ts.labels.size(); i++) setLabels.add(
            new LabelNode()
        );
        List<LabelNode> originalTargets = new ArrayList<>(ts.labels);
        LabelNode originalDefault = ts.dflt;
        ts.labels.clear();
        ts.labels.addAll(setLabels);
        ts.dflt = defaultSet;
        InsnList tail = new InsnList();
        tail.add(defaultSet);
        tail.add(
            transition(
                requireState(
                    originalDefault,
                    labelValue(stateByLabel, originalDefault)
                ),
                requireTarget(
                    originalDefault,
                    labelValue(dispatchByLabel, originalDefault)
                ),
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                dataLocal,
                keyTmpLocal,
                requireDispatchSeed(
                    requireTarget(originalDefault, labelValue(dispatchByLabel, originalDefault)),
                    dispatchSeedByTarget
                ),
                requireBlockKey(source, keyStateByLabel.get(source)),
                requireBlockKey(originalDefault, labelValue(keyStateByLabel, originalDefault)),
                methodSeed,
                edgeSeed(salt, source, originalDefault, 0x54534446),
                runtimeKeyLabels.contains(originalDefault),
                EdgeRole.SWITCH_DEFAULT,
                transitionOutliner
            )
        );
        for (int i = 0; i < setLabels.size(); i++) {
            LabelNode originalTarget = originalTargets.get(i);
            tail.add(setLabels.get(i));
            tail.add(
                transition(
                    requireState(
                        originalTarget,
                        labelValue(stateByLabel, originalTarget)
                    ),
                    requireTarget(
                        originalTarget,
                        labelValue(dispatchByLabel, originalTarget)
                    ),
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    requireDispatchSeed(
                        requireTarget(originalTarget, labelValue(dispatchByLabel, originalTarget)),
                        dispatchSeedByTarget
                    ),
                    requireBlockKey(source, keyStateByLabel.get(source)),
                    requireBlockKey(originalTarget, labelValue(keyStateByLabel, originalTarget)),
                    methodSeed,
                    edgeSeed(
                        salt,
                        source,
                        originalTarget,
                        (ts.min + i) ^ 0x54534C53
                    ),
                    runtimeKeyLabels.contains(originalTarget),
                    EdgeRole.SWITCH_CASE,
                    transitionOutliner
                )
            );
        }
        mn.instructions.insert(ts, tail);
    }

    protected <T> T labelValue(Map<LabelNode, T> values, LabelNode label) {
        T value = values.get(label);
        if (value != null) return value;
        for (
            AbstractInsnNode scan = label.getPrevious();
            scan != null && scan.getOpcode() < 0;
            scan = scan.getPrevious()
        ) {
            if (scan instanceof LabelNode alias) {
                value = values.get(alias);
                if (value != null) return value;
            }
        }
        for (
            AbstractInsnNode scan = label.getNext();
            scan != null && scan.getOpcode() < 0;
            scan = scan.getNext()
        ) {
            if (scan instanceof LabelNode alias) {
                value = values.get(alias);
                if (value != null) return value;
            }
        }
        return null;
    }

    protected int requireState(LabelNode target, Integer state) {
        if (state == null) {
            throw new IllegalStateException(
                "CFF target has no state: " + target.getLabel()
            );
        }
        return state;
    }

    protected DispatchTarget requireTarget(
        LabelNode label,
        DispatchTarget target
    ) {
        if (target == null) {
            StackTraceElement caller = Thread.currentThread().getStackTrace().length > 2
                ? Thread.currentThread().getStackTrace()[2]
                : null;
            throw new IllegalStateException(
                "CFF target has no dispatch target at " +
                    (caller == null ? "<unknown>" : caller.getMethodName() + ":" + caller.getLineNumber()) +
                    ": " +
                    label.getLabel()
            );
        }
        return target;
    }

    protected CffBlockKeyState requireBlockKey(
        LabelNode label,
        CffBlockKeyState keyState
    ) {
        if (keyState == null) {
            throw new IllegalStateException(
                "CFF target has no key state: " + label.getLabel()
            );
        }
        return keyState;
    }

    protected InsnList transition(
        int state,
        DispatchTarget target,
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
        long edgeSeed,
        boolean updateGuard,
        EdgeRole role,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        long stepSeed = transitionKeySeed(edgeSeed, state, target, role);
        EdgeKind edgeKind = chooseEdgeKind(edgeSeed, role, target);
        LabelNode jumpTarget = transitionJumpTarget(target, edgeKind, edgeSeed);
        if (transitionOutliner != null) {
            if (transitionOutliner.canInlineBudgetedDirectTransition(edgeKind, role)) {
                InsnList inline = new InsnList();
                emitTransitionCore(
                    inline,
                    state,
                    target,
                    edgeKind,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    targetDispatchSeed,
                    sourceKeys,
                    targetKeys,
                    methodSeed,
                    stepSeed,
                    role,
                    updateGuard
                );
                inline.add(new JumpInsnNode(Opcodes.GOTO, jumpTarget));
                if (transitionOutliner.consumeBudgetedDirectTransition(inline)) {
                    transitionOutliner.recordDirectIslandEntry(target);
                    return inline;
                }
            }
            return transitionOutliner.emitCall(
                state,
                target,
                edgeKind,
                jumpTarget,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                dataLocal,
                keyTmpLocal,
                targetDispatchSeed,
                sourceKeys,
                targetKeys,
                methodSeed,
                stepSeed,
                role
            );
        }
        InsnList insns = new InsnList();
        emitTransitionCore(
            insns,
            state,
            target,
            edgeKind,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            domainLocal,
            dataLocal,
            keyTmpLocal,
            targetDispatchSeed,
            sourceKeys,
            targetKeys,
            methodSeed,
            stepSeed,
            role,
            updateGuard
        );
        insns.add(new JumpInsnNode(Opcodes.GOTO, jumpTarget));
        return insns;
    }

    protected LabelNode transitionJumpTarget(
        DispatchTarget target,
        EdgeKind edgeKind,
        long edgeSeed
    ) {
        return switch (edgeKind) {
            case DIRECT_ISLAND -> target.islandLabels()[target.island()];
            case ALIAS_HUB -> selectAliasHub(target, edgeSeed);
            case HUB -> target.hub();
        };
    }

    protected void emitTransitionCore(
        InsnList insns,
        int state,
        DispatchTarget target,
        EdgeKind edgeKind,
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
        EdgeRole role,
        boolean updateGuard
    ) {
        if (useDeltaTransitionKeys(edgeKind, role)) {
            emitDeltaBlockKeys(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                keyTmpLocal,
                keyTmpLocal + 3,
                sourceKeys,
                targetKeys,
                stepSeed,
                role
            );
        } else {
            emitDecodeBlockKeys(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                keyTmpLocal,
                keyTmpLocal + 3,
                sourceKeys,
                targetKeys,
                methodSeed,
                stepSeed,
                role
            );
        }
        long transitionBaseSeed = transitionBaseSeed(stepSeed, role);
        emitStoreTransitionBaseToken(
            insns,
            pcLocal,
            targetKeys.pcToken(),
            sourceKeys,
            keyTmpLocal + 3,
            transitionBaseSeed,
            target.selectorSeed() ^ state ^ 0x5043544F4B454E31L
        );
        emitStoreMethodKeyFromBase(
            insns,
            keyLocal,
            keyTmpLocal + 3,
            sourceKeys,
            targetKeys,
            transitionBaseSeed,
            stepSeed ^ 0x4D45544844454331L ^ role.ordinal()
        );
        emitBindDispatchPcToDataDigest(
            insns,
            pcLocal,
            dataLocal,
            targetDispatchSeed
        );
        if (edgeKind != EdgeKind.DIRECT_ISLAND) {
            emitStoreTransitionBaseToken(
                insns,
                domainLocal,
                target.domainToken(),
                sourceKeys,
                keyTmpLocal + 3,
                transitionBaseSeed,
                target.domainSeed() ^ target.island() ^ 0x444F4D544F4B31L
            );
        }
    }

    private boolean useDeltaTransitionKeys(EdgeKind edgeKind, EdgeRole role) {
        return edgeKind == EdgeKind.DIRECT_ISLAND && role != EdgeRole.HANDLER;
    }

    private void emitDeltaBlockKeys(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        int keyBaseLocal,
        CffBlockKeyState sourceKeys,
        CffBlockKeyState targetKeys,
        long seed,
        EdgeRole role
    ) {
        long baseSeed = transitionBaseSeed(seed, role);
        emitCompactControlTokenBase(
            insns,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            keyBaseLocal,
            baseSeed,
            keyTmpLocal
        );
        emitDeltaBlockKeyWord(
            insns,
            guardLocal,
            targetKeys.guardKey() - sourceKeys.guardKey(),
            sourceKeys,
            baseSeed,
            keyBaseLocal,
            seed ^ 0x44474B4755415244L ^ role.ordinal()
        );
        emitDeltaBlockKeyWord(
            insns,
            pathKeyLocal,
            targetKeys.pathKey() - sourceKeys.pathKey(),
            sourceKeys,
            baseSeed,
            keyBaseLocal,
            seed ^ 0x44474B50415448L ^ role.ordinal()
        );
        emitDeltaBlockKeyWord(
            insns,
            blockKeyLocal,
            targetKeys.blockKey() - sourceKeys.blockKey(),
            sourceKeys,
            baseSeed,
            keyBaseLocal,
            seed ^ 0x44474B424C4F434BL ^ role.ordinal()
        );
    }

    private void emitDeltaBlockKeyWord(
        InsnList insns,
        int dstLocal,
        int delta,
        CffBlockKeyState sourceKeys,
        long baseSeed,
        int keyBaseLocal,
        long seed
    ) {
        int encrypted =
            delta ^
            controlTokenMaskFromBase(compactControlTokenBase(sourceKeys, baseSeed), seed);
        insns.add(new VarInsnNode(Opcodes.ILOAD, dstLocal));
        JvmPassBytecode.pushInt(insns, encrypted);
        emitControlTokenMaskFromBase(insns, keyBaseLocal, seed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dstLocal));
    }

    protected InsnList buildIslandDispatcher(
        IslandGroup group,
        Map<LabelNode, Integer> stateByLabel,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        int keyTmpLocal,
        LabelNode poison,
        int island,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        Set<LabelNode> zeroStackLabels,
        long methodSeed,
        long salt,
        int smallTokenDispatchCases,
        SyntheticNoiseBudget syntheticNoiseBudget,
        CffTransitionOutliner.TransitionOutliner dispatcherOutliner,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        InsnList insns = new InsnList();
        TreeMap<Integer, LabelNode> cases = new TreeMap<>();
        Map<LabelNode, LabelNode> stubs = new IdentityHashMap<>();
        List<LabelNode> fakes = new ArrayList<>();
        List<Block> islandBlocks = new ArrayList<>();
        int firstState = 0;
        boolean first = true;
        long dispatchSeed = tokenDispatchSeed(group, island, keyStateByLabel);
        for (Block block : group.blocks()) {
            Integer blockIsland = group.islands().get(block.label());
            if (blockIsland != null && blockIsland == island) {
                islandBlocks.add(block);
                int state = requireState(
                    block.label(),
                    stateByLabel.get(block.label())
                );
                CffBlockKeyState blockKeys = requireBlockKey(
                    block.label(),
                    keyStateByLabel.get(block.label())
                );
                LabelNode caseTarget;
                if (isDirectRealCaseTargetVerifierCompatible(block, zeroStackLabels)) {
                    caseTarget = block.label();
                } else {
                    LabelNode stub = new LabelNode();
                    stubs.put(stub, block.label());
                    caseTarget = stub;
                }
                cases.put(
                    maskedDispatchToken(
                        blockKeys.pcToken(),
                        blockKeys,
                        dispatchSeed
                    ),
                    caseTarget
                );
                if (first) {
                    firstState = state;
                    first = false;
                }
            }
        }
        if (first) return insns;
        int fakeCount = fakeCaseCount(group.salt() ^ salt ^ island, syntheticNoiseBudget);
        if (dispatcherOutliner != null) {
            return dispatcherOutliner.emitIslandDispatchCall(
                group,
                island,
                islandBlocks,
                firstState,
                fakeCount,
                dispatchSeed,
                stateByLabel,
                keyStateByLabel,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                dataLocal,
                keyTmpLocal,
                poison,
                methodSeed,
                salt
            );
        }
        for (int fakeIndex = 0; fakeIndex < fakeCount; fakeIndex++) {
            LabelNode fake = new LabelNode();
            fakes.add(fake);
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
            cases.put(fakeToken, fake);
        }
        insns.add(group.islandLabels()[island]);
        emitTokenDispatch(
            insns,
            pcLocal,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            dataLocal,
            cases,
            poison,
            dispatchSeed,
            keyTmpLocal,
            smallTokenDispatchCases
        );
        for (Map.Entry<LabelNode, LabelNode> stub : stubs.entrySet()) {
            insns.add(stub.getKey());
            insns.add(new JumpInsnNode(Opcodes.GOTO, stub.getValue()));
        }
        if (useSharedFakeCaseRouter(fakes.size(), syntheticNoiseBudget)) {
            LabelNode sharedFake = new LabelNode();
            int fakeSelectorLocal = keyTmpLocal + 3;
            for (int fakeIndex = 0; fakeIndex < fakes.size(); fakeIndex++) {
                insns.add(fakes.get(fakeIndex));
                JvmPassBytecode.pushInt(insns, fakeIndex);
                insns.add(new VarInsnNode(Opcodes.ISTORE, fakeSelectorLocal));
                insns.add(new JumpInsnNode(Opcodes.GOTO, sharedFake));
            }
            long sharedFakeSeed = edgeSeed(
                salt,
                group.hub(),
                group.islandLabels()[island],
                0x534846414B45524CL ^ island ^ fakes.size()
            );
            insns.add(sharedFake);
            emitSharedFakeSelectorPollution(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                fakeSelectorLocal,
                sharedFakeSeed
            );
            emitStepKeys(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                sharedFakeSeed,
                EdgeRole.FAKE
            );
            emitFakeCaseBounce(
                insns,
                group,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                domainLocal,
                dataLocal,
                keyTmpLocal,
                firstState,
                island,
                keyStateByLabel,
                dispatchSeed,
                methodSeed,
                sharedFakeSeed,
                transitionOutliner
            );
        } else {
            for (int fakeIndex = 0; fakeIndex < fakes.size(); fakeIndex++) {
                insns.add(fakes.get(fakeIndex));
                long fakeSeed = edgeSeed(
                    salt,
                    group.hub(),
                    group.islandLabels()[island],
                    0x46414B4549534C45L ^ island ^ fakeIndex
                );
                emitStepKeys(
                    insns,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    fakeSeed,
                    EdgeRole.FAKE
                );
                emitFakeCaseBounce(
                    insns,
                    group,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    firstState,
                    island,
                    keyStateByLabel,
                    dispatchSeed,
                    methodSeed,
                    fakeSeed,
                    transitionOutliner
                );
            }
        }
        return insns;
    }

    private boolean useSharedFakeCaseRouter(
        int fakeCount,
        SyntheticNoiseBudget syntheticNoiseBudget
    ) {
        return fakeCount > 1 && syntheticNoiseBudget != SyntheticNoiseBudget.CRITICAL;
    }

    private void emitSharedFakeSelectorPollution(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int fakeSelectorLocal,
        long seed
    ) {
        int guardMask = nonZeroInt(JvmPassBytecode.mix(seed, 0x5348464755415244L));
        int blockMask = nonZeroInt(JvmPassBytecode.mix(seed, 0x534846424C4F434BL));

        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, fakeSelectorLocal));
        JvmPassBytecode.pushInt(insns, guardMask);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, guardLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, fakeSelectorLocal));
        JvmPassBytecode.pushInt(insns, blockMask);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, blockKeyLocal));

        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, fakeSelectorLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
    }

    private boolean isDirectRealCaseTargetVerifierCompatible(
        Block block,
        Set<LabelNode> zeroStackLabels
    ) {
        return isZeroStackLabel(block.label(), zeroStackLabels);
    }

    private void emitPoisonDiversion(
        InsnList insns,
        IslandGroup group,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        int keyTmpLocal,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long methodSeed,
        long salt
    ) {
        List<Integer> islands = new ArrayList<>();
        List<LabelNode> diversionLabels = new ArrayList<>();
        for (int island = 0; island < group.islandLabels().length; island++) {
            if (!islandHasBlock(group, island)) continue;
            islands.add(island);
            diversionLabels.add(new LabelNode());
        }
        if (diversionLabels.isEmpty()) {
            throw new IllegalStateException("CFF poison diversion has no island target");
        }
        emitPoisonDiversionRouter(
            insns,
            diversionLabels,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            domainLocal,
            group.salt() ^ salt
        );
        for (int i = 0; i < diversionLabels.size(); i++) {
            int island = islands.get(i);
            int state = firstIslandState(group, island, stateByLabel);
            CffBlockKeyState targetKeys = firstIslandKeyState(
                group,
                island,
                keyStateByLabel
            );
            long fakeSeed = edgeSeed(
                salt,
                group.hub(),
                group.islandLabels()[island],
                0x504F495346414B45L ^ island ^ i
            );
            insns.add(diversionLabels.get(i));
            emitStepKeys(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                fakeSeed,
                EdgeRole.FAKE
            );
            emitStorePc(
                insns,
                pcLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                keyLocal,
                state,
                targetKeys,
                methodSeed,
                group.salt() ^ island,
                keyTmpLocal
            );
            emitStoreMethodKey(
                insns,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                targetKeys
            );
            emitBindDispatchPcToDataDigest(
                insns,
                pcLocal,
                dataLocal,
                tokenDispatchSeed(group, island, keyStateByLabel)
            );
            emitStoreDomain(
                insns,
                domainLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                keyLocal,
                island,
                domainToken(group.salt(), island),
                targetKeys,
                methodSeed,
                domainSeed(group),
                keyTmpLocal
            );
            insns.add(new JumpInsnNode(Opcodes.GOTO, firstIslandLabel(group, island)));
        }
    }

    private void emitPoisonDiversionRouter(
        InsnList insns,
        List<LabelNode> diversionLabels,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        long seed
    ) {
        if (diversionLabels.size() == 1) {
            insns.add(new JumpInsnNode(Opcodes.GOTO, diversionLabels.get(0)));
            return;
        }
        int bucketCount = 1;
        while (bucketCount < diversionLabels.size()) {
            bucketCount <<= 1;
        }
        LabelNode[] labels = new LabelNode[bucketCount];
        for (int i = 0; i < bucketCount; i++) {
            labels[i] = diversionLabels.get(i % diversionLabels.size());
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x50444956525431L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, bucketCount - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new TableSwitchInsnNode(0, bucketCount - 1, labels[0], labels));
    }

    private boolean islandHasBlock(IslandGroup group, int island) {
        for (Block block : group.blocks()) {
            Integer blockIsland = group.islands().get(block.label());
            if (blockIsland != null && blockIsland == island) {
                return true;
            }
        }
        return false;
    }

    private int firstIslandState(
        IslandGroup group,
        int island,
        Map<LabelNode, Integer> stateByLabel
    ) {
        for (Block block : group.blocks()) {
            Integer blockIsland = group.islands().get(block.label());
            if (blockIsland != null && blockIsland == island) {
                return requireState(block.label(), stateByLabel.get(block.label()));
            }
        }
        throw new IllegalStateException("CFF poison diversion island has no state");
    }

    private void emitPoisonMethodExit(
        InsnList insns,
        MethodNode mn,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal
    ) {
        Type returnType = Type.getReturnType(mn.desc);
        switch (returnType.getSort()) {
            case Type.VOID -> insns.add(new InsnNode(Opcodes.RETURN));
            case Type.BOOLEAN, Type.CHAR, Type.BYTE, Type.SHORT, Type.INT -> {
                emitPoisonIntValue(insns, keyLocal, guardLocal, pathKeyLocal, blockKeyLocal);
                insns.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.FLOAT -> {
                emitPoisonIntValue(insns, keyLocal, guardLocal, pathKeyLocal, blockKeyLocal);
                insns.add(new InsnNode(Opcodes.I2F));
                insns.add(new InsnNode(Opcodes.FRETURN));
            }
            case Type.LONG -> {
                insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
                insns.add(new InsnNode(Opcodes.LRETURN));
            }
            case Type.DOUBLE -> {
                insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
                insns.add(new InsnNode(Opcodes.L2D));
                insns.add(new InsnNode(Opcodes.DRETURN));
            }
            default -> {
                insns.add(new InsnNode(Opcodes.ACONST_NULL));
                insns.add(new InsnNode(Opcodes.ARETURN));
            }
        }
    }

    private void emitPoisonIntValue(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, 0x4E504F49);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitFakeCaseBounce(
        InsnList insns,
        IslandGroup group,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        int keyTmpLocal,
        int state,
        int island,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long dispatchSeed,
        long methodSeed,
        long seed,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        LabelNode hop = new LabelNode();
        LabelNode pass = new LabelNode();
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
        if (transitionOutliner != null) {
            long fakeStepSeed = transitionKeySeed(seed, state, bounceTarget, EdgeRole.FAKE);
            EdgeKind fakeEdgeKind = chooseEdgeKind(seed, EdgeRole.FAKE, bounceTarget);
            LabelNode jumpTarget = transitionJumpTarget(bounceTarget, fakeEdgeKind, seed);
            insns.add(
                transitionOutliner.emitCall(
                    state,
                    bounceTarget,
                    fakeEdgeKind,
                    jumpTarget,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    dispatchSeed,
                    bounceKeys,
                    bounceKeys,
                    methodSeed,
                    fakeStepSeed,
                    EdgeRole.FAKE
                )
            );
            return;
        }
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
                insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
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
                insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
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
                insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
                insns.add(pass);
                insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
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
                insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
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
                insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
            }
        }
    }

    protected long caseSelectorSeed(
        IslandGroup group,
        LabelNode label,
        int state,
        int island
    ) {
        long seed = JvmPassBytecode.mix(
            group.salt() ^ 0x4341534553454C31L ^ island,
            state
        );
        seed = JvmPassBytecode.mix(seed, System.identityHashCode(label));
        return seed == 0L ? group.salt() ^ 0x53454C45435431L : seed;
    }

    protected long fakeCaseSelectorSeed(
        IslandGroup group,
        int fakeState,
        int island,
        int fakeIndex
    ) {
        long seed = JvmPassBytecode.mix(
            group.salt() ^ 0x46414B4553454C31L ^ island,
            fakeState
        );
        seed = JvmPassBytecode.mix(seed, fakeIndex);
        return seed == 0L ? group.salt() ^ 0x46414B45534C31L : seed;
    }

    protected InsnList aliasHub(
        IslandGroup group,
        int alias,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal
    ) {
        InsnList insns = new InsnList();
        LabelNode aliasLabel = group.aliasHubs()[alias];
        long seed = group.salt() ^ 0x414C494153485542L ^ alias;
        insns.add(aliasLabel);
        switch ((int) ((seed >>> 7) & 7L)) {
            case 0 -> insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
            case 1 -> {
                LabelNode hop = new LabelNode();
                insns.add(new JumpInsnNode(Opcodes.GOTO, hop));
                insns.add(hop);
                insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
            }
            case 2, 4, 6 -> emitOpaqueHubBranch(
                insns,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                seed,
                group.hub()
            );
            case 5 -> {
                LabelNode hopA = new LabelNode();
                LabelNode hopB = new LabelNode();
                insns.add(new JumpInsnNode(Opcodes.GOTO, hopA));
                insns.add(hopB);
                insns.add(new JumpInsnNode(Opcodes.GOTO, group.hub()));
                insns.add(hopA);
                insns.add(new JumpInsnNode(Opcodes.GOTO, hopB));
            }
            default -> emitOpaqueHubBranch(
                insns,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                seed ^ 0x4855424252414E43L,
                group.hub()
            );
        }
        return insns;
    }

    protected void emitOpaqueHubBranch(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        LabelNode hub
    ) {
        LabelNode left = new LabelNode();
        LabelNode right = new LabelNode();
        emitKeyPredicate(insns, guardLocal, pathKeyLocal, blockKeyLocal, seed);
        insns.add(
            new JumpInsnNode(
                ((seed >>> 3) & 1L) == 0L ? Opcodes.IFEQ : Opcodes.IFNE,
                left
            )
        );
        insns.add(new JumpInsnNode(Opcodes.GOTO, right));
        insns.add(left);
        insns.add(new JumpInsnNode(Opcodes.GOTO, hub));
        insns.add(right);
        insns.add(new JumpInsnNode(Opcodes.GOTO, hub));
    }

    protected void emitDomainDispatch(
        InsnList insns,
        int domainLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        IslandGroup group,
        LabelNode poison
    ) {
        LabelNode[] islandLabels = group.islandLabels();
        if (islandLabels.length == 1) {
            insns.add(new JumpInsnNode(Opcodes.GOTO, islandLabels[0]));
            return;
        }
        emitEncodedDomainIfChain(
            insns,
            domainLocal,
            islandLabels,
            poison,
            group.salt()
        );
    }

    protected void emitEncodedDomainIfChain(
        InsnList insns,
        int domainLocal,
        LabelNode[] islandLabels,
        LabelNode poison,
        long orderSeed
    ) {
        TreeMap<Integer, LabelNode> cases = new TreeMap<>();
        for (int i = 0; i < islandLabels.length; i++) {
            cases.put(domainToken(orderSeed, i), islandLabels[i]);
        }
        int[] keys = new int[cases.size()];
        LabelNode[] labels = new LabelNode[cases.size()];
        int index = 0;
        for (Map.Entry<Integer, LabelNode> entry : cases.entrySet()) {
            keys[index] = entry.getKey();
            labels[index] = entry.getValue();
            index++;
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, domainLocal));
        insns.add(new LookupSwitchInsnNode(poison, keys, labels));
    }

    protected void emitTokenDispatch(
        InsnList insns,
        int pcLocal,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int dataLocal,
        TreeMap<Integer, LabelNode> cases,
        LabelNode poison,
        long seed,
        int scratchLocal,
        int smallTokenDispatchCases
    ) {
        if (cases.size() <= smallTokenDispatchCases) {
            emitSmallTokenDispatch(
                insns,
                pcLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                dataLocal,
                cases,
                poison,
                seed,
                scratchLocal
            );
            return;
        }
        emitDispatchTokenMask(
            insns,
            pcLocal,
            keyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            dataLocal,
            seed,
            scratchLocal
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        int[] keys = new int[cases.size()];
        LabelNode[] labels = new LabelNode[cases.size()];
        int index = 0;
        for (Map.Entry<Integer, LabelNode> entry : cases.entrySet()) {
            keys[index] = entry.getKey();
            labels[index] = entry.getValue();
            index++;
        }
        insns.add(new LookupSwitchInsnNode(poison, keys, labels));
    }

    protected void emitSmallTokenDispatch(
        InsnList insns,
        int pcLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int dataLocal,
        TreeMap<Integer, LabelNode> cases,
        LabelNode poison,
        long seed,
        int scratchLocal
    ) {
        int multiplierLocal = scratchLocal;
        int inverseLocal = scratchLocal + 1;
        int rawPcLocal = scratchLocal + 2;
        if (cases.size() == 1) {
            Map.Entry<Integer, LabelNode> entry = cases.firstEntry();
            emitDispatchSelectorFromEncodedPc(
                insns,
                pcLocal,
                rawPcLocal,
                dataLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                seed,
                multiplierLocal,
                inverseLocal
            );
            JvmPassBytecode.pushInt(insns, entry.getKey());
            insns.add(new JumpInsnNode(Opcodes.IF_ICMPNE, poison));
            emitRestoreRawDispatchPc(insns, pcLocal, rawPcLocal);
            insns.add(new JumpInsnNode(Opcodes.GOTO, entry.getValue()));
            return;
        }
        List<Map.Entry<Integer, LabelNode>> ordered = new ArrayList<>(cases.entrySet());
        ordered.sort((left, right) -> Long.compare(
            JvmPassBytecode.mix(seed, left.getKey()),
            JvmPassBytecode.mix(seed, right.getKey())
        ));
        int selectorLocal = scratchLocal + 3;
        emitDispatchSelectorFromEncodedPc(
            insns,
            pcLocal,
            rawPcLocal,
            dataLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            seed,
            multiplierLocal,
            inverseLocal
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, selectorLocal));
        List<LabelNode> matches = new ArrayList<>(ordered.size() - 1);
        for (int i = 0; i < ordered.size() - 1; i++) {
            Map.Entry<Integer, LabelNode> entry = ordered.get(i);
            LabelNode match = new LabelNode();
            matches.add(match);
            insns.add(new VarInsnNode(Opcodes.ILOAD, selectorLocal));
            JvmPassBytecode.pushInt(insns, entry.getKey());
            insns.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, match));
        }
        Map.Entry<Integer, LabelNode> last = ordered.get(ordered.size() - 1);
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorLocal));
        JvmPassBytecode.pushInt(insns, last.getKey());
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPNE, poison));
        emitRestoreRawDispatchPc(insns, pcLocal, rawPcLocal);
        insns.add(new JumpInsnNode(Opcodes.GOTO, last.getValue()));
        for (int i = 0; i < matches.size(); i++) {
            insns.add(matches.get(i));
            emitRestoreRawDispatchPc(insns, pcLocal, rawPcLocal);
            insns.add(new JumpInsnNode(Opcodes.GOTO, ordered.get(i).getValue()));
        }
    }

    protected long tokenDispatchSeed(long groupSalt, int island) {
        return JvmPassBytecode.mix(groupSalt ^ 0x544F4B4449535031L, island);
    }

    protected long tokenDispatchSeed(
        IslandGroup group,
        int island,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel
    ) {
        long seed = tokenDispatchSeed(group.salt(), island);
        for (int attempt = 0; attempt < 32; attempt++) {
            Set<Integer> seen = new HashSet<>();
            boolean collision = false;
            for (Block block : group.blocks()) {
                Integer blockIsland = group.islands().get(block.label());
                if (blockIsland == null || blockIsland != island) {
                    continue;
                }
                CffBlockKeyState keyState = requireBlockKey(
                    block.label(),
                    keyStateByLabel.get(block.label())
                );
                int masked = maskedDispatchToken(keyState.pcToken(), keyState, seed);
                if (!seen.add(masked)) {
                    collision = true;
                    break;
                }
            }
            if (!collision) {
                return seed;
            }
            seed = JvmPassBytecode.mix(seed, attempt + 1L);
        }
        throw new IllegalStateException("CFF token dispatch seed collision for island");
    }

    protected Map<DispatchTarget, Long> buildDispatchSeedByTarget(
        DispatchPlan dispatchPlan,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel
    ) {
        Map<DispatchTarget, Long> seeds = new IdentityHashMap<>();
        for (IslandGroup group : dispatchPlan.groups()) {
            for (int island = 0; island < group.islandLabels().length; island++) {
                long seed = tokenDispatchSeed(group, island, keyStateByLabel);
                for (Block block : group.blocks()) {
                    Integer blockIsland = group.islands().get(block.label());
                    if (blockIsland == null || blockIsland != island) {
                        continue;
                    }
                    DispatchTarget target = requireTarget(
                        block.label(),
                        dispatchPlan.targets().get(block.label())
                    );
                    Long existing = seeds.putIfAbsent(target, seed);
                    if (existing != null && existing.longValue() != seed) {
                        throw new IllegalStateException(
                            "CFF dispatch target maps to multiple token seeds"
                        );
                    }
                }
            }
        }
        return seeds;
    }

    protected long requireDispatchSeed(
        DispatchTarget target,
        Map<DispatchTarget, Long> dispatchSeedByTarget
    ) {
        Long seed = dispatchSeedByTarget.get(target);
        if (seed == null) {
            throw new IllegalStateException("CFF dispatch target has no token seed");
        }
        return seed;
    }

    protected int maskedDispatchToken(
        int token,
        CffBlockKeyState keyState,
        long seed
    ) {
        return token ^ dispatchTokenMask(token, keyState, seed);
    }

    protected int dispatchTokenMask(
        int token,
        CffBlockKeyState keyState,
        long seed
    ) {
        return dispatchTokenCoreMask(token, keyState, seed);
    }

    private int dispatchTokenCoreMask(
        int token,
        CffBlockKeyState keyState,
        long seed
    ) {
        int x = keyState.guardKey() +
            (keyState.pathKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x44545041544831L)));
        x ^= keyState.blockKey() *
            (nonZeroInt(JvmPassBytecode.mix(seed, 0x4454424C4F434B31L)) | 1);
        x ^= token + nonZeroInt(JvmPassBytecode.mix(seed, 0x44545043544F4B31L));
        return x;
    }

    protected void emitBindDispatchPcToDataDigest(
        InsnList insns,
        int pcLocal,
        int dataLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        emitDispatchDataTokenMultiplier(insns, dataLocal, seed);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
    }

    protected int dispatchMethodKeyFold(long keyValue, long seed) {
        return ((int) keyValue) ^
            ((int) (keyValue >>> 32)) ^
            nonZeroInt(JvmPassBytecode.mix(seed, 0x444953504D4B31L));
    }

    protected void emitDispatchTokenMask(
        InsnList insns,
        int pcLocal,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int dataLocal,
        long seed,
        int scratchLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        emitDispatchDataTokenMultiplier(insns, dataLocal, seed);
        insns.add(new VarInsnNode(Opcodes.ISTORE, scratchLocal));
        emitOddIntInverse(insns, scratchLocal, scratchLocal + 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
        emitDispatchTokenCoreMask(
            insns,
            pcLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            seed
        );
    }

    private void emitDispatchSelectorFromEncodedPc(
        InsnList insns,
        int encodedPcLocal,
        int rawPcLocal,
        int dataLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int multiplierLocal,
        int inverseLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, encodedPcLocal));
        emitDispatchDataTokenMultiplier(insns, dataLocal, seed);
        insns.add(new VarInsnNode(Opcodes.ISTORE, multiplierLocal));
        emitOddIntInverse(insns, multiplierLocal, inverseLocal);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, rawPcLocal));
        emitDispatchTokenCoreMask(
            insns,
            rawPcLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            seed
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, rawPcLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRestoreRawDispatchPc(
        InsnList insns,
        int pcLocal,
        int rawPcLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, rawPcLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
    }

    private void emitDispatchTokenCoreMask(
        InsnList insns,
        int pcTokenLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x44545041544831L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4454424C4F434B31L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcTokenLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x44545043544F4B31L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitDispatchDataTokenMultiplier(
        InsnList insns,
        int dataLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4454444D554C4131L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 3));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4454444D554C4D31L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 19));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4454444D554C4631L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
    }

    private void emitOddIntInverse(
        InsnList insns,
        int multiplierLocal,
        int inverseLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, multiplierLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, inverseLocal));
        for (int i = 0; i < 5; i++) {
            insns.add(new VarInsnNode(Opcodes.ILOAD, inverseLocal));
            JvmPassBytecode.pushInt(insns, 2);
            insns.add(new VarInsnNode(Opcodes.ILOAD, multiplierLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, inverseLocal));
            insns.add(new InsnNode(Opcodes.IMUL));
            insns.add(new InsnNode(Opcodes.ISUB));
            insns.add(new InsnNode(Opcodes.IMUL));
            insns.add(new VarInsnNode(Opcodes.ISTORE, inverseLocal));
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, inverseLocal));
    }

    protected void emitDispatchMethodKeyFold(InsnList insns, int keyLocal, long seed) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x444953504D4B31L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
    }
}
