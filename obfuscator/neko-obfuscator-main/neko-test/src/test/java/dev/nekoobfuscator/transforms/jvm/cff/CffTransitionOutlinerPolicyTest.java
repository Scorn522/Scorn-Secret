package dev.nekoobfuscator.transforms.jvm.cff;

import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.EdgeKind.ALIAS_HUB;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.EdgeKind.DIRECT_ISLAND;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.EdgeKind.HUB;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.EdgeRole.CONDITIONAL_FALSE;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.EdgeRole.FAKE;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.EdgeRole.FALLTHROUGH;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.EdgeRole.HANDLER;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.EdgeRole.POISON;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import dev.nekoobfuscator.transforms.jvm.internal.JvmCodeSizeEstimator;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

final class CffTransitionOutlinerPolicyTest {
    private static final String CFF_SHARED_GROUP_DISPATCH_DESC = "(JIIIIII[J)J";
    private static final String CFF_COMPACT_GROUP_DISPATCH_DESC = "(JIIIIII[I)J";
    private static final String CFF_TRANSITION_MATERIAL_DESC =
        "(JIII[Ljava/lang/Object;II[J)J";
    private static final String CFF_COMPACT_STATE_TRANSITION_DESC =
        "(JIIII[J[I)J";
    private static final String CFF_ISLAND_MATERIAL_DESC =
        "(JIII[Ljava/lang/Object;III)I";

    @Test
    void budgetedInlineOnlyAcceptsRealDirectIslandEdges() {
        assertTrue(
            CffTransitionOutliner.isBudgetedDirectTransitionEligible(
                DIRECT_ISLAND,
                FALLTHROUGH,
                1
            )
        );
        assertTrue(
            CffTransitionOutliner.isBudgetedDirectTransitionEligible(
                DIRECT_ISLAND,
                CONDITIONAL_FALSE,
                128
            )
        );

        assertFalse(
            CffTransitionOutliner.isBudgetedDirectTransitionEligible(
                DIRECT_ISLAND,
                FALLTHROUGH,
                0
            )
        );
        assertFalse(
            CffTransitionOutliner.isBudgetedDirectTransitionEligible(
                DIRECT_ISLAND,
                HANDLER,
                128
            )
        );
        assertFalse(
            CffTransitionOutliner.isBudgetedDirectTransitionEligible(
                DIRECT_ISLAND,
                FAKE,
                128
            )
        );
        assertFalse(
            CffTransitionOutliner.isBudgetedDirectTransitionEligible(
                DIRECT_ISLAND,
                POISON,
                128
            )
        );
        assertFalse(
            CffTransitionOutliner.isBudgetedDirectTransitionEligible(
                HUB,
                FALLTHROUGH,
                128
            )
        );
        assertFalse(
            CffTransitionOutliner.isBudgetedDirectTransitionEligible(
                ALIAS_HUB,
                FALLTHROUGH,
                128
            )
        );
    }

    @Test
    void denseResultRoutesReloadTransitionPcBeforeRouteMask() {
        assertTrue(
            CffTransitionOutliner.shouldReloadPcForGroupResultRoute(false, true, false),
            "dense group result routing must reload pc even without a hub result"
        );
        assertTrue(
            CffTransitionOutliner.shouldReloadPcForGroupResultRoute(false, false, true),
            "hub result routing must keep the previous pc reload behavior"
        );
        assertFalse(
            CffTransitionOutliner.shouldReloadPcForGroupResultRoute(true, true, false),
            "inlined single-result fallthrough should not emit result routing loads"
        );
        assertFalse(
            CffTransitionOutliner.shouldReloadPcForGroupResultRoute(false, false, false),
            "sparse non-hub result routing does not consume the pc route mask"
        );

        assertTrue(
            CffTransitionOutliner.shouldReloadPcForIslandResultRoute(true, 0),
            "dense island result routing must reload pc even without fake routes"
        );
        assertTrue(
            CffTransitionOutliner.shouldReloadPcForIslandResultRoute(false, 1),
            "fake island routes must keep the previous pc reload behavior"
        );
        assertFalse(
            CffTransitionOutliner.shouldReloadPcForIslandResultRoute(false, 0),
            "sparse island result routing without fake routes does not consume the pc route mask"
        );

        assertTrue(
            CffTransitionOutliner.useCompactSparseResultFirst(true, false),
            "compact sparse group callers should reject poison before reloading full state"
        );
        assertFalse(
            CffTransitionOutliner.useCompactSparseResultFirst(true, true),
            "dense group routers must keep full masked state routing"
        );
        assertFalse(
            CffTransitionOutliner.useCompactSparseResultFirst(false, false),
            "packed long[] dispatch state cannot use compact sparse result-first routing"
        );
        assertEquals(
            Opcodes.IFNE,
            CffTransitionOutliner.compactSparsePoisonBranchOpcode(true),
            "single zero-token sparse fallthrough must reject nonzero poison tokens"
        );
        assertEquals(
            Opcodes.IFEQ,
            CffTransitionOutliner.compactSparsePoisonBranchOpcode(false),
            "normal sparse routers must reject the zero poison token"
        );

        assertFalse(CffTransitionOutliner.useSmallDomainRouterBranches(0));
        assertTrue(CffTransitionOutliner.useSmallDomainRouterBranches(1));
        assertTrue(CffTransitionOutliner.useSmallDomainRouterBranches(2));
        assertFalse(CffTransitionOutliner.useSmallDomainRouterBranches(3));
    }

    @Test
    void generatedCffStaticHelpersUseInterfaceCompatibleAccess() {
        int interfaceAccess = CffTransitionOutliner.generatedStaticHelperAccess(true);
        assertTrue((interfaceAccess & Opcodes.ACC_PUBLIC) != 0);
        assertFalse((interfaceAccess & Opcodes.ACC_PRIVATE) != 0);
        assertTrue((interfaceAccess & Opcodes.ACC_STATIC) != 0);
        assertTrue((interfaceAccess & Opcodes.ACC_SYNTHETIC) != 0);

        int classAccess = CffTransitionOutliner.generatedStaticHelperAccess(false);
        assertTrue((classAccess & Opcodes.ACC_PRIVATE) != 0);
        assertFalse((classAccess & Opcodes.ACC_PUBLIC) != 0);
        assertTrue((classAccess & Opcodes.ACC_STATIC) != 0);
        assertTrue((classAccess & Opcodes.ACC_SYNTHETIC) != 0);
    }

    @Test
    void smallDomainRouterEmitterUsesBranchesAndLeavesLargeRoutersForSwitch() {
        LabelNode poison = new LabelNode();
        LabelNode first = new LabelNode();
        LabelNode second = new LabelNode();

        InsnList oneKey = new InsnList();
        assertTrue(CffTransitionOutliner.emitSmallDomainRouterBranches(
            oneKey,
            6,
            poison,
            new int[] { 0x12345678 },
            new LabelNode[] { first }
        ));
        assertEquals(0, lookupSwitchCount(oneKey));
        assertEquals(1, jumpOpcodeCount(oneKey, Opcodes.IF_ICMPNE));

        InsnList twoKeys = new InsnList();
        assertTrue(CffTransitionOutliner.emitSmallDomainRouterBranches(
            twoKeys,
            6,
            poison,
            new int[] { 0x12345678, 0x3456789A },
            new LabelNode[] { first, second }
        ));
        assertEquals(0, lookupSwitchCount(twoKeys));
        assertEquals(2, jumpOpcodeCount(twoKeys, Opcodes.IF_ICMPEQ));
        assertEquals(1, jumpOpcodeCount(twoKeys, Opcodes.GOTO));

        InsnList large = new InsnList();
        assertFalse(CffTransitionOutliner.emitSmallDomainRouterBranches(
            large,
            6,
            poison,
            new int[] { 1, 2, 3 },
            new LabelNode[] { first, second, new LabelNode() }
        ));
        assertEquals(0, large.size());
    }

    @Test
    void adaptiveReserveTracksFuturePostCffSitePressure() {
        MethodNode lowPressure = new MethodNode(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "lowPressure",
            "()V",
            null,
            null
        );
        lowPressure.instructions.add(new InsnNode(Opcodes.ICONST_0));
        lowPressure.instructions.add(new InsnNode(Opcodes.POP));
        lowPressure.instructions.add(new InsnNode(Opcodes.RETURN));

        MethodNode highPressure = new MethodNode(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "highPressure",
            "()V",
            null,
            null
        );
        for (int i = 0; i < 5; i++) {
            highPressure.instructions.add(stringConcatIndy());
            highPressure.instructions.add(new InsnNode(Opcodes.POP));
            highPressure.instructions.add(new LdcInsnNode("protected literal " + i));
            highPressure.instructions.add(new InsnNode(Opcodes.POP));
        }
        highPressure.instructions.add(new InsnNode(Opcodes.RETURN));

        int lowReserve = CffBlockBuilder.adaptivePostCffReserveBytes(lowPressure);
        int highReserve = CffBlockBuilder.adaptivePostCffReserveBytes(highPressure);
        assertTrue(lowReserve < highReserve, "low-pressure methods should spend more inline budget");
        assertEquals(1_500, highReserve, "high-pressure methods should keep the fixed reserve cap");
    }

    @Test
    void adaptiveReserveStillRejectsAlreadyOversizedProjectedMethods() {
        MethodNode lowPressure = new MethodNode(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "lowPressure",
            "()V",
            null,
            null
        );
        lowPressure.instructions.add(new InsnNode(Opcodes.RETURN));

        assertEquals(
            0,
            CffBlockBuilder.inlineDirectTransitionBudgetBytesForProjectedSize(
                lowPressure,
                8_000
            )
        );
    }

    @Test
    void cyclicJitBudgetEmitsBudgetedInlineAndKeepsOutlinedRoutes()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-budgeted-direct-inline"));
        Path source = work.resolve("CffBudgetedDirectInlineShape.java");
        Files.writeString(source, cyclicJitBudgetSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("cff-budgeted-direct-inline.jar");
        writeJar(inputJar, classes, "CffBudgetedDirectInlineShape");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("cff-budgeted-direct-inline-obf.jar");
        String oldProperty = System.getProperty("neko.cff.recordBudgetedDirectInlineStats");
        System.setProperty("neko.cff.recordBudgetedDirectInlineStats", "true");
        ControlFlowFlatteningPass.clearBudgetedDirectInlineStatsForTesting();
        try {
            runCffOnlyObfuscation(inputJar, outputJar);
        } finally {
            if (oldProperty == null) {
                System.clearProperty("neko.cff.recordBudgetedDirectInlineStats");
            } else {
                System.setProperty("neko.cff.recordBudgetedDirectInlineStats", oldProperty);
            }
        }
        assertEquals(original, runJar(outputJar));

        ControlFlowFlatteningPass.BudgetedDirectInlineStats stats =
            ControlFlowFlatteningPass.budgetedDirectInlineStatsForTesting()
                .entrySet()
                .stream()
                .filter(entry -> entry.getKey().endsWith(".hot(I)I"))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElseThrow(() -> new AssertionError("missing budgeted direct-inline stats"));
        assertTrue(stats.candidates() > 0, "no eligible budgeted direct-island transitions");
        assertTrue(stats.accepted() > 0, "no budgeted direct-island transition was inlined");

        MethodNode hot = method(outputJar, "CffBudgetedDirectInlineShape", "hot");
        assertTrue(
            JvmCodeSizeEstimator.estimateMethodBytes(hot) < 8_000,
            "budgeted inline CFF method exceeded JIT budget"
        );
        assertTrue(
            cffOutlinerHelperCallCount(hot) > 0,
            "budgeted direct inline removed all outlined helper routes"
        );
        assertTrue(
            compactGroupDispatchCallCount(hot) > 0,
            "JIT-budget CFF method did not route dispatch helpers through compact state ABI"
        );
        assertTrue(
            compactStateTransitionCallCount(hot) > 0,
            "JIT-budget CFF method did not route direct transitions through compact state wrappers"
        );
        assertIslandDispatchMissUsesColdHelper(outputJar, "CffBudgetedDirectInlineShape");
        assertCompactDispatchHelpersUseIntState(outputJar, "CffBudgetedDirectInlineShape");
        assertCompactSparseGroupDispatchUsesResultOnlyDefault(
            outputJar,
            "CffBudgetedDirectInlineShape"
        );
        assertLargeDomainGroupRoutersKeepSwitchDispatch(outputJar, "CffBudgetedDirectInlineShape");
        assertCompactSparseGroupCallerBranchesOnResultFirst(hot);
        assertCompactTransitionWrappersPreserveMaterialCalls(
            outputJar,
            "CffBudgetedDirectInlineShape"
        );
    }

    private static void runCffOnlyObfuscation(Path input, Path output)
        throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x5A6C0FFEE11L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private static MethodNode method(Path jar, String owner, String name)
        throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        assertTrue(clazz != null, "missing class " + owner);
        for (MethodNode method : clazz.asmNode().methods) {
            if (name.equals(method.name)
                && method.instructions != null
                && method.instructions.size() > 0) {
                return method;
            }
        }
        throw new AssertionError("missing transformed method " + owner + "." + name);
    }

    private static int cffOutlinerHelperCallCount(MethodNode method) {
        int calls = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof MethodInsnNode call)) continue;
            if (CFF_SHARED_GROUP_DISPATCH_DESC.equals(call.desc)) {
                calls++;
            } else if (CFF_COMPACT_GROUP_DISPATCH_DESC.equals(call.desc)) {
                calls++;
            } else if (CFF_TRANSITION_MATERIAL_DESC.equals(call.desc)) {
                calls++;
            } else if ("(JIIII[J)J".equals(call.desc)) {
                calls++;
            } else if (CFF_COMPACT_STATE_TRANSITION_DESC.equals(call.desc)) {
                calls++;
            }
        }
        return calls;
    }

    private static int compactGroupDispatchCallCount(MethodNode method) {
        int calls = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                && CFF_COMPACT_GROUP_DISPATCH_DESC.equals(call.desc)) {
                calls++;
            }
        }
        return calls;
    }

    private static int compactStateTransitionCallCount(MethodNode method) {
        int calls = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                && CFF_COMPACT_STATE_TRANSITION_DESC.equals(call.desc)) {
                calls++;
            }
        }
        return calls;
    }

    private static void assertCompactTransitionWrappersPreserveMaterialCalls(Path jar, String owner)
        throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        assertTrue(clazz != null, "missing class " + owner);
        int wrappers = 0;
        for (MethodNode method : clazz.asmNode().methods) {
            if (!CFF_COMPACT_STATE_TRANSITION_DESC.equals(method.desc)
                || method.instructions == null
                || method.instructions.size() == 0) {
                continue;
            }
            wrappers++;
            assertEquals(
                1,
                transitionMaterialCallCount(method),
                "compact transition wrapper lost transition material helper coverage"
            );
        }
        assertTrue(wrappers > 0, "no compact state transition wrappers were generated");
    }

    private static int transitionMaterialCallCount(MethodNode method) {
        int calls = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                && CFF_TRANSITION_MATERIAL_DESC.equals(call.desc)) {
                calls++;
            }
        }
        return calls;
    }

    private static void assertCompactDispatchHelpersUseIntState(Path jar, String owner)
        throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        assertTrue(clazz != null, "missing class " + owner);
        int helpers = 0;
        for (MethodNode method : clazz.asmNode().methods) {
            if (!CFF_COMPACT_GROUP_DISPATCH_DESC.equals(method.desc)
                || method.instructions == null
                || method.instructions.size() == 0) {
                continue;
            }
            helpers++;
            assertTrue(
                storesIntState(method),
                "compact dispatch helper did not store state through int[] carrier"
            );
        }
        assertTrue(helpers > 0, "no compact dispatch helpers were generated");
    }

    private static void assertCompactSparseGroupDispatchUsesResultOnlyDefault(
        Path jar,
        String owner
    ) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        assertTrue(clazz != null, "missing class " + owner);
        int groupWrappers = 0;
        int resultOnlyDefaults = 0;
        for (MethodNode method : clazz.asmNode().methods) {
            if (!CFF_COMPACT_GROUP_DISPATCH_DESC.equals(method.desc)
                || method.instructions == null
                || method.instructions.size() == 0) {
                continue;
            }
            LabelNode defaultLabel = leadingDomainRouterDefault(method);
            if (defaultLabel == null) {
                continue;
            }
            groupWrappers++;
            int stores = iastoreCountUntilReturn(defaultLabel);
            if (stores == 1 && firstIastoreStoresIndex(defaultLabel, 5)) {
                resultOnlyDefaults++;
            }
        }
        assertTrue(groupWrappers > 0, "no compact group dispatch wrappers were generated");
        assertTrue(
            resultOnlyDefaults > 0,
            "compact sparse group dispatch default did not use result-only state return"
        );
    }

    private static void assertLargeDomainGroupRoutersKeepSwitchDispatch(Path jar, String owner)
        throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        assertTrue(clazz != null, "missing class " + owner);
        int switchRouters = 0;
        for (MethodNode method : clazz.asmNode().methods) {
            if (!CFF_COMPACT_GROUP_DISPATCH_DESC.equals(method.desc)
                || method.instructions == null
                || method.instructions.size() == 0) {
                continue;
            }
            LookupSwitchInsnNode switchInsn = leadingDomainLookupSwitch(method);
            if (switchInsn != null) {
                switchRouters++;
                assertTrue(
                    switchInsn.labels.size() > 2,
                    "small group domain router retained lookup switch dispatch"
                );
                continue;
            }
        }
        assertTrue(switchRouters > 0, "no larger compact group router retained switch dispatch");
    }

    private static void assertCompactSparseGroupCallerBranchesOnResultFirst(MethodNode method) {
        int compactCalls = 0;
        int resultFirstCalls = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof MethodInsnNode call)
                || !CFF_COMPACT_GROUP_DISPATCH_DESC.equals(call.desc)) {
                continue;
            }
            compactCalls++;
            if (loadsResultCellBeforeFullStateReload(call)) {
                resultFirstCalls++;
            }
        }
        assertTrue(compactCalls > 0, "hot method did not call compact dispatch helpers");
        assertTrue(
            resultFirstCalls > 0,
            "compact sparse group caller did not branch on result before full state reload"
        );
    }

    private static LookupSwitchInsnNode leadingDomainLookupSwitch(MethodNode method) {
        AbstractInsnNode first = nextOpcodeInsn(method.instructions.getFirst());
        if (!isIntLoad(first, 6)) {
            return null;
        }
        AbstractInsnNode second = nextOpcodeInsn(first.getNext());
        if (second instanceof LookupSwitchInsnNode switchInsn) {
            return switchInsn;
        }
        return null;
    }

    private static LabelNode leadingDomainRouterDefault(MethodNode method) {
        LookupSwitchInsnNode switchInsn = leadingDomainLookupSwitch(method);
        if (switchInsn != null) {
            return switchInsn.dflt;
        }
        AbstractInsnNode first = nextOpcodeInsn(method.instructions.getFirst());
        if (!isIntLoad(first, 6)) {
            return null;
        }
        AbstractInsnNode second = nextOpcodeInsn(first.getNext());
        if (pushedInt(second) == null) {
            return null;
        }
        AbstractInsnNode third = nextOpcodeInsn(second.getNext());
        if (!(third instanceof JumpInsnNode firstJump)) {
            return null;
        }
        if (firstJump.getOpcode() == Opcodes.IF_ICMPNE) {
            return firstJump.label;
        }
        if (firstJump.getOpcode() != Opcodes.IF_ICMPEQ) {
            return null;
        }
        AbstractInsnNode fourth = nextOpcodeInsn(firstJump.getNext());
        if (!isIntLoad(fourth, 6)) {
            return null;
        }
        AbstractInsnNode fifth = nextOpcodeInsn(fourth.getNext());
        if (pushedInt(fifth) == null) {
            return null;
        }
        AbstractInsnNode sixth = nextOpcodeInsn(fifth.getNext());
        if (!(sixth instanceof JumpInsnNode secondJump)
            || secondJump.getOpcode() != Opcodes.IF_ICMPEQ) {
            return null;
        }
        AbstractInsnNode seventh = nextOpcodeInsn(secondJump.getNext());
        if (seventh instanceof JumpInsnNode miss
            && miss.getOpcode() == Opcodes.GOTO) {
            return miss.label;
        }
        return null;
    }

    private static boolean isIntLoad(AbstractInsnNode insn, int local) {
        return insn instanceof VarInsnNode load
            && load.getOpcode() == Opcodes.ILOAD
            && load.var == local;
    }

    private static int lookupSwitchCount(InsnList insns) {
        int count = 0;
        for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LookupSwitchInsnNode) {
                count++;
            }
        }
        return count;
    }

    private static int jumpOpcodeCount(InsnList insns, int opcode) {
        int count = 0;
        for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode jump && jump.getOpcode() == opcode) {
                count++;
            }
        }
        return count;
    }

    private static int iastoreCountUntilReturn(LabelNode start) {
        int stores = 0;
        for (
            AbstractInsnNode insn = nextOpcodeInsn(start.getNext());
            insn != null && insn.getOpcode() != Opcodes.LRETURN;
            insn = nextOpcodeInsn(insn.getNext())
        ) {
            if (insn.getOpcode() == Opcodes.IASTORE) {
                stores++;
            }
        }
        return stores;
    }

    private static boolean firstIastoreStoresIndex(LabelNode start, int expectedIndex) {
        for (
            AbstractInsnNode insn = nextOpcodeInsn(start.getNext());
            insn != null && insn.getOpcode() != Opcodes.LRETURN;
            insn = nextOpcodeInsn(insn.getNext())
        ) {
            if (insn.getOpcode() != Opcodes.IASTORE) {
                continue;
            }
            AbstractInsnNode valueInsn = previousOpcodeInsn(insn.getPrevious());
            AbstractInsnNode indexInsn = valueInsn == null
                ? null
                : previousOpcodeInsn(valueInsn.getPrevious());
            Integer index = pushedInt(indexInsn);
            return index != null && index == expectedIndex;
        }
        return false;
    }

    private static boolean loadsResultCellBeforeFullStateReload(MethodInsnNode call) {
        boolean sawCallStore = false;
        for (
            AbstractInsnNode insn = nextOpcodeInsn(call.getNext());
            insn != null;
            insn = nextOpcodeInsn(insn.getNext())
        ) {
            if (!sawCallStore) {
                if (insn.getOpcode() == Opcodes.LSTORE) {
                    sawCallStore = true;
                    continue;
                }
                if (insn instanceof MethodInsnNode || insn instanceof JumpInsnNode) {
                    return false;
                }
                continue;
            }
            if (insn instanceof JumpInsnNode jump) {
                return jump.getOpcode() == Opcodes.IFEQ || jump.getOpcode() == Opcodes.IFNE;
            }
            if (insn.getOpcode() == Opcodes.IALOAD) {
                AbstractInsnNode indexInsn = previousOpcodeInsn(insn.getPrevious());
                Integer index = pushedInt(indexInsn);
                if (index == null) {
                    return false;
                }
                return index == 5 && branchesOnLoadedResult(insn);
            }
            if (insn instanceof MethodInsnNode) {
                return false;
            }
        }
        return false;
    }

    private static boolean branchesOnLoadedResult(AbstractInsnNode iaload) {
        AbstractInsnNode store = nextOpcodeInsn(iaload.getNext());
        AbstractInsnNode load = store == null ? null : nextOpcodeInsn(store.getNext());
        AbstractInsnNode branch = load == null ? null : nextOpcodeInsn(load.getNext());
        return store != null
            && store.getOpcode() == Opcodes.ISTORE
            && load != null
            && load.getOpcode() == Opcodes.ILOAD
            && branch instanceof JumpInsnNode
            && (branch.getOpcode() == Opcodes.IFEQ || branch.getOpcode() == Opcodes.IFNE);
    }

    private static boolean storesIntState(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() == Opcodes.IASTORE) {
                return true;
            }
        }
        return false;
    }

    private static void assertIslandDispatchMissUsesColdHelper(Path jar, String owner)
        throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        assertTrue(clazz != null, "missing class " + owner);
        Set<String> sharedHelpers = new HashSet<>();
        for (MethodNode method : clazz.asmNode().methods) {
            if (isCffDispatchHelperDesc(method.desc)) {
                sharedHelpers.add(method.name);
            }
        }

        for (MethodNode method : clazz.asmNode().methods) {
            if (!isCffDispatchHelperDesc(method.desc)
                || method.instructions == null
                || method.instructions.size() == 0) {
                continue;
            }
            boolean decodesRealResult = false;
            boolean returnedRealResultBeforeColdMiss = false;
            boolean callsColdMissHelper = false;
            for (
                AbstractInsnNode insn = method.instructions.getFirst();
                insn != null;
                insn = insn.getNext()
            ) {
                if (insn.getOpcode() == Opcodes.LRETURN && !callsColdMissHelper) {
                    returnedRealResultBeforeColdMiss = true;
                }
                if (!(insn instanceof MethodInsnNode call)) {
                    continue;
                }
                if (CFF_ISLAND_MATERIAL_DESC.equals(call.desc)) {
                    decodesRealResult = true;
                    continue;
                }
                if (!isCffDispatchHelperDesc(call.desc)
                    || !owner.equals(call.owner)
                    || !sharedHelpers.contains(call.name)
                    || call.name.equals(method.name)) {
                    continue;
                }
                AbstractInsnNode next = nextOpcodeInsn(call.getNext());
                if (next != null && next.getOpcode() == Opcodes.LRETURN) {
                    callsColdMissHelper = true;
                }
            }
            if (decodesRealResult && returnedRealResultBeforeColdMiss && callsColdMissHelper) {
                return;
            }
        }
        throw new AssertionError(
            "missing island dispatch helper with hot real-result returns and cold miss helper call"
        );
    }

    private static boolean isCffDispatchHelperDesc(String desc) {
        return CFF_SHARED_GROUP_DISPATCH_DESC.equals(desc)
            || CFF_COMPACT_GROUP_DISPATCH_DESC.equals(desc);
    }

    private static AbstractInsnNode nextOpcodeInsn(AbstractInsnNode insn) {
        while (insn != null && insn.getOpcode() < 0) {
            insn = insn.getNext();
        }
        return insn;
    }

    private static AbstractInsnNode previousOpcodeInsn(AbstractInsnNode insn) {
        while (insn != null && insn.getOpcode() < 0) {
            insn = insn.getPrevious();
        }
        return insn;
    }

    private static Integer pushedInt(AbstractInsnNode insn) {
        if (insn == null) {
            return null;
        }
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return opcode - Opcodes.ICONST_0;
        }
        if (insn instanceof IntInsnNode intInsn
            && (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH)) {
            return intInsn.operand;
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) {
            return value;
        }
        return null;
    }

    private static InvokeDynamicInsnNode stringConcatIndy() {
        return new InvokeDynamicInsnNode(
            "makeConcatWithConstants",
            "()Ljava/lang/String;",
            new Handle(
                Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/StringConcatFactory",
                "makeConcatWithConstants",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;" +
                    "Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)" +
                    "Ljava/lang/invoke/CallSite;",
                false
            ),
            "prefix\u0001suffix"
        );
    }

    private static Path recreateWork(Path work)
        throws Exception {
        if (Files.exists(work)) {
            try (var stream = Files.walk(work)) {
                for (Path path : stream.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
        return Files.createDirectories(work);
    }

    private static void writeJar(Path jar, Path classes, String mainClass)
        throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", mainClass);
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest);
             var stream = Files.walk(classes)) {
            for (Path path : stream.filter(Files::isRegularFile).toList()) {
                String name = classes.relativize(path).toString().replace('\\', '/');
                out.putNextEntry(new JarEntry(name));
                Files.copy(path, out);
                out.closeEntry();
            }
        }
    }

    private static String runJar(Path jar)
        throws Exception {
        return run(
            List.of("java", "-XX:-UsePerfData", "-jar", jar.toString()),
            Duration.ofSeconds(30)
        );
    }

    private static String run(List<String> command, Duration timeout)
        throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean exited = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(exited, "command timed out: " + command);
        assertEquals(0, process.exitValue(), "command failed: " + command + "\n" + output);
        return output;
    }

    private static String cyclicJitBudgetSourceText() {
        return """
            public class CffBudgetedDirectInlineShape {
                public static void main(String[] args) {
                    int out = hot(41);
                    System.out.println("CFF BUDGETED DIRECT INLINE OK " + out);
                    if (out == 0x12345678) {
                        throw new AssertionError(out);
                    }
                }

                static int hot(int seed) {
                    int v = seed;
                    int a = 3;
                    int b = 5;
                    int c = 7;
                    int d = 11;
                    for (int i = 0; i < 96; i++) {
                        v = (v * 1103515245 + 12345) ^ i;
                        if ((v & 1) == 0) {
                            a += v ^ i;
                        } else {
                            b ^= v + i;
                        }
                        if ((v & 2) == 0) {
                            c += a ^ b;
                        } else {
                            d ^= c + i;
                        }
                        if ((v & 4) == 0) {
                            b += d ^ (v >>> 3);
                        } else {
                            c ^= b + (v << 1);
                        }
                        if ((v & 8) == 0) {
                            d += a ^ (c >>> 1);
                        } else {
                            a ^= d + (b << 2);
                        }
                        v ^= a + b + c + d;
                    }
                    return v ^ a ^ b ^ c ^ d;
                }
            }
            """;
    }
}
