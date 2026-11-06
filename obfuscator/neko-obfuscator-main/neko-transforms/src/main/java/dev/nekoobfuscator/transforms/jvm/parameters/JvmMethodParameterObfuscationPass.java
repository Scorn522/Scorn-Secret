package dev.nekoobfuscator.transforms.jvm.parameters;

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
import dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningPass;
import dev.nekoobfuscator.transforms.jvm.internal.JvmBridgeAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmEnumAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmMethodParametersAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;
import dev.nekoobfuscator.transforms.jvm.internal.JvmRecordAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmSerializationAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmServiceAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmVarargsMetadata;
import dev.nekoobfuscator.transforms.jvm.key.JvmKeyDispatchPass;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Replaces eligible method parameter lists with a single Object[] carrier.
 */
public final class JvmMethodParameterObfuscationPass implements TransformPass {
    public static final String ID = "methodParameterObfuscation";
    private static final String PREPARED = "methodParameterObfuscation.prepared";
    private static final String PLAN_BY_OLD_KEY = "methodParameterObfuscation.planByOldKey";
    private static final String PLAN_BY_FINAL_KEY = "methodParameterObfuscation.planByFinalKey";
    private static final String PLAN_BY_OWNER_NAME_DESC = "methodParameterObfuscation.planByOwnerNameDesc";
    private static final String INDY_HANDLE_TARGETS = "methodParameterObfuscation.indyHandleTargets";
    private static final String INDY_SAM_TARGETS = "methodParameterObfuscation.indySamTargets";
    private static final String METHOD_HANDLE_LOOKUP_TARGETS = "methodParameterObfuscation.methodHandleLookupTargets";
    private static final String REFLECTIVE_METHOD_LOOKUP_TARGETS =
        "methodParameterObfuscation.reflectiveMethodLookupTargets";
    private static final String REFLECTIVE_CONSTRUCTOR_LOOKUP_TARGETS =
        "methodParameterObfuscation.reflectiveConstructorLookupTargets";
    public static final String CFF_KEY_LOAD_TARGET_SEED = "controlFlowFlattening.generatedKeyLoadTargetSeed";
    public static final String CFF_PACKED_CALL_TARGET_SEED = "controlFlowFlattening.packedCallTargetSeed";
    public static final String CFF_PACKED_VIRTUAL_ENTRY_KEYS = "controlFlowFlattening.packedVirtualEntryKeys";
    public static final String CFF_DATA_DIGEST_EXCLUDED_ARGUMENT_LOCALS =
        "controlFlowFlattening.dataDigestExcludedArgumentLocals";
    public static final String CARRIER_INDEX_PLAN_BY_FINAL_KEY = "methodParameterObfuscation.carrierIndexPlanByFinalKey";
    public static final String CARRIER_INDEX_DECODE_SITES = "methodParameterObfuscation.carrierIndexDecodeSites";
    private static final String CARRIER_ATTESTATION_SITE_SEEDS = "methodParameterObfuscation.carrierAttestationSiteSeeds";
    private static final String ESCAPED_REFLECTIVE_PARAMETER_CANDIDATES =
        "methodParameterObfuscation.escapedReflectiveParameterCandidates";
    private static final String LAMBDA_REFLECTIVE_CAPTURE_CANDIDATES =
        "methodParameterObfuscation.lambdaReflectiveCaptureCandidates";
    private static final String DYNAMIC_PROXY_HANDLER_TARGETS =
        "methodParameterObfuscation.dynamicProxyHandlerTargets";
    private static final String RUNTIME_CARRIER_TABLE_HELPERS =
        "methodParameterObfuscation.runtimeCarrierTableHelpers";
    private static final String RUNTIME_CARRIER_TABLE_HELPER_DESC =
        "(Ljava/lang/Object;Ljava/lang/Object;I)[Ljava/lang/Object;";
    private static final String CARRIER_INDEX_MARKER_OWNER = "dev/nekoobfuscator/runtime/CarrierIndex";
    private static final String CARRIER_INDEX_MARKER_NAME = "__neko_carrier_index";
    private static final String CARRIER_INDEX_MARKER_DESC = "()I";
    private static final Type OBJECT_ARRAY_TYPE = Type.getType(Object[].class);
    private static final int CARRIER_INDEX_CLASS_WORDS = 64;
    private static final int CARRIER_INDEX_DOMAIN = 0x4F424649;
    private static final long CARRIER_ATTEST_DOMAIN = 0x415454455354314CL;
    private static final long CARRIER_ATTEST_SITE_DOMAIN = 0x53495445314CL;
    private static final long CARRIER_ATTEST_TAG_DOMAIN = 0x54414731314CL;
    private static final int SOURCE_ANALYSIS_MIN_MAX_STACK = 64;
    private static final int SOURCE_ANALYSIS_MAX_MAX_STACK = 4096;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "JVM Method Parameter Obfuscation";
    }

    @Override
    public TransformPhase phase() {
        return TransformPhase.PRE_TRANSFORM;
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
        for (L1Class clazz : classes) {
            for (L1Method method : clazz.methods()) {
                MethodNode mn = method.asmNode();
                if (mn == null || mn.instructions == null) continue;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (isCarrierIndexMarker(insn)) {
                        throw new IllegalStateException(
                            "Unreplaced carrier index decode marker in " +
                                clazz.name() + "." + mn.name + mn.desc
                        );
                    }
                }
            }
        }
    }

    @Override
    public void transformClass(TransformContext ctx) {
        if (!(ctx instanceof PipelineContext pctx)) return;
        if (Boolean.TRUE.equals(ctx.getPassData(PREPARED))) return;
        prepare(pctx);
        ctx.putPassData(PREPARED, Boolean.TRUE);
    }

    @Override
    public void transformMethod(TransformContext ctx) {
        if (!(ctx instanceof PipelineContext pctx)) return;
        L1Class clazz = pctx.currentL1Class();
        L1Method method = pctx.currentL1Method();
        if (clazz == null || method == null || !method.hasCode()) return;

        MethodNode mn = method.asmNode();
        MethodPlan plan = planByFinalKey(pctx).get(JvmKeyDispatchPass.coverageKey(clazz, method));
        boolean proxyHandlerChanged = installDynamicProxyHandlerArgumentView(
            pctx,
            mn,
            dynamicProxyHandlerTargets(pctx).get(key(clazz.name(), mn.name, mn.desc))
        );
        if (plan == null) {
            boolean callsitesChanged = rewriteCallsites(pctx, clazz, mn, callerKeyLocal(pctx, clazz, mn));
            if (proxyHandlerChanged || callsitesChanged) {
                mn.maxStack = Math.max(mn.maxStack, 32);
                clazz.markDirty();
                pctx.invalidate(method);
                JvmObfuscationCoverage.get(ctx).safe(
                    id(),
                    clazz.name(),
                    method.name(),
                    method.descriptor(),
                    "callsite-parameter-carriers"
                );
            }
            return;
        }

        installUnpackPrologue(pctx, mn, plan);
        rewriteStaticVoidTailSelfRecursion(pctx, mn, plan);
        rewriteCallsites(pctx, clazz, mn, callerKeyLocal(pctx, clazz, mn));
        cleanupParameterMetadata(mn);
        mn.maxStack = Math.max(mn.maxStack, 32);
        clazz.markDirty();
        pctx.invalidate(method);
        JvmObfuscationCoverage.get(ctx).full(
            id(),
            clazz.name(),
            method.name(),
            method.descriptor(),
            "object-array-parameters-" + plan.argumentTypes().length
        );
    }

    @SuppressWarnings("unchecked")
    private static Map<String, MethodPlan> planByOldKey(TransformContext ctx) {
        Map<String, MethodPlan> map = ctx.getPassData(PLAN_BY_OLD_KEY);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(PLAN_BY_OLD_KEY, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, MethodPlan> planByFinalKey(TransformContext ctx) {
        Map<String, MethodPlan> map = ctx.getPassData(PLAN_BY_FINAL_KEY);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(PLAN_BY_FINAL_KEY, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, MethodPlan> planByOwnerNameDesc(TransformContext ctx) {
        Map<String, MethodPlan> map = ctx.getPassData(PLAN_BY_OWNER_NAME_DESC);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(PLAN_BY_OWNER_NAME_DESC, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, List<MethodPlan>> escapedReflectiveParameterCandidates(TransformContext ctx) {
        Map<String, List<MethodPlan>> map = ctx.getPassData(ESCAPED_REFLECTIVE_PARAMETER_CANDIDATES);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(ESCAPED_REFLECTIVE_PARAMETER_CANDIDATES, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, List<MethodPlan>> lambdaReflectiveCaptureCandidates(TransformContext ctx) {
        Map<String, List<MethodPlan>> map = ctx.getPassData(LAMBDA_REFLECTIVE_CAPTURE_CANDIDATES);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(LAMBDA_REFLECTIVE_CAPTURE_CANDIDATES, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, List<DynamicProxyHandlerTarget>> dynamicProxyHandlerTargets(TransformContext ctx) {
        Map<String, List<DynamicProxyHandlerTarget>> map = ctx.getPassData(DYNAMIC_PROXY_HANDLER_TARGETS);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(DYNAMIC_PROXY_HANDLER_TARGETS, map);
        }
        return map;
    }

    private void prepare(PipelineContext pctx) {
        Map<String, MethodPlan> oldPlans = planByOldKey(pctx);
        Map<String, MethodPlan> finalPlans = planByFinalKey(pctx);
        Map<String, MethodPlan> directPlans = planByOwnerNameDesc(pctx);
        Set<String> indyHandleTargets = indyHandleTargets(pctx);
        Set<String> indySamTargets = indySamTargets(pctx);
        Set<String> reflectiveLookupTargets = reflectiveLookupTargets(pctx);
        Map<String, Type[]> constructorSuffixTypes = constructorPackedSuffixTypes(pctx);
        List<MethodPlan> plans = new ArrayList<>();
        for (L1Class clazz : pctx.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                if (!isEligible(pctx, clazz, method)) continue;
                if (indyHandleTargets.contains(key(clazz.name(), method.name(), method.descriptor()))) continue;
                if (indySamTargets.contains(key(clazz.name(), method.name(), method.descriptor()))) continue;
                MethodNode mn = method.asmNode();
                String oldName = mn.name;
                String oldDesc = mn.desc;
                Integer keyLocal = findRecordedKeyLocal(pctx, clazz.name(), oldName, oldDesc);
                boolean constructor = method.isConstructor();
                if (constructor && keyLocal == null) {
                    throw new IllegalStateException(
                        "Constructor methodParameterObfuscation requires keyDispatch local for " +
                            clazz.name() + "." + oldName + oldDesc
                    );
                }
                Type[] suffixTypes = constructor
                    ? constructorSuffixTypes.getOrDefault(key(clazz.name(), oldName, oldDesc), new Type[0])
                    : new Type[0];
                boolean splitHiddenKey = constructor || canUseSplitHiddenKeyAbi(clazz, mn);
                boolean syntheticHiddenKey = constructor || (splitHiddenKey && keyLocal == null);
                Type[] visibleArgumentTypes = Type.getArgumentTypes(oldDesc);
                int[] visibleArgumentLocals = argumentLocals(mn.access, oldDesc);
                Type[] argumentTypes = syntheticHiddenKey
                    ? appendHiddenKeyArgument(visibleArgumentTypes)
                    : visibleArgumentTypes;
                int[] argumentLocals = syntheticHiddenKey
                    ? appendHiddenKeyLocal(visibleArgumentLocals, keyLocal == null ? -1 : keyLocal)
                    : visibleArgumentLocals;
                String oldKey = key(clazz.name(), oldName, oldDesc);
                boolean reflectionKeyed = JvmKeyDispatchPass.isReflectiveKeyedEntry(pctx, oldKey);
                boolean reflectionLookupTarget = reflectiveLookupTargets.contains(oldKey)
                    || reflectiveLookupTargets.contains(clazz.name() + "." + oldName)
                    || reflectiveLookupTargets.contains("*." + oldName)
                    || reflectiveLookupTargets.contains(clazz.name() + ".*");
                String packedDesc = packedDescriptor(oldDesc, splitHiddenKey, suffixTypes);
                MethodPlan plan = new MethodPlan(
                    clazz.name(),
                    oldName,
                    oldDesc,
                    oldName,
                    packedDesc,
                    argumentTypes,
                    argumentLocals,
                    keyLocal,
                    splitHiddenKey,
                    syntheticHiddenKey,
                    suffixTypes,
                    method.hasCode()
                );
                plans.add(plan);
            }
        }

        Map<String, List<MethodPlan>> collisionGroups = new HashMap<>();
        for (MethodPlan plan : plans) {
            collisionGroups.computeIfAbsent(
                plan.owner() + "." + plan.oldName() + plan.packedDesc(),
                ignored -> new ArrayList<>()
            ).add(plan);
        }
        for (List<MethodPlan> group : collisionGroups.values()) {
            if (group.size() <= 1) continue;
            for (MethodPlan plan : group) {
                if ("<init>".equals(plan.oldName())) {
                    throw new IllegalStateException(
                        "Constructor packed descriptor collision remained after ABI suffix assignment for " +
                            plan.owner() + "." + plan.oldName() + plan.oldDesc()
                    );
                }
                plan.finalName(plan.oldName() + "$nkop$" + Integer.toHexString(plan.oldDesc().hashCode()));
            }
        }

        plans.sort(Comparator.comparing(MethodPlan::owner).thenComparing(MethodPlan::oldName).thenComparing(MethodPlan::oldDesc));
        Map<String, CarrierIndexPlan> carrierPlansByFamily = new HashMap<>();
        Map<String, String> carrierAnchorOwners = carrierIndexAnchorOwners(pctx, plans);
        String fallbackCarrierAnchorOwner = carrierIndexFallbackAnchorOwner(pctx);
        for (MethodPlan plan : plans) {
            L1Class clazz = pctx.classMap().get(plan.owner());
            if (clazz == null) continue;
            MethodNode mn = findMethodNode(clazz, plan.oldName(), plan.oldDesc());
            if (mn == null) continue;
            String oldKey = key(plan.owner(), plan.oldName(), plan.oldDesc());
            L1Method seedMethod = plan.hasCode() ? null : findAsmMethod(clazz, plan.oldName(), plan.oldDesc());
            Long abstractSeed = seedMethod == null
                ? null
                : JvmKeyDispatchPass.methodSeed(pctx, clazz, seedMethod, mn);
            String finalKey = key(plan.owner(), plan.finalName(), plan.packedDesc());
            oldPlans.put(oldKey, plan);
            finalPlans.put(finalKey, plan);
            directPlans.put(oldKey, plan);
            migrateKeyDispatchMetadata(pctx, oldKey, finalKey);
            if (abstractSeed != null) {
                JvmKeyDispatchPass.recordMethodSeed(pctx, finalKey, abstractSeed);
            }
            long targetSeed = requireMethodSeed(pctx, plan, finalKey);
            String carrierFamily = carrierIndexFamily(pctx, plan, mn.access, finalKey);
            long carrierSeed = ((mn.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) == 0)
                ? JvmPassBytecode.mix(pctx.masterSeed() ^ CARRIER_INDEX_DOMAIN, carrierFamily.hashCode())
                : targetSeed;
            CarrierIndexPlan carrierIndexPlan = carrierPlansByFamily.computeIfAbsent(
                carrierFamily,
                ignored -> createCarrierIndexPlan(
                    plan,
                    carrierSeed,
                    carrierFamily,
                    carrierAnchorOwners.getOrDefault(
                        carrierFamily,
                        fallbackCarrierAnchorOwner == null ? plan.owner() : fallbackCarrierAnchorOwner
                    )
                )
            );
            plan.carrierIndexPlan(carrierIndexPlan);
            plan.carrierIndexKeySeed(carrierIndexKeySeed(carrierIndexPlan));
            carrierIndexPlans(pctx).put(finalKey, carrierIndexPlan);
            if (isPackedVirtualEntry(mn, plan)) {
                cffPackedVirtualEntryKeys(pctx).add(finalKey);
            }
            recordCffDataDigestExcludedArgumentLocals(pctx, plan, mn.access);
        }
        assertVirtualCarrierFamilySeeds(pctx, plans);
        collectEscapedReflectiveParameterCandidates(pctx);
        collectDynamicProxyHandlerTargets(pctx);
        collectCarrierAttestationSites(pctx);
        for (MethodPlan plan : plans) {
            L1Class clazz = pctx.classMap().get(plan.owner());
            if (clazz == null) continue;
            MethodNode mn = findMethodNode(clazz, plan.oldName(), plan.oldDesc());
            if (mn == null) continue;
            mn.name = plan.finalName();
            mn.desc = plan.packedDesc();
            JvmVarargsMetadata.normalizeAfterDescriptorRewrite(mn);
            cleanupParameterMetadata(mn);
            clazz.markDirty();
        }
        collectCarrierAttestationSites(pctx);
        seedEmptyCarrierAttestationSites(pctx);
    }

    private void collectCarrierAttestationSites(PipelineContext pctx) {
        for (L1Class clazz : pctx.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                if (!method.hasCode()) continue;
                MethodNode mn = method.asmNode();
                if (mn == null || mn.instructions == null) continue;
                for (AbstractInsnNode insn : mn.instructions.toArray()) {
                    if (!(insn instanceof MethodInsnNode call)) continue;
                    if ("java/lang/invoke/MethodHandle".equals(call.owner)
                        && ("invoke".equals(call.name) || "invokeExact".equals(call.name))) {
                        MethodHandleRewriteTarget target = sourceMethodHandleRewriteTarget(pctx, mn, call);
                        if (target != null) {
                            recordCarrierAttestationSite(pctx, target.plan(), clazz.name(), mn, call, "MethodHandle target");
                        } else {
                            for (MethodHandleRuntimeCandidate candidate : methodHandleRuntimeInvokeCandidates(pctx, call.desc)) {
                                recordCarrierAttestationSite(
                                    pctx,
                                    candidate.plan(),
                                    clazz.name(),
                                    mn,
                                    call,
                                    "MethodHandle runtime target"
                                );
                            }
                        }
                        continue;
                    }
                    if ("java/lang/reflect/Method".equals(call.owner)
                        && "invoke".equals(call.name)
                        && "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) {
                        MethodPlan plan = resolveReflectiveInvokePlan(pctx, mn, call);
                        if (plan != null) {
                            recordCarrierAttestationSite(pctx, plan, clazz.name(), mn, call, "reflective target");
                        } else {
                            for (MethodPlan candidate : runtimeReflectiveInvokeCandidates(pctx, clazz.name(), mn, call)) {
                                if (packedHiddenKeyArgumentIndex(candidate) >= 0) {
                                    recordCarrierAttestationSite(
                                        pctx,
                                        candidate,
                                        clazz.name(),
                                        mn,
                                        call,
                                        "reflective runtime target"
                                    );
                                }
                            }
                        }
                        continue;
                    }
                    if ("java/lang/reflect/Constructor".equals(call.owner)
                        && "newInstance".equals(call.name)
                        && "([Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) {
                        MethodPlan plan = resolveReflectiveConstructorInvokePlan(pctx, mn, call);
                        if (plan != null) {
                            recordCarrierAttestationSite(pctx, plan, clazz.name(), mn, call, "reflective constructor target");
                        } else {
                            for (MethodPlan candidate : runtimeReflectiveConstructorInvokeCandidates(pctx, clazz.name(), mn, call)) {
                                if (packedHiddenKeyArgumentIndex(candidate) >= 0) {
                                    recordCarrierAttestationSite(
                                        pctx,
                                        candidate,
                                        clazz.name(),
                                        mn,
                                        call,
                                        "reflective constructor runtime target"
                                    );
                                }
                            }
                        }
                        continue;
                    }
                    if ("java/lang/Class".equals(call.owner)
                        && "newInstance".equals(call.name)
                        && "()Ljava/lang/Object;".equals(call.desc)) {
                        for (MethodPlan candidate : classNewInstanceConstructorCandidates(pctx, mn, call)) {
                            if (packedHiddenKeyArgumentIndex(candidate) >= 0) {
                                recordCarrierAttestationSite(
                                    pctx,
                                    candidate,
                                    clazz.name(),
                                    mn,
                                    call,
                                    "Class.newInstance constructor target"
                                );
                            }
                        }
                        continue;
                    }
                    MethodPlan plan = resolvePlan(pctx, call.owner, call.name, call.desc);
                    if (plan != null) {
                        recordCarrierAttestationSite(pctx, plan, clazz.name(), mn, call, "direct");
                    }
                }
            }
        }
    }

    private void collectEscapedReflectiveParameterCandidates(PipelineContext pctx) {
        Map<String, List<MethodPlan>> escaped = escapedReflectiveParameterCandidates(pctx);
        Map<String, List<MethodPlan>> lambdaCaptured = lambdaReflectiveCaptureCandidates(pctx);
        for (L1Class clazz : pctx.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                if (!method.hasCode()) continue;
                MethodNode mn = method.asmNode();
                if (mn == null || mn.instructions == null) continue;
                try {
                    Frame<SourceValue>[] frames = analyzeSourceValues(clazz.name(), mn);
                    for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                        if (!(insn instanceof MethodInsnNode call)) continue;
                        List<MethodPlan> callees = escapedReflectiveCalleePlans(pctx, call);
                        if (callees.isEmpty()) continue;
                        int index = mn.instructions.indexOf(call);
                        if (index < 0 || index >= frames.length) continue;
                        Frame<SourceValue> frame = frames[index];
                        if (frame == null) continue;
                        Type[] args = Type.getArgumentTypes(call.desc);
                        if (frame.getStackSize() < args.length) continue;
                        int firstArg = frame.getStackSize() - args.length;
                        for (int i = 0; i < args.length; i++) {
                            if (isReflectiveMethodType(args[i])) {
                                List<MethodPlan> candidates = reflectiveMemberSourceCandidates(
                                    pctx,
                                    mn,
                                    frames,
                                    frame.getStack(firstArg + i),
                                    true,
                                    0
                                );
                                for (MethodPlan callee : callees) {
                                    recordEscapedReflectiveParameterCandidates(
                                        escaped,
                                        true,
                                        key(callee.owner(), callee.oldName(), callee.oldDesc()),
                                        i,
                                        candidates
                                    );
                                }
                            } else if (isReflectiveConstructorType(args[i])) {
                                List<MethodPlan> candidates = reflectiveMemberSourceCandidates(
                                    pctx,
                                    mn,
                                    frames,
                                    frame.getStack(firstArg + i),
                                    false,
                                    0
                                );
                                for (MethodPlan callee : callees) {
                                    recordEscapedReflectiveParameterCandidates(
                                        escaped,
                                        false,
                                        key(callee.owner(), callee.oldName(), callee.oldDesc()),
                                        i,
                                        candidates
                                    );
                                }
                            }
                        }
                    }
                } catch (AnalyzerException | RuntimeException ignored) {
                    // Missing provenance only leaves this escaped reflective path unclaimed.
                }
            }
        }
        for (L1Class clazz : pctx.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                if (!method.hasCode()) continue;
                MethodNode mn = method.asmNode();
                if (mn == null || mn.instructions == null) continue;
                try {
                    Frame<SourceValue>[] frames = analyzeSourceValues(clazz.name(), mn);
                    for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                        if (insn instanceof InvokeDynamicInsnNode indy) {
                            collectLambdaCapturedReflectiveParameterCandidates(
                                pctx,
                                lambdaCaptured,
                                clazz.name(),
                                mn,
                                frames,
                                indy
                            );
                        }
                    }
                } catch (AnalyzerException | RuntimeException ignored) {
                    // Missing provenance only leaves this lambda capture path unclaimed.
                }
            }
        }
    }

    private void collectLambdaCapturedReflectiveParameterCandidates(
        PipelineContext pctx,
        Map<String, List<MethodPlan>> lambdaCaptured,
        String currentOwner,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        InvokeDynamicInsnNode indy
    ) {
        Handle implementation = lambdaImplementationHandle(indy);
        if (implementation == null || implementation.getTag() != Opcodes.H_INVOKESTATIC) return;
        if (!pctx.classMap().containsKey(implementation.getOwner())) return;
        Type[] capturedTypes = Type.getArgumentTypes(indy.desc);
        Type[] implementationTypes = Type.getArgumentTypes(implementation.getDesc());
        int capturedCount = Math.min(capturedTypes.length, implementationTypes.length);
        if (capturedCount == 0) return;
        int index = mn.instructions.indexOf(indy);
        if (index < 0 || index >= frames.length) return;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() < capturedTypes.length) return;
        int firstArg = frame.getStackSize() - capturedTypes.length;
        int[] implementationLocals = argumentLocals(Opcodes.ACC_STATIC, implementation.getDesc());
        String implementationKey = key(implementation.getOwner(), implementation.getName(), implementation.getDesc());
        for (int i = 0; i < capturedCount; i++) {
            if (isReflectiveMethodType(capturedTypes[i]) && isReflectiveMethodType(implementationTypes[i])) {
                List<MethodPlan> candidates = reflectiveCaptureSourceCandidates(
                    pctx,
                    currentOwner,
                    mn,
                    frames,
                    frame.getStack(firstArg + i),
                    true
                );
                recordLambdaReflectiveCaptureCandidates(
                    lambdaCaptured,
                    true,
                    implementationKey,
                    implementationLocals[i],
                    candidates
                );
            } else if (isReflectiveConstructorType(capturedTypes[i]) && isReflectiveConstructorType(implementationTypes[i])) {
                List<MethodPlan> candidates = reflectiveCaptureSourceCandidates(
                    pctx,
                    currentOwner,
                    mn,
                    frames,
                    frame.getStack(firstArg + i),
                    false
                );
                recordLambdaReflectiveCaptureCandidates(
                    lambdaCaptured,
                    false,
                    implementationKey,
                    implementationLocals[i],
                    candidates
                );
            }
        }
    }

    private void collectDynamicProxyHandlerTargets(PipelineContext pctx) {
        Map<String, List<DynamicProxyHandlerTarget>> targets = dynamicProxyHandlerTargets(pctx);
        for (L1Class clazz : pctx.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                if (!method.hasCode()) continue;
                MethodNode mn = method.asmNode();
                if (mn == null || mn.instructions == null) continue;
                try {
                    Frame<SourceValue>[] frames = analyzeSourceValues(clazz.name(), mn);
                    for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                        if (!(insn instanceof MethodInsnNode call) || !isProxyNewProxyInstance(call)) continue;
                        int index = mn.instructions.indexOf(call);
                        if (index < 0 || index >= frames.length) continue;
                        Frame<SourceValue> frame = frames[index];
                        if (frame == null || frame.getStackSize() < 3) continue;
                        int base = frame.getStackSize() - 3;
                        Set<String> interfaces = sourceProxyInterfaceOwners(
                            pctx,
                            mn,
                            frames,
                            call,
                            frame.getStack(base + 1)
                        );
                        if (interfaces.isEmpty()) {
                            interfaces = nearbyProxyInterfaceOwners(pctx, mn, call);
                        }
                        if (interfaces.isEmpty()) continue;
                        List<MethodPlan> plans = dynamicProxyInterfacePlans(pctx, interfaces);
                        if (plans.isEmpty()) continue;
                        InvokeDynamicInsnNode indy = sourceInvocationHandlerLambda(
                            mn,
                            frames,
                            frame.getStack(base + 2),
                            0
                        );
                        if (indy == null) {
                            indy = nearbyInvocationHandlerLambda(mn, call);
                        }
                        if (indy == null) continue;
                        Handle implementation = lambdaImplementationHandle(indy);
                        if (implementation == null || implementation.getTag() != Opcodes.H_INVOKESTATIC) continue;
                        if (!pctx.classMap().containsKey(implementation.getOwner())) continue;
                        InvocationHandlerSamLocals locals = invocationHandlerSamLocals(indy, implementation);
                        if (locals == null) continue;
                        recordDynamicProxyHandlerTarget(
                            targets,
                            implementation,
                            locals.methodLocal(),
                            locals.argsLocal(),
                            plans
                        );
                    }
                } catch (AnalyzerException | RuntimeException ignored) {
                    // Missing provenance only leaves this dynamic-proxy handler path unclaimed.
                }
            }
        }
    }

    private static boolean isProxyNewProxyInstance(MethodInsnNode call) {
        return call.getOpcode() == Opcodes.INVOKESTATIC
            && "java/lang/reflect/Proxy".equals(call.owner)
            && "newProxyInstance".equals(call.name)
            && "(Ljava/lang/ClassLoader;[Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;"
                .equals(call.desc);
    }

    private Set<String> sourceProxyInterfaceOwners(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode call,
        SourceValue value
    ) {
        Type[] interfaceTypes = sourceClassArrayParameterTypes(pctx, mn, frames, call, value);
        if (interfaceTypes == null || interfaceTypes.length == 0) return Set.of();
        Set<String> owners = new LinkedHashSet<>();
        for (Type type : interfaceTypes) {
            if (type.getSort() == Type.OBJECT) {
                addDynamicProxyInterfaceOwner(pctx, owners, type.getInternalName());
            }
        }
        return owners;
    }

    private Set<String> nearbyProxyInterfaceOwners(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        Set<String> owners = new LinkedHashSet<>();
        int scanned = 0;
        for (AbstractInsnNode scan = call.getPrevious(); scan != null && scanned++ < 64; scan = scan.getPrevious()) {
            if (scan instanceof LdcInsnNode ldc
                && ldc.cst instanceof Type type
                && type.getSort() == Type.OBJECT) {
                addDynamicProxyInterfaceOwner(pctx, owners, type.getInternalName());
            }
            if (scan instanceof MethodInsnNode previous
                && "java/lang/reflect/Proxy".equals(previous.owner)
                && "newProxyInstance".equals(previous.name)) {
                break;
            }
            if (mn.instructions.indexOf(scan) == 0) break;
        }
        return owners;
    }

    private void addDynamicProxyInterfaceOwner(PipelineContext pctx, Set<String> owners, String owner) {
        if (owner == null) return;
        L1Class clazz = pctx.classMap().get(owner);
        if (clazz == null || !clazz.isInterface()) return;
        if (!owners.add(owner)) return;
        for (String parent : clazz.interfaces()) {
            addDynamicProxyInterfaceOwner(pctx, owners, parent);
        }
    }

    private List<MethodPlan> dynamicProxyInterfacePlans(PipelineContext pctx, Set<String> owners) {
        List<MethodPlan> plans = new ArrayList<>();
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if (!owners.contains(plan.owner())) continue;
            if ("<init>".equals(plan.oldName()) || "<clinit>".equals(plan.oldName())) continue;
            addUniquePlan(plans, plan);
        }
        return plans;
    }

    private InvokeDynamicInsnNode sourceInvocationHandlerLambda(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 8) return null;
        InvokeDynamicInsnNode result = null;
        for (AbstractInsnNode source : value.insns) {
            InvokeDynamicInsnNode sourced = null;
            if (source instanceof InvokeDynamicInsnNode indy && isInvocationHandlerLambda(indy)) {
                sourced = indy;
            } else if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceInvocationHandlerLambda(mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            } else if (source instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceInvocationHandlerLambda(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            }
            if (sourced == null) return null;
            if (result != null && result != sourced) return null;
            result = sourced;
        }
        return result;
    }

    private InvokeDynamicInsnNode nearbyInvocationHandlerLambda(MethodNode mn, MethodInsnNode call) {
        int scanned = 0;
        for (AbstractInsnNode scan = call.getPrevious(); scan != null && scanned++ < 32; scan = scan.getPrevious()) {
            if (scan instanceof InvokeDynamicInsnNode indy && isInvocationHandlerLambda(indy)) {
                return indy;
            }
            if (scan instanceof MethodInsnNode) break;
            if (mn.instructions.indexOf(scan) == 0) break;
        }
        return null;
    }

    private static boolean isInvocationHandlerLambda(InvokeDynamicInsnNode indy) {
        if (!isLambdaMetafactory(indy) || indy.bsmArgs.length == 0 || !(indy.bsmArgs[0] instanceof Type samType)) {
            return false;
        }
        Type returnType = Type.getReturnType(indy.desc);
        Type[] samArgs = Type.getArgumentTypes(samType.getDescriptor());
        return returnType.getSort() == Type.OBJECT
            && "java/lang/reflect/InvocationHandler".equals(returnType.getInternalName())
            && samArgs.length == 3
            && "Ljava/lang/Object;".equals(samArgs[0].getDescriptor())
            && "Ljava/lang/reflect/Method;".equals(samArgs[1].getDescriptor())
            && OBJECT_ARRAY_TYPE.equals(samArgs[2]);
    }

    private InvocationHandlerSamLocals invocationHandlerSamLocals(InvokeDynamicInsnNode indy, Handle implementation) {
        if (!(indy.bsmArgs[0] instanceof Type samType)) return null;
        Type[] samArgs = Type.getArgumentTypes(samType.getDescriptor());
        Type[] implementationArgs = Type.getArgumentTypes(implementation.getDesc());
        int samStart = implementationArgs.length - samArgs.length;
        if (samStart < 0) return null;
        if (!"Ljava/lang/reflect/Method;".equals(implementationArgs[samStart + 1].getDescriptor())) return null;
        if (!OBJECT_ARRAY_TYPE.equals(implementationArgs[samStart + 2])) return null;
        int[] locals = argumentLocals(Opcodes.ACC_STATIC, implementation.getDesc());
        return new InvocationHandlerSamLocals(locals[samStart + 1], locals[samStart + 2]);
    }

    private void recordDynamicProxyHandlerTarget(
        Map<String, List<DynamicProxyHandlerTarget>> targets,
        Handle implementation,
        int methodLocal,
        int argsLocal,
        List<MethodPlan> plans
    ) {
        String implementationKey = key(implementation.getOwner(), implementation.getName(), implementation.getDesc());
        List<DynamicProxyHandlerTarget> recorded = targets.computeIfAbsent(implementationKey, ignored -> new ArrayList<>());
        for (DynamicProxyHandlerTarget existing : recorded) {
            if (existing.methodLocal() == methodLocal && existing.argsLocal() == argsLocal) {
                for (MethodPlan plan : plans) {
                    addUniquePlan(existing.plans(), plan);
                }
                return;
            }
        }
        List<MethodPlan> copy = new ArrayList<>();
        for (MethodPlan plan : plans) {
            addUniquePlan(copy, plan);
        }
        recorded.add(new DynamicProxyHandlerTarget(methodLocal, argsLocal, copy));
    }

    private List<MethodPlan> escapedReflectiveCalleePlans(PipelineContext pctx, MethodInsnNode call) {
        MethodPlan exact = planByOldKey(pctx).get(key(call.owner, call.name, call.desc));
        if (call.getOpcode() != Opcodes.INVOKEVIRTUAL && call.getOpcode() != Opcodes.INVOKEINTERFACE) {
            return exact == null ? List.of() : List.of(exact);
        }
        List<MethodPlan> plans = new ArrayList<>();
        if (exact != null) {
            addUniquePlan(plans, exact);
        }
        for (MethodPlan plan : planByOldKey(pctx).values()) {
            if (!plan.oldName().equals(call.name) || !plan.oldDesc().equals(call.desc)) continue;
            if (!isSubtypeOf(pctx, pctx.classMap().get(plan.owner()), call.owner)) continue;
            addUniquePlan(plans, plan);
        }
        return plans;
    }

    private void recordEscapedReflectiveParameterCandidates(
        Map<String, List<MethodPlan>> escaped,
        boolean methodMember,
        String calleeKey,
        int argumentIndex,
        List<MethodPlan> candidates
    ) {
        if (candidates.isEmpty()) return;
        List<MethodPlan> plans = escaped.computeIfAbsent(
            escapedReflectiveParameterKey(methodMember, calleeKey, argumentIndex),
            ignored -> new ArrayList<>()
        );
        for (MethodPlan candidate : candidates) {
            addUniquePlan(plans, candidate);
        }
    }

    private List<MethodPlan> reflectiveCaptureSourceCandidates(
        PipelineContext pctx,
        String currentOwner,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        boolean methodMember
    ) {
        List<MethodPlan> direct = reflectiveMemberSourceCandidates(pctx, mn, frames, value, methodMember, 0);
        if (!direct.isEmpty()) return direct;
        MethodPlan currentPlan = planByOldKey(pctx).get(key(currentOwner, mn.name, mn.desc));
        if (currentPlan == null) return List.of();
        String methodKey = key(currentPlan.owner(), currentPlan.oldName(), currentPlan.oldDesc());
        List<Integer> locals = new ArrayList<>();
        collectSourceLoadLocals(mn, frames, value, locals, 0);
        if (locals.isEmpty()) return List.of();
        List<MethodPlan> candidates = new ArrayList<>();
        for (int local : locals) {
            int argumentIndex = argumentIndexForLocal(currentPlan, local);
            if (argumentIndex < 0) continue;
            List<MethodPlan> recorded = escapedReflectiveParameterCandidates(pctx).get(
                escapedReflectiveParameterKey(methodMember, methodKey, argumentIndex)
            );
            if (recorded == null) continue;
            for (MethodPlan candidate : recorded) {
                addUniquePlan(candidates, candidate);
            }
        }
        return candidates;
    }

    private void recordLambdaReflectiveCaptureCandidates(
        Map<String, List<MethodPlan>> lambdaCaptured,
        boolean methodMember,
        String methodKey,
        int local,
        List<MethodPlan> candidates
    ) {
        if (candidates.isEmpty()) return;
        List<MethodPlan> plans = lambdaCaptured.computeIfAbsent(
            lambdaReflectiveCaptureKey(methodMember, methodKey, local),
            ignored -> new ArrayList<>()
        );
        for (MethodPlan candidate : candidates) {
            addUniquePlan(plans, candidate);
        }
    }

    private List<MethodPlan> reflectiveMemberSourceCandidates(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        boolean methodMember,
        int depth
    ) {
        ReflectiveSourcePlans resolved = reflectiveMemberSourceCandidatesResult(pctx, mn, frames, value, methodMember, depth);
        return resolved.known() ? resolved.plans() : List.of();
    }

    private ReflectiveSourcePlans reflectiveMemberSourceCandidatesResult(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        boolean methodMember,
        int depth
    ) {
        if (value == null || depth > 4 || value.insns.isEmpty()) return ReflectiveSourcePlans.unknown();
        List<MethodPlan> candidates = new ArrayList<>();
        for (AbstractInsnNode insn : value.insns) {
            ReflectiveSourcePlans sourced = ReflectiveSourcePlans.unknown();
            if (insn instanceof MethodInsnNode call) {
                MethodPlan plan = null;
                if (methodMember && isReflectionLookup(call)) {
                    plan = resolveReflectiveLookupPlan(pctx, mn, call);
                } else if (!methodMember && isReflectionConstructorLookup(call)) {
                    plan = resolveReflectiveConstructorLookupPlan(pctx, mn, call);
                } else {
                    return ReflectiveSourcePlans.unknown();
                }
                if (plan != null) {
                    sourced = ReflectiveSourcePlans.known(List.of(plan));
                } else if (methodMember && isReflectionLookup(call)) {
                    List<MethodPlan> runtimeCandidates = new ArrayList<>();
                    for (MethodPlan candidate : runtimeReflectiveLookupCandidates(pctx, mn, call)) {
                        addUniquePlan(runtimeCandidates, candidate);
                    }
                    if (!runtimeCandidates.isEmpty()) {
                        sourced = ReflectiveSourcePlans.known(runtimeCandidates);
                    }
                }
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = reflectiveMemberSourceCandidatesResult(
                    pctx,
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    methodMember,
                    depth + 1
                );
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index < 0 || index >= frames.length) return ReflectiveSourcePlans.unknown();
                Frame<SourceValue> frame = frames[index];
                if (frame == null || frame.getStackSize() == 0) return ReflectiveSourcePlans.unknown();
                sourced = reflectiveMemberSourceCandidatesResult(
                    pctx,
                    mn,
                    frames,
                    frame.getStack(frame.getStackSize() - 1),
                    methodMember,
                    depth + 1
                );
            } else {
                return ReflectiveSourcePlans.unknown();
            }
            if (!sourced.known() || sourced.plans().isEmpty()) {
                return ReflectiveSourcePlans.unknown();
            }
            for (MethodPlan candidate : sourced.plans()) {
                addUniquePlan(candidates, candidate);
            }
        }
        return candidates.isEmpty()
            ? ReflectiveSourcePlans.unknown()
            : ReflectiveSourcePlans.known(candidates);
    }

    private static void addUniquePlan(List<MethodPlan> plans, MethodPlan candidate) {
        String key = finalKey(candidate);
        for (MethodPlan plan : plans) {
            if (finalKey(plan).equals(key)) return;
        }
        plans.add(candidate);
    }

    private static boolean isReflectiveMethodType(Type type) {
        return type.getSort() == Type.OBJECT && "java/lang/reflect/Method".equals(type.getInternalName());
    }

    private static boolean isReflectiveConstructorType(Type type) {
        return type.getSort() == Type.OBJECT && "java/lang/reflect/Constructor".equals(type.getInternalName());
    }

    private static String escapedReflectiveParameterKey(boolean methodMember, String methodKey, int argumentIndex) {
        return (methodMember ? "M:" : "C:") + methodKey + "#" + argumentIndex;
    }

    private static String lambdaReflectiveCaptureKey(boolean methodMember, String methodKey, int local) {
        return (methodMember ? "M:" : "C:") + methodKey + "#L" + local;
    }

    private static Frame<SourceValue>[] analyzeSourceValues(String owner, MethodNode mn) throws AnalyzerException {
        ensureAnalysisMaxStack(mn);
        while (true) {
            try {
                return new Analyzer<>(new SourceInterpreter()).analyze(owner, mn);
            } catch (AnalyzerException ex) {
                if (!raiseAnalysisMaxStackAfter(ex, mn)) throw ex;
            }
        }
    }

    private static Frame<BasicValue>[] analyzeBasicValues(String owner, MethodNode mn) throws AnalyzerException {
        ensureAnalysisMaxStack(mn);
        while (true) {
            try {
                return new Analyzer<>(new BasicInterpreter()).analyze(owner, mn);
            } catch (AnalyzerException ex) {
                if (!raiseAnalysisMaxStackAfter(ex, mn)) throw ex;
            }
        }
    }

    private static void ensureAnalysisMaxStack(MethodNode mn) {
        if (mn.maxStack < SOURCE_ANALYSIS_MIN_MAX_STACK) {
            mn.maxStack = SOURCE_ANALYSIS_MIN_MAX_STACK;
        }
    }

    private static boolean raiseAnalysisMaxStackAfter(AnalyzerException ex, MethodNode mn) {
        String message = ex.getMessage();
        if (message == null || !message.contains("Insufficient maximum stack size")) return false;
        int current = Math.max(mn.maxStack, SOURCE_ANALYSIS_MIN_MAX_STACK);
        if (current >= SOURCE_ANALYSIS_MAX_MAX_STACK) return false;
        mn.maxStack = Math.min(SOURCE_ANALYSIS_MAX_MAX_STACK, Math.max(current + 1, current << 1));
        return true;
    }

    private static String carrierIndexFamily(PipelineContext pctx, MethodPlan plan, int access, String finalKey) {
        if ("<init>".equals(plan.oldName())) {
            return "M:" + finalKey;
        }
        if ((access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0) {
            return "M:" + finalKey;
        }
        L1Class clazz = pctx.classMap().get(plan.owner());
        String rootOwner = clazz == null
            ? plan.owner()
            : JvmKeyDispatchPass.virtualFamilyOwner(pctx, clazz, plan.oldName(), plan.oldDesc());
        return "V:" + rootOwner + "." + plan.oldName() + plan.oldDesc();
    }

    private static Map<String, String> carrierIndexAnchorOwners(PipelineContext pctx, List<MethodPlan> plans) {
        Map<String, String> anchors = new LinkedHashMap<>();
        for (MethodPlan plan : plans) {
            L1Class clazz = pctx.classMap().get(plan.owner());
            if (clazz == null) continue;
            MethodNode mn = findMethodNode(clazz, plan.oldName(), plan.oldDesc());
            if (!isCarrierIndexAnchorCandidate(clazz, mn)) continue;
            String finalKey = key(plan.owner(), plan.finalName(), plan.packedDesc());
            String family = carrierIndexFamily(pctx, plan, mn.access, finalKey);
            anchors.merge(
                family,
                plan.owner(),
                (current, candidate) -> current.compareTo(candidate) <= 0 ? current : candidate
            );
        }
        return anchors;
    }

    private static void assertVirtualCarrierFamilySeeds(PipelineContext pctx, List<MethodPlan> plans) {
        Map<String, Long> seedByFamily = new LinkedHashMap<>();
        Map<String, String> ownerByFamily = new LinkedHashMap<>();
        for (MethodPlan plan : plans) {
            L1Class clazz = pctx.classMap().get(plan.owner());
            if (clazz == null) continue;
            MethodNode mn = findMethodNode(clazz, plan.oldName(), plan.oldDesc());
            if (mn == null) continue;
            if ("<init>".equals(plan.oldName()) || (mn.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0) {
                continue;
            }
            String finalKey = key(plan.owner(), plan.finalName(), plan.packedDesc());
            String family = carrierIndexFamily(pctx, plan, mn.access, finalKey);
            long seed = seedForPlan(pctx, plan);
            Long existing = seedByFamily.putIfAbsent(family, seed);
            if (existing == null) {
                ownerByFamily.put(family, plan.owner() + "." + plan.finalName() + plan.packedDesc());
            } else if (existing.longValue() != seed) {
                throw new IllegalStateException(
                    "Virtual packed carrier family seed mismatch for " + family +
                        " between " + ownerByFamily.get(family) + " and " +
                        plan.owner() + "." + plan.finalName() + plan.packedDesc()
                );
            }
        }
    }

    private static String carrierIndexFallbackAnchorOwner(PipelineContext pctx) {
        String best = null;
        for (L1Class clazz : pctx.classMap().values()) {
            if (TransformGuards.isRuntimeClass(clazz) || clazz.isAnnotation()) continue;
            for (L1Method method : clazz.methods()) {
                if (TransformGuards.isGeneratedMethod(method)) continue;
                MethodNode mn = method.asmNode();
                if (!isCarrierIndexAnchorCandidate(clazz, mn)) continue;
                best = best == null || clazz.name().compareTo(best) < 0 ? clazz.name() : best;
                break;
            }
        }
        return best;
    }

    private static boolean isCarrierIndexAnchorCandidate(L1Class clazz, MethodNode mn) {
        if (mn == null) return false;
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return false;
        if (mn.instructions == null || mn.instructions.size() == 0) return false;
        return true;
    }

    private boolean isEligible(PipelineContext pctx, L1Class clazz, L1Method method) {
        if (pctx.isTransformExcluded(ID, clazz, method)) return false;
        if (TransformGuards.isRuntimeClass(clazz) || TransformGuards.isGeneratedMethod(method)) return false;
        if (clazz.isAnnotation()) return false;
        if (method.isClassInit() || method.isNative()) return false;
        if ("main".equals(method.name()) && "([Ljava/lang/String;)V".equals(method.descriptor()) && method.isStatic()) {
            return false;
        }
        if (JvmServiceAbi.isServiceProviderNoArgConstructor(pctx, clazz, method)) return false;
        if (JvmBridgeAbi.isBridgeFamilyMethod(pctx, clazz, method)) return false;
        if (JvmMethodParametersAbi.isObservedMethodParametersMethod(pctx, clazz, method)) return false;
        if (JvmSerializationAbi.isSerializationMagicMethod(pctx, clazz, method)) return false;
        if (JvmEnumAbi.isEnumAbiMethod(clazz, method)) return false;
        if (JvmRecordAbi.isRecordAbiMethod(clazz, method)) return false;
        if (!method.isConstructor() && overridesExternalMethod(pctx, clazz, method.asmNode(), method.descriptor())) return false;
        return true;
    }

    private static Map<String, Type[]> constructorPackedSuffixTypes(PipelineContext pctx) {
        Map<String, Type[]> suffixes = new HashMap<>();
        for (L1Class clazz : pctx.classMap().values()) {
            if (TransformGuards.isRuntimeClass(clazz) || clazz.isAnnotation()) continue;
            List<L1Method> constructors = new ArrayList<>();
            for (L1Method method : clazz.methods()) {
                if (!method.isConstructor() || method.isNative() || TransformGuards.isGeneratedMethod(method)) continue;
                if (JvmServiceAbi.isServiceProviderNoArgConstructor(pctx, clazz, method)) continue;
                if (JvmMethodParametersAbi.isObservedMethodParametersMethod(pctx, clazz, method)) continue;
                if (JvmEnumAbi.isEnumConstructor(clazz, method)) continue;
                if (JvmRecordAbi.isRecordCanonicalConstructor(clazz, method)) continue;
                constructors.add(method);
            }
            constructors.sort(Comparator.comparing(L1Method::descriptor));
            int width = constructorSuffixWidth(constructors.size());
            for (int i = 0; i < constructors.size(); i++) {
                L1Method method = constructors.get(i);
                suffixes.put(
                    key(clazz.name(), method.name(), method.descriptor()),
                    constructorSuffixTypes(i, width)
                );
            }
        }
        return suffixes;
    }

    private static int constructorSuffixWidth(int constructorCount) {
        int width = 0;
        int capacity = 1;
        while (capacity < constructorCount) {
            width++;
            capacity <<= 1;
        }
        return width;
    }

    private static Type[] constructorSuffixTypes(int ordinal, int width) {
        Type[] suffix = new Type[width];
        for (int i = 0; i < width; i++) {
            suffix[i] = ((ordinal >>> i) & 1) == 0 ? Type.INT_TYPE : Type.LONG_TYPE;
        }
        return suffix;
    }

    private static Type[] appendHiddenKeyArgument(Type[] original) {
        Type[] extended = new Type[original.length + 1];
        System.arraycopy(original, 0, extended, 0, original.length);
        extended[original.length] = Type.LONG_TYPE;
        return extended;
    }

    private static int[] appendHiddenKeyLocal(int[] original, int keyLocal) {
        int[] extended = new int[original.length + 1];
        System.arraycopy(original, 0, extended, 0, original.length);
        extended[original.length] = keyLocal;
        return extended;
    }

    private static L1Method findAsmMethod(L1Class clazz, String name, String desc) {
        L1Method direct = clazz.findMethod(name, desc);
        if (direct != null) return direct;
        for (L1Method method : clazz.methods()) {
            MethodNode mn = method.asmNode();
            if (mn != null && name.equals(mn.name) && desc.equals(mn.desc)) return method;
        }
        return null;
    }

    private static Set<String> indyHandleTargets(PipelineContext pctx) {
        Set<String> targets = pctx.getPassData(INDY_HANDLE_TARGETS);
        if (targets != null) return targets;
        targets = new java.util.LinkedHashSet<>();
        for (L1Class clazz : pctx.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                if (!method.hasCode()) continue;
                for (AbstractInsnNode insn = method.instructions().getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof InvokeDynamicInsnNode indy)) continue;
                    for (Object arg : indy.bsmArgs) {
                        if (arg instanceof Handle handle) {
                            targets.add(key(handle.getOwner(), handle.getName(), handle.getDesc()));
                            if (isLambdaMetafactory(indy) &&
                                pctx.classMap().containsKey(handle.getOwner()) &&
                                isUnboundLambdaMethodReference(indy, handle)) {
                                addVirtualFamilyTargets(pctx, targets, handle.getOwner(), handle.getName(), handle.getDesc());
                            }
                        }
                    }
                }
            }
        }
        pctx.putPassData(INDY_HANDLE_TARGETS, targets);
        return targets;
    }

    private static boolean isUnboundLambdaMethodReference(InvokeDynamicInsnNode indy, Handle handle) {
        return handle.getTag() != Opcodes.H_INVOKESTATIC &&
            Type.getArgumentTypes(indy.desc).length == 0;
    }

    private static void addVirtualFamilyTargets(
        PipelineContext pctx,
        Set<String> targets,
        String owner,
        String name,
        String desc
    ) {
        for (L1Class clazz : pctx.classMap().values()) {
            if (!isSubtypeOf(pctx, clazz, owner)) continue;
            for (L1Method method : clazz.methods()) {
                if (method.name().equals(name) && method.descriptor().equals(desc)) {
                    targets.add(key(clazz.name(), method.name(), method.descriptor()));
                }
            }
        }
    }

    private static boolean isSubtypeOf(PipelineContext pctx, L1Class clazz, String targetOwner) {
        if (clazz == null) return false;
        if (clazz.name().equals(targetOwner)) return true;
        if (clazz.interfaces().contains(targetOwner)) return true;
        for (String iface : clazz.interfaces()) {
            if (isSubtypeOf(pctx, pctx.classMap().get(iface), targetOwner)) return true;
        }
        return isSubtypeOf(pctx, pctx.classMap().get(clazz.superName()), targetOwner);
    }

    private static boolean isMethodHandleLookup(MethodInsnNode call) {
        if (!"java/lang/invoke/MethodHandles$Lookup".equals(call.owner)) return false;
        if ("findConstructor".equals(call.name)) {
            return "(Ljava/lang/Class;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;".equals(call.desc);
        }
        return ("findStatic".equals(call.name)
            || "findVirtual".equals(call.name)
            || "findSpecial".equals(call.name))
            && call.desc.startsWith("(Ljava/lang/Class;Ljava/lang/String;");
    }

    private static MethodHandleLookupTarget sourceMethodHandleLookupTarget(
        PipelineContext pctx,
        MethodNode mn,
        MethodInsnNode call
    ) {
        if (mn == null || mn.instructions == null) return null;
        int index = mn.instructions.indexOf(call);
        if (index < 0) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            return sourceMethodHandleLookupTarget(pctx, mn, frames, call);
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private static MethodHandleLookupTarget sourceMethodHandleLookupTarget(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode call
    ) {
        if (!isMethodHandleLookup(call)) return null;
        if (pctx != null) {
            MethodHandleLookupTarget rewritten = methodHandleLookupTargets(pctx).get(call);
            if (rewritten != null) return rewritten;
        }
        int index = mn.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        Type[] args = Type.getArgumentTypes(call.desc);
        int base = frame == null ? -1 : frame.getStackSize() - args.length;
        if (base <= 0 || base + args.length > frame.getStackSize()) return null;
        boolean constructorLookup = "findConstructor".equals(call.name);
        String owner = literalObjectClass(mn, frames, frame.getStack(base), 0);
        SourceValue methodTypeValue = frame.getStack(base + (constructorLookup ? 1 : 2));
        Type[] parameterTypes = literalMethodTypeParameterTypes(pctx, mn, frames, methodTypeValue, 0);
        if (constructorLookup) {
            return owner == null ? null : new MethodHandleLookupTarget(owner, "<init>", call.name, parameterTypes);
        }
        String name = literalString(mn, frames, frame.getStack(base + 1), 0);
        return name == null ? null : new MethodHandleLookupTarget(owner, name, call.name, parameterTypes);
    }

    private static Type[] literalMethodTypeParameterTypes(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 6) return null;
        Type[] result = null;
        for (AbstractInsnNode insn : value.insns) {
            Type[] sourced = null;
            if (insn instanceof MethodInsnNode call && isMethodTypeFactory(call)) {
                sourced = sourceMethodTypeParameterTypes(pctx, mn, frames, call);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = literalMethodTypeParameterTypes(
                    pctx,
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    depth + 1
                );
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = literalMethodTypeParameterTypes(
                            pctx,
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            }
            if (sourced == null) return null;
            if (result != null && !sameTypes(result, sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private static boolean isMethodTypeFactory(MethodInsnNode call) {
        return "java/lang/invoke/MethodType".equals(call.owner) && "methodType".equals(call.name);
    }

    private static Type[] sourceMethodTypeParameterTypes(
        PipelineContext pctx,
        MethodNode mn,
        MethodInsnNode methodTypeCall
    ) {
        if (mn == null || mn.instructions == null) return null;
        int index = mn.instructions.indexOf(methodTypeCall);
        if (index < 0) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            if (frame == null) return null;
            Type[] args = Type.getArgumentTypes(methodTypeCall.desc);
            if (args.length == 1 && Type.getType(Class.class).equals(args[0])) {
                return new Type[0];
            }
            if (args.length == 2
                && Type.getType(Class.class).equals(args[0])
                && Type.getType(Class.class).equals(args[1])
                && frame.getStackSize() >= 2) {
                Type single = literalClassType(mn, frames, frame.getStack(frame.getStackSize() - 1), 0);
                return single == null ? null : new Type[] {single};
            }
            if (args.length == 2
                && Type.getType(Class.class).equals(args[0])
                && Type.getType(Class[].class).equals(args[1])) {
                return frame.getStackSize() >= 2
                    ? sourceClassArrayParameterTypes(
                        pctx,
                        mn,
                        frames,
                        methodTypeCall,
                        frame.getStack(frame.getStackSize() - 1)
                    )
                    : null;
            }
            if (args.length == 3
                && Type.getType(Class.class).equals(args[0])
                && Type.getType(Class.class).equals(args[1])
                && Type.getType(Class[].class).equals(args[2])
                && frame.getStackSize() >= 3) {
                Type first = literalClassType(mn, frames, frame.getStack(frame.getStackSize() - 2), 0);
                Type[] tail = sourceClassArrayParameterTypes(
                    pctx,
                    mn,
                    frames,
                    methodTypeCall,
                    frame.getStack(frame.getStackSize() - 1)
                );
                if (first == null || tail == null) return null;
                Type[] combined = new Type[tail.length + 1];
                combined[0] = first;
                System.arraycopy(tail, 0, combined, 1, tail.length);
                return combined;
            }
            return null;
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private static Type[] sourceMethodTypeParameterTypes(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode methodTypeCall
    ) {
        int index = mn.instructions.indexOf(methodTypeCall);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null) return null;
        Type[] args = Type.getArgumentTypes(methodTypeCall.desc);
        if (args.length == 1 && Type.getType(Class.class).equals(args[0])) {
            return new Type[0];
        }
        if (args.length == 2
            && Type.getType(Class.class).equals(args[0])
            && Type.getType(Class.class).equals(args[1])
            && frame.getStackSize() >= 2) {
            Type single = literalClassType(mn, frames, frame.getStack(frame.getStackSize() - 1), 0);
            return single == null ? null : new Type[] {single};
        }
        if (args.length == 2
            && Type.getType(Class.class).equals(args[0])
            && Type.getType(Class[].class).equals(args[1])) {
            return frame.getStackSize() >= 2
                ? sourceClassArrayParameterTypes(
                    pctx,
                    mn,
                    frames,
                    methodTypeCall,
                    frame.getStack(frame.getStackSize() - 1)
                )
                : null;
        }
        if (args.length == 3
            && Type.getType(Class.class).equals(args[0])
            && Type.getType(Class.class).equals(args[1])
            && Type.getType(Class[].class).equals(args[2])
            && frame.getStackSize() >= 3) {
            Type first = literalClassType(mn, frames, frame.getStack(frame.getStackSize() - 2), 0);
            Type[] tail = sourceClassArrayParameterTypes(
                pctx,
                mn,
                frames,
                methodTypeCall,
                frame.getStack(frame.getStackSize() - 1)
            );
            if (first == null || tail == null) return null;
            Type[] combined = new Type[tail.length + 1];
            combined[0] = first;
            System.arraycopy(tail, 0, combined, 1, tail.length);
            return combined;
        }
        return null;
    }

    private static Set<String> reflectiveLookupTargets(PipelineContext pctx) {
        Set<String> targets = new java.util.LinkedHashSet<>();
        for (L1Class clazz : pctx.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                if (!method.hasCode()) continue;
                for (AbstractInsnNode insn = method.instructions().getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode call)) continue;
                    if (isReflectionLookup(call)) {
                        MethodHandleLookupTarget target = sourceReflectiveLookupTarget(pctx, method.asmNode(), call);
                        if (target == null) continue;
                        if (target.name() == null) {
                            if (target.owner() != null &&
                                !addExactReflectiveLookupTargets(pctx, targets, method.asmNode(), call, target.owner())) {
                                targets.add(target.owner() + ".*");
                            }
                        } else {
                            targets.add((target.owner() == null ? "*" : target.owner()) + "." + target.name());
                        }
                    } else if (isReflectionMethodArrayLookup(call)) {
                        String owner = sourceReflectionArrayLookupOwner(pctx, method.asmNode(), call);
                        if (owner != null) {
                            targets.add(owner + ".*");
                        }
                    }
                }
            }
        }
        return targets;
    }

    private static boolean addExactReflectiveLookupTargets(
        PipelineContext pctx,
        Set<String> targets,
        MethodNode mn,
        MethodInsnNode call,
        String owner
    ) {
        Type[] parameterTypes = sourceReflectiveParameterTypes(pctx, mn, call);
        if (parameterTypes == null) return false;
        L1Class targetClass = pctx.classMap().get(owner);
        if (targetClass == null) return false;
        boolean added = false;
        for (L1Method candidate : targetClass.methods()) {
            Type[] candidateArgs = Type.getArgumentTypes(candidate.descriptor());
            if (candidateArgs.length != parameterTypes.length) continue;
            boolean same = true;
            for (int i = 0; i < candidateArgs.length; i++) {
                if (!candidateArgs[i].equals(parameterTypes[i])) {
                    same = false;
                    break;
                }
            }
            if (!same) continue;
            targets.add(key(owner, candidate.name(), candidate.descriptor()));
            added = true;
        }
        return added;
    }

    private static Type[] sourceReflectiveParameterTypes(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        if (mn == null || mn.instructions == null) return null;
        int index = mn.instructions.indexOf(call);
        if (index < 0) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            if (frame == null || frame.getStackSize() == 0) return null;
            SourceValue arrayValue = frame.getStack(frame.getStackSize() - 1);
            Type[] result = sourceClassArrayParameterTypes(
                pctx,
                mn,
                frames,
                call,
                arrayValue
            );
            return result;
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private static Type[] stripGeneratedTrailingHiddenKeyParameter(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        SourceValue arrayValue,
        String owner,
        String name,
        Type[] parameterTypes
    ) {
        if (pctx == null
            || parameterTypes == null
            || parameterTypes.length == 0
            || !Type.LONG_TYPE.equals(parameterTypes[parameterTypes.length - 1])) {
            return parameterTypes;
        }
        if (isPackedReflectiveLookupParameters(pctx, owner, name, parameterTypes)) {
            return parameterTypes;
        }
        if (!hasGeneratedTrailingHiddenKeyParameter(pctx, mn, frames, consumerCall, arrayValue, parameterTypes, 0)) {
            return parameterTypes;
        }
        Type[] visible = new Type[parameterTypes.length - 1];
        System.arraycopy(parameterTypes, 0, visible, 0, visible.length);
        return visible;
    }

    private static boolean isPackedReflectiveLookupParameters(
        PipelineContext pctx,
        String owner,
        String name,
        Type[] parameterTypes
    ) {
        if (pctx == null || parameterTypes == null) return false;
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if ("<init>".equals(plan.oldName())) continue;
            if (owner != null && !owner.equals(plan.owner())) continue;
            if (name != null && !name.equals(plan.oldName()) && !name.equals(plan.finalName())) continue;
            if (sameTypes(Type.getArgumentTypes(plan.packedDesc()), parameterTypes)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasGeneratedTrailingHiddenKeyParameter(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        SourceValue arrayValue,
        Type[] parameterTypes,
        int depth
    ) {
        if (arrayValue == null || depth > 6) return false;
        boolean proved = false;
        for (AbstractInsnNode insn : arrayValue.insns) {
            Boolean sourced = null;
            if (insn instanceof TypeInsnNode type
                && type.getOpcode() == Opcodes.ANEWARRAY
                && "java/lang/Class".equals(type.desc)) {
                sourced = allocationStoresGeneratedTrailingHiddenKey(
                    pctx,
                    mn,
                    frames,
                    consumerCall,
                    type,
                    parameterTypes
                );
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = hasGeneratedTrailingHiddenKeyParameter(
                    pctx,
                    mn,
                    frames,
                    consumerCall,
                    storedLocalValue(mn, frames, var),
                    parameterTypes,
                    depth + 1
                );
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = hasGeneratedTrailingHiddenKeyParameter(
                            pctx,
                            mn,
                            frames,
                            consumerCall,
                            frame.getStack(frame.getStackSize() - 1),
                            parameterTypes,
                            depth + 1
                        );
                    }
                }
            } else if (insn.getOpcode() == Opcodes.DUP) {
                int index = mn.instructions.indexOf(insn);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = hasGeneratedTrailingHiddenKeyParameter(
                            pctx,
                            mn,
                            frames,
                            consumerCall,
                            frame.getStack(frame.getStackSize() - 1),
                            parameterTypes,
                            depth + 1
                        );
                    }
                }
            } else if (isClassArraySourceBookkeeping(insn)) {
                continue;
            }
            if (sourced == null || !sourced) return false;
            proved = true;
        }
        return proved;
    }

    private static boolean allocationStoresGeneratedTrailingHiddenKey(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        TypeInsnNode allocation,
        Type[] parameterTypes
    ) {
        int allocationIndex = mn.instructions.indexOf(allocation);
        int consumerIndex = mn.instructions.indexOf(consumerCall);
        if (allocationIndex < 0 || consumerIndex <= allocationIndex || allocationIndex >= frames.length) {
            return false;
        }
        Frame<SourceValue> allocationFrame = frames[allocationIndex];
        if (allocationFrame == null || allocationFrame.getStackSize() == 0) return false;
        Integer length = literalInt(
            mn,
            frames,
            allocationFrame.getStack(allocationFrame.getStackSize() - 1),
            0
        );
        if (length == null || length != parameterTypes.length) return false;
        int trailingSlot = parameterTypes.length - 1;
        for (
            AbstractInsnNode scan = allocation.getNext();
            scan != null && scan != consumerCall;
            scan = scan.getNext()
        ) {
            if (!(scan instanceof InsnNode store) || store.getOpcode() != Opcodes.AASTORE) continue;
            int storeIndex = mn.instructions.indexOf(store);
            if (storeIndex < 0 || storeIndex >= frames.length) return false;
            Frame<SourceValue> frame = frames[storeIndex];
            if (frame == null || frame.getStackSize() < 3) return false;
            SourceValue arrayRef = frame.getStack(frame.getStackSize() - 3);
            if (!sourceMayAliasInstruction(mn, frames, arrayRef, allocation, 0)) continue;
            Integer slot = literalInt(
                mn,
                frames,
                frame.getStack(frame.getStackSize() - 2),
                0,
                allocation,
                parameterTypes.length
            );
            if (slot == null || slot != trailingSlot) continue;
            Type type = literalClassType(mn, frames, frame.getStack(frame.getStackSize() - 1), 0);
            if (Type.LONG_TYPE.equals(type) && JvmKeyDispatchPass.isGeneratedNode(pctx, store)) {
                return true;
            }
        }
        return false;
    }

    private static Type[] sourceClassArrayParameterTypes(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        SourceValue arrayValue
    ) {
        return sourceClassArrayParameterTypes(pctx, mn, frames, consumerCall, arrayValue, 0);
    }

    private static Type[] sourceClassArrayParameterTypes(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        SourceValue arrayValue,
        int depth
    ) {
        if (arrayValue == null || depth > 6) return null;
        Type[] result = null;
        for (AbstractInsnNode insn : arrayValue.insns) {
            Type[] sourced = null;
            if (insn.getOpcode() == Opcodes.ACONST_NULL) {
                sourced = new Type[0];
            } else if (insn instanceof TypeInsnNode type
                && type.getOpcode() == Opcodes.ANEWARRAY
                && "java/lang/Class".equals(type.desc)) {
                sourced = sourceClassArrayParameterTypesFromAllocation(
                    pctx,
                    mn,
                    frames,
                    consumerCall,
                    type
                );
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceClassArrayParameterTypes(
                    pctx,
                    mn,
                    frames,
                    consumerCall,
                    storedLocalValue(mn, frames, var),
                    depth + 1
                );
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceClassArrayParameterTypes(
                            pctx,
                            mn,
                            frames,
                            consumerCall,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            } else if (insn.getOpcode() == Opcodes.DUP) {
                int index = mn.instructions.indexOf(insn);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceClassArrayParameterTypes(
                            pctx,
                            mn,
                            frames,
                            consumerCall,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            } else if (isClassArraySourceBookkeeping(insn)) {
                continue;
            }
            if (sourced == null) {
                return null;
            }
            if (result != null && !sameTypes(result, sourced)) {
                return null;
            }
            result = sourced;
        }
        return result;
    }

    private static boolean isClassArraySourceBookkeeping(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return opcode == Opcodes.AASTORE || opcode == Opcodes.ASTORE;
    }

    private static Type[] sourceClassArrayParameterTypesFromAllocation(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        TypeInsnNode allocation
    ) {
        int allocationIndex = mn.instructions.indexOf(allocation);
        int consumerIndex = mn.instructions.indexOf(consumerCall);
        if (allocationIndex < 0 || consumerIndex <= allocationIndex || allocationIndex >= frames.length) {
            return null;
        }
        Frame<SourceValue> allocationFrame = frames[allocationIndex];
        if (allocationFrame == null || allocationFrame.getStackSize() == 0) return null;
        Integer length = literalInt(
            mn,
            frames,
            allocationFrame.getStack(allocationFrame.getStackSize() - 1),
            0
        );
        if (length == null || length < 0 || length > 256) {
            return null;
        }
        Type[] types = new Type[length];
        boolean[] seen = new boolean[length];
        for (
            AbstractInsnNode scan = allocation.getNext();
            scan != null && scan != consumerCall;
            scan = scan.getNext()
        ) {
            if (scan instanceof MethodInsnNode arraycopy && isSystemArrayCopy(arraycopy)) {
                if (!applyClassArrayCopy(pctx, mn, frames, consumerCall, allocation, arraycopy, types, seen)) {
                    return null;
                }
                continue;
            }
            if (!(scan instanceof InsnNode store) || store.getOpcode() != Opcodes.AASTORE) continue;
            int storeIndex = mn.instructions.indexOf(store);
            if (storeIndex < 0 || storeIndex >= frames.length) return null;
            Frame<SourceValue> frame = frames[storeIndex];
            if (frame == null || frame.getStackSize() < 3) return null;
            SourceValue arrayRef = frame.getStack(frame.getStackSize() - 3);
            boolean alias = sourceMayAliasInstruction(mn, frames, arrayRef, allocation, 0);
            if (!alias) continue;
            Integer slot = literalInt(
                mn,
                frames,
                frame.getStack(frame.getStackSize() - 2),
                0,
                allocation,
                types.length
            );
            Type type = literalClassType(mn, frames, frame.getStack(frame.getStackSize() - 1), 0);
            if (slot == null || slot < 0 || slot >= types.length || type == null) {
                return null;
            }
            if (!storeClassArrayType(types, seen, slot, type)) return null;
        }
        for (int i = 0; i < seen.length; i++) {
            if (!seen[i]) {
                return null;
            }
        }
        return types;
    }

    private static boolean isSystemArrayCopy(MethodInsnNode call) {
        return call.getOpcode() == Opcodes.INVOKESTATIC
            && "java/lang/System".equals(call.owner)
            && "arraycopy".equals(call.name)
            && "(Ljava/lang/Object;ILjava/lang/Object;II)V".equals(call.desc);
    }

    private static boolean applyClassArrayCopy(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        AbstractInsnNode allocation,
        MethodInsnNode arraycopy,
        Type[] types,
        boolean[] seen
    ) {
        int index = mn.instructions.indexOf(arraycopy);
        if (index < 0 || index >= frames.length) return false;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() < 5) return false;
        int base = frame.getStackSize() - 5;
        SourceValue sourceArray = frame.getStack(base);
        SourceValue destArray = frame.getStack(base + 2);
        if (!sourceMayAliasInstruction(mn, frames, destArray, allocation, 0)) return true;
        Integer sourceOffset = literalInt(mn, frames, frame.getStack(base + 1), 0);
        Integer destOffset = literalInt(mn, frames, frame.getStack(base + 3), 0);
        Integer copyLength = literalInt(mn, frames, frame.getStack(base + 4), 0);
        Type[] sourceTypes = sourceClassArrayParameterTypes(
            pctx,
            mn,
            frames,
            arraycopy,
            sourceArray
        );
        if (sourceOffset == null || destOffset == null || copyLength == null || sourceTypes == null) return false;
        if (sourceOffset < 0 || destOffset < 0 || copyLength < 0) return false;
        if (sourceOffset + copyLength > sourceTypes.length || destOffset + copyLength > types.length) return false;
        for (int i = 0; i < copyLength; i++) {
            if (!storeClassArrayType(types, seen, destOffset + i, sourceTypes[sourceOffset + i])) {
                return false;
            }
        }
        return true;
    }

    private static boolean storeClassArrayType(Type[] types, boolean[] seen, int slot, Type type) {
        if (slot < 0 || slot >= types.length || type == null) return false;
        if (seen[slot] && !types[slot].equals(type)) return false;
        types[slot] = type;
        seen[slot] = true;
        return true;
    }

    private static boolean sourceAliasesInstruction(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        AbstractInsnNode target,
        int depth
    ) {
        if (value == null || depth > 6) return false;
        boolean sawSource = false;
        for (AbstractInsnNode insn : value.insns) {
            if (insn == target) {
                sawSource = true;
                continue;
            }
            boolean sourced = false;
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceAliasesInstruction(
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    target,
                    depth + 1
                );
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    sourced = frame != null
                        && frame.getStackSize() > 0
                        && sourceAliasesInstruction(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            target,
                            depth + 1
                        );
                }
            } else if (insn.getOpcode() == Opcodes.DUP) {
                int index = mn.instructions.indexOf(insn);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    sourced = frame != null
                        && frame.getStackSize() > 0
                        && sourceAliasesInstruction(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            target,
                            depth + 1
                        );
                }
            }
            if (!sourced) return false;
            sawSource = true;
        }
        return sawSource;
    }

    private static boolean sourceMayAliasInstruction(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        AbstractInsnNode target,
        int depth
    ) {
        if (value == null || depth > 12) return false;
        for (AbstractInsnNode insn : value.insns) {
            if (insn == target) return true;
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                if (sourceMayAliasInstruction(
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    target,
                    depth + 1
                )) {
                    return true;
                }
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0 &&
                        sourceMayAliasInstruction(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            target,
                            depth + 1
                        )) {
                        return true;
                    }
                }
            } else if (insn.getOpcode() == Opcodes.DUP) {
                int index = mn.instructions.indexOf(insn);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0 &&
                        sourceMayAliasInstruction(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            target,
                            depth + 1
                        )) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static Integer literalInt(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        return literalInt(mn, frames, value, depth, null, null);
    }

    private static Integer literalInt(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth,
        AbstractInsnNode arrayLengthAlias,
        Integer aliasLength
    ) {
        if (value == null || depth > 4) return null;
        Integer result = null;
        for (AbstractInsnNode insn : value.insns) {
            Integer sourced = intConstant(insn);
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ILOAD) {
                sourced = literalInt(
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    depth + 1,
                    arrayLengthAlias,
                    aliasLength
                );
            } else if (sourced == null) {
                sourced = literalIntExpression(mn, frames, insn, depth + 1, arrayLengthAlias, aliasLength);
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private static Integer literalIntExpression(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        AbstractInsnNode insn,
        int depth,
        AbstractInsnNode arrayLengthAlias,
        Integer aliasLength
    ) {
        if (insn == null || depth > 4) return null;
        int index = mn.instructions.indexOf(insn);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null) return null;
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.INEG) {
            if (frame.getStackSize() < 1) return null;
            Integer value = literalInt(
                mn,
                frames,
                frame.getStack(frame.getStackSize() - 1),
                depth + 1,
                arrayLengthAlias,
                aliasLength
            );
            return value == null ? null : -value;
        }
        if (opcode == Opcodes.I2B || opcode == Opcodes.I2C || opcode == Opcodes.I2S) {
            if (frame.getStackSize() < 1) return null;
            Integer value = literalInt(
                mn,
                frames,
                frame.getStack(frame.getStackSize() - 1),
                depth + 1,
                arrayLengthAlias,
                aliasLength
            );
            if (value == null) return null;
            return switch (opcode) {
                case Opcodes.I2B -> (int) (byte) value.intValue();
                case Opcodes.I2C -> (int) (char) value.intValue();
                case Opcodes.I2S -> (int) (short) value.intValue();
                default -> null;
            };
        }
        if (opcode == Opcodes.ARRAYLENGTH) {
            if (frame.getStackSize() < 1) return null;
            SourceValue array = frame.getStack(frame.getStackSize() - 1);
            if (arrayLengthAlias != null && aliasLength != null &&
                sourceMayAliasInstruction(mn, frames, array, arrayLengthAlias, 0)) {
                return aliasLength;
            }
            Integer length = sourceArrayLength(mn, frames, array, depth + 1);
            return length;
        }
        if (!isIntBinaryExpression(opcode) || frame.getStackSize() < 2) return null;
        Integer left = literalInt(
            mn,
            frames,
            frame.getStack(frame.getStackSize() - 2),
            depth + 1,
            arrayLengthAlias,
            aliasLength
        );
        Integer right = literalInt(
            mn,
            frames,
            frame.getStack(frame.getStackSize() - 1),
            depth + 1,
            arrayLengthAlias,
            aliasLength
        );
        if (left == null || right == null) {
            return null;
        }
        return switch (opcode) {
            case Opcodes.IADD -> left + right;
            case Opcodes.ISUB -> left - right;
            case Opcodes.IMUL -> left * right;
            case Opcodes.IAND -> left & right;
            case Opcodes.IOR -> left | right;
            case Opcodes.IXOR -> left ^ right;
            case Opcodes.ISHL -> left << (right & 31);
            case Opcodes.ISHR -> left >> (right & 31);
            case Opcodes.IUSHR -> left >>> (right & 31);
            default -> null;
        };
    }

    private static boolean isIntBinaryExpression(int opcode) {
        return opcode == Opcodes.IADD
            || opcode == Opcodes.ISUB
            || opcode == Opcodes.IMUL
            || opcode == Opcodes.IAND
            || opcode == Opcodes.IOR
            || opcode == Opcodes.IXOR
            || opcode == Opcodes.ISHL
            || opcode == Opcodes.ISHR
            || opcode == Opcodes.IUSHR;
    }

    private static Integer sourceArrayLength(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 12) return null;
        Integer result = null;
        for (AbstractInsnNode insn : value.insns) {
            Integer sourced = null;
            if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.ANEWARRAY) {
                sourced = sourceNewArrayLength(mn, frames, type, depth + 1);
            } else if (insn instanceof IntInsnNode intInsn && intInsn.getOpcode() == Opcodes.NEWARRAY) {
                sourced = sourceNewArrayLength(mn, frames, intInsn, depth + 1);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                SourceValue stored = storedLocalValue(mn, frames, var);
                sourced = sourceArrayLength(mn, frames, stored, depth + 1);
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceArrayLength(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            } else if (insn.getOpcode() == Opcodes.DUP) {
                int index = mn.instructions.indexOf(insn);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceArrayLength(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            } else if (isClassArraySourceBookkeeping(insn)) {
                continue;
            }
            if (sourced == null) {
                return null;
            }
            if (result != null && !result.equals(sourced)) {
                return null;
            }
            result = sourced;
        }
        return result;
    }

    private static Integer sourceNewArrayLength(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        AbstractInsnNode allocation,
        int depth
    ) {
        int index = mn.instructions.indexOf(allocation);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() == 0) return null;
        return literalInt(mn, frames, frame.getStack(frame.getStackSize() - 1), 0);
    }

    private static Integer intConstant(AbstractInsnNode insn) {
        if (insn == null) return null;
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.ICONST_M1) {
            return -1;
        }
        if (opcode >= Opcodes.ICONST_0 && opcode <= Opcodes.ICONST_5) {
            return opcode - Opcodes.ICONST_0;
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return ((IntInsnNode) insn).operand;
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) {
            return value;
        }
        return null;
    }

    private static Type classConstant(AbstractInsnNode insn) {
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Type type) {
            return type;
        }
        if (!(insn instanceof FieldInsnNode field) ||
            field.getOpcode() != Opcodes.GETSTATIC ||
            !"TYPE".equals(field.name) ||
            !"Ljava/lang/Class;".equals(field.desc)) {
            return null;
        }
        return switch (field.owner) {
            case "java/lang/Boolean" -> Type.BOOLEAN_TYPE;
            case "java/lang/Character" -> Type.CHAR_TYPE;
            case "java/lang/Byte" -> Type.BYTE_TYPE;
            case "java/lang/Short" -> Type.SHORT_TYPE;
            case "java/lang/Integer" -> Type.INT_TYPE;
            case "java/lang/Float" -> Type.FLOAT_TYPE;
            case "java/lang/Long" -> Type.LONG_TYPE;
            case "java/lang/Double" -> Type.DOUBLE_TYPE;
            case "java/lang/Void" -> Type.VOID_TYPE;
            default -> null;
        };
    }

    private static boolean isReflectionLookup(MethodInsnNode call) {
        return "java/lang/Class".equals(call.owner)
            && ("getMethod".equals(call.name) || "getDeclaredMethod".equals(call.name))
            && "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;".equals(call.desc);
    }

    private static boolean isReflectionMethodArrayLookup(MethodInsnNode call) {
        return "java/lang/Class".equals(call.owner)
            && ("getMethods".equals(call.name) || "getDeclaredMethods".equals(call.name))
            && "()[Ljava/lang/reflect/Method;".equals(call.desc);
    }

    private static boolean isReflectionConstructorArrayLookup(MethodInsnNode call) {
        return "java/lang/Class".equals(call.owner)
            && ("getConstructors".equals(call.name) || "getDeclaredConstructors".equals(call.name))
            && "()[Ljava/lang/reflect/Constructor;".equals(call.desc);
    }

    private static boolean isReflectionConstructorLookup(MethodInsnNode call) {
        return "java/lang/Class".equals(call.owner)
            && ("getConstructor".equals(call.name) || "getDeclaredConstructor".equals(call.name))
            && "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;".equals(call.desc);
    }

    private static MethodHandleLookupTarget sourceReflectiveLookupTarget(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        if (mn == null || mn.instructions == null) return null;
        if (pctx != null) {
            MethodHandleLookupTarget rewritten = reflectiveMethodLookupTargets(pctx).get(call);
            if (rewritten != null) return rewritten;
        }
        int index = mn.instructions.indexOf(call);
        if (index < 0) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            if (frame == null || frame.getStackSize() < 3) return null;
            int top = frame.getStackSize();
            String owner = sourceClassObjectOwner(pctx, mn, frames, frame.getStack(top - 3), 0);
            String name = literalString(mn, frames, frame.getStack(top - 2), 0);
            SourceValue parameterArray = frame.getStack(top - 1);
            Type[] params = sourceClassArrayParameterTypes(
                pctx,
                mn,
                frames,
                call,
                parameterArray
            );
            params = stripGeneratedTrailingHiddenKeyParameter(
                pctx,
                mn,
                frames,
                call,
                parameterArray,
                owner,
                name,
                params
            );
            return owner == null && name == null && params == null
                ? null
                : new MethodHandleLookupTarget(owner, name, null, params);
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private static MethodHandleLookupTarget sourceReflectiveLookupTarget(MethodNode mn, MethodInsnNode call) {
        return sourceReflectiveLookupTarget(null, mn, call);
    }

    private static String literalObjectClass(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 4) return null;
        String owner = null;
        for (AbstractInsnNode insn : value.insns) {
            String sourced = null;
            if (insn instanceof LdcInsnNode ldc &&
                ldc.cst instanceof Type type &&
                type.getSort() == Type.OBJECT) {
                sourced = type.getInternalName();
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = literalObjectClass(mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            }
            if (sourced == null) return null;
            if (owner != null && !owner.equals(sourced)) return null;
            owner = sourced;
        }
        return owner;
    }

    private static String sourceClassObjectOwner(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 6) return null;
        String owner = null;
        for (AbstractInsnNode insn : value.insns) {
            String sourced = null;
            if (insn instanceof LdcInsnNode ldc &&
                ldc.cst instanceof Type type &&
                type.getSort() == Type.OBJECT) {
                sourced = type.getInternalName();
            } else if (insn instanceof MethodInsnNode call && returnsClassObject(call)) {
                sourced = sourceClassObjectOwnerFromProducingCall(pctx, mn, frames, call, depth + 1);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceClassObjectOwner(pctx, mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceClassObjectOwner(
                            pctx,
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            }
            if (sourced == null) return null;
            if (owner != null && !owner.equals(sourced)) return null;
            owner = sourced;
        }
        return owner;
    }

    private static boolean returnsClassObject(MethodInsnNode call) {
        return "()Ljava/lang/Class;".equals(call.desc)
            || call.desc.endsWith(")Ljava/lang/Class;");
    }

    private static String sourceClassObjectOwnerFromProducingCall(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode call,
        int depth
    ) {
        int index = mn.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        Type[] args = Type.getArgumentTypes(call.desc);
        int receiverSlots = call.getOpcode() == Opcodes.INVOKESTATIC ? 0 : 1;
        int base = frame == null ? -1 : frame.getStackSize() - args.length - receiverSlots;
        if (base < 0) return null;
        if ("java/lang/Class".equals(call.owner)
            && "forName".equals(call.name)
            && call.desc.startsWith("(Ljava/lang/String;")) {
            return normalizedClassName(pctx, literalString(mn, frames, frame.getStack(base), depth + 1));
        }
        if (args.length == 1
            && "Ljava/lang/String;".equals(args[0].getDescriptor())
            && ("loadClass".equals(call.name) || "findClass".equals(call.name))) {
            return normalizedClassName(
                pctx,
                literalString(mn, frames, frame.getStack(base + receiverSlots), depth + 1)
            );
        }
        return null;
    }

    private static String normalizedClassName(PipelineContext pctx, String name) {
        if (name == null || name.isEmpty()) return null;
        String internal = name;
        if (internal.startsWith("[L") && internal.endsWith(";")) {
            internal = internal.substring(2, internal.length() - 1);
        }
        internal = internal.replace('.', '/');
        if (pctx == null || pctx.classMap().containsKey(internal)) {
            return internal;
        }
        return internal.indexOf('/') >= 0 ? internal : null;
    }

    private static Type literalClassType(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 4) return null;
        Type result = null;
        for (AbstractInsnNode insn : value.insns) {
            Type sourced = classConstant(insn);
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = literalClassType(mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private static String literalString(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 4) return null;
        String string = null;
        for (AbstractInsnNode insn : value.insns) {
            String sourced = null;
            if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String valueString) {
                sourced = valueString;
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = literalString(mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            }
            if (sourced == null) return null;
            if (string != null && !string.equals(sourced)) return null;
            string = sourced;
        }
        return string;
    }

    private static SourceValue storedLocalValue(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        VarInsnNode load
    ) {
        int loadIndex = mn.instructions.indexOf(load);
        if (loadIndex < 0 || loadIndex >= frames.length) return null;
        Frame<SourceValue> frame = frames[loadIndex];
        if (frame == null || load.var < 0 || load.var >= frame.getLocals()) return null;
        SourceValue local = frame.getLocal(load.var);
        return storedLocalValueFromFrame(mn, frames, local, storeOpcodeForLoad(load.getOpcode()), 0);
    }

    private static SourceValue storedLocalValueFromFrame(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue local,
        int storeOpcode,
        int depth
    ) {
        if (local == null || depth > 4) return null;
        if (storeOpcode < 0) return local;
        Set<AbstractInsnNode> merged = new java.util.LinkedHashSet<>();
        boolean sawStore = false;
        for (AbstractInsnNode insn : local.insns) {
            if (insn instanceof VarInsnNode store && store.getOpcode() == storeOpcode) {
                int storeIndex = mn.instructions.indexOf(store);
                if (storeIndex < 0 || storeIndex >= frames.length) return null;
                Frame<SourceValue> storeFrame = frames[storeIndex];
                if (storeFrame == null || storeFrame.getStackSize() == 0) return null;
                SourceValue stored = storeFrame.getStack(storeFrame.getStackSize() - 1);
                SourceValue resolved = storedLocalValueFromFrame(
                    mn,
                    frames,
                    stored,
                    storeOpcode,
                    depth + 1
                );
                if (resolved == null) return null;
                merged.addAll(resolved.insns);
                sawStore = true;
            } else {
                merged.add(insn);
            }
        }
        return sawStore ? new SourceValue(local.getSize(), merged) : local;
    }

    private static int storeOpcodeForLoad(int loadOpcode) {
        return switch (loadOpcode) {
            case Opcodes.ILOAD -> Opcodes.ISTORE;
            case Opcodes.LLOAD -> Opcodes.LSTORE;
            case Opcodes.FLOAD -> Opcodes.FSTORE;
            case Opcodes.DLOAD -> Opcodes.DSTORE;
            case Opcodes.ALOAD -> Opcodes.ASTORE;
            default -> -1;
        };
    }

    private static Set<String> indySamTargets(PipelineContext pctx) {
        Set<String> targets = pctx.getPassData(INDY_SAM_TARGETS);
        if (targets != null) return targets;
        targets = new java.util.LinkedHashSet<>();
        for (L1Class clazz : pctx.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                if (!method.hasCode()) continue;
                for (AbstractInsnNode insn = method.instructions().getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof InvokeDynamicInsnNode indy)) continue;
                    if (!isLambdaMetafactory(indy) || indy.bsmArgs.length == 0 || !(indy.bsmArgs[0] instanceof Type samType)) {
                        continue;
                    }
                    Type owner = Type.getReturnType(indy.desc);
                    if (owner.getSort() == Type.OBJECT) {
                        targets.add(key(owner.getInternalName(), indy.name, samType.getDescriptor()));
                    }
                }
            }
        }
        pctx.putPassData(INDY_SAM_TARGETS, targets);
        return targets;
    }

    @SuppressWarnings("unchecked")
    private static Map<MethodInsnNode, MethodHandleLookupTarget> methodHandleLookupTargets(PipelineContext pctx) {
        Map<MethodInsnNode, MethodHandleLookupTarget> targets = pctx.getPassData(METHOD_HANDLE_LOOKUP_TARGETS);
        if (targets == null) {
            targets = new IdentityHashMap<>();
            pctx.putPassData(METHOD_HANDLE_LOOKUP_TARGETS, targets);
        }
        return targets;
    }

    @SuppressWarnings("unchecked")
    private static Map<MethodInsnNode, MethodHandleLookupTarget> reflectiveMethodLookupTargets(PipelineContext pctx) {
        Map<MethodInsnNode, MethodHandleLookupTarget> targets = pctx.getPassData(REFLECTIVE_METHOD_LOOKUP_TARGETS);
        if (targets == null) {
            targets = new IdentityHashMap<>();
            pctx.putPassData(REFLECTIVE_METHOD_LOOKUP_TARGETS, targets);
        }
        return targets;
    }

    @SuppressWarnings("unchecked")
    private static Map<MethodInsnNode, MethodHandleLookupTarget> reflectiveConstructorLookupTargets(PipelineContext pctx) {
        Map<MethodInsnNode, MethodHandleLookupTarget> targets =
            pctx.getPassData(REFLECTIVE_CONSTRUCTOR_LOOKUP_TARGETS);
        if (targets == null) {
            targets = new IdentityHashMap<>();
            pctx.putPassData(REFLECTIVE_CONSTRUCTOR_LOOKUP_TARGETS, targets);
        }
        return targets;
    }

    private static boolean isLambdaMetafactory(InvokeDynamicInsnNode indy) {
        return indy.bsm != null
            && "java/lang/invoke/LambdaMetafactory".equals(indy.bsm.getOwner())
            && ("metafactory".equals(indy.bsm.getName()) || "altMetafactory".equals(indy.bsm.getName()));
    }

    private static Handle lambdaImplementationHandle(InvokeDynamicInsnNode indy) {
        if (!isLambdaMetafactory(indy) || indy.bsmArgs.length < 2 || !(indy.bsmArgs[1] instanceof Handle handle)) {
            return null;
        }
        return handle;
    }

    private static MethodNode findMethodNode(L1Class clazz, String name, String desc) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) return method;
        }
        return null;
    }

    private static Integer findRecordedKeyLocal(PipelineContext pctx, String owner, String name, String desc) {
        Map<String, Integer> locals = pctx.getPassData(JvmKeyDispatchPass.LOCAL_BY_METHOD);
        return locals == null ? null : locals.get(key(owner, name, desc));
    }

    private static void migrateKeyDispatchMetadata(PipelineContext pctx, String oldKey, String finalKey) {
        migrateMapKey(pctx, JvmKeyDispatchPass.LOCAL_BY_METHOD, oldKey, finalKey);
        migrateMapKey(pctx, JvmKeyDispatchPass.SEED_BY_METHOD, oldKey, finalKey);
        migrateMapKey(pctx, JvmKeyDispatchPass.CFF_LOCAL_BY_METHOD, oldKey, finalKey);
        JvmKeyDispatchPass.migrateReflectiveKeyedEntry(pctx, oldKey, finalKey);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void migrateMapKey(PipelineContext pctx, String mapKey, String oldKey, String finalKey) {
        Map map = pctx.getPassData(mapKey);
        if (map == null || !map.containsKey(oldKey)) return;
        Object value = map.remove(oldKey);
        map.put(finalKey, value);
    }

    private static String packedDescriptor(String desc, boolean splitHiddenKey, Type[] suffixTypes) {
        List<Type> packedArgs = new ArrayList<>();
        packedArgs.add(OBJECT_ARRAY_TYPE);
        if (splitHiddenKey) {
            packedArgs.add(Type.LONG_TYPE);
        }
        for (Type suffixType : suffixTypes) {
            packedArgs.add(suffixType);
        }
        return Type.getMethodDescriptor(Type.getReturnType(desc), packedArgs.toArray(Type[]::new));
    }

    private static int[] argumentLocals(int access, String desc) {
        Type[] args = Type.getArgumentTypes(desc);
        int[] locals = new int[args.length];
        int local = (access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (int i = 0; i < args.length; i++) {
            locals[i] = local;
            local += args[i].getSize();
        }
        return locals;
    }

    private static int parameterLocalLimit(int access, String desc) {
        int local = (access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type arg : Type.getArgumentTypes(desc)) {
            local += arg.getSize();
        }
        return local;
    }

    private boolean installDynamicProxyHandlerArgumentView(
        PipelineContext pctx,
        MethodNode mn,
        List<DynamicProxyHandlerTarget> targets
    ) {
        if (targets == null || targets.isEmpty()) return false;
        int carrierLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        int unpackedLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        boolean needsHiddenKeyLocals = false;
        for (DynamicProxyHandlerTarget target : targets) {
            for (MethodPlan plan : target.plans()) {
                if (packedHiddenKeyArgumentIndex(plan) >= 0) {
                    needsHiddenKeyLocals = true;
                    break;
                }
            }
            if (needsHiddenKeyLocals) break;
        }
        int carrierIndexKeyLocal = needsHiddenKeyLocals ? allocateLocal(mn, Type.LONG_TYPE) : -1;
        int targetKeyLocal = needsHiddenKeyLocals ? allocateLocal(mn, Type.LONG_TYPE) : -1;
        int tokenLocal = needsHiddenKeyLocals ? allocateLocal(mn, Type.LONG_TYPE) : -1;
        int tagLocal = needsHiddenKeyLocals ? allocateLocal(mn, Type.LONG_TYPE) : -1;
        LabelNode done = new LabelNode();
        InsnList out = new InsnList();
        boolean emitted = false;
        for (DynamicProxyHandlerTarget target : targets) {
            for (MethodPlan plan : target.plans()) {
                LabelNode next = new LabelNode();
                emitRuntimeMethodMatch(out, target.methodLocal(), plan, next, false);
                emitDynamicProxyOuterCarrierLoad(out, target.argsLocal(), plan, carrierLocal, next);
                int hiddenKeyIndex = packedHiddenKeyArgumentIndex(plan);
                if (hiddenKeyIndex >= 0) {
                    emitCarrierShapeValidation(out, carrierLocal, plan);
                    emitCarrierArrayLoadSafe(
                        pctx,
                        out,
                        carrierLocal,
                        plan,
                        carrierIndexKeyLogicalIndex(plan),
                        -1,
                        false,
                        plan.carrierIndexKeySeed()
                    );
                    emitUnboxOrCast(out, Type.LONG_TYPE);
                    out.add(new VarInsnNode(Opcodes.LSTORE, carrierIndexKeyLocal));
                    if (plan.splitHiddenKey()) {
                        out.add(new VarInsnNode(Opcodes.ALOAD, target.argsLocal()));
                        JvmPassBytecode.pushInt(out, 1);
                        out.add(new InsnNode(Opcodes.AALOAD));
                    } else {
                        emitCarrierArrayLoad(
                            pctx,
                            out,
                            carrierLocal,
                            plan,
                            hiddenKeyIndex,
                            carrierIndexKeyLocal,
                            false,
                            plan.carrierIndexKeySeed()
                        );
                    }
                    emitUnboxOrCast(out, Type.LONG_TYPE);
                    out.add(new VarInsnNode(Opcodes.LSTORE, targetKeyLocal));
                    emitCarrierAttestationValidation(
                        pctx,
                        out,
                        plan,
                        carrierLocal,
                        targetKeyLocal,
                        carrierIndexKeyLocal,
                        tokenLocal,
                        tagLocal
                    );
                }
                emitDynamicProxyOriginalArgumentArray(
                    pctx,
                    out,
                    target.argsLocal(),
                    carrierLocal,
                    unpackedLocal,
                    plan,
                    hiddenKeyIndex >= 0 ? carrierIndexKeyLocal : -1
                );
                out.add(new JumpInsnNode(Opcodes.GOTO, done));
                out.add(next);
                emitted = true;
            }
        }
        if (!emitted) return false;
        out.add(done);
        JvmKeyDispatchPass.markGenerated(pctx, out);
        AbstractInsnNode first = firstRealInstruction(mn);
        if (first == null) {
            mn.instructions.add(out);
        } else {
            mn.instructions.insertBefore(first, out);
        }
        return true;
    }

    private static void emitDynamicProxyOuterCarrierLoad(
        InsnList out,
        int argsLocal,
        MethodPlan plan,
        int carrierLocal,
        LabelNode next
    ) {
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        out.add(new JumpInsnNode(Opcodes.IFNULL, next));
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        out.add(new InsnNode(Opcodes.ARRAYLENGTH));
        JvmPassBytecode.pushInt(out, packedOuterArgumentCount(plan));
        LabelNode lengthOk = new LabelNode();
        out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, lengthOk));
        out.add(new JumpInsnNode(Opcodes.GOTO, next));
        out.add(lengthOk);
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        JvmPassBytecode.pushInt(out, 0);
        out.add(new InsnNode(Opcodes.AALOAD));
        out.add(new TypeInsnNode(Opcodes.INSTANCEOF, "[Ljava/lang/Object;"));
        LabelNode carrierOk = new LabelNode();
        out.add(new JumpInsnNode(Opcodes.IFNE, carrierOk));
        out.add(new JumpInsnNode(Opcodes.GOTO, next));
        out.add(carrierOk);
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        JvmPassBytecode.pushInt(out, 0);
        out.add(new InsnNode(Opcodes.AALOAD));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
        out.add(new VarInsnNode(Opcodes.ASTORE, carrierLocal));
    }

    private void emitDynamicProxyOriginalArgumentArray(
        PipelineContext pctx,
        InsnList out,
        int argsLocal,
        int carrierLocal,
        int unpackedLocal,
        MethodPlan plan,
        int carrierIndexKeyLocal
    ) {
        Type[] visibleArgs = visibleArgumentTypes(plan);
        if (visibleArgs.length == 0) {
            out.add(new InsnNode(Opcodes.ACONST_NULL));
            out.add(new VarInsnNode(Opcodes.ASTORE, argsLocal));
            return;
        }
        JvmPassBytecode.pushInt(out, visibleArgs.length);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        out.add(new VarInsnNode(Opcodes.ASTORE, unpackedLocal));
        int carrierIndex = 0;
        int visibleIndex = 0;
        Type[] packedArgs = plan.argumentTypes();
        for (int i = 0; i < packedArgs.length; i++) {
            if (plan.splitHiddenKey() && isHiddenKeyArgument(plan, i)) {
                continue;
            }
            if (isHiddenKeyArgument(plan, i)) {
                carrierIndex++;
                continue;
            }
            out.add(new VarInsnNode(Opcodes.ALOAD, unpackedLocal));
            JvmPassBytecode.pushInt(out, visibleIndex++);
            emitCarrierArrayLoad(
                pctx,
                out,
                carrierLocal,
                plan,
                carrierIndex++,
                carrierIndexKeyLocal,
                false,
                plan.carrierIndexKeySeed()
            );
            out.add(new InsnNode(Opcodes.AASTORE));
        }
        out.add(new VarInsnNode(Opcodes.ALOAD, unpackedLocal));
        out.add(new VarInsnNode(Opcodes.ASTORE, argsLocal));
    }

    private void installUnpackPrologue(PipelineContext pctx, MethodNode mn, MethodPlan plan) {
        int packedArgumentLocal = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        mn.maxLocals = Math.max(mn.maxLocals, parameterLocalLimit(mn.access, plan.packedDesc()));
        if (plan.keyLocal() != null) {
            mn.maxLocals = Math.max(mn.maxLocals, plan.keyLocal() + Type.LONG_TYPE.getSize());
        }
        int argsLocal = mn.maxLocals++;
        int hiddenKeyIndex = packedHiddenKeyArgumentIndex(plan);
        Integer incomingKeyTemp = null;
        if (hiddenKeyIndex >= 0) {
            incomingKeyTemp = mn.maxLocals;
            mn.maxLocals += 2;
        }
        Integer methodKeyTemp = null;
        if (hiddenKeyIndex >= 0) {
            methodKeyTemp = mn.maxLocals;
            mn.maxLocals += 2;
        }
        Integer carrierIndexKeyTemp = null;
        if (hiddenKeyIndex >= 0) {
            carrierIndexKeyTemp = mn.maxLocals;
            mn.maxLocals += 2;
        }
        Integer attestationTokenTemp = null;
        if (hiddenKeyIndex >= 0) {
            attestationTokenTemp = mn.maxLocals;
            mn.maxLocals += 2;
        }
        Integer attestationTagTemp = null;
        if (hiddenKeyIndex >= 0) {
            attestationTagTemp = mn.maxLocals;
            mn.maxLocals += 2;
        }
        InsnList prologue = new InsnList();
        if (plan.splitHiddenKey() && incomingKeyTemp != null) {
            int primitiveKeyLocal = packedArgumentLocal + 1;
            prologue.add(new VarInsnNode(Opcodes.LLOAD, primitiveKeyLocal));
            prologue.add(new VarInsnNode(Opcodes.LSTORE, incomingKeyTemp));
        }
        prologue.add(new VarInsnNode(Opcodes.ALOAD, packedArgumentLocal));
        prologue.add(new VarInsnNode(Opcodes.ASTORE, argsLocal));
        if (hiddenKeyIndex >= 0) {
            emitCarrierShapeValidation(prologue, argsLocal, plan);
        }
        if (hiddenKeyIndex >= 0 && carrierIndexKeyTemp != null) {
            emitCarrierArrayLoadSafe(
                pctx,
                prologue,
                argsLocal,
                plan,
                carrierIndexKeyLogicalIndex(plan),
                -1,
                false,
                plan.carrierIndexKeySeed()
            );
            emitUnboxOrCast(prologue, Type.LONG_TYPE);
            prologue.add(new VarInsnNode(Opcodes.LSTORE, carrierIndexKeyTemp));
        }
        if (!plan.splitHiddenKey() && hiddenKeyIndex >= 0 && incomingKeyTemp != null) {
            emitCarrierArrayLoad(
                pctx,
                prologue,
                argsLocal,
                plan,
                hiddenKeyIndex,
                carrierIndexKeyTemp == null ? -1 : carrierIndexKeyTemp,
                false,
                plan.carrierIndexKeySeed()
            );
            emitUnboxOrCast(prologue, Type.LONG_TYPE);
            prologue.add(new VarInsnNode(Opcodes.LSTORE, incomingKeyTemp));
        }
        if (hiddenKeyIndex >= 0
            && incomingKeyTemp != null
            && carrierIndexKeyTemp != null
            && attestationTokenTemp != null
            && attestationTagTemp != null) {
            emitCarrierAttestationValidation(
                pctx,
                prologue,
                plan,
                argsLocal,
                incomingKeyTemp,
                carrierIndexKeyTemp,
                attestationTokenTemp,
                attestationTagTemp
            );
        }
        if (incomingKeyTemp != null && methodKeyTemp != null) {
            JvmKeyDispatchPass.emitIncomingKeyMix(
                prologue,
                incomingKeyTemp,
                methodKeyTemp,
                seedForPlan(pctx, plan),
                JvmKeyDispatchPass.INCOMING_KEY_MIX_MASK
            );
        }
        int carrierIndex = 0;
        for (int i = 0; i < plan.argumentTypes().length; i++) {
            Type type = plan.argumentTypes()[i];
            int targetLocal = plan.argumentLocals()[i];
            if (plan.splitHiddenKey() && i == hiddenKeyIndex) {
                continue;
            }
            if (!plan.splitHiddenKey() && i == hiddenKeyIndex) {
                carrierIndex++;
                continue;
            }
            emitCarrierArrayLoad(
                pctx,
                prologue,
                argsLocal,
                plan,
                carrierIndex++,
                carrierIndexKeyTemp == null ? -1 : carrierIndexKeyTemp,
                false,
                plan.carrierIndexKeySeed()
            );
            int storeLocal = i == hiddenKeyIndex ? incomingKeyTemp : targetLocal;
            emitUnboxOrCast(prologue, type);
            prologue.add(new VarInsnNode(type.getOpcode(Opcodes.ISTORE), storeLocal));
        }
        List<AbstractInsnNode> prologueNodes = instructionNodes(prologue);
        AbstractInsnNode first = firstRealInstruction(mn);
        if (first == null) {
            mn.instructions.add(prologue);
        } else {
            mn.instructions.insertBefore(first, prologue);
        }
        if (incomingKeyTemp != null) {
            int activeKeyLocal = methodKeyTemp == null ? incomingKeyTemp : methodKeyTemp;
            if (plan.keyLocal() != null) {
                rewriteFirstKeyDispatchLoad(pctx, mn, plan, plan.keyLocal(), incomingKeyTemp, activeKeyLocal);
            }
            rewriteGeneratedKeyLocalLoads(pctx, mn, plan.keyLocal(), activeKeyLocal);
            JvmKeyDispatchPass.recordMethodKeyLocal(pctx, finalKey(plan), activeKeyLocal, seedForPlan(pctx, plan));
        }
        markGeneratedNodes(pctx, prologueNodes);
    }

    private static int packedHiddenKeyArgumentIndex(MethodPlan plan) {
        int byLocal = hiddenKeyArgumentIndex(plan.argumentTypes(), plan.argumentLocals(), plan.keyLocal());
        if (byLocal >= 0) return byLocal;
        if (plan.syntheticHiddenKey()
            && plan.argumentTypes().length > 0
            && Type.LONG_TYPE.equals(plan.argumentTypes()[plan.argumentTypes().length - 1])) {
            return plan.argumentTypes().length - 1;
        }
        if (!plan.hasCode()
            && plan.argumentTypes().length > 0
            && Type.LONG_TYPE.equals(plan.argumentTypes()[plan.argumentTypes().length - 1])) {
            return plan.argumentTypes().length - 1;
        }
        return -1;
    }

    private static int hiddenKeyArgumentIndex(Type[] argumentTypes, int[] argumentLocals, Integer keyLocal) {
        if (keyLocal == null) return -1;
        for (int i = 0; i < argumentLocals.length; i++) {
            if (argumentLocals[i] == keyLocal
                && Type.LONG_TYPE.equals(argumentTypes[i])) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isPackedDescriptor(MethodPlan plan, String desc) {
        if (!plan.packedDesc().equals(desc)) return false;
        Type[] args = Type.getArgumentTypes(desc);
        return args.length >= 1 && OBJECT_ARRAY_TYPE.equals(args[0]);
    }

    private static boolean canUseSplitHiddenKeyAbi(L1Class clazz, MethodNode mn) {
        return (mn.access & Opcodes.ACC_STATIC) != 0
            || (mn.access & Opcodes.ACC_PRIVATE) != 0;
    }

    private static int carrierArgumentCount(MethodPlan plan) {
        return carrierValueCount(plan) + (packedHiddenKeyArgumentIndex(plan) >= 0 ? 3 : 0);
    }

    private static int carrierValueCount(MethodPlan plan) {
        return plan.argumentTypes().length - (plan.splitHiddenKey() ? 1 : 0);
    }

    private static int carrierIndexKeyLogicalIndex(MethodPlan plan) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) {
            throw new IllegalStateException(
                "Carrier index key requires hidden key metadata for " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        return carrierValueCount(plan);
    }

    private static int carrierAttestationTokenLogicalIndex(MethodPlan plan) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) {
            throw new IllegalStateException(
                "Carrier attestation token requires hidden key metadata for " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        return carrierValueCount(plan) + 1;
    }

    private static int carrierAttestationTagLogicalIndex(MethodPlan plan) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) {
            throw new IllegalStateException(
                "Carrier attestation tag requires hidden key metadata for " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        return carrierValueCount(plan) + 2;
    }

    private static void rewriteFirstKeyDispatchLoad(
        PipelineContext pctx,
        MethodNode mn,
        MethodPlan plan,
        int keyLocal,
        int incomingKeyTemp,
        int activeKeyLocal
    ) {
        long seed = seedForPlan(pctx, plan);
        int scanned = 0;
        for (
            AbstractInsnNode insn = mn.instructions.getFirst();
            insn != null && scanned++ < 128;
            insn = insn.getNext()
        ) {
            if (!JvmKeyDispatchPass.isGeneratedNode(pctx, insn)) continue;
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.LLOAD && var.var == keyLocal) {
                var.var = activeKeyLocal;
                return;
            }
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.LSTORE && var.var == keyLocal) {
                if (replaceStaticKeyInit(pctx, mn, insn, incomingKeyTemp, activeKeyLocal, seed)) {
                    return;
                }
                InsnList mix = new InsnList();
                mix.add(new InsnNode(Opcodes.POP2));
                JvmKeyDispatchPass.emitIncomingKeyMix(
                    mix,
                    incomingKeyTemp,
                    activeKeyLocal,
                    seed,
                    JvmKeyDispatchPass.INCOMING_KEY_MIX_MASK
                );
                JvmKeyDispatchPass.markGenerated(pctx, mix);
                mn.instructions.insertBefore(insn, mix);
                mn.instructions.remove(insn);
                return;
            }
        }
    }

    private static void rewriteGeneratedKeyLocalLoads(
        PipelineContext pctx,
        MethodNode mn,
        Integer keyLocal,
        int incomingKeyTemp
    ) {
        if (keyLocal == null) return;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!JvmKeyDispatchPass.isGeneratedNode(pctx, insn)) continue;
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.LLOAD && var.var == keyLocal) {
                var.var = incomingKeyTemp;
            }
        }
    }

    private static boolean replaceStaticKeyInit(
        PipelineContext pctx,
        MethodNode mn,
        AbstractInsnNode store,
        int incomingKeyTemp,
        int activeKeyLocal,
        long seed
    ) {
        AbstractInsnNode xor = previousReal(store.getPrevious());
        AbstractInsnNode mask = xor == null ? null : previousReal(xor.getPrevious());
        AbstractInsnNode encoded = mask == null ? null : previousReal(mask.getPrevious());
        if (xor == null || mask == null || encoded == null) return false;
        if (xor.getOpcode() != Opcodes.LXOR) return false;
        if (!isLongPush(encoded) || !isLongPush(mask)) return false;

        InsnList mix = new InsnList();
        JvmKeyDispatchPass.emitIncomingKeyMix(
            mix,
            incomingKeyTemp,
            activeKeyLocal,
            seed,
            JvmKeyDispatchPass.INCOMING_KEY_MIX_MASK
        );
        JvmKeyDispatchPass.markGenerated(pctx, mix);
        mn.instructions.insertBefore(encoded, mix);
        mn.instructions.remove(encoded);
        mn.instructions.remove(mask);
        mn.instructions.remove(xor);
        mn.instructions.remove(store);
        return true;
    }

    private static boolean isLongPush(AbstractInsnNode insn) {
        if (insn == null) return false;
        int opcode = insn.getOpcode();
        return opcode == Opcodes.LCONST_0 ||
            opcode == Opcodes.LCONST_1 ||
            (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Long);
    }

    private static AbstractInsnNode previousReal(AbstractInsnNode start) {
        for (AbstractInsnNode insn = start; insn != null; insn = insn.getPrevious()) {
            if (insn.getOpcode() >= 0) return insn;
        }
        return null;
    }

    private Integer callerKeyLocal(PipelineContext pctx, L1Class clazz, MethodNode mn) {
        return JvmKeyDispatchPass.findMethodKeyLocal(pctx, key(clazz.name(), mn.name, mn.desc));
    }

    private static boolean rewriteStaticVoidTailSelfRecursion(
        PipelineContext pctx,
        MethodNode mn,
        MethodPlan plan
    ) {
        if ((mn.access & Opcodes.ACC_STATIC) == 0) return false;
        if (!Type.VOID_TYPE.equals(Type.getReturnType(plan.oldDesc()))) return false;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return false;

        AbstractInsnNode bodyStart = firstApplicationInstruction(pctx, mn, plan.keyLocal());
        if (bodyStart == null) return false;
        LabelNode loopStart = new LabelNode();
        mn.instructions.insertBefore(bodyStart, loopStart);
        mn.instructions.insert(loopStart, new InsnNode(Opcodes.NOP));

        boolean changed = false;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof MethodInsnNode call)) continue;
            if (call.getOpcode() != Opcodes.INVOKESTATIC) continue;
            if (!plan.owner().equals(call.owner) ||
                !plan.oldName().equals(call.name) ||
                !plan.oldDesc().equals(call.desc)) {
                continue;
            }
            AbstractInsnNode next = nextRealInstruction(call.getNext());
            if (next == null || next.getOpcode() != Opcodes.RETURN) continue;

            InsnList replacement = new InsnList();
            Type[] args = plan.argumentTypes();
            int[] locals = plan.argumentLocals();
            for (int i = args.length - 1; i >= 0; i--) {
                replacement.add(new VarInsnNode(args[i].getOpcode(Opcodes.ISTORE), locals[i]));
            }
            replacement.add(new JumpInsnNode(Opcodes.GOTO, loopStart));
            mn.instructions.insertBefore(call, replacement);
            mn.instructions.remove(call);
            changed = true;
        }
        return changed;
    }

    private static AbstractInsnNode firstApplicationInstruction(
        PipelineContext pctx,
        MethodNode mn,
        Integer keyLocal
    ) {
        boolean afterKeyInit = keyLocal == null;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (
                !afterKeyInit &&
                insn instanceof VarInsnNode var &&
                var.getOpcode() == Opcodes.LSTORE &&
                var.var == keyLocal
            ) {
                afterKeyInit = true;
                continue;
            }
            if (!afterKeyInit) continue;
            if (insn.getOpcode() < 0) continue;
            if (JvmKeyDispatchPass.isGeneratedNode(pctx, insn)) continue;
            return insn;
        }
        return null;
    }

    private static AbstractInsnNode nextRealInstruction(AbstractInsnNode insn) {
        for (AbstractInsnNode scan = insn; scan != null; scan = scan.getNext()) {
            if (scan.getOpcode() >= 0) return scan;
        }
        return null;
    }

    private boolean rewriteCallsites(PipelineContext pctx, L1Class callerClass, MethodNode mn, Integer callerKeyLocal) {
        boolean changed = false;
        Map<MethodInsnNode, List<MethodPlan>> precomputedReflectiveInvokeCandidates =
            precomputeRuntimeReflectiveInvokeCandidates(pctx, callerClass.name(), mn);
        Map<MethodInsnNode, List<MethodPlan>> precomputedReflectiveConstructorCandidates =
            precomputeRuntimeReflectiveConstructorCandidates(pctx, callerClass.name(), mn);
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (insn instanceof InvokeDynamicInsnNode indy) {
                rewriteInvokeDynamic(pctx, indy);
                continue;
            }
            if (!(insn instanceof MethodInsnNode call)) continue;
            if (rewriteMethodHandleLookup(pctx, mn, call)) {
                changed = true;
                callerClass.markDirty();
                continue;
            }
            if (rewriteMethodHandleInvoke(pctx, callerClass.name(), mn, call, callerKeyLocal)) {
                changed = true;
                callerClass.markDirty();
                continue;
            }
            if (rewriteReflectionCall(
                pctx,
                callerClass.name(),
                mn,
                call,
                callerKeyLocal,
                precomputedReflectiveInvokeCandidates,
                precomputedReflectiveConstructorCandidates
            )) {
                changed = true;
                callerClass.markDirty();
                continue;
            }
            MethodPlan plan = resolvePlan(pctx, call.owner, call.name, call.desc);
            if (plan == null) continue;
            cffPackedCallTargetSeeds(pctx).put(
                JvmKeyDispatchPass.coverageKey(call.owner, plan.finalName(), plan.packedDesc()),
                seedForPlan(pctx, plan)
            );
            long siteSeed = carrierAttestationSiteSeedOrZero(pctx, plan, callerClass.name(), mn, call, "direct");
            InsnList pack = packCallArguments(pctx, mn, plan, callerKeyLocal, siteSeed);
            call.name = plan.finalName();
            call.desc = plan.packedDesc();
            mn.instructions.insertBefore(call, pack);
            changed = true;
            callerClass.markDirty();
        }
        return changed;
    }

    private Map<MethodInsnNode, List<MethodPlan>> precomputeRuntimeReflectiveInvokeCandidates(
        PipelineContext pctx,
        String callerOwner,
        MethodNode mn
    ) {
        Map<MethodInsnNode, List<MethodPlan>> candidates = new IdentityHashMap<>();
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof MethodInsnNode call)) continue;
            if (!"java/lang/reflect/Method".equals(call.owner)
                || !"invoke".equals(call.name)
                || !"(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) {
                continue;
            }
            List<MethodPlan> runtime = runtimeReflectiveInvokeCandidates(pctx, callerOwner, mn, call);
            candidates.put(call, List.copyOf(runtime));
        }
        return candidates;
    }

    private Map<MethodInsnNode, List<MethodPlan>> precomputeRuntimeReflectiveConstructorCandidates(
        PipelineContext pctx,
        String callerOwner,
        MethodNode mn
    ) {
        Map<MethodInsnNode, List<MethodPlan>> candidates = new IdentityHashMap<>();
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!(insn instanceof MethodInsnNode call)) continue;
            if (!"java/lang/reflect/Constructor".equals(call.owner)
                || !"newInstance".equals(call.name)
                || !"([Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) {
                continue;
            }
            List<MethodPlan> runtime = runtimeReflectiveConstructorInvokeCandidates(pctx, callerOwner, mn, call);
            candidates.put(call, List.copyOf(runtime));
        }
        return candidates;
    }

    private boolean rewriteMethodHandleLookup(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        if (!isMethodHandleLookup(call)) return false;
        MethodHandleLookupTarget target = sourceMethodHandleLookupTarget(pctx, mn, call);
        MethodPlan plan = target == null ? null : resolveExactMethodHandleLookupPlan(pctx, target);
        if (plan == null) return false;
        methodHandleLookupTargets(pctx).put(call, target);
        boolean specialLookup = "findSpecial".equals(target.lookupKind());
        boolean constructorLookup = "findConstructor".equals(target.lookupKind());
        if (!specialLookup) {
            InsnList before = new InsnList();
            before.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/invoke/MethodType",
                "returnType",
                "()Ljava/lang/Class;",
                false
            ));
            emitParameterTypes(before, Type.getArgumentTypes(plan.packedDesc()));
            before.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/invoke/MethodType",
                "methodType",
                "(Ljava/lang/Class;[Ljava/lang/Class;)Ljava/lang/invoke/MethodType;",
                false
            ));
            JvmKeyDispatchPass.markGenerated(pctx, before);
            mn.instructions.insertBefore(call, before);
            return true;
        }
        int specialCallerLocal = specialLookup ? allocateLocal(mn, Type.getType(Class.class)) : -1;
        int methodTypeLocal = allocateLocal(mn, Type.getType("Ljava/lang/invoke/MethodType;"));
        int nameLocal = constructorLookup ? -1 : allocateLocal(mn, Type.getType(String.class));
        int classLocal = allocateLocal(mn, Type.getType(Class.class));
        InsnList before = new InsnList();
        if (specialLookup) {
            before.add(new VarInsnNode(Opcodes.ASTORE, specialCallerLocal));
        }
        before.add(new VarInsnNode(Opcodes.ASTORE, methodTypeLocal));
        if (!constructorLookup) {
            before.add(new VarInsnNode(Opcodes.ASTORE, nameLocal));
        }
        before.add(new VarInsnNode(Opcodes.ASTORE, classLocal));
        before.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        if (!constructorLookup) {
            before.add(new VarInsnNode(Opcodes.ALOAD, nameLocal));
        }
        before.add(new VarInsnNode(Opcodes.ALOAD, methodTypeLocal));
        before.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/invoke/MethodType",
            "returnType",
            "()Ljava/lang/Class;",
            false
        ));
        emitParameterTypes(before, Type.getArgumentTypes(plan.packedDesc()));
        before.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/invoke/MethodType",
            "methodType",
            "(Ljava/lang/Class;[Ljava/lang/Class;)Ljava/lang/invoke/MethodType;",
            false
        ));
        if (specialLookup) {
            before.add(new VarInsnNode(Opcodes.ALOAD, specialCallerLocal));
        }
        JvmKeyDispatchPass.markGenerated(pctx, before);
        mn.instructions.insertBefore(call, before);
        return true;
    }

    private static void emitClassConstant(InsnList out, Type type) {
        String primitiveOwner = switch (type.getSort()) {
            case Type.BOOLEAN -> "java/lang/Boolean";
            case Type.CHAR -> "java/lang/Character";
            case Type.BYTE -> "java/lang/Byte";
            case Type.SHORT -> "java/lang/Short";
            case Type.INT -> "java/lang/Integer";
            case Type.FLOAT -> "java/lang/Float";
            case Type.LONG -> "java/lang/Long";
            case Type.DOUBLE -> "java/lang/Double";
            case Type.VOID -> "java/lang/Void";
            default -> null;
        };
        if (primitiveOwner != null) {
            out.add(new FieldInsnNode(Opcodes.GETSTATIC, primitiveOwner, "TYPE", "Ljava/lang/Class;"));
            return;
        }
        out.add(new LdcInsnNode(type));
    }

    private boolean rewriteMethodHandleInvoke(
        PipelineContext pctx,
        String callerOwner,
        MethodNode mn,
        MethodInsnNode call,
        Integer callerKeyLocal
    ) {
        if (!"java/lang/invoke/MethodHandle".equals(call.owner)
            || (!"invoke".equals(call.name) && !"invokeExact".equals(call.name))) {
            return false;
        }
        MethodHandleRewriteTarget target = sourceMethodHandleRewriteTarget(pctx, mn, call);
        if (target == null) {
            return rewriteRuntimeMethodHandleInvoke(pctx, callerOwner, mn, call, callerKeyLocal);
        }
        MethodPlan plan = target.plan();
        Type[] args = Type.getArgumentTypes(call.desc);
        if (isPackedDescriptor(plan, call.desc)) return false;
        String attestationKind = methodHandleAttestationSiteKind(pctx, plan, call);
        Type returnType = Type.getReturnType(call.desc);
        boolean receiverHandle = methodHandleHasReceiver(target.lookupKind());
        int[] locals = new int[args.length];
        for (int i = args.length - 1; i >= 0; i--) {
            locals[i] = allocateLocal(mn, args[i]);
        }
        InsnList before = new InsnList();
        for (int i = args.length - 1; i >= 0; i--) {
            before.add(new VarInsnNode(args[i].getOpcode(Opcodes.ISTORE), locals[i]));
        }
        CarrierCallsiteKeys carrierKeys = materializeCarrierCallsiteKeys(
            pctx,
            mn,
            before,
            plan,
            callerKeyLocal,
            attestationKind
        );
        if (receiverHandle) {
            if (args.length == 0 || (args[0].getSort() != Type.OBJECT && args[0].getSort() != Type.ARRAY)) {
                throw new IllegalStateException(
                    "MethodHandle " + target.lookupKind() + " target has no receiver argument for " +
                        plan.owner() + "." + plan.finalName() + plan.packedDesc()
                );
            }
            before.add(new VarInsnNode(args[0].getOpcode(Opcodes.ILOAD), locals[0]));
        }
        Type[] packedArgs = plan.argumentTypes();
        JvmPassBytecode.pushInt(before, carrierArgumentCount(plan));
        before.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        emitCarrierIndexKeyStore(pctx, before, plan, callerKeyLocal, carrierKeys, attestationKind);
        emitCarrierAttestationStores(
            pctx,
            before,
            plan,
            callerKeyLocal,
            carrierKeys,
            carrierAttestationSiteSeedOrZero(pctx, plan, callerOwner, mn, call, attestationKind),
            attestationKind
        );
        int sourceIndex = receiverHandle ? 1 : 0;
        int carrierIndex = 0;
        for (int i = 0; i < packedArgs.length; i++) {
            if (plan.splitHiddenKey() && isHiddenKeyArgument(plan, i)) {
                continue;
            }
            before.add(new InsnNode(Opcodes.DUP));
            emitBoundedCarrierIndexForArrayOnStack(
                pctx,
                before,
                plan,
                carrierIndex++,
                carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
                carrierKeys == null,
                plan.carrierIndexKeySeed()
            );
            if (isHiddenKeyArgument(plan, i)) {
                if (callerKeyLocal == null) {
                    throw new IllegalStateException(
                        "Missing caller key for methodParameterObfuscation MethodHandle target " +
                        plan.owner() + "." + plan.finalName() + plan.packedDesc()
                    );
                }
                before.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.targetKeyLocal()));
            } else {
                if (sourceIndex >= args.length) {
                    throw new IllegalStateException(
                        "Cannot map MethodHandle.invoke argument " + sourceIndex + " for " +
                            plan.owner() + "." + plan.finalName() + plan.packedDesc()
                    );
                }
                before.add(new VarInsnNode(args[sourceIndex].getOpcode(Opcodes.ILOAD), locals[sourceIndex]));
                sourceIndex++;
            }
            emitBox(before, packedArgs[i]);
            before.add(new InsnNode(Opcodes.AASTORE));
        }
        if (plan.splitHiddenKey()) {
            if (callerKeyLocal == null) {
                throw new IllegalStateException(
                    "Missing caller key for methodParameterObfuscation MethodHandle target " +
                        plan.owner() + "." + plan.finalName() + plan.packedDesc()
                );
            }
            VarInsnNode keyLoad = new VarInsnNode(Opcodes.LLOAD, callerKeyLocal);
            if (carrierKeys == null) {
                before.add(keyLoad);
                cffKeyLoadTargetSeeds(pctx).put(keyLoad, seedForPlan(pctx, plan));
            } else {
                before.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.targetKeyLocal()));
            }
            call.desc = methodHandlePackedInvokeDescriptor(returnType, receiverHandle ? args[0] : null, plan);
        } else {
            call.desc = methodHandlePackedInvokeDescriptor(returnType, receiverHandle ? args[0] : null, plan);
        }
        emitPackedSuffixArguments(pctx, before, plan, callerKeyLocal, attestationKind);
        JvmKeyDispatchPass.markGenerated(pctx, before);
        mn.instructions.insertBefore(call, before);
        return true;
    }

    private boolean rewriteRuntimeMethodHandleInvoke(
        PipelineContext pctx,
        String callerOwner,
        MethodNode mn,
        MethodInsnNode call,
        Integer callerKeyLocal
    ) {
        if (callerKeyLocal == null) return false;
        List<MethodHandleRuntimeCandidate> candidates = methodHandleRuntimeInvokeCandidates(pctx, call.desc);
        if (candidates.isEmpty()) return false;

        Type[] args = Type.getArgumentTypes(call.desc);
        Type returnType = Type.getReturnType(call.desc);
        int[] locals = new int[args.length];
        for (int i = args.length - 1; i >= 0; i--) {
            locals[i] = allocateLocal(mn, args[i]);
        }
        int handleLocal = allocateLocal(mn, Type.getType("Ljava/lang/invoke/MethodHandle;"));
        int infoLocal = allocateLocal(mn, Type.getType("Ljava/lang/invoke/MethodHandleInfo;"));
        List<Type> stackPrefixTypes = stackPrefixTypes(mn, call, args.length + 1);
        int[] stackPrefixLocals = allocateStackPrefixLocals(mn, stackPrefixTypes);

        InsnList before = new InsnList();
        for (int i = args.length - 1; i >= 0; i--) {
            before.add(new VarInsnNode(args[i].getOpcode(Opcodes.ISTORE), locals[i]));
        }
        before.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        storeStackPrefix(before, stackPrefixTypes, stackPrefixLocals);

        LabelNode done = new LabelNode();
        for (MethodHandleRuntimeCandidate candidate : candidates) {
            LabelNode next = new LabelNode();
            emitRuntimeMethodHandleMatch(mn, before, candidate, handleLocal, infoLocal, returnType, next);
            emitRuntimeMethodHandlePackedInvoke(
                pctx,
                before,
                callerOwner,
                mn,
                call,
                candidate,
                args,
                locals,
                handleLocal,
                stackPrefixTypes,
                stackPrefixLocals,
                callerKeyLocal
            );
            before.add(new JumpInsnNode(Opcodes.GOTO, done));
            before.add(next);
        }

        loadStackPrefix(before, stackPrefixTypes, stackPrefixLocals);
        before.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        for (int i = 0; i < args.length; i++) {
            before.add(new VarInsnNode(args[i].getOpcode(Opcodes.ILOAD), locals[i]));
        }
        JvmKeyDispatchPass.markGenerated(pctx, before);
        mn.instructions.insertBefore(call, before);
        mn.instructions.insert(call, done);
        return true;
    }

    private static boolean methodHandleHasReceiver(String lookupKind) {
        return "findVirtual".equals(lookupKind) || "findSpecial".equals(lookupKind);
    }

    private static String methodHandlePackedInvokeDescriptor(Type returnType, Type receiverType, MethodPlan plan) {
        List<Type> args = new ArrayList<>();
        if (receiverType != null) args.add(receiverType);
        for (Type packedArg : Type.getArgumentTypes(plan.packedDesc())) {
            args.add(packedArg);
        }
        return Type.getMethodDescriptor(returnType, args.toArray(Type[]::new));
    }

    private List<MethodHandleRuntimeCandidate> methodHandleRuntimeInvokeCandidates(PipelineContext pctx, String invokeDesc) {
        Type[] invokeArgs = Type.getArgumentTypes(invokeDesc);
        Type invokeReturn = Type.getReturnType(invokeDesc);
        List<MethodHandleRuntimeCandidate> candidates = new ArrayList<>();
        Set<String> seen = new java.util.LinkedHashSet<>();
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if (packedHiddenKeyArgumentIndex(plan) < 0) continue;
            Type expectedReturn = "<init>".equals(plan.oldName())
                ? Type.getObjectType(plan.owner())
                : Type.getReturnType(plan.oldDesc());
            if (!expectedReturn.equals(invokeReturn)) continue;
            Type[] visiblePlanArgs = visibleArgumentTypes(plan);
            if (sameTypes(invokeArgs, visiblePlanArgs)) {
                String key = finalKey(plan) + "#static";
                if (seen.add(key)) {
                    candidates.add(new MethodHandleRuntimeCandidate(plan, null));
                }
            }
            if (invokeArgs.length == visiblePlanArgs.length + 1
                && isReferenceType(invokeArgs[0])
                && receiverCompatible(pctx, invokeArgs[0], plan.owner())
                && sameTypes(invokeArgs, 1, visiblePlanArgs)) {
                String key = finalKey(plan) + "#" + invokeArgs[0].getDescriptor();
                if (seen.add(key)) {
                    candidates.add(new MethodHandleRuntimeCandidate(plan, invokeArgs[0]));
                }
            }
        }
        return candidates;
    }

    private static boolean sameTypes(Type[] left, Type[] right) {
        return sameTypes(left, 0, right);
    }

    private static boolean sameTypes(Type[] left, int leftOffset, Type[] right) {
        if (left.length - leftOffset != right.length) return false;
        for (int i = 0; i < right.length; i++) {
            if (!left[leftOffset + i].equals(right[i])) return false;
        }
        return true;
    }

    private static boolean isReferenceType(Type type) {
        return type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY;
    }

    private static Type[] visibleArgumentTypes(MethodPlan plan) {
        List<Type> visible = new ArrayList<>();
        Type[] args = plan.argumentTypes();
        for (int i = 0; i < args.length; i++) {
            if (isHiddenKeyArgument(plan, i)) continue;
            visible.add(args[i]);
        }
        return visible.toArray(Type[]::new);
    }

    private static boolean matchesVisibleOrPackedArguments(MethodPlan plan, Type[] argumentTypes) {
        return sameTypes(visibleArgumentTypes(plan), argumentTypes)
            || sameTypes(Type.getArgumentTypes(plan.packedDesc()), argumentTypes);
    }

    private static boolean receiverCompatible(PipelineContext pctx, Type receiverType, String owner) {
        if (receiverType.getSort() != Type.OBJECT) return false;
        String receiver = receiverType.getInternalName();
        return receiver.equals(owner) || isSubtypeOf(pctx, pctx.classMap().get(receiver), owner);
    }

    private void emitRuntimeMethodHandlePackedInvoke(
        PipelineContext pctx,
        InsnList out,
        String callerOwner,
        MethodNode mn,
        MethodInsnNode originalCall,
        MethodHandleRuntimeCandidate candidate,
        Type[] invokeArgs,
        int[] locals,
        int handleLocal,
        List<Type> stackPrefixTypes,
        int[] stackPrefixLocals,
        Integer callerKeyLocal
    ) {
        MethodPlan plan = candidate.plan();
        Type receiverType = candidate.receiverType();
        String attestationKind = methodHandleAttestationSiteKind(pctx, plan, originalCall);
        CarrierCallsiteKeys carrierKeys = materializeCarrierCallsiteKeys(
            pctx,
            mn,
            out,
            plan,
            callerKeyLocal,
            attestationKind
        );
        loadStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
        out.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        if (receiverType != null) {
            out.add(new VarInsnNode(invokeArgs[0].getOpcode(Opcodes.ILOAD), locals[0]));
        }
        JvmPassBytecode.pushInt(out, carrierArgumentCount(plan));
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        emitCarrierIndexKeyStore(pctx, out, plan, callerKeyLocal, carrierKeys, attestationKind);
        emitCarrierAttestationStores(
            pctx,
            out,
            plan,
            callerKeyLocal,
            carrierKeys,
            carrierAttestationSiteSeedOrZero(pctx, plan, callerOwner, mn, originalCall, attestationKind),
            attestationKind
        );
        int sourceIndex = receiverType == null ? 0 : 1;
        int carrierIndex = 0;
        for (int i = 0; i < plan.argumentTypes().length; i++) {
            Type planArg = plan.argumentTypes()[i];
            if (plan.splitHiddenKey() && isHiddenKeyArgument(plan, i)) {
                continue;
            }
            out.add(new InsnNode(Opcodes.DUP));
            emitBoundedCarrierIndexForArrayOnStack(
                pctx,
                out,
                plan,
                carrierIndex++,
                carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
                carrierKeys == null,
                plan.carrierIndexKeySeed()
            );
            if (isHiddenKeyArgument(plan, i)) {
                out.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.targetKeyLocal()));
            } else {
                out.add(new VarInsnNode(invokeArgs[sourceIndex].getOpcode(Opcodes.ILOAD), locals[sourceIndex]));
                sourceIndex++;
            }
            emitBox(out, planArg);
            out.add(new InsnNode(Opcodes.AASTORE));
        }
        if (plan.splitHiddenKey()) {
            if (carrierKeys == null) {
                VarInsnNode keyLoad = new VarInsnNode(Opcodes.LLOAD, callerKeyLocal);
                out.add(keyLoad);
                cffKeyLoadTargetSeeds(pctx).put(keyLoad, seedForPlan(pctx, plan));
            } else {
                out.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.targetKeyLocal()));
            }
        }
        emitPackedSuffixArguments(pctx, out, plan, callerKeyLocal, attestationKind);
        out.add(new MethodInsnNode(
            originalCall.getOpcode(),
            originalCall.owner,
            originalCall.name,
                methodHandlePackedInvokeDescriptor(Type.getReturnType(originalCall.desc), receiverType, plan),
            originalCall.itf
        ));
    }

    private static void emitRuntimeMethodHandleMatch(
        MethodNode mn,
        InsnList out,
        MethodHandleRuntimeCandidate candidate,
        int handleLocal,
        int infoLocal,
        Type invokeReturn,
        LabelNode next
    ) {
        MethodPlan plan = candidate.plan();
        out.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/invoke/MethodHandle",
            "type",
            "()Ljava/lang/invoke/MethodType;",
            false
        ));
        emitMethodType(
            out,
            invokeReturn,
            methodHandlePackedParameterTypes(candidate.receiverType(), plan)
        );
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/invoke/MethodType",
            "equals",
            "(Ljava/lang/Object;)Z",
            false
        ));
        out.add(new JumpInsnNode(Opcodes.IFEQ, next));

        LabelNode revealStart = new LabelNode();
        LabelNode revealEnd = new LabelNode();
        LabelNode revealFail = new LabelNode();
        LabelNode revealDone = new LabelNode();
        out.add(revealStart);
        out.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/invoke/MethodHandles",
            "lookup",
            "()Ljava/lang/invoke/MethodHandles$Lookup;",
            false
        ));
        out.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/invoke/MethodHandles$Lookup",
            "revealDirect",
            "(Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/MethodHandleInfo;",
            false
        ));
        out.add(new VarInsnNode(Opcodes.ASTORE, infoLocal));
        out.add(revealEnd);
        out.add(new JumpInsnNode(Opcodes.GOTO, revealDone));
        out.add(revealFail);
        out.add(new InsnNode(Opcodes.POP));
        out.add(new JumpInsnNode(Opcodes.GOTO, next));
        out.add(revealDone);
        if (mn.tryCatchBlocks == null) {
            mn.tryCatchBlocks = new ArrayList<>();
        }
        mn.tryCatchBlocks.add(new TryCatchBlockNode(
            revealStart,
            revealEnd,
            revealFail,
            "java/lang/IllegalArgumentException"
        ));

        emitMethodHandleInfoOwnerFingerprintMatch(out, infoLocal, plan.owner().replace('/', '.'), next);
        emitMethodHandleInfoNameFingerprintMatch(out, infoLocal, plan.finalName(), next);

        out.add(new VarInsnNode(Opcodes.ALOAD, infoLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEINTERFACE,
            "java/lang/invoke/MethodHandleInfo",
            "getMethodType",
            "()Ljava/lang/invoke/MethodType;",
            true
        ));
        emitMethodType(out, Type.getReturnType(plan.packedDesc()), Type.getArgumentTypes(plan.packedDesc()));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/invoke/MethodType",
            "equals",
            "(Ljava/lang/Object;)Z",
            false
        ));
        out.add(new JumpInsnNode(Opcodes.IFEQ, next));
    }

    private static void emitMethodHandleInfoOwnerFingerprintMatch(
        InsnList out,
        int infoLocal,
        String expected,
        LabelNode next
    ) {
        out.add(new VarInsnNode(Opcodes.ALOAD, infoLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEINTERFACE,
            "java/lang/invoke/MethodHandleInfo",
            "getDeclaringClass",
            "()Ljava/lang/Class;",
            true
        ));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getName",
            "()Ljava/lang/String;",
            false
        ));
        emitProtectedStringEqualsGuards(out, expected, next);
    }

    private static void emitMethodHandleInfoNameFingerprintMatch(
        InsnList out,
        int infoLocal,
        String expected,
        LabelNode next
    ) {
        out.add(new VarInsnNode(Opcodes.ALOAD, infoLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEINTERFACE,
            "java/lang/invoke/MethodHandleInfo",
            "getName",
            "()Ljava/lang/String;",
            true
        ));
        emitProtectedStringEqualsGuards(out, expected, next);
    }

    private static void emitProtectedStringEqualsGuards(InsnList out, String expected, LabelNode next) {
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false));
        JvmPassBytecode.pushInt(out, expected.length());
        LabelNode lengthOk = new LabelNode();
        out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, lengthOk));
        out.add(new InsnNode(Opcodes.POP));
        out.add(new JumpInsnNode(Opcodes.GOTO, next));
        out.add(lengthOk);
        long seed = JvmPassBytecode.mix(0x50524F5445585453L, expected.length());
        seed = JvmPassBytecode.mix(seed, expected.hashCode());
        for (int i = 0; i < expected.length(); i++) {
            LabelNode charOk = new LabelNode();
            int xor = (int) JvmPassBytecode.mix(seed, 0x584F524348415200L + i);
            int mul = ((int) JvmPassBytecode.mix(seed, 0x4D554C4348415200L + i)) | 1;
            int add = (int) JvmPassBytecode.mix(seed, 0x4144444348415200L + i);
            int transformed = ((expected.charAt(i) ^ xor) * mul) + add;
            out.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(out, i);
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false));
            JvmPassBytecode.pushInt(out, xor);
            out.add(new InsnNode(Opcodes.IXOR));
            JvmPassBytecode.pushInt(out, mul);
            out.add(new InsnNode(Opcodes.IMUL));
            JvmPassBytecode.pushInt(out, add);
            out.add(new InsnNode(Opcodes.IADD));
            JvmPassBytecode.pushInt(out, transformed);
            out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, charOk));
            out.add(new InsnNode(Opcodes.POP));
            out.add(new JumpInsnNode(Opcodes.GOTO, next));
            out.add(charOk);
        }
        out.add(new InsnNode(Opcodes.POP));
    }

    private static Type[] methodHandlePackedParameterTypes(Type receiverType, MethodPlan plan) {
        List<Type> args = new ArrayList<>();
        if (receiverType != null) args.add(receiverType);
        for (Type packedArg : Type.getArgumentTypes(plan.packedDesc())) {
            args.add(packedArg);
        }
        return args.toArray(Type[]::new);
    }

    private static void emitMethodType(InsnList out, Type returnType, Type[] argumentTypes) {
        emitClassConstant(out, returnType);
        emitParameterTypes(out, argumentTypes);
        out.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/invoke/MethodType",
            "methodType",
            "(Ljava/lang/Class;[Ljava/lang/Class;)Ljava/lang/invoke/MethodType;",
            false
        ));
    }

    private MethodHandleRewriteTarget sourceMethodHandleRewriteTarget(
        PipelineContext pctx,
        MethodNode mn,
        MethodInsnNode invokeCall
    ) {
        if (mn == null || mn.instructions == null) return null;
        int index = mn.instructions.indexOf(invokeCall);
        if (index < 0) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            int argCount = Type.getArgumentTypes(invokeCall.desc).length;
            int handleIndex = frame == null ? -1 : frame.getStackSize() - argCount - 1;
            if (handleIndex < 0) return null;
            MethodHandleLookupTarget target = sourceMethodHandleLookupTarget(
                pctx,
                mn,
                frames,
                frame.getStack(handleIndex),
                0
            );
            MethodPlan plan = target == null ? null : resolveExactMethodHandleLookupPlan(pctx, target);
            return plan == null ? null : new MethodHandleRewriteTarget(plan, target.lookupKind());
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private MethodHandleLookupTarget sourceMethodHandleLookupTarget(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 6) return null;
        MethodHandleLookupTarget result = null;
        for (AbstractInsnNode insn : value.insns) {
            MethodHandleLookupTarget sourced = null;
            if (insn instanceof MethodInsnNode call && isMethodHandleLookup(call)) {
                sourced = sourceMethodHandleLookupTarget(pctx, mn, frames, call);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceMethodHandleLookupTarget(
                    pctx,
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    depth + 1
                );
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceMethodHandleLookupTarget(
                            pctx,
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private MethodPlan resolveMethodHandleLookupPlan(PipelineContext pctx, MethodHandleLookupTarget target) {
        if ("<init>".equals(target.name())) {
            if (target.owner() == null) return null;
            return resolveConstructorPlan(pctx, target.owner(), target.parameterTypes());
        }
        MethodPlan matched = null;
        for (MethodPlan plan : planByOwnerNameDesc(pctx).values()) {
            if (target.name() == null) continue;
            if (!plan.oldName().equals(target.name()) && !plan.finalName().equals(target.name())) continue;
            if (target.owner() != null && !plan.owner().equals(target.owner())) continue;
            if (target.parameterTypes() != null && !matchesVisibleOrPackedArguments(plan, target.parameterTypes())) {
                continue;
            }
            if (matched != null) return null;
            matched = plan;
        }
        return matched;
    }

    private MethodPlan resolveExactMethodHandleLookupPlan(PipelineContext pctx, MethodHandleLookupTarget target) {
        if (!hasExactLookupTarget(target)) return null;
        return resolveMethodHandleLookupPlan(pctx, target);
    }

    private static boolean hasExactLookupTarget(MethodHandleLookupTarget target) {
        return target != null
            && target.owner() != null
            && target.name() != null
            && target.parameterTypes() != null;
    }

    private void rewriteInvokeDynamic(PipelineContext pctx, InvokeDynamicInsnNode indy) {
        for (Object arg : indy.bsmArgs) {
            if (arg instanceof Handle handle && resolvePlan(pctx, handle.getOwner(), handle.getName(), handle.getDesc()) != null) {
                throw new IllegalStateException(
                    "methodParameterObfuscation cannot rewrite invokedynamic handle without adapter: " +
                        handle.getOwner() + "." + handle.getName() + handle.getDesc()
                );
            }
        }
    }

    private boolean rewriteReflectionCall(
        PipelineContext pctx,
        String callerOwner,
        MethodNode mn,
        MethodInsnNode call,
        Integer callerKeyLocal,
        Map<MethodInsnNode, List<MethodPlan>> precomputedReflectiveInvokeCandidates,
        Map<MethodInsnNode, List<MethodPlan>> precomputedReflectiveConstructorCandidates
    ) {
        if ("java/lang/Class".equals(call.owner)
            && ("getMethod".equals(call.name) || "getDeclaredMethod".equals(call.name))
            && "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;".equals(call.desc)) {
            MethodPlan plan = resolveReflectiveLookupPlan(pctx, mn, call);
            List<MethodPlan> runtimeCandidates = plan == null ? runtimeReflectiveLookupCandidates(pctx, mn, call) : List.of();
            if (plan == null && runtimeCandidates.isEmpty()) {
                return false;
            }
            InsnList before = rewriteMethodLookup(
                pctx,
                mn,
                plan,
                runtimeCandidates
            );
            mn.instructions.insertBefore(call, before);
            return true;
        }
        if ("java/lang/Class".equals(call.owner)
            && "newInstance".equals(call.name)
            && "()Ljava/lang/Object;".equals(call.desc)) {
            if (!rewriteClassNewInstance(pctx, callerOwner, mn, call, callerKeyLocal)) return false;
            return true;
        }
        if ("java/lang/Class".equals(call.owner)
            && ("getConstructor".equals(call.name) || "getDeclaredConstructor".equals(call.name))
            && "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;".equals(call.desc)) {
            MethodPlan plan = resolveReflectiveConstructorLookupPlan(pctx, mn, call);
            if (plan == null) return false;
            InsnList before = rewriteConstructorLookup(pctx, mn, plan);
            mn.instructions.insertBefore(call, before);
            return true;
        }
        if ("java/lang/reflect/Method".equals(call.owner)
            && "invoke".equals(call.name)
            && "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) {
            InsnList before = rewriteReflectiveInvoke(
                pctx,
                mn,
                callerOwner,
                call,
                true,
                resolveReflectiveInvokePlan(pctx, mn, call),
                precomputedReflectiveInvokeCandidates.getOrDefault(call, List.of()),
                callerKeyLocal,
                "reflective target"
            );
            mn.instructions.insertBefore(call, before);
            return true;
        }
                    if ("java/lang/reflect/Constructor".equals(call.owner)
                        && "newInstance".equals(call.name)
                        && "([Ljava/lang/Object;)Ljava/lang/Object;".equals(call.desc)) {
            MethodPlan plan = resolveReflectiveConstructorInvokePlan(pctx, mn, call);
            InsnList before = rewriteReflectiveInvoke(
                pctx,
                mn,
                callerOwner,
                call,
                false,
                plan,
                precomputedReflectiveConstructorCandidates.getOrDefault(call, List.of()),
                callerKeyLocal,
                "reflective constructor target"
            );
            mn.instructions.insertBefore(call, before);
            return true;
        }
        return false;
    }

    private MethodPlan resolveReflectiveLookupPlan(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        MethodHandleLookupTarget target = sourceReflectiveLookupTarget(pctx, mn, call);
        if (target == null) {
            return null;
        }
        MethodPlan plan = resolveExactMethodHandleLookupPlan(pctx, target);
        if (plan != null) {
            reflectiveMethodLookupTargets(pctx).put(call, target);
        }
        return plan;
    }

    private List<MethodPlan> runtimeReflectiveLookupCandidates(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        MethodHandleLookupTarget target = sourceReflectiveLookupTarget(pctx, mn, call);
        if (target == null || target.owner() == null) {
            return List.of();
        }
        return runtimeReflectiveLookupCandidates(pctx, target);
    }

    private List<MethodPlan> exactRuntimeReflectiveLookupCandidates(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        MethodHandleLookupTarget target = sourceReflectiveLookupTarget(pctx, mn, call);
        if (!hasExactLookupTarget(target)) return List.of();
        return runtimeReflectiveLookupCandidates(pctx, target);
    }

    private List<MethodPlan> runtimeReflectiveLookupCandidates(PipelineContext pctx, MethodHandleLookupTarget target) {
        List<MethodPlan> candidates = new ArrayList<>();
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if ("<init>".equals(plan.oldName())) continue;
            if (!target.owner().equals(plan.owner())) continue;
            if (target.name() != null
                && !plan.oldName().equals(target.name())
                && !plan.finalName().equals(target.name())) {
                continue;
            }
            if (target.parameterTypes() != null && !matchesVisibleOrPackedArguments(plan, target.parameterTypes())) continue;
            addUniquePlan(candidates, plan);
        }
        return candidates;
    }

    private MethodPlan resolveReflectiveInvokePlan(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        List<MethodPlan> candidates = reflectiveInvokeSourceCandidates(pctx, mn, call, true, 3);
        return candidates.size() == 1 ? candidates.get(0) : null;
    }

    private static MethodHandleLookupTarget sourceReflectiveConstructorLookupTarget(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        if (mn == null || mn.instructions == null) return null;
        if (pctx != null) {
            MethodHandleLookupTarget rewritten = reflectiveConstructorLookupTargets(pctx).get(call);
            if (rewritten != null) return rewritten;
        }
        int index = mn.instructions.indexOf(call);
        if (index < 0) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            if (frame == null || frame.getStackSize() < 2) return null;
            String sourced = sourceClassObjectOwner(pctx, mn, frames, frame.getStack(frame.getStackSize() - 2), 0);
            return sourced == null ? null : new MethodHandleLookupTarget(sourced, "<init>", null);
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private MethodPlan resolveReflectiveConstructorLookupPlan(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        MethodHandleLookupTarget target = sourceReflectiveConstructorLookupTarget(pctx, mn, call);
        if (target == null || target.owner() == null) return null;
        Type[] params = target.parameterTypes() == null
            ? sourceReflectiveParameterTypes(pctx, mn, call)
            : target.parameterTypes();
        if (params == null) return null;
        MethodPlan plan = resolveConstructorPlan(pctx, target.owner(), params);
        if (plan != null) {
            reflectiveConstructorLookupTargets(pctx).put(
                call,
                new MethodHandleLookupTarget(target.owner(), "<init>", target.lookupKind(), params)
            );
        }
        return plan;
    }

    private MethodPlan resolveReflectiveConstructorInvokePlan(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        List<MethodPlan> candidates = reflectiveInvokeSourceCandidates(pctx, mn, call, false, 2);
        return candidates.size() == 1 ? candidates.get(0) : null;
    }

    private MethodPlan resolveConstructorPlan(PipelineContext pctx, String owner, Type[] visibleArgs) {
        MethodPlan matched = null;
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if (!"<init>".equals(plan.oldName()) || !owner.equals(plan.owner())) continue;
            if (visibleArgs != null
                && !sameTypes(visibleArgumentTypes(plan), visibleArgs)
                && !sameTypes(Type.getArgumentTypes(plan.packedDesc()), visibleArgs)) {
                continue;
            }
            if (matched != null) return null;
            matched = plan;
        }
        return matched;
    }

    private InsnList rewriteMethodLookup(
        PipelineContext pctx,
        MethodNode mn,
        MethodPlan plan,
        List<MethodPlan> runtimeCandidates
    ) {
        int paramsLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        int nameLocal = allocateLocal(mn, Type.getType(String.class));
        int classLocal = allocateLocal(mn, Type.getType(Class.class));
        InsnList out = new InsnList();
        out.add(new VarInsnNode(Opcodes.ASTORE, paramsLocal));
        out.add(new VarInsnNode(Opcodes.ASTORE, nameLocal));
        out.add(new VarInsnNode(Opcodes.ASTORE, classLocal));
        if (plan == null && runtimeCandidates != null && !runtimeCandidates.isEmpty()) {
            LabelNode done = new LabelNode();
            for (MethodPlan candidate : runtimeCandidates) {
                LabelNode next = new LabelNode();
                out.add(new VarInsnNode(Opcodes.ALOAD, nameLocal));
                emitProtectedStringEqualsGuards(out, candidate.finalName(), next);
                if (requiresRuntimeLookupParameterGuard(runtimeCandidates, candidate)) {
                    out.add(new VarInsnNode(Opcodes.ALOAD, paramsLocal));
                    emitParameterTypeArrayEqualsGuard(out, visibleArgumentTypes(candidate), next);
                }
                out.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
                out.add(new VarInsnNode(Opcodes.ALOAD, nameLocal));
                emitParameterTypes(out, Type.getArgumentTypes(candidate.packedDesc()));
                out.add(new JumpInsnNode(Opcodes.GOTO, done));
                out.add(next);
            }
            out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/NoSuchMethodException"));
            out.add(new InsnNode(Opcodes.DUP));
            out.add(new VarInsnNode(Opcodes.ALOAD, nameLocal));
            out.add(new MethodInsnNode(
                Opcodes.INVOKESPECIAL,
                "java/lang/NoSuchMethodException",
                "<init>",
                "(Ljava/lang/String;)V",
                false
            ));
            out.add(new InsnNode(Opcodes.ATHROW));
            out.add(done);
            JvmKeyDispatchPass.markGenerated(pctx, out);
            return out;
        }
        out.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        out.add(new VarInsnNode(Opcodes.ALOAD, nameLocal));
        emitParameterTypes(out, plan == null
            ? new Type[] { OBJECT_ARRAY_TYPE }
            : Type.getArgumentTypes(plan.packedDesc()));
        JvmKeyDispatchPass.markGenerated(pctx, out);
        return out;
    }

    private static boolean requiresRuntimeLookupParameterGuard(List<MethodPlan> candidates, MethodPlan candidate) {
        int matches = 0;
        for (MethodPlan other : candidates) {
            if (candidate.finalName().equals(other.finalName()) && ++matches > 1) {
                return true;
            }
        }
        return false;
    }

    private InsnList rewriteConstructorLookup(PipelineContext pctx, MethodNode mn, MethodPlan plan) {
        int paramsLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        int classLocal = allocateLocal(mn, Type.getType(Class.class));
        InsnList out = new InsnList();
        out.add(new VarInsnNode(Opcodes.ASTORE, paramsLocal));
        out.add(new VarInsnNode(Opcodes.ASTORE, classLocal));
        out.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        emitParameterTypes(out, plan == null
            ? new Type[] { OBJECT_ARRAY_TYPE }
            : Type.getArgumentTypes(plan.packedDesc()));
        JvmKeyDispatchPass.markGenerated(pctx, out);
        return out;
    }

    private InsnList rewriteReflectiveInvoke(
        PipelineContext pctx,
        MethodNode mn,
        String callerOwner,
        MethodInsnNode call,
        boolean hasTarget,
        MethodPlan plan,
        List<MethodPlan> runtimeCandidates,
        Integer callerKeyLocal,
        String siteKind
    ) {
        int argsLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        int targetLocal = hasTarget ? allocateLocal(mn, Type.getType(Object.class)) : -1;
        int memberLocal = allocateLocal(mn, Type.getType(Object.class));
        int innerLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        int outerLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        List<Type> stackPrefixTypes = stackPrefixTypes(mn, call, hasTarget ? 3 : 2);
        int[] stackPrefixLocals = allocateStackPrefixLocals(mn, stackPrefixTypes);
        boolean runtimeCandidate = plan == null && hasHiddenKeyCandidate(runtimeCandidates);
        int runtimeCarrierTableLocal = plan != null || runtimeCandidate
            ? allocateLocal(mn, OBJECT_ARRAY_TYPE)
            : -1;
        boolean runtimeSplitCandidate = runtimeCandidate && hasSplitHiddenKeyCandidate(runtimeCandidates);
        int splitKeyLocal = (plan != null && plan.splitHiddenKey()) || runtimeSplitCandidate
            ? allocateLocal(mn, Type.getType(Object.class))
            : -1;
        int outerArityLocal = runtimeCandidate ? allocateLocal(mn, Type.INT_TYPE) : -1;
        int matchedLocal = runtimeCandidate ? allocateLocal(mn, Type.INT_TYPE) : -1;
        int[] runtimeSuffixLocals = runtimeCandidate
            ? allocateRuntimeSuffixLocals(mn, runtimeCandidates)
            : new int[0];
        InsnList out = new InsnList();
        out.add(new VarInsnNode(Opcodes.ASTORE, argsLocal));
        if (hasTarget) {
            out.add(new VarInsnNode(Opcodes.ASTORE, targetLocal));
        }
        out.add(new VarInsnNode(Opcodes.ASTORE, memberLocal));
        storeStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
        if (runtimeCandidate) {
            out.add(new InsnNode(Opcodes.ICONST_0));
            out.add(new VarInsnNode(Opcodes.ISTORE, matchedLocal));
        }
        if (runtimeCandidate) {
            JvmPassBytecode.pushInt(out, 1);
            out.add(new VarInsnNode(Opcodes.ISTORE, outerArityLocal));
        }
        initializeRuntimeSuffixLocals(out, runtimeSuffixLocals);
        if (plan == null) {
            if (runtimeCandidate) {
                emitRuntimeReflectiveCarrierSelection(
                    pctx,
                    out,
                    callerOwner,
                    mn,
                    call,
                    hasTarget,
                    memberLocal,
                    targetLocal,
                    argsLocal,
                    innerLocal,
                    splitKeyLocal,
                    outerArityLocal,
                    matchedLocal,
                    runtimeSuffixLocals,
                    runtimeCandidates,
                    callerKeyLocal,
                    runtimeCarrierTableLocal
                );
            }
        } else {
            emitRuntimeCarrierTableFromMember(
                pctx,
                mn,
                out,
                callerOwner,
                hasTarget,
                memberLocal,
                targetLocal,
                runtimeCarrierTableLocal
            );
            emitReflectiveCarrierForPlan(
                pctx,
                mn,
                out,
                plan,
                argsLocal,
                innerLocal,
                splitKeyLocal,
                callerKeyLocal,
                carrierAttestationSiteSeedOrZero(pctx, plan, callerOwner, mn, call, siteKind),
                runtimeCarrierTableLocal
            );
        }
        if (runtimeCandidate) {
            LabelNode originalArgs = new LabelNode();
            LabelNode doneArgs = new LabelNode();
            out.add(new VarInsnNode(Opcodes.ILOAD, matchedLocal));
            out.add(new JumpInsnNode(Opcodes.IFEQ, originalArgs));
            emitReflectiveOuterArray(
                pctx,
                out,
                plan,
                innerLocal,
                splitKeyLocal,
                outerArityLocal,
                runtimeSuffixLocals,
                callerKeyLocal,
                outerLocal
            );
            loadStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
            out.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
            if (hasTarget) {
                out.add(new VarInsnNode(Opcodes.ALOAD, targetLocal));
            }
            out.add(new VarInsnNode(Opcodes.ALOAD, outerLocal));
            out.add(new JumpInsnNode(Opcodes.GOTO, doneArgs));
            out.add(originalArgs);
            loadStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
            out.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
            if (hasTarget) {
                out.add(new VarInsnNode(Opcodes.ALOAD, targetLocal));
            }
            out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
            out.add(doneArgs);
            return out;
        }
        if (plan == null) {
            loadStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
            out.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
            if (hasTarget) {
                out.add(new VarInsnNode(Opcodes.ALOAD, targetLocal));
            }
            out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
            return out;
        }
        emitReflectiveOuterArray(
            pctx,
            out,
            plan,
            innerLocal,
            splitKeyLocal,
            outerArityLocal,
            runtimeSuffixLocals,
            callerKeyLocal,
            outerLocal
        );
        loadStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
        out.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        if (hasTarget) {
            out.add(new VarInsnNode(Opcodes.ALOAD, targetLocal));
        }
        out.add(new VarInsnNode(Opcodes.ALOAD, outerLocal));
        return out;
    }

    private boolean rewriteClassNewInstance(
        PipelineContext pctx,
        String callerOwner,
        MethodNode mn,
        MethodInsnNode call,
        Integer callerKeyLocal
    ) {
        List<MethodPlan> candidates = classNewInstanceConstructorCandidates(pctx, mn, call);
        if (candidates.isEmpty()) return false;
        int classLocal = allocateLocal(mn, Type.getType(Class.class));
        int emptyArgsLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        int innerLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        int splitKeyLocal = hasSplitHiddenKeyCandidate(candidates)
            ? allocateLocal(mn, Type.getType(Object.class))
            : -1;
        int outerLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        int runtimeCarrierTableLocal = allocateLocal(mn, OBJECT_ARRAY_TYPE);
        List<Type> stackPrefixTypes = stackPrefixTypes(mn, call, 1);
        int[] stackPrefixLocals = allocateStackPrefixLocals(mn, stackPrefixTypes);
        InsnList out = new InsnList();
        out.add(new VarInsnNode(Opcodes.ASTORE, classLocal));
        storeStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
        JvmPassBytecode.pushInt(out, 0);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        out.add(new VarInsnNode(Opcodes.ASTORE, emptyArgsLocal));

        LabelNode fallback = new LabelNode();
        LabelNode done = new LabelNode();
        for (MethodPlan candidate : candidates) {
            LabelNode next = new LabelNode();
            emitClassNameMatch(out, classLocal, candidate.owner().replace('/', '.'), next);
            emitRuntimeCarrierTableFromClass(pctx, mn, out, callerOwner, classLocal, runtimeCarrierTableLocal);
            emitReflectiveCarrierForPlan(
                pctx,
                mn,
                out,
                candidate,
                emptyArgsLocal,
                innerLocal,
                candidate.splitHiddenKey() ? splitKeyLocal : -1,
                callerKeyLocal,
                carrierAttestationSiteSeedOrZero(
                    pctx,
                    candidate,
                    callerOwner,
                    mn,
                    call,
                    "Class.newInstance constructor target"
                ),
                runtimeCarrierTableLocal
            );
            emitReflectiveOuterArray(
                pctx,
                out,
                candidate,
                innerLocal,
                candidate.splitHiddenKey() ? splitKeyLocal : -1,
                -1,
                new int[0],
                callerKeyLocal,
                outerLocal
            );
            loadStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
            out.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
            emitParameterTypes(out, Type.getArgumentTypes(candidate.packedDesc()));
            out.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/Class",
                "getDeclaredConstructor",
                "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;",
                false
            ));
            out.add(new VarInsnNode(Opcodes.ALOAD, outerLocal));
            out.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Constructor",
                "newInstance",
                "([Ljava/lang/Object;)Ljava/lang/Object;",
                false
            ));
            out.add(new JumpInsnNode(Opcodes.GOTO, done));
            out.add(next);
        }
        out.add(fallback);
        loadStackPrefix(out, stackPrefixTypes, stackPrefixLocals);
        out.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "newInstance",
            "()Ljava/lang/Object;",
            false
        ));
        out.add(done);
        mn.instructions.insertBefore(call, out);
        mn.instructions.remove(call);
        return true;
    }

    private List<MethodPlan> classNewInstanceConstructorCandidates(
        PipelineContext pctx,
        MethodNode mn,
        MethodInsnNode call
    ) {
        String owner = sourceClassNewInstanceOwner(pctx, mn, call);
        List<MethodPlan> candidates = new ArrayList<>();
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if (!"<init>".equals(plan.oldName())) continue;
            if (owner != null && !owner.equals(plan.owner())) continue;
            if (visibleArgumentTypes(plan).length != 0) continue;
            addUniquePlan(candidates, plan);
        }
        return candidates;
    }

    private static String sourceClassNewInstanceOwner(PipelineContext pctx, MethodNode mn, MethodInsnNode call) {
        if (mn == null || mn.instructions == null) return null;
        int index = mn.instructions.indexOf(call);
        if (index < 0) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            if (frame == null || frame.getStackSize() < 1) return null;
            return sourceClassObjectOwner(pctx, mn, frames, frame.getStack(frame.getStackSize() - 1), 0);
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private void emitReflectiveOuterArray(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int innerLocal,
        int splitKeyLocal,
        int outerArityLocal,
        int[] runtimeSuffixLocals,
        Integer callerKeyLocal,
        int outerLocal
    ) {
        if (plan == null) {
            out.add(new VarInsnNode(Opcodes.ILOAD, outerArityLocal));
        } else {
            JvmPassBytecode.pushInt(out, packedOuterArgumentCount(plan));
        }
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        out.add(new VarInsnNode(Opcodes.ASTORE, outerLocal));
        out.add(new VarInsnNode(Opcodes.ALOAD, outerLocal));
        JvmPassBytecode.pushInt(out, 0);
        out.add(new VarInsnNode(Opcodes.ALOAD, innerLocal));
        out.add(new InsnNode(Opcodes.AASTORE));
        if (plan != null && plan.splitHiddenKey()) {
            out.add(new VarInsnNode(Opcodes.ALOAD, outerLocal));
            JvmPassBytecode.pushInt(out, 1);
            out.add(new VarInsnNode(Opcodes.ALOAD, splitKeyLocal));
            out.add(new InsnNode(Opcodes.AASTORE));
        } else if (plan == null && splitKeyLocal >= 0) {
            LabelNode noSplit = new LabelNode();
            out.add(new VarInsnNode(Opcodes.ILOAD, outerArityLocal));
            JvmPassBytecode.pushInt(out, 2);
            out.add(new JumpInsnNode(Opcodes.IF_ICMPLT, noSplit));
            out.add(new VarInsnNode(Opcodes.ALOAD, outerLocal));
            JvmPassBytecode.pushInt(out, 1);
            out.add(new VarInsnNode(Opcodes.ALOAD, splitKeyLocal));
            out.add(new InsnNode(Opcodes.AASTORE));
            out.add(noSplit);
        }
        if (plan != null) {
            emitReflectivePackedSuffixStores(pctx, out, plan, callerKeyLocal, outerLocal);
        } else {
            emitRuntimeReflectivePackedSuffixStores(out, outerLocal, outerArityLocal, runtimeSuffixLocals);
        }
    }

    private static int packedOuterArgumentCount(MethodPlan plan) {
        return Type.getArgumentTypes(plan.packedDesc()).length;
    }

    private static void emitReflectivePackedSuffixStores(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        int outerLocal
    ) {
        Type[] suffixTypes = plan.packedSuffixTypes();
        int slot = 1 + (plan.splitHiddenKey() ? 1 : 0);
        for (int i = 0; i < suffixTypes.length; i++) {
            out.add(new VarInsnNode(Opcodes.ALOAD, outerLocal));
            JvmPassBytecode.pushInt(out, slot + i);
            emitPackedSuffixArgument(pctx, out, plan, callerKeyLocal, suffixTypes[i], i, "reflective target");
            emitBox(out, suffixTypes[i]);
            out.add(new InsnNode(Opcodes.AASTORE));
        }
    }

    private static List<Type> stackPrefixTypes(MethodNode mn, MethodInsnNode call, int invokeOperandValues) {
        int index = mn.instructions.indexOf(call);
        if (index < 0) return List.of();
        try {
            Frame<BasicValue>[] frames = analyzeBasicValues("java/lang/Object", mn);
            Frame<BasicValue> frame = frames[index];
            if (frame == null || frame.getStackSize() <= invokeOperandValues) return List.of();
            int prefixSize = frame.getStackSize() - invokeOperandValues;
            List<Type> types = new ArrayList<>(prefixSize);
            for (int i = 0; i < prefixSize; i++) {
                types.add(typeForBasicValue(frame.getStack(i)));
            }
            return types;
        } catch (AnalyzerException | RuntimeException ignored) {
            return List.of();
        }
    }

    private static Type typeForBasicValue(BasicValue value) {
        if (value == BasicValue.INT_VALUE) return Type.INT_TYPE;
        if (value == BasicValue.FLOAT_VALUE) return Type.FLOAT_TYPE;
        if (value == BasicValue.LONG_VALUE) return Type.LONG_TYPE;
        if (value == BasicValue.DOUBLE_VALUE) return Type.DOUBLE_TYPE;
        Type type = value == null ? null : value.getType();
        if (type == null || type.getSort() == Type.VOID || type.getSort() == Type.METHOD) {
            return Type.getType(Object.class);
        }
        if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
            return type;
        }
        return Type.getType(Object.class);
    }

    private static int[] allocateStackPrefixLocals(MethodNode mn, List<Type> types) {
        int[] locals = new int[types.size()];
        for (int i = 0; i < types.size(); i++) {
            locals[i] = allocateLocal(mn, types.get(i));
        }
        return locals;
    }

    private static void storeStackPrefix(InsnList out, List<Type> types, int[] locals) {
        for (int i = types.size() - 1; i >= 0; i--) {
            Type type = types.get(i);
            out.add(new VarInsnNode(type.getOpcode(Opcodes.ISTORE), locals[i]));
        }
    }

    private static void loadStackPrefix(InsnList out, List<Type> types, int[] locals) {
        for (int i = 0; i < types.size(); i++) {
            Type type = types.get(i);
            out.add(new VarInsnNode(type.getOpcode(Opcodes.ILOAD), locals[i]));
        }
    }

    private void emitDefaultReflectiveCarrier(InsnList out, int argsLocal, int innerLocal) {
        LabelNode copyExisting = new LabelNode();
        LabelNode done = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        out.add(new JumpInsnNode(Opcodes.IFNONNULL, copyExisting));
        JvmPassBytecode.pushInt(out, 0);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        out.add(new VarInsnNode(Opcodes.ASTORE, innerLocal));
        out.add(new JumpInsnNode(Opcodes.GOTO, done));
        out.add(copyExisting);
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        out.add(new VarInsnNode(Opcodes.ASTORE, innerLocal));
        out.add(done);
    }

    private static void emitRuntimeCarrierTableFromMember(
        PipelineContext pctx,
        MethodNode mn,
        InsnList out,
        String callerOwner,
        boolean methodMember,
        int memberLocal,
        int targetLocal,
        int tableLocal
    ) {
        InsnList generated = new InsnList();
        generated.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        if (targetLocal >= 0) {
            generated.add(new VarInsnNode(Opcodes.ALOAD, targetLocal));
        } else {
            generated.add(new InsnNode(Opcodes.ACONST_NULL));
        }
        JvmPassBytecode.pushInt(generated, methodMember ? 2 : 1);
        generated.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            callerOwner,
            ensureRuntimeCarrierTableHelper(pctx, callerOwner),
            RUNTIME_CARRIER_TABLE_HELPER_DESC,
            runtimeCarrierTableHelperOwnerIsInterface(pctx, callerOwner)
        ));
        generated.add(new VarInsnNode(Opcodes.ASTORE, tableLocal));
        JvmKeyDispatchPass.markGenerated(pctx, generated);
        out.add(generated);
    }

    private static void emitRuntimeCarrierTableFromClass(
        PipelineContext pctx,
        MethodNode mn,
        InsnList out,
        String callerOwner,
        int classLocal,
        int tableLocal
    ) {
        InsnList generated = new InsnList();
        generated.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        generated.add(new InsnNode(Opcodes.ACONST_NULL));
        JvmPassBytecode.pushInt(generated, 0);
        generated.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            callerOwner,
            ensureRuntimeCarrierTableHelper(pctx, callerOwner),
            RUNTIME_CARRIER_TABLE_HELPER_DESC,
            runtimeCarrierTableHelperOwnerIsInterface(pctx, callerOwner)
        ));
        generated.add(new VarInsnNode(Opcodes.ASTORE, tableLocal));
        JvmKeyDispatchPass.markGenerated(pctx, generated);
        out.add(generated);
    }

    private static String ensureRuntimeCarrierTableHelper(PipelineContext pctx, String owner) {
        Map<String, String> helpers = runtimeCarrierTableHelpers(pctx);
        String existing = helpers.get(owner);
        if (existing != null) return existing;
        L1Class clazz = pctx.classMap().get(owner);
        if (clazz == null) {
            throw new IllegalStateException("Missing runtime carrier table helper owner " + owner);
        }
        String name = uniqueRuntimeCarrierTableHelperName(clazz);
        int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC |
            (clazz.isInterface() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE);
        MethodNode helper = new MethodNode(
            access,
            name,
            RUNTIME_CARRIER_TABLE_HELPER_DESC,
            null,
            null
        );
        emitRuntimeCarrierTableHelperBody(helper);
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        clazz.markDirty();
        helpers.put(owner, name);
        return name;
    }

    private static boolean runtimeCarrierTableHelperOwnerIsInterface(PipelineContext pctx, String owner) {
        L1Class clazz = pctx.classMap().get(owner);
        if (clazz == null) {
            throw new IllegalStateException("Missing runtime carrier table helper owner " + owner);
        }
        return clazz.isInterface();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> runtimeCarrierTableHelpers(PipelineContext pctx) {
        Map<String, String> helpers = pctx.getPassData(RUNTIME_CARRIER_TABLE_HELPERS);
        if (helpers == null) {
            helpers = new LinkedHashMap<>();
            pctx.putPassData(RUNTIME_CARRIER_TABLE_HELPERS, helpers);
        }
        return helpers;
    }

    private static String uniqueRuntimeCarrierTableHelperName(L1Class clazz) {
        Set<String> existing = new LinkedHashSet<>();
        for (MethodNode method : clazz.asmNode().methods) {
            existing.add(method.name + method.desc);
        }
        int index = 0;
        String name;
        do {
            name = "__neko_mpo_rtab$" + Integer.toHexString(index++);
        } while (existing.contains(name + RUNTIME_CARRIER_TABLE_HELPER_DESC));
        return name;
    }

    private static void emitRuntimeCarrierTableHelperBody(MethodNode helper) {
        int sourceLocal = 0;
        int targetLocal = 1;
        int modeLocal = 2;
        int classLocal = 3;
        int fieldsLocal = 4;
        int indexLocal = 5;
        int fieldLocal = 6;
        int candidateLocal = 7;
        int fallbackLocal = 8;
        LabelNode loop = new LabelNode();
        LabelNode next = new LabelNode();
        LabelNode found = new LabelNode();
        LabelNode missing = new LabelNode();
        LabelNode scan = new LabelNode();
        LabelNode memberSource = new LabelNode();
        LabelNode tryReceiver = new LabelNode();
        LabelNode throwMissing = new LabelNode();
        InsnList out = helper.instructions;

        JvmPassBytecode.pushInt(out, 0);
        out.add(new VarInsnNode(Opcodes.ISTORE, fallbackLocal));
        out.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        out.add(new JumpInsnNode(Opcodes.IFNE, memberSource));
        out.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Class"));
        out.add(new VarInsnNode(Opcodes.ASTORE, classLocal));
        out.add(new JumpInsnNode(Opcodes.GOTO, scan));

        out.add(memberSource);
        out.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/reflect/Member"));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEINTERFACE,
            "java/lang/reflect/Member",
            "getDeclaringClass",
            "()Ljava/lang/Class;",
            true
        ));
        out.add(new VarInsnNode(Opcodes.ASTORE, classLocal));

        out.add(scan);
        out.add(new InsnNode(Opcodes.ACONST_NULL));
        out.add(new VarInsnNode(Opcodes.ASTORE, candidateLocal));
        out.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredFields",
            "()[Ljava/lang/reflect/Field;",
            false
        ));
        out.add(new VarInsnNode(Opcodes.ASTORE, fieldsLocal));
        JvmPassBytecode.pushInt(out, 0);
        out.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));

        out.add(loop);
        out.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        out.add(new VarInsnNode(Opcodes.ALOAD, fieldsLocal));
        out.add(new InsnNode(Opcodes.ARRAYLENGTH));
        out.add(new JumpInsnNode(Opcodes.IF_ICMPGE, missing));
        out.add(new VarInsnNode(Opcodes.ALOAD, fieldsLocal));
        out.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        out.add(new InsnNode(Opcodes.AALOAD));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/reflect/Field"));
        out.add(new VarInsnNode(Opcodes.ASTORE, fieldLocal));

        out.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "isSynthetic",
            "()Z",
            false
        ));
        out.add(new JumpInsnNode(Opcodes.IFEQ, next));
        out.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "getModifiers",
            "()I",
            false
        ));
        out.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/reflect/Modifier",
            "isStatic",
            "(I)Z",
            false
        ));
        out.add(new JumpInsnNode(Opcodes.IFEQ, next));
        out.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "getType",
            "()Ljava/lang/Class;",
            false
        ));
        out.add(new LdcInsnNode(OBJECT_ARRAY_TYPE));
        out.add(new JumpInsnNode(Opcodes.IF_ACMPNE, next));
        out.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        out.add(new InsnNode(Opcodes.ICONST_1));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "setAccessible",
            "(Z)V",
            false
        ));
        out.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        out.add(new InsnNode(Opcodes.ACONST_NULL));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            false
        ));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
        out.add(new VarInsnNode(Opcodes.ASTORE, candidateLocal));
        out.add(new VarInsnNode(Opcodes.ALOAD, candidateLocal));
        out.add(new JumpInsnNode(Opcodes.IFNULL, next));
        out.add(new VarInsnNode(Opcodes.ALOAD, candidateLocal));
        out.add(new InsnNode(Opcodes.ARRAYLENGTH));
        JvmPassBytecode.pushInt(out, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SLOT);
        out.add(new JumpInsnNode(Opcodes.IF_ICMPLE, next));
        out.add(new VarInsnNode(Opcodes.ALOAD, candidateLocal));
        JvmPassBytecode.pushInt(out, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SLOT);
        out.add(new InsnNode(Opcodes.AALOAD));
        out.add(new TypeInsnNode(Opcodes.INSTANCEOF, "[I"));
        out.add(new JumpInsnNode(Opcodes.IFNE, found));

        out.add(next);
        out.add(new IincInsnNode(indexLocal, 1));
        out.add(new JumpInsnNode(Opcodes.GOTO, loop));

        out.add(found);
        out.add(new VarInsnNode(Opcodes.ALOAD, candidateLocal));
        out.add(new InsnNode(Opcodes.ARETURN));

        out.add(missing);
        out.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        JvmPassBytecode.pushInt(out, 2);
        out.add(new JumpInsnNode(Opcodes.IF_ICMPNE, throwMissing));
        out.add(new VarInsnNode(Opcodes.ILOAD, fallbackLocal));
        out.add(new JumpInsnNode(Opcodes.IFNE, throwMissing));
        out.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/reflect/Member"));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEINTERFACE,
            "java/lang/reflect/Member",
            "getModifiers",
            "()I",
            true
        ));
        out.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/reflect/Modifier",
            "isStatic",
            "(I)Z",
            false
        ));
        out.add(new JumpInsnNode(Opcodes.IFNE, throwMissing));
        out.add(new VarInsnNode(Opcodes.ALOAD, targetLocal));
        out.add(new JumpInsnNode(Opcodes.IFNULL, throwMissing));
        out.add(tryReceiver);
        JvmPassBytecode.pushInt(out, 1);
        out.add(new VarInsnNode(Opcodes.ISTORE, fallbackLocal));
        out.add(new VarInsnNode(Opcodes.ALOAD, targetLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Object",
            "getClass",
            "()Ljava/lang/Class;",
            false
        ));
        out.add(new VarInsnNode(Opcodes.ASTORE, classLocal));
        out.add(new JumpInsnNode(Opcodes.GOTO, scan));

        out.add(throwMissing);
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/SecurityException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(
            Opcodes.INVOKESPECIAL,
            "java/lang/SecurityException",
            "<init>",
            "()V",
            false
        ));
        out.add(new InsnNode(Opcodes.ATHROW));

        helper.maxLocals = 9;
        helper.maxStack = 5;
    }

    private void emitReflectiveCarrierForPlan(
        PipelineContext pctx,
        MethodNode mn,
        InsnList out,
        MethodPlan plan,
        int argsLocal,
        int innerLocal,
        int splitKeyLocal,
        Integer callerKeyLocal,
        long siteSeed,
        int runtimeCarrierTableLocal
    ) {
        CarrierCallsiteKeys carrierKeys = materializeCarrierCallsiteKeys(
            pctx,
            mn,
            out,
            plan,
            callerKeyLocal,
            "reflective target"
        );
        JvmPassBytecode.pushInt(out, carrierArgumentCount(plan));
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        out.add(new VarInsnNode(Opcodes.ASTORE, innerLocal));
        emitCarrierIndexKeyStoreFromLocal(
            pctx,
            out,
            plan,
            callerKeyLocal,
            carrierKeys,
            innerLocal,
            "reflective target",
            runtimeCarrierTableLocal
        );
        emitCarrierAttestationStoresFromLocal(
            pctx,
            out,
            plan,
            callerKeyLocal,
            carrierKeys,
            innerLocal,
            siteSeed,
            "reflective target",
            runtimeCarrierTableLocal
        );
        int sourceIndex = 0;
        int carrierIndex = 0;
        Type[] args = plan.argumentTypes();
        for (int i = 0; i < args.length; i++) {
            if (isHiddenKeyArgument(plan, i)) {
                if (callerKeyLocal == null) {
                    throw new IllegalStateException(
                        "Missing caller key for reflective methodParameterObfuscation target " +
                            plan.owner() + "." + plan.finalName() + plan.packedDesc()
                    );
                }
                if (plan.splitHiddenKey()) {
                    out.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.targetKeyLocal()));
                    out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf",
                        "(J)Ljava/lang/Long;", false));
                    out.add(new VarInsnNode(Opcodes.ASTORE, splitKeyLocal));
                } else {
                    out.add(new VarInsnNode(Opcodes.ALOAD, innerLocal));
                    emitBoundedCarrierIndexForArrayOnStack(
                        pctx,
                        out,
                        plan,
                        carrierIndex++,
                        carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
                        carrierKeys == null,
                        plan.carrierIndexKeySeed(),
                        runtimeCarrierTableLocal
                    );
                    out.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.targetKeyLocal()));
                    out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf",
                        "(J)Ljava/lang/Long;", false));
                    out.add(new InsnNode(Opcodes.AASTORE));
                }
                continue;
            }
            out.add(new VarInsnNode(Opcodes.ALOAD, innerLocal));
            emitBoundedCarrierIndexForArrayOnStack(
                pctx,
                out,
                plan,
                carrierIndex++,
                carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
                carrierKeys == null,
                plan.carrierIndexKeySeed(),
                runtimeCarrierTableLocal
            );
            out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
            JvmPassBytecode.pushInt(out, sourceIndex++);
            out.add(new InsnNode(Opcodes.AALOAD));
            out.add(new InsnNode(Opcodes.AASTORE));
        }
    }

    private void emitRuntimeReflectiveCarrierSelection(
        PipelineContext pctx,
        InsnList out,
        String callerOwner,
        MethodNode mn,
        MethodInsnNode call,
        boolean methodMember,
        int memberLocal,
        int targetLocal,
        int argsLocal,
        int innerLocal,
        int splitKeyLocal,
        int outerArityLocal,
        int matchedLocal,
        int[] runtimeSuffixLocals,
        List<MethodPlan> runtimeCandidates,
        Integer callerKeyLocal,
        int runtimeCarrierTableLocal
    ) {
        if (callerKeyLocal == null) return;
        List<MethodPlan> candidates = new ArrayList<>();
        for (MethodPlan candidate : runtimeCandidates) {
            if (packedHiddenKeyArgumentIndex(candidate) < 0) continue;
            candidates.add(candidate);
        }
        if (candidates.isEmpty()) return;

        LabelNode done = new LabelNode();
        Map<String, List<MethodPlan>> candidatesByOwner = new LinkedHashMap<>();
        for (MethodPlan candidate : candidates) {
            candidatesByOwner.computeIfAbsent(candidate.owner(), ignored -> new ArrayList<>()).add(candidate);
        }
        for (Map.Entry<String, List<MethodPlan>> ownerEntry : candidatesByOwner.entrySet()) {
            LabelNode nextOwner = new LabelNode();
            emitRuntimeMemberOwnerMatch(out, methodMember, memberLocal, ownerEntry.getKey(), nextOwner);
            for (MethodPlan candidate : ownerEntry.getValue()) {
                LabelNode next = new LabelNode();
                if (methodMember) {
                    emitRuntimeMethodMatch(out, memberLocal, candidate, next, true);
                } else {
                    emitRuntimeConstructorMatch(out, memberLocal, candidate, next, true);
                }
                emitRuntimeCarrierTableFromMember(
                    pctx,
                    mn,
                    out,
                    callerOwner,
                    methodMember,
                    memberLocal,
                    targetLocal,
                    runtimeCarrierTableLocal
                );
                emitReflectiveCarrierForPlan(
                    pctx,
                    mn,
                    out,
                    candidate,
                    argsLocal,
                    innerLocal,
                    candidate.splitHiddenKey() ? splitKeyLocal : -1,
                    callerKeyLocal,
                    carrierAttestationSiteSeedOrZero(
                        pctx,
                        candidate,
                        callerOwner,
                        mn,
                        call,
                        reflectiveAttestationSiteKind(
                            pctx,
                            candidate,
                            call,
                            methodMember ? "reflective target" : "reflective constructor target",
                            methodMember ? "reflective runtime target" : "reflective constructor runtime target"
                        )
                    ),
                    runtimeCarrierTableLocal
                );
                if (matchedLocal >= 0) {
                    out.add(new InsnNode(Opcodes.ICONST_1));
                    out.add(new VarInsnNode(Opcodes.ISTORE, matchedLocal));
                }
                if (outerArityLocal >= 0) {
                    JvmPassBytecode.pushInt(out, packedOuterArgumentCount(candidate));
                    out.add(new VarInsnNode(Opcodes.ISTORE, outerArityLocal));
                }
                emitRuntimeSuffixLocalStores(pctx, out, candidate, callerKeyLocal, runtimeSuffixLocals);
                out.add(new JumpInsnNode(Opcodes.GOTO, done));
                out.add(next);
            }
            out.add(nextOwner);
        }
        out.add(done);
    }

    private static boolean hasSplitHiddenKeyCandidate(List<MethodPlan> runtimeCandidates) {
        for (MethodPlan candidate : runtimeCandidates) {
            if (candidate.splitHiddenKey() && packedHiddenKeyArgumentIndex(candidate) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasHiddenKeyCandidate(List<MethodPlan> runtimeCandidates) {
        for (MethodPlan candidate : runtimeCandidates) {
            if (packedHiddenKeyArgumentIndex(candidate) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static int[] allocateRuntimeSuffixLocals(MethodNode mn, List<MethodPlan> runtimeCandidates) {
        int max = 0;
        for (MethodPlan candidate : runtimeCandidates) {
            max = Math.max(max, candidate.packedSuffixTypes().length);
        }
        int[] locals = new int[max];
        for (int i = 0; i < max; i++) {
            locals[i] = allocateLocal(mn, Type.getType(Object.class));
        }
        return locals;
    }

    private static void initializeRuntimeSuffixLocals(InsnList out, int[] runtimeSuffixLocals) {
        for (int local : runtimeSuffixLocals) {
            out.add(new InsnNode(Opcodes.ACONST_NULL));
            out.add(new VarInsnNode(Opcodes.ASTORE, local));
        }
    }

    private static void emitRuntimeSuffixLocalStores(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        int[] runtimeSuffixLocals
    ) {
        Type[] suffixTypes = plan.packedSuffixTypes();
        for (int i = 0; i < suffixTypes.length; i++) {
            emitPackedSuffixArgument(pctx, out, plan, callerKeyLocal, suffixTypes[i], i, "reflective runtime target");
            emitBox(out, suffixTypes[i]);
            out.add(new VarInsnNode(Opcodes.ASTORE, runtimeSuffixLocals[i]));
        }
    }

    private static void emitRuntimeReflectivePackedSuffixStores(
        InsnList out,
        int outerLocal,
        int outerArityLocal,
        int[] runtimeSuffixLocals
    ) {
        for (int i = 0; i < runtimeSuffixLocals.length; i++) {
            int slot = 2 + i;
            LabelNode skip = new LabelNode();
            out.add(new VarInsnNode(Opcodes.ILOAD, outerArityLocal));
            JvmPassBytecode.pushInt(out, slot);
            out.add(new JumpInsnNode(Opcodes.IF_ICMPLE, skip));
            out.add(new VarInsnNode(Opcodes.ALOAD, outerLocal));
            JvmPassBytecode.pushInt(out, slot);
            out.add(new VarInsnNode(Opcodes.ALOAD, runtimeSuffixLocals[i]));
            out.add(new InsnNode(Opcodes.AASTORE));
            out.add(skip);
        }
    }

    private List<MethodPlan> escapedReflectiveParameterCandidates(
        PipelineContext pctx,
        String currentOwner,
        MethodNode mn,
        MethodInsnNode invokeCall,
        boolean methodMember
    ) {
        MethodPlan currentPlan = planByFinalKey(pctx).get(key(currentOwner, mn.name, mn.desc));
        if (currentPlan == null) {
            currentPlan = planByOldKey(pctx).get(key(currentOwner, mn.name, mn.desc));
        }
        if (currentPlan == null) return List.of();
        String methodKey = key(currentPlan.owner(), currentPlan.oldName(), currentPlan.oldDesc());
        int operandValues = methodMember ? 3 : 2;
        List<MethodPlan> candidates = new ArrayList<>();
        for (int local : reflectiveMemberSourceLocals(mn, invokeCall, operandValues)) {
            int argumentIndex = argumentIndexForLocal(currentPlan, local);
            if (argumentIndex < 0) continue;
            List<MethodPlan> recorded = escapedReflectiveParameterCandidates(pctx).get(
                escapedReflectiveParameterKey(methodMember, methodKey, argumentIndex)
            );
            if (recorded == null) continue;
            for (MethodPlan candidate : recorded) {
                addUniquePlan(candidates, candidate);
            }
        }
        return candidates;
    }

    private List<MethodPlan> lambdaCapturedReflectiveParameterCandidates(
        PipelineContext pctx,
        String currentOwner,
        MethodNode mn,
        MethodInsnNode invokeCall,
        boolean methodMember
    ) {
        int operandValues = methodMember ? 3 : 2;
        String methodKey = key(currentOwner, mn.name, mn.desc);
        List<MethodPlan> candidates = new ArrayList<>();
        for (int local : reflectiveMemberSourceLocals(mn, invokeCall, operandValues)) {
            List<MethodPlan> recorded = lambdaReflectiveCaptureCandidates(pctx).get(
                lambdaReflectiveCaptureKey(methodMember, methodKey, local)
            );
            if (recorded == null) continue;
            for (MethodPlan candidate : recorded) {
                addUniquePlan(candidates, candidate);
            }
        }
        return candidates;
    }

    private List<MethodPlan> reflectiveInvokeSourceCandidates(
        PipelineContext pctx,
        MethodNode mn,
        MethodInsnNode invokeCall,
        boolean methodMember,
        int invokeOperandValues
    ) {
        int index = mn.instructions.indexOf(invokeCall);
        if (index < 0) return List.of();
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            if (frame == null || frame.getStackSize() < invokeOperandValues) return List.of();
            SourceValue member = frame.getStack(frame.getStackSize() - invokeOperandValues);
            return reflectiveMemberSourceCandidates(pctx, mn, frames, member, methodMember, 0);
        } catch (AnalyzerException | RuntimeException ignored) {
            return List.of();
        }
    }

    private static List<Integer> reflectiveMemberSourceLocals(
        MethodNode mn,
        MethodInsnNode invokeCall,
        int invokeOperandValues
    ) {
        int index = mn.instructions.indexOf(invokeCall);
        if (index < 0) return List.of();
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            if (frame == null || frame.getStackSize() < invokeOperandValues) return List.of();
            SourceValue member = frame.getStack(frame.getStackSize() - invokeOperandValues);
            List<Integer> locals = new ArrayList<>();
            collectSourceLoadLocals(mn, frames, member, locals, 0);
            return locals;
        } catch (AnalyzerException | RuntimeException ignored) {
            return List.of();
        }
    }

    private static void collectSourceLoadLocals(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        List<Integer> locals,
        int depth
    ) {
        if (value == null || depth > 4) return;
        for (AbstractInsnNode insn : value.insns) {
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                if (!locals.contains(var.var)) {
                    locals.add(var.var);
                }
                collectSourceLoadLocals(mn, frames, storedLocalValue(mn, frames, var), locals, depth + 1);
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        collectSourceLoadLocals(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            locals,
                            depth + 1
                        );
                    }
                }
            }
        }
    }

    private static int argumentIndexForLocal(MethodPlan plan, int local) {
        int[] locals = plan.argumentLocals();
        for (int i = 0; i < locals.length; i++) {
            if (locals[i] == local) return i;
        }
        return -1;
    }

    private List<MethodPlan> runtimeReflectiveInvokeCandidates(
        PipelineContext pctx,
        String currentOwner,
        MethodNode mn,
        MethodInsnNode invokeCall
    ) {
        List<MethodPlan> sourcedPlans = reflectiveInvokeSourceCandidates(pctx, mn, invokeCall, true, 3);
        if (!sourcedPlans.isEmpty()) return sourcedPlans;
        String arrayOwner = methodArrayOwner(pctx, mn, invokeCall);
        if (arrayOwner != null) {
            String arrayName = previousMethodArrayGuardName(mn, invokeCall);
            List<MethodPlan> plans = plansMatchingReflectionTarget(pctx, arrayOwner, arrayName);
            if (!plans.isEmpty()) return plans;
            if (arrayName != null) return plansMatchingReflectionTarget(pctx, null, arrayName);
        }
        List<MethodPlan> lambdaCaptured = lambdaCapturedReflectiveParameterCandidates(
            pctx,
            currentOwner,
            mn,
            invokeCall,
            true
        );
        if (!lambdaCaptured.isEmpty()) return lambdaCaptured;
        return escapedReflectiveParameterCandidates(pctx, currentOwner, mn, invokeCall, true);
    }

    private List<MethodPlan> runtimeReflectiveConstructorInvokeCandidates(
        PipelineContext pctx,
        String currentOwner,
        MethodNode mn,
        MethodInsnNode invokeCall
    ) {
        List<MethodPlan> sourcedPlans = reflectiveInvokeSourceCandidates(pctx, mn, invokeCall, false, 2);
        if (!sourcedPlans.isEmpty()) return sourcedPlans;
        String arrayOwner = constructorArrayOwner(pctx, mn, invokeCall);
        if (arrayOwner != null) {
            List<MethodPlan> plans = constructorPlansMatchingReflectionTarget(pctx, arrayOwner, null);
            if (!plans.isEmpty()) return plans;
        }
        List<MethodPlan> lambdaCaptured = lambdaCapturedReflectiveParameterCandidates(
            pctx,
            currentOwner,
            mn,
            invokeCall,
            false
        );
        if (!lambdaCaptured.isEmpty()) return lambdaCaptured;
        return escapedReflectiveParameterCandidates(pctx, currentOwner, mn, invokeCall, false);
    }

    private List<MethodPlan> plansMatchingReflectionTarget(PipelineContext pctx, String owner, String name) {
        List<MethodPlan> plans = new ArrayList<>();
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if ("<init>".equals(plan.oldName())) continue;
            if (owner != null && !owner.equals(plan.owner())) continue;
            if (name != null && !name.equals(plan.oldName()) && !name.equals(plan.finalName())) continue;
            plans.add(plan);
        }
        return plans;
    }

    private List<MethodPlan> constructorPlansMatchingReflectionTarget(PipelineContext pctx, String owner, Type[] visibleArgs) {
        List<MethodPlan> plans = new ArrayList<>();
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if (!"<init>".equals(plan.oldName())) continue;
            if (owner != null && !owner.equals(plan.owner())) continue;
            if (visibleArgs != null && !sameTypes(visibleArgumentTypes(plan), visibleArgs)) continue;
            plans.add(plan);
        }
        return plans;
    }

    private String methodArrayOwner(PipelineContext pctx, MethodNode mn, MethodInsnNode invokeCall) {
        return sourceReflectiveMemberArrayOwner(pctx, mn, invokeCall, 3, true);
    }

    private String previousMethodArrayGuardName(MethodNode mn, MethodInsnNode invokeCall) {
        List<Integer> memberLocals = reflectiveMemberSourceLocals(mn, invokeCall, 3);
        if (memberLocals.isEmpty()) return null;
        int invokeIndex = mn.instructions.indexOf(invokeCall);
        if (invokeIndex < 0) return null;
        int scanned = 0;
        for (AbstractInsnNode scan = invokeCall.getPrevious(); scan != null && scanned++ < 512; scan = scan.getPrevious()) {
            if (!(scan instanceof MethodInsnNode call)
                || !"java/lang/reflect/Method".equals(call.owner)
                || !"getName".equals(call.name)
                || !"()Ljava/lang/String;".equals(call.desc)) {
                continue;
            }
            List<Integer> nameLocals = reflectiveMemberSourceLocals(mn, call, 1);
            if (!sharesAnyLocal(nameLocals, memberLocals)) continue;
            String value = guardedStringEqualsValue(mn, call, invokeIndex);
            if (value != null) return value;
        }
        return null;
    }

    private static boolean sharesAnyLocal(List<Integer> left, List<Integer> right) {
        for (int value : left) {
            if (right.contains(value)) return true;
        }
        return false;
    }

    private static String guardedStringEqualsValue(MethodNode mn, MethodInsnNode getNameCall, int invokeIndex) {
        AbstractInsnNode ldcNode = nextRealInstruction(getNameCall.getNext());
        if (!(ldcNode instanceof LdcInsnNode ldc) || !(ldc.cst instanceof String value)) return null;
        AbstractInsnNode equalsNode = nextRealInstruction(ldcNode.getNext());
        if (!(equalsNode instanceof MethodInsnNode equals)
            || !"java/lang/String".equals(equals.owner)
            || !"equals".equals(equals.name)
            || !"(Ljava/lang/Object;)Z".equals(equals.desc)) {
            return null;
        }
        AbstractInsnNode branchNode = nextRealInstruction(equals.getNext());
        if (!(branchNode instanceof JumpInsnNode branch) || branch.getOpcode() != Opcodes.IFEQ) return null;
        int branchIndex = mn.instructions.indexOf(branch);
        int falseIndex = mn.instructions.indexOf(branch.label);
        if (branchIndex < 0 || falseIndex < 0) return null;
        return branchIndex < invokeIndex && invokeIndex < falseIndex ? value : null;
    }

    private String constructorArrayOwner(PipelineContext pctx, MethodNode mn, MethodInsnNode invokeCall) {
        return sourceReflectiveMemberArrayOwner(pctx, mn, invokeCall, 2, false);
    }

    private static String sourceReflectiveMemberArrayOwner(
        PipelineContext pctx,
        MethodNode mn,
        MethodInsnNode invokeCall,
        int invokeOperandValues,
        boolean methodMember
    ) {
        int index = mn.instructions.indexOf(invokeCall);
        if (index < 0) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            Frame<SourceValue> frame = frames[index];
            if (frame == null || frame.getStackSize() < invokeOperandValues) return null;
            SourceValue member = frame.getStack(frame.getStackSize() - invokeOperandValues);
            return sourceReflectiveMemberArrayOwner(pctx, mn, frames, member, methodMember, 0);
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private static String sourceReflectiveMemberArrayOwner(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        boolean methodMember,
        int depth
    ) {
        if (value == null || depth > 6) return null;
        String owner = null;
        for (AbstractInsnNode insn : value.insns) {
            String sourced = null;
            if (insn instanceof MethodInsnNode call &&
                (methodMember ? isReflectionMethodArrayLookup(call) : isReflectionConstructorArrayLookup(call))) {
                sourced = sourceReflectionArrayLookupOwner(pctx, mn, frames, call);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceReflectiveMemberArrayOwner(
                    pctx,
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    methodMember,
                    depth + 1
                );
            } else if (insn.getOpcode() == Opcodes.AALOAD) {
                int index = mn.instructions.indexOf(insn);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() >= 2) {
                        sourced = sourceReflectiveMemberArrayOwner(
                            pctx,
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 2),
                            methodMember,
                            depth + 1
                        );
                    }
                }
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceReflectiveMemberArrayOwner(
                            pctx,
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            methodMember,
                            depth + 1
                        );
                    }
                }
            }
            if (sourced == null) return null;
            if (owner != null && !owner.equals(sourced)) return null;
            owner = sourced;
        }
        return owner;
    }

    private static String sourceReflectionArrayLookupOwner(
        PipelineContext pctx,
        MethodNode mn,
        MethodInsnNode call
    ) {
        if (mn == null || mn.instructions == null) return null;
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues("java/lang/Object", mn);
            return sourceReflectionArrayLookupOwner(pctx, mn, frames, call);
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private static String sourceReflectionArrayLookupOwner(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode call
    ) {
        int index = mn.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() == 0) return null;
        return sourceClassObjectOwner(pctx, mn, frames, frame.getStack(frame.getStackSize() - 1), 0);
    }

    private static void emitRuntimeMemberOwnerMatch(
        InsnList out,
        boolean methodMember,
        int memberLocal,
        String owner,
        LabelNode next
    ) {
        out.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        out.add(new TypeInsnNode(
            Opcodes.CHECKCAST,
            methodMember ? "java/lang/reflect/Method" : "java/lang/reflect/Constructor"
        ));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            methodMember ? "java/lang/reflect/Method" : "java/lang/reflect/Constructor",
            "getDeclaringClass",
            "()Ljava/lang/Class;",
            false
        ));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Class",
            "getName", "()Ljava/lang/String;", false));
        emitProtectedStringEqualsGuards(out, owner.replace('/', '.'), next);
    }

    private static void emitRuntimeMethodMatch(
        InsnList out,
        int memberLocal,
        MethodPlan candidate,
        LabelNode next,
        boolean ownerAlreadyMatched
    ) {
        if (!ownerAlreadyMatched) {
            emitRuntimeMemberOwnerMatch(out, true, memberLocal, candidate.owner(), next);
        }

        out.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/reflect/Method"));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
            "getName", "()Ljava/lang/String;", false));
        emitProtectedStringEqualsGuards(out, candidate.finalName(), next);

        out.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/reflect/Method"));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
            "getParameterTypes", "()[Ljava/lang/Class;", false));
        emitParameterTypeArrayEqualsGuard(out, Type.getArgumentTypes(candidate.packedDesc()), next);
    }

    private static void emitClassNameMatch(InsnList out, int classLocal, String expectedName, LabelNode next) {
        out.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        out.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getName",
            "()Ljava/lang/String;",
            false
        ));
        emitProtectedStringEqualsGuards(out, expectedName, next);
    }

    private static void emitRuntimeConstructorMatch(
        InsnList out,
        int memberLocal,
        MethodPlan candidate,
        LabelNode next,
        boolean ownerAlreadyMatched
    ) {
        if (!ownerAlreadyMatched) {
            emitRuntimeMemberOwnerMatch(out, false, memberLocal, candidate.owner(), next);
        }

        out.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/reflect/Constructor"));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Constructor",
            "getParameterTypes", "()[Ljava/lang/Class;", false));
        emitParameterTypeArrayEqualsGuard(out, Type.getArgumentTypes(candidate.packedDesc()), next);
    }

    private void emitPackedParameterTypes(InsnList out) {
        emitParameterTypes(out, new Type[] { OBJECT_ARRAY_TYPE });
    }

    private static void emitParameterTypeArrayEqualsGuard(InsnList out, Type[] parameterTypes, LabelNode next) {
        emitParameterTypes(out, parameterTypes);
        out.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/util/Arrays",
            "equals",
            "([Ljava/lang/Object;[Ljava/lang/Object;)Z",
            false
        ));
        out.add(new JumpInsnNode(Opcodes.IFEQ, next));
    }

    private static void emitParameterTypes(InsnList out, Type[] parameterTypes) {
        JvmPassBytecode.pushInt(out, parameterTypes.length);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Class"));
        for (int i = 0; i < parameterTypes.length; i++) {
            out.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(out, i);
            emitClassConstant(out, parameterTypes[i]);
            out.add(new InsnNode(Opcodes.AASTORE));
        }
    }

    private InsnList packCallArguments(
        PipelineContext pctx,
        MethodNode mn,
        MethodPlan plan,
        Integer callerKeyLocal,
        long siteSeed
    ) {
        Type[] args = plan.argumentTypes();
        int[] locals = new int[args.length];
        for (int i = args.length - 1; i >= 0; i--) {
            if (isSyntheticHiddenKeyArgument(plan, i)) continue;
            locals[i] = allocateLocal(mn, args[i]);
        }
        InsnList out = new InsnList();
        for (int i = args.length - 1; i >= 0; i--) {
            if (isSyntheticHiddenKeyArgument(plan, i)) continue;
            out.add(new VarInsnNode(args[i].getOpcode(Opcodes.ISTORE), locals[i]));
        }
        CarrierCallsiteKeys carrierKeys = materializeCarrierCallsiteKeys(
            pctx,
            mn,
            out,
            plan,
            callerKeyLocal,
            "target"
        );
        JvmPassBytecode.pushInt(out, carrierArgumentCount(plan));
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        emitCarrierIndexKeyStore(pctx, out, plan, callerKeyLocal, carrierKeys, "target");
        emitCarrierAttestationStores(pctx, out, plan, callerKeyLocal, carrierKeys, siteSeed, "target");
        int carrierIndex = 0;
        for (int i = 0; i < args.length; i++) {
            if (plan.splitHiddenKey() && isHiddenKeyArgument(plan, i)) {
                continue;
            }
            out.add(new InsnNode(Opcodes.DUP));
            emitBoundedCarrierIndexForArrayOnStack(
                pctx,
                out,
                plan,
                carrierIndex++,
                carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
                carrierKeys == null,
                plan.carrierIndexKeySeed()
            );
            if (isHiddenKeyArgument(plan, i)) {
                if (callerKeyLocal == null) {
                    throw new IllegalStateException(
                        "Missing caller key for methodParameterObfuscation target " +
                        plan.owner() + "." + plan.finalName() + plan.packedDesc()
                    );
                }
                out.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.targetKeyLocal()));
            } else {
                out.add(new VarInsnNode(args[i].getOpcode(Opcodes.ILOAD), locals[i]));
            }
            emitBox(out, args[i]);
            out.add(new InsnNode(Opcodes.AASTORE));
        }
        if (plan.splitHiddenKey()) {
            if (callerKeyLocal == null) {
                throw new IllegalStateException(
                "Missing caller key for methodParameterObfuscation target " +
                        plan.owner() + "." + plan.finalName() + plan.packedDesc()
                );
            }
            if (carrierKeys == null) {
                VarInsnNode keyLoad = new VarInsnNode(Opcodes.LLOAD, callerKeyLocal);
                out.add(keyLoad);
                cffKeyLoadTargetSeeds(pctx).put(keyLoad, seedForPlan(pctx, plan));
            } else {
                out.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.targetKeyLocal()));
            }
        }
        emitPackedSuffixArguments(pctx, out, plan, callerKeyLocal, "target");
        JvmKeyDispatchPass.markGenerated(pctx, out);
        return out;
    }

    private static void emitPackedSuffixArguments(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        String targetKind
    ) {
        Type[] suffixTypes = plan.packedSuffixTypes();
        for (int i = 0; i < suffixTypes.length; i++) {
            emitPackedSuffixArgument(pctx, out, plan, callerKeyLocal, suffixTypes[i], i, targetKind);
        }
    }

    private static void emitPackedSuffixArgument(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        Type suffixType,
        int suffixIndex,
        String targetKind
    ) {
        if (callerKeyLocal == null) {
            throw new IllegalStateException(
                "Missing caller key for methodParameterObfuscation ABI suffix " + targetKind + " " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        long suffixSeed = JvmPassBytecode.mix(seedForPlan(pctx, plan), 0x43544F525355464CL + suffixIndex);
        VarInsnNode keyLoad = new VarInsnNode(Opcodes.LLOAD, callerKeyLocal);
        out.add(keyLoad);
        cffKeyLoadTargetSeeds(pctx).put(keyLoad, seedForPlan(pctx, plan));
        if (Type.INT_TYPE.equals(suffixType)) {
            out.add(new InsnNode(Opcodes.L2I));
            JvmPassBytecode.pushInt(out, (int) suffixSeed);
            out.add(new InsnNode(Opcodes.IXOR));
            return;
        }
        if (Type.LONG_TYPE.equals(suffixType)) {
            JvmPassBytecode.pushLong(out, suffixSeed);
            out.add(new InsnNode(Opcodes.LXOR));
            return;
        }
        throw new IllegalStateException("Unsupported constructor ABI suffix type: " + suffixType);
    }

    private static boolean isHiddenKeyArgument(MethodPlan plan, int index) {
        return packedHiddenKeyArgumentIndex(plan) == index;
    }

    private static boolean isSyntheticHiddenKeyArgument(MethodPlan plan, int index) {
        return plan.syntheticHiddenKey() && isHiddenKeyArgument(plan, index);
    }

    private static boolean shouldUseCanonicalRawSeed(PipelineContext pctx, MethodPlan plan) {
        if (plan.keyLocal() == null) return false;
        if ("<init>".equals(plan.finalName())) return false;
        L1Class clazz = pctx.classMap().get(plan.owner());
        if (clazz == null) return false;
        MethodNode method = findMethodNode(clazz, plan.finalName(), plan.packedDesc());
        if (method == null) return false;
        int access = method.access;
        return (access & Opcodes.ACC_STATIC) != 0
            || (access & Opcodes.ACC_PRIVATE) != 0
            || (access & Opcodes.ACC_FINAL) != 0
            || (clazz.asmNode().access & Opcodes.ACC_FINAL) != 0;
    }

    private static long seedForPlan(PipelineContext pctx, MethodPlan plan) {
        Long seed = JvmKeyDispatchPass.findMethodSeed(
            pctx,
            key(plan.owner(), plan.finalName(), plan.packedDesc())
        );
        if (seed == null) {
            throw new IllegalStateException(
                "Missing keyDispatch seed for methodParameterObfuscation target " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        return seed;
    }

    private static long carrierAttestationPlanSeed(PipelineContext pctx, MethodPlan plan) {
        CarrierIndexPlan carrierPlan = plan.carrierIndexPlan();
        long baseSeed = carrierPlan == null ? seedForPlan(pctx, plan) : carrierPlan.seed();
        long seed = JvmPassBytecode.mix(baseSeed ^ CARRIER_ATTEST_DOMAIN, plan.oldName().hashCode());
        seed = JvmPassBytecode.mix(seed, plan.oldDesc().hashCode());
        seed = JvmPassBytecode.mix(seed, plan.carrierIndexKeySeed());
        return seed == 0L ? CARRIER_ATTEST_DOMAIN : seed;
    }

    private static long carrierAttestationTagSeed(PipelineContext pctx, MethodPlan plan) {
        long seed = JvmPassBytecode.mix(carrierAttestationPlanSeed(pctx, plan), CARRIER_ATTEST_TAG_DOMAIN);
        return seed == 0L ? CARRIER_ATTEST_TAG_DOMAIN : seed;
    }

    private static long carrierAttestationSiteSeed(
        PipelineContext pctx,
        MethodPlan plan,
        String callerOwner,
        MethodNode caller,
        AbstractInsnNode site,
        String siteKind
    ) {
        Long prepared = carrierAttestationSiteSeeds(pctx).get(
            new CarrierAttestationSiteKey(finalKey(plan), site, siteKind)
        );
        if (prepared != null) return prepared;
        return recordCarrierAttestationSite(pctx, plan, callerOwner, caller, site, siteKind);
    }

    private static long carrierAttestationSiteSeedOrZero(
        PipelineContext pctx,
        MethodPlan plan,
        String callerOwner,
        MethodNode caller,
        AbstractInsnNode site,
        String siteKind
    ) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) return 0L;
        return carrierAttestationSiteSeed(pctx, plan, callerOwner, caller, site, siteKind);
    }

    private static void seedEmptyCarrierAttestationSites(PipelineContext pctx) {
        for (MethodPlan plan : planByFinalKey(pctx).values()) {
            if (packedHiddenKeyArgumentIndex(plan) < 0) continue;
            if (!plan.carrierAttestationSiteSeeds().isEmpty()) continue;
            long seed = JvmPassBytecode.mix(
                carrierAttestationPlanSeed(pctx, plan),
                0x4E4F43414C4C314CL
            );
            seed = JvmPassBytecode.mix(seed, finalKey(plan).hashCode());
            plan.addCarrierAttestationSiteSeed(seed == 0L ? CARRIER_ATTEST_SITE_DOMAIN : seed);
        }
    }

    private static String methodHandleAttestationSiteKind(
        PipelineContext pctx,
        MethodPlan plan,
        AbstractInsnNode site
    ) {
        CarrierAttestationSiteKey exact =
            new CarrierAttestationSiteKey(finalKey(plan), site, "MethodHandle target");
        if (carrierAttestationSiteSeeds(pctx).containsKey(exact)) {
            return "MethodHandle target";
        }
        CarrierAttestationSiteKey runtime =
            new CarrierAttestationSiteKey(finalKey(plan), site, "MethodHandle runtime target");
        return carrierAttestationSiteSeeds(pctx).containsKey(runtime)
            ? "MethodHandle runtime target"
            : "MethodHandle target";
    }

    private static String reflectiveAttestationSiteKind(
        PipelineContext pctx,
        MethodPlan plan,
        AbstractInsnNode site,
        String exactKind,
        String runtimeKind
    ) {
        CarrierAttestationSiteKey exact = new CarrierAttestationSiteKey(finalKey(plan), site, exactKind);
        if (carrierAttestationSiteSeeds(pctx).containsKey(exact)) {
            return exactKind;
        }
        CarrierAttestationSiteKey runtime = new CarrierAttestationSiteKey(finalKey(plan), site, runtimeKind);
        return carrierAttestationSiteSeeds(pctx).containsKey(runtime) ? runtimeKind : exactKind;
    }

    private static long recordCarrierAttestationSite(
        PipelineContext pctx,
        MethodPlan plan,
        String callerOwner,
        MethodNode caller,
        AbstractInsnNode site,
        String siteKind
    ) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) return 0L;
        long seed = computeCarrierAttestationSiteSeed(pctx, plan, callerOwner, caller, site, siteKind);
        CarrierAttestationSiteKey siteKey = new CarrierAttestationSiteKey(finalKey(plan), site, siteKind);
        Long existing = carrierAttestationSiteSeeds(pctx).put(siteKey, seed);
        if (existing != null && existing.longValue() != seed) {
            throw new IllegalStateException(
                "Conflicting carrier attestation site seed for " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        for (MethodPlan candidate : planByFinalKey(pctx).values()) {
            if (candidate.carrierIndexPlan() == plan.carrierIndexPlan()) {
                candidate.addCarrierAttestationSiteSeed(seed);
            }
        }
        return seed;
    }

    private static long computeCarrierAttestationSiteSeed(
        PipelineContext pctx,
        MethodPlan plan,
        String callerOwner,
        MethodNode caller,
        AbstractInsnNode site,
        String siteKind
    ) {
        CallerAttestationIdentity callerIdentity = callerAttestationIdentity(pctx, callerOwner, caller);
        long seed = JvmPassBytecode.mix(carrierAttestationPlanSeed(pctx, plan), callerIdentity.owner().hashCode());
        seed = JvmPassBytecode.mix(seed, callerIdentity.name().hashCode());
        seed = JvmPassBytecode.mix(seed, callerIdentity.desc().hashCode());
        int siteIndex = caller.instructions == null ? -1 : caller.instructions.indexOf(site);
        seed = JvmPassBytecode.mix(seed, siteIndex);
        seed = JvmPassBytecode.mix(seed, site == null ? 0 : site.getOpcode());
        seed = JvmPassBytecode.mix(seed, siteKind.hashCode());
        return seed == 0L ? CARRIER_ATTEST_SITE_DOMAIN : seed;
    }

    private static CallerAttestationIdentity callerAttestationIdentity(
        PipelineContext pctx,
        String callerOwner,
        MethodNode caller
    ) {
        MethodPlan oldPlan = planByOldKey(pctx).get(key(callerOwner, caller.name, caller.desc));
        if (oldPlan != null) {
            return new CallerAttestationIdentity(callerOwner, oldPlan.finalName(), oldPlan.packedDesc());
        }
        MethodPlan finalPlan = planByFinalKey(pctx).get(key(callerOwner, caller.name, caller.desc));
        if (finalPlan != null) {
            return new CallerAttestationIdentity(callerOwner, finalPlan.finalName(), finalPlan.packedDesc());
        }
        return new CallerAttestationIdentity(callerOwner, caller.name, caller.desc);
    }

    private static String finalKey(MethodPlan plan) {
        return key(plan.owner(), plan.finalName(), plan.packedDesc());
    }

    private static long requireMethodSeed(PipelineContext pctx, MethodPlan plan, String finalKey) {
        Long seed = JvmKeyDispatchPass.findMethodSeed(pctx, finalKey);
        if (seed == null) {
            throw new IllegalStateException(
                "Missing keyDispatch seed for methodParameterObfuscation carrier index plan " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        return seed;
    }

    private static long carrierIndexKeySeed(CarrierIndexPlan plan) {
        long seed = JvmPassBytecode.mix(plan.seed(), 0x4341525249455249L);
        return seed == 0L ? 0x4341525249455249L : seed;
    }

    private static long incomingRawForCanonical(long targetSeed) {
        return JvmKeyDispatchPass.incomingRawForCanonical(targetSeed);
    }

    @SuppressWarnings("unchecked")
    private static Map<AbstractInsnNode, Long> cffKeyLoadTargetSeeds(PipelineContext pctx) {
        Map<AbstractInsnNode, Long> map = pctx.getPassData(CFF_KEY_LOAD_TARGET_SEED);
        if (map == null) {
            map = new IdentityHashMap<>();
            pctx.putPassData(CFF_KEY_LOAD_TARGET_SEED, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Long> cffPackedCallTargetSeeds(PipelineContext pctx) {
        Map<String, Long> map = pctx.getPassData(CFF_PACKED_CALL_TARGET_SEED);
        if (map == null) {
            map = new LinkedHashMap<>();
            pctx.putPassData(CFF_PACKED_CALL_TARGET_SEED, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    public static Set<String> cffPackedVirtualEntryKeys(PipelineContext pctx) {
        Set<String> set = pctx.getPassData(CFF_PACKED_VIRTUAL_ENTRY_KEYS);
        if (set == null) {
            set = new java.util.LinkedHashSet<>();
            pctx.putPassData(CFF_PACKED_VIRTUAL_ENTRY_KEYS, set);
        }
        return set;
    }

    public static boolean isCffPackedVirtualEntry(
        PipelineContext pctx,
        String owner,
        String name,
        String desc
    ) {
        Set<String> entries = pctx.getPassData(CFF_PACKED_VIRTUAL_ENTRY_KEYS);
        return entries != null && entries.contains(key(owner, name, desc));
    }

    private static boolean isPackedVirtualEntry(MethodNode mn, MethodPlan plan) {
        if (mn == null) return false;
        if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) return false;
        if ((mn.access & Opcodes.ACC_STATIC) != 0) return false;
        if ((mn.access & Opcodes.ACC_PRIVATE) != 0) return false;
        return packedHiddenKeyArgumentIndex(plan) >= 0;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Set<Integer>> cffDataDigestExcludedArgumentLocals(PipelineContext pctx) {
        Map<String, Set<Integer>> map = pctx.getPassData(CFF_DATA_DIGEST_EXCLUDED_ARGUMENT_LOCALS);
        if (map == null) {
            map = new LinkedHashMap<>();
            pctx.putPassData(CFF_DATA_DIGEST_EXCLUDED_ARGUMENT_LOCALS, map);
        }
        return map;
    }

    public static Set<Integer> cffDataDigestExcludedArgumentLocals(
        PipelineContext pctx,
        String owner,
        String name,
        String desc
    ) {
        Map<String, Set<Integer>> map = pctx.getPassData(CFF_DATA_DIGEST_EXCLUDED_ARGUMENT_LOCALS);
        if (map == null) return Set.of();
        return map.getOrDefault(key(owner, name, desc), Set.of());
    }

    private static void recordCffDataDigestExcludedArgumentLocals(
        PipelineContext pctx,
        MethodPlan plan,
        int access
    ) {
        Set<Integer> excluded = new java.util.LinkedHashSet<>();
        Type[] packedArgs = Type.getArgumentTypes(plan.packedDesc());
        int local = (access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        int suffixStart = 1 + (plan.splitHiddenKey() ? 1 : 0);
        for (int i = 0; i < packedArgs.length; i++) {
            boolean hiddenTransport = plan.splitHiddenKey() && i == 1;
            boolean constructorSuffix = i >= suffixStart && i < suffixStart + plan.packedSuffixTypes().length;
            if (hiddenTransport || constructorSuffix) {
                excluded.add(local);
            }
            local += packedArgs[i].getSize();
        }
        if (!excluded.isEmpty()) {
            cffDataDigestExcludedArgumentLocals(pctx).put(finalKey(plan), Set.copyOf(excluded));
        }
    }

    private static void emitLiveSeededLongMaterial(InsnList out, long seed, long domain) {
        long mixed = JvmPassBytecode.mix(seed, domain);
        JvmPassBytecode.pushLong(out, JvmPassBytecode.mix(mixed, 0x4D504F4154314131L));
        out.add(new InsnNode(Opcodes.LXOR));
        out.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(out, derivedLongShift(mixed, 9));
        out.add(new InsnNode(Opcodes.LUSHR));
        out.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(out, nonZeroOddLong(JvmPassBytecode.mix(mixed, 0x4D504F4154314D32L)));
        out.add(new InsnNode(Opcodes.LMUL));
        JvmPassBytecode.pushLong(out, JvmPassBytecode.mix(mixed, 0x4D504F4154314132L));
        out.add(new InsnNode(Opcodes.LADD));
    }

    private static long nonZeroOddLong(long value) {
        long odd = value | 1L;
        return odd == 0L ? 0x4D504F414D415431L : odd;
    }

    private static int derivedLongShift(long seed, int base) {
        return 1 + (int) ((seed >>> base) & 62L);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, CarrierIndexPlan> carrierIndexPlans(PipelineContext pctx) {
        Map<String, CarrierIndexPlan> map = pctx.getPassData(CARRIER_INDEX_PLAN_BY_FINAL_KEY);
        if (map == null) {
            map = new LinkedHashMap<>();
            pctx.putPassData(CARRIER_INDEX_PLAN_BY_FINAL_KEY, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<CarrierAttestationSiteKey, Long> carrierAttestationSiteSeeds(PipelineContext pctx) {
        Map<CarrierAttestationSiteKey, Long> map = pctx.getPassData(CARRIER_ATTESTATION_SITE_SEEDS);
        if (map == null) {
            map = new LinkedHashMap<>();
            pctx.putPassData(CARRIER_ATTESTATION_SITE_SEEDS, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<AbstractInsnNode, CarrierIndexDecodeSite> carrierIndexDecodeSites(PipelineContext pctx) {
        Map<AbstractInsnNode, CarrierIndexDecodeSite> map = pctx.getPassData(CARRIER_INDEX_DECODE_SITES);
        if (map == null) {
            map = new IdentityHashMap<>();
            pctx.putPassData(CARRIER_INDEX_DECODE_SITES, map);
        }
        return map;
    }

    private static CarrierIndexPlan createCarrierIndexPlan(
        MethodPlan plan,
        long targetSeed,
        String carrierFamily,
        String anchorOwner
    ) {
        int count = carrierArgumentCount(plan);
        long seed = JvmPassBytecode.mix(targetSeed ^ CARRIER_INDEX_DOMAIN, carrierFamily.hashCode());
        seed = JvmPassBytecode.mix(seed, plan.packedDesc().hashCode());
        seed = JvmPassBytecode.mix(seed, plan.oldDesc().hashCode());
        seed = JvmPassBytecode.mix(seed, count);
        int step = carrierPermutationStep(count, seed);
        int encodedStep = step ^ carrierIndexWord(seed, 0x53544550);
        int encodedCount = count ^ carrierIndexWord(seed, 0x434F554E);
        int classKeyIdentity = carrierIndexWord(seed, 0x4B594944)
            ^ anchorOwner.hashCode()
            ^ carrierFamily.hashCode()
            ^ plan.packedDesc().hashCode();
        int classWordIndex = Math.floorMod(
            carrierIndexWord(seed ^ classKeyIdentity, 0x574F5244),
            CARRIER_INDEX_CLASS_WORDS
        );
        CarrierIndexCell[] cells = new CarrierIndexCell[count];
        for (int logical = 0; logical < count; logical++) {
            int physicalSlot = count == 0 ? 0 : Math.floorMod(logical * step, count);
            long cellSeed = JvmPassBytecode.mix(seed, logical ^ 0x43454C4CL);
            int guardMask = carrierIndexWord(cellSeed ^ classKeyIdentity, 0x47554152);
            cells[logical] = new CarrierIndexCell(
                logical,
                physicalSlot,
                Math.floorMod(classWordIndex + logical, CARRIER_INDEX_CLASS_WORDS),
                carrierIndexWord(cellSeed, 0x4D41534B),
                guardMask | 1
            );
        }
        return new CarrierIndexPlan(
            count,
            seed,
            encodedCount,
            encodedStep,
            classKeyIdentity,
            classWordIndex,
            cells,
            anchorOwner
        );
    }

    private static int carrierPermutationStep(int count, long seed) {
        if (count <= 1) return 1;
        int candidate = Math.floorMod(carrierIndexWord(seed, 0x53544550), count);
        if (candidate == 0) candidate = 1;
        for (int i = 0; i < count; i++) {
            int step = 1 + Math.floorMod(candidate + i, count);
            if (gcd(step, count) == 1) return step;
        }
        return 1;
    }

    private static int gcd(int a, int b) {
        a = Math.abs(a);
        b = Math.abs(b);
        while (b != 0) {
            int next = a % b;
            a = b;
            b = next;
        }
        return a == 0 ? 1 : a;
    }

    private static int carrierIndexWord(long seed, int domain) {
        long mixed = JvmPassBytecode.mix(seed, domain ^ 0x49445831L);
        return (int) mixed ^ Integer.rotateLeft((int) (mixed >>> 32), 13);
    }

    public static int rewriteCarrierIndexDecodeSites(
        PipelineContext pctx,
        MethodNode mn,
        ControlFlowFlatteningPass.CffClassKeyTable table,
        int keyLocal
    ) {
        Map<AbstractInsnNode, CarrierIndexDecodeSite> sites = carrierIndexDecodeSites(pctx);
        int replaced = 0;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (isCarrierIndexMarker(insn)) {
                CarrierIndexDecodeSite site = sites.remove(insn);
                if (site == null) {
                    throw new IllegalStateException("Unregistered carrier index decode marker");
                }
                ControlFlowFlatteningPass.CffClassKeyTable anchorTable =
                    ControlFlowFlatteningPass.classKeyTable(pctx, site.plan().anchorOwner());
                if (anchorTable == null) {
                    throw new IllegalStateException(
                        "Missing carrier index anchor class-key table for " + site.plan().anchorOwner()
                    );
                }
                InsnList replacement = new InsnList();
                emitDecodedCarrierIndex(
                    pctx,
                    replacement,
                    site.plan(),
                    site.logicalIndex(),
                    site.keyLocal() < 0 ? keyLocal : site.keyLocal(),
                    site.keyLocal() >= 0,
                    site.rewriteKeyToTarget(),
                    anchorTable,
                    site.targetSeed()
                );
                JvmKeyDispatchPass.markGenerated(pctx, replacement);
                mn.instructions.insertBefore(insn, replacement);
                mn.instructions.remove(insn);
                replaced++;
            }
            insn = next;
        }
        return replaced;
    }

    private static boolean isCarrierIndexMarker(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call
            && call.getOpcode() == Opcodes.INVOKESTATIC
            && CARRIER_INDEX_MARKER_OWNER.equals(call.owner)
            && CARRIER_INDEX_MARKER_NAME.equals(call.name)
            && CARRIER_INDEX_MARKER_DESC.equals(call.desc);
    }

    private static void emitDecodedCarrierIndex(
        PipelineContext pctx,
        InsnList out,
        CarrierIndexPlan plan,
        int logicalIndex,
        int keyLocal,
        boolean useLiveKey,
        boolean rewriteKeyToTarget,
        ControlFlowFlatteningPass.CffClassKeyTable table,
        long targetSeed
    ) {
        if (useLiveKey && keyLocal < 0) {
            throw new IllegalStateException("Carrier index decoding requires a live method key local");
        }
        CarrierIndexCell cell = plan.cell(logicalIndex);
        JvmPassBytecode.pushInt(out, cell.physicalSlot());
        emitCarrierIndexRuntimeOffset(out, plan, table);
        out.add(new InsnNode(Opcodes.IADD));
    }

    private static void emitDecodedCarrierIndexFromRuntimeTable(
        InsnList out,
        MethodPlan plan,
        int logicalIndex,
        int runtimeCarrierTableLocal
    ) {
        CarrierIndexCell cell = plan.carrierIndexPlan().cell(logicalIndex);
        JvmPassBytecode.pushInt(out, cell.physicalSlot());
        emitCarrierIndexRuntimeOffset(out, plan.carrierIndexPlan(), runtimeCarrierTableLocal);
        out.add(new InsnNode(Opcodes.IADD));
    }

    private static void emitCarrierIndexRuntimeOffset(
        InsnList out,
        CarrierIndexPlan plan,
        ControlFlowFlatteningPass.CffClassKeyTable table
    ) {
        out.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            table.owner(),
            table.objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        emitCarrierIndexRuntimeOffsetFromTableOnStack(out, plan);
    }

    private static void emitCarrierIndexRuntimeOffset(
        InsnList out,
        CarrierIndexPlan plan,
        int runtimeCarrierTableLocal
    ) {
        out.add(new VarInsnNode(Opcodes.ALOAD, runtimeCarrierTableLocal));
        emitCarrierIndexRuntimeOffsetFromTableOnStack(out, plan);
    }

    private static void emitCarrierIndexRuntimeOffsetFromTableOnStack(
        InsnList out,
        CarrierIndexPlan plan
    ) {
        JvmPassBytecode.pushInt(out, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SLOT);
        out.add(new InsnNode(Opcodes.AALOAD));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        JvmPassBytecode.pushInt(out, plan.classWordIndex());
        out.add(new InsnNode(Opcodes.IALOAD));
        JvmPassBytecode.pushInt(out, ControlFlowFlatteningPass.CLASS_KEY_WORD_SEAL);
        out.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(out, carrierIndexWord(plan.seed(), 0x4F464653));
        out.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(out, plan.classKeyIdentity());
        out.add(new InsnNode(Opcodes.IADD));
        out.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(out, 13);
        out.add(new InsnNode(Opcodes.IUSHR));
        out.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(out, plan.encodedCount() ^ carrierIndexWord(plan.seed(), 0x434F554E));
        out.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(out, plan.encodedStep() ^ carrierIndexWord(plan.seed(), 0x53544550));
        out.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(out, carrierIndexWord(plan.seed() ^ plan.classKeyIdentity(), 0x47554152) | 1);
        out.add(new InsnNode(Opcodes.IMUL));
        out.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(out, 17);
        out.add(new InsnNode(Opcodes.IUSHR));
        out.add(new InsnNode(Opcodes.IADD));
    }

    private MethodPlan resolvePlan(PipelineContext pctx, String owner, String name, String desc) {
        MethodPlan direct = planByOwnerNameDesc(pctx).get(key(owner, name, desc));
        if (direct != null) return direct;
        L1Class clazz = pctx.classMap().get(owner);
        if (clazz == null) return null;
        MethodPlan fromSuper = resolveInSuper(pctx, clazz.superName(), name, desc);
        if (fromSuper != null) return fromSuper;
        return resolveInInterfaces(pctx, clazz.interfaces(), name, desc);
    }

    private MethodPlan resolveInSuper(PipelineContext pctx, String owner, String name, String desc) {
        if (owner == null) return null;
        MethodPlan direct = planByOwnerNameDesc(pctx).get(key(owner, name, desc));
        if (direct != null) return direct;
        L1Class clazz = pctx.classMap().get(owner);
        if (clazz == null) return null;
        MethodPlan fromSuper = resolveInSuper(pctx, clazz.superName(), name, desc);
        if (fromSuper != null) return fromSuper;
        return resolveInInterfaces(pctx, clazz.interfaces(), name, desc);
    }

    private MethodPlan resolveInInterfaces(PipelineContext pctx, List<String> interfaces, String name, String desc) {
        for (String iface : interfaces) {
            MethodPlan direct = planByOwnerNameDesc(pctx).get(key(iface, name, desc));
            if (direct != null) return direct;
            L1Class clazz = pctx.classMap().get(iface);
            if (clazz == null) continue;
            MethodPlan nested = resolveInInterfaces(pctx, clazz.interfaces(), name, desc);
            if (nested != null) return nested;
        }
        return null;
    }

    private static void emitArrayLoad(InsnList out, int argsLocal, int index) {
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        JvmPassBytecode.pushInt(out, index);
        out.add(new InsnNode(Opcodes.AALOAD));
    }

    private static void emitCarrierArrayLoad(
        PipelineContext pctx,
        InsnList out,
        int argsLocal,
        MethodPlan plan,
        int logicalIndex,
        int keyLocal,
        boolean rewriteKeyToTarget,
        long targetSeed
    ) {
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        emitBoundedCarrierIndexForArrayOnStack(pctx, out, plan, logicalIndex, keyLocal, rewriteKeyToTarget, targetSeed);
        out.add(new InsnNode(Opcodes.AALOAD));
    }

    private static void emitCarrierArrayLoadSafe(
        PipelineContext pctx,
        InsnList out,
        int argsLocal,
        MethodPlan plan,
        int logicalIndex,
        int keyLocal,
        boolean rewriteKeyToTarget,
        long targetSeed
    ) {
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        emitBoundedCarrierIndexForArrayOnStack(pctx, out, plan, logicalIndex, keyLocal, rewriteKeyToTarget, targetSeed);
        out.add(new InsnNode(Opcodes.AALOAD));
    }

    private static void emitBoundedCarrierIndexForArrayOnStack(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int logicalIndex,
        int keyLocal,
        boolean rewriteKeyToTarget,
        long targetSeed
    ) {
        emitBoundedCarrierIndexForArrayOnStack(
            pctx,
            out,
            plan,
            logicalIndex,
            keyLocal,
            rewriteKeyToTarget,
            targetSeed,
            -1
        );
    }

    private static void emitBoundedCarrierIndexForArrayOnStack(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int logicalIndex,
        int keyLocal,
        boolean rewriteKeyToTarget,
        long targetSeed,
        int runtimeCarrierTableLocal
    ) {
        out.add(new InsnNode(Opcodes.DUP));
        if (runtimeCarrierTableLocal >= 0) {
            emitDecodedCarrierIndexFromRuntimeTable(out, plan, logicalIndex, runtimeCarrierTableLocal);
        } else {
            emitCarrierIndexDecodeMarker(pctx, out, plan, logicalIndex, keyLocal, rewriteKeyToTarget, targetSeed);
        }
        out.add(new InsnNode(Opcodes.SWAP));
        out.add(new InsnNode(Opcodes.ARRAYLENGTH));
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "floorMod", "(II)I", false));
    }

    private static void emitCarrierShapeValidation(InsnList out, int argsLocal, MethodPlan plan) {
        out.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        out.add(new InsnNode(Opcodes.ARRAYLENGTH));
        JvmPassBytecode.pushInt(out, carrierArgumentCount(plan));
        LabelNode ok = new LabelNode();
        out.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, ok));
        emitAttestationFailure(out, plan.syntheticHiddenKey());
        out.add(ok);
    }

    private static void emitCarrierAttestationValidation(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int argsLocal,
        int incomingKeyTemp,
        int carrierIndexKeyTemp,
        int tokenTemp,
        int tagTemp
    ) {
        emitCarrierArrayLoadSafe(
            pctx,
            out,
            argsLocal,
            plan,
            carrierAttestationTokenLogicalIndex(plan),
            carrierIndexKeyTemp,
            false,
            plan.carrierIndexKeySeed()
        );
        emitUnboxOrCast(out, Type.LONG_TYPE);
        out.add(new VarInsnNode(Opcodes.LSTORE, tokenTemp));
        emitCarrierArrayLoadSafe(
            pctx,
            out,
            argsLocal,
            plan,
            carrierAttestationTagLogicalIndex(plan),
            carrierIndexKeyTemp,
            false,
            plan.carrierIndexKeySeed()
        );
        emitUnboxOrCast(out, Type.LONG_TYPE);
        out.add(new VarInsnNode(Opcodes.LSTORE, tagTemp));
        emitCarrierAttestationTokenValidation(
            pctx,
            out,
            plan,
            incomingKeyTemp,
            carrierIndexKeyTemp,
            tokenTemp
        );
        emitCarrierAttestationExpectedTagFromLocals(pctx, out, plan, incomingKeyTemp, carrierIndexKeyTemp, tokenTemp);
        out.add(new VarInsnNode(Opcodes.LLOAD, tagTemp));
        out.add(new InsnNode(Opcodes.LCMP));
        LabelNode ok = new LabelNode();
        out.add(new JumpInsnNode(Opcodes.IFEQ, ok));
        emitAttestationFailure(out, plan.syntheticHiddenKey());
        out.add(ok);
    }

    private static void emitCarrierAttestationTokenValidation(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int incomingKeyTemp,
        int carrierIndexKeyTemp,
        int tokenTemp
    ) {
        LabelNode ok = new LabelNode();
        for (long siteSeed : plan.carrierAttestationSiteSeeds()) {
            emitCarrierAttestationTokenFromLocals(pctx, out, plan, incomingKeyTemp, carrierIndexKeyTemp, siteSeed);
            out.add(new VarInsnNode(Opcodes.LLOAD, tokenTemp));
            out.add(new InsnNode(Opcodes.LCMP));
            out.add(new JumpInsnNode(Opcodes.IFEQ, ok));
        }
        emitAttestationFailure(out, plan.syntheticHiddenKey());
        out.add(ok);
    }

    private static CarrierCallsiteKeys materializeCarrierCallsiteKeys(
        PipelineContext pctx,
        MethodNode mn,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        String targetKind
    ) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) return null;
        if (callerKeyLocal == null) {
            throw new IllegalStateException(
                "Missing caller key for methodParameterObfuscation carrier keys " + targetKind + " " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        int targetKeyLocal = allocateLocal(mn, Type.LONG_TYPE);
        int carrierIndexKeyLocal = allocateLocal(mn, Type.LONG_TYPE);
        emitCallerKeyForTarget(pctx, out, callerKeyLocal, seedForPlan(pctx, plan));
        out.add(new VarInsnNode(Opcodes.LSTORE, targetKeyLocal));
        emitCallerKeyForTarget(pctx, out, callerKeyLocal, plan.carrierIndexKeySeed());
        out.add(new VarInsnNode(Opcodes.LSTORE, carrierIndexKeyLocal));
        return new CarrierCallsiteKeys(targetKeyLocal, carrierIndexKeyLocal);
    }

    private static int carrierStoreKeyLocal(Integer callerKeyLocal, CarrierCallsiteKeys carrierKeys) {
        if (carrierKeys != null) return carrierKeys.carrierIndexKeyLocal();
        if (callerKeyLocal == null) return -1;
        return callerKeyLocal;
    }

    private static void emitCarrierAttestationStores(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        CarrierCallsiteKeys carrierKeys,
        long siteSeed,
        String targetKind
    ) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) return;
        if (callerKeyLocal == null && carrierKeys == null) {
            throw new IllegalStateException(
                "Missing caller key for methodParameterObfuscation carrier attestation " + targetKind + " " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        out.add(new InsnNode(Opcodes.DUP));
        emitBoundedCarrierIndexForArrayOnStack(
            pctx,
            out,
            plan,
            carrierAttestationTokenLogicalIndex(plan),
            carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
            carrierKeys == null,
            plan.carrierIndexKeySeed()
        );
        if (carrierKeys == null) {
            emitCarrierAttestationTokenFromCaller(pctx, out, plan, callerKeyLocal, siteSeed);
        } else {
            emitCarrierAttestationTokenFromLocals(
                pctx,
                out,
                plan,
                carrierKeys.targetKeyLocal(),
                carrierKeys.carrierIndexKeyLocal(),
                siteSeed
            );
        }
        emitBox(out, Type.LONG_TYPE);
        out.add(new InsnNode(Opcodes.AASTORE));

        out.add(new InsnNode(Opcodes.DUP));
        emitBoundedCarrierIndexForArrayOnStack(
            pctx,
            out,
            plan,
            carrierAttestationTagLogicalIndex(plan),
            carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
            carrierKeys == null,
            plan.carrierIndexKeySeed()
        );
        if (carrierKeys == null) {
            emitCarrierAttestationTagFromCaller(pctx, out, plan, callerKeyLocal, siteSeed);
        } else {
            emitCarrierAttestationTagFromLocals(
                pctx,
                out,
                plan,
                carrierKeys.targetKeyLocal(),
                carrierKeys.carrierIndexKeyLocal(),
                siteSeed
            );
        }
        emitBox(out, Type.LONG_TYPE);
        out.add(new InsnNode(Opcodes.AASTORE));
    }

    private static void emitCarrierAttestationStoresFromLocal(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        CarrierCallsiteKeys carrierKeys,
        int carrierLocal,
        long siteSeed,
        String targetKind
    ) {
        emitCarrierAttestationStoresFromLocal(
            pctx,
            out,
            plan,
            callerKeyLocal,
            carrierKeys,
            carrierLocal,
            siteSeed,
            targetKind,
            -1
        );
    }

    private static void emitCarrierAttestationStoresFromLocal(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        CarrierCallsiteKeys carrierKeys,
        int carrierLocal,
        long siteSeed,
        String targetKind,
        int runtimeCarrierTableLocal
    ) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) return;
        if (callerKeyLocal == null && carrierKeys == null) {
            throw new IllegalStateException(
                "Missing caller key for methodParameterObfuscation carrier attestation " + targetKind + " " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        out.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        emitBoundedCarrierIndexForArrayOnStack(
            pctx,
            out,
            plan,
            carrierAttestationTokenLogicalIndex(plan),
            carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
            carrierKeys == null,
            plan.carrierIndexKeySeed(),
            runtimeCarrierTableLocal
        );
        if (carrierKeys == null) {
            emitCarrierAttestationTokenFromCaller(pctx, out, plan, callerKeyLocal, siteSeed);
        } else {
            emitCarrierAttestationTokenFromLocals(
                pctx,
                out,
                plan,
                carrierKeys.targetKeyLocal(),
                carrierKeys.carrierIndexKeyLocal(),
                siteSeed
            );
        }
        emitBox(out, Type.LONG_TYPE);
        out.add(new InsnNode(Opcodes.AASTORE));

        out.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        emitBoundedCarrierIndexForArrayOnStack(
            pctx,
            out,
            plan,
            carrierAttestationTagLogicalIndex(plan),
            carrierStoreKeyLocal(callerKeyLocal, carrierKeys),
            carrierKeys == null,
            plan.carrierIndexKeySeed(),
            runtimeCarrierTableLocal
        );
        if (carrierKeys == null) {
            emitCarrierAttestationTagFromCaller(pctx, out, plan, callerKeyLocal, siteSeed);
        } else {
            emitCarrierAttestationTagFromLocals(
                pctx,
                out,
                plan,
                carrierKeys.targetKeyLocal(),
                carrierKeys.carrierIndexKeyLocal(),
                siteSeed
            );
        }
        emitBox(out, Type.LONG_TYPE);
        out.add(new InsnNode(Opcodes.AASTORE));
    }

    private static void emitCarrierAttestationTokenFromCaller(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int callerKeyLocal,
        long siteSeed
    ) {
        long planSeed = carrierAttestationPlanSeed(pctx, plan);
        emitCallerKeyForTarget(pctx, out, callerKeyLocal, seedForPlan(pctx, plan));
        emitCallerKeyForTarget(pctx, out, callerKeyLocal, plan.carrierIndexKeySeed());
        out.add(new InsnNode(Opcodes.LXOR));
        emitLiveSeededLongMaterial(out, siteSeed, JvmPassBytecode.mix(planSeed, CARRIER_ATTEST_SITE_DOMAIN));
        emitAttestationDomainSeal(out, JvmPassBytecode.mix(planSeed, siteSeed));
    }

    private static void emitCarrierAttestationTagFromCaller(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int callerKeyLocal,
        long siteSeed
    ) {
        emitCarrierAttestationTokenFromCaller(pctx, out, plan, callerKeyLocal, siteSeed);
        emitRotatedCallerKey(pctx, out, callerKeyLocal, seedForPlan(pctx, plan), 29);
        out.add(new InsnNode(Opcodes.LADD));
        emitRotatedCallerKey(pctx, out, callerKeyLocal, plan.carrierIndexKeySeed(), 17);
        out.add(new InsnNode(Opcodes.LXOR));
        emitLiveSeededLongMaterial(
            out,
            carrierAttestationTagSeed(pctx, plan),
            JvmPassBytecode.mix(carrierAttestationPlanSeed(pctx, plan), CARRIER_ATTEST_TAG_DOMAIN)
        );
        emitAttestationDomainSeal(out, carrierAttestationTagSeed(pctx, plan));
    }

    private static void emitCarrierAttestationTagFromLocals(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int incomingKeyLocal,
        int carrierIndexKeyLocal,
        long siteSeed
    ) {
        emitCarrierAttestationTokenFromLocals(pctx, out, plan, incomingKeyLocal, carrierIndexKeyLocal, siteSeed);
        emitRotatedLocalLong(out, incomingKeyLocal, 29);
        out.add(new InsnNode(Opcodes.LADD));
        emitRotatedLocalLong(out, carrierIndexKeyLocal, 17);
        out.add(new InsnNode(Opcodes.LXOR));
        emitLiveSeededLongMaterial(
            out,
            carrierAttestationTagSeed(pctx, plan),
            JvmPassBytecode.mix(carrierAttestationPlanSeed(pctx, plan), CARRIER_ATTEST_TAG_DOMAIN)
        );
        emitAttestationDomainSeal(out, carrierAttestationTagSeed(pctx, plan));
    }

    private static void emitCarrierAttestationExpectedTagFromLocals(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int incomingKeyTemp,
        int carrierIndexKeyTemp,
        int tokenTemp
    ) {
        out.add(new VarInsnNode(Opcodes.LLOAD, tokenTemp));
        emitRotatedLocalLong(out, incomingKeyTemp, 29);
        out.add(new InsnNode(Opcodes.LADD));
        emitRotatedLocalLong(out, carrierIndexKeyTemp, 17);
        out.add(new InsnNode(Opcodes.LXOR));
        emitLiveSeededLongMaterial(
            out,
            carrierAttestationTagSeed(pctx, plan),
            JvmPassBytecode.mix(carrierAttestationPlanSeed(pctx, plan), CARRIER_ATTEST_TAG_DOMAIN)
        );
        emitAttestationDomainSeal(out, carrierAttestationTagSeed(pctx, plan));
    }

    private static void emitCarrierAttestationTokenFromLocals(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int incomingKeyTemp,
        int carrierIndexKeyTemp,
        long siteSeed
    ) {
        long planSeed = carrierAttestationPlanSeed(pctx, plan);
        out.add(new VarInsnNode(Opcodes.LLOAD, incomingKeyTemp));
        out.add(new VarInsnNode(Opcodes.LLOAD, carrierIndexKeyTemp));
        out.add(new InsnNode(Opcodes.LXOR));
        emitLiveSeededLongMaterial(out, siteSeed, JvmPassBytecode.mix(planSeed, CARRIER_ATTEST_SITE_DOMAIN));
        emitAttestationDomainSeal(out, JvmPassBytecode.mix(planSeed, siteSeed));
    }

    private static void emitAttestationDomainSeal(InsnList out, long seed) {
        JvmPassBytecode.pushLong(out, nonZeroOddLong(JvmPassBytecode.mix(seed, 0x4154545345414C31L)));
        out.add(new InsnNode(Opcodes.LXOR));
        out.add(new InsnNode(Opcodes.LCONST_1));
        out.add(new InsnNode(Opcodes.LOR));
    }

    private static void emitCallerKeyForTarget(
        PipelineContext pctx,
        InsnList out,
        int callerKeyLocal,
        long targetSeed
    ) {
        VarInsnNode keyLoad = new VarInsnNode(Opcodes.LLOAD, callerKeyLocal);
        out.add(keyLoad);
        cffKeyLoadTargetSeeds(pctx).put(keyLoad, targetSeed);
    }

    private static void emitRotatedCallerKey(
        PipelineContext pctx,
        InsnList out,
        int callerKeyLocal,
        long targetSeed,
        int distance
    ) {
        emitCallerKeyForTarget(pctx, out, callerKeyLocal, targetSeed);
        JvmPassBytecode.pushInt(out, distance);
        out.add(new InsnNode(Opcodes.LSHL));
        emitCallerKeyForTarget(pctx, out, callerKeyLocal, targetSeed);
        JvmPassBytecode.pushInt(out, 64 - distance);
        out.add(new InsnNode(Opcodes.LUSHR));
        out.add(new InsnNode(Opcodes.LOR));
    }

    private static void emitRotatedLocalLong(InsnList out, int local, int distance) {
        out.add(new VarInsnNode(Opcodes.LLOAD, local));
        JvmPassBytecode.pushInt(out, distance);
        out.add(new InsnNode(Opcodes.LSHL));
        out.add(new VarInsnNode(Opcodes.LLOAD, local));
        JvmPassBytecode.pushInt(out, 64 - distance);
        out.add(new InsnNode(Opcodes.LUSHR));
        out.add(new InsnNode(Opcodes.LOR));
    }

    private static void emitAttestationFailure(InsnList out, boolean preSuperConstructorPath) {
        if (preSuperConstructorPath) {
            out.add(new InsnNode(Opcodes.ACONST_NULL));
            out.add(new InsnNode(Opcodes.ATHROW));
            return;
        }
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/SecurityException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(
            Opcodes.INVOKESPECIAL,
            "java/lang/SecurityException",
            "<init>",
            "()V",
            false
        ));
        out.add(new InsnNode(Opcodes.ATHROW));
    }

    private static void emitCarrierIndexKeyStore(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        CarrierCallsiteKeys carrierKeys,
        String targetKind
    ) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) return;
        if (callerKeyLocal == null && carrierKeys == null) {
            throw new IllegalStateException(
                "Missing caller key for methodParameterObfuscation carrier index key " + targetKind + " " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        out.add(new InsnNode(Opcodes.DUP));
        emitBoundedCarrierIndexForArrayOnStack(
            pctx,
            out,
            plan,
            carrierIndexKeyLogicalIndex(plan),
            -1,
            false,
            plan.carrierIndexKeySeed()
        );
        if (carrierKeys == null) {
            VarInsnNode keyLoad = new VarInsnNode(Opcodes.LLOAD, callerKeyLocal);
            out.add(keyLoad);
            cffKeyLoadTargetSeeds(pctx).put(keyLoad, plan.carrierIndexKeySeed());
        } else {
            out.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.carrierIndexKeyLocal()));
        }
        emitBox(out, Type.LONG_TYPE);
        out.add(new InsnNode(Opcodes.AASTORE));
    }

    private static void emitCarrierIndexKeyStoreFromLocal(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        CarrierCallsiteKeys carrierKeys,
        int carrierLocal,
        String targetKind
    ) {
        emitCarrierIndexKeyStoreFromLocal(
            pctx,
            out,
            plan,
            callerKeyLocal,
            carrierKeys,
            carrierLocal,
            targetKind,
            -1
        );
    }

    private static void emitCarrierIndexKeyStoreFromLocal(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        Integer callerKeyLocal,
        CarrierCallsiteKeys carrierKeys,
        int carrierLocal,
        String targetKind,
        int runtimeCarrierTableLocal
    ) {
        if (packedHiddenKeyArgumentIndex(plan) < 0) return;
        if (callerKeyLocal == null && carrierKeys == null) {
            throw new IllegalStateException(
                "Missing caller key for methodParameterObfuscation carrier index key " + targetKind + " " +
                    plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        out.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        emitBoundedCarrierIndexForArrayOnStack(
            pctx,
            out,
            plan,
            carrierIndexKeyLogicalIndex(plan),
            -1,
            false,
            plan.carrierIndexKeySeed(),
            runtimeCarrierTableLocal
        );
        if (carrierKeys == null) {
            VarInsnNode keyLoad = new VarInsnNode(Opcodes.LLOAD, callerKeyLocal);
            out.add(keyLoad);
            cffKeyLoadTargetSeeds(pctx).put(keyLoad, plan.carrierIndexKeySeed());
        } else {
            out.add(new VarInsnNode(Opcodes.LLOAD, carrierKeys.carrierIndexKeyLocal()));
        }
        emitBox(out, Type.LONG_TYPE);
        out.add(new InsnNode(Opcodes.AASTORE));
    }

    private static void emitCarrierIndexDecodeMarker(
        PipelineContext pctx,
        InsnList out,
        MethodPlan plan,
        int logicalIndex,
        Integer keyLocal,
        boolean rewriteKeyToTarget,
        long targetSeed
    ) {
        CarrierIndexPlan indexPlan = plan.carrierIndexPlan();
        if (indexPlan == null) {
            throw new IllegalStateException(
                "Missing carrier index plan for " + plan.owner() + "." + plan.finalName() + plan.packedDesc()
            );
        }
        MethodInsnNode marker = new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            CARRIER_INDEX_MARKER_OWNER,
            CARRIER_INDEX_MARKER_NAME,
            CARRIER_INDEX_MARKER_DESC,
            false
        );
        carrierIndexDecodeSites(pctx).put(marker, new CarrierIndexDecodeSite(
            indexPlan,
            logicalIndex,
            plan.owner(),
            plan.finalName(),
            plan.packedDesc(),
            targetSeed,
            keyLocal == null ? -1 : keyLocal,
            rewriteKeyToTarget
        ));
        out.add(marker);
    }

    private static void emitUnboxOrCast(InsnList out, Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Boolean"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false));
            }
            case Type.CHAR -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Character"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false));
            }
            case Type.BYTE -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Byte"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Byte", "byteValue", "()B", false));
            }
            case Type.SHORT -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Short"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Short", "shortValue", "()S", false));
            }
            case Type.INT -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false));
            }
            case Type.FLOAT -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Float"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Float", "floatValue", "()F", false));
            }
            case Type.LONG -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false));
            }
            case Type.DOUBLE -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Double"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Double", "doubleValue", "()D", false));
            }
            case Type.ARRAY -> out.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getDescriptor()));
            case Type.OBJECT -> out.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getInternalName()));
            default -> throw new IllegalStateException("Unsupported parameter type: " + type);
        }
    }

    private static void emitBox(InsnList out, Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false));
            case Type.CHAR -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false));
            case Type.BYTE -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false));
            case Type.SHORT -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false));
            case Type.INT -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
            case Type.FLOAT -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false));
            case Type.LONG -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false));
            case Type.DOUBLE -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false));
            case Type.ARRAY, Type.OBJECT -> {
            }
            default -> throw new IllegalStateException("Unsupported parameter type: " + type);
        }
    }

    private static int allocateLocal(MethodNode mn, Type type) {
        int local = mn.maxLocals;
        mn.maxLocals += type.getSize();
        return local;
    }

    private static List<AbstractInsnNode> instructionNodes(InsnList insns) {
        List<AbstractInsnNode> nodes = new ArrayList<>();
        for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
            nodes.add(insn);
        }
        return nodes;
    }

    private static void markGeneratedNodes(PipelineContext pctx, List<AbstractInsnNode> nodes) {
        JvmKeyDispatchPass.generatedNodes(pctx).addAll(nodes);
    }

    private static AbstractInsnNode firstRealInstruction(MethodNode mn) {
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) return insn;
        }
        return mn.instructions.getFirst();
    }

    private static void cleanupParameterMetadata(MethodNode mn) {
        mn.signature = null;
        mn.parameters = null;
        mn.visibleParameterAnnotations = null;
        mn.invisibleParameterAnnotations = null;
        mn.visibleTypeAnnotations = null;
        mn.invisibleTypeAnnotations = null;
        mn.visibleLocalVariableAnnotations = null;
        mn.invisibleLocalVariableAnnotations = null;
        if (mn.localVariables == null) return;
        for (LocalVariableNode local : mn.localVariables) {
            if (local.index > 0 || (mn.access & Opcodes.ACC_STATIC) != 0) {
                local.desc = "Ljava/lang/Object;";
                local.signature = null;
            }
        }
    }

    private static boolean overridesExternalMethod(PipelineContext pctx, L1Class clazz, MethodNode mn, String desc) {
        return overridesExternalIn(pctx, clazz.superName(), mn.name, desc)
            || overridesExternalInInterfaces(pctx, clazz.interfaces(), mn.name, desc);
    }

    private static boolean overridesExternalIn(PipelineContext pctx, String owner, String name, String desc) {
        if (owner == null) return false;
        L1Class appClass = pctx.classMap().get(owner);
        if (appClass != null) {
            if (appClass.findMethod(name, desc) != null) return false;
            return overridesExternalIn(pctx, appClass.superName(), name, desc)
                || overridesExternalInInterfaces(pctx, appClass.interfaces(), name, desc);
        }
        return externalClassDeclares(owner, name, desc);
    }

    private static boolean overridesExternalInInterfaces(PipelineContext pctx, List<String> interfaces, String name, String desc) {
        for (String iface : interfaces) {
            L1Class appInterface = pctx.classMap().get(iface);
            if (appInterface != null) {
                if (appInterface.findMethod(name, desc) != null) return false;
                if (overridesExternalInInterfaces(pctx, appInterface.interfaces(), name, desc)) return true;
                continue;
            }
            if (externalClassDeclares(iface, name, desc)) return true;
        }
        return false;
    }

    private static boolean externalClassDeclares(String owner, String name, String desc) {
        try {
            Class<?> type = Class.forName(owner.replace('/', '.'), false, JvmMethodParameterObfuscationPass.class.getClassLoader());
            for (java.lang.reflect.Method method : type.getDeclaredMethods()) {
                if (method.getName().equals(name) && Type.getMethodDescriptor(method).equals(desc)) return true;
            }
            for (java.lang.reflect.Constructor<?> ctor : type.getDeclaredConstructors()) {
                if ("<init>".equals(name) && Type.getConstructorDescriptor(ctor).equals(desc)) return true;
            }
            return false;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String key(String owner, String name, String desc) {
        return owner + "." + name + desc;
    }

    private static final class MethodPlan {
        private final String owner;
        private final String oldName;
        private final String oldDesc;
        private String finalName;
        private final String packedDesc;
        private final Type[] argumentTypes;
        private final int[] argumentLocals;
        private final Integer keyLocal;
        private final boolean splitHiddenKey;
        private final boolean syntheticHiddenKey;
        private final Type[] packedSuffixTypes;
        private final boolean hasCode;
        private CarrierIndexPlan carrierIndexPlan;
        private long carrierIndexKeySeed;
        private final List<Long> carrierAttestationSiteSeeds = new ArrayList<>();

        MethodPlan(
            String owner,
            String oldName,
            String oldDesc,
            String finalName,
            String packedDesc,
            Type[] argumentTypes,
            int[] argumentLocals,
            Integer keyLocal,
            boolean splitHiddenKey,
            boolean syntheticHiddenKey,
            Type[] packedSuffixTypes,
            boolean hasCode
        ) {
            this.owner = owner;
            this.oldName = oldName;
            this.oldDesc = oldDesc;
            this.finalName = finalName;
            this.packedDesc = packedDesc;
            this.argumentTypes = argumentTypes;
            this.argumentLocals = argumentLocals;
            this.keyLocal = keyLocal;
            this.splitHiddenKey = splitHiddenKey;
            this.syntheticHiddenKey = syntheticHiddenKey;
            this.packedSuffixTypes = packedSuffixTypes;
            this.hasCode = hasCode;
        }

        String owner() { return owner; }
        String oldName() { return oldName; }
        String oldDesc() { return oldDesc; }
        String finalName() { return finalName; }
        void finalName(String value) { this.finalName = value; }
        String packedDesc() { return packedDesc; }
        Type[] argumentTypes() { return argumentTypes; }
        int[] argumentLocals() { return argumentLocals; }
        Integer keyLocal() { return keyLocal; }
        CarrierIndexPlan carrierIndexPlan() { return carrierIndexPlan; }
        void carrierIndexPlan(CarrierIndexPlan value) { this.carrierIndexPlan = value; }
        long carrierIndexKeySeed() { return carrierIndexKeySeed; }
        void carrierIndexKeySeed(long value) { this.carrierIndexKeySeed = value; }
        List<Long> carrierAttestationSiteSeeds() { return carrierAttestationSiteSeeds; }
        void addCarrierAttestationSiteSeed(long value) {
            if (!carrierAttestationSiteSeeds.contains(value)) {
                carrierAttestationSiteSeeds.add(value);
            }
        }
        boolean splitHiddenKey() { return splitHiddenKey; }
        boolean syntheticHiddenKey() { return syntheticHiddenKey; }
        Type[] packedSuffixTypes() { return packedSuffixTypes; }
        boolean hasCode() { return hasCode; }
    }

    public record CarrierIndexPlan(
        int carrierCount,
        long seed,
        int encodedCount,
        int encodedStep,
        int classKeyIdentity,
        int classWordIndex,
        CarrierIndexCell[] cells,
        String anchorOwner
    ) {
        CarrierIndexCell cell(int logicalIndex) {
            if (logicalIndex < 0 || logicalIndex >= cells.length) {
                throw new IllegalStateException(
                    "Invalid carrier logical index " + logicalIndex + " for " + carrierCount
                );
            }
            return cells[logicalIndex];
        }
    }

    public record CarrierIndexCell(
        int logicalIndex,
        int physicalSlot,
        int classWordIndex,
        int mixSalt,
        int guardMask
    ) {}

    private record CarrierCallsiteKeys(int targetKeyLocal, int carrierIndexKeyLocal) {}

    private record DynamicProxyHandlerTarget(int methodLocal, int argsLocal, List<MethodPlan> plans) {}

    private record InvocationHandlerSamLocals(int methodLocal, int argsLocal) {}

    public record CarrierIndexDecodeSite(
        CarrierIndexPlan plan,
        int logicalIndex,
        String owner,
        String name,
        String desc,
        long targetSeed,
        int keyLocal,
        boolean rewriteKeyToTarget
    ) {}

    private record CarrierAttestationSiteKey(String targetKey, AbstractInsnNode site, String siteKind) {}

    private record ReflectiveSourcePlans(boolean known, List<MethodPlan> plans) {
        static ReflectiveSourcePlans unknown() {
            return new ReflectiveSourcePlans(false, List.of());
        }

        static ReflectiveSourcePlans known(List<MethodPlan> plans) {
            return new ReflectiveSourcePlans(true, plans);
        }
    }

    private record MethodHandleLookupTarget(String owner, String name, String lookupKind, Type[] parameterTypes) {
        MethodHandleLookupTarget(String owner, String name, String lookupKind) {
            this(owner, name, lookupKind, null);
        }
    }

    private record MethodHandleRewriteTarget(MethodPlan plan, String lookupKind) {}

    private record MethodHandleRuntimeCandidate(MethodPlan plan, Type receiverType) {}

    private record CallerAttestationIdentity(String owner, String name, String desc) {}
}
