package dev.nekoobfuscator.transforms.jvm.invoke;

import dev.nekoobfuscator.api.transform.IRLevel;
import dev.nekoobfuscator.api.transform.TransformContext;
import dev.nekoobfuscator.api.transform.TransformPass;
import dev.nekoobfuscator.api.transform.TransformPhase;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.pipeline.GeneratedHelperTargetMap;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.util.JvmObfuscationCoverage;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import dev.nekoobfuscator.transforms.jvm.internal.JvmCodeSizeEstimator;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;
import dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningPass;
import dev.nekoobfuscator.transforms.jvm.constants.JvmStaticArrayMaterial;
import dev.nekoobfuscator.transforms.jvm.constants.JvmStaticArrayMaterial.PrimitiveArrayKind;
import dev.nekoobfuscator.transforms.jvm.key.JvmKeyDispatchPass;
import dev.nekoobfuscator.transforms.jvm.validation.JvmValidationSinkHardeningPass;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
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
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Flow-keyed invokedynamic reference obfuscation for CFF-protected code.
 */
public final class JvmInvokeDynamicObfuscationPass implements TransformPass {
    public static final String ID = "invokeDynamic";

    private static final int KIND_GETFIELD = 1;
    private static final int KIND_PUTFIELD = 2;
    private static final int KIND_GETSTATIC = 3;
    private static final int KIND_PUTSTATIC = 4;
    private static final int KIND_INVOKEVIRTUAL = 5;
    private static final int KIND_INVOKESTATIC = 6;
    private static final int KIND_INVOKEINTERFACE = 7;
    private static final int KIND_INVOKESPECIAL = 8;
    private static final int KIND_GETSTATIC_ARRAY_MATERIAL = 9;
    private static final int KIND_PUTSTATIC_ARRAY_MATERIAL = 10;

    private static final long OWNER_SEED = 0x494E44594F574E31L;
    private static final long NAME_SEED = 0x494E44594E414D31L;
    private static final long DESC_SEED = 0x494E445944455331L;
    private static final long CHAR_STRIDE = 0xD1342543DE82EF95L;
    private static final int RESOLVER_FLOW_LOCAL = 12;
    private static final int GENERATED_HELPER_HARDENING_SIZE_PRESSURE = 12_000;

    private static final String LOOKUP = "java/lang/invoke/MethodHandles$Lookup";
    private static final String METHOD_HANDLES = "java/lang/invoke/MethodHandles";
    private static final String METHOD_HANDLE = "java/lang/invoke/MethodHandle";
    private static final String METHOD_TYPE = "java/lang/invoke/MethodType";
    private static final String CALL_SITE = "java/lang/invoke/CallSite";
    private static final String MUTABLE_CALL_SITE = "java/lang/invoke/MutableCallSite";
    private static final String OBJECT = "java/lang/Object";
    private static final String OBJECT_ARRAY_DESC = "[Ljava/lang/Object;";
    private static final String OBJECT_ARRAY_TO_VOID_DESC = "([Ljava/lang/Object;)V";
    private static final String CLASS = "java/lang/Class";
    private static final String LONG = "java/lang/Long";
    private static final String BOOLEAN = "java/lang/Boolean";
    private static final String VOID = "java/lang/Void";
    private static final String CONCURRENT_HASH_MAP = "java/util/concurrent/ConcurrentHashMap";

    private static final String BSM_DESC =
        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
            "Ljava/lang/String;ILjava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;";
    private static final String BSM_CORE_DESC =
        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
            "Ljava/lang/String;I[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;";
    private static final String RESOLVER_DESC =
        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/invoke/MutableCallSite;Ljava/lang/invoke/MethodType;" +
        "Ljava/lang/String;I[Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
    private static final String FLOW_DESC = "(IIIII[Ljava/lang/Object;IJ)J";
    private static final String COMPACT_FLOW_DESC = "(II[Ljava/lang/Object;IJ)J";
    private static final String KEY_DESC = "([Ljava/lang/Object;I)J";
    private static final String HELPERS_KEY = "invokeDynamic.classHelpers";
    private static final String SHARED_HELPERS_KEY = "invokeDynamic.sharedHelpers";
    private static final String FLOW_TABLES_KEY = "invokeDynamic.flowSaltTables";
    private static final String PAYLOAD_SITES_KEY = "invokeDynamic.payloadSites";
    private static final int OUTLINED_SITE_SIZE_PRESSURE = 55_000;
    private static final int INDY_INIT_INLINE_CELL_LIMIT = 64;
    private static final int INDY_INIT_CHUNK_MAX_CELLS = 48;
    private static final String STATIC_ARRAY_MATERIAL_ELIGIBLE_KEY =
        "invokeDynamic.staticPrimitiveArrayMaterial.eligible";
    private static final int INDY_CELL_DESCRIPTOR_SLOT = 0;
    private static final int INDY_CELL_SPAN_SHIFT = 0;
    private static final int INDY_CELL_STRIDE_SHIFT = 8;
    private static final int INDY_CELL_OFFSET_SHIFT = 16;
    private static final int INDY_CELL_LAYOUT_SHIFT = 24;
    private static final long INDY_CELL_BYTE_MASK = 0xFFL;
    private static final int INDY_FLOW_EPOCH_LOGICAL = 0;
    private static final int INDY_FLOW_METHOD_SALT_LOGICAL = 1;
    private static final int INDY_FLOW_SITE_SEED_LOGICAL = 2;
    private static final int INDY_FLOW_STATE_LOGICAL = 3;
    private static final int INDY_FLOW_PC_TOKEN_LOGICAL = 4;
    private static final int INDY_FLOW_METHOD_KEY_LOGICAL = 5;
    private static final int INDY_FLOW_GUARD_LOGICAL = 6;
    private static final int INDY_FLOW_PATH_LOGICAL = 7;
    private static final int INDY_FLOW_BLOCK_LOGICAL = 8;
    private static final int INDY_FLOW_CLASS_WORD_LOGICAL = 9;
    private static final int INDY_RESOLVER_EPOCH_LOGICAL = 0;
    private static final int INDY_RESOLVER_SEED_LOGICAL = 1;
    private static final int INDY_RESOLVER_SALT_LOGICAL = 2;
    private static final int INDY_ARRAY_MATERIAL_TABLE_LOGICAL = 3;
    private static final int FLOW_HELPER_DATA_WORD_LOCAL = 4;
    private static final int FLOW_HELPER_METHOD_KEY_LOCAL = 7;
    private static final int COMPACT_FLOW_HELPER_METHOD_KEY_LOCAL = 4;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "JVM InvokeDynamic Reference Obfuscation";
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
        // Class-level helper setup is driven lazily from protected callsites.
    }

    @Override
    public void transformMethod(TransformContext ctx) {
        if (!(ctx instanceof PipelineContext pctx)) return;
        L1Class clazz = pctx.currentL1Class();
        L1Method method = pctx.currentL1Method();
        if (clazz == null || method == null || !method.hasCode()) return;
        if (TransformGuards.isRuntimeClass(clazz)) return;
        boolean generatedHelper = TransformGuards.isGeneratedMethod(method);
        boolean hardenGeneratedHelper =
            Boolean.TRUE.equals(pctx.getPassData("invokeDynamic.hardenGeneratedHelpers"));
        if (generatedHelper && !hardenGeneratedHelper) return;
        if (method.isAbstract() || method.isNative()) return;
        if (generatedHelper
            && hardenGeneratedHelper
            && generatedHelperUnderSizePressure(method.asmNode())
            && !hasGeneratedValidationFinalStageCall(clazz, method.asmNode())) {
            return;
        }

        String methodKey = JvmKeyDispatchPass.coverageKey(clazz, method);
        ControlFlowFlatteningPass.CffMethodMetadata metadata =
            ControlFlowFlatteningPass.methodMetadata(pctx).get(methodKey);
        if (metadata == null) {
            return;
        }
        if (metadata.classKeyTable() == null) {
            throw new IllegalStateException("invokeDynamic requires CFF class key table metadata for " + methodKey);
        }

        MethodNode mn = method.asmNode();
        HelperNames helpers = null;
        int transformed = 0;
        int ordinal = 0;
        boolean hasFlowCacheInit = false;
        int indyMaterialLocal = -1;
        int indySiteKeyLocal = -1;
        IndyFlowTable activeFlowTable = null;
        Set<AbstractInsnNode> loopInstructions = loopRegionInstructions(mn);
        InsnList flowCacheInit = new InsnList();
        InsnList indyMaterialInit = new InsnList();
        boolean outlineSites = useOutlinedIndySites(mn);
        int outlined = 0;
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!metadata.applicationInstructions().contains(insn)) continue;
            ControlFlowFlatteningPass.CffInstructionState state = metadata.instructionStates().get(insn);
            if (state == null) {
                throw new IllegalStateException("invokeDynamic cannot bind CFF state for " + methodKey);
            }
            SiteSpec spec = siteSpec(pctx, clazz, insn);
            if (spec == null) continue;
            if (helpers == null) {
                helpers = ensureHelpers(pctx, clazz, metadata);
            }
            long siteSeed = siteSeed(pctx.masterSeed(), clazz, method, state, ordinal++);
            long salt = JvmPassBytecode.mix(siteSeed ^ 0x494E445953414C54L, spec.owner().hashCode());
            long flow = liveIndyWord(metadata, state, siteSeed);
            long token = indyTokenFromFlow(siteSeed, salt, flow);
            IndyFlowTable flowTable = ensureIndyFlowTable(pctx, clazz, metadata);
            activeFlowTable = flowTable;
            if (!outlineSites && indyMaterialLocal < 0) {
                indyMaterialLocal = mn.maxLocals++;
                indyMaterialInit.add(new FieldInsnNode(Opcodes.GETSTATIC, clazz.name(), flowTable.fieldName(), OBJECT_ARRAY_DESC));
                indyMaterialInit.add(new VarInsnNode(Opcodes.ASTORE, indyMaterialLocal));
            }
            int flowSaltSlot = registerIndyFlowSalt(
                pctx,
                flowTable,
                state.methodSalt(),
                siteSeed,
                state.state(),
                state.pcToken(),
                state.methodKey(),
                state.guardKey(),
                state.pathKey(),
                state.blockKey(),
                indyClassWord(metadata, state, siteSeed)
            );
            IndyResolverMaterialCell resolverSeedCell =
                indyResolverMaterialCell(
                    flowTable,
                    flowTable.resolverCells().size(),
                    siteSeed,
                    salt,
                    flow,
                    indyResolverHelperKey(state.methodKey(), flow)
                );
            int resolverSeedSlot = registerIndyResolverSeed(pctx, flowTable, resolverSeedCell);
            if (spec.kind() == KIND_GETSTATIC_ARRAY_MATERIAL && spec.staticArrayMaterial() != null) {
                setIndyStaticArrayMaterial(
                    pctx,
                    flowTable,
                    resolverSeedSlot,
                    indyStaticArrayMaterialCell(
                        spec.staticArrayMaterial(),
                        resolverSeedSlot,
                        siteSeed,
                        salt,
                        flow
                    )
                );
            }

            boolean interfaceOwner = (clazz.asmNode().access & Opcodes.ACC_INTERFACE) != 0;
            InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(
                indyName(siteSeed, spec.kind()),
                appendIndyHiddenArgs(spec.indyDesc()),
                new Handle(
                    Opcodes.H_INVOKESTATIC,
                    helpers.bootstrapOwner(),
                    helpers.bootstrap(),
                    BSM_DESC,
                    helpers.bootstrapInterfaceOwner()
                ),
                encrypt(payload(spec), siteSeed ^ salt ^ OWNER_SEED, token, flow, resolverSeedCell.descriptor()),
                resolverSeedSlot,
                new Handle(
                    Opcodes.H_GETSTATIC,
                    clazz.name(),
                    flowTable.fieldName(),
                    OBJECT_ARRAY_DESC,
                    interfaceOwner
                )
            );
            recordPayloadSite(
                pctx,
                indy,
                spec.kind(),
                spec.owner(),
                spec.name(),
                spec.desc(),
                siteSeed ^ salt ^ OWNER_SEED,
                token,
                flow,
                resolverSeedCell.descriptor()
            );

            InsnList replacement = new InsnList();
            if (outlineSites) {
                String helperName = addOutlinedIndySiteHelper(
                    pctx,
                    clazz,
                    spec,
                    indy,
                    siteSeed,
                    helpers,
                    flowSaltSlot,
                    flowTable.fieldName()
                );
                emitOutlinedIndySiteCall(
                    replacement,
                    clazz,
                    spec.indyDesc(),
                    helperName,
                    metadata
                );
                outlined++;
            } else if (loopInstructions.contains(insn)) {
                if (indySiteKeyLocal < 0) {
                    indySiteKeyLocal = mn.maxLocals;
                    mn.maxLocals = indySiteKeyLocal + 2;
                }
                emitBoundIndySiteKeyCall(
                    replacement,
                    helpers,
                    indyMaterialLocal,
                    flowSaltSlot,
                    indySiteKeyLocal
                );
                int flowCacheLocal = mn.maxLocals;
                mn.maxLocals += 2;
                flowCacheInit.add(new InsnNode(Opcodes.LCONST_0));
                flowCacheInit.add(new VarInsnNode(Opcodes.LSTORE, flowCacheLocal));
                hasFlowCacheInit = true;
                replacement.add(new VarInsnNode(Opcodes.LLOAD, indySiteKeyLocal));
                emitCachedLiveIndyWord(
                    replacement,
                    clazz.name(),
                    helpers,
                    metadata,
                    state,
                    interfaceOwner,
                    flowCacheLocal,
                    indyMaterialLocal,
                    flowSaltSlot,
                    indySiteKeyLocal
                );
                replacement.add(indy);
            } else {
                if (indySiteKeyLocal < 0) {
                    indySiteKeyLocal = mn.maxLocals;
                    mn.maxLocals = indySiteKeyLocal + 2;
                }
                emitBoundIndySiteKeyCall(
                    replacement,
                    helpers,
                    indyMaterialLocal,
                    flowSaltSlot,
                    indySiteKeyLocal
                );
                replacement.add(new VarInsnNode(Opcodes.LLOAD, indySiteKeyLocal));
                emitLiveIndyWord(
                    replacement,
                    clazz.name(),
                    helpers,
                    metadata,
                    state,
                    interfaceOwner,
                    indyMaterialLocal,
                    flowSaltSlot,
                    indySiteKeyLocal
                );
                replacement.add(indy);
            }
            JvmKeyDispatchPass.markGenerated(pctx, replacement);
            mn.instructions.insertBefore(insn, replacement);
            mn.instructions.remove(insn);
            transformed++;
        }

        if (transformed > 0) {
            if (hasFlowCacheInit) {
                JvmKeyDispatchPass.markGenerated(pctx, flowCacheInit);
                mn.instructions.insert(flowCacheInit);
            }
            if (indyMaterialInit.size() > 0) {
                JvmKeyDispatchPass.markGenerated(pctx, indyMaterialInit);
                if ("<clinit>".equals(method.name()) && "()V".equals(method.descriptor()) && activeFlowTable != null) {
                    mn.instructions.insert(activeFlowTable.initEnd(), indyMaterialInit);
                } else {
                    mn.instructions.insert(indyMaterialInit);
                }
            }
            mn.maxStack = Math.max(mn.maxStack, 32);
            clazz.markDirty();
            pctx.invalidate(method);
            JvmObfuscationCoverage.get(ctx).full(
                id(),
                clazz.name(),
                method.name(),
                method.descriptor(),
                "cff-keyed-indy-reference-sites-" + transformed + "-outlined-" + outlined
            );
        }
    }

    private boolean useOutlinedIndySites(MethodNode mn) {
        return JvmCodeSizeEstimator.estimateMethodBytes(mn) >= OUTLINED_SITE_SIZE_PRESSURE;
    }

    public static int reconcileGeneratedHelperPayloads(
        PipelineContext pctx,
        List<L1Class> classes
    ) {
        Map<IndyPayloadKey, IndyPayloadSite> sites = payloadSites(pctx, false);
        if (sites == null || sites.isEmpty()) return 0;
        int rewritten = 0;
        for (L1Class clazz : classes) {
            boolean changed = false;
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof InvokeDynamicInsnNode indy)) continue;
                    IndyPayloadSite site = sites.get(payloadKey(indy));
                    if (site == null) continue;
                    GeneratedHelperTargetMap.MethodTarget target =
                        GeneratedHelperTargetMap.resolveMethod(pctx, site.owner(), site.name(), site.desc());
                    if (site.owner().equals(target.owner())
                        && site.name().equals(target.name())
                        && site.desc().equals(target.desc())) {
                        continue;
                    }
                    indy.bsmArgs[0] = encryptedPayload(
                        site.kind(),
                        target.owner(),
                        target.name(),
                        target.desc(),
                        site.decodeSeed(),
                        site.token(),
                        site.flow(),
                        site.resolverDescriptor()
                    );
                    changed = true;
                    rewritten++;
                }
            }
            if (changed) {
                clazz.markDirty();
            }
        }
        return rewritten;
    }

    static void recordPayloadSite(
        PipelineContext pctx,
        InvokeDynamicInsnNode indy,
        int kind,
        String owner,
        String name,
        String desc,
        long decodeSeed,
        long token,
        long flow,
        long resolverDescriptor
    ) {
        Map<IndyPayloadKey, IndyPayloadSite> sites = payloadSites(pctx, true);
        sites.put(
            payloadKey(indy),
            new IndyPayloadSite(kind, owner, name, desc, decodeSeed, token, flow, resolverDescriptor)
        );
    }

    @SuppressWarnings("unchecked")
    private static Map<IndyPayloadKey, IndyPayloadSite> payloadSites(
        PipelineContext pctx,
        boolean create
    ) {
        Map<IndyPayloadKey, IndyPayloadSite> sites = pctx.getPassData(PAYLOAD_SITES_KEY);
        if (sites == null && create) {
            sites = new LinkedHashMap<>();
            pctx.putPassData(PAYLOAD_SITES_KEY, sites);
        }
        return sites;
    }

    private static IndyPayloadKey payloadKey(InvokeDynamicInsnNode indy) {
        Object payload = indy.bsmArgs.length > 0 ? indy.bsmArgs[0] : null;
        Object resolverSlot = indy.bsmArgs.length > 1 ? indy.bsmArgs[1] : null;
        return new IndyPayloadKey(
            indy.name,
            indy.desc,
            payload instanceof String value ? value : "",
            resolverSlot instanceof Integer value ? value : Integer.MIN_VALUE
        );
    }

    private String addOutlinedIndySiteHelper(
        PipelineContext pctx,
        L1Class clazz,
        SiteSpec spec,
        InvokeDynamicInsnNode indy,
        long siteSeed,
        HelperNames helpers,
        int flowSaltSlot,
        String carrierFieldName
    ) {
        String desc = outlinedIndySiteDescriptor(spec.indyDesc());
        String name = uniqueMethodName(
            clazz,
            "__neko_indysite$" + Long.toUnsignedString(siteSeed, 36)
        );
        int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        access |= clazz.isInterface() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
        MethodNode helper = new MethodNode(access, name, desc, null, null);
        Type[] originalArgs = Type.getArgumentTypes(spec.indyDesc());
        int originalArgSlots = 0;
        for (Type arg : originalArgs) {
            originalArgSlots += arg.getSize();
        }
        int pcLocal = originalArgSlots;
        int dataLocal = pcLocal + 1;
        int indyMaterialLocal = dataLocal + 1;
        int keyLocal = indyMaterialLocal + 1;
        helper.instructions.add(new FieldInsnNode(Opcodes.GETSTATIC, clazz.name(), carrierFieldName, OBJECT_ARRAY_DESC));
        helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, indyMaterialLocal));
        helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, indyMaterialLocal));
        JvmPassBytecode.pushInt(helper.instructions, flowSaltSlot);
        helper.instructions.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            helpers.keyOwner(),
            helpers.key(),
            KEY_DESC,
            helpers.keyInterfaceOwner()
        ));
        helper.instructions.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        int local = 0;
        for (Type arg : originalArgs) {
            helper.instructions.add(new VarInsnNode(arg.getOpcode(Opcodes.ILOAD), local));
            local += arg.getSize();
        }
        local = keyLocal + 2;
        helper.instructions.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        emitCompactLiveIndyWordFromLocals(
            helper.instructions,
            helpers,
            pcLocal,
            dataLocal,
            indyMaterialLocal,
            flowSaltSlot,
            keyLocal
        );
        helper.instructions.add(indy);
        Type returnType = Type.getReturnType(spec.indyDesc());
        helper.instructions.add(new InsnNode(returnType.getOpcode(Opcodes.IRETURN)));
        helper.maxLocals = local;
        helper.maxStack = 32;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        clazz.markDirty();
        publishGeneratedIndyHelperFlowKey(pctx, clazz.name(), name, desc, keyLocal);
        return name;
    }

    private void emitOutlinedIndySiteCall(
        InsnList replacement,
        L1Class clazz,
        String indyDesc,
        String helperName,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        replacement.add(new VarInsnNode(Opcodes.ILOAD, metadata.pcLocal()));
        replacement.add(new VarInsnNode(Opcodes.ILOAD, metadata.dataLocal()));
        replacement.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            clazz.name(),
            helperName,
            outlinedIndySiteDescriptor(indyDesc),
            clazz.isInterface()
        ));
    }

    private String outlinedIndySiteDescriptor(String indyDesc) {
        Type method = Type.getMethodType(indyDesc);
        Type[] originalArgs = method.getArgumentTypes();
        Type[] args = new Type[originalArgs.length + 2];
        System.arraycopy(originalArgs, 0, args, 0, originalArgs.length);
        int offset = originalArgs.length;
        args[offset] = Type.INT_TYPE;
        args[offset + 1] = Type.INT_TYPE;
        return Type.getMethodDescriptor(method.getReturnType(), args);
    }

    private Set<AbstractInsnNode> loopRegionInstructions(MethodNode mn) {
        AbstractInsnNode[] nodes = mn.instructions.toArray();
        Map<AbstractInsnNode, Integer> indexByNode = new IdentityHashMap<>();
        for (int i = 0; i < nodes.length; i++) {
            indexByNode.put(nodes[i], i);
        }
        Set<AbstractInsnNode> loop = Collections.newSetFromMap(new IdentityHashMap<>());
        for (int i = 0; i < nodes.length; i++) {
            AbstractInsnNode node = nodes[i];
            if (node instanceof JumpInsnNode jump) {
                markBackwardRegion(loop, nodes, indexByNode, i, jump.label);
            } else if (node instanceof LookupSwitchInsnNode lookup) {
                markBackwardRegion(loop, nodes, indexByNode, i, lookup.dflt);
                for (LabelNode label : lookup.labels) {
                    markBackwardRegion(loop, nodes, indexByNode, i, label);
                }
            } else if (node instanceof org.objectweb.asm.tree.TableSwitchInsnNode table) {
                markBackwardRegion(loop, nodes, indexByNode, i, table.dflt);
                for (LabelNode label : table.labels) {
                    markBackwardRegion(loop, nodes, indexByNode, i, label);
                }
            }
        }
        return loop;
    }

    private boolean generatedHelperUnderSizePressure(MethodNode mn) {
        return JvmCodeSizeEstimator.estimateMethodBytes(mn) >= GENERATED_HELPER_HARDENING_SIZE_PRESSURE;
    }

    private boolean hasGeneratedValidationFinalStageCall(L1Class caller, MethodNode mn) {
        if (mn.instructions == null) return false;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call && isGeneratedValidationFinalStageCall(caller, call)) {
                return true;
            }
        }
        return false;
    }

    private void markBackwardRegion(
        Set<AbstractInsnNode> loop,
        AbstractInsnNode[] nodes,
        Map<AbstractInsnNode, Integer> indexByNode,
        int sourceIndex,
        LabelNode target
    ) {
        Integer targetIndex = indexByNode.get(target);
        if (targetIndex == null || targetIndex > sourceIndex) {
            return;
        }
        for (int i = targetIndex; i <= sourceIndex; i++) {
            loop.add(nodes[i]);
        }
    }

    private String payload(SiteSpec spec) {
        return payload(spec.kind(), spec.owner(), spec.name(), spec.desc());
    }

    static String payload(int kind, String owner, String name, String desc) {
        return kind + "\n" + owner + "\n" + name + "\n" + desc;
    }

    private SiteSpec siteSpec(PipelineContext pctx, L1Class caller, AbstractInsnNode insn) {
        if (insn instanceof MethodInsnNode call) {
            if ("<init>".equals(call.name) || "<clinit>".equals(call.name)) return null;
            boolean generatedName = TransformGuards.isGeneratedName(call.name);
            boolean generatedValidationFinalStage = isGeneratedValidationFinalStageCall(caller, call);
            boolean generatedValidationPrimitiveEntry = isGeneratedValidationPrimitiveEntryCall(caller, call);
            if (TransformGuards.isRuntimeClass(call.owner) ||
                (generatedName && !generatedValidationFinalStage && !generatedValidationPrimitiveEntry)) {
                return null;
            }
            if (isAnnotationElementCall(pctx, call)) return null;
            int kind = switch (call.getOpcode()) {
                case Opcodes.INVOKEVIRTUAL -> KIND_INVOKEVIRTUAL;
                case Opcodes.INVOKESTATIC -> KIND_INVOKESTATIC;
                case Opcodes.INVOKEINTERFACE -> KIND_INVOKEINTERFACE;
                case Opcodes.INVOKESPECIAL -> KIND_INVOKESPECIAL;
                default -> 0;
            };
            if (kind == 0) return null;
            String receiverOwner = kind == KIND_INVOKESPECIAL ? caller.name() : call.owner;
            String indyDesc = methodIndyDescriptor(receiverOwner, call.desc, kind == KIND_INVOKESTATIC);
            return new SiteSpec(kind, call.owner, call.name, call.desc, indyDesc, null);
        }
        if (insn instanceof FieldInsnNode field) {
            if (TransformGuards.isRuntimeClass(field.owner) || TransformGuards.isGeneratedName(field.name)) return null;
            int kind = switch (field.getOpcode()) {
                case Opcodes.GETFIELD -> KIND_GETFIELD;
                case Opcodes.PUTFIELD -> KIND_PUTFIELD;
                case Opcodes.GETSTATIC -> KIND_GETSTATIC;
                case Opcodes.PUTSTATIC -> KIND_PUTSTATIC;
                default -> 0;
            };
            if (kind == 0) return null;
            JvmStaticArrayMaterial.Material staticArrayMaterial =
                staticArrayMaterialForField(pctx, field, kind);
            if (staticArrayMaterial != null) {
                int materialKind = kind == KIND_GETSTATIC
                    ? KIND_GETSTATIC_ARRAY_MATERIAL
                    : KIND_PUTSTATIC_ARRAY_MATERIAL;
                return new SiteSpec(
                    materialKind,
                    field.owner,
                    field.name,
                    "()" + field.desc,
                    fieldIndyDescriptor(field, kind),
                    staticArrayMaterial
                );
            }
            makeWritableFinalStoreTarget(pctx, field, kind);
            return new SiteSpec(kind, field.owner, field.name, "()" + field.desc, fieldIndyDescriptor(field, kind), null);
        }
        return null;
    }

    private boolean isGeneratedValidationFinalStageCall(
        L1Class caller,
        MethodInsnNode call
    ) {
        return call.getOpcode() == Opcodes.INVOKESTATIC
            && call.owner.equals(caller.name())
            && (
                (call.name.startsWith("__neko_vsend") && "(JJI)Z".equals(call.desc)) ||
                    (call.name.startsWith(JvmValidationSinkHardeningPass.PRIMITIVE_FINAL_STAGE_PREFIX) &&
                        JvmValidationSinkHardeningPass.PRIMITIVE_FINAL_STAGE_DESC.equals(call.desc))
            );
    }

    private boolean isGeneratedValidationPrimitiveEntryCall(
        L1Class caller,
        MethodInsnNode call
    ) {
        return call.getOpcode() == Opcodes.INVOKESTATIC
            && call.owner.equals(caller.name())
            && call.name.startsWith(JvmValidationSinkHardeningPass.PRIMITIVE_ENTRY_PREFIX)
            && JvmValidationSinkHardeningPass.PRIMITIVE_ENTRY_DESC.equals(call.desc);
    }

    private boolean isAnnotationElementCall(PipelineContext pctx, MethodInsnNode call) {
        if (call.getOpcode() != Opcodes.INVOKEINTERFACE) return false;
        L1Class owner = pctx.classMap().get(call.owner);
        if (owner == null || !owner.isAnnotation()) return false;
        if (Type.getArgumentTypes(call.desc).length != 0) return false;
        Type returnType = Type.getReturnType(call.desc);
        if (returnType == Type.VOID_TYPE) return false;
        for (L1Method method : owner.methods()) {
            if (method.name().equals(call.name) && method.descriptor().equals(call.desc)) {
                return true;
            }
        }
        return false;
    }

    private JvmStaticArrayMaterial.Material staticArrayMaterialForField(
        PipelineContext pctx,
        FieldInsnNode field,
        int kind
    ) {
        if (kind != KIND_GETSTATIC && kind != KIND_PUTSTATIC) return null;
        PrimitiveArrayKind arrayKind = PrimitiveArrayKind.fromDescriptor(field.desc);
        if (arrayKind == null) return null;
        String key = JvmStaticArrayMaterial.key(field.owner, field.name, field.desc);
        if (!eligibleStaticArrayMaterials(pctx).contains(key)) return null;
        return JvmStaticArrayMaterial.materials(pctx).get(key);
    }

    @SuppressWarnings("unchecked")
    private Set<String> eligibleStaticArrayMaterials(PipelineContext pctx) {
        Set<String> eligible = pctx.getPassData(STATIC_ARRAY_MATERIAL_ELIGIBLE_KEY);
        if (eligible != null) return eligible;
        eligible = new java.util.LinkedHashSet<>();
        Map<String, JvmStaticArrayMaterial.Material> materials = JvmStaticArrayMaterial.materials(pctx);
        for (JvmStaticArrayMaterial.Material material : materials.values()) {
            if (isEligibleStaticArrayMaterial(pctx, material)) {
                eligible.add(material.key());
            }
        }
        pctx.putPassData(STATIC_ARRAY_MATERIAL_ELIGIBLE_KEY, eligible);
        return eligible;
    }

    private boolean isEligibleStaticArrayMaterial(
        PipelineContext pctx,
        JvmStaticArrayMaterial.Material material
    ) {
        L1Class owner = pctx.classMap().get(material.owner());
        if (owner == null || TransformGuards.isRuntimeClass(owner)) return false;
        if (JvmStaticArrayMaterial.hasOriginalFieldReflection(pctx) ||
            JvmStaticArrayMaterial.hasOriginalDynamicFieldAccess(pctx)) {
            return false;
        }
        FieldNode field = findField(owner, material.name(), material.desc());
        if (field == null) return false;
        if ((field.access & Opcodes.ACC_PRIVATE) == 0 || (field.access & Opcodes.ACC_STATIC) == 0) {
            return false;
        }
        JvmStaticArrayMaterial.UseSummary originalUses =
            JvmStaticArrayMaterial.useSummaries(pctx).get(material.key());
        if (originalUses == null ||
            originalUses.unsafe() ||
            originalUses.gets() <= 0 ||
            originalUses.puts() != 1) {
            return false;
        }

        int gets = 0;
        int puts = 0;
        for (L1Class clazz : pctx.classMap().values()) {
            if (TransformGuards.isRuntimeClass(clazz)) continue;
            for (L1Method method : clazz.methods()) {
                if (!method.hasCode() || TransformGuards.isGeneratedMethod(method)) continue;
                MethodNode mn = method.asmNode();
                if (mn.instructions == null) continue;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof FieldInsnNode fieldInsn) ||
                        !material.owner().equals(fieldInsn.owner) ||
                        !material.name().equals(fieldInsn.name) ||
                        !material.desc().equals(fieldInsn.desc)) {
                        continue;
                    }
                    if (!material.owner().equals(clazz.name())) {
                        return false;
                    }
                    int opcode = fieldInsn.getOpcode();
                    if (opcode == Opcodes.GETSTATIC) {
                        gets++;
                    } else if (opcode == Opcodes.PUTSTATIC) {
                        if (!material.owner().equals(clazz.name()) ||
                            !"<clinit>".equals(method.name()) ||
                            !"()V".equals(method.descriptor())) {
                            return false;
                        }
                        puts++;
                    } else {
                        return false;
                    }
                    if (!isProtectedApplicationInstruction(pctx, clazz, method, insn)) {
                        return false;
                    }
                }
            }
        }
        return gets == originalUses.gets() && puts == originalUses.puts();
    }

    private FieldNode findField(L1Class clazz, String name, String desc) {
        for (FieldNode field : clazz.asmNode().fields) {
            if (field.name.equals(name) && field.desc.equals(desc)) return field;
        }
        return null;
    }

    private boolean isProtectedApplicationInstruction(
        PipelineContext pctx,
        L1Class clazz,
        L1Method method,
        AbstractInsnNode insn
    ) {
        String methodKey = JvmKeyDispatchPass.coverageKey(clazz, method);
        ControlFlowFlatteningPass.CffMethodMetadata metadata =
            ControlFlowFlatteningPass.methodMetadata(pctx).get(methodKey);
        return metadata != null && metadata.applicationInstructions().contains(insn);
    }

    private void makeWritableFinalStoreTarget(PipelineContext pctx, FieldInsnNode field, int kind) {
        if (kind != KIND_PUTFIELD && kind != KIND_PUTSTATIC) return;
        L1Class owner = pctx.classMap().get(field.owner);
        if (owner == null) return;
        for (FieldNode declared : owner.asmNode().fields) {
            if (declared.name.equals(field.name) && declared.desc.equals(field.desc)) {
                if ((declared.access & Opcodes.ACC_FINAL) != 0) {
                    declared.access &= ~Opcodes.ACC_FINAL;
                    declared.value = null;
                    owner.markDirty();
                }
                return;
            }
        }
    }

    private String methodIndyDescriptor(String owner, String desc, boolean isStatic) {
        Type method = Type.getMethodType(desc);
        Type[] args = method.getArgumentTypes();
        Type[] indyArgs;
        if (isStatic) {
            indyArgs = args;
        } else {
            indyArgs = new Type[args.length + 1];
            indyArgs[0] = Type.getType(Object.class);
            System.arraycopy(args, 0, indyArgs, 1, args.length);
        }
        return Type.getMethodDescriptor(method.getReturnType(), indyArgs);
    }

    private String fieldIndyDescriptor(FieldInsnNode field, int kind) {
        Type owner = Type.getType(Object.class);
        Type value = Type.getType(field.desc);
        return switch (kind) {
            case KIND_GETFIELD -> Type.getMethodDescriptor(value, owner);
            case KIND_PUTFIELD -> Type.getMethodDescriptor(Type.VOID_TYPE, owner, value);
            case KIND_GETSTATIC -> Type.getMethodDescriptor(value);
            case KIND_PUTSTATIC -> Type.getMethodDescriptor(Type.VOID_TYPE, value);
            default -> throw new IllegalArgumentException("Unknown field kind " + kind);
        };
    }

    private Type ownerType(String owner) {
        return owner.startsWith("[") ? Type.getType(owner) : Type.getObjectType(owner);
    }

    private String appendIndyHiddenArgs(String desc) {
        Type method = Type.getMethodType(desc);
        Type[] args = method.getArgumentTypes();
        Type[] out = new Type[args.length + 2];
        System.arraycopy(args, 0, out, 0, args.length);
        out[args.length] = Type.LONG_TYPE;
        out[args.length + 1] = Type.LONG_TYPE;
        return Type.getMethodDescriptor(method.getReturnType(), out);
    }

    @SuppressWarnings("unchecked")
    private HelperNames ensureHelpers(
        PipelineContext pctx,
        L1Class clazz,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        Map<String, HelperNames> helpersByClass = pctx.getPassData(HELPERS_KEY);
        if (helpersByClass == null) {
            helpersByClass = new HashMap<>();
            pctx.putPassData(HELPERS_KEY, helpersByClass);
        }
        HelperNames existing = helpersByClass.get(clazz.name());
        if (existing != null) {
            return existing;
        }
        IndyFlowTable materialTable = ensureIndyFlowTable(pctx, clazz, metadata);
        ensureIndyCacheCarrierSlot(pctx, clazz, materialTable.fieldName(), metadata.classKeyTable().initEnd());
        boolean interfaceOwner = (clazz.asmNode().access & Opcodes.ACC_INTERFACE) != 0;
        SharedHelperNames shared = ensureSharedHelpers(pctx, clazz, metadata, interfaceOwner);
        HelperNames created = new HelperNames(
            shared.bootstrapOwner(),
            shared.bootstrap(),
            shared.bootstrapInterfaceOwner(),
            shared.flowOwner(),
            shared.flow(),
            shared.flowInterfaceOwner(),
            shared.compactFlowOwner(),
            shared.compactFlow(),
            shared.compactFlowInterfaceOwner(),
            shared.keyOwner(),
            shared.key(),
            shared.keyInterfaceOwner(),
            shared.guardOwner(),
            shared.guard(),
            shared.guardInterfaceOwner()
        );
        helpersByClass.put(clazz.name(), created);
        return created;
    }

    @SuppressWarnings("unchecked")
    private SharedHelperNames ensureSharedHelpers(
        PipelineContext pctx,
        L1Class clazz,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        boolean interfaceOwner
    ) {
        Map<String, SharedHelperNames> helpersByPackage = pctx.getPassData(SHARED_HELPERS_KEY);
        if (helpersByPackage == null) {
            helpersByPackage = new HashMap<>();
            pctx.putPassData(SHARED_HELPERS_KEY, helpersByPackage);
        }
        int classKeyMask = metadata.classKeyTable().values().length - 1;
        String sharedKey = clazz.name() + "#" + classKeyMask;
        SharedHelperNames existing = helpersByPackage.get(sharedKey);
        if (existing != null) {
            return existing;
        }
        String flow = uniqueMethodName(clazz, "__neko_indy_flow");
        String compactFlow = uniqueMethodName(clazz, "__neko_indy_flowc");
        String helperKey = uniqueMethodName(clazz, "__neko_indy_sitekey");
        String guard = uniqueMethodName(clazz, "__neko_indy_guard");
        String resolver = uniqueMethodName(clazz, "__neko_indy_resolve");
        String bootstrapCore = uniqueMethodName(clazz, "__neko_indy_core");
        String bootstrap = uniqueMethodName(clazz, "__neko_indy_bsm");
        StaticArrayHelperNames arrayHelpers = new StaticArrayHelperNames(
            uniqueMethodName(clazz, "__neko_indy_arr_z"),
            uniqueMethodName(clazz, "__neko_indy_arr_b"),
            uniqueMethodName(clazz, "__neko_indy_arr_c"),
            uniqueMethodName(clazz, "__neko_indy_arr_s"),
            uniqueMethodName(clazz, "__neko_indy_arr_i"),
            uniqueMethodName(clazz, "__neko_indy_arr_j"),
            uniqueMethodName(clazz, "__neko_indy_arr_f"),
            uniqueMethodName(clazz, "__neko_indy_arr_d")
        );
        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        clazz.asmNode().methods.add(emitBootstrapTrampoline(
            bootstrap,
            access,
            clazz.name(),
            bootstrapCore,
            interfaceOwner
        ));
        clazz.asmNode().methods.add(emitBootstrapCore(
            bootstrapCore,
            clazz.name(),
            resolver,
            interfaceOwner,
            access
        ));
        clazz.asmNode().methods.add(emitResolver(
            resolver,
            clazz.name(),
            guard,
            interfaceOwner,
            arrayHelpers,
            access
        ));
        clazz.asmNode().methods.add(emitStaticArrayMaterialHelper(
            arrayHelpers.booleanHelper(), PrimitiveArrayKind.BOOLEAN, access));
        clazz.asmNode().methods.add(emitStaticArrayMaterialHelper(
            arrayHelpers.byteHelper(), PrimitiveArrayKind.BYTE, access));
        clazz.asmNode().methods.add(emitStaticArrayMaterialHelper(
            arrayHelpers.charHelper(), PrimitiveArrayKind.CHAR, access));
        clazz.asmNode().methods.add(emitStaticArrayMaterialHelper(
            arrayHelpers.shortHelper(), PrimitiveArrayKind.SHORT, access));
        clazz.asmNode().methods.add(emitStaticArrayMaterialHelper(
            arrayHelpers.intHelper(), PrimitiveArrayKind.INT, access));
        clazz.asmNode().methods.add(emitStaticArrayMaterialHelper(
            arrayHelpers.longHelper(), PrimitiveArrayKind.LONG, access));
        clazz.asmNode().methods.add(emitStaticArrayMaterialHelper(
            arrayHelpers.floatHelper(), PrimitiveArrayKind.FLOAT, access));
        clazz.asmNode().methods.add(emitStaticArrayMaterialHelper(
            arrayHelpers.doubleHelper(), PrimitiveArrayKind.DOUBLE, access));
        clazz.asmNode().methods.add(emitGuard(guard, access));
        clazz.asmNode().methods.add(emitKey(helperKey, access));
        clazz.asmNode().methods.add(emitFlow(flow, classKeyMask, access));
        clazz.asmNode().methods.add(emitCompactFlow(compactFlow, classKeyMask, access));
        publishGeneratedIndyHelperFlowKey(pctx, clazz.name(), resolver, RESOLVER_DESC, RESOLVER_FLOW_LOCAL);
        publishGeneratedIndyHelperFlowKey(pctx, clazz.name(), flow, FLOW_DESC, FLOW_HELPER_METHOD_KEY_LOCAL);
        publishGeneratedIndyHelperFlowKey(
            pctx,
            clazz.name(),
            compactFlow,
            COMPACT_FLOW_DESC,
            COMPACT_FLOW_HELPER_METHOD_KEY_LOCAL
        );
        installInjectedStackTraceFilter(
            pctx,
            clazz.name(),
            List.of(
                bootstrap,
                bootstrapCore,
                resolver,
                flow,
                compactFlow,
                helperKey,
                guard,
                arrayHelpers.booleanHelper(),
                arrayHelpers.byteHelper(),
                arrayHelpers.charHelper(),
                arrayHelpers.shortHelper(),
                arrayHelpers.intHelper(),
                arrayHelpers.longHelper(),
                arrayHelpers.floatHelper(),
                arrayHelpers.doubleHelper()
            )
        );
        SharedHelperNames created = new SharedHelperNames(
            clazz.name(),
            bootstrap,
            interfaceOwner,
            clazz.name(),
            bootstrapCore,
            interfaceOwner,
            clazz.name(),
            resolver,
            interfaceOwner,
            clazz.name(),
            flow,
            interfaceOwner,
            clazz.name(),
            compactFlow,
            interfaceOwner,
            clazz.name(),
            helperKey,
            interfaceOwner,
            clazz.name(),
            guard,
            interfaceOwner
        );
        helpersByPackage.put(sharedKey, created);
        return created;
    }

    private void ensureIndyCacheCarrierSlot(
        PipelineContext pctx,
        L1Class clazz,
        String carrierFieldName,
        LabelNode anchor
    ) {
        MethodNode clinit = findOrCreateClassInit(clazz);
        InsnList init = new InsnList();
        init.add(new FieldInsnNode(Opcodes.GETSTATIC, clazz.name(), carrierFieldName, OBJECT_ARRAY_DESC));
        JvmPassBytecode.pushInt(init, ControlFlowFlatteningPass.INDY_CACHE_SLOT);
        init.add(new TypeInsnNode(Opcodes.NEW, CONCURRENT_HASH_MAP));
        init.add(new InsnNode(Opcodes.DUP));
        init.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, CONCURRENT_HASH_MAP, "<init>", "()V", false));
        init.add(new InsnNode(Opcodes.AASTORE));
        JvmKeyDispatchPass.markGenerated(pctx, init);
        clinit.instructions.insert(anchor, init);
        clinit.maxStack = Math.max(clinit.maxStack, 4);
        clazz.markDirty();
    }

    @SuppressWarnings("unchecked")
    private IndyFlowTable ensureIndyFlowTable(
        PipelineContext pctx,
        L1Class clazz,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        Map<String, IndyFlowTable> tables = pctx.getPassData(FLOW_TABLES_KEY);
        if (tables == null) {
            tables = new HashMap<>();
            pctx.putPassData(FLOW_TABLES_KEY, tables);
        }
        IndyFlowTable existing = tables.get(clazz.name());
        if (existing != null) return existing;

        String fieldName = metadata.classKeyTable().objectFieldName();
        boolean interfaceOwner = (clazz.asmNode().access & Opcodes.ACC_INTERFACE) != 0;
        MethodNode clinit = findOrCreateClassInit(clazz);
        MethodNode helper = createIndyInitHelper(clazz, interfaceOwner);
        LabelNode initStart = new LabelNode();
        LabelNode initEnd = new LabelNode();
        insertClassInitCallAfter(
            clinit,
            metadata.classKeyTable().initEnd(),
            initStart,
            initEnd,
            clazz.name(),
            helper.name,
            interfaceOwner
        );

        IndyFlowTable table = new IndyFlowTable(
            clazz.name(),
            fieldName,
            helper,
            new java.util.ArrayList<>(),
            new java.util.ArrayList<>(),
            new java.util.ArrayList<>(),
            new java.util.ArrayList<>(),
            initStart,
            initEnd
        );
        tables.put(clazz.name(), table);
        clazz.markDirty();
        return table;
    }

    private int registerIndyFlowSalt(
        PipelineContext pctx,
        IndyFlowTable table,
        long methodSalt,
        long siteSeed,
        int stateToken,
        int pcToken,
        long methodKey,
        int guardKey,
        int pathKey,
        int blockKey,
        int classWord
    ) {
        int slot = table.cells().size();
        table.cells().add(indyFlowMaterialCell(
            table,
            slot,
            methodSalt,
            siteSeed,
            stateToken,
            pcToken,
            methodKey,
            guardKey,
            pathKey,
            blockKey,
            classWord
        ));
        rebuildIndyFlowTableInit(pctx, table);
        return slot;
    }

    private void rebuildIndyFlowTableInit(PipelineContext pctx, IndyFlowTable table) {
        L1Class owner = pctx.classMap().get(table.owner());
        if (owner == null) {
            throw new IllegalStateException("invokeDynamic material owner missing: " + table.owner());
        }
        removeIndyInitChunkHelpers(owner, table);
        InsnList insns = new InsnList();
        boolean directClinit = "<clinit>".equals(table.initHelper().name);
        int tableLocal = directClinit ? table.initHelper().maxLocals : 0;
        JvmPassBytecode.pushInt(insns, 4);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
        insns.add(new VarInsnNode(Opcodes.ASTORE, tableLocal));
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC, table.owner(), table.fieldName(), OBJECT_ARRAY_DESC));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_SLOT);
        insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC, table.owner(), table.fieldName(), OBJECT_ARRAY_DESC));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_ALIAS_SLOT);
        insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC, table.owner(), table.fieldName(), OBJECT_ARRAY_DESC));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_SELECTOR_SLOT);
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_SLOT);
        insns.add(new InsnNode(Opcodes.IASTORE));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_ALIAS_SLOT);
        insns.add(new InsnNode(Opcodes.IASTORE));
        insns.add(new InsnNode(Opcodes.AASTORE));

        if (shouldChunkIndyFlowTableInit(table)) {
            emitAllocateIndyMaterialSubtable(insns, tableLocal, 0, table.cells().size());
            emitAllocateIndyMaterialSubtable(insns, tableLocal, 1, table.resolverCells().size());
            emitAllocateIndyMaterialSubtable(insns, tableLocal, 2, table.cells().size());
            emitAllocateIndyMaterialSubtable(
                insns,
                tableLocal,
                INDY_ARRAY_MATERIAL_TABLE_LOGICAL,
                table.arrayCells().size()
            );
            emitIndyInitChunkCalls(pctx, owner, table, insns, tableLocal);
        } else {
            insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
            insns.add(new InsnNode(Opcodes.ICONST_0));
            JvmPassBytecode.pushInt(insns, table.cells().size());
            insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
            for (int i = 0; i < table.cells().size(); i++) {
                insns.add(new InsnNode(Opcodes.DUP));
                JvmPassBytecode.pushInt(insns, i);
                emitLongArray(insns, table.cells().get(i).encoded());
                insns.add(new InsnNode(Opcodes.AASTORE));
            }
            insns.add(new InsnNode(Opcodes.AASTORE));
            insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
            insns.add(new InsnNode(Opcodes.ICONST_1));
            JvmPassBytecode.pushInt(insns, table.resolverCells().size());
            insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
            for (int i = 0; i < table.resolverCells().size(); i++) {
                insns.add(new InsnNode(Opcodes.DUP));
                JvmPassBytecode.pushInt(insns, i);
                emitLongArray(insns, table.resolverCells().get(i).encoded());
                insns.add(new InsnNode(Opcodes.AASTORE));
            }
            insns.add(new InsnNode(Opcodes.AASTORE));
            insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
            JvmPassBytecode.pushInt(insns, 2);
            JvmPassBytecode.pushInt(insns, table.cells().size());
            insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
            for (int i = 0; i < table.cells().size(); i++) {
                insns.add(new InsnNode(Opcodes.DUP));
                JvmPassBytecode.pushInt(insns, i);
                insns.add(new TypeInsnNode(Opcodes.NEW, OBJECT));
                insns.add(new InsnNode(Opcodes.DUP));
                insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, OBJECT, "<init>", "()V", false));
                insns.add(new InsnNode(Opcodes.AASTORE));
            }
            insns.add(new InsnNode(Opcodes.AASTORE));
            insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
            JvmPassBytecode.pushInt(insns, INDY_ARRAY_MATERIAL_TABLE_LOGICAL);
            JvmPassBytecode.pushInt(insns, table.arrayCells().size());
            insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
            for (int i = 0; i < table.arrayCells().size(); i++) {
                insns.add(new InsnNode(Opcodes.DUP));
                JvmPassBytecode.pushInt(insns, i);
                IndyStaticArrayMaterialCell cell = table.arrayCells().get(i);
                if (cell == null) {
                    insns.add(new InsnNode(Opcodes.ACONST_NULL));
                } else {
                    emitLongArray(insns, cell.encoded());
                }
                insns.add(new InsnNode(Opcodes.AASTORE));
            }
            insns.add(new InsnNode(Opcodes.AASTORE));
        }
        JvmKeyDispatchPass.markGenerated(pctx, insns);
        replaceIndyFlowTableInit(table, insns);
        table.initHelper().maxLocals = directClinit
            ? Math.max(table.initHelper().maxLocals, tableLocal + 1)
            : tableLocal + 1;
        table.initHelper().maxStack = Math.max(table.initHelper().maxStack, 8);
        owner.markDirty();
    }

    private boolean shouldChunkIndyFlowTableInit(IndyFlowTable table) {
        return table.cells().size() > INDY_INIT_INLINE_CELL_LIMIT
            || table.resolverCells().size() > INDY_INIT_INLINE_CELL_LIMIT
            || table.arrayCells().size() > INDY_INIT_INLINE_CELL_LIMIT;
    }

    private void emitAllocateIndyMaterialSubtable(
        InsnList insns,
        int tableLocal,
        int logicalIndex,
        int size
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
        JvmPassBytecode.pushInt(insns, logicalIndex);
        JvmPassBytecode.pushInt(insns, size);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
        insns.add(new InsnNode(Opcodes.AASTORE));
    }

    private void emitIndyInitChunkCalls(
        PipelineContext pctx,
        L1Class owner,
        IndyFlowTable table,
        InsnList init,
        int tableLocal
    ) {
        emitIndyInitChunks(pctx, owner, table, init, tableLocal, IndyInitChunkKind.FLOW, 0, table.cells().size());
        emitIndyInitChunks(
            pctx,
            owner,
            table,
            init,
            tableLocal,
            IndyInitChunkKind.RESOLVER,
            0,
            table.resolverCells().size()
        );
        emitIndyInitChunks(pctx, owner, table, init, tableLocal, IndyInitChunkKind.LOCKS, 0, table.cells().size());
        emitIndyInitChunks(
            pctx,
            owner,
            table,
            init,
            tableLocal,
            IndyInitChunkKind.STATIC_ARRAY,
            0,
            table.arrayCells().size()
        );
    }

    private void emitIndyInitChunks(
        PipelineContext pctx,
        L1Class owner,
        IndyFlowTable table,
        InsnList init,
        int tableLocal,
        IndyInitChunkKind kind,
        int start,
        int end
    ) {
        for (int chunkStart = start; chunkStart < end; chunkStart += INDY_INIT_CHUNK_MAX_CELLS) {
            int chunkEnd = Math.min(end, chunkStart + INDY_INIT_CHUNK_MAX_CELLS);
            MethodNode helper = createIndyInitChunkHelper(pctx, owner, table, kind, chunkStart, chunkEnd);
            if (helper == null) continue;
            init.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
            init.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                owner.name(),
                helper.name,
                OBJECT_ARRAY_TO_VOID_DESC,
                owner.isInterface()
            ));
        }
    }

    private MethodNode createIndyInitChunkHelper(
        PipelineContext pctx,
        L1Class owner,
        IndyFlowTable table,
        IndyInitChunkKind kind,
        int start,
        int end
    ) {
        if (kind == IndyInitChunkKind.STATIC_ARRAY && !hasStaticArrayMaterialCells(table, start, end)) {
            return null;
        }
        int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        access |= owner.isInterface() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
        MethodNode helper = new MethodNode(
            access,
            uniqueMethodName(owner, "__neko_indyinit$" + kind.suffix() + "$"),
            OBJECT_ARRAY_TO_VOID_DESC,
            null,
            null
        );
        helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        JvmPassBytecode.pushInt(helper.instructions, kind.logicalIndex());
        helper.instructions.add(new InsnNode(Opcodes.AALOAD));
        helper.instructions.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
        for (int i = start; i < end; i++) {
            switch (kind) {
                case FLOW -> emitObjectArrayLongCell(helper.instructions, 1, i, table.cells().get(i).encoded());
                case RESOLVER -> emitObjectArrayLongCell(
                    helper.instructions,
                    1,
                    i,
                    table.resolverCells().get(i).encoded()
                );
                case LOCKS -> emitObjectArrayNewObjectCell(helper.instructions, 1, i);
                case STATIC_ARRAY -> {
                    IndyStaticArrayMaterialCell cell = table.arrayCells().get(i);
                    if (cell != null) {
                        emitObjectArrayLongCell(helper.instructions, 1, i, cell.encoded());
                    }
                }
            }
        }
        helper.instructions.add(new InsnNode(Opcodes.RETURN));
        helper.maxLocals = 2;
        helper.maxStack = 12;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        owner.asmNode().methods.add(helper);
        table.initChunkHelpers().add(helper);
        return helper;
    }

    private boolean hasStaticArrayMaterialCells(IndyFlowTable table, int start, int end) {
        for (int i = start; i < end; i++) {
            if (table.arrayCells().get(i) != null) return true;
        }
        return false;
    }

    private void emitObjectArrayLongCell(InsnList insns, int arrayLocal, int index, long[] values) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(insns, index);
        emitLongArray(insns, values);
        insns.add(new InsnNode(Opcodes.AASTORE));
    }

    private void emitObjectArrayNewObjectCell(InsnList insns, int arrayLocal, int index) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(insns, index);
        insns.add(new TypeInsnNode(Opcodes.NEW, OBJECT));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, OBJECT, "<init>", "()V", false));
        insns.add(new InsnNode(Opcodes.AASTORE));
    }

    private void removeIndyInitChunkHelpers(L1Class owner, IndyFlowTable table) {
        if (table.initChunkHelpers().isEmpty()) return;
        owner.asmNode().methods.removeAll(table.initChunkHelpers());
        table.initChunkHelpers().clear();
        owner.markDirty();
    }

    private MethodNode createIndyInitHelper(L1Class clazz, boolean interfaceOwner) {
        int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        access |= interfaceOwner ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
        MethodNode helper = new MethodNode(
            access,
            uniqueMethodName(clazz, "__neko_indyinit$"),
            "()V",
            null,
            null
        );
        clazz.asmNode().methods.add(helper);
        return helper;
    }

    private void emitLongArray(InsnList insns, long[] values) {
        JvmPassBytecode.pushInt(insns, values.length);
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
        for (int i = 0; i < values.length; i++) {
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, i);
            JvmPassBytecode.pushLong(insns, values[i]);
            insns.add(new InsnNode(Opcodes.LASTORE));
        }
    }

    private IndyFlowMaterialCell indyFlowMaterialCell(
        IndyFlowTable table,
        int slot,
        long methodSalt,
        long siteSeed,
        int stateToken,
        int pcToken,
        long methodKey,
        int guardKey,
        int pathKey,
        int blockKey,
        int classWord
    ) {
        long layoutSeed = JvmPassBytecode.mix(
            methodSalt ^ Long.rotateLeft(siteSeed, 17) ^ stateToken,
            0x494E4459464C5954L ^ slot
        );
        long descriptor = indyMaterialDescriptor(layoutSeed, slot, 10, 0x494E4459464C4159L);
        long epoch = indyFlowSaltInitialEpoch(table, slot, descriptor);
        long[] encoded = indyMaterialNoiseCell(descriptor, 10, layoutSeed, 0x494E4459464E4F49L);
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_EPOCH_LOGICAL,
            epoch
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_METHOD_SALT_LOGICAL,
            methodSalt ^ indyFlowSaltMask(slot, descriptor, epoch, 0x494E4459464D534CL)
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_SITE_SEED_LOGICAL,
            siteSeed ^ indyFlowSaltMask(slot, descriptor, epoch, 0x494E445946535445L)
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_STATE_LOGICAL,
            stateToken ^ indyFlowStateMask(slot, descriptor, methodSalt, siteSeed)
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_PC_TOKEN_LOGICAL,
            pcToken ^ indyFlowPcTokenMask(slot, descriptor, methodSalt, siteSeed)
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_METHOD_KEY_LOGICAL,
            methodKey ^ indyFlowStaticLongMask(
                slot,
                descriptor,
                methodSalt,
                siteSeed,
                0x494E4459464D4B31L,
                0x494E4459464D4B32L
            )
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_GUARD_LOGICAL,
            guardKey ^ indyFlowStaticIntMask(slot, descriptor, methodSalt, siteSeed, 0x494E445946475541L)
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_PATH_LOGICAL,
            pathKey ^ indyFlowStaticIntMask(slot, descriptor, methodSalt, siteSeed, 0x494E445946504154L)
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_BLOCK_LOGICAL,
            blockKey ^ indyFlowStaticIntMask(slot, descriptor, methodSalt, siteSeed, 0x494E445946424C4BL)
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_FLOW_CLASS_WORD_LOGICAL,
            classWord ^ indyFlowStaticIntMask(slot, descriptor, methodSalt, siteSeed, 0x494E445946434C53L)
        );
        return new IndyFlowMaterialCell(descriptor, encoded);
    }

    private long indyFlowSaltInitialEpoch(IndyFlowTable table, int slot, long descriptor) {
        return JvmPassBytecode.mix(
            0x494E445946455043L ^ table.owner().hashCode() ^ indyMaterialFingerprint(descriptor),
            table.fieldName().hashCode() ^ slot ^ descriptor
        );
    }

    private long indyFlowSaltMask(int slot, long descriptor, long epoch, long tag) {
        return JvmPassBytecode.mix(
            epoch ^ (((long) slot) << 32) ^ tag ^ descriptor,
            tag ^ 0x494E4459464D4153L ^ slot ^ indyMaterialFingerprint(descriptor)
        );
    }

    private long indyFlowStateMask(int slot, long descriptor, long methodSalt, long siteSeed) {
        return JvmPassBytecode.mix(
            methodSalt ^ (((long) slot) << 32) ^ 0x494E445946535431L ^ descriptor,
            siteSeed ^ 0x494E445946535432L ^ slot ^ indyMaterialFingerprint(descriptor)
        );
    }

    private long indyFlowPcTokenMask(int slot, long descriptor, long methodSalt, long siteSeed) {
        return JvmPassBytecode.mix(
            methodSalt ^ (((long) slot) << 32) ^ 0x494E445946504331L ^ descriptor,
            siteSeed ^ 0x494E445946504332L ^ slot ^ indyMaterialFingerprint(descriptor)
        );
    }

    private long indyFlowStaticLongMask(
        int slot,
        long descriptor,
        long methodSalt,
        long siteSeed,
        long leftTag,
        long rightTag
    ) {
        return JvmPassBytecode.mix(
            methodSalt ^
                (((long) slot) << 32) ^
                leftTag ^
                descriptor,
            siteSeed ^
                rightTag ^
                slot ^
                indyMaterialFingerprint(descriptor)
        );
    }

    private long indyFlowStaticIntMask(
        int slot,
        long descriptor,
        long methodSalt,
        long siteSeed,
        long tag
    ) {
        return JvmPassBytecode.mix(
            methodSalt ^ (((long) slot) << 32) ^ tag ^ descriptor,
            siteSeed ^ (tag + 0x31L) ^ slot ^ indyMaterialFingerprint(descriptor)
        );
    }

    private int registerIndyResolverSeed(
        PipelineContext pctx,
        IndyFlowTable table,
        IndyResolverMaterialCell cell
    ) {
        int slot = table.resolverCells().size();
        table.resolverCells().add(cell);
        table.arrayCells().add(null);
        rebuildIndyFlowTableInit(pctx, table);
        return slot;
    }

    private void setIndyStaticArrayMaterial(
        PipelineContext pctx,
        IndyFlowTable table,
        int slot,
        IndyStaticArrayMaterialCell cell
    ) {
        while (table.arrayCells().size() <= slot) {
            table.arrayCells().add(null);
        }
        table.arrayCells().set(slot, cell);
        rebuildIndyFlowTableInit(pctx, table);
    }

    private IndyResolverMaterialCell indyResolverMaterialCell(
        IndyFlowTable table,
        int slot,
        long siteSeed,
        long salt,
        long flow,
        long helperKey
    ) {
        long layoutSeed = JvmPassBytecode.mix(
            siteSeed ^ Long.rotateLeft(salt, 23),
            0x494E4459524C5954L ^ slot
        );
        long descriptor = indyMaterialDescriptor(layoutSeed, slot, 3, 0x494E4459524C4159L);
        long epoch = indyResolverSeedInitialEpoch(table, slot, descriptor);
        long[] encoded = indyMaterialNoiseCell(descriptor, 3, layoutSeed, 0x494E4459524E4F49L);
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_RESOLVER_EPOCH_LOGICAL,
            epoch
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_RESOLVER_SEED_LOGICAL,
            siteSeed ^ indyResolverSeedMask(slot, descriptor, epoch, flow, helperKey, 0x494E445952534545L)
        );
        putIndyMaterialCellValue(
            encoded,
            descriptor,
            INDY_RESOLVER_SALT_LOGICAL,
            salt ^ indyResolverSeedMask(slot, descriptor, epoch, flow, helperKey, 0x494E44595253414CL)
        );
        return new IndyResolverMaterialCell(descriptor, encoded);
    }

    private IndyStaticArrayMaterialCell indyStaticArrayMaterialCell(
        JvmStaticArrayMaterial.Material material,
        int slot,
        long siteSeed,
        long salt,
        long flow
    ) {
        long[] values = material.values();
        long[] encoded = new long[values.length + 1];
        encoded[0] = values.length;
        for (int i = 0; i < values.length; i++) {
            encoded[i + 1] = values[i] ^ staticArrayMaterialMask(
                siteSeed,
                salt,
                flow,
                i,
                values.length,
                material.kind()
            ) ^ slot;
        }
        return new IndyStaticArrayMaterialCell(encoded);
    }

    private static long staticArrayMaterialMask(
        long seed,
        long salt,
        long flow,
        int index,
        int length,
        PrimitiveArrayKind kind
    ) {
        long value = seed
            ^ Long.rotateLeft(salt + ((long) index * 0x9E3779B97F4A7C15L), 17)
            ^ flow
            ^ (((long) index) << 32)
            ^ length
            ^ staticArrayMaterialDomain(kind);
        value ^= value >>> 33;
        value *= 0xff51afd7ed558ccdl;
        value ^= value >>> 33;
        value *= 0xc4ceb9fe1a85ec53L;
        value ^= value >>> 33;
        return value;
    }

    private static long staticArrayMaterialDomain(PrimitiveArrayKind kind) {
        return switch (kind) {
            case BOOLEAN -> 0x4152524D5A424F4FL;
            case BYTE -> 0x4152524D5A425954L;
            case CHAR -> 0x4152524D5A434852L;
            case SHORT -> 0x4152524D5A534852L;
            case INT -> 0x4152524D5A494E54L;
            case LONG -> 0x4152524D5A4C4F4EL;
            case FLOAT -> 0x4152524D5A464C54L;
            case DOUBLE -> 0x4152524D5A44424CL;
        };
    }

    private long indyResolverSeedInitialEpoch(IndyFlowTable table, int slot, long descriptor) {
        return JvmPassBytecode.mix(
            0x494E445952455043L ^ table.owner().hashCode() ^ indyMaterialFingerprint(descriptor),
            table.fieldName().hashCode() ^ slot ^ descriptor
        );
    }

    private long indyResolverHelperKey(long siteKey, long flow) {
        return JvmPassBytecode.mix(
            siteKey ^ flow ^ 0x494E445952484B31L,
            Long.rotateLeft(flow, 17) ^ 0x494E445952484B32L
        );
    }


    private long indyResolverSeedMask(
        int slot,
        long descriptor,
        long epoch,
        long flow,
        long helperKey,
        long tag
    ) {
        return JvmPassBytecode.mix(
            epoch ^ (((long) slot) << 32) ^ tag ^ descriptor ^ flow,
            tag ^ 0x494E4459524D4153L ^ slot ^ indyMaterialFingerprint(descriptor) ^ helperKey
        );
    }

    private long indyMaterialDescriptor(long layoutSeed, int slot, int logicalValues, long domain) {
        int layoutId = 1 + (int) Long.remainderUnsigned(
            JvmPassBytecode.mix(layoutSeed ^ domain, slot),
            0x7EL
        );
        int span = logicalValues + 3 + (layoutId & 3);
        int stride = indyMaterialStride(layoutSeed, span);
        int offset = (int) Long.remainderUnsigned(
            JvmPassBytecode.mix(layoutSeed, domain ^ 0x4F46465345544CL),
            span
        );
        long fingerprint = indyMaterialFingerprint(layoutSeed, slot, domain, layoutId, span, stride, offset);
        return (span & INDY_CELL_BYTE_MASK)
            | ((long) (stride & 0xFF) << INDY_CELL_STRIDE_SHIFT)
            | ((long) (offset & 0xFF) << INDY_CELL_OFFSET_SHIFT)
            | ((long) (layoutId & 0xFF) << INDY_CELL_LAYOUT_SHIFT)
            | (fingerprint << 32);
    }

    private int indyMaterialStride(long layoutSeed, int span) {
        int stride = 1 + (int) Long.remainderUnsigned(
            JvmPassBytecode.mix(layoutSeed, 0x535452494445L),
            span - 1L
        );
        while (gcd(stride, span) != 1) {
            stride++;
            if (stride >= span) {
                stride = 1;
            }
        }
        return stride;
    }

    private long indyMaterialFingerprint(
        long layoutSeed,
        int slot,
        long domain,
        int layoutId,
        int span,
        int stride,
        int offset
    ) {
        long mixed = JvmPassBytecode.mix(
            layoutSeed ^ (((long) layoutId) << 32) ^ domain,
            (((long) slot) << 24) ^ (((long) span) << 16) ^ (((long) stride) << 8) ^ offset
        );
        long fingerprint = mixed & 0xFFFFFFFFL;
        return fingerprint == 0L ? 1L : fingerprint;
    }

    private long indyMaterialFingerprint(long descriptor) {
        return descriptor >>> 32;
    }

    private long[] indyMaterialNoiseCell(long descriptor, int logicalValues, long layoutSeed, long domain) {
        long[] cell = new long[1 + indyMaterialSpan(descriptor)];
        cell[INDY_CELL_DESCRIPTOR_SLOT] = descriptor;
        for (int i = 1; i < cell.length; i++) {
            cell[i] = JvmPassBytecode.mix(layoutSeed ^ descriptor, domain + i);
        }
        return cell;
    }

    private void putIndyMaterialCellValue(long[] cell, long descriptor, int logicalIndex, long value) {
        cell[indyMaterialPhysicalIndex(descriptor, logicalIndex)] = value;
    }

    private int indyMaterialPhysicalIndex(long descriptor, int logicalIndex) {
        int span = indyMaterialSpan(descriptor);
        int stride = (int) ((descriptor >>> INDY_CELL_STRIDE_SHIFT) & INDY_CELL_BYTE_MASK);
        int offset = (int) ((descriptor >>> INDY_CELL_OFFSET_SHIFT) & INDY_CELL_BYTE_MASK);
        return 1 + Math.floorMod(logicalIndex * stride + offset, span);
    }

    private int indyMaterialSpan(long descriptor) {
        return (int) ((descriptor >>> INDY_CELL_SPAN_SHIFT) & INDY_CELL_BYTE_MASK);
    }

    private int gcd(int a, int b) {
        while (b != 0) {
            int t = a % b;
            a = b;
            b = t;
        }
        return Math.abs(a);
    }

    private void replaceIndyFlowTableInit(IndyFlowTable table, InsnList replacement) {
        if (!"<clinit>".equals(table.initHelper().name)) {
            InsnList instructions = table.initHelper().instructions;
            while (instructions.getFirst() != null) {
                instructions.remove(instructions.getFirst());
            }
            instructions.add(replacement);
            instructions.add(new InsnNode(Opcodes.RETURN));
            return;
        }
        InsnList instructions = table.initHelper().instructions;
        AbstractInsnNode cursor = table.initStart().getNext();
        while (cursor != null && cursor != table.initEnd()) {
            AbstractInsnNode next = cursor.getNext();
            instructions.remove(cursor);
            cursor = next;
        }
        instructions.insert(table.initStart(), replacement);
    }

    private void insertClassInitCallAfter(
        MethodNode clinit,
        LabelNode anchor,
        LabelNode start,
        LabelNode end,
        String owner,
        String name,
        boolean interfaceOwner
    ) {
        InsnList segment = new InsnList();
        segment.add(start);
        segment.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            owner,
            name,
            "()V",
            interfaceOwner
        ));
        segment.add(end);
        if (anchor == null) {
            AbstractInsnNode first = clinit.instructions.getFirst();
            if (first == null) {
                clinit.instructions.add(segment);
                clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            } else {
                clinit.instructions.insertBefore(first, segment);
            }
            return;
        }
        clinit.instructions.insert(anchor, segment);
    }

    @SuppressWarnings("unchecked")
    private void publishGeneratedIndyHelperFlowKey(
        PipelineContext pctx,
        String owner,
        String name,
        String desc,
        int keyLocal
    ) {
        Map<String, Integer> locals = pctx.getPassData(JvmKeyDispatchPass.CFF_LOCAL_BY_METHOD);
        if (locals == null) {
            locals = new HashMap<>();
            pctx.putPassData(JvmKeyDispatchPass.CFF_LOCAL_BY_METHOD, locals);
        }
        locals.put(owner + "." + name + desc, keyLocal);
    }

    private MethodNode findOrCreateClassInit(L1Class clazz) {
        for (MethodNode method : clazz.asmNode().methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 0;
        clinit.maxLocals = 0;
        clazz.asmNode().methods.add(clinit);
        return clinit;
    }

    private void installInjectedStackTraceFilter(
        PipelineContext pctx,
        String helperOwner,
        List<String> helperMethods
    ) {
        for (L1Class target : pctx.classMap().values()) {
            for (MethodNode method : target.asmNode().methods) {
                if (method.instructions == null) continue;
                if (TransformGuards.isGeneratedMethod(method)) continue;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode call) || !isStackTraceCall(call)) continue;
                    InsnList filter = injectedStackTraceFilter(method, helperOwner, helperMethods);
                    JvmKeyDispatchPass.markGenerated(pctx, filter);
                    method.instructions.insert(call, filter);
                    target.markDirty();
                }
            }
        }
    }

    private boolean isStackTraceCall(MethodInsnNode call) {
        return call.getOpcode() == Opcodes.INVOKEVIRTUAL
            && "getStackTrace".equals(call.name)
            && "()[Ljava/lang/StackTraceElement;".equals(call.desc)
            && ("java/lang/Throwable".equals(call.owner) || "java/lang/Thread".equals(call.owner));
    }

    private InsnList injectedStackTraceFilter(MethodNode mn, String helperOwner, List<String> helperMethods) {
        int sourceLocal = mn.maxLocals++;
        int filteredLocal = mn.maxLocals++;
        int indexLocal = mn.maxLocals++;
        int writeLocal = mn.maxLocals++;
        int frameLocal = mn.maxLocals++;
        int methodNameLocal = mn.maxLocals++;
        LabelNode loop = new LabelNode();
        LabelNode skip = new LabelNode();
        LabelNode end = new LabelNode();
        InsnList insns = new InsnList();

        insns.add(new VarInsnNode(Opcodes.ASTORE, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/StackTraceElement"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, filteredLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, writeLocal));

        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, frameLocal));
        emitInjectedFrameTest(insns, frameLocal, methodNameLocal, helperOwner, helperMethods, skip);
        insns.add(new VarInsnNode(Opcodes.ALOAD, filteredLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, writeLocal));
        insns.add(new IincInsnNode(writeLocal, 1));
        insns.add(new VarInsnNode(Opcodes.ALOAD, frameLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(skip);
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));

        insns.add(end);
        insns.add(new VarInsnNode(Opcodes.ALOAD, filteredLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, writeLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/util/Arrays",
            "copyOf",
            "([Ljava/lang/Object;I)[Ljava/lang/Object;",
            false
        ));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/StackTraceElement;"));
        mn.maxStack = Math.max(mn.maxStack, 6);
        return insns;
    }

    private void emitInjectedFrameTest(
        InsnList insns,
        int frameLocal,
        int methodNameLocal,
        String helperOwner,
        List<String> helperMethods,
        LabelNode skip
    ) {
        if (helperMethods.isEmpty()) {
            return;
        }
        String ownerName = helperOwner.replace('/', '.');
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, frameLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StackTraceElement",
            "getClassName",
            "()Ljava/lang/String;",
            false
        ));
        insns.add(new LdcInsnNode(ownerName));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "equals",
            "(Ljava/lang/Object;)Z",
            false
        ));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, done));
        insns.add(new VarInsnNode(Opcodes.ALOAD, frameLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StackTraceElement",
            "getMethodName",
            "()Ljava/lang/String;",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ASTORE, methodNameLocal));
        for (String helperMethod : helperMethods) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, methodNameLocal));
            insns.add(new LdcInsnNode(helperMethod));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "equals",
                "(Ljava/lang/Object;)Z",
                false
            ));
            insns.add(new JumpInsnNode(Opcodes.IFNE, skip));
        }
        insns.add(done);
    }

    private void installInjectedMethodReflectionFilter(
        PipelineContext pctx,
        String helperOwner,
        List<String> helperMethods
    ) {
        for (L1Class target : pctx.classMap().values()) {
            for (MethodNode method : target.asmNode().methods) {
                if (method.instructions == null) continue;
                String activeOwner = null;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode ldc
                        && ldc.cst instanceof Type type
                        && type.getSort() == Type.OBJECT) {
                        activeOwner = type.getInternalName();
                        continue;
                    }
                    if (!isMethodReflectionResult(insn) || !helperOwner.equals(activeOwner)) continue;
                    InsnList filter = injectedMethodFilter(method, helperOwner, helperMethods);
                    JvmKeyDispatchPass.markGenerated(pctx, filter);
                    method.instructions.insert(insn, filter);
                    target.markDirty();
                    activeOwner = null;
                }
            }
        }
    }

    private boolean isMethodReflectionResult(AbstractInsnNode insn) {
        if (insn instanceof MethodInsnNode call) {
            return isMethodReflectionCall(call);
        }
        if (insn instanceof InvokeDynamicInsnNode indy) {
            return Type.getMethodType(indy.desc).getReturnType().getDescriptor().equals("[Ljava/lang/reflect/Method;");
        }
        return false;
    }

    private boolean isMethodReflectionCall(MethodInsnNode call) {
        return call.getOpcode() == Opcodes.INVOKEVIRTUAL
            && "java/lang/Class".equals(call.owner)
            && ("getMethods".equals(call.name) || "getDeclaredMethods".equals(call.name))
            && "()[Ljava/lang/reflect/Method;".equals(call.desc);
    }

    private void installInjectedFieldReflectionFilter(
        PipelineContext pctx,
        String helperOwner,
        List<String> helperFields
    ) {
        for (L1Class target : pctx.classMap().values()) {
            for (MethodNode method : target.asmNode().methods) {
                if (method.instructions == null) continue;
                String activeOwner = null;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode ldc
                        && ldc.cst instanceof Type type
                        && type.getSort() == Type.OBJECT) {
                        activeOwner = type.getInternalName();
                        continue;
                    }
                    if (!isFieldReflectionResult(insn) || !helperOwner.equals(activeOwner)) continue;
                    InsnList filter = injectedFieldFilter(method, helperOwner, helperFields);
                    JvmKeyDispatchPass.markGenerated(pctx, filter);
                    method.instructions.insert(insn, filter);
                    target.markDirty();
                    activeOwner = null;
                }
            }
        }
    }

    private boolean isFieldReflectionResult(AbstractInsnNode insn) {
        if (insn instanceof MethodInsnNode call) {
            return isFieldReflectionCall(call);
        }
        if (insn instanceof InvokeDynamicInsnNode indy) {
            return Type.getMethodType(indy.desc).getReturnType().getDescriptor().equals("[Ljava/lang/reflect/Field;");
        }
        return false;
    }

    private boolean isFieldReflectionCall(MethodInsnNode call) {
        return call.getOpcode() == Opcodes.INVOKEVIRTUAL
            && "java/lang/Class".equals(call.owner)
            && ("getFields".equals(call.name) || "getDeclaredFields".equals(call.name))
            && "()[Ljava/lang/reflect/Field;".equals(call.desc);
    }

    private InsnList injectedFieldFilter(MethodNode mn, String helperOwner, List<String> helperFields) {
        int sourceLocal = mn.maxLocals++;
        int filteredLocal = mn.maxLocals++;
        int indexLocal = mn.maxLocals++;
        int writeLocal = mn.maxLocals++;
        int fieldLocal = mn.maxLocals++;
        LabelNode loop = new LabelNode();
        LabelNode skip = new LabelNode();
        LabelNode end = new LabelNode();
        InsnList insns = new InsnList();

        insns.add(new VarInsnNode(Opcodes.ASTORE, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/reflect/Field"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, filteredLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, writeLocal));

        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, fieldLocal));
        LabelNode syntheticDone = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "isSynthetic",
            "()Z",
            false
        ));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, syntheticDone));
        insns.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "getModifiers",
            "()I",
            false
        ));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/reflect/Modifier",
            "isStatic",
            "(I)Z",
            false
        ));
        insns.add(new JumpInsnNode(Opcodes.IFNE, skip));
        insns.add(syntheticDone);
        insns.add(new VarInsnNode(Opcodes.ALOAD, filteredLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, writeLocal));
        insns.add(new IincInsnNode(writeLocal, 1));
        insns.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(skip);
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));

        insns.add(end);
        insns.add(new VarInsnNode(Opcodes.ALOAD, filteredLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, writeLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/util/Arrays",
            "copyOf",
            "([Ljava/lang/Object;I)[Ljava/lang/Object;",
            false
        ));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/reflect/Field;"));
        mn.maxStack = Math.max(mn.maxStack, 6);
        return insns;
    }

    private void emitInjectedFieldTest(
        InsnList insns,
        int fieldLocal,
        String helperOwner,
        List<String> helperFields,
        LabelNode skip
    ) {
        String ownerName = helperOwner.replace('/', '.');
        for (String helperField : helperFields) {
            LabelNode next = new LabelNode();
            insns.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Field",
                "getName",
                "()Ljava/lang/String;",
                false
            ));
            insns.add(new LdcInsnNode(helperField));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "equals",
                "(Ljava/lang/Object;)Z",
                false
            ));
            insns.add(new JumpInsnNode(Opcodes.IFEQ, next));
            insns.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Field",
                "getDeclaringClass",
                "()Ljava/lang/Class;",
                false
            ));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/Class",
                "getName",
                "()Ljava/lang/String;",
                false
            ));
            insns.add(new LdcInsnNode(ownerName));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "equals",
                "(Ljava/lang/Object;)Z",
                false
            ));
            insns.add(new JumpInsnNode(Opcodes.IFNE, skip));
            insns.add(next);
        }
    }

    private InsnList injectedMethodFilter(MethodNode mn, String helperOwner, List<String> helperMethods) {
        int sourceLocal = mn.maxLocals++;
        int filteredLocal = mn.maxLocals++;
        int indexLocal = mn.maxLocals++;
        int writeLocal = mn.maxLocals++;
        int methodLocal = mn.maxLocals++;
        LabelNode loop = new LabelNode();
        LabelNode skip = new LabelNode();
        LabelNode end = new LabelNode();
        InsnList insns = new InsnList();

        insns.add(new VarInsnNode(Opcodes.ASTORE, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/reflect/Method"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, filteredLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, writeLocal));

        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, methodLocal));
        LabelNode syntheticDone = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, methodLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Method",
            "isSynthetic",
            "()Z",
            false
        ));
        insns.add(new JumpInsnNode(Opcodes.IFNE, skip));
        insns.add(new JumpInsnNode(Opcodes.GOTO, syntheticDone));
        insns.add(new VarInsnNode(Opcodes.ALOAD, methodLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Method",
            "getModifiers",
            "()I",
            false
        ));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/reflect/Modifier",
            "isStatic",
            "(I)Z",
            false
        ));
        insns.add(new JumpInsnNode(Opcodes.IFNE, skip));
        insns.add(syntheticDone);
        insns.add(new VarInsnNode(Opcodes.ALOAD, filteredLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, writeLocal));
        insns.add(new IincInsnNode(writeLocal, 1));
        insns.add(new VarInsnNode(Opcodes.ALOAD, methodLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(skip);
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));

        insns.add(end);
        insns.add(new VarInsnNode(Opcodes.ALOAD, filteredLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, writeLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/util/Arrays",
            "copyOf",
            "([Ljava/lang/Object;I)[Ljava/lang/Object;",
            false
        ));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/reflect/Method;"));
        mn.maxStack = Math.max(mn.maxStack, 6);
        return insns;
    }

    private void emitInjectedMethodTest(
        InsnList insns,
        int methodLocal,
        String helperOwner,
        List<String> helperMethods,
        LabelNode skip
    ) {
        String ownerName = helperOwner.replace('/', '.');
        for (String helperMethod : helperMethods) {
            LabelNode next = new LabelNode();
            insns.add(new VarInsnNode(Opcodes.ALOAD, methodLocal));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Method",
                "getName",
                "()Ljava/lang/String;",
                false
            ));
            insns.add(new LdcInsnNode(helperMethod));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "equals",
                "(Ljava/lang/Object;)Z",
                false
            ));
            insns.add(new JumpInsnNode(Opcodes.IFEQ, next));
            insns.add(new VarInsnNode(Opcodes.ALOAD, methodLocal));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/reflect/Method",
                "getDeclaringClass",
                "()Ljava/lang/Class;",
                false
            ));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/Class",
                "getName",
                "()Ljava/lang/String;",
                false
            ));
            insns.add(new LdcInsnNode(ownerName));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String",
                "equals",
                "(Ljava/lang/Object;)Z",
                false
            ));
            insns.add(new JumpInsnNode(Opcodes.IFNE, skip));
            insns.add(next);
        }
    }

    private String uniqueMethodName(L1Class clazz, String base) {
        String name = base;
        int i = 0;
        while (hasMethod(clazz, name)) {
            name = base + "$" + (++i);
        }
        return name;
    }

    private String packageName(String owner) {
        int slash = owner.lastIndexOf('/');
        return slash < 0 ? "" : owner.substring(0, slash);
    }

    private boolean hasMethod(L1Class clazz, String name) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.name.equals(name)) return true;
        }
        return false;
    }

    private MethodNode emitBootstrapTrampoline(
        String name,
        int access,
        String bootstrapCoreOwner,
        String bootstrapCoreName,
        boolean bootstrapCoreInterfaceOwner
    ) {
        MethodNode mn = new MethodNode(
            access,
            name,
            BSM_DESC,
            null,
            new String[] {"java/lang/Throwable"}
        );
        InsnList insns = mn.instructions;
        int carrierLocal = 6;
        insns.add(new VarInsnNode(Opcodes.ALOAD, 5));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            METHOD_HANDLE,
            "invoke",
            "()Ljava/lang/Object;",
            false
        ));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ASTORE, carrierLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 1));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 3));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 4));
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            bootstrapCoreOwner,
            bootstrapCoreName,
            BSM_CORE_DESC,
            bootstrapCoreInterfaceOwner
        ));
        insns.add(new InsnNode(Opcodes.ARETURN));
        mn.maxStack = 6;
        mn.maxLocals = 7;
        return mn;
    }

    private MethodNode emitBootstrapCore(
        String name,
        String resolverOwner,
        String resolverName,
        boolean resolverInterfaceOwner,
        int access
    ) {
        MethodNode mn = new MethodNode(
            access,
            name,
            BSM_CORE_DESC,
            null,
            new String[] {"java/lang/Throwable"}
        );
        InsnList insns = mn.instructions;
        int carrierLocal = 5;
        int callSiteLocal = 8;
        int handleLocal = 9;

        insns.add(new TypeInsnNode(Opcodes.NEW, MUTABLE_CALL_SITE));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, MUTABLE_CALL_SITE, "<init>",
            "(Ljava/lang/invoke/MethodType;)V", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, callSiteLocal));

        insns.add(new LdcInsnNode(new Handle(
            Opcodes.H_INVOKESTATIC,
            resolverOwner,
            resolverName,
            RESOLVER_DESC,
            resolverInterfaceOwner
        )));
        insns.add(new LdcInsnNode(Type.getType(OBJECT_ARRAY_DESC)));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_TYPE, "parameterCount", "()I", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_HANDLE, "asCollector",
            "(Ljava/lang/Class;I)Ljava/lang/invoke/MethodHandle;", false));
        JvmPassBytecode.pushInt(insns, 0);
        JvmPassBytecode.pushInt(insns, 6);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
        arrayStore(insns, 0, () -> insns.add(new VarInsnNode(Opcodes.ALOAD, 0)));
        arrayStore(insns, 1, () -> insns.add(new VarInsnNode(Opcodes.ALOAD, callSiteLocal)));
        arrayStore(insns, 2, () -> insns.add(new VarInsnNode(Opcodes.ALOAD, 2)));
        arrayStore(insns, 3, () -> insns.add(new VarInsnNode(Opcodes.ALOAD, 3)));
        arrayStore(insns, 4, () -> {
            insns.add(new VarInsnNode(Opcodes.ILOAD, 4));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                "java/lang/Integer",
                "valueOf",
                "(I)Ljava/lang/Integer;",
                false
            ));
        });
        arrayStore(insns, 5, () -> insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal)));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "insertArguments",
            "(Ljava/lang/invoke/MethodHandle;I[Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "explicitCastArguments",
            "(Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_CACHE_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, CONCURRENT_HASH_MAP));
        emitResolverMissCacheKey(insns, 4);
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CONCURRENT_HASH_MAP, "putIfAbsent",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new InsnNode(Opcodes.POP));
        insns.add(new VarInsnNode(Opcodes.ALOAD, callSiteLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, MUTABLE_CALL_SITE, "setTarget",
            "(Ljava/lang/invoke/MethodHandle;)V", false));
        insns.add(new VarInsnNode(Opcodes.ALOAD, callSiteLocal));
        insns.add(new InsnNode(Opcodes.ARETURN));
        mn.maxStack = 10;
        mn.maxLocals = 10;
        return mn;
    }

    private MethodNode emitResolver(
        String name,
        String guardOwner,
        String guardName,
        boolean guardInterfaceOwner,
        StaticArrayHelperNames arrayHelpers,
        int access
    ) {
        MethodNode mn = new MethodNode(
            access,
            name,
            RESOLVER_DESC,
            null,
            new String[] {"java/lang/Throwable"}
        );
        InsnList insns = mn.instructions;
        int resolverSlotLocal = 4;
        int carrierLocal = 5;
        int argsLocal = 6;
        int indexLocal = 9;
        int tokenLocal = 10;
        int flowLocal = RESOLVER_FLOW_LOCAL;
        int payloadLocal = 14;
        int ownerLocal = 15;
        int nameLocal = 16;
        int descLocal = 17;
        int classLocal = 18;
        int typeLocal = 19;
        int handleLocal = 20;
        int cacheKeyLocal = 21;
        int sep1Local = 22;
        int sep2Local = 23;
        int sep3Local = 24;
        int kindLocal = 25;
        int classKeyLocal = 26;
        int typeKeyLocal = 27;
        int resultLocal = 31;
        int filterSourceLocal = 32;
        int filterTargetLocal = 33;
        int filterIndexLocal = 34;
        int filterWriteLocal = 35;
        int filterMemberLocal = 36;
        int resolverSlabLocal = 37;
        int resolverIndexLocal = 38;
        int resolverEpochLocal = 39;
        int resolverNextEpochLocal = 41;
        int seedLocal = 43;
        int saltLocal = 45;
        int cacheLocal = 47;
        int missHandleLocal = 48;
        int testHandleLocal = 49;
        int resolverDescriptorLocal = 50;
        int resolverHelperKeyLocal = 52;

        insns.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.ISUB));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        loadLongArrayArg(insns, argsLocal, indexLocal);
        insns.add(new VarInsnNode(Opcodes.LSTORE, flowLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.ISUB));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        loadLongArrayArg(insns, argsLocal, indexLocal);
        insns.add(new VarInsnNode(Opcodes.LSTORE, resolverHelperKeyLocal));
        emitResolverHelperKey(insns, resolverHelperKeyLocal, flowLocal);
        emitResolverSeedPairLoad(
            insns,
            carrierLocal,
            resolverSlotLocal,
            resolverSlabLocal,
            resolverIndexLocal,
            resolverDescriptorLocal,
            resolverEpochLocal,
            flowLocal,
            resolverHelperKeyLocal,
            seedLocal,
            saltLocal
        );
        emitIndyTokenFromFlow(insns, tokenLocal, seedLocal, saltLocal, flowLocal);
        emitIndyCacheLoad(insns, carrierLocal, cacheLocal);

        LabelNode resolve = new LabelNode();
        LabelNode afterResolve = new LabelNode();
        LabelNode invoke = new LabelNode();
        emitLiveCacheKey(
            insns,
            cacheKeyLocal,
            tokenLocal,
            flowLocal,
            seedLocal,
            saltLocal,
            resolverDescriptorLocal,
            2,
            1
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheKeyLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CONCURRENT_HASH_MAP, "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, METHOD_HANDLE));
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.IFNULL, resolve));
        insns.add(new JumpInsnNode(Opcodes.GOTO, invoke));
        insns.add(resolve);

        emitDecodeInline(
            insns,
            3,
            seedLocal,
            saltLocal,
            OWNER_SEED,
            tokenLocal,
            flowLocal,
            resolverDescriptorLocal,
            payloadLocal,
            28,
            29,
            30
        );
        emitParsePayload(insns, payloadLocal, ownerLocal, nameLocal, descLocal, kindLocal, sep1Local, sep2Local, sep3Local);

        emitResolveClassWithCache(insns, cacheLocal, ownerLocal, classLocal, classKeyLocal);
        emitResolveMethodTypeWithCache(insns, cacheLocal, descLocal, typeLocal, typeKeyLocal);

        LabelNode getField = new LabelNode();
        LabelNode putField = new LabelNode();
        LabelNode getStatic = new LabelNode();
        LabelNode putStatic = new LabelNode();
        LabelNode virtual = new LabelNode();
        LabelNode statik = new LabelNode();
        LabelNode iface = new LabelNode();
        LabelNode special = new LabelNode();
        LabelNode getStaticArrayMaterial = new LabelNode();
        LabelNode putStaticArrayMaterial = new LabelNode();
        LabelNode badKind = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, kindLocal));
        insns.add(new LookupSwitchInsnNode(
            badKind,
            new int[] {
                KIND_GETFIELD, KIND_PUTFIELD, KIND_GETSTATIC, KIND_PUTSTATIC,
                KIND_INVOKEVIRTUAL, KIND_INVOKESTATIC, KIND_INVOKEINTERFACE, KIND_INVOKESPECIAL,
                KIND_GETSTATIC_ARRAY_MATERIAL, KIND_PUTSTATIC_ARRAY_MATERIAL
            },
            new LabelNode[] {
                getField, putField, getStatic, putStatic, virtual, statik, iface, special,
                getStaticArrayMaterial, putStaticArrayMaterial
            }
        ));

        insns.add(getField);
        emitFindField(insns, "findGetter", classLocal, nameLocal, typeLocal);
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(putField);
        emitFindField(insns, "findSetter", classLocal, nameLocal, typeLocal);
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(getStatic);
        emitFindField(insns, "findStaticGetter", classLocal, nameLocal, typeLocal);
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(putStatic);
        emitFindField(insns, "findStaticSetter", classLocal, nameLocal, typeLocal);
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(virtual);
        emitFindMethod(insns, "findVirtual", classLocal, nameLocal, typeLocal, false);
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(statik);
        emitFindMethod(insns, "findStatic", classLocal, nameLocal, typeLocal, false);
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(iface);
        emitFindMethod(insns, "findVirtual", classLocal, nameLocal, typeLocal, false);
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(special);
        emitFindMethod(insns, "findSpecial", classLocal, nameLocal, typeLocal, true);
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(getStaticArrayMaterial);
        emitStaticArrayMaterialGetter(
            insns,
            guardOwner,
            guardInterfaceOwner,
            arrayHelpers,
            descLocal,
            carrierLocal,
            resolverSlotLocal,
            seedLocal,
            saltLocal,
            flowLocal,
            handleLocal,
            badKind
        );
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(putStaticArrayMaterial);
        emitStaticArrayMaterialPutNoop(insns, typeLocal, handleLocal);
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterResolve));

        insns.add(badKind);
        insns.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new LdcInsnNode("Bad invokedynamic reference kind"));
        insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException", "<init>",
            "(Ljava/lang/String;)V", false));
        insns.add(new InsnNode(Opcodes.ATHROW));

        insns.add(afterResolve);
        emitAdaptTarget(insns, handleLocal);
        emitInstallGuardedTarget(
            insns,
            guardOwner,
            guardName,
            guardInterfaceOwner,
            handleLocal,
            missHandleLocal,
            testHandleLocal,
            flowLocal,
            cacheLocal,
            resolverSlotLocal,
            cacheKeyLocal,
            tokenLocal,
            seedLocal,
            saltLocal,
            resolverDescriptorLocal,
            2,
            1
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new LdcInsnNode(Type.getType(OBJECT_ARRAY_DESC)));
        insns.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_HANDLE, "asSpreader",
            "(Ljava/lang/Class;I)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CONCURRENT_HASH_MAP, "putIfAbsent",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new InsnNode(Opcodes.POP));

        insns.add(invoke);
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_HANDLE, "invoke",
            "([Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, resultLocal));
        emitInlineReflectionArrayResultFilter(
            insns,
            resultLocal,
            filterSourceLocal,
            filterTargetLocal,
            filterIndexLocal,
            filterWriteLocal,
            filterMemberLocal
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, resultLocal));
        insns.add(new InsnNode(Opcodes.ARETURN));
        mn.maxStack = 16;
        mn.maxLocals = 54;
        return mn;
    }

    private void emitIndyCacheLoad(InsnList insns, int carrierLocal, int cacheLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_CACHE_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, CONCURRENT_HASH_MAP));
        insns.add(new VarInsnNode(Opcodes.ASTORE, cacheLocal));
    }

    private void emitInlineReflectionArrayResultFilter(
        InsnList insns,
        int resultLocal,
        int sourceLocal,
        int filteredLocal,
        int indexLocal,
        int writeLocal,
        int memberLocal
    ) {
        LabelNode fieldCheck = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, resultLocal));
        insns.add(new TypeInsnNode(Opcodes.INSTANCEOF, "[Ljava/lang/reflect/Method;"));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, fieldCheck));
        insns.add(new VarInsnNode(Opcodes.ALOAD, resultLocal));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/reflect/Method;"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, sourceLocal));
        emitInlineMemberFilterLoop(
            insns,
            "java/lang/reflect/Method",
            "([Ljava/lang/Object;I)[Ljava/lang/Object;",
            "[Ljava/lang/reflect/Method;",
            resultLocal,
            sourceLocal,
            filteredLocal,
            indexLocal,
            writeLocal,
            memberLocal
        );
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(fieldCheck);
        insns.add(new VarInsnNode(Opcodes.ALOAD, resultLocal));
        insns.add(new TypeInsnNode(Opcodes.INSTANCEOF, "[Ljava/lang/reflect/Field;"));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, done));
        insns.add(new VarInsnNode(Opcodes.ALOAD, resultLocal));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/reflect/Field;"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, sourceLocal));
        emitInlineMemberFilterLoop(
            insns,
            "java/lang/reflect/Field",
            "([Ljava/lang/Object;I)[Ljava/lang/Object;",
            "[Ljava/lang/reflect/Field;",
            resultLocal,
            sourceLocal,
            filteredLocal,
            indexLocal,
            writeLocal,
            memberLocal
        );
        insns.add(done);
    }

    private void emitInlineMemberFilterLoop(
        InsnList insns,
        String memberType,
        String copyDesc,
        String arrayType,
        int resultLocal,
        int sourceLocal,
        int filteredLocal,
        int indexLocal,
        int writeLocal,
        int memberLocal
    ) {
        LabelNode loop = new LabelNode();
        LabelNode keep = new LabelNode();
        LabelNode skip = new LabelNode();
        LabelNode end = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, memberType));
        insns.add(new VarInsnNode(Opcodes.ASTORE, filteredLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, writeLocal));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        insns.add(new VarInsnNode(Opcodes.ALOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, memberLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            memberType,
            "isSynthetic",
            "()Z",
            false
        ));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, keep));
        insns.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            memberType,
            "getModifiers",
            "()I",
            false
        ));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/reflect/Modifier",
            "isStatic",
            "(I)Z",
            false
        ));
        insns.add(new JumpInsnNode(Opcodes.IFNE, skip));
        insns.add(keep);
        insns.add(new VarInsnNode(Opcodes.ALOAD, filteredLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, writeLocal));
        insns.add(new IincInsnNode(writeLocal, 1));
        insns.add(new VarInsnNode(Opcodes.ALOAD, memberLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(skip);
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
        insns.add(new VarInsnNode(Opcodes.ALOAD, filteredLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, writeLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/util/Arrays",
            "copyOf",
            copyDesc,
            false
        ));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, arrayType));
        insns.add(new VarInsnNode(Opcodes.ASTORE, resultLocal));
    }

    private void emitStaticArrayMaterialGetter(
        InsnList insns,
        String helperOwner,
        boolean helperInterfaceOwner,
        StaticArrayHelperNames helpers,
        int descLocal,
        int carrierLocal,
        int resolverSlotLocal,
        int seedLocal,
        int saltLocal,
        int flowLocal,
        int handleLocal,
        LabelNode badKind
    ) {
        LabelNode done = new LabelNode();
        emitStaticArrayMaterialGetterBranch(
            insns, "()[Z", helperOwner, helpers.booleanHelper(), "[Z", helperInterfaceOwner,
            descLocal, carrierLocal, resolverSlotLocal, seedLocal, saltLocal, flowLocal, handleLocal, done);
        emitStaticArrayMaterialGetterBranch(
            insns, "()[B", helperOwner, helpers.byteHelper(), "[B", helperInterfaceOwner,
            descLocal, carrierLocal, resolverSlotLocal, seedLocal, saltLocal, flowLocal, handleLocal, done);
        emitStaticArrayMaterialGetterBranch(
            insns, "()[C", helperOwner, helpers.charHelper(), "[C", helperInterfaceOwner,
            descLocal, carrierLocal, resolverSlotLocal, seedLocal, saltLocal, flowLocal, handleLocal, done);
        emitStaticArrayMaterialGetterBranch(
            insns, "()[S", helperOwner, helpers.shortHelper(), "[S", helperInterfaceOwner,
            descLocal, carrierLocal, resolverSlotLocal, seedLocal, saltLocal, flowLocal, handleLocal, done);
        emitStaticArrayMaterialGetterBranch(
            insns, "()[I", helperOwner, helpers.intHelper(), "[I", helperInterfaceOwner,
            descLocal, carrierLocal, resolverSlotLocal, seedLocal, saltLocal, flowLocal, handleLocal, done);
        emitStaticArrayMaterialGetterBranch(
            insns, "()[J", helperOwner, helpers.longHelper(), "[J", helperInterfaceOwner,
            descLocal, carrierLocal, resolverSlotLocal, seedLocal, saltLocal, flowLocal, handleLocal, done);
        emitStaticArrayMaterialGetterBranch(
            insns, "()[F", helperOwner, helpers.floatHelper(), "[F", helperInterfaceOwner,
            descLocal, carrierLocal, resolverSlotLocal, seedLocal, saltLocal, flowLocal, handleLocal, done);
        emitStaticArrayMaterialGetterBranch(
            insns, "()[D", helperOwner, helpers.doubleHelper(), "[D", helperInterfaceOwner,
            descLocal, carrierLocal, resolverSlotLocal, seedLocal, saltLocal, flowLocal, handleLocal, done);
        insns.add(new JumpInsnNode(Opcodes.GOTO, badKind));
        insns.add(done);
    }

    private void emitStaticArrayMaterialGetterBranch(
        InsnList insns,
        String expectedDesc,
        String helperOwner,
        String helperName,
        String returnDesc,
        boolean helperInterfaceOwner,
        int descLocal,
        int carrierLocal,
        int resolverSlotLocal,
        int seedLocal,
        int saltLocal,
        int flowLocal,
        int handleLocal,
        LabelNode done
    ) {
        LabelNode next = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, descLocal));
        insns.add(new LdcInsnNode(expectedDesc));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals",
            "(Ljava/lang/Object;)Z", false));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, next));
        insns.add(new LdcInsnNode(new Handle(
            Opcodes.H_INVOKESTATIC,
            helperOwner,
            helperName,
            "(Ljava/lang/Object;IJJJ)" + returnDesc,
            helperInterfaceOwner
        )));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        JvmPassBytecode.pushInt(insns, 5);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new VarInsnNode(Opcodes.ILOAD, resolverSlotLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
            "(I)Ljava/lang/Integer;", false));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, LONG, "valueOf", "(J)Ljava/lang/Long;", false));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new VarInsnNode(Opcodes.LLOAD, saltLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, LONG, "valueOf", "(J)Ljava/lang/Long;", false));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 4);
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, LONG, "valueOf", "(J)Ljava/lang/Long;", false));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "insertArguments",
            "(Ljava/lang/invoke/MethodHandle;I[Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(next);
    }

    private void emitStaticArrayMaterialPutNoop(InsnList insns, int typeLocal, int handleLocal) {
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC, VOID, "TYPE", "Ljava/lang/Class;"));
        insns.add(new VarInsnNode(Opcodes.ALOAD, typeLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_TYPE, "returnType",
            "()Ljava/lang/Class;", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_TYPE, "methodType",
            "(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/invoke/MethodType;", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "empty",
            "(Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
    }

    private MethodNode emitStaticArrayMaterialHelper(
        String name,
        PrimitiveArrayKind kind,
        int access
    ) {
        MethodNode mn = new MethodNode(
            access,
            name,
            "(Ljava/lang/Object;IJJJ)" + kind.descriptor(),
            null,
            null
        );
        InsnList insns = mn.instructions;
        int carrierLocal = 0;
        int slotLocal = 1;
        int seedLocal = 2;
        int saltLocal = 4;
        int flowLocal = 6;
        int tableLocal = 8;
        int arraysLocal = 9;
        int cellLocal = 10;
        int lengthLocal = 11;
        int outputLocal = 12;
        int indexLocal = 13;
        int valueLocal = 14;

        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ASTORE, tableLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
        JvmPassBytecode.pushInt(insns, INDY_ARRAY_MATERIAL_TABLE_LOGICAL);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ASTORE, arraysLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, arraysLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, cellLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cellLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.LALOAD));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ISTORE, lengthLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, kind.newArrayOperand()));
        insns.add(new VarInsnNode(Opcodes.ASTORE, outputLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));

        LabelNode loop = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, done));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cellLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.LALOAD));
        emitStaticArrayMaterialMask(
            insns,
            seedLocal,
            saltLocal,
            flowLocal,
            slotLocal,
            indexLocal,
            lengthLocal,
            kind
        );
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, valueLocal));
        emitStaticArrayElementStore(insns, kind, outputLocal, indexLocal, valueLocal);
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(done);
        insns.add(new VarInsnNode(Opcodes.ALOAD, outputLocal));
        insns.add(new InsnNode(Opcodes.ARETURN));
        mn.maxStack = 12;
        mn.maxLocals = 16;
        return mn;
    }

    private void emitStaticArrayMaterialMask(
        InsnList insns,
        int seedLocal,
        int saltLocal,
        int flowLocal,
        int slotLocal,
        int indexLocal,
        int lengthLocal,
        PrimitiveArrayKind kind
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, saltLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0x9E3779B97F4A7C15L);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.LADD));
        JvmPassBytecode.pushInt(insns, 17);
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, LONG, "rotateLeft", "(JI)J", false));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, staticArrayMaterialDomain(kind));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineLongMix(insns);
    }

    private void emitStaticArrayElementStore(
        InsnList insns,
        PrimitiveArrayKind kind,
        int outputLocal,
        int indexLocal,
        int valueLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, outputLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, valueLocal));
        switch (kind) {
            case BOOLEAN -> {
                insns.add(new InsnNode(Opcodes.L2I));
                insns.add(new InsnNode(Opcodes.ICONST_1));
                insns.add(new InsnNode(Opcodes.IAND));
                insns.add(new InsnNode(Opcodes.BASTORE));
            }
            case BYTE -> {
                insns.add(new InsnNode(Opcodes.L2I));
                insns.add(new InsnNode(Opcodes.BASTORE));
            }
            case CHAR -> {
                insns.add(new InsnNode(Opcodes.L2I));
                insns.add(new InsnNode(Opcodes.CASTORE));
            }
            case SHORT -> {
                insns.add(new InsnNode(Opcodes.L2I));
                insns.add(new InsnNode(Opcodes.SASTORE));
            }
            case INT -> {
                insns.add(new InsnNode(Opcodes.L2I));
                insns.add(new InsnNode(Opcodes.IASTORE));
            }
            case LONG -> insns.add(new InsnNode(Opcodes.LASTORE));
            case FLOAT -> {
                insns.add(new InsnNode(Opcodes.L2I));
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "intBitsToFloat",
                    "(I)F", false));
                insns.add(new InsnNode(Opcodes.FASTORE));
            }
            case DOUBLE -> {
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "longBitsToDouble",
                    "(J)D", false));
                insns.add(new InsnNode(Opcodes.DASTORE));
            }
        }
    }

    private void emitInlineLongMix(InsnList insns) {
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 33);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0xff51afd7ed558ccdl);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 33);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0xc4ceb9fe1a85ec53L);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 33);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitAdaptTarget(InsnList insns, int handleLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_HANDLE, "asFixedArity",
            "()Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_HANDLE, "type",
            "()Ljava/lang/invoke/MethodType;", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_TYPE, "parameterCount", "()I", false));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, CLASS));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC, LONG, "TYPE", "Ljava/lang/Class;"));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC, LONG, "TYPE", "Ljava/lang/Class;"));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "dropArguments",
            "(Ljava/lang/invoke/MethodHandle;I[Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "explicitCastArguments",
            "(Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, handleLocal));
    }

    private void emitInstallGuardedTarget(
        InsnList insns,
        String owner,
        String guardName,
        boolean interfaceOwner,
        int handleLocal,
        int missHandleLocal,
        int testHandleLocal,
        int flowLocal,
        int cacheLocal,
        int resolverSlotLocal,
        int cacheKeyLocal,
        int tokenLocal,
        int seedLocal,
        int saltLocal,
        int descriptorLocal,
        int methodTypeLocal,
        int callSiteLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheLocal));
        emitResolverMissCacheKey(insns, resolverSlotLocal);
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CONCURRENT_HASH_MAP, "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, METHOD_HANDLE));
        insns.add(new VarInsnNode(Opcodes.ASTORE, missHandleLocal));

        insns.add(new LdcInsnNode(new Handle(
            Opcodes.H_INVOKESTATIC,
            owner,
            guardName,
            "(JJ)Z",
            interfaceOwner
        )));
        JvmPassBytecode.pushInt(insns, 1);
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, LONG, "valueOf", "(J)Ljava/lang/Long;", false));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "insertArguments",
            "(Ljava/lang/invoke/MethodHandle;I[Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC, BOOLEAN, "TYPE", "Ljava/lang/Class;"));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_TYPE, "changeReturnType",
            "(Ljava/lang/Class;)Ljava/lang/invoke/MethodType;", false));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new VarInsnNode(Opcodes.ALOAD, 2));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_TYPE, "parameterCount", "()I", false));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.ISUB));
        insns.add(new InsnNode(Opcodes.IASTORE));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "permuteArguments",
            "(Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;[I)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, testHandleLocal));

        emitLiveCacheKey(
            insns,
            cacheKeyLocal,
            tokenLocal,
            flowLocal,
            seedLocal,
            saltLocal,
            descriptorLocal,
            methodTypeLocal,
            callSiteLocal
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, 1));
        insns.add(new VarInsnNode(Opcodes.ALOAD, testHandleLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, handleLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, missHandleLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_HANDLES, "guardWithTest",
            "(Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/MethodHandle;", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, MUTABLE_CALL_SITE, "setTarget",
            "(Ljava/lang/invoke/MethodHandle;)V", false));
    }

    private void emitResolverMissCacheKey(InsnList insns, int resolverSlotLocal) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, resolverSlotLocal));
        JvmPassBytecode.pushInt(insns, 0x4E4B4642);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/Integer",
            "valueOf",
            "(I)Ljava/lang/Integer;",
            false
        ));
    }

    private MethodNode emitKey(String name, int access) {
        MethodNode mn = new MethodNode(access, name, KEY_DESC, null, null);
        InsnList insns = mn.instructions;
        int carrierLocal = 0;
        int slotLocal = 1;
        int tableLocal = 2;
        int flowTableLocal = 3;
        int cellLocal = 4;
        int descriptorLocal = 5;
        int epochLocal = 7;
        int methodSaltLocal = 9;
        int siteSeedLocal = 11;
        int lockTableLocal = 13;
        int lockLocal = 14;
        int keyLocal = 15;

        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ASTORE, tableLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ASTORE, flowTableLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, flowTableLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, cellLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ASTORE, lockTableLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, lockTableLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, lockLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, lockLocal));
        insns.add(new InsnNode(Opcodes.MONITORENTER));
        emitIndyMaterialDescriptorLoad(insns, cellLocal, descriptorLocal);
        emitIndyMaterialCellValueLoad(insns, cellLocal, descriptorLocal, INDY_FLOW_EPOCH_LOGICAL);
        insns.add(new VarInsnNode(Opcodes.LSTORE, epochLocal));
        emitIndyMaterialCellValueLoad(insns, cellLocal, descriptorLocal, INDY_FLOW_METHOD_SALT_LOGICAL);
        emitIndyFlowSaltMask(insns, slotLocal, descriptorLocal, epochLocal, 0x494E4459464D534CL);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, methodSaltLocal));
        emitIndyMaterialCellValueLoad(insns, cellLocal, descriptorLocal, INDY_FLOW_SITE_SEED_LOGICAL);
        emitIndyFlowSaltMask(insns, slotLocal, descriptorLocal, epochLocal, 0x494E445946535445L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, siteSeedLocal));
        emitIndyMaterialCellValueLoad(insns, cellLocal, descriptorLocal, INDY_FLOW_METHOD_KEY_LOGICAL);
        emitIndyFlowStaticLongMask(
            insns,
            slotLocal,
            descriptorLocal,
            methodSaltLocal,
            siteSeedLocal,
            0x494E4459464D4B31L,
            0x494E4459464D4B32L
        );
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, lockLocal));
        insns.add(new InsnNode(Opcodes.MONITOREXIT));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.LRETURN));
        mn.maxStack = 10;
        mn.maxLocals = 17;
        return mn;
    }

    private MethodNode emitGuard(String name, int access) {
        MethodNode mn = new MethodNode(
            access,
            name,
            "(JJ)Z",
            null,
            null
        );
        LabelNode miss = new LabelNode();
        InsnList insns = mn.instructions;
        insns.add(new VarInsnNode(Opcodes.LLOAD, 0));
        insns.add(new VarInsnNode(Opcodes.LLOAD, 2));
        insns.add(new InsnNode(Opcodes.LCMP));
        insns.add(new JumpInsnNode(Opcodes.IFNE, miss));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(miss);
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.IRETURN));
        mn.maxStack = 4;
        mn.maxLocals = 4;
        return mn;
    }

    private void emitLiveCacheKey(
        InsnList insns,
        int cacheKeyLocal,
        int tokenLocal,
        int flowLocal,
        int seedLocal,
        int saltLocal,
        int descriptorLocal,
        int methodTypeLocal,
        int callSiteLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, tokenLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, saltLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ALOAD, methodTypeLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, OBJECT, "hashCode", "()I", false));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new VarInsnNode(Opcodes.ALOAD, callSiteLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "identityHashCode",
            "(Ljava/lang/Object;)I", false));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ALOAD, methodTypeLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_TYPE, "parameterCount", "()I", false));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0x494E4459434B4559L);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, LONG, "valueOf", "(J)Ljava/lang/Long;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, cacheKeyLocal));
    }

    private void emitParsePayload(
        InsnList insns,
        int payloadLocal,
        int ownerLocal,
        int nameLocal,
        int descLocal,
        int kindLocal,
        int sep1Local,
        int sep2Local,
        int sep3Local
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, payloadLocal));
        JvmPassBytecode.pushInt(insns, '\n');
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "indexOf", "(I)I", false));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sep1Local));

        insns.add(new VarInsnNode(Opcodes.ALOAD, payloadLocal));
        JvmPassBytecode.pushInt(insns, '\n');
        insns.add(new VarInsnNode(Opcodes.ILOAD, sep1Local));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "indexOf", "(II)I", false));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sep2Local));

        insns.add(new VarInsnNode(Opcodes.ALOAD, payloadLocal));
        JvmPassBytecode.pushInt(insns, '\n');
        insns.add(new VarInsnNode(Opcodes.ILOAD, sep2Local));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "indexOf", "(II)I", false));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sep3Local));

        insns.add(new VarInsnNode(Opcodes.ALOAD, payloadLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ILOAD, sep1Local));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "substring",
            "(II)Ljava/lang/String;", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "parseInt",
            "(Ljava/lang/String;)I", false));
        insns.add(new VarInsnNode(Opcodes.ISTORE, kindLocal));

        emitSubstring(insns, payloadLocal, sep1Local, sep2Local, ownerLocal);
        emitSubstring(insns, payloadLocal, sep2Local, sep3Local, nameLocal);

        insns.add(new VarInsnNode(Opcodes.ALOAD, payloadLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sep3Local));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "substring",
            "(I)Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, descLocal));
    }

    private void emitSubstring(InsnList insns, int payloadLocal, int startSepLocal, int endSepLocal, int outLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, payloadLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, startSepLocal));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, endSepLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "substring",
            "(II)Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, outLocal));
    }

    private void emitResolveClassWithCache(
        InsnList insns,
        int cacheLocal,
        int ownerLocal,
        int classLocal,
        int classKeyLocal
    ) {
        LabelNode miss = new LabelNode();
        LabelNode done = new LabelNode();

        insns.add(new LdcInsnNode("\u0001"));
        insns.add(new VarInsnNode(Opcodes.ALOAD, ownerLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat",
            "(Ljava/lang/String;)Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, classKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classKeyLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CONCURRENT_HASH_MAP, "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, CLASS));
        insns.add(new VarInsnNode(Opcodes.ASTORE, classLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        insns.add(new JumpInsnNode(Opcodes.IFNULL, miss));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));

        insns.add(miss);
        insns.add(new VarInsnNode(Opcodes.ALOAD, ownerLocal));
        JvmPassBytecode.pushInt(insns, '/');
        JvmPassBytecode.pushInt(insns, '.');
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "replace",
            "(CC)Ljava/lang/String;", false));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        emitLookupClassLoader(insns);
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, CLASS, "forName",
            "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, classLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CONCURRENT_HASH_MAP, "putIfAbsent",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new InsnNode(Opcodes.POP));
        insns.add(done);
    }

    private void emitResolveMethodTypeWithCache(
        InsnList insns,
        int cacheLocal,
        int descLocal,
        int typeLocal,
        int typeKeyLocal
    ) {
        LabelNode miss = new LabelNode();
        LabelNode done = new LabelNode();

        insns.add(new LdcInsnNode("\u0002"));
        insns.add(new VarInsnNode(Opcodes.ALOAD, descLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat",
            "(Ljava/lang/String;)Ljava/lang/String;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, typeKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, typeKeyLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CONCURRENT_HASH_MAP, "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, METHOD_TYPE));
        insns.add(new VarInsnNode(Opcodes.ASTORE, typeLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, typeLocal));
        insns.add(new JumpInsnNode(Opcodes.IFNULL, miss));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));

        insns.add(miss);
        insns.add(new VarInsnNode(Opcodes.ALOAD, descLocal));
        emitLookupClassLoader(insns);
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, METHOD_TYPE, "fromMethodDescriptorString",
            "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/invoke/MethodType;", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, typeLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, typeKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, typeLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CONCURRENT_HASH_MAP, "putIfAbsent",
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", false));
        insns.add(new InsnNode(Opcodes.POP));
        insns.add(done);
    }

    private void emitFindField(InsnList insns, String method, int classLocal, int nameLocal, int typeLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, nameLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, typeLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, METHOD_TYPE, "returnType", "()Ljava/lang/Class;", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, LOOKUP, method,
            "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;", false));
    }

    private void emitFindMethod(InsnList insns, String method, int classLocal, int nameLocal, int typeLocal, boolean special) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, nameLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, typeLocal));
        if (special) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
            insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, LOOKUP, "lookupClass", "()Ljava/lang/Class;", false));
            insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, LOOKUP, method,
                "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/Class;)Ljava/lang/invoke/MethodHandle;", false));
        } else {
            insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, LOOKUP, method,
                "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;", false));
        }
    }

    private void emitLookupClassLoader(InsnList insns) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, 0));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, LOOKUP, "lookupClass", "()Ljava/lang/Class;", false));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CLASS, "getClassLoader", "()Ljava/lang/ClassLoader;", false));
    }

    private void emitDecodeInline(
        InsnList insns,
        int stringLocal,
        int seedLocal,
        int saltLocal,
        long label,
        int tokenLocal,
        int flowLocal,
        int descriptorLocal,
        int outputLocal,
        int charsLocal,
        int indexLocal,
        int maskLocal
    ) {
        LabelNode loop = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, charsLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, charsLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, done));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, saltLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, label);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, tokenLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, CHAR_STRIDE);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.LADD));
        emitInlineMix(insns);
        insns.add(new VarInsnNode(Opcodes.LSTORE, maskLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, charsLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.DUP2));
        insns.add(new InsnNode(Opcodes.CALOAD));
        insns.add(new VarInsnNode(Opcodes.LLOAD, maskLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, maskLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2C));
        insns.add(new InsnNode(Opcodes.CASTORE));
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(done);
        insns.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ALOAD, charsLocal));
        insns.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false));
        insns.add(new VarInsnNode(Opcodes.ASTORE, outputLocal));
    }

    private void emitIndyTokenFromFlow(
        InsnList insns,
        int tokenLocal,
        int seedLocal,
        int saltLocal,
        int flowLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, saltLocal));
        JvmPassBytecode.pushLong(insns, 0x494E4459544B4631L);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
        insns.add(new VarInsnNode(Opcodes.LSTORE, tokenLocal));
    }

    private void emitResolverHelperKey(InsnList insns, int helperKeyLocal, int flowLocal) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, helperKeyLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0x494E445952484B31L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        JvmPassBytecode.pushInt(insns, 17);
        insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, LONG, "rotateLeft", "(JI)J", false));
        JvmPassBytecode.pushLong(insns, 0x494E445952484B32L);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
        insns.add(new VarInsnNode(Opcodes.LSTORE, helperKeyLocal));
    }

    private void emitResolverSeedPairLoad(
        InsnList insns,
        int carrierLocal,
        int slotLocal,
        int slabLocal,
        int indexLocal,
        int descriptorLocal,
        int epochLocal,
        int flowLocal,
        int helperKeyLocal,
        int seedLocal,
        int saltLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, slabLocal));
        emitIndyMaterialDescriptorLoad(insns, slabLocal, descriptorLocal);
        emitIndyMaterialCellValueLoad(insns, slabLocal, descriptorLocal, INDY_RESOLVER_EPOCH_LOGICAL);
        insns.add(new VarInsnNode(Opcodes.LSTORE, epochLocal));
        emitIndyMaterialCellValueLoad(insns, slabLocal, descriptorLocal, INDY_RESOLVER_SEED_LOGICAL);
        emitResolverSeedMask(insns, slotLocal, descriptorLocal, epochLocal, flowLocal, helperKeyLocal, 0x494E445952534545L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, seedLocal));
        emitIndyMaterialCellValueLoad(insns, slabLocal, descriptorLocal, INDY_RESOLVER_SALT_LOGICAL);
        emitResolverSeedMask(insns, slotLocal, descriptorLocal, epochLocal, flowLocal, helperKeyLocal, 0x494E44595253414CL);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, saltLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
    }

    private void emitResolverSeedPairUpdate(
        InsnList insns,
        int slotLocal,
        int slabLocal,
        int indexLocal,
        int descriptorLocal,
        int epochLocal,
        int nextEpochLocal,
        int seedFlowLocal,
        int helperKeyLocal,
        int seedLocal,
        int saltLocal,
        int tokenLocal
    ) {
        emitResolverSeedNextEpoch(insns, slotLocal, descriptorLocal, epochLocal, tokenLocal, seedFlowLocal);
        insns.add(new VarInsnNode(Opcodes.LSTORE, nextEpochLocal));
        emitResolverSeedCellStore(
            insns,
            slabLocal,
            descriptorLocal,
            INDY_RESOLVER_SEED_LOGICAL,
            slotLocal,
            nextEpochLocal,
            seedFlowLocal,
            helperKeyLocal,
            seedLocal,
            0x494E445952534545L
        );
        emitResolverSeedCellStore(
            insns,
            slabLocal,
            descriptorLocal,
            INDY_RESOLVER_SALT_LOGICAL,
            slotLocal,
            nextEpochLocal,
            seedFlowLocal,
            helperKeyLocal,
            saltLocal,
            0x494E44595253414CL
        );
        emitIndyMaterialCellValueStore(
            insns,
            slabLocal,
            descriptorLocal,
            INDY_RESOLVER_EPOCH_LOGICAL,
            nextEpochLocal
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
    }

    private void emitResolverSeedMask(
        InsnList insns,
        int slotLocal,
        int descriptorLocal,
        int epochLocal,
        int flowLocal,
        int helperKeyLocal,
        long tag
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, epochLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, tag);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, tag ^ 0x494E4459524D4153L);
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, helperKeyLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
    }

    private void emitResolverSeedNextEpoch(
        InsnList insns,
        int slotLocal,
        int descriptorLocal,
        int epochLocal,
        int tokenLocal,
        int flowLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, epochLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, tokenLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0x494E44595245504CL);
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
    }

    private void emitResolverSeedCellStore(
        InsnList insns,
        int slabLocal,
        int descriptorLocal,
        int logicalIndex,
        int slotLocal,
        int epochLocal,
        int flowLocal,
        int helperKeyLocal,
        int valueLocal,
        long tag
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, slabLocal));
        emitIndyMaterialPhysicalIndex(insns, descriptorLocal, logicalIndex);
        insns.add(new VarInsnNode(Opcodes.LLOAD, valueLocal));
        emitResolverSeedMask(insns, slotLocal, descriptorLocal, epochLocal, flowLocal, helperKeyLocal, tag);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LASTORE));
    }

    private void emitIndyMaterialDescriptorLoad(InsnList insns, int cellLocal, int descriptorLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, cellLocal));
        JvmPassBytecode.pushInt(insns, INDY_CELL_DESCRIPTOR_SLOT);
        insns.add(new InsnNode(Opcodes.LALOAD));
        insns.add(new VarInsnNode(Opcodes.LSTORE, descriptorLocal));
    }

    private void emitIndyMaterialCellValueLoad(
        InsnList insns,
        int cellLocal,
        int descriptorLocal,
        int logicalIndex
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, cellLocal));
        emitIndyMaterialPhysicalIndex(insns, descriptorLocal, logicalIndex);
        insns.add(new InsnNode(Opcodes.LALOAD));
    }

    private void emitIndyMaterialCellValueStore(
        InsnList insns,
        int cellLocal,
        int descriptorLocal,
        int logicalIndex,
        int valueLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, cellLocal));
        emitIndyMaterialPhysicalIndex(insns, descriptorLocal, logicalIndex);
        insns.add(new VarInsnNode(Opcodes.LLOAD, valueLocal));
        insns.add(new InsnNode(Opcodes.LASTORE));
    }

    private void emitIndyMaterialPhysicalIndex(InsnList insns, int descriptorLocal, int logicalIndex) {
        JvmPassBytecode.pushInt(insns, logicalIndex);
        emitIndyDescriptorByte(insns, descriptorLocal, INDY_CELL_STRIDE_SHIFT);
        insns.add(new InsnNode(Opcodes.IMUL));
        emitIndyDescriptorByte(insns, descriptorLocal, INDY_CELL_OFFSET_SHIFT);
        insns.add(new InsnNode(Opcodes.IADD));
        emitIndyDescriptorByte(insns, descriptorLocal, INDY_CELL_SPAN_SHIFT);
        insns.add(new InsnNode(Opcodes.IREM));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
    }

    private void emitIndyDescriptorByte(InsnList insns, int descriptorLocal, int shift) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        if (shift != 0) {
            JvmPassBytecode.pushInt(insns, shift);
            insns.add(new InsnNode(Opcodes.LUSHR));
        }
        insns.add(new InsnNode(Opcodes.L2I));
        JvmPassBytecode.pushInt(insns, (int) INDY_CELL_BYTE_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
    }

    private void emitIndyDescriptorFingerprint(InsnList insns, int descriptorLocal) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
    }

    private void loadLongArrayArg(InsnList insns, int argsLocal, int indexLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, argsLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, LONG));
        insns.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, LONG, "longValue", "()J", false));
    }

    private void emitInlineMix(InsnList insns) {
        insns.add(new InsnNode(Opcodes.LADD));
        JvmPassBytecode.pushLong(insns, 0x9E3779B97F4A7C15L);
        insns.add(new InsnNode(Opcodes.LADD));
        emitInlineMixRound(insns, 30, 0xBF58476D1CE4E5B9L);
        emitInlineMixRound(insns, 27, 0x94D049BB133111EBL);
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 31);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitInlineMixRound(InsnList insns, int shift, long mul) {
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, shift);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, mul);
        insns.add(new InsnNode(Opcodes.LMUL));
    }

    private void arrayStore(InsnList insns, int index, Runnable valueEmitter) {
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, index);
        valueEmitter.run();
        insns.add(new InsnNode(Opcodes.AASTORE));
    }

    private long liveIndyWord(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed
    ) {
        int x = (state.guardKey() + seededIndyInt(siteSeed, 0x494E44474731L)) ^
            state.pathKey();
        x += x >>> shift(siteSeed, 9);
        x = (x ^ state.blockKey()) * seededIndyInt(siteSeed, 0x494E444D554CL);
        x ^= state.pcToken() + seededIndyInt(siteSeed, 0x494E44504331L);
        x += indyClassWord(metadata, state, siteSeed) ^ seededIndyInt(siteSeed, 0x494E445456414CL);
        x ^= x >>> shift(siteSeed, 21);
        return (((long) x) & 0xFFFFFFFFL) ^
            state.methodKey() ^
            JvmPassBytecode.mix(state.methodKey(), 0x494E44594D4B31L) ^
            siteSeed;
    }

    private int indyClassWord(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed
    ) {
        int x = (state.guardKey() + seededIndyInt(siteSeed, 0x494E44474731L)) ^
            state.pathKey();
        x += x >>> shift(siteSeed, 9);
        x = (x ^ state.blockKey()) * seededIndyInt(siteSeed, 0x494E444D554CL);
        x ^= state.pcToken() + seededIndyInt(siteSeed, 0x494E44504331L);
        int idx = (x + state.state() + seededIndyInt(siteSeed, 0x494E445441424CL)) &
            (metadata.classKeyTable().values().length - 1);
        return metadata.classKeyTable().values()[idx];
    }

    private long indyTokenFromFlow(long siteSeed, long salt, long flow) {
        return JvmPassBytecode.mix(flow ^ siteSeed, salt ^ 0x494E4459544B4631L);
    }

    private void emitDynamicIndyLong(
        InsnList insns,
        long value,
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        int dynamicTokenLocal,
        int dynamicFlowLocal
    ) {
        int mask = liveIndyMask(metadata, state, siteSeed);
        int lowPad = nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x494E44594C504144L));

        insns.add(new VarInsnNode(Opcodes.LLOAD, dynamicFlowLocal));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dynamicTokenLocal));
        JvmPassBytecode.pushInt(insns, (int) (value >>> 32) ^ mask);
        insns.add(new VarInsnNode(Opcodes.ILOAD, dynamicTokenLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));

        JvmPassBytecode.pushInt(insns, ((int) value) ^ (mask ^ lowPad));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dynamicTokenLocal));
        JvmPassBytecode.pushInt(insns, lowPad);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    private int liveIndyMask(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long seed
    ) {
        long word = liveIndyWord(metadata, state, seed);
        return (int) (word ^ (word >>> 32));
    }

    private void emitBoundIndySiteKeyCall(
        InsnList insns,
        HelperNames helpers,
        int carrierLocal,
        int flowSaltSlot,
        int keyLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, flowSaltSlot);
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            helpers.keyOwner(),
            helpers.key(),
            KEY_DESC,
            helpers.keyInterfaceOwner()
        ));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
    }

    private void emitLiveIndyWord(
        InsnList insns,
        String owner,
        HelperNames helpers,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        boolean interfaceOwner,
        int indyMaterialLocal,
        int flowSaltSlot,
        int keyLocal
    ) {
        emitLiveIndyWordFromLocals(
            insns,
            helpers,
            metadata.guardLocal(),
            metadata.pathKeyLocal(),
            metadata.blockKeyLocal(),
            metadata.pcLocal(),
            metadata.dataLocal(),
            indyMaterialLocal,
            flowSaltSlot,
            keyLocal
        );
    }

    private void emitLiveIndyWordFromLocals(
        InsnList insns,
        HelperNames helpers,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int dataLocal,
        int indyMaterialLocal,
        int flowSaltSlot,
        int keyLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, indyMaterialLocal));
        JvmPassBytecode.pushInt(insns, flowSaltSlot);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            helpers.flowOwner(),
            helpers.flow(),
            FLOW_DESC,
            helpers.flowInterfaceOwner()
        ));
    }

    private void emitCompactLiveIndyWordFromLocals(
        InsnList insns,
        HelperNames helpers,
        int pcLocal,
        int dataLocal,
        int indyMaterialLocal,
        int flowSaltSlot,
        int keyLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, indyMaterialLocal));
        JvmPassBytecode.pushInt(insns, flowSaltSlot);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            helpers.compactFlowOwner(),
            helpers.compactFlow(),
            COMPACT_FLOW_DESC,
            helpers.compactFlowInterfaceOwner()
        ));
    }

    private void emitCachedLiveIndyWord(
        InsnList insns,
        String owner,
        HelperNames helpers,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        boolean interfaceOwner,
        int flowCacheLocal,
        int indyMaterialLocal,
        int flowSaltSlot,
        int keyLocal
    ) {
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowCacheLocal));
        insns.add(new InsnNode(Opcodes.DUP2));
        insns.add(new InsnNode(Opcodes.LCONST_0));
        insns.add(new InsnNode(Opcodes.LCMP));
        insns.add(new JumpInsnNode(Opcodes.IFNE, done));
        insns.add(new InsnNode(Opcodes.POP2));
        emitLiveIndyWord(
            insns,
            owner,
            helpers,
            metadata,
            state,
            interfaceOwner,
            indyMaterialLocal,
            flowSaltSlot,
            keyLocal
        );
        insns.add(new InsnNode(Opcodes.DUP2));
        insns.add(new VarInsnNode(Opcodes.LSTORE, flowCacheLocal));
        insns.add(done);
    }

    private MethodNode emitFlow(
        String name,
        int classKeyMask,
        int access
    ) {
        MethodNode mn = new MethodNode(
            access,
            name,
            FLOW_DESC,
            null,
            null
        );
        InsnList insns = mn.instructions;
        int carrierLocal = 5;
        int flowSlotLocal = 6;
        int stateLocal = 9;
        int xLocal = 10;
        int idxLocal = 11;
        int saltCellLocal = 12;
        int methodSaltLocal = 13;
        int siteSeedLocal = 15;
        int epochLocal = 17;
        int nextEpochLocal = 19;
        int flowTableLocal = 21;
        int selectorFoldLocal = 22;
        int saltLockLocal = 23;
        int sourceLocal = 24;
        int threadLocal = 25;
        int stackLocal = 26;
        int stackLenLocal = 27;
        int descriptorLocal = 28;
        int pcTokenLocal = 30;
        int staticGuardLocal = 31;
        int staticPathLocal = 32;
        int staticBlockLocal = 33;
        int staticClassWordLocal = 34;

        insns.add(new VarInsnNode(Opcodes.ILOAD, flowSlotLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, FLOW_HELPER_METHOD_KEY_LOCAL));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, FLOW_HELPER_METHOD_KEY_LOCAL));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, FLOW_HELPER_DATA_WORD_LOCAL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, selectorFoldLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, FLOW_HELPER_DATA_WORD_LOCAL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorFoldLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ASTORE, flowTableLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, flowTableLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flowSlotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, saltCellLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, flowTableLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flowSlotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, saltLockLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, saltLockLocal));
        insns.add(new InsnNode(Opcodes.MONITORENTER));
        emitIndyMaterialDescriptorLoad(insns, saltCellLocal, descriptorLocal);
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_EPOCH_LOGICAL);
        insns.add(new VarInsnNode(Opcodes.LSTORE, epochLocal));
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_METHOD_SALT_LOGICAL);
        emitIndyFlowSaltMask(insns, flowSlotLocal, descriptorLocal, epochLocal, 0x494E4459464D534CL);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, methodSaltLocal));
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_SITE_SEED_LOGICAL);
        emitIndyFlowSaltMask(insns, flowSlotLocal, descriptorLocal, epochLocal, 0x494E445946535445L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, siteSeedLocal));
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_STATE_LOGICAL);
        emitIndyFlowStateMask(insns, flowSlotLocal, descriptorLocal, methodSaltLocal, siteSeedLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_PC_TOKEN_LOGICAL);
        emitIndyFlowPcTokenMask(insns, flowSlotLocal, descriptorLocal, methodSaltLocal, siteSeedLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcTokenLocal));
        emitIndyFlowStaticIntLoad(
            insns,
            saltCellLocal,
            descriptorLocal,
            flowSlotLocal,
            methodSaltLocal,
            siteSeedLocal,
            INDY_FLOW_GUARD_LOGICAL,
            0x494E445946475541L,
            staticGuardLocal
        );
        emitIndyFlowStaticIntLoad(
            insns,
            saltCellLocal,
            descriptorLocal,
            flowSlotLocal,
            methodSaltLocal,
            siteSeedLocal,
            INDY_FLOW_PATH_LOGICAL,
            0x494E445946504154L,
            staticPathLocal
        );
        emitIndyFlowStaticIntLoad(
            insns,
            saltCellLocal,
            descriptorLocal,
            flowSlotLocal,
            methodSaltLocal,
            siteSeedLocal,
            INDY_FLOW_BLOCK_LOGICAL,
            0x494E445946424C4BL,
            staticBlockLocal
        );
        emitIndyFlowStaticIntLoad(
            insns,
            saltCellLocal,
            descriptorLocal,
            flowSlotLocal,
            methodSaltLocal,
            siteSeedLocal,
            INDY_FLOW_CLASS_WORD_LOGICAL,
            0x494E445946434C53L,
            staticClassWordLocal
        );
        emitRuntimeThreadStackSource(
            insns,
            sourceLocal,
            threadLocal,
            stackLocal,
            stackLenLocal,
            FLOW_HELPER_METHOD_KEY_LOCAL,
            stateLocal
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, flowSlotLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, FLOW_HELPER_METHOD_KEY_LOCAL));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, FLOW_HELPER_METHOD_KEY_LOCAL));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, FLOW_HELPER_DATA_WORD_LOCAL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, selectorFoldLocal));
        emitIndyFlowSaltNextEpoch(
            insns,
            flowSlotLocal,
            descriptorLocal,
            epochLocal,
            FLOW_HELPER_METHOD_KEY_LOCAL,
            stateLocal,
            sourceLocal,
            0,
            1,
            2,
            3
        );
        insns.add(new VarInsnNode(Opcodes.LSTORE, nextEpochLocal));
        emitIndyFlowSaltCellStore(
            insns,
            saltCellLocal,
            descriptorLocal,
            INDY_FLOW_METHOD_SALT_LOGICAL,
            flowSlotLocal,
            nextEpochLocal,
            methodSaltLocal,
            0x494E4459464D534CL
        );
        emitIndyFlowSaltCellStore(
            insns,
            saltCellLocal,
            descriptorLocal,
            INDY_FLOW_SITE_SEED_LOGICAL,
            flowSlotLocal,
            nextEpochLocal,
            siteSeedLocal,
            0x494E445946535445L
        );
        emitIndyMaterialCellValueStore(
            insns,
            saltCellLocal,
            descriptorLocal,
            INDY_FLOW_EPOCH_LOGICAL,
            nextEpochLocal
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, saltLockLocal));
        insns.add(new InsnNode(Opcodes.MONITOREXIT));

        insns.add(new VarInsnNode(Opcodes.ILOAD, staticGuardLocal));
        emitSeededInt(insns, siteSeedLocal, 0x494E44474731L);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, staticPathLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        emitShift(insns, siteSeedLocal, 9);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, staticBlockLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitSeededInt(insns, siteSeedLocal, 0x494E444D554CL);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcTokenLocal));
        emitSeededInt(insns, siteSeedLocal, 0x494E44504331L);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        emitSeededInt(insns, siteSeedLocal, 0x494E445441424CL);
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, classKeyMask);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, idxLocal));

        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        emitIndyClassKeyWordsSlotSelectionFromCarrier(insns, selectorFoldLocal);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, idxLocal));
        ControlFlowFlatteningPass.emitDecodedSealedClassKeyWord(
            insns,
            ControlFlowFlatteningPass.CLASS_KEY_WORD_SEAL
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorFoldLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, selectorFoldLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, staticClassWordLocal));
        emitSeededInt(insns, siteSeedLocal, 0x494E445456414CL);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        emitShift(insns, siteSeedLocal, 21);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new VarInsnNode(Opcodes.LLOAD, FLOW_HELPER_METHOD_KEY_LOCAL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, FLOW_HELPER_METHOD_KEY_LOCAL));
        JvmPassBytecode.pushLong(insns, 0x494E44594D4B31L);
        emitInlineMix(insns);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LRETURN));
        mn.maxStack = 12;
        mn.maxLocals = 35;
        return mn;
    }

    private MethodNode emitCompactFlow(
        String name,
        int classKeyMask,
        int access
    ) {
        MethodNode mn = new MethodNode(
            access,
            name,
            COMPACT_FLOW_DESC,
            null,
            null
        );
        InsnList insns = mn.instructions;
        int pcArgLocal = 0;
        int dataArgLocal = 1;
        int carrierLocal = 2;
        int flowSlotLocal = 3;
        int methodKeyLocal = 4;
        int stateLocal = 6;
        int xLocal = 7;
        int idxLocal = 8;
        int saltCellLocal = 9;
        int methodSaltLocal = 10;
        int siteSeedLocal = 12;
        int epochLocal = 14;
        int nextEpochLocal = 16;
        int flowTableLocal = 18;
        int selectorFoldLocal = 19;
        int saltLockLocal = 20;
        int sourceLocal = 21;
        int threadLocal = 22;
        int stackLocal = 23;
        int stackLenLocal = 24;
        int descriptorLocal = 25;
        int staticGuardLocal = 27;
        int staticPathLocal = 28;
        int staticBlockLocal = 29;
        int staticClassWordLocal = 30;
        int selectedClassKeySlotLocal = 31;
        int pcTokenLocal = 32;

        emitCompactFlowSelectorFold(
            insns,
            flowSlotLocal,
            methodKeyLocal,
            pcArgLocal,
            dataArgLocal,
            selectorFoldLocal
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.INDY_MATERIAL_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        emitCompactFlowSelectorFold(
            insns,
            flowSlotLocal,
            methodKeyLocal,
            pcArgLocal,
            dataArgLocal,
            -1
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorFoldLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ASTORE, flowTableLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, flowTableLocal));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flowSlotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, saltCellLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, flowTableLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, OBJECT_ARRAY_DESC));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flowSlotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, saltLockLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, saltLockLocal));
        insns.add(new InsnNode(Opcodes.MONITORENTER));
        emitIndyMaterialDescriptorLoad(insns, saltCellLocal, descriptorLocal);
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_EPOCH_LOGICAL);
        insns.add(new VarInsnNode(Opcodes.LSTORE, epochLocal));
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_METHOD_SALT_LOGICAL);
        emitIndyFlowSaltMask(insns, flowSlotLocal, descriptorLocal, epochLocal, 0x494E4459464D534CL);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, methodSaltLocal));
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_SITE_SEED_LOGICAL);
        emitIndyFlowSaltMask(insns, flowSlotLocal, descriptorLocal, epochLocal, 0x494E445946535445L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, siteSeedLocal));
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_STATE_LOGICAL);
        emitIndyFlowStateMask(insns, flowSlotLocal, descriptorLocal, methodSaltLocal, siteSeedLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, INDY_FLOW_PC_TOKEN_LOGICAL);
        emitIndyFlowPcTokenMask(insns, flowSlotLocal, descriptorLocal, methodSaltLocal, siteSeedLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcTokenLocal));
        emitIndyFlowStaticIntLoad(
            insns,
            saltCellLocal,
            descriptorLocal,
            flowSlotLocal,
            methodSaltLocal,
            siteSeedLocal,
            INDY_FLOW_GUARD_LOGICAL,
            0x494E445946475541L,
            staticGuardLocal
        );
        emitIndyFlowStaticIntLoad(
            insns,
            saltCellLocal,
            descriptorLocal,
            flowSlotLocal,
            methodSaltLocal,
            siteSeedLocal,
            INDY_FLOW_PATH_LOGICAL,
            0x494E445946504154L,
            staticPathLocal
        );
        emitIndyFlowStaticIntLoad(
            insns,
            saltCellLocal,
            descriptorLocal,
            flowSlotLocal,
            methodSaltLocal,
            siteSeedLocal,
            INDY_FLOW_BLOCK_LOGICAL,
            0x494E445946424C4BL,
            staticBlockLocal
        );
        emitIndyFlowStaticIntLoad(
            insns,
            saltCellLocal,
            descriptorLocal,
            flowSlotLocal,
            methodSaltLocal,
            siteSeedLocal,
            INDY_FLOW_CLASS_WORD_LOGICAL,
            0x494E445946434C53L,
            staticClassWordLocal
        );
        emitRuntimeThreadStackSource(
            insns,
            sourceLocal,
            threadLocal,
            stackLocal,
            stackLenLocal,
            methodKeyLocal,
            stateLocal
        );
        emitCompactFlowSelectorFold(
            insns,
            flowSlotLocal,
            methodKeyLocal,
            pcArgLocal,
            dataArgLocal,
            selectorFoldLocal
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorFoldLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, selectorFoldLocal));
        emitIndyFlowSaltNextEpoch(
            insns,
            flowSlotLocal,
            descriptorLocal,
            epochLocal,
            methodKeyLocal,
            stateLocal,
            sourceLocal,
            staticGuardLocal,
            staticPathLocal,
            staticBlockLocal,
            pcArgLocal
        );
        insns.add(new VarInsnNode(Opcodes.LSTORE, nextEpochLocal));
        emitIndyFlowSaltCellStore(
            insns,
            saltCellLocal,
            descriptorLocal,
            INDY_FLOW_METHOD_SALT_LOGICAL,
            flowSlotLocal,
            nextEpochLocal,
            methodSaltLocal,
            0x494E4459464D534CL
        );
        emitIndyFlowSaltCellStore(
            insns,
            saltCellLocal,
            descriptorLocal,
            INDY_FLOW_SITE_SEED_LOGICAL,
            flowSlotLocal,
            nextEpochLocal,
            siteSeedLocal,
            0x494E445946535445L
        );
        emitIndyMaterialCellValueStore(
            insns,
            saltCellLocal,
            descriptorLocal,
            INDY_FLOW_EPOCH_LOGICAL,
            nextEpochLocal
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, saltLockLocal));
        insns.add(new InsnNode(Opcodes.MONITOREXIT));

        insns.add(new VarInsnNode(Opcodes.ILOAD, staticGuardLocal));
        emitSeededInt(insns, siteSeedLocal, 0x494E44474731L);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, staticPathLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        emitShift(insns, siteSeedLocal, 9);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, staticBlockLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitSeededInt(insns, siteSeedLocal, 0x494E444D554CL);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcTokenLocal));
        emitSeededInt(insns, siteSeedLocal, 0x494E44504331L);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        emitSeededInt(insns, siteSeedLocal, 0x494E445441424CL);
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, classKeyMask);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, idxLocal));

        emitCompactIndyClassKeyWordsSlotSelectionFromCarrier(
            insns,
            carrierLocal,
            pcArgLocal,
            dataArgLocal,
            flowSlotLocal,
            selectorFoldLocal,
            selectedClassKeySlotLocal
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectedClassKeySlotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, idxLocal));
        ControlFlowFlatteningPass.emitDecodedSealedClassKeyWord(
            insns,
            ControlFlowFlatteningPass.CLASS_KEY_WORD_SEAL
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorFoldLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, selectorFoldLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, staticClassWordLocal));
        emitSeededInt(insns, siteSeedLocal, 0x494E445456414CL);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, xLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, xLocal));
        emitShift(insns, siteSeedLocal, 21);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushLong(insns, 0x494E44594D4B31L);
        emitInlineMix(insns);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LRETURN));
        mn.maxStack = 12;
        mn.maxLocals = 33;
        return mn;
    }

    private void emitCompactFlowSelectorFold(
        InsnList insns,
        int flowSlotLocal,
        int methodKeyLocal,
        int pcLocal,
        int dataLocal,
        int storeLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, flowSlotLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        if (storeLocal >= 0) {
            insns.add(new VarInsnNode(Opcodes.ISTORE, storeLocal));
        }
    }

    private void emitRuntimeThreadStackSource(
        InsnList insns,
        int sourceLocal,
        int threadLocal,
        int stackLocal,
        int stackLenLocal,
        int methodKeyLocal,
        int stateLocal
    ) {
        LabelNode noStack = new LabelNode();
        LabelNode skipFrame = new LabelNode();
        LabelNode skipTail = new LabelNode();
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/Thread",
            "currentThread",
            "()Ljava/lang/Thread;",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ASTORE, threadLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, threadLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/System",
            "identityHashCode",
            "(Ljava/lang/Object;)I",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, threadLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Thread",
            "getName",
            "()Ljava/lang/String;",
            false
        ));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "hashCode",
            "()I",
            false
        ));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, 0x45d9f3b);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, threadLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            OBJECT,
            "getClass",
            "()Ljava/lang/Class;",
            false
        ));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            OBJECT,
            "hashCode",
            "()I",
            false
        ));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        JvmPassBytecode.pushInt(insns, 15);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFNE, noStack));
        insns.add(new VarInsnNode(Opcodes.ALOAD, threadLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Thread",
            "getStackTrace",
            "()[Ljava/lang/StackTraceElement;",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ASTORE, stackLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, stackLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new VarInsnNode(Opcodes.ISTORE, stackLenLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stackLenLocal));
        JvmPassBytecode.pushInt(insns, 0x7feb352d);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stackLenLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPLE, skipFrame));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        JvmPassBytecode.pushInt(insns, 0x85ebca6b);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ALOAD, stackLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StackTraceElement",
            "hashCode",
            "()I",
            false
        ));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
        insns.add(skipFrame);
        insns.add(new VarInsnNode(Opcodes.ILOAD, stackLenLocal));
        JvmPassBytecode.pushInt(insns, 4);
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPLE, skipTail));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, stackLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stackLenLocal));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.ISUB));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/StackTraceElement",
            "hashCode",
            "()I",
            false
        ));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, 0xc2b2ae35);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
        insns.add(skipTail);
        insns.add(noStack);
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
    }

    private void emitIndyClassKeyWordsSlotSelectionFromCarrier(
        InsnList insns,
        int selectorFoldLocal
    ) {
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorFoldLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
    }

    private void emitCompactIndyClassKeyWordsSlotSelectionFromCarrier(
        InsnList insns,
        int carrierLocal,
        int pcLocal,
        int dataLocal,
        int flowSlotLocal,
        int selectorFoldLocal,
        int selectedSlotLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flowSlotLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorFoldLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, selectedSlotLocal));
    }

    private void emitIndyFlowSaltMask(
        InsnList insns,
        int slotLocal,
        int descriptorLocal,
        int epochLocal,
        long tag
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, epochLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, tag);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, tag ^ 0x494E4459464D4153L);
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
    }

    private void emitIndyFlowStateMask(
        InsnList insns,
        int slotLocal,
        int descriptorLocal,
        int methodSaltLocal,
        int siteSeedLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodSaltLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0x494E445946535431L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        JvmPassBytecode.pushLong(insns, 0x494E445946535432L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
    }

    private void emitIndyFlowPcTokenMask(
        InsnList insns,
        int slotLocal,
        int descriptorLocal,
        int methodSaltLocal,
        int siteSeedLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodSaltLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0x494E445946504331L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        JvmPassBytecode.pushLong(insns, 0x494E445946504332L);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
    }

    private void emitIndyFlowStaticIntMask(
        InsnList insns,
        int slotLocal,
        int descriptorLocal,
        int methodSaltLocal,
        int siteSeedLocal,
        long tag
    ) {
        emitIndyFlowStaticLongMask(
            insns,
            slotLocal,
            descriptorLocal,
            methodSaltLocal,
            siteSeedLocal,
            tag,
            tag + 0x31L
        );
    }

    private void emitIndyFlowStaticIntLoad(
        InsnList insns,
        int saltCellLocal,
        int descriptorLocal,
        int flowSlotLocal,
        int methodSaltLocal,
        int siteSeedLocal,
        int logicalIndex,
        long tag,
        int dstLocal
    ) {
        emitIndyMaterialCellValueLoad(insns, saltCellLocal, descriptorLocal, logicalIndex);
        emitIndyFlowStaticIntMask(insns, flowSlotLocal, descriptorLocal, methodSaltLocal, siteSeedLocal, tag);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dstLocal));
    }

    private void emitIndyFlowStaticLongMask(
        InsnList insns,
        int slotLocal,
        int descriptorLocal,
        int methodSaltLocal,
        int siteSeedLocal,
        long leftTag,
        long rightTag
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodSaltLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, leftTag);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        JvmPassBytecode.pushLong(insns, rightTag);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
    }

    private void emitIndyFlowSaltNextEpoch(
        InsnList insns,
        int slotLocal,
        int descriptorLocal,
        int epochLocal,
        int methodKeyLocal,
        int stateLocal,
        int sourceLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int pcLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, epochLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, descriptorLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 17);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0x494E44594645504CL);
        emitIndyDescriptorFingerprint(insns, descriptorLocal);
        insns.add(new InsnNode(Opcodes.LXOR));
        emitInlineMix(insns);
    }

    private void emitIndyFlowSaltCellStore(
        InsnList insns,
        int saltCellLocal,
        int descriptorLocal,
        int logicalIndex,
        int slotLocal,
        int epochLocal,
        int valueLocal,
        long tag
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, saltCellLocal));
        emitIndyMaterialPhysicalIndex(insns, descriptorLocal, logicalIndex);
        insns.add(new VarInsnNode(Opcodes.LLOAD, valueLocal));
        emitIndyFlowSaltMask(insns, slotLocal, descriptorLocal, epochLocal, tag);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LASTORE));
    }

    private void emitRuntimeBlockMethodKey(InsnList insns, int methodSaltLocal) {
        LabelNode nonZero = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, 0));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 1));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 2));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodSaltLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 3));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        JvmPassBytecode.pushLong(insns, 0x9E3779B97F4A7C15L);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.DUP2));
        insns.add(new InsnNode(Opcodes.LCONST_0));
        insns.add(new InsnNode(Opcodes.LCMP));
        insns.add(new JumpInsnNode(Opcodes.IFNE, nonZero));
        insns.add(new InsnNode(Opcodes.POP2));
        JvmPassBytecode.pushLong(insns, 0xD1B54A32D192ED03L);
        insns.add(nonZero);
    }

    private void emitSeededInt(
        InsnList insns,
        int seedLocal,
        long salt
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, salt);
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(salt >>> 32));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
    }

    private int seededIndyInt(long seed, long salt) {
        int value = (int) (seed ^ (seed >>> 32) ^ salt);
        value ^= value >>> 16;
        return (value * nonZeroInt(salt >>> 32)) | 1;
    }


    private void emitShift(InsnList insns, int seedLocal, int base) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        JvmPassBytecode.pushInt(insns, base);
        insns.add(new InsnNode(Opcodes.LUSHR));
        JvmPassBytecode.pushLong(insns, 30L);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
    }

    private String encrypt(String value, long seed, long token, long flow, long descriptor) {
        char[] chars = value.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (chars[i] ^ charMask(seed, token, flow, descriptor, i));
        }
        return new String(chars);
    }

    static String encryptedPayload(
        int kind,
        String owner,
        String name,
        String desc,
        long decodeSeed,
        long token,
        long flow,
        long resolverDescriptor
    ) {
        return new JvmInvokeDynamicObfuscationPass().encrypt(
            payload(kind, owner, name, desc),
            decodeSeed,
            token,
            flow,
            resolverDescriptor
        );
    }

    private int charMask(long seed, long token, long flow, long descriptor, int index) {
        long mixed = JvmPassBytecode.mix(
            flow ^ seed ^ indyMaterialFingerprint(descriptor),
            token + ((long) index * CHAR_STRIDE)
        );
        return (int) (mixed ^ (mixed >>> 32));
    }

    private String indyName(long siteSeed, int kind) {
        int c = 0x80 + (int) ((siteSeed ^ (kind * 131L)) & 0x3F);
        return Character.toString((char) c);
    }

    private long siteSeed(
        long masterSeed,
        L1Class clazz,
        L1Method method,
        ControlFlowFlatteningPass.CffInstructionState state,
        int ordinal
    ) {
        long h = JvmPassBytecode.mix(masterSeed ^ 0x494E44594F424631L, clazz.name().hashCode());
        h = JvmPassBytecode.mix(h, method.name().hashCode());
        h = JvmPassBytecode.mix(h, method.descriptor().hashCode());
        h = JvmPassBytecode.mix(h, state.blockIndex());
        h = JvmPassBytecode.mix(h, state.state());
        return JvmPassBytecode.mix(h, ordinal);
    }

    private int shift(long seed, int base) {
        return 1 + (int) ((seed >>> base) & 30L);
    }

    private int nonZeroInt(long value) {
        return ((int) value) | 1;
    }

    private record HelperNames(
        String bootstrapOwner,
        String bootstrap,
        boolean bootstrapInterfaceOwner,
        String flowOwner,
        String flow,
        boolean flowInterfaceOwner,
        String compactFlowOwner,
        String compactFlow,
        boolean compactFlowInterfaceOwner,
        String keyOwner,
        String key,
        boolean keyInterfaceOwner,
        String guardOwner,
        String guard,
        boolean guardInterfaceOwner
    ) {}

    private record SharedHelperNames(
        String bootstrapOwner,
        String bootstrap,
        boolean bootstrapInterfaceOwner,
        String bootstrapCoreOwner,
        String bootstrapCore,
        boolean bootstrapCoreInterfaceOwner,
        String resolverOwner,
        String resolver,
        boolean resolverInterfaceOwner,
        String flowOwner,
        String flow,
        boolean flowInterfaceOwner,
        String compactFlowOwner,
        String compactFlow,
        boolean compactFlowInterfaceOwner,
        String keyOwner,
        String key,
        boolean keyInterfaceOwner,
        String guardOwner,
        String guard,
        boolean guardInterfaceOwner
    ) {}

    private record StaticArrayHelperNames(
        String booleanHelper,
        String byteHelper,
        String charHelper,
        String shortHelper,
        String intHelper,
        String longHelper,
        String floatHelper,
        String doubleHelper
    ) {}

    private enum IndyInitChunkKind {
        FLOW(0, "flow"),
        RESOLVER(1, "resolver"),
        LOCKS(2, "locks"),
        STATIC_ARRAY(INDY_ARRAY_MATERIAL_TABLE_LOGICAL, "array");

        private final int logicalIndex;
        private final String suffix;

        IndyInitChunkKind(int logicalIndex, String suffix) {
            this.logicalIndex = logicalIndex;
            this.suffix = suffix;
        }

        private int logicalIndex() {
            return logicalIndex;
        }

        private String suffix() {
            return suffix;
        }
    }

    private record IndyFlowTable(
        String owner,
        String fieldName,
        MethodNode initHelper,
        List<IndyFlowMaterialCell> cells,
        List<IndyResolverMaterialCell> resolverCells,
        List<IndyStaticArrayMaterialCell> arrayCells,
        List<MethodNode> initChunkHelpers,
        LabelNode initStart,
        LabelNode initEnd
    ) {}

    private record IndyFlowMaterialCell(long descriptor, long[] encoded) {}

    private record IndyResolverMaterialCell(long descriptor, long[] encoded) {}

    private record IndyStaticArrayMaterialCell(long[] encoded) {}

    private record IndyPayloadKey(String indyName, String indyDesc, String payload, int resolverSlot) {}

    private record IndyPayloadSite(
        int kind,
        String owner,
        String name,
        String desc,
        long decodeSeed,
        long token,
        long flow,
        long resolverDescriptor
    ) {}

    private record SiteSpec(
        int kind,
        String owner,
        String name,
        String desc,
        String indyDesc,
        JvmStaticArrayMaterial.Material staticArrayMaterial
    ) {}
}
