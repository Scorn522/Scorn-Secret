package dev.nekoobfuscator.transforms.jvm.strings;

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
import dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningPass;
import dev.nekoobfuscator.transforms.jvm.key.JvmKeyDispatchPass;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Flow-keyed string literal protection for CFF-protected application code.
 */
public final class JvmStringObfuscationPass implements TransformPass {
    public static final String ID = "stringObfuscation";
    private static final String STRING_SITE_CACHES = "stringObfuscation.stringSiteCaches";
    private static final String STRING_KEY_TABLES = "stringObfuscation.stringKeyTables";
    private static final String STRING_DECODE_TAILS = "stringObfuscation.stringDecodeTails";
    private static final String STRING_CONCAT_HELPERS = "stringObfuscation.stringConcatHelpers";
    private static final String STRING_TAIL_DESC = "([Ljava/lang/Object;JIIIIII)Ljava/lang/String;";
    private static final String STRING_TAIL_COMPACT_DESC = "([Ljava/lang/Object;JIII)Ljava/lang/String;";
    private static final int STRING_CLASS_KEY_TABLE_MASK = 63;
    private static final int GENERATED_HELPER_HARDENING_SIZE_PRESSURE = 12_000;
    private static final int STRING_CALLER_SIZE_PRESSURE = 48_000;
    private static final int STRING_PAYLOAD_TABLE_SLOT = 0;
    private static final int STRING_CACHE_TABLE_SLOT = 1;
    private static final int STRING_AES_CIPHER_SLOT = 2;
    private static final int STRING_DES_CIPHER_SLOT = 3;
    private static final int STRING_KEY_CELL_BASE_SLOT = 4;
    private static final int STRING_KEY_CELL_PAYLOAD_SLOT = 8;
    private static final int STRING_KEY_CELL_CACHE_SLOT = 9;
    private static final int STRING_KEY_CELL_LENGTH = 10;
    private static final int STRING_KEY_CELL_RAW_PC = 11;
    private static final int STRING_KEY_CELL_GUARD = 12;
    private static final int STRING_KEY_CELL_PATH = 13;
    private static final int STRING_KEY_CELL_BLOCK = 14;
    private static final int STRING_KEY_CELL_DESCRIPTOR_SLOT = 0;
    private static final int STRING_KEY_CELL_PHYSICAL_MASK = 31;
    private static final int STRING_KEY_CELL_PHYSICAL_LENGTH = STRING_KEY_CELL_PHYSICAL_MASK + 2;
    private static final int STRING_KEY_CELL_OFFSET_SHIFT = 5;
    private static final int STRING_SELECTOR_LAYOUT_SHIFT = 8;
    private static final int STRING_SELECTOR_LAYOUT_MASK = 0x3F;
    private static final int STRING_SELECTOR_FINGERPRINT_SHIFT = 14;
    private static final int STRING_SELECTOR_FINGERPRINT_MASK = 0x3FFFF;
    private static final long STRING_KEY_CELL_PAYLOAD_MASK = 0x5354525041594C44L;
    private static final long STRING_KEY_CELL_CACHE_MASK = 0x5354524341434845L;
    private static final long STRING_KEY_CELL_LENGTH_MASK = 0x5354524C454E3031L;
    private static final long STRING_KEY_CELL_RAW_PC_MASK = 0x5354525043544F4BL;
    private static final long STRING_KEY_CELL_GUARD_MASK = 0x5354524755415244L;
    private static final long STRING_KEY_CELL_PATH_MASK = 0x5354525041544831L;
    private static final long STRING_KEY_CELL_BLOCK_MASK = 0x535452424C4F434BL;
    private static final long STATIC_CHAR_STRIDE = 0x9E3779B97F4A7C15L;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "JVM String Obfuscation";
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
        L1Class clazz = pctx.currentL1Class();
        L1Method method = pctx.currentL1Method();
        if (clazz == null || method == null || !method.hasCode()) return;
        if (TransformGuards.isRuntimeClass(clazz)) return;
        boolean generatedHelper = TransformGuards.isGeneratedMethod(method);
        boolean hardenGeneratedHelper =
            Boolean.TRUE.equals(pctx.getPassData("stringObfuscation.hardenGeneratedHelpers"));
        if (generatedHelper && !hardenGeneratedHelper) return;
        if (method.isAbstract() || method.isNative()) return;
        if (generatedHelper && hardenGeneratedHelper && generatedHelperUnderSizePressure(method.asmNode())) {
            return;
        }

        String methodKey = JvmKeyDispatchPass.coverageKey(clazz, method);
        ControlFlowFlatteningPass.CffMethodMetadata metadata =
            ControlFlowFlatteningPass.methodMetadata(pctx).get(methodKey);
        if (metadata == null) return;
        if (metadata.classKeyTable() == null) {
            throw new IllegalStateException(
                "stringObfuscation requires CFF class key table metadata for " + methodKey
            );
        }

        MethodNode mn = method.asmNode();
        int transformed = 0;
        int ordinal = 0;
        boolean hasLoopStringCacheInit = false;
        boolean canUseCallerCarrierLocal = !"<clinit>".equals(method.name());
        int callerCarrierLocal = -1;
        InsnList callerCarrierInit = new InsnList();
        Set<AbstractInsnNode> loopInstructions = loopRegionInstructions(mn);
        InsnList loopStringCacheInit = new InsnList();
        Set<Integer> defaultedStringResultLocals = new LinkedHashSet<>();
        InsnList stringResultLocalInit = new InsnList();
        boolean compactDecodeState = stringDecodeCallerUnderSizePressure(mn);
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (!metadata.applicationInstructions().contains(insn)) continue;
            ControlFlowFlatteningPass.CffInstructionState state =
                metadata.instructionStates().get(insn);
            if (state == null) {
                throw new IllegalStateException(
                    "stringObfuscation cannot bind CFF state for " + methodKey
                );
            }

            if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String value) {
                long siteSeed = siteSeed(pctx.masterSeed(), clazz, method, state, ordinal);
                StringSiteMaterial keyMaterial = stringSiteMaterial(pctx, clazz, siteSeed, state);
                Algorithm algorithm = algorithmFor(ordinal, siteSeed, metadata, state, keyMaterial);
                ByteLayer byteLayer = byteLayerFor(siteSeed, metadata, state, keyMaterial);
                byte[] encrypted = encryptPayload(value, siteSeed, metadata, state, algorithm, byteLayer, keyMaterial);
                StringSiteCache siteCache = ensureStringSiteCache(
                    pctx,
                    clazz,
                    metadata,
                    siteSeed,
                    encrypted,
                    keyMaterial,
                    algorithm,
                    byteLayer
                );
                if (canUseCallerCarrierLocal && callerCarrierLocal < 0) {
                    callerCarrierLocal = mn.maxLocals++;
                    callerCarrierInit.add(new FieldInsnNode(
                        Opcodes.GETSTATIC,
                        siteCache.owner(),
                        siteCache.keyTableFieldName(),
                        "[Ljava/lang/Object;"
                    ));
                    callerCarrierInit.add(new VarInsnNode(Opcodes.ASTORE, callerCarrierLocal));
                }
                InsnList replacement = new InsnList();
                if (loopInstructions.contains(insn)) {
                    int activeCarrierLocal = callerCarrierLocal;
                    int cacheLocal = mn.maxLocals++;
                    loopStringCacheInit.add(new InsnNode(Opcodes.ACONST_NULL));
                    loopStringCacheInit.add(new VarInsnNode(Opcodes.ASTORE, cacheLocal));
                    hasLoopStringCacheInit = true;
                    emitLoopCachedString(replacement, cacheLocal, () -> emitDecodedStringCall(
                        pctx,
                        clazz,
                        replacement,
                        mn,
                        encrypted.length,
                        siteSeed,
                        metadata,
                        state,
                        algorithm,
                        byteLayer,
                        siteCache,
                        activeCarrierLocal,
                        compactDecodeState
                    ));
                } else {
                    emitDecodedStringCall(
                        pctx,
                        clazz,
                        replacement,
                        mn,
                        encrypted.length,
                        siteSeed,
                        metadata,
                        state,
                        algorithm,
                        byteLayer,
                        siteCache,
                        callerCarrierLocal,
                        compactDecodeState
                    );
                }
                maybeAddStringResultLocalDefault(
                    mn,
                    insn,
                    defaultedStringResultLocals,
                    stringResultLocalInit
                );
                JvmKeyDispatchPass.markGenerated(pctx, replacement);
                mn.instructions.insertBefore(insn, replacement);
                mn.instructions.remove(insn);
                transformed++;
                ordinal++;
                continue;
            }

            if (insn instanceof InvokeDynamicInsnNode indy && isStringConcatWithConstants(indy)) {
                ConcatPlan concat = concatPlan(indy);
                if (concat.hasStringConstants()) {
                    boolean loopSite = loopInstructions.contains(insn);
                    if (loopSite && canUseCallerCarrierLocal && callerCarrierLocal < 0) {
                        callerCarrierLocal = mn.maxLocals++;
                        callerCarrierInit.add(new FieldInsnNode(
                            Opcodes.GETSTATIC,
                            metadata.classKeyTable().owner(),
                            metadata.classKeyTable().objectFieldName(),
                            "[Ljava/lang/Object;"
                        ));
                        callerCarrierInit.add(new VarInsnNode(Opcodes.ASTORE, callerCarrierLocal));
                    }
                    ConcatRewriteResult result = rewriteStringConcat(
                        pctx,
                        clazz,
                        method,
                        metadata,
                        state,
                        mn,
                        indy,
                        concat,
                        ordinal,
                        loopSite,
                        loopSite && canUseCallerCarrierLocal ? callerCarrierLocal : -1,
                        loopStringCacheInit
                    );
                    maybeAddStringResultLocalDefault(
                        mn,
                        insn,
                        defaultedStringResultLocals,
                        stringResultLocalInit
                    );
                    JvmKeyDispatchPass.markGenerated(pctx, result.instructions());
                    mn.instructions.insertBefore(insn, result.instructions());
                    mn.instructions.remove(insn);
                    transformed += result.encryptedStrings();
                    ordinal += result.encryptedStrings();
                    hasLoopStringCacheInit |= result.usesLoopCache();
                }
            }
        }

        if (transformed > 0) {
            InsnList entryInit = new InsnList();
            if (stringResultLocalInit.size() > 0) {
                entryInit.add(stringResultLocalInit);
            }
            if (hasLoopStringCacheInit) {
                entryInit.add(loopStringCacheInit);
            }
            if (callerCarrierLocal >= 0) {
                entryInit.add(callerCarrierInit);
            }
            if (entryInit.size() > 0) {
                JvmKeyDispatchPass.markGenerated(pctx, entryInit);
                insertStringEntryInit(mn, metadata.keyLocal(), metadata.guardLocal(), entryInit);
            }
            mn.maxStack = Math.max(mn.maxStack, 32);
            clazz.markDirty();
            pctx.invalidate(method);
            JvmObfuscationCoverage.get(ctx).full(
                id(),
                clazz.name(),
                method.name(),
                method.descriptor(),
                "cff-keyed-string-sites-" + transformed
            );
        }
    }

    private void insertStringEntryInit(MethodNode mn, int keyLocal, int guardLocal, InsnList init) {
        AbstractInsnNode anchor = hiddenKeyInitializationAnchor(mn, keyLocal, guardLocal);
        if (anchor == null) {
            mn.instructions.insert(init);
        } else {
            mn.instructions.insert(anchor, init);
        }
    }

    private AbstractInsnNode hiddenKeyInitializationAnchor(MethodNode mn, int keyLocal, int guardLocal) {
        AbstractInsnNode firstGuardStore = null;
        for (
            AbstractInsnNode insn = mn.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (
                insn instanceof VarInsnNode var &&
                    var.getOpcode() == Opcodes.ISTORE &&
                    var.var == guardLocal
            ) {
                firstGuardStore = insn;
                break;
            }
        }
        AbstractInsnNode anchor = null;
        for (
            AbstractInsnNode insn = mn.instructions.getFirst();
            insn != null && insn != firstGuardStore;
            insn = insn.getNext()
        ) {
            if (
                insn instanceof VarInsnNode var &&
                    var.getOpcode() == Opcodes.LSTORE &&
                    var.var == keyLocal
            ) {
                anchor = insn;
            }
        }
        return anchor == null ? firstHiddenKeyStore(mn, keyLocal) : anchor;
    }

    private AbstractInsnNode firstHiddenKeyStore(MethodNode mn, int keyLocal) {
        for (
            AbstractInsnNode insn = mn.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (
                insn instanceof VarInsnNode var &&
                    var.getOpcode() == Opcodes.LSTORE &&
                    var.var == keyLocal
            ) {
                return insn;
            }
        }
        return null;
    }

    private void maybeAddStringResultLocalDefault(
        MethodNode mn,
        AbstractInsnNode stringProducer,
        Set<Integer> defaultedLocals,
        InsnList init
    ) {
        AbstractInsnNode consumer = nextReal(stringProducer.getNext());
        if (!(consumer instanceof VarInsnNode store) || store.getOpcode() != Opcodes.ASTORE) return;
        if (store.var < argumentLocalLimit(mn)) return;
        if (!hasReferenceLocalLoad(mn, store.var)) return;
        if (!defaultedLocals.add(store.var)) return;
        init.add(new InsnNode(Opcodes.ACONST_NULL));
        init.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        init.add(new VarInsnNode(Opcodes.ASTORE, store.var));
        mn.maxLocals = Math.max(mn.maxLocals, store.var + 1);
    }

    private boolean hasReferenceLocalLoad(MethodNode mn, int local) {
        for (AbstractInsnNode insn : mn.instructions.toArray()) {
            if (insn instanceof VarInsnNode var
                    && var.var == local
                    && var.getOpcode() == Opcodes.ALOAD) {
                return true;
            }
        }
        return false;
    }

    private int argumentLocalLimit(MethodNode mn) {
        int local = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type type : Type.getArgumentTypes(mn.desc)) {
            local += type.getSize();
        }
        return local;
    }

    private AbstractInsnNode nextReal(AbstractInsnNode insn) {
        for (AbstractInsnNode cursor = insn; cursor != null; cursor = cursor.getNext()) {
            if (cursor.getOpcode() >= 0) return cursor;
        }
        return null;
    }

    private ConcatRewriteResult rewriteStringConcat(
        PipelineContext pctx,
        L1Class clazz,
        L1Method method,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        MethodNode mn,
        InvokeDynamicInsnNode indy,
        ConcatPlan concat,
        int ordinal,
        boolean loopSite,
        int callerCarrierLocal,
        InsnList loopStringCacheInit
    ) {
        Type[] args = Type.getArgumentTypes(indy.desc);
        long helperSeed = siteSeed(pctx.masterSeed(), clazz, method, state, ordinal) ^ 0x5354524341543131L;
        boolean compactState = stringConcatCallerUnderSizePressure(mn);
        List<String> externalStrings = compactState
            ? List.of()
            : concatStringConstants(concat);
        ConcatRewriteResult helper = installConcatHelper(
            pctx,
            clazz,
            method,
            metadata,
            state,
            indy,
            concat,
            ordinal,
            args,
            helperSeed,
            externalStrings,
            compactState
        );
        InsnList out = new InsnList();
        int externalized = 0;
        boolean usesLoopCache = false;
        for (String value : externalStrings) {
            long siteSeed = siteSeed(pctx.masterSeed(), clazz, method, state, ordinal + externalized);
            StringSiteMaterial keyMaterial = stringSiteMaterial(pctx, clazz, siteSeed, state);
            Algorithm algorithm = algorithmFor(ordinal + externalized, siteSeed, metadata, state, keyMaterial);
            ByteLayer byteLayer = byteLayerFor(siteSeed, metadata, state, keyMaterial);
            byte[] payload = encryptPayload(value, siteSeed, metadata, state, algorithm, byteLayer, keyMaterial);
            StringSiteCache siteCache = ensureStringSiteCache(
                pctx,
                clazz,
                metadata,
                siteSeed,
                payload,
                keyMaterial,
                algorithm,
                byteLayer
            );
            if (loopSite) {
                int cacheLocal = mn.maxLocals++;
                loopStringCacheInit.add(new InsnNode(Opcodes.ACONST_NULL));
                loopStringCacheInit.add(new VarInsnNode(Opcodes.ASTORE, cacheLocal));
                usesLoopCache = true;
                emitLoopCachedString(out, cacheLocal, () -> emitDecodedStringCall(
                    pctx,
                    clazz,
                    out,
                    mn,
                    payload.length,
                    siteSeed,
                    metadata,
                    state,
                    algorithm,
                    byteLayer,
                    siteCache,
                    callerCarrierLocal
                ));
            } else {
                emitDecodedStringCall(
                    pctx,
                    clazz,
                    out,
                    mn,
                    payload.length,
                    siteSeed,
                    metadata,
                    state,
                    algorithm,
                    byteLayer,
                    siteCache,
                    callerCarrierLocal
                );
            }
            externalized++;
        }
        out.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        if (compactState) {
            out.add(new VarInsnNode(Opcodes.ILOAD, metadata.pcLocal()));
        } else {
            out.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
            out.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
            out.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
            emitCanonicalPcToken(out, metadata, state, helperSeed);
        }
        out.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            clazz.name(),
            helper.helperName(),
            concatHelperDescriptor(args, externalStrings.size(), compactState),
            (clazz.asmNode().access & Opcodes.ACC_INTERFACE) != 0
        ));
        return new ConcatRewriteResult(out, helper.encryptedStrings() + externalized, null, usesLoopCache);
    }

    private ConcatRewriteResult installConcatHelper(
        PipelineContext pctx,
        L1Class clazz,
        L1Method method,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        InvokeDynamicInsnNode indy,
        ConcatPlan concat,
        int ordinal,
        Type[] args,
        long helperSeed,
        List<String> externalStrings,
        boolean compactState
    ) {
        int[] argLocals = new int[args.length];
        int nextLocal = 0;
        for (int i = 0; i < args.length; i++) {
            argLocals[i] = nextLocal;
            nextLocal += args[i].getSize();
        }
        Map<String, Integer> decodedStrings = new LinkedHashMap<>();
        for (String value : externalStrings) {
            decodedStrings.put(value, nextLocal++);
        }
        for (ConcatPiece piece : concat.pieces()) {
            if (piece instanceof LiteralPiece literal && !literal.value().isEmpty()) {
                decodedStrings.putIfAbsent(literal.value(), -1);
            } else if (piece instanceof ConstPiece constant
                && constant.value() instanceof String value
                && !value.isEmpty()) {
                decodedStrings.putIfAbsent(value, -1);
            }
        }
        boolean hasInternalDecodedStrings = decodedStrings.containsValue(-1);
        String helperDesc = concatHelperDescriptor(args, externalStrings.size(), compactState);
        ConcatHelperCacheKey cacheKey = null;
        if (!hasInternalDecodedStrings) {
            cacheKey = new ConcatHelperCacheKey(
                clazz.name(),
                helperDesc,
                concatHelperCachePieces(concat, externalStrings),
                concatExternalStringPattern(externalStrings)
            );
            String cached = cachedConcatHelper(pctx, cacheKey);
            if (cached != null) {
                return new ConcatRewriteResult(null, 0, cached, false);
            }
        }
        int methodKeyLocal = nextLocal;
        nextLocal += 2;
        int pcLocal = nextLocal++;
        int guardLocal;
        int pathKeyLocal;
        int blockKeyLocal;
        int rawPcLocal;
        if (compactState) {
            guardLocal = nextLocal++;
            pathKeyLocal = nextLocal++;
            blockKeyLocal = nextLocal++;
            rawPcLocal = nextLocal++;
        } else {
            guardLocal = pcLocal;
            pathKeyLocal = nextLocal++;
            blockKeyLocal = nextLocal++;
            pcLocal = nextLocal++;
            rawPcLocal = pcLocal;
        }
        int dataLocal = nextLocal++;
        String name = uniqueMethodName(
            clazz,
            "__neko_strcat$" + Long.toUnsignedString(helperSeed, 36)
        );
        MethodNode helper = new MethodNode(
            Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
            name,
            helperDesc,
            null,
            null
        );
        ControlFlowFlatteningPass.CffMethodMetadata helperMetadata =
            new ControlFlowFlatteningPass.CffMethodMetadata(
                state.methodKey(),
                methodKeyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                -1,
                dataLocal,
                Set.of(),
                Map.of(),
                metadata.classKeyTable()
        );
        helper.maxLocals = nextLocal;
        helper.maxStack = 32;
        int helperCarrierLocal = helper.maxLocals++;
        int selectorArrayLocal = helper.maxLocals++;
        int classWordsLocal = helper.maxLocals++;
        int concatPredicateLocal = helper.maxLocals++;
        int concatResultLocal = helper.maxLocals++;
        InsnList helperCarrierInit = new InsnList();
        helperCarrierInit.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            metadata.classKeyTable().owner(),
            metadata.classKeyTable().objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        helperCarrierInit.add(new VarInsnNode(Opcodes.ASTORE, helperCarrierLocal));
        if (compactState) {
            emitCompactConcatRawPcInit(
                helperCarrierInit,
                helperSeed,
                state,
                methodKeyLocal,
                rawPcLocal
            );
            emitCompactConcatStateInit(
                helperCarrierInit,
                metadata,
                state,
                helperSeed,
                helperCarrierLocal,
                methodKeyLocal,
                rawPcLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                concatPredicateLocal
            );
        }
        emitStringHelperDataDigestInit(
            helperCarrierInit,
            methodKeyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            dataLocal,
            helperSeed
        );
        int encrypted = 0;
        for (String value : new ArrayList<>(decodedStrings.keySet())) {
            if (decodedStrings.get(value) != -1) continue;
            nextLocal = Math.max(nextLocal, helper.maxLocals);
            int local = nextLocal++;
            helper.maxLocals = nextLocal;
            long siteSeed = siteSeed(pctx.masterSeed(), clazz, method, state, ordinal + encrypted);
            StringSiteMaterial keyMaterial = stringSiteMaterial(pctx, clazz, siteSeed, state);
            Algorithm algorithm = algorithmFor(ordinal + encrypted, siteSeed, metadata, state, keyMaterial);
            ByteLayer byteLayer = byteLayerFor(siteSeed, metadata, state, keyMaterial);
            byte[] payload = encryptPayload(value, siteSeed, metadata, state, algorithm, byteLayer, keyMaterial);
            StringSiteCache siteCache = ensureStringSiteCache(
                pctx,
                clazz,
                helperMetadata,
                siteSeed,
                payload,
                keyMaterial,
                algorithm,
                byteLayer
            );
            emitDecodedStringCall(
                pctx,
                clazz,
                helper.instructions,
                helper,
                payload.length,
                siteSeed,
                helperMetadata,
                state,
                algorithm,
                byteLayer,
                siteCache,
                helperCarrierLocal
            );
            nextLocal = Math.max(nextLocal, helper.maxLocals);
            helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, local));
            decodedStrings.put(value, local);
            encrypted++;
        }
        emitConcatCarrierDependency(
            helper.instructions,
            helperCarrierLocal,
            methodKeyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            selectorArrayLocal,
            classWordsLocal,
            concatPredicateLocal
        );
        JvmKeyDispatchPass.markGenerated(pctx, helperCarrierInit);
        helper.instructions.insertBefore(helper.instructions.getFirst(), helperCarrierInit);

        List<Type> concatArgs = new ArrayList<>();
        int argIndex = 0;
        for (ConcatPiece piece : concat.pieces()) {
            if (piece instanceof ArgPiece) {
                Type type = args[argIndex];
                helper.instructions.add(new VarInsnNode(type.getOpcode(Opcodes.ILOAD), argLocals[argIndex]));
                concatArgs.add(type);
                argIndex++;
            } else if (piece instanceof LiteralPiece literal) {
                if (emitDecodedStringLoad(helper.instructions, decodedStrings, literal.value())) {
                    concatArgs.add(Type.getType(String.class));
                }
            } else if (piece instanceof ConstPiece constant) {
                Type type = emitConcatConstant(helper.instructions, decodedStrings, constant.value());
                if (type != null) {
                    concatArgs.add(type);
                }
            }
        }
        helper.instructions.add(new InvokeDynamicInsnNode(
            "makeConcat",
            Type.getMethodDescriptor(
                Type.getType(String.class),
                concatArgs.toArray(Type[]::new)
            ),
            new Handle(
                Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/StringConcatFactory",
                "makeConcat",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
                false
            )
        ));
        helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, concatResultLocal));
        LabelNode predicateZero = new LabelNode();
        LabelNode predicateDone = new LabelNode();
        helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, concatPredicateLocal));
        helper.instructions.add(new JumpInsnNode(Opcodes.IFEQ, predicateZero));
        helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, concatResultLocal));
        helper.instructions.add(new JumpInsnNode(Opcodes.GOTO, predicateDone));
        helper.instructions.add(predicateZero);
        helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, concatResultLocal));
        helper.instructions.add(predicateDone);
        helper.instructions.add(new InsnNode(Opcodes.ARETURN));
        helper.maxLocals = Math.max(helper.maxLocals, nextLocal);
        helper.maxStack = 32;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        clazz.markDirty();
        publishGeneratedStringHelperFlowKey(
            pctx,
            clazz.name(),
            name,
            helper.desc,
            methodKeyLocal
        );
        if (cacheKey != null) {
            cacheConcatHelper(pctx, cacheKey, name);
        }
        return new ConcatRewriteResult(null, encrypted, name, false);
    }

    private void emitConcatCarrierDependency(
        InsnList insns,
        int carrierLocal,
        int methodKeyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int selectorArrayLocal,
        int classWordsLocal,
        int predicateLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(
            insns,
            ControlFlowFlatteningPass.CLASS_KEY_WORDS_SELECTOR_SLOT
        );
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, selectorArrayLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, selectorArrayLocal));
        emitConcatCarrierSelectorIndex(
            insns,
            methodKeyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal
        );
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, classWordsLocal));
        emitConcatCarrierSelectorIndex(
            insns,
            methodKeyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, predicateLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classWordsLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, predicateLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classWordsLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.ISUB));
        insns.add(new InsnNode(Opcodes.IAND));
        ControlFlowFlatteningPass.emitDecodedSealedClassKeyWord(
            insns,
            ControlFlowFlatteningPass.CLASS_KEY_WORD_SEAL
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, predicateLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, predicateLocal));
    }

    private void emitConcatCarrierSelectorIndex(
        InsnList insns,
        int methodKeyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitCompactConcatRawPcInit(
        InsnList insns,
        long helperSeed,
        ControlFlowFlatteningPass.CffInstructionState state,
        int methodKeyLocal,
        int outLocal
    ) {
        emitStaticIntFragmented(insns, state.pcToken() ^ compactConcatRawPcMask(helperSeed, state));
        emitCompactConcatRawPcMask(insns, helperSeed, methodKeyLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));
    }

    private void emitCompactConcatRawPcMask(
        InsnList insns,
        long helperSeed,
        int methodKeyLocal
    ) {
        long seed = JvmPassBytecode.mix(helperSeed, 0x5354435043524157L);
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544350434D4B31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 7));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544350434D554CL)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x535443504346494EL)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 19));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private int compactConcatRawPcMask(
        long helperSeed,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        long seed = JvmPassBytecode.mix(helperSeed, 0x5354435043524157L);
        int x = (int) state.methodKey() ^ (int) (state.methodKey() >>> 32);
        x ^= nonZeroInt(JvmPassBytecode.mix(seed, 0x53544350434D4B31L));
        x ^= x >>> shift(seed, 7);
        x *= nonZeroInt(JvmPassBytecode.mix(seed, 0x53544350434D554CL)) | 1;
        x += nonZeroInt(JvmPassBytecode.mix(seed, 0x535443504346494EL));
        return x ^ (x >>> shift(seed, 19));
    }

    private void emitCompactConcatStateInit(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long helperSeed,
        int carrierLocal,
        int methodKeyLocal,
        int pcLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int classWordLocal
    ) {
        int classWordIndex = compactConcatClassWordIndex(metadata, state, helperSeed);
        int classWord = metadata.classKeyTable().values()[classWordIndex];
        emitCompactConcatClassWord(insns, metadata, state, helperSeed, carrierLocal, methodKeyLocal, pcLocal, classWordLocal);
        emitCompactConcatStateWord(insns, helperSeed, state, classWord, 0, methodKeyLocal, pcLocal, classWordLocal, guardLocal);
        emitCompactConcatStateWord(insns, helperSeed, state, classWord, 1, methodKeyLocal, pcLocal, classWordLocal, pathKeyLocal);
        emitCompactConcatStateWord(insns, helperSeed, state, classWord, 2, methodKeyLocal, pcLocal, classWordLocal, blockKeyLocal);
    }

    private void emitCompactConcatClassWord(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long helperSeed,
        int carrierLocal,
        int methodKeyLocal,
        int pcLocal,
        int outLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        emitCompactConcatClassWordsSlotSelector(insns, helperSeed, methodKeyLocal, pcLocal);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));

        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, outLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        emitCompactConcatClassWordIndex(insns, metadata, state, helperSeed, methodKeyLocal, pcLocal);
        ControlFlowFlatteningPass.emitDecodedSealedClassKeyWord(
            insns,
            ControlFlowFlatteningPass.CLASS_KEY_WORD_SEAL
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));
    }

    private void emitCompactConcatClassWordsSlotSelector(
        InsnList insns,
        long helperSeed,
        int methodKeyLocal,
        int pcLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(helperSeed, 0x5354434154534C31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitCompactConcatClassWordIndex(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long helperSeed,
        int methodKeyLocal,
        int pcLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(helperSeed, 0x5354434149445831L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        emitStaticIntFragmented(insns, (int) state.selectorSeed());
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(helperSeed, 5));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(helperSeed, 0x5354434149445832L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        JvmPassBytecode.pushInt(insns, metadata.classKeyTable().values().length - 1);
        insns.add(new InsnNode(Opcodes.IAND));
    }

    private int compactConcatClassWordIndex(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long helperSeed
    ) {
        int x = (int) state.methodKey() ^ (int) (state.methodKey() >>> 32);
        x += state.pcToken() ^ nonZeroInt(JvmPassBytecode.mix(helperSeed, 0x5354434149445831L));
        x ^= (int) state.selectorSeed();
        x ^= x >>> shift(helperSeed, 5);
        x *= nonZeroInt(JvmPassBytecode.mix(helperSeed, 0x5354434149445832L)) | 1;
        return x & (metadata.classKeyTable().values().length - 1);
    }

    private void emitCompactConcatStateWord(
        InsnList insns,
        long helperSeed,
        ControlFlowFlatteningPass.CffInstructionState state,
        int classWord,
        int lane,
        int methodKeyLocal,
        int pcLocal,
        int classWordLocal,
        int outLocal
    ) {
        int value = switch (lane) {
            case 0 -> state.guardKey();
            case 1 -> state.pathKey();
            case 2 -> state.blockKey();
            default -> throw new IllegalArgumentException("invalid compact concat lane " + lane);
        };
        int mask = compactConcatStateMask(helperSeed, state, classWord, lane);
        emitStaticIntFragmented(insns, value ^ mask);
        emitCompactConcatStateMask(insns, helperSeed, state, lane, methodKeyLocal, pcLocal, classWordLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));
    }

    private void emitCompactConcatStateMask(
        InsnList insns,
        long helperSeed,
        ControlFlowFlatteningPass.CffInstructionState state,
        int lane,
        int methodKeyLocal,
        int pcLocal,
        int classWordLocal
    ) {
        long laneSeed = compactConcatStateLaneSeed(helperSeed, state, lane);
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, classWordLocal));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B32L)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStaticIntFragmented(insns, state.state() ^ nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B33L)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(laneSeed, 11));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B34L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(laneSeed, 19));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B35L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private int compactConcatStateMask(
        long helperSeed,
        ControlFlowFlatteningPass.CffInstructionState state,
        int classWord,
        int lane
    ) {
        long laneSeed = compactConcatStateLaneSeed(helperSeed, state, lane);
        int x = (int) state.methodKey() ^ (int) (state.methodKey() >>> 32);
        x += state.pcToken() ^ nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B31L));
        x ^= classWord + nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B32L));
        x += state.state() ^ nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B33L));
        x ^= x >>> shift(laneSeed, 11);
        x *= nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B34L)) | 1;
        x += x >>> shift(laneSeed, 19);
        return x ^ nonZeroInt(JvmPassBytecode.mix(laneSeed, 0x5354434D41534B35L));
    }

    private long compactConcatStateLaneSeed(
        long helperSeed,
        ControlFlowFlatteningPass.CffInstructionState state,
        int lane
    ) {
        return JvmPassBytecode.mix(
            helperSeed ^ state.selectorSeed() ^ (((long) lane) << 48),
            0x5354435354415445L
        );
    }

    private List<ConcatCachePiece> concatHelperCachePieces(
        ConcatPlan concat,
        List<String> externalStrings
    ) {
        Map<String, Integer> externalSlotByValue = new LinkedHashMap<>();
        for (int i = 0; i < externalStrings.size(); i++) {
            externalSlotByValue.put(externalStrings.get(i), i);
        }
        List<ConcatCachePiece> pieces = new ArrayList<>();
        for (ConcatPiece piece : concat.pieces()) {
            if (piece instanceof ArgPiece) {
                pieces.add(new CacheArgPiece());
            } else if (piece instanceof LiteralPiece literal) {
                if (!literal.value().isEmpty()) {
                    pieces.add(new CacheStringPiece(externalSlotByValue.get(literal.value())));
                }
            } else if (piece instanceof ConstPiece constant) {
                Object value = constant.value();
                if (value instanceof String stringValue) {
                    if (!stringValue.isEmpty()) {
                        pieces.add(new CacheStringPiece(externalSlotByValue.get(stringValue)));
                    }
                } else {
                    pieces.add(new CacheConstPiece(value));
                }
            }
        }
        return List.copyOf(pieces);
    }

    private List<Integer> concatExternalStringPattern(List<String> externalStrings) {
        Map<String, Integer> patternByValue = new LinkedHashMap<>();
        List<Integer> pattern = new ArrayList<>(externalStrings.size());
        for (String value : externalStrings) {
            Integer id = patternByValue.get(value);
            if (id == null) {
                id = patternByValue.size();
                patternByValue.put(value, id);
            }
            pattern.add(id);
        }
        return List.copyOf(pattern);
    }

    private String concatHelperDescriptor(Type[] args) {
        return concatHelperDescriptor(args, 0, false);
    }

    @SuppressWarnings("unchecked")
    private String cachedConcatHelper(
        PipelineContext pctx,
        ConcatHelperCacheKey key
    ) {
        Map<ConcatHelperCacheKey, String> helpers =
            pctx.getPassData(STRING_CONCAT_HELPERS);
        if (helpers == null) return null;
        return helpers.get(key);
    }

    @SuppressWarnings("unchecked")
    private void cacheConcatHelper(
        PipelineContext pctx,
        ConcatHelperCacheKey key,
        String helperName
    ) {
        Map<ConcatHelperCacheKey, String> helpers =
            pctx.getPassData(STRING_CONCAT_HELPERS);
        if (helpers == null) {
            helpers = new LinkedHashMap<>();
            pctx.putPassData(STRING_CONCAT_HELPERS, helpers);
        }
        helpers.putIfAbsent(key, helperName);
    }

    private String concatHelperDescriptor(Type[] args, int externalStrings) {
        return concatHelperDescriptor(args, externalStrings, false);
    }

    private String concatHelperDescriptor(Type[] args, int externalStrings, boolean compactState) {
        Type[] helperArgs = new Type[args.length + externalStrings + (compactState ? 2 : 5)];
        System.arraycopy(args, 0, helperArgs, 0, args.length);
        for (int i = 0; i < externalStrings; i++) {
            helperArgs[args.length + i] = Type.getType(String.class);
        }
        int keyOffset = args.length + externalStrings;
        helperArgs[keyOffset] = Type.LONG_TYPE;
        for (int i = 1; i < (compactState ? 2 : 5); i++) {
            helperArgs[keyOffset + i] = Type.INT_TYPE;
        }
        return Type.getMethodDescriptor(Type.getType(String.class), helperArgs);
    }

    private List<String> concatStringConstants(ConcatPlan concat) {
        Map<String, Boolean> values = new LinkedHashMap<>();
        for (ConcatPiece piece : concat.pieces()) {
            if (piece instanceof LiteralPiece literal && !literal.value().isEmpty()) {
                values.putIfAbsent(literal.value(), Boolean.TRUE);
            } else if (piece instanceof ConstPiece constant
                && constant.value() instanceof String value
                && !value.isEmpty()) {
                values.putIfAbsent(value, Boolean.TRUE);
            }
        }
        return new ArrayList<>(values.keySet());
    }

    private void emitLoopCachedString(
        InsnList insns,
        int cacheLocal,
        Runnable decodeEmitter
    ) {
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, cacheLocal));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new JumpInsnNode(Opcodes.IFNONNULL, done));
        insns.add(new InsnNode(Opcodes.POP));
        decodeEmitter.run();
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ASTORE, cacheLocal));
        insns.add(done);
    }

    private boolean generatedHelperUnderSizePressure(MethodNode mn) {
        return JvmCodeSizeEstimator.estimateMethodBytes(mn) >= GENERATED_HELPER_HARDENING_SIZE_PRESSURE;
    }

    private boolean stringConcatCallerUnderSizePressure(MethodNode mn) {
        return JvmCodeSizeEstimator.estimateMethodBytes(mn) >= STRING_CALLER_SIZE_PRESSURE;
    }

    private boolean stringDecodeCallerUnderSizePressure(MethodNode mn) {
        return JvmCodeSizeEstimator.estimateMethodBytes(mn) >= STRING_CALLER_SIZE_PRESSURE;
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
            } else if (node instanceof org.objectweb.asm.tree.LookupSwitchInsnNode lookup) {
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

    private boolean emitDecodedStringLoad(
        InsnList insns,
        Map<String, Integer> decodedStrings,
        String value
    ) {
        if (value.isEmpty()) return false;
        Integer local = decodedStrings.get(value);
        if (local == null || local < 0) {
            throw new IllegalStateException("Missing decoded concat string local");
        }
        insns.add(new VarInsnNode(Opcodes.ALOAD, local));
        return true;
    }

    private Type emitConcatConstant(
        InsnList insns,
        Map<String, Integer> decodedStrings,
        Object value
    ) {
        if (value instanceof String string) {
            return emitDecodedStringLoad(insns, decodedStrings, string)
                ? Type.getType(String.class)
                : null;
        }
        emitConstant(insns, value);
        return valueType(value);
    }

    private void emitConstant(InsnList insns, Object value) {
        if (value instanceof Integer v) {
            JvmPassBytecode.pushInt(insns, v);
        } else if (value instanceof Long v) {
            JvmPassBytecode.pushLong(insns, v);
        } else if (value instanceof Float || value instanceof Double || value instanceof Type || value instanceof Handle) {
            insns.add(new LdcInsnNode(value));
        } else {
            throw new IllegalStateException(
                "Unsupported StringConcatFactory constant type: " +
                    (value == null ? "null" : value.getClass().getName())
            );
        }
    }

    private Type valueType(Object value) {
        if (value instanceof Integer) return Type.INT_TYPE;
        if (value instanceof Long) return Type.LONG_TYPE;
        if (value instanceof Float) return Type.FLOAT_TYPE;
        if (value instanceof Double) return Type.DOUBLE_TYPE;
        return Type.getType(Object.class);
    }

    private boolean isStringConcatWithConstants(InvokeDynamicInsnNode indy) {
        return indy.bsm != null
            && "java/lang/invoke/StringConcatFactory".equals(indy.bsm.getOwner())
            && "makeConcatWithConstants".equals(indy.bsm.getName())
            && indy.bsmArgs.length > 0
            && indy.bsmArgs[0] instanceof String
            && Type.getReturnType(indy.desc).equals(Type.getType(String.class));
    }

    private ConcatPlan concatPlan(InvokeDynamicInsnNode indy) {
        String recipe = (String) indy.bsmArgs[0];
        Object[] constants = new Object[Math.max(0, indy.bsmArgs.length - 1)];
        System.arraycopy(indy.bsmArgs, 1, constants, 0, constants.length);
        List<ConcatPiece> pieces = new ArrayList<>();
        StringBuilder literal = new StringBuilder();
        int argCount = 0;
        int constCount = 0;
        for (int i = 0; i < recipe.length(); i++) {
            char ch = recipe.charAt(i);
            if (ch == '\u0001' || ch == '\u0002') {
                if (!literal.isEmpty()) {
                    pieces.add(new LiteralPiece(literal.toString()));
                    literal.setLength(0);
                }
                if (ch == '\u0001') {
                    pieces.add(new ArgPiece());
                    argCount++;
                } else {
                    if (constCount >= constants.length) {
                        throw new IllegalStateException("Malformed StringConcatFactory recipe constant count");
                    }
                    pieces.add(new ConstPiece(constants[constCount++]));
                }
            } else {
                literal.append(ch);
            }
        }
        if (!literal.isEmpty()) {
            pieces.add(new LiteralPiece(literal.toString()));
        }
        int descriptorArgs = Type.getArgumentTypes(indy.desc).length;
        if (argCount != descriptorArgs || constCount != constants.length) {
            throw new IllegalStateException("Malformed StringConcatFactory recipe argument count");
        }
        return new ConcatPlan(pieces);
    }

    private Algorithm algorithmFor(
        int ordinal,
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        StringSiteMaterial keyMaterial
    ) {
        if ((ordinal & 1) == 0) return Algorithm.AES;
        int root = stringRoot(metadata, state, siteSeed, keyMaterial);
        byte[] key = keyBytes(root, siteSeed, Algorithm.DES, stringStreamFlow(root));
        try {
            return DESKeySpec.isWeak(key, 0) ? Algorithm.AES : Algorithm.DES;
        } catch (InvalidKeyException ex) {
            return Algorithm.AES;
        }
    }

    private ByteLayer byteLayerFor(
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        StringSiteMaterial keyMaterial
    ) {
        int selector = stringKeyMixedWord(
            liveStringWord(metadata, state, byteLayerSeed(siteSeed)),
            siteSeed ^ 0x5354524C41595231L,
            keyMaterial
        ) ^
            (int) (siteSeed >>> 32);
        return switch (selector & 3) {
            case 0 -> ByteLayer.ADD;
            case 1 -> ByteLayer.SUBTRACT;
            case 2 -> ByteLayer.XOR;
            default -> ByteLayer.ADD;
        };
    }

    private byte[] encryptPayload(
        String value,
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        Algorithm algorithm,
        ByteLayer byteLayer,
        StringSiteMaterial keyMaterial
    ) {
        int root = stringRoot(metadata, state, siteSeed, keyMaterial);
        long streamFlow = stringStreamFlow(root);
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        int rawLength = 4 + utf8.length;
        int paddedLength = ((rawLength + algorithm.blockSize - 1) / algorithm.blockSize) * algorithm.blockSize;
        byte[] payload = new byte[paddedLength];
        payload[0] = (byte) (utf8.length >>> 24);
        payload[1] = (byte) (utf8.length >>> 16);
        payload[2] = (byte) (utf8.length >>> 8);
        payload[3] = (byte) utf8.length;
        System.arraycopy(utf8, 0, payload, 4, utf8.length);
        long pad = JvmPassBytecode.mix(siteSeed, 0x5354525041444B31L);
        for (int i = rawLength; i < payload.length; i++) {
            pad = JvmPassBytecode.mix(pad, i);
            payload[i] = (byte) pad;
        }
        byte[] xor = xorBytes(root, siteSeed, payload.length, streamFlow);
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (payload[i] ^ xor[i]);
        }
        applyByteLayer(payload, root, siteSeed, byteLayer, streamFlow);
        try {
            Cipher cipher = Cipher.getInstance(algorithm.transformation);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes(root, siteSeed, algorithm, streamFlow), algorithm.keyName));
            return cipher.doFinal(payload);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to encrypt string literal with " + algorithm.keyName, ex);
        }
    }

    private byte[] keyBytes(
        int root,
        long siteSeed,
        Algorithm algorithm,
        long streamFlow
    ) {
        byte[] out = new byte[algorithm.keySize];
        long seed = keyStreamSeed(siteSeed, algorithm);
        for (int word = 0; word < out.length / 4; word++) {
            int value = streamWord(root, seed, word, streamFlow);
            writeWord(out, word * 4, value);
        }
        return out;
    }

    private byte[] xorBytes(
        int root,
        long siteSeed,
        int length,
        long streamFlow
    ) {
        byte[] out = new byte[length];
        long seed = xorSeed(siteSeed);
        for (int offset = 0; offset < out.length; offset++) {
            int value = streamWord(root, seed, offset >>> 2, streamFlow);
            int shift = (3 - (offset & 3)) << 3;
            out[offset] = (byte) (value >>> shift);
        }
        return out;
    }

    private void applyByteLayer(
        byte[] payload,
        int root,
        long siteSeed,
        ByteLayer byteLayer,
        long streamFlow
    ) {
        long seed = byteLayerSeed(siteSeed);
        for (int offset = 0; offset < payload.length; offset++) {
            int value = streamWord(root, seed, offset >>> 2, streamFlow);
            int shift = (3 - (offset & 3)) << 3;
            int mask = (value >>> shift) & 0xFF;
            int b = payload[offset] & 0xFF;
            payload[offset] = switch (byteLayer) {
                case ADD -> (byte) (b + mask);
                case SUBTRACT -> (byte) (b - mask);
                case XOR -> (byte) (b ^ mask);
            };
        }
    }

    private void writeWord(byte[] out, int offset, int value) {
        out[offset] = (byte) (value >>> 24);
        out[offset + 1] = (byte) (value >>> 16);
        out[offset + 2] = (byte) (value >>> 8);
        out[offset + 3] = (byte) value;
    }

    private void emitDecodedString(
        InsnList insns,
        int encryptedLength,
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        Algorithm algorithm,
        ByteLayer byteLayer,
        StringSiteCache siteCache,
        StringDecodeTail tail,
        int keyTableLocal,
        MethodNode mn,
        boolean compactState
    ) {
        if (!siteCache.hasKeyMaterial()) {
            throw new IllegalStateException("shared string decode tail requires key material table");
        }
        if (keyTableLocal >= 0) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, keyTableLocal));
        } else {
            insns.add(new FieldInsnNode(
                Opcodes.GETSTATIC,
                siteCache.owner(),
                siteCache.keyTableFieldName(),
                "[Ljava/lang/Object;"
            ));
        }
        insns.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        if (compactState) {
            emitStaticIntFragmented(insns, state.pcToken() ^ compactStringPcMask(state, siteCache.keySlot()));
        } else {
            insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
            insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
            insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
            emitCanonicalPcToken(insns, metadata, state, siteSeed);
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.dataLocal()));
        JvmPassBytecode.pushInt(insns, siteCache.keySlot());
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            tail.owner(),
            tail.name(),
            tail.desc(),
            tail.interfaceOwner()
        ));
    }

    private void emitDecodedStringCall(
        PipelineContext pctx,
        L1Class clazz,
        InsnList caller,
        MethodNode mn,
        int encryptedLength,
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        Algorithm algorithm,
        ByteLayer byteLayer,
        StringSiteCache siteCache
    ) {
        emitDecodedStringCall(
            pctx,
            clazz,
            caller,
            mn,
            encryptedLength,
            siteSeed,
            metadata,
            state,
            algorithm,
            byteLayer,
            siteCache,
            -1
        );
    }

    private void emitDecodedStringCall(
        PipelineContext pctx,
        L1Class clazz,
        InsnList caller,
        MethodNode mn,
        int encryptedLength,
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        Algorithm algorithm,
        ByteLayer byteLayer,
        StringSiteCache siteCache,
        int carrierLocal
    ) {
        emitDecodedStringCall(
            pctx,
            clazz,
            caller,
            mn,
            encryptedLength,
            siteSeed,
            metadata,
            state,
            algorithm,
            byteLayer,
            siteCache,
            carrierLocal,
            false
        );
    }

    private void emitDecodedStringCall(
        PipelineContext pctx,
        L1Class clazz,
        InsnList caller,
        MethodNode mn,
        int encryptedLength,
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        Algorithm algorithm,
        ByteLayer byteLayer,
        StringSiteCache siteCache,
        int carrierLocal,
        boolean compactState
    ) {
        if (!siteCache.hasKeyMaterial()) {
            throw new IllegalStateException(
                "stringObfuscation requires dynamic key material table for decode helper in " + clazz.name()
            );
        }
        StringDecodeTail tail = ensureStringDecodeTail(
            pctx,
            clazz,
            compactState
        );
        emitDecodedString(
            caller,
            encryptedLength,
            siteSeed,
            metadata,
            state,
            algorithm,
            byteLayer,
            siteCache,
            tail,
            carrierLocal,
            mn,
            compactState
        );
    }

    @SuppressWarnings("unchecked")
    private StringDecodeTail ensureStringDecodeTail(
        PipelineContext pctx,
        L1Class clazz,
        boolean compactState
    ) {
        Map<String, StringDecodeTail> tails = pctx.getPassData(STRING_DECODE_TAILS);
        if (tails == null) {
            tails = new LinkedHashMap<>();
            pctx.putPassData(STRING_DECODE_TAILS, tails);
        }
        String key = clazz.name() + ":" + compactState;
        StringDecodeTail existing = tails.get(key);
        if (existing != null) {
            return existing;
        }

        boolean interfaceOwner = (clazz.asmNode().access & Opcodes.ACC_INTERFACE) != 0;
        String desc = compactState ? STRING_TAIL_COMPACT_DESC : STRING_TAIL_DESC;
        String name = uniqueMethodName(
            clazz,
            "__neko_strtail$"
        );
        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        MethodNode helper = new MethodNode(
            access,
            name,
            desc,
            null,
            null
        );
        rebuildStringDecodeTail(pctx, clazz.name(), helper, compactState);
        clazz.asmNode().methods.add(helper);
        clazz.markDirty();
        publishGeneratedStringHelperFlowKey(pctx, clazz.name(), name, desc, 1);

        StringDecodeTail tail = new StringDecodeTail(clazz.name(), name, desc, interfaceOwner);
        tails.put(key, tail);
        return tail;
    }

    private void rebuildStringDecodeTail(
        PipelineContext pctx,
        String owner,
        MethodNode helper,
        boolean compactState
    ) {
        helper.instructions.clear();
        helper.maxLocals = 12;
        helper.maxStack = 32;
        emitDecodedStringTail(
            pctx,
            owner,
            helper.instructions,
            helper,
            compactState
        );
        helper.instructions.add(new InsnNode(Opcodes.ARETURN));
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
    }

    private void emitDecodedStringTail(
        PipelineContext pctx,
        String owner,
        InsnList insns,
        MethodNode mn,
        boolean compactState
    ) {
        int carrierLocal = 0;
        int methodKeyLocal = 1;
        int guardLocal = compactState ? 6 : 3;
        int pathKeyLocal = compactState ? 7 : 4;
        int blockKeyLocal = compactState ? 8 : 5;
        int pcLocal = compactState ? 3 : 6;
        int inputDataLocal = compactState ? 4 : 7;
        int keySlotLocal = compactState ? 5 : 8;
        int rawPcLocal = 9;
        int methodFoldLocal = 10;
        int rootLocal = 11;
        int dataWordLocal = 12;
        int payloadSlotLocal = 13;
        int cacheSlotLocal = 14;
        int encryptedLengthLocal = 15;
        int keySeedLocal = 16;
        int byteLayerSeedLocal = 18;
        int xorSeedLocal = 20;
        int siteSeedLocal = 22;
        int encryptedLocal = 24;
        int keyLocal = 25;
        int cipherLocal = 26;
        int plainLocal = 27;
        int wordLocal = 28;
        int lengthLocal = 29;
        int indexLocal = 30;
        int stringLocal = 31;
        int throwableLocal = 32;
        int keyCellLocal = 33;
        int oldEpochLocal = 34;
        int nextEpochLocal = 35;
        int fingerprintLocal = 36;
        int selectorLocal = 38;
        int streamFlowLocal = 39;
        int keyTableLocal = 41;
        int slotSelectorLocal = 42;
        int classWordsSelectorLocal = 43;
        int keyCellDescriptorLocal = 44;
        mn.maxLocals = Math.max(mn.maxLocals, 45);
        LabelNode monitorStart = new LabelNode();
        LabelNode monitorEnd = new LabelNode();
        LabelNode monitorHandler = new LabelNode();
        LabelNode afterMonitor = new LabelNode();

        if (compactState) {
            emitRuntimeCompactStringPcDecode(insns, methodKeyLocal, pcLocal, keySlotLocal);
            emitRuntimeCompactStringInitialMaterialSlotSelection(
                insns,
                carrierLocal,
                methodKeyLocal,
                pcLocal,
                inputDataLocal,
                keySlotLocal
            );
        } else {
            emitRuntimeMethodKeyFold(insns, guardLocal, pathKeyLocal, blockKeyLocal, methodKeyLocal, methodFoldLocal);
            emitRuntimeStringInitialMaterialSlotSelection(
                insns,
                carrierLocal,
                methodKeyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                inputDataLocal,
                keySlotLocal
            );
        }
        insns.add(new VarInsnNode(Opcodes.ISTORE, slotSelectorLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotSelectorLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, keyTableLocal));

        emitRuntimeStringKeyCellLoad(insns, keyTableLocal, keySlotLocal);
        insns.add(new VarInsnNode(Opcodes.ASTORE, keyCellLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyCellLocal));
        insns.add(new InsnNode(Opcodes.MONITORENTER));
        insns.add(monitorStart);
        emitRuntimeStringCellDescriptorLoad(insns, keyCellLocal, keyCellDescriptorLocal);
        emitRuntimeStringCellValueLoad(
            insns,
            keyCellLocal,
            keyCellDescriptorLocal,
            4
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, oldEpochLocal));
        emitRuntimeStringSiteSeedLoad(
            insns,
            keyCellLocal,
            keyCellDescriptorLocal,
            oldEpochLocal,
            siteSeedLocal
        );
        emitRuntimeStringSiteMetadataLoad(
            insns,
            keyCellLocal,
            keyCellDescriptorLocal,
            oldEpochLocal,
            siteSeedLocal,
            STRING_KEY_CELL_RAW_PC,
            STRING_KEY_CELL_RAW_PC_MASK,
            rawPcLocal
        );
        if (compactState) {
            emitRuntimeCompactStringStateLoad(
                insns,
                keyCellLocal,
                keyCellDescriptorLocal,
                oldEpochLocal,
                siteSeedLocal,
                methodKeyLocal,
                pcLocal,
                keySlotLocal,
                STRING_KEY_CELL_GUARD,
                STRING_KEY_CELL_GUARD_MASK,
                0,
                guardLocal
            );
            emitRuntimeCompactStringStateLoad(
                insns,
                keyCellLocal,
                keyCellDescriptorLocal,
                oldEpochLocal,
                siteSeedLocal,
                methodKeyLocal,
                pcLocal,
                keySlotLocal,
                STRING_KEY_CELL_PATH,
                STRING_KEY_CELL_PATH_MASK,
                1,
                pathKeyLocal
            );
            emitRuntimeCompactStringStateLoad(
                insns,
                keyCellLocal,
                keyCellDescriptorLocal,
                oldEpochLocal,
                siteSeedLocal,
                methodKeyLocal,
                pcLocal,
                keySlotLocal,
                STRING_KEY_CELL_BLOCK,
                STRING_KEY_CELL_BLOCK_MASK,
                2,
                blockKeyLocal
            );
            emitRuntimeMethodKeyFold(insns, guardLocal, pathKeyLocal, blockKeyLocal, methodKeyLocal, methodFoldLocal);
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, rawPcLocal));
        emitRuntimeStringRawPcArgumentMask(
            insns,
            siteSeedLocal,
            methodKeyLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, rawPcLocal));
        emitRuntimeRootSeed(insns, siteSeedLocal, keySeedLocal);
        emitRuntimeStringDataWord(
            insns,
            inputDataLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            methodKeyLocal,
            keySeedLocal,
            dataWordLocal
        );
        emitRuntimeLiveStringWordPrefix(
            insns,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            rawPcLocal,
            methodFoldLocal,
            keySeedLocal,
            rootLocal
        );
        emitRuntimeStringClassKeyWordsSelector(
            insns,
            guardLocal,
            pathKeyLocal,
            classWordsSelectorLocal
        );
        emitRuntimeStringMaterialSlotSelection(
            insns,
            carrierLocal,
            rootLocal,
            methodKeyLocal,
            keySlotLocal,
            dataWordLocal
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, slotSelectorLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, slotSelectorLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, keyTableLocal));
        emitRuntimeStringTailSelectorLoad(
            insns,
            keyCellLocal,
            keyCellDescriptorLocal,
            oldEpochLocal,
            selectorLocal,
            siteSeedLocal,
            dataWordLocal
        );
        emitRuntimeStringSiteMetadataLoad(
            insns,
            keyCellLocal,
            keyCellDescriptorLocal,
            oldEpochLocal,
            siteSeedLocal,
            STRING_KEY_CELL_PAYLOAD_SLOT,
            STRING_KEY_CELL_PAYLOAD_MASK,
            payloadSlotLocal
        );
        emitRuntimeStringSiteMetadataLoad(
            insns,
            keyCellLocal,
            keyCellDescriptorLocal,
            oldEpochLocal,
            siteSeedLocal,
            STRING_KEY_CELL_CACHE_SLOT,
            STRING_KEY_CELL_CACHE_MASK,
            cacheSlotLocal
        );
        emitRuntimeStringSiteMetadataLoad(
            insns,
            keyCellLocal,
            keyCellDescriptorLocal,
            oldEpochLocal,
            siteSeedLocal,
            STRING_KEY_CELL_LENGTH,
            STRING_KEY_CELL_LENGTH_MASK,
            encryptedLengthLocal
        );
        emitRuntimeLiveStringWordTail(
            insns,
            carrierLocal,
            rootLocal,
            rawPcLocal,
            blockKeyLocal,
            classWordsSelectorLocal,
            dataWordLocal,
            siteSeedLocal,
            keySeedLocal,
            wordLocal
        );
        emitRuntimeStringKeyMixedWord(
            insns,
            rootLocal,
            keyCellLocal,
            keyCellDescriptorLocal,
            oldEpochLocal,
            siteSeedLocal
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, rootLocal));
        emitRuntimeStringStreamFlow(insns, rootLocal);
        insns.add(new VarInsnNode(Opcodes.LSTORE, streamFlowLocal));
        emitRuntimeStringKeyCellUpdate(
            insns,
            keyCellLocal,
            keyCellDescriptorLocal,
            rootLocal,
            nextEpochLocal,
            oldEpochLocal,
            siteSeedLocal,
            selectorLocal,
            dataWordLocal,
            wordLocal
        );
        emitRuntimeFingerprint(insns, rootLocal, streamFlowLocal, siteSeedLocal, keySeedLocal, dataWordLocal);
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, fingerprintLocal));
        emitRuntimeDerivedSeed(insns, siteSeedLocal, 0x5354524C41595231L, 0x425954454C415952L, byteLayerSeedLocal);
        emitRuntimeDerivedSeed(insns, siteSeedLocal, 0x535452584F524B31L, 0x425954455354524DL, xorSeedLocal);

        LabelNode cacheMiss = new LabelNode();
        LabelNode done = new LabelNode();
        emitRuntimeStringCacheTableLoad(insns, keyTableLocal);
        emitStringCacheIndex(insns, cacheSlotLocal, false);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, stringLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
        insns.add(new JumpInsnNode(Opcodes.IFNULL, cacheMiss));
        emitRuntimeStringCacheTableLoad(insns, keyTableLocal);
        emitStringCacheIndex(insns, cacheSlotLocal, true);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Long",
            "longValue",
            "()J",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.LLOAD, fingerprintLocal));
        insns.add(new InsnNode(Opcodes.LCMP));
        insns.add(new JumpInsnNode(Opcodes.IFNE, cacheMiss));
        insns.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));

        insns.add(cacheMiss);
        emitRuntimeStringPayloadTableLoad(insns, keyTableLocal);
        insns.add(new VarInsnNode(Opcodes.ILOAD, payloadSlotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[B"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, encryptedLocal));
        emitAlgorithmCipherDecrypt(
            insns,
            keyTableLocal,
            selectorLocal,
            encryptedLocal,
            keyLocal,
            cipherLocal,
            plainLocal,
            throwableLocal,
            wordLocal,
            rootLocal,
            streamFlowLocal,
            indexLocal,
            siteSeedLocal,
            dataWordLocal,
            keySeedLocal,
            mn
        );
        emitByteLayerDecode(
            insns,
            selectorLocal,
            plainLocal,
            wordLocal,
            rootLocal,
            streamFlowLocal,
            indexLocal,
            encryptedLengthLocal,
            siteSeedLocal,
            dataWordLocal,
            byteLayerSeedLocal
        );
        emitXorPlaintext(insns, plainLocal, wordLocal, rootLocal, streamFlowLocal, indexLocal, encryptedLengthLocal, xorSeedLocal);
        emitStringLength(insns, plainLocal);
        insns.add(new VarInsnNode(Opcodes.ISTORE, lengthLocal));
        insns.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        JvmPassBytecode.pushInt(insns, 4);
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            "java/nio/charset/StandardCharsets",
            "UTF_8",
            "Ljava/nio/charset/Charset;"
        ));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESPECIAL,
            "java/lang/String",
            "<init>",
            "([BIILjava/nio/charset/Charset;)V",
            false
        ));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "intern",
            "()Ljava/lang/String;",
            false
        ));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ASTORE, stringLocal));
        emitRuntimeStringCacheTableLoad(insns, keyTableLocal);
        emitStringCacheIndex(insns, cacheSlotLocal, true);
        insns.add(new VarInsnNode(Opcodes.LLOAD, fingerprintLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/Long",
            "valueOf",
            "(J)Ljava/lang/Long;",
            false
        ));
        insns.add(new InsnNode(Opcodes.AASTORE));
        emitRuntimeStringCacheTableLoad(insns, keyTableLocal);
        emitStringCacheIndex(insns, cacheSlotLocal, false);
        insns.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(done);
        insns.add(monitorEnd);
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyCellLocal));
        insns.add(new InsnNode(Opcodes.MONITOREXIT));
        insns.add(new JumpInsnNode(Opcodes.GOTO, afterMonitor));
        insns.add(monitorHandler);
        insns.add(new VarInsnNode(Opcodes.ASTORE, throwableLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyCellLocal));
        insns.add(new InsnNode(Opcodes.MONITOREXIT));
        insns.add(new VarInsnNode(Opcodes.ALOAD, throwableLocal));
        insns.add(new InsnNode(Opcodes.ATHROW));
        insns.add(afterMonitor);
        mn.tryCatchBlocks.add(new TryCatchBlockNode(monitorStart, monitorEnd, monitorHandler, null));
    }

    private void emitStringCacheIndex(InsnList insns, int cacheSlotLocal, boolean fingerprint) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, cacheSlotLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.IMUL));
        if (fingerprint) {
            JvmPassBytecode.pushInt(insns, 1);
            insns.add(new InsnNode(Opcodes.IADD));
        }
    }

    private void emitRuntimeStringInitialMaterialSlotSelection(
        InsnList insns,
        int carrierLocal,
        int methodKeyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int dataLocal,
        int keySlotLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.STRING_MATERIAL_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
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
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, keySlotLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
    }

    private void emitRuntimeCompactStringPcDecode(
        InsnList insns,
        int methodKeyLocal,
        int pcLocal,
        int keySlotLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        emitRuntimeCompactStringPcMask(insns, methodKeyLocal, keySlotLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
    }

    private void emitRuntimeCompactStringPcMask(
        InsnList insns,
        int methodKeyLocal,
        int keySlotLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, keySlotLocal));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(0x5354524350434D31L, 0x4B4559534C4F5431L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 11);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(0x5354524350434D32L, 0x4B4559534C4F5432L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        emitStaticIntFragmented(insns, nonZeroInt(JvmPassBytecode.mix(0x5354524350434D33L, 0x4B4559534C4F5433L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private int compactStringPcMask(
        ControlFlowFlatteningPass.CffInstructionState state,
        int keySlot
    ) {
        int x = (int) state.methodKey() ^ (int) (state.methodKey() >>> 32);
        x += keySlot ^ nonZeroInt(JvmPassBytecode.mix(0x5354524350434D31L, 0x4B4559534C4F5431L));
        x ^= x >>> 11;
        x *= nonZeroInt(JvmPassBytecode.mix(0x5354524350434D32L, 0x4B4559534C4F5432L)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(0x5354524350434D33L, 0x4B4559534C4F5433L));
    }

    private void emitRuntimeCompactStringInitialMaterialSlotSelection(
        InsnList insns,
        int carrierLocal,
        int methodKeyLocal,
        int pcLocal,
        int dataLocal,
        int keySlotLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.STRING_MATERIAL_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, keySlotLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
    }

    private void emitRuntimeCompactStringStateLoad(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int epochLocal,
        int siteSeedLocal,
        int methodKeyLocal,
        int pcLocal,
        int keySlotLocal,
        int logicalIndex,
        long metadataMask,
        int lane,
        int outLocal
    ) {
        emitRuntimeStringSiteMetadataLoad(
            insns,
            keyCellLocal,
            descriptorLocal,
            epochLocal,
            siteSeedLocal,
            logicalIndex,
            metadataMask,
            outLocal
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, outLocal));
        emitRuntimeCompactStringStateMask(insns, siteSeedLocal, methodKeyLocal, pcLocal, keySlotLocal, lane);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));
    }

    private void emitRuntimeCompactStringStateMask(
        InsnList insns,
        int siteSeedLocal,
        int methodKeyLocal,
        int pcLocal,
        int keySlotLocal,
        int lane
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354435354413131L + lane);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, keySlotLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354435354413231L + lane);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 13 + lane);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354435354413331L + lane);
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354435354413431L + lane);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private int compactStringStateMask(
        long siteSeed,
        ControlFlowFlatteningPass.CffInstructionState state,
        int keySlot,
        int lane
    ) {
        int x = (int) state.methodKey() ^ (int) (state.methodKey() >>> 32);
        x += state.pcToken() ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354435354413131L + lane));
        x ^= keySlot + nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354435354413231L + lane));
        x ^= x >>> (13 + lane);
        x *= nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354435354413331L + lane)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354435354413431L + lane));
    }

    private void emitRuntimeStringMaterialSlotSelection(
        InsnList insns,
        int carrierLocal,
        int rootLocal,
        int flowLocal,
        int keySlotLocal,
        int dataWordLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.STRING_MATERIAL_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, keySlotLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
    }

    private void emitRuntimeRootSeed(InsnList insns, int siteSeedLocal, int outLocal) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        JvmPassBytecode.pushLong(insns, 0x535452524F4F5431L);
        emitRuntimeMixLong(insns);
        insns.add(new VarInsnNode(Opcodes.LSTORE, outLocal));
    }

    private void emitRuntimeStringDataWord(
        InsnList insns,
        int inputDataLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int methodKeyLocal,
        int rootSeedLocal,
        int outLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, inputDataLocal));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x5354444154413031L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, rootSeedLocal, 7);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x5354444154413032L);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x5354444154413033L);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, rootSeedLocal, 19);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x5354444154413034L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));
    }

    private void emitRuntimeLiveStringWordPrefix(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int methodFoldLocal,
        int rootSeedLocal,
        int outLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x5354475541524431L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, rootSeedLocal, 5);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x5354424C4F434B31L);
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x53544D554C544B31L);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, methodFoldLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x53545043544F4B31L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));
    }

    private void emitRuntimeMethodKeyFold(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int methodKeyLocal,
        int outLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));
    }

    private void emitRuntimeStringClassKeyWordsSelector(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int outLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, outLocal));
    }

    private void emitRuntimeLiveStringWordTail(
        InsnList insns,
        int carrierLocal,
        int rootLocal,
        int pcLocal,
        int blockKeyLocal,
        int classWordsSelectorLocal,
        int dataWordLocal,
        int siteSeedLocal,
        int rootSeedLocal,
        int wordLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        JvmPassBytecode.pushLong(insns, 0x535452524F4F5431L);
        emitRuntimeMixLong(insns);
        insns.add(new VarInsnNode(Opcodes.LSTORE, rootSeedLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x535454414249584CL);
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, STRING_CLASS_KEY_TABLE_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));

        insns.add(new VarInsnNode(Opcodes.ALOAD, carrierLocal));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, classWordsSelectorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
        ControlFlowFlatteningPass.emitDecodedSealedClassKeyWord(
            insns,
            ControlFlowFlatteningPass.CLASS_KEY_WORD_SEAL
        );
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x535454414256414CL);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, rootSeedLocal, 23);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        emitRuntimeMixToNonZeroInt(insns, rootSeedLocal, 0x535446494E414C31L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, rootLocal));
    }

    private void emitAlgorithmCipherDecrypt(
        InsnList insns,
        int keyTableLocal,
        int selectorLocal,
        int encryptedLocal,
        int keyLocal,
        int cipherLocal,
        int plainLocal,
        int throwableLocal,
        int wordLocal,
        int rootLocal,
        int flowLocal,
        int indexLocal,
        int siteSeedLocal,
        int dataWordLocal,
        int keySeedLocal,
        MethodNode mn
    ) {
        LabelNode des = new LabelNode();
        LabelNode done = new LabelNode();
        emitRuntimeBoundSelectorEquals(
            insns,
            selectorLocal,
            siteSeedLocal,
            dataWordLocal,
            3,
            1,
            Algorithm.DES.ordinal(),
            0x535452414C474231L,
            des
        );
        emitRuntimeDerivedSeed(insns, siteSeedLocal, 0x5354524B45594C31L, Algorithm.AES.keySize, keySeedLocal);
        JvmPassBytecode.pushInt(insns, Algorithm.AES.keySize);
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        insns.add(new VarInsnNode(Opcodes.ASTORE, keyLocal));
        emitFillKey(
            insns,
            Algorithm.AES,
            selectorLocal,
            keyLocal,
            wordLocal,
            rootLocal,
            flowLocal,
            indexLocal,
            siteSeedLocal,
            dataWordLocal,
            keySeedLocal
        );
        emitCipherDecryptTail(insns, Algorithm.AES, keyTableLocal, encryptedLocal, keyLocal, cipherLocal, plainLocal, throwableLocal, mn);
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(des);
        emitRuntimeDerivedSeed(insns, siteSeedLocal, 0x5354524B45594C31L, Algorithm.DES.keySize, keySeedLocal);
        JvmPassBytecode.pushInt(insns, Algorithm.DES.keySize);
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        insns.add(new VarInsnNode(Opcodes.ASTORE, keyLocal));
        emitFillKey(
            insns,
            Algorithm.DES,
            selectorLocal,
            keyLocal,
            wordLocal,
            rootLocal,
            flowLocal,
            indexLocal,
            siteSeedLocal,
            dataWordLocal,
            keySeedLocal
        );
        emitCipherDecryptTail(insns, Algorithm.DES, keyTableLocal, encryptedLocal, keyLocal, cipherLocal, plainLocal, throwableLocal, mn);
        insns.add(done);
    }

    private void emitFillKey(
        InsnList insns,
        Algorithm algorithm,
        int selectorLocal,
        int keyLocal,
        int wordLocal,
        int rootLocal,
        int flowLocal,
        int indexLocal,
        int siteSeedLocal,
        int dataWordLocal,
        int keySeedLocal
    ) {
        LabelNode reverse = new LabelNode();
        LabelNode done = new LabelNode();
        emitRuntimeBoundSelectorEquals(
            insns,
            selectorLocal,
            siteSeedLocal,
            dataWordLocal,
            0,
            1,
            1,
            0x5354524B4F524431L,
            reverse
        );
        emitFillKeyLoop(insns, algorithm, false, keyLocal, wordLocal, rootLocal, flowLocal, indexLocal, keySeedLocal);
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(reverse);
        emitFillKeyLoop(insns, algorithm, true, keyLocal, wordLocal, rootLocal, flowLocal, indexLocal, keySeedLocal);
        insns.add(done);
    }

    private void emitFillKeyLoop(
        InsnList insns,
        Algorithm algorithm,
        boolean reverseBytes,
        int keyLocal,
        int wordLocal,
        int rootLocal,
        int flowLocal,
        int indexLocal,
        int keySeedLocal
    ) {
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, algorithm.keySize / 4);
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        emitRuntimeStreamWord(insns, rootLocal, indexLocal, keySeedLocal, flowLocal);
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));
        for (int step = 0; step < 4; step++) {
            int b = reverseBytes ? 3 - step : step;
            insns.add(new VarInsnNode(Opcodes.ALOAD, keyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
            JvmPassBytecode.pushInt(insns, 4);
            insns.add(new InsnNode(Opcodes.IMUL));
            JvmPassBytecode.pushInt(insns, b);
            insns.add(new InsnNode(Opcodes.IADD));
            insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
            JvmPassBytecode.pushInt(insns, 24 - b * 8);
            insns.add(new InsnNode(Opcodes.IUSHR));
            insns.add(new InsnNode(Opcodes.BASTORE));
        }
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
    }

    private void emitCipherDecryptTail(
        InsnList insns,
        Algorithm algorithm,
        int keyTableLocal,
        int encryptedLocal,
        int keyLocal,
        int cipherLocal,
        int plainLocal,
        int throwableLocal,
        MethodNode mn
    ) {
        LabelNode protectedStart = new LabelNode();
        LabelNode protectedEnd = new LabelNode();
        LabelNode handler = new LabelNode();
        LabelNode done = new LabelNode();

        emitRuntimeStringCipherLoad(insns, keyTableLocal, algorithm);
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ASTORE, cipherLocal));
        insns.add(new InsnNode(Opcodes.MONITORENTER));
        insns.add(protectedStart);
        insns.add(new VarInsnNode(Opcodes.ALOAD, cipherLocal));
        JvmPassBytecode.pushInt(insns, Cipher.DECRYPT_MODE);
        insns.add(new TypeInsnNode(Opcodes.NEW, "javax/crypto/spec/SecretKeySpec"));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyLocal));
        emitStaticString(
            insns,
            algorithm.keyName,
            JvmPassBytecode.mix(0x535452544B455931L, algorithm.ordinal())
        );
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESPECIAL,
            "javax/crypto/spec/SecretKeySpec",
            "<init>",
            "([BLjava/lang/String;)V",
            false
        ));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "javax/crypto/Cipher",
            "init",
            "(ILjava/security/Key;)V",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cipherLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, encryptedLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "javax/crypto/Cipher",
            "doFinal",
            "([B)[B",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ASTORE, plainLocal));
        insns.add(protectedEnd);
        insns.add(new VarInsnNode(Opcodes.ALOAD, cipherLocal));
        insns.add(new InsnNode(Opcodes.MONITOREXIT));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(handler);
        insns.add(new VarInsnNode(Opcodes.ASTORE, throwableLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cipherLocal));
        insns.add(new InsnNode(Opcodes.MONITOREXIT));
        insns.add(new VarInsnNode(Opcodes.ALOAD, throwableLocal));
        insns.add(new InsnNode(Opcodes.ATHROW));
        insns.add(done);
        mn.tryCatchBlocks.add(new TryCatchBlockNode(protectedStart, protectedEnd, handler, null));
    }

    private void emitByteLayerDecode(
        InsnList insns,
        int selectorLocal,
        int plainLocal,
        int wordLocal,
        int rootLocal,
        int flowLocal,
        int indexLocal,
        int encryptedLengthLocal,
        int siteSeedLocal,
        int dataWordLocal,
        int byteLayerSeedLocal
    ) {
        LabelNode subtract = new LabelNode();
        LabelNode xor = new LabelNode();
        LabelNode done = new LabelNode();
        emitRuntimeBoundSelectorEquals(
            insns,
            selectorLocal,
            siteSeedLocal,
            dataWordLocal,
            1,
            3,
            ByteLayer.SUBTRACT.ordinal(),
            0x535452424C595231L,
            subtract
        );
        emitRuntimeBoundSelectorEquals(
            insns,
            selectorLocal,
            siteSeedLocal,
            dataWordLocal,
            1,
            3,
            ByteLayer.XOR.ordinal(),
            0x535452424C595232L,
            xor
        );
        emitByteLayerDecodeLoop(insns, ByteLayer.ADD, plainLocal, wordLocal, rootLocal, flowLocal, indexLocal, encryptedLengthLocal, byteLayerSeedLocal);
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(subtract);
        emitByteLayerDecodeLoop(insns, ByteLayer.SUBTRACT, plainLocal, wordLocal, rootLocal, flowLocal, indexLocal, encryptedLengthLocal, byteLayerSeedLocal);
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(xor);
        emitByteLayerDecodeLoop(insns, ByteLayer.XOR, plainLocal, wordLocal, rootLocal, flowLocal, indexLocal, encryptedLengthLocal, byteLayerSeedLocal);
        insns.add(done);
    }

    private void emitByteLayerDecodeLoop(
        InsnList insns,
        ByteLayer byteLayer,
        int plainLocal,
        int wordLocal,
        int rootLocal,
        int flowLocal,
        int indexLocal,
        int encryptedLengthLocal,
        int byteLayerSeedLocal
    ) {
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, encryptedLengthLocal));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.BALOAD));
        emitRuntimeStreamWord(insns, rootLocal, wordLocal, byteLayerSeedLocal, flowLocal);
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.ISUB));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IUSHR));
        switch (byteLayer) {
            case ADD -> insns.add(new InsnNode(Opcodes.ISUB));
            case SUBTRACT -> insns.add(new InsnNode(Opcodes.IADD));
            case XOR -> insns.add(new InsnNode(Opcodes.IXOR));
        }
        insns.add(new InsnNode(Opcodes.BASTORE));
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
    }

    private void emitXorPlaintext(
        InsnList insns,
        int plainLocal,
        int wordLocal,
        int rootLocal,
        int flowLocal,
        int indexLocal,
        int encryptedLengthLocal,
        int xorSeedLocal
    ) {
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, encryptedLengthLocal));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.BALOAD));
        emitRuntimeStreamWord(insns, rootLocal, wordLocal, xorSeedLocal, flowLocal);
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.ISUB));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.BASTORE));
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
    }

    private void emitRuntimeStringPayloadTableLoad(InsnList insns, int keyTableLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyTableLocal));
        JvmPassBytecode.pushInt(insns, STRING_PAYLOAD_TABLE_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
    }

    private void emitRuntimeStringCacheTableLoad(InsnList insns, int keyTableLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyTableLocal));
        JvmPassBytecode.pushInt(insns, STRING_CACHE_TABLE_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
    }

    private void emitRuntimeStringCipherLoad(InsnList insns, int keyTableLocal, Algorithm algorithm) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyTableLocal));
        JvmPassBytecode.pushInt(insns, stringCipherSlot(algorithm));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "javax/crypto/Cipher"));
    }

    private int stringCipherSlot(Algorithm algorithm) {
        return switch (algorithm) {
            case AES -> STRING_AES_CIPHER_SLOT;
            case DES -> STRING_DES_CIPHER_SLOT;
        };
    }

    private void emitRuntimeStringKeyCellLoad(InsnList insns, int keyTableLocal, int keySlotLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyTableLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, keySlotLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
    }

    private void emitRuntimeStringCellDescriptorLoad(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyCellLocal));
        JvmPassBytecode.pushInt(insns, STRING_KEY_CELL_DESCRIPTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        emitRuntimeNumberIntValue(insns);
        insns.add(new VarInsnNode(Opcodes.ISTORE, descriptorLocal));
    }

    private void emitRuntimeStringCellValueLoad(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int logicalIndex
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyCellLocal));
        emitRuntimeStringCellPackPhysicalIndex(insns, descriptorLocal, logicalIndex);
        insns.add(new InsnNode(Opcodes.AALOAD));
        emitRuntimeNumberLongValue(insns);
        if ((logicalIndex & 1) != 0) {
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LUSHR));
        }
        insns.add(new InsnNode(Opcodes.L2I));
    }

    private void emitRuntimeStringCellValueStore(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int logicalIndex,
        int valueLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyCellLocal));
        emitRuntimeStringCellPackPhysicalIndex(insns, descriptorLocal, logicalIndex);
        insns.add(new VarInsnNode(Opcodes.ALOAD, keyCellLocal));
        emitRuntimeStringCellPackPhysicalIndex(insns, descriptorLocal, logicalIndex);
        insns.add(new InsnNode(Opcodes.AALOAD));
        emitRuntimeNumberLongValue(insns);
        if ((logicalIndex & 1) == 0) {
            JvmPassBytecode.pushLong(insns, 0xFFFFFFFF00000000L);
            insns.add(new InsnNode(Opcodes.LAND));
            insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
            insns.add(new InsnNode(Opcodes.I2L));
            JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
            insns.add(new InsnNode(Opcodes.LAND));
        } else {
            JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
            insns.add(new InsnNode(Opcodes.LAND));
            insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
            insns.add(new InsnNode(Opcodes.I2L));
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LSHL));
        }
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/Long",
            "valueOf",
            "(J)Ljava/lang/Long;",
            false
        ));
        insns.add(new InsnNode(Opcodes.AASTORE));
    }

    private void emitRuntimeStringCellPackPhysicalIndex(
        InsnList insns,
        int descriptorLocal,
        int logicalIndex
    ) {
        JvmPassBytecode.pushInt(insns, logicalIndex >>> 1);
        insns.add(new VarInsnNode(Opcodes.ILOAD, descriptorLocal));
        JvmPassBytecode.pushInt(insns, STRING_KEY_CELL_PHYSICAL_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, descriptorLocal));
        JvmPassBytecode.pushInt(insns, STRING_KEY_CELL_OFFSET_SHIFT);
        insns.add(new InsnNode(Opcodes.IUSHR));
        JvmPassBytecode.pushInt(insns, STRING_KEY_CELL_PHYSICAL_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, STRING_KEY_CELL_PHYSICAL_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IADD));
    }

    private void emitRuntimeNumberLongValue(InsnList insns) {
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Number",
            "longValue",
            "()J",
            false
        ));
    }

    private void emitRuntimeNumberIntValue(InsnList insns) {
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Number",
            "intValue",
            "()I",
            false
        ));
    }

    private void emitRuntimeStringSiteSeedLoad(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int epochLocal,
        int siteSeedLocal
    ) {
        emitRuntimeStringCellValueLoad(insns, keyCellLocal, descriptorLocal, 5);
        emitRuntimeStringSiteTokenCellMask(insns, descriptorLocal, epochLocal, 0);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        emitRuntimeStringCellValueLoad(insns, keyCellLocal, descriptorLocal, 6);
        emitRuntimeStringSiteTokenCellMask(insns, descriptorLocal, epochLocal, 1);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, siteSeedLocal));
    }

    private void emitRuntimeStringTailSelectorLoad(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int epochLocal,
        int selectorLocal,
        int siteSeedLocal,
        int dataWordLocal
    ) {
        emitRuntimeStringCellValueLoad(insns, keyCellLocal, descriptorLocal, 7);
        emitRuntimeStringTailSelectorCellMask(insns, descriptorLocal, epochLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, selectorLocal));
    }

    private void emitRuntimeBoundSelectorEquals(
        InsnList insns,
        int selectorLocal,
        int siteSeedLocal,
        int dataWordLocal,
        int shift,
        int mask,
        int expected,
        long seed,
        LabelNode target
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorLocal));
        if (shift != 0) {
            JvmPassBytecode.pushInt(insns, shift);
            insns.add(new InsnNode(Opcodes.IUSHR));
        }
        JvmPassBytecode.pushInt(insns, mask);
        insns.add(new InsnNode(Opcodes.IAND));
        JvmPassBytecode.pushInt(insns, expected);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, seed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, (int) seed);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, seed ^ 0x53454C4252414E31L);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, (int) (seed >>> 32));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, target));
    }

    private void emitRuntimeDecodeStringRootTransport(
        InsnList insns,
        int rootLocal,
        int dataWordLocal,
        int multiplierLocal,
        int inverseLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        emitStringRootTransportMultiplierFromTop(insns);
        insns.add(new VarInsnNode(Opcodes.ISTORE, multiplierLocal));
        emitOddIntInverse(insns, multiplierLocal, inverseLocal);
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, rootLocal));
    }

    private void emitRuntimeStringKeyMixedWord(
        InsnList insns,
        int liveWordLocal,
        int keyCellLocal,
        int descriptorLocal,
        int epochLocal,
        int siteSeedLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, liveWordLocal));
        emitRuntimeDecodedStringKeyWord(insns, keyCellLocal, descriptorLocal, epochLocal, siteSeedLocal, 0);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, liveWordLocal));
        emitRuntimeShift(insns, siteSeedLocal, 7);
        insns.add(new InsnNode(Opcodes.ISHL));
        emitRuntimeDecodedStringKeyWord(insns, keyCellLocal, descriptorLocal, epochLocal, siteSeedLocal, 1);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, 17);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeDecodedStringKeyWord(insns, keyCellLocal, descriptorLocal, epochLocal, siteSeedLocal, 2);
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, liveWordLocal));
        emitRuntimeShift(insns, siteSeedLocal, 29);
        insns.add(new InsnNode(Opcodes.IUSHR));
        emitRuntimeDecodedStringKeyWord(insns, keyCellLocal, descriptorLocal, epochLocal, siteSeedLocal, 3);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, 5);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeDecodedStringKeyWord(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int epochLocal,
        int siteSeedLocal,
        int wordIndex
    ) {
        emitRuntimeStringCellValueLoad(insns, keyCellLocal, descriptorLocal, wordIndex);
        emitRuntimeStringKeyCellMask(insns, siteSeedLocal, wordIndex, epochLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeStringRawPcArgumentMask(
        InsnList insns,
        int siteSeedLocal,
        int methodKeyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354504347554131L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354504350415431L);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x53545043424C4B31L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, 13);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x535450434D554C31L);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, 21);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354504346494E31L);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeStringKeyCellUpdate(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int rootLocal,
        int nextEpochLocal,
        int oldEpochLocal,
        int siteSeedLocal,
        int selectorLocal,
        int dataWordLocal,
        int valueLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, oldEpochLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354524B55504431L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, 19);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354524B55504432L);
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354524B55504433L);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, nextEpochLocal));
        for (int i = 0; i < 4; i++) {
            emitRuntimeStringCellValueLoad(insns, keyCellLocal, descriptorLocal, i);
            emitRuntimeStringKeyCellMask(insns, siteSeedLocal, i, oldEpochLocal);
            insns.add(new InsnNode(Opcodes.IXOR));
            emitRuntimeStringKeyCellMask(insns, siteSeedLocal, i, nextEpochLocal);
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
            emitRuntimeStringCellValueStore(insns, keyCellLocal, descriptorLocal, i, valueLocal);
        }
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        emitRuntimeStringSiteTokenCellMask(insns, descriptorLocal, nextEpochLocal, 0);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        emitRuntimeStringCellValueStore(insns, keyCellLocal, descriptorLocal, 5, valueLocal);
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        emitRuntimeStringSiteTokenCellMask(insns, descriptorLocal, nextEpochLocal, 1);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        emitRuntimeStringCellValueStore(insns, keyCellLocal, descriptorLocal, 6, valueLocal);
        insns.add(new VarInsnNode(Opcodes.ILOAD, selectorLocal));
        emitRuntimeStringTailSelectorCellMask(insns, descriptorLocal, nextEpochLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        emitRuntimeStringCellValueStore(insns, keyCellLocal, descriptorLocal, 7, valueLocal);
        emitRuntimeStringCellValueStore(insns, keyCellLocal, descriptorLocal, 4, nextEpochLocal);
        emitRuntimeStringSiteMetadataCellUpdate(
            insns,
            keyCellLocal,
            descriptorLocal,
            siteSeedLocal,
            oldEpochLocal,
            nextEpochLocal,
            STRING_KEY_CELL_PAYLOAD_SLOT,
            STRING_KEY_CELL_PAYLOAD_MASK,
            valueLocal
        );
        emitRuntimeStringSiteMetadataCellUpdate(
            insns,
            keyCellLocal,
            descriptorLocal,
            siteSeedLocal,
            oldEpochLocal,
            nextEpochLocal,
            STRING_KEY_CELL_CACHE_SLOT,
            STRING_KEY_CELL_CACHE_MASK,
            valueLocal
        );
        emitRuntimeStringSiteMetadataCellUpdate(
            insns,
            keyCellLocal,
            descriptorLocal,
            siteSeedLocal,
            oldEpochLocal,
            nextEpochLocal,
            STRING_KEY_CELL_LENGTH,
            STRING_KEY_CELL_LENGTH_MASK,
            valueLocal
        );
        emitRuntimeStringSiteMetadataCellUpdate(
            insns,
            keyCellLocal,
            descriptorLocal,
            siteSeedLocal,
            oldEpochLocal,
            nextEpochLocal,
            STRING_KEY_CELL_RAW_PC,
            STRING_KEY_CELL_RAW_PC_MASK,
            valueLocal
        );
        emitRuntimeStringSiteMetadataCellUpdate(
            insns,
            keyCellLocal,
            descriptorLocal,
            siteSeedLocal,
            oldEpochLocal,
            nextEpochLocal,
            STRING_KEY_CELL_GUARD,
            STRING_KEY_CELL_GUARD_MASK,
            valueLocal
        );
        emitRuntimeStringSiteMetadataCellUpdate(
            insns,
            keyCellLocal,
            descriptorLocal,
            siteSeedLocal,
            oldEpochLocal,
            nextEpochLocal,
            STRING_KEY_CELL_PATH,
            STRING_KEY_CELL_PATH_MASK,
            valueLocal
        );
        emitRuntimeStringSiteMetadataCellUpdate(
            insns,
            keyCellLocal,
            descriptorLocal,
            siteSeedLocal,
            oldEpochLocal,
            nextEpochLocal,
            STRING_KEY_CELL_BLOCK,
            STRING_KEY_CELL_BLOCK_MASK,
            valueLocal
        );
    }

    private void emitRuntimeStringSiteMetadataLoad(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int epochLocal,
        int siteSeedLocal,
        int cellIndex,
        long maskSeed,
        int targetLocal
    ) {
        emitRuntimeStringCellValueLoad(insns, keyCellLocal, descriptorLocal, cellIndex);
        emitRuntimeStringSiteMetadataCellMask(insns, siteSeedLocal, epochLocal, maskSeed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, targetLocal));
    }

    private void emitRuntimeStringSiteMetadataCellUpdate(
        InsnList insns,
        int keyCellLocal,
        int descriptorLocal,
        int siteSeedLocal,
        int oldEpochLocal,
        int nextEpochLocal,
        int cellIndex,
        long maskSeed,
        int valueLocal
    ) {
        emitRuntimeStringCellValueLoad(insns, keyCellLocal, descriptorLocal, cellIndex);
        emitRuntimeStringSiteMetadataCellMask(insns, siteSeedLocal, oldEpochLocal, maskSeed);
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeStringSiteMetadataCellMask(insns, siteSeedLocal, nextEpochLocal, maskSeed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        emitRuntimeStringCellValueStore(insns, keyCellLocal, descriptorLocal, cellIndex, valueLocal);
    }

    private void emitRuntimeStringSiteMetadataCellMask(
        InsnList insns,
        int siteSeedLocal,
        int epochLocal,
        long maskSeed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, epochLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, maskSeed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, 11);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, maskSeed ^ 0x5354524D45544131L);
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, maskSeed ^ 0x5354524D45544132L);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeStringKeyCellMask(
        InsnList insns,
        int siteSeedLocal,
        int wordIndex,
        int epochLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, epochLocal));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354524B4D41534BL + wordIndex);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, siteSeedLocal, 9 + wordIndex);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354524B4D554C31L + wordIndex);
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        emitRuntimeMixToNonZeroInt(insns, siteSeedLocal, 0x5354524B4D46494EL + wordIndex);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeStringSiteTokenCellMask(
        InsnList insns,
        int descriptorLocal,
        int epochLocal,
        int wordIndex
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, epochLocal));
        emitRuntimeStringDescriptorMaterial(insns, descriptorLocal, wordIndex, 0x5354525349544531L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 7 + wordIndex);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeStringDescriptorMaterial(insns, descriptorLocal, wordIndex, 0x5354525349544532L);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        emitRuntimeStringDescriptorMaterial(insns, descriptorLocal, wordIndex, 0x5354525349544533L);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeStringTailSelectorCellMask(InsnList insns, int descriptorLocal, int epochLocal) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, epochLocal));
        emitRuntimeStringDescriptorMaterial(insns, descriptorLocal, 0x5441494C, 0x53545253454C3131L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 13);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeStringDescriptorMaterial(insns, descriptorLocal, 0x5441494C, 0x53545253454C3132L);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        emitRuntimeStringDescriptorMaterial(insns, descriptorLocal, 0x5441494C, 0x53545253454C3133L);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeStringDescriptorMaterial(
        InsnList insns,
        int descriptorLocal,
        int ordinal,
        long domain
    ) {
        int c1 = stringDescriptorMaterialWord(ordinal, domain, 0);
        int c2 = stringDescriptorMaterialWord(ordinal, domain, 1);
        int c3 = stringDescriptorMaterialWord(ordinal, domain, 2);
        insns.add(new VarInsnNode(Opcodes.ILOAD, descriptorLocal));
        emitStaticIntFragmented(insns, c1);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, descriptorLocal));
        JvmPassBytecode.pushInt(insns, stringDescriptorMaterialShift(ordinal, 0));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, stringDescriptorMaterialShift(ordinal, 1));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStaticIntFragmented(insns, c2 | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        emitStaticIntFragmented(insns, c3);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeFingerprint(
        InsnList insns,
        int rootLocal,
        int flowLocal,
        int siteSeedLocal,
        int seedScratchLocal,
        int dataWordLocal
    ) {
        emitRuntimeDerivedSeed(insns, siteSeedLocal, 0x5354524341434845L, 0, seedScratchLocal);
        emitRuntimeStreamWordConstant(insns, rootLocal, 0, seedScratchLocal, flowLocal);
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        emitRuntimeDerivedSeed(insns, siteSeedLocal, 0x5354524341434845L, 1, seedScratchLocal);
        emitRuntimeStreamWordConstant(insns, rootLocal, 0, seedScratchLocal, flowLocal);
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataWordLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitRuntimeStreamWord(InsnList insns, int rootLocal, int wordLocal, int seedLocal, int flowLocal) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        emitRuntimeStreamWordTail(insns, () -> insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal)), seedLocal, flowLocal);
    }

    private void emitRuntimeStreamWordConstant(InsnList insns, int rootLocal, int word, int seedLocal, int flowLocal) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        emitRuntimeStreamWordTail(insns, () -> JvmPassBytecode.pushInt(insns, word), seedLocal, flowLocal);
    }

    private void emitRuntimeStreamWordTail(InsnList insns, Runnable wordEmitter, int seedLocal, int flowLocal) {
        emitRuntimeMixToNonZeroInt(insns, seedLocal, 0x535453545245414DL);
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeFlowMixToNonZeroInt(insns, flowLocal, seedLocal, 0x53545354464C4F57L);
        insns.add(new InsnNode(Opcodes.IXOR));
        wordEmitter.run();
        emitRuntimeMixToNonZeroInt(insns, seedLocal, 0x53545354494E4458L);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, seedLocal, 3);
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitRuntimeShift(insns, seedLocal, 13);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitRuntimeMixToNonZeroInt(insns, seedLocal, 0x53545354524D554CL);
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new InsnNode(Opcodes.IMUL));
        emitRuntimeMixToNonZeroInt(insns, seedLocal, 0x5354535446494E31L);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitRuntimeDerivedSeed(InsnList insns, int siteSeedLocal, long xorConst, long value, int outLocal) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, siteSeedLocal));
        JvmPassBytecode.pushLong(insns, xorConst);
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, value);
        emitRuntimeMixLong(insns);
        insns.add(new VarInsnNode(Opcodes.LSTORE, outLocal));
    }

    private void emitRuntimeMixLong(InsnList insns) {
        insns.add(new InsnNode(Opcodes.LADD));
        JvmPassBytecode.pushLong(insns, 0x9E3779B97F4A7C15L);
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 30);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0xBF58476D1CE4E5B9L);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 27);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, 0x94D049BB133111EBL);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 31);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
    }

    private void emitRuntimeMixToNonZeroInt(InsnList insns, int seedLocal, long value) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        JvmPassBytecode.pushLong(insns, value);
        emitRuntimeMixLong(insns);
        insns.add(new InsnNode(Opcodes.L2I));
        LabelNode nonZero = new LabelNode();
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new JumpInsnNode(Opcodes.IFNE, nonZero));
        insns.add(new InsnNode(Opcodes.POP));
        JvmPassBytecode.pushInt(insns, 0x3D6B2A4F);
        insns.add(nonZero);
    }

    private void emitRuntimeFlowMixToNonZeroInt(
        InsnList insns,
        int flowLocal,
        int seedLocal,
        long value
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, flowLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        JvmPassBytecode.pushLong(insns, value);
        emitRuntimeMixLong(insns);
        insns.add(new InsnNode(Opcodes.L2I));
        LabelNode nonZero = new LabelNode();
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new JumpInsnNode(Opcodes.IFNE, nonZero));
        insns.add(new InsnNode(Opcodes.POP));
        JvmPassBytecode.pushInt(insns, 0x5A17C3E9);
        insns.add(nonZero);
    }

    private long stringStreamFlow(int root) {
        int high = root ^ 0x53545346;
        int low = (root * 0x45D9F3B) ^ (root >>> 16) ^ 0x464C4F57;
        return (((long) high) << 32) | (Integer.toUnsignedLong(low));
    }

    private void emitRuntimeStringStreamFlow(InsnList insns, int rootLocal) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        JvmPassBytecode.pushInt(insns, 0x53545346);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        JvmPassBytecode.pushInt(insns, 0x45D9F3B);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, 0x464C4F57);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    private void emitRuntimeShift(InsnList insns, int seedLocal, int base) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, seedLocal));
        JvmPassBytecode.pushInt(insns, base);
        insns.add(new InsnNode(Opcodes.LUSHR));
        JvmPassBytecode.pushLong(insns, 30L);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.L2I));
        JvmPassBytecode.pushInt(insns, 1);
        insns.add(new InsnNode(Opcodes.IADD));
    }

    private String uniqueMethodName(L1Class clazz, String base) {
        String candidate = base;
        int suffix = 0;
        while (hasAsmMethodName(clazz, candidate)) {
            candidate = base + "$" + ++suffix;
        }
        return candidate;
    }

    private boolean hasAsmMethodName(L1Class clazz, String name) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (name.equals(method.name)) {
                return true;
            }
        }
        return false;
    }

    private String packageName(String owner) {
        int slash = owner.lastIndexOf('/');
        return slash < 0 ? "" : owner.substring(0, slash);
    }

    private void emitRecoverMethodSeedLocal(
        InsnList insns,
        long siteSeed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        int methodKeyLocal
    ) {
        long seed = methodSeedArgumentSeed(siteSeed);
        JvmPassBytecode.pushInt(insns, ((int) state.methodKey()) ^ methodSeedTransferWord(metadata, state, seed));
        emitMethodSeedTransferWord(insns, seed, metadata, state);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, methodKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, methodKeyLocal));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354525041434B31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, methodKeyLocal));
    }

    private void emitByteArray(InsnList insns, byte[] data) {
        JvmPassBytecode.pushInt(insns, data.length);
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < data.length; i++) {
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, i);
            JvmPassBytecode.pushInt(insns, data[i]);
            insns.add(new InsnNode(Opcodes.BASTORE));
        }
    }

    @SuppressWarnings("unchecked")
    private void publishGeneratedStringHelperFlowKey(
        PipelineContext pctx,
        String owner,
        String name,
        String desc,
        int keyLocal
    ) {
        Map<String, Integer> locals = pctx.getPassData(JvmKeyDispatchPass.CFF_LOCAL_BY_METHOD);
        if (locals == null) {
            locals = new LinkedHashMap<>();
            pctx.putPassData(JvmKeyDispatchPass.CFF_LOCAL_BY_METHOD, locals);
        }
        locals.put(owner + "." + name + desc, keyLocal);
    }

    private void emitFingerprint(InsnList insns, long siteSeed, int rootLocal) {
        emitStreamWord(insns, rootLocal, fingerprintSeed(siteSeed, 0));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        emitStreamWord(insns, rootLocal, fingerprintSeed(siteSeed, 1));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    private StringSiteMaterial stringSiteMaterial(
        PipelineContext pctx,
        L1Class clazz,
        long siteSeed,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        long seed = JvmPassBytecode.mix(pctx.masterSeed() ^ 0x5354524B4D415431L, clazz.name().hashCode());
        int layoutId = 1 + (int) Long.remainderUnsigned(
            JvmPassBytecode.mix(seed ^ siteSeed, 0x5354524C41594F55L),
            STRING_SELECTOR_LAYOUT_MASK
        );
        int wordCount = 5 + (layoutId & 3);
        List<Integer> words = new ArrayList<>(wordCount);
        for (int i = 0; i < wordCount; i++) {
            long wordSeed = JvmPassBytecode.mix(
                seed ^ Long.rotateLeft(siteSeed, (i * 11 + layoutId) & 63),
                0x5354524B4D415430L + i
            );
            words.add(nonZeroInt(wordSeed));
        }
        List<Integer> wordIndexes = shuffledStringWordIndexes(seed, siteSeed, layoutId, wordCount);
        int epoch = nonZeroInt(JvmPassBytecode.mix(
            seed ^ Long.rotateLeft(siteSeed, 29) ^ layoutId,
            0x5354524B45504F43L
        ));
        int fingerprint = stringMaterialFingerprint(seed, siteSeed, layoutId, words, wordIndexes);
        return new StringSiteMaterial(
            siteSeed,
            layoutId,
            epoch,
            fingerprint,
            words,
            wordIndexes,
            state.pcToken(),
            state.methodKey(),
            state.pcToken() ^ stringRawPcArgumentMask(siteSeed, state),
            state.guardKey(),
            state.pathKey(),
            state.blockKey(),
            StringPayloadMetadata.unbound(fingerprint)
        );
    }

    private Object[] encodedStringKeyCell(
        StringSiteMaterial keyMaterial,
        Algorithm algorithm,
        ByteLayer byteLayer,
        int payloadSlot,
        int cacheSlot,
        int encryptedLength,
        int keySlot
    ) {
        keyMaterial = keyMaterial.withPayloadMetadata(payloadSlot, cacheSlot, encryptedLength);
        int descriptor = stringKeyCellDescriptor(keyMaterial);
        Object[] cell = new Object[STRING_KEY_CELL_PHYSICAL_LENGTH];
        cell[STRING_KEY_CELL_DESCRIPTOR_SLOT] = descriptor;
        for (int i = 0; i < 4; i++) {
            putStringKeyCellValue(
                cell,
                descriptor,
                i,
                keyMaterial.word(i) ^ stringKeyCellMask(keyMaterial.siteSeed(), i, keyMaterial.epoch())
            );
        }
        putStringKeyCellValue(cell, descriptor, 4, keyMaterial.epoch());
        putStringKeyCellValue(
            cell,
            descriptor,
            5,
            (int) (keyMaterial.siteSeed() >>> 32) ^ stringSiteTokenCellMask(descriptor, keyMaterial.epoch(), 0)
        );
        putStringKeyCellValue(
            cell,
            descriptor,
            6,
            (int) keyMaterial.siteSeed() ^ stringSiteTokenCellMask(descriptor, keyMaterial.epoch(), 1)
        );
        int selector = (algorithm.ordinal() << 3)
            | (byteLayer.ordinal() << 1)
            | ((keyMaterial.siteSeed() & 2L) != 0L ? 1 : 0)
            | keyMaterial.selectorMaterial();
        putStringKeyCellValue(
            cell,
            descriptor,
            7,
            selector ^ stringTailSelectorCellMask(descriptor, keyMaterial.epoch())
        );
        StringPayloadMetadata payloadMetadata = keyMaterial.payloadMetadata();
        putStringKeyCellValue(
            cell,
            descriptor,
            STRING_KEY_CELL_PAYLOAD_SLOT,
            payloadMetadata.payloadSlot() ^ stringSiteMetadataCellMask(
                keyMaterial.siteSeed(),
                keyMaterial.epoch(),
                STRING_KEY_CELL_PAYLOAD_MASK
            )
        );
        putStringKeyCellValue(
            cell,
            descriptor,
            STRING_KEY_CELL_CACHE_SLOT,
            payloadMetadata.cacheSlot() ^ stringSiteMetadataCellMask(
                keyMaterial.siteSeed(),
                keyMaterial.epoch(),
                STRING_KEY_CELL_CACHE_MASK
            )
        );
        putStringKeyCellValue(
            cell,
            descriptor,
            STRING_KEY_CELL_LENGTH,
            payloadMetadata.encryptedLength() ^ stringSiteMetadataCellMask(
                keyMaterial.siteSeed(),
                keyMaterial.epoch(),
                STRING_KEY_CELL_LENGTH_MASK
            )
        );
        putStringKeyCellValue(
            cell,
            descriptor,
            STRING_KEY_CELL_RAW_PC,
            keyMaterial.encodedRawPc() ^ stringSiteMetadataCellMask(
                keyMaterial.siteSeed(),
                keyMaterial.epoch(),
                STRING_KEY_CELL_RAW_PC_MASK
            )
        );
        putStringKeyCellValue(
            cell,
            descriptor,
            STRING_KEY_CELL_GUARD,
            keyMaterial.encodedGuardKey(keySlot) ^ stringSiteMetadataCellMask(
                keyMaterial.siteSeed(),
                keyMaterial.epoch(),
                STRING_KEY_CELL_GUARD_MASK
            )
        );
        putStringKeyCellValue(
            cell,
            descriptor,
            STRING_KEY_CELL_PATH,
            keyMaterial.encodedPathKey(keySlot) ^ stringSiteMetadataCellMask(
                keyMaterial.siteSeed(),
                keyMaterial.epoch(),
                STRING_KEY_CELL_PATH_MASK
            )
        );
        putStringKeyCellValue(
            cell,
            descriptor,
            STRING_KEY_CELL_BLOCK,
            keyMaterial.encodedBlockKey(keySlot) ^ stringSiteMetadataCellMask(
                keyMaterial.siteSeed(),
                keyMaterial.epoch(),
                STRING_KEY_CELL_BLOCK_MASK
            )
        );
        return cell;
    }

    private int stringKeyCellDescriptor(StringSiteMaterial keyMaterial) {
        int stride = (keyMaterial.fingerprint() | 1) & STRING_KEY_CELL_PHYSICAL_MASK;
        int offset = (keyMaterial.fingerprint() ^ (keyMaterial.layoutId() * 13)) &
            STRING_KEY_CELL_PHYSICAL_MASK;
        return stride | (offset << STRING_KEY_CELL_OFFSET_SHIFT);
    }

    private void putStringKeyCellValue(Object[] cell, int descriptor, int logicalIndex, int value) {
        int physicalIndex = stringKeyCellPackPhysicalIndex(descriptor, logicalIndex);
        long current = cell[physicalIndex] instanceof Long longValue ? longValue : 0L;
        if ((logicalIndex & 1) == 0) {
            current = (current & 0xFFFFFFFF00000000L) | (value & 0xFFFFFFFFL);
        } else {
            current = (current & 0xFFFFFFFFL) | ((long) value << 32);
        }
        cell[physicalIndex] = current;
    }

    private int stringKeyCellPackPhysicalIndex(int descriptor, int logicalIndex) {
        int stride = (descriptor & STRING_KEY_CELL_PHYSICAL_MASK) | 1;
        int offset = (descriptor >>> STRING_KEY_CELL_OFFSET_SHIFT) & STRING_KEY_CELL_PHYSICAL_MASK;
        return 1 + (((logicalIndex >>> 1) * stride + offset) & STRING_KEY_CELL_PHYSICAL_MASK);
    }

    private int stringRoot(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long siteSeed,
        StringSiteMaterial keyMaterial
    ) {
        return stringKeyMixedWord(liveStringWord(metadata, state, rootSeed(siteSeed)), siteSeed, keyMaterial);
    }

    private int stringKeyMixedWord(int liveWord, long siteSeed, StringSiteMaterial keyMaterial) {
        if (keyMaterial == null) {
            return liveWord;
        }
        int x = liveWord ^ keyMaterial.word(0);
        x += (liveWord << shift(siteSeed, 7)) ^ keyMaterial.word(1);
        x ^= x >>> shift(siteSeed, 17);
        x *= keyMaterial.word(2) | 1;
        x += (liveWord >>> shift(siteSeed, 29)) ^ keyMaterial.word(3);
        x ^= x >>> shift(siteSeed, 5);
        return x;
    }

    private int stringRawPcArgumentMask(
        long siteSeed,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        int x = (int) state.methodKey() ^ (int) (state.methodKey() >>> 32);
        x += state.guardKey() ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354504347554131L));
        x ^= state.pathKey() + nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354504350415431L));
        x += state.blockKey() ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x53545043424C4B31L));
        x ^= x >>> shift(siteSeed, 13);
        x *= nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x535450434D554C31L)) | 1;
        x += x >>> shift(siteSeed, 21);
        return x ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354504346494E31L));
    }

    private List<Integer> shuffledStringWordIndexes(long seed, long siteSeed, int layoutId, int wordCount) {
        List<Integer> indexes = new ArrayList<>(wordCount);
        for (int i = 0; i < wordCount; i++) {
            indexes.add(i);
        }
        long shuffle = JvmPassBytecode.mix(seed ^ Long.rotateRight(siteSeed, 7), layoutId);
        for (int i = 0; i < indexes.size(); i++) {
            int remaining = indexes.size() - i;
            int swap = i + (int) Long.remainderUnsigned(
                JvmPassBytecode.mix(shuffle, i),
                remaining
            );
            Collections.swap(indexes, i, swap);
        }
        if (
            indexes.get(0) == 0 &&
                indexes.get(1) == 1 &&
                indexes.get(2) == 2 &&
                indexes.get(3) == 3
        ) {
            Collections.rotate(indexes, 1);
        }
        return List.copyOf(indexes.subList(0, 4));
    }

    private int stringMaterialFingerprint(
        long seed,
        long siteSeed,
        int layoutId,
        List<Integer> words,
        List<Integer> wordIndexes
    ) {
        long fp = JvmPassBytecode.mix(seed ^ Long.rotateLeft(siteSeed, 41), 0x5354524650524E54L ^ layoutId);
        for (int index : wordIndexes) {
            fp = JvmPassBytecode.mix(fp, words.get(index));
        }
        int encoded = (int) fp & STRING_SELECTOR_FINGERPRINT_MASK;
        return encoded == 0 ? 1 : encoded;
    }

    private int stringKeyCellMask(long siteSeed, int wordIndex, int epoch) {
        int x = epoch ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354524B4D41534BL + wordIndex));
        x ^= x >>> shift(siteSeed, 9 + wordIndex);
        x *= nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354524B4D554C31L + wordIndex)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354524B4D46494EL + wordIndex));
    }

    private int stringSiteTokenCellMask(int descriptor, int epoch, int wordIndex) {
        int x = epoch ^ stringDescriptorMaterial(descriptor, wordIndex, 0x5354525349544531L);
        x ^= x >>> (7 + wordIndex);
        x *= stringDescriptorMaterial(descriptor, wordIndex, 0x5354525349544532L) | 1;
        return x ^ stringDescriptorMaterial(descriptor, wordIndex, 0x5354525349544533L);
    }

    private int stringTailSelectorCellMask(int descriptor, int epoch) {
        int x = epoch ^ stringDescriptorMaterial(descriptor, 0x5441494C, 0x53545253454C3131L);
        x ^= x >>> 13;
        x *= stringDescriptorMaterial(descriptor, 0x5441494C, 0x53545253454C3132L) | 1;
        return x ^ stringDescriptorMaterial(descriptor, 0x5441494C, 0x53545253454C3133L);
    }

    private int stringDescriptorMaterial(int descriptor, int ordinal, long domain) {
        int x = descriptor ^ stringDescriptorMaterialWord(ordinal, domain, 0);
        x += descriptor >>> stringDescriptorMaterialShift(ordinal, 0);
        x ^= x >>> stringDescriptorMaterialShift(ordinal, 1);
        x *= stringDescriptorMaterialWord(ordinal, domain, 1) | 1;
        return x ^ stringDescriptorMaterialWord(ordinal, domain, 2);
    }

    private int stringDescriptorMaterialWord(int ordinal, long domain, int lane) {
        return nonZeroInt(JvmPassBytecode.mix(domain ^ ordinal, 0x5354524445534331L + lane));
    }

    private int stringDescriptorMaterialShift(int ordinal, int lane) {
        return 3 + ((ordinal + lane * 11) & 15);
    }

    private int stringSiteMetadataCellMask(long siteSeed, int epoch, long maskSeed) {
        int x = epoch ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, maskSeed));
        x ^= x >>> shift(siteSeed, 11);
        x *= nonZeroInt(JvmPassBytecode.mix(siteSeed, maskSeed ^ 0x5354524D45544131L)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, maskSeed ^ 0x5354524D45544132L));
    }

    private void emitFillKey(
        InsnList insns,
        long siteSeed,
        Algorithm algorithm,
        int keyLocal,
        int wordLocal,
        int rootLocal,
        int indexLocal
    ) {
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        boolean reverseBytes = (siteSeed & 2L) != 0L;
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, algorithm.keySize / 4);
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        emitStreamWord(insns, rootLocal, indexLocal, keyStreamSeed(siteSeed, algorithm));
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));
        for (int step = 0; step < 4; step++) {
            int b = reverseBytes ? 3 - step : step;
            insns.add(new VarInsnNode(Opcodes.ALOAD, keyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
            JvmPassBytecode.pushInt(insns, 4);
            insns.add(new InsnNode(Opcodes.IMUL));
            JvmPassBytecode.pushInt(insns, b);
            insns.add(new InsnNode(Opcodes.IADD));
            insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
            JvmPassBytecode.pushInt(insns, 24 - b * 8);
            insns.add(new InsnNode(Opcodes.IUSHR));
            insns.add(new InsnNode(Opcodes.BASTORE));
        }
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
    }

    private void emitByteLayerDecode(
        InsnList insns,
        long siteSeed,
        int length,
        ByteLayer byteLayer,
        int plainLocal,
        int wordLocal,
        int rootLocal,
        int indexLocal
    ) {
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, length);
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.BALOAD));
        emitStreamWord(insns, rootLocal, wordLocal, byteLayerSeed(siteSeed));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.ISUB));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IUSHR));
        switch (byteLayer) {
            case ADD -> insns.add(new InsnNode(Opcodes.ISUB));
            case SUBTRACT -> insns.add(new InsnNode(Opcodes.IADD));
            case XOR -> insns.add(new InsnNode(Opcodes.IXOR));
        }
        insns.add(new InsnNode(Opcodes.BASTORE));
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
    }

    private void emitXorPlaintext(
        InsnList insns,
        long siteSeed,
        int length,
        int plainLocal,
        int wordLocal,
        int rootLocal,
        int indexLocal
    ) {
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(loop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, length);
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.BALOAD));
        emitStreamWord(insns, rootLocal, wordLocal, xorSeed(siteSeed));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.ISUB));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.BASTORE));
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, loop));
        insns.add(end);
    }

    @SuppressWarnings("unchecked")
    private StringSiteCache ensureStringSiteCache(
        PipelineContext pctx,
        L1Class clazz,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        long siteSeed,
        byte[] encrypted,
        StringSiteMaterial keyMaterial,
        Algorithm algorithm,
        ByteLayer byteLayer
    ) {
        Map<String, StringSiteCache> caches = pctx.getPassData(STRING_SITE_CACHES);
        if (caches == null) {
            caches = new LinkedHashMap<>();
            pctx.putPassData(STRING_SITE_CACHES, caches);
        }
        String key = clazz.name() + ":" + Long.toUnsignedString(siteSeed, 36);
        StringSiteCache existing = caches.get(key);
        if (existing != null) return existing;

        StringKeyTable keyTable = ensureStringKeyTable(pctx, clazz, metadata);
        int payloadSlot = registerStringPayload(pctx, keyTable, encrypted);
        int cacheSlot = registerStringCacheSlot(pctx, keyTable);
        int keySlot = registerStringSiteMaterial(
            pctx,
            keyTable,
            keyMaterial,
            algorithm,
            byteLayer,
            payloadSlot,
            cacheSlot,
            encrypted.length
        );
        StringSiteCache cache = new StringSiteCache(
            clazz.name(),
            keyTable.fieldName(),
            keySlot
        );
        caches.put(key, cache);
        clazz.markDirty();
        return cache;
    }

    @SuppressWarnings("unchecked")
    private StringKeyTable ensureStringKeyTable(
        PipelineContext pctx,
        L1Class clazz,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        Map<String, StringKeyTable> tables = pctx.getPassData(STRING_KEY_TABLES);
        if (tables == null) {
            tables = new LinkedHashMap<>();
            pctx.putPassData(STRING_KEY_TABLES, tables);
        }
        StringKeyTable existing = tables.get(clazz.name());
        if (existing != null) return existing;

        String fieldName = metadata.classKeyTable().objectFieldName();
        boolean directClinit = false;
        boolean interfaceOwner = (clazz.asmNode().access & Opcodes.ACC_INTERFACE) != 0;
        MethodNode clinit = findOrCreateClassInit(clazz);
        MethodNode helper = createStringInitHelper(clazz, interfaceOwner);
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

        StringKeyTable table = new StringKeyTable(
            clazz.name(),
            fieldName,
            helper,
            new ArrayList<>(),
            new ArrayList<>(),
            new ArrayList<>(),
            directClinit,
            initStart,
            initEnd
        );
        tables.put(clazz.name(), table);
        clazz.markDirty();
        return table;
    }

    private MethodNode createStringInitHelper(L1Class clazz, boolean interfaceOwner) {
        int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        access |= interfaceOwner ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
        MethodNode helper = new MethodNode(
            access,
            uniqueMethodName(clazz, "__neko_strinit$"),
            "()V",
            null,
            null
        );
        clazz.asmNode().methods.add(helper);
        return helper;
    }

    private int registerStringSiteMaterial(
        PipelineContext pctx,
        StringKeyTable table,
        StringSiteMaterial keyMaterial,
        Algorithm algorithm,
        ByteLayer byteLayer,
        int payloadSlot,
        int cacheSlot,
        int encryptedLength
    ) {
        if (keyMaterial == null) {
            throw new IllegalStateException("string key material table requires encoded key material");
        }
        int slot = table.cells().size() + STRING_KEY_CELL_BASE_SLOT;
        table.cells().add(encodedStringKeyCell(
            keyMaterial,
            algorithm,
            byteLayer,
            payloadSlot,
            cacheSlot,
            encryptedLength,
            slot
        ));
        rebuildStringKeyInit(pctx, table);
        return slot;
    }

    private int registerStringPayload(
        PipelineContext pctx,
        StringKeyTable table,
        byte[] encrypted
    ) {
        int slot = table.payloads().size();
        table.payloads().add(encrypted.clone());
        rebuildStringKeyInit(pctx, table);
        return slot;
    }

    private int registerStringCacheSlot(PipelineContext pctx, StringKeyTable table) {
        int slot = table.cacheSlots().size();
        table.cacheSlots().add(slot);
        rebuildStringKeyInit(pctx, table);
        return slot;
    }

    private void rebuildStringKeyInit(PipelineContext pctx, StringKeyTable table) {
        InsnList insns = new InsnList();
        int arrayLocal = table.directClinit() ? table.initHelper().maxLocals : 0;
        JvmPassBytecode.pushInt(insns, table.cells().size() + STRING_KEY_CELL_BASE_SLOT);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, arrayLocal));
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            table.owner(),
            table.fieldName(),
            "[Ljava/lang/Object;"
        ));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.STRING_MATERIAL_SLOT);
        insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            table.owner(),
            table.fieldName(),
            "[Ljava/lang/Object;"
        ));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.STRING_MATERIAL_ALIAS_SLOT);
        insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            table.owner(),
            table.fieldName(),
            "[Ljava/lang/Object;"
        ));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.STRING_MATERIAL_SELECTOR_SLOT);
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new InsnNode(Opcodes.ICONST_0));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.STRING_MATERIAL_SLOT);
        insns.add(new InsnNode(Opcodes.IASTORE));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.STRING_MATERIAL_ALIAS_SLOT);
        insns.add(new InsnNode(Opcodes.IASTORE));
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(insns, STRING_PAYLOAD_TABLE_SLOT);
        JvmPassBytecode.pushInt(insns, table.payloads().size());
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        for (int i = 0; i < table.payloads().size(); i++) {
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, i);
            emitByteArray(insns, table.payloads().get(i));
            insns.add(new InsnNode(Opcodes.AASTORE));
        }
        insns.add(new InsnNode(Opcodes.AASTORE));
        insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(insns, STRING_CACHE_TABLE_SLOT);
        JvmPassBytecode.pushInt(insns, table.cacheSlots().size() * 2);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        insns.add(new InsnNode(Opcodes.AASTORE));
        emitStringCipherCacheStore(insns, table, arrayLocal, Algorithm.AES);
        emitStringCipherCacheStore(insns, table, arrayLocal, Algorithm.DES);
        for (int i = 0; i < table.cells().size(); i++) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
            JvmPassBytecode.pushInt(insns, i + STRING_KEY_CELL_BASE_SLOT);
            emitObjectArray(insns, table.cells().get(i));
            insns.add(new InsnNode(Opcodes.AASTORE));
        }
        JvmKeyDispatchPass.markGenerated(pctx, insns);
        if (table.directClinit()) {
            replaceClassInitSegment(table.initHelper(), table.initStart(), table.initEnd(), insns);
        } else {
            table.initHelper().instructions.clear();
            table.initHelper().instructions.add(insns);
            table.initHelper().instructions.add(new InsnNode(Opcodes.RETURN));
            table.initHelper().maxLocals = 0;
        }
        table.initHelper().maxLocals = Math.max(table.initHelper().maxLocals, arrayLocal + 1);
        table.initHelper().maxStack = 16;
    }

    private void emitStringCipherCacheStore(InsnList insns, StringKeyTable table, int tableLocal, Algorithm algorithm) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
        JvmPassBytecode.pushInt(insns, stringCipherSlot(algorithm));
        emitStaticString(
            insns,
            algorithm.transformation,
            JvmPassBytecode.mix(
                table.owner().hashCode() ^ table.fieldName().hashCode(),
                0x535452434950484CL ^ algorithm.ordinal()
            )
        );
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "javax/crypto/Cipher",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            false
        ));
        insns.add(new InsnNode(Opcodes.AASTORE));
    }

    private void emitObjectArray(InsnList insns, Object[] values) {
        JvmPassBytecode.pushInt(insns, values.length);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        for (int i = 0; i < values.length; i++) {
            Object value = values[i];
            if (value == null) {
                continue;
            }
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, i);
            if (value instanceof Integer intValue) {
                emitStaticIntFragmented(insns, intValue);
                insns.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/Integer",
                    "valueOf",
                    "(I)Ljava/lang/Integer;",
                    false
                ));
            } else if (value instanceof Long longValue) {
                emitStaticLongFragmented(insns, longValue);
                insns.add(new MethodInsnNode(
                    Opcodes.INVOKESTATIC,
                    "java/lang/Long",
                    "valueOf",
                    "(J)Ljava/lang/Long;",
                    false
                ));
            } else {
                throw new IllegalStateException("string material object cells currently support numeric values only");
            }
            insns.add(new InsnNode(Opcodes.AASTORE));
        }
    }

    private void emitStaticLongFragmented(InsnList insns, long value) {
        JvmPassBytecode.pushInt(insns, (int) (value >>> 32));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        JvmPassBytecode.pushInt(insns, (int) value);
        insns.add(new InsnNode(Opcodes.I2L));
        emitStaticUnsignedIntMask(insns);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    private void emitStaticIntFragmented(InsnList insns, int value) {
        emitStaticUnsignedShort(insns, value >>> 16);
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.ISHL));
        emitStaticUnsignedShort(insns, value);
        insns.add(new InsnNode(Opcodes.IOR));
    }

    private void emitStaticUnsignedShort(InsnList insns, int value) {
        int word = value & 0xFFFF;
        JvmPassBytecode.pushInt(insns, (short) word);
        if (word > Short.MAX_VALUE) {
            insns.add(new InsnNode(Opcodes.ICONST_M1));
            JvmPassBytecode.pushInt(insns, 16);
            insns.add(new InsnNode(Opcodes.IUSHR));
            insns.add(new InsnNode(Opcodes.IAND));
        }
    }

    private void emitStaticUnsignedIntMask(InsnList insns) {
        insns.add(new InsnNode(Opcodes.ICONST_M1));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
    }

    private int stringMaterialTableFieldAccess(L1Class clazz) {
        if ((clazz.asmNode().access & Opcodes.ACC_INTERFACE) != 0) {
            return Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        }
        return Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
    }

    private String uniqueFieldName(L1Class clazz, String base) {
        String candidate = base;
        int suffix = 0;
        while (hasAsmFieldName(clazz, candidate)) {
            candidate = base + "$" + ++suffix;
        }
        return candidate;
    }

    private boolean hasAsmFieldName(L1Class clazz, String name) {
        for (FieldNode field : clazz.asmNode().fields) {
            if (name.equals(field.name)) {
                return true;
            }
        }
        return false;
    }

    private void emitStaticString(InsnList insns, String value, long seed) {
        JvmPassBytecode.pushInt(insns, value.length());
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_CHAR));
        for (int i = 0; i < value.length(); i++) {
            int mask = staticCharMask(seed, i);
            insns.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushInt(insns, i);
            JvmPassBytecode.pushInt(insns, value.charAt(i) ^ mask);
            JvmPassBytecode.pushInt(insns, mask);
            insns.add(new InsnNode(Opcodes.IXOR));
            insns.add(new InsnNode(Opcodes.I2C));
            insns.add(new InsnNode(Opcodes.CASTORE));
        }
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/String",
            "valueOf",
            "([C)Ljava/lang/String;",
            false
        ));
    }

    private int staticCharMask(long seed, int index) {
        long mixed = JvmPassBytecode.mix(seed ^ 0x5354415449435354L, index * STATIC_CHAR_STRIDE);
        return (int) (mixed ^ (mixed >>> 32)) & 0xFFFF;
    }

    private MethodNode findOrCreateClassInit(L1Class clazz) {
        for (MethodNode method : clazz.asmNode().methods) {
            if ("<clinit>".equals(method.name)) return method;
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        clazz.asmNode().methods.add(clinit);
        return clinit;
    }

    private void insertClassInitSegment(MethodNode clinit, LabelNode start, LabelNode end) {
        InsnList segment = new InsnList();
        segment.add(start);
        segment.add(end);
        AbstractInsnNode first = clinit.instructions.getFirst();
        if (first == null) {
            clinit.instructions.add(segment);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        } else {
            clinit.instructions.insertBefore(first, segment);
        }
    }

    private void insertClassInitSegmentAfter(
        MethodNode clinit,
        LabelNode anchor,
        LabelNode start,
        LabelNode end
    ) {
        if (anchor == null) {
            insertClassInitSegment(clinit, start, end);
            return;
        }
        InsnList segment = new InsnList();
        segment.add(start);
        segment.add(end);
        clinit.instructions.insert(anchor, segment);
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

    private void replaceClassInitSegment(
        MethodNode clinit,
        LabelNode start,
        LabelNode end,
        InsnList replacement
    ) {
        AbstractInsnNode insn = start.getNext();
        while (insn != null && insn != end) {
            AbstractInsnNode next = insn.getNext();
            clinit.instructions.remove(insn);
            insn = next;
        }
        clinit.instructions.insert(start, replacement);
    }

    private AbstractInsnNode firstReal(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int type = insn.getType();
            if (type != AbstractInsnNode.LABEL && type != AbstractInsnNode.LINE && type != AbstractInsnNode.FRAME) {
                return insn;
            }
        }
        return null;
    }

    private void installInjectedFieldReflectionFilter(
        PipelineContext pctx,
        L1Class clazz,
        String fieldName
    ) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!(insn instanceof MethodInsnNode call) || !isFieldReflectionCall(call)) continue;
                InsnList filter = injectedFieldFilter(method, clazz, fieldName);
                JvmKeyDispatchPass.markGenerated(pctx, filter);
                method.instructions.insert(call, filter);
            }
        }
    }

    private boolean isFieldReflectionCall(MethodInsnNode call) {
        return call.getOpcode() == Opcodes.INVOKEVIRTUAL
            && "java/lang/Class".equals(call.owner)
            && ("getFields".equals(call.name) || "getDeclaredFields".equals(call.name))
            && "()[Ljava/lang/reflect/Field;".equals(call.desc);
    }

    private InsnList injectedFieldFilter(
        MethodNode mn,
        L1Class clazz,
        String fieldName
    ) {
        int sourceLocal = mn.maxLocals++;
        int filteredLocal = mn.maxLocals++;
        int indexLocal = mn.maxLocals++;
        int writeLocal = mn.maxLocals++;
        int fieldLocal = mn.maxLocals++;
        LabelNode loop = new LabelNode();
        LabelNode keep = new LabelNode();
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
        insns.add(keep);
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
        L1Class clazz,
        String fieldName,
        LabelNode skip
    ) {
        LabelNode next = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ALOAD, fieldLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/reflect/Field",
            "getName",
            "()Ljava/lang/String;",
            false
        ));
        insns.add(new LdcInsnNode(fieldName));
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
        insns.add(new LdcInsnNode(clazz.name().replace('/', '.')));
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

    private int streamWord(int root, long seed) {
        return streamWord(root, seed, 0, 0L);
    }

    private int streamWord(int root, long seed, int wordIndex, long streamFlow) {
        int x = root ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x535453545245414DL));
        x ^= nonZeroInt(JvmPassBytecode.mix(streamFlow ^ seed, 0x53545354464C4F57L));
        x += wordIndex * nonZeroInt(JvmPassBytecode.mix(seed, 0x53545354494E4458L));
        x += x << shift(seed, 3);
        x ^= x >>> shift(seed, 13);
        x *= nonZeroInt(JvmPassBytecode.mix(seed, 0x53545354524D554CL)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x5354535446494E31L));
    }

    private void emitStreamWord(InsnList insns, int rootLocal, long seed) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x535453545245414DL)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 3));
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 13));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53545354524D554CL)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354535446494E31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitStreamWord(InsnList insns, int rootLocal, int wordLocal, long seed) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, rootLocal));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x535453545245414DL)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53545354494E4458L)));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 3));
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 13));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53545354524D554CL)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354535446494E31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitStringLength(InsnList insns, int plainLocal) {
        for (int i = 0; i < 4; i++) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, plainLocal));
            JvmPassBytecode.pushInt(insns, i);
            insns.add(new InsnNode(Opcodes.BALOAD));
            JvmPassBytecode.pushInt(insns, 0xFF);
            insns.add(new InsnNode(Opcodes.IAND));
            if (i != 3) {
                JvmPassBytecode.pushInt(insns, 24 - i * 8);
                insns.add(new InsnNode(Opcodes.ISHL));
            }
            if (i != 0) {
                insns.add(new InsnNode(Opcodes.IOR));
            }
        }
    }

    private int liveStringWord(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long seed
    ) {
        int x =
            (state.guardKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x5354475541524431L))) +
            state.pathKey();
        x ^= x >>> shift(seed, 5);
        x = (x + state.blockKey()) ^
            nonZeroInt(JvmPassBytecode.mix(seed, 0x5354424C4F434B31L));
        x *= nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D554C544B31L)) | 1;
        x ^= derivedMethodKeyFold(metadata, state);
        x += state.pcToken() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x53545043544F4B31L));
        int idx =
            (x ^ state.pcToken() ^ state.blockKey() ^
                nonZeroInt(JvmPassBytecode.mix(seed, 0x535454414249584CL))) &
                (metadata.classKeyTable().values().length - 1);
        x ^= metadata.classKeyTable().values()[idx] +
            nonZeroInt(JvmPassBytecode.mix(seed, 0x535454414256414CL));
        x += x >>> shift(seed, 23);
        return x ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x535446494E414C31L));
    }

    private void emitCanonicalPcToken(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long seed
    ) {
        long maskSeed = canonicalPcTokenSeed(seed, state);
        emitCanonicalPcTokenMask(insns, metadata, maskSeed);
        JvmPassBytecode.pushInt(insns, state.pcToken() ^ canonicalPcTokenMask(state, maskSeed));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private int canonicalPcTokenMask(
        ControlFlowFlatteningPass.CffInstructionState state,
        long seed
    ) {
        int blockMix = state.blockKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x53545043424C4B31L));
        blockMix ^= blockMix >>> shift(seed, 9);
        int keyFold = (int) state.methodKey() ^ (int) (state.methodKey() >>> 32);
        int x = (state.guardKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x5354504347554131L))) +
            state.pathKey();
        x ^= blockMix;
        x += keyFold ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x535450434D4B4631L));
        x ^= x >>> shift(seed, 15);
        x *= nonZeroInt(JvmPassBytecode.mix(seed, 0x535450434D554C31L)) | 1;
        x += state.guardKey() ^ state.blockKey() ^
            nonZeroInt(JvmPassBytecode.mix(seed, 0x5354504346494E31L));
        x ^= x >>> shift(seed, 23);
        return x;
    }

    private void emitCanonicalPcTokenMask(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354504347554131L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53545043424C4B31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 9));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x535450434D4B4631L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 15));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x535450434D554C31L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354504346494E31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 23));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private long canonicalPcTokenSeed(long seed, ControlFlowFlatteningPass.CffInstructionState state) {
        return JvmPassBytecode.mix(seed ^ state.selectorSeed(), 0x5354525043544F4BL);
    }

    private void emitLiveStringWord(
        InsnList insns,
        long seed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354475541524431L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 5));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354424C4F434B31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D554C544B31L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        emitDerivedMethodKeyFold(insns, metadata, state);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pcLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53545043544F4B31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pcLocal()));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x535454414249584CL)));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, metadata.classKeyTable().values().length - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            metadata.classKeyTable().owner(),
            metadata.classKeyTable().objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        emitStringClassKeyWordsSlotSelectionFromCarrier(insns, metadata, state);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new InsnNode(Opcodes.SWAP));
        ControlFlowFlatteningPass.emitDecodedSealedClassKeyWord(
            insns,
            ControlFlowFlatteningPass.CLASS_KEY_WORD_SEAL
        );
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x535454414256414CL)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 23));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x535446494E414C31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitLiveStringWordPrefix(
        InsnList insns,
        long seed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354475541524431L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 5));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354424C4F434B31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D554C544B31L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        emitDerivedMethodKeyFold(insns, metadata, state);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pcLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53545043544F4B31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
    }

    private void emitStringDataWord(
        InsnList insns,
        long seed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.dataLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354444154413031L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 7));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354444154413032L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354444154413033L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 19));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x5354444154413034L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitStringRootTransportMultiplierFromTop(InsnList insns) {
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(0x535452524F4F544DL, 0x44415441574F5244L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 13);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(0x535452524F4F544EL, 0x4D554C5449504CL)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 17);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(0x535452524F4F544FL, 0x46494E414C3031L)));
        insns.add(new InsnNode(Opcodes.IXOR));
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

    private void emitStringHelperDataDigestInit(
        InsnList insns,
        int methodKeyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int dataLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, methodKeyLocal));
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
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544448494E4931L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 11));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544448494E4932L)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dataLocal));
    }

    private int derivedMethodKeyFold(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        int x = (state.guardKey() ^ state.pathKey()) + state.blockKey();
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
        insns.add(new VarInsnNode(Opcodes.LLOAD, metadata.keyLocal()));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private void emitStringClassKeyWordsSlotSelectionFromCarrier(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, ControlFlowFlatteningPass.CLASS_KEY_WORDS_SELECTOR_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IALOAD));
    }

    private void emitStringClassKeyWordsSelector(
        InsnList insns,
        ControlFlowFlatteningPass.CffMethodMetadata metadata
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
    }

    private int methodSeedTransferWord(
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state,
        long seed
    ) {
        int x =
            (state.guardKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54475531L))) +
            state.pathKey();
        x ^= x >>> 11;
        x += state.blockKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54424C31L));
        x ^= state.pcToken() + nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54504331L));
        int idx =
            (x ^ state.state() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54544231L))) &
            (metadata.classKeyTable().values().length - 1);
        x += metadata.classKeyTable().values()[idx] ^
            nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54545631L));
        x ^= x >>> 17;
        return x;
    }

    private void emitMethodSeedTransferWord(
        InsnList insns,
        long seed,
        ControlFlowFlatteningPass.CffMethodMetadata metadata,
        ControlFlowFlatteningPass.CffInstructionState state
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.guardLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54475531L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.pathKeyLocal()));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 11);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, metadata.blockKeyLocal()));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54424C31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        emitCanonicalPcToken(insns, metadata, state, seed);
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54504331L)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, state.state());
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54544231L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, metadata.classKeyTable().values().length - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            metadata.classKeyTable().owner(),
            metadata.classKeyTable().objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        emitStringClassKeyWordsSlotSelectionFromCarrier(insns, metadata, state);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new InsnNode(Opcodes.SWAP));
        ControlFlowFlatteningPass.emitDecodedSealedClassKeyWord(
            insns,
            ControlFlowFlatteningPass.CLASS_KEY_WORD_SEAL
        );
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x53544D54545631L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 17);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    private long byteLayerSeed(long siteSeed) {
        return JvmPassBytecode.mix(siteSeed ^ 0x5354524C41595231L, 0x425954454C415952L);
    }

    private long methodSeedArgumentSeed(long siteSeed) {
        return JvmPassBytecode.mix(siteSeed ^ 0x5354524D45544831L, 0x4152474B45594C31L);
    }

    private long keySeed(long siteSeed, int word, Algorithm algorithm) {
        long h = JvmPassBytecode.mix(siteSeed ^ 0x5354524B45594B31L, word);
        return JvmPassBytecode.mix(h, algorithm.keySize);
    }

    private long keyStreamSeed(long siteSeed, Algorithm algorithm) {
        return JvmPassBytecode.mix(siteSeed ^ 0x5354524B45594C31L, algorithm.keySize);
    }

    private long rootSeed(long siteSeed) {
        return JvmPassBytecode.mix(siteSeed, 0x535452524F4F5431L);
    }

    private long xorSeed(long siteSeed) {
        return JvmPassBytecode.mix(siteSeed ^ 0x535452584F524B31L, 0x425954455354524DL);
    }

    private long fingerprintSeed(long siteSeed, int word) {
        return JvmPassBytecode.mix(siteSeed ^ 0x5354524341434845L, word);
    }

    private long siteSeed(
        long masterSeed,
        L1Class clazz,
        L1Method method,
        ControlFlowFlatteningPass.CffInstructionState state,
        int ordinal
    ) {
        long h = JvmPassBytecode.mix(masterSeed ^ 0x5354524F42464B31L, clazz.name().hashCode());
        h = JvmPassBytecode.mix(h, method.name().hashCode());
        h = JvmPassBytecode.mix(h, method.descriptor().hashCode());
        h = JvmPassBytecode.mix(h, state.blockIndex());
        h = JvmPassBytecode.mix(h, state.state());
        return JvmPassBytecode.mix(h, ordinal);
    }

    private int shift(long seed, int base) {
        return 1 + (int) ((seed >>> base) & 30L);
    }

    private static int nonZeroInt(long value) {
        int v = (int) value;
        return v == 0 ? 0x3D6B2A4F : v;
    }

    private sealed interface ConcatPiece permits ArgPiece, LiteralPiece, ConstPiece {}

    private record ArgPiece() implements ConcatPiece {}

    private record LiteralPiece(String value) implements ConcatPiece {}

    private record ConstPiece(Object value) implements ConcatPiece {}

    private record ConcatPlan(List<ConcatPiece> pieces) {
        boolean hasStringConstants() {
            for (ConcatPiece piece : pieces) {
                if (piece instanceof LiteralPiece literal && !literal.value().isEmpty()) {
                    return true;
                }
                if (piece instanceof ConstPiece constant
                    && constant.value() instanceof String value
                    && !value.isEmpty()) {
                    return true;
                }
            }
            return false;
        }
    }

    private record ConcatRewriteResult(
        InsnList instructions,
        int encryptedStrings,
        String helperName,
        boolean usesLoopCache
    ) {}

    private record ConcatHelperCacheKey(
        String owner,
        String desc,
        List<ConcatCachePiece> pieces,
        List<Integer> externalStringPattern
    ) {}

    private sealed interface ConcatCachePiece permits CacheArgPiece, CacheStringPiece, CacheConstPiece {}

    private record CacheArgPiece() implements ConcatCachePiece {}

    private record CacheStringPiece(int externalSlot) implements ConcatCachePiece {}

    private record CacheConstPiece(Object value) implements ConcatCachePiece {}

    private record StringSiteCache(
        String owner,
        String keyTableFieldName,
        int keySlot
    ) {
        boolean hasKeyMaterial() {
            return keyTableFieldName != null && keySlot >= 0;
        }
    }

    private record StringSiteMaterial(
        long siteSeed,
        int layoutId,
        int epoch,
        int fingerprint,
        List<Integer> words,
        List<Integer> wordIndexes,
        int pcToken,
        long methodKey,
        int encodedRawPc,
        int guardKey,
        int pathKey,
        int blockKey,
        StringPayloadMetadata payloadMetadata
    ) {
        private StringSiteMaterial {
            if (layoutId <= 0 || layoutId > STRING_SELECTOR_LAYOUT_MASK) {
                throw new IllegalArgumentException("invalid string material layout id");
            }
            if (fingerprint <= 0 || fingerprint > STRING_SELECTOR_FINGERPRINT_MASK) {
                throw new IllegalArgumentException("invalid string material fingerprint");
            }
            if (words.size() < 4 || wordIndexes.size() != 4) {
                throw new IllegalArgumentException("invalid string material word layout");
            }
            words = List.copyOf(words);
            wordIndexes = List.copyOf(wordIndexes);
            payloadMetadata = payloadMetadata == null
                ? StringPayloadMetadata.unbound(fingerprint)
                : payloadMetadata;
        }

        int word(int logicalIndex) {
            return words.get(wordIndexes.get(logicalIndex));
        }

        int selectorMaterial() {
            return ((layoutId & STRING_SELECTOR_LAYOUT_MASK) << STRING_SELECTOR_LAYOUT_SHIFT) |
                ((fingerprint & STRING_SELECTOR_FINGERPRINT_MASK) << STRING_SELECTOR_FINGERPRINT_SHIFT);
        }

        StringSiteMaterial withPayloadMetadata(int payloadSlot, int cacheSlot, int encryptedLength) {
            return new StringSiteMaterial(
                siteSeed,
                layoutId,
                epoch,
                fingerprint,
                words,
                wordIndexes,
                pcToken,
                methodKey,
                encodedRawPc,
                guardKey,
                pathKey,
                blockKey,
                new StringPayloadMetadata(
                    payloadSlot,
                    cacheSlot,
                    encryptedLength,
                    nonZeroInt(JvmPassBytecode.mix(
                        fingerprint ^ encryptedLength,
                        ((long) payloadSlot << 32) ^ (cacheSlot & 0xFFFFFFFFL)
                    ))
                )
            );
        }

        int encodedGuardKey(int keySlot) {
            return guardKey ^ compactStringStateMask(siteSeed, keySlot, 0);
        }

        int encodedPathKey(int keySlot) {
            return pathKey ^ compactStringStateMask(siteSeed, keySlot, 1);
        }

        int encodedBlockKey(int keySlot) {
            return blockKey ^ compactStringStateMask(siteSeed, keySlot, 2);
        }

        private int compactStringStateMask(long siteSeed, int keySlot, int lane) {
            int x = (int) methodKey ^ (int) (methodKey >>> 32);
            x += pcToken ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354435354413131L + lane));
            x ^= keySlot + nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354435354413231L + lane));
            x ^= x >>> (13 + lane);
            x *= nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354435354413331L + lane)) | 1;
            return x ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354435354413431L + lane));
        }
    }

    private record StringPayloadMetadata(
        int payloadSlot,
        int cacheSlot,
        int encryptedLength,
        int fingerprint
    ) {
        static StringPayloadMetadata unbound(int fingerprint) {
            return new StringPayloadMetadata(-1, -1, -1, fingerprint);
        }
    }

    private record StringKeyTable(
        String owner,
        String fieldName,
        MethodNode initHelper,
        List<Object[]> cells,
        List<byte[]> payloads,
        List<Integer> cacheSlots,
        boolean directClinit,
        LabelNode initStart,
        LabelNode initEnd
    ) {}

    private record StringDecodeTail(String owner, String name, String desc, boolean interfaceOwner) {}

    private enum ByteLayer {
        ADD,
        SUBTRACT,
        XOR
    }

    private enum Algorithm {
        AES("AES", "AES/ECB/NoPadding", 16, 16),
        DES("DES", "DES/ECB/NoPadding", 8, 8);

        final String keyName;
        final String transformation;
        final int keySize;
        final int blockSize;

        Algorithm(String keyName, String transformation, int keySize, int blockSize) {
            this.keyName = keyName;
            this.transformation = transformation;
            this.keySize = keySize;
            this.blockSize = blockSize;
        }
    }
}
