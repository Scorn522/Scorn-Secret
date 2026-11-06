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
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Shared state, stable metadata API, and cross-split contracts for CFF.
 */
abstract class CffSharedState {
    protected static final class TransitionMaterialRowCursor {
        final int local;
        int offset;

        TransitionMaterialRowCursor(int local) {
            this.local = local;
            this.offset = 0;
        }
    }

    public static final String ID = "controlFlowFlattening";
    protected static final Logger log = LoggerFactory.getLogger(ControlFlowFlatteningPass.class);
    static final String METHOD_METADATA =
        "controlFlowFlattening.methodMetadata";
    protected static final String CLASS_KEY_TABLES =
        "controlFlowFlattening.classKeyTables";
    protected static final String CLASS_KEY_TABLES_PREPARED =
        "controlFlowFlattening.classKeyTablesPrepared";
    protected static final String CLASS_INTEGRITY_ORDER_METADATA =
        "controlFlowFlattening.classIntegrityOrderMetadata";
    protected static final String SHARED_CLASS_HELPERS =
        "controlFlowFlattening.sharedClassHelpers";
    protected static final String CLASS_INTEGRITY_STATE =
        "controlFlowFlattening.classIntegrityState";
    protected static final String STRING_CONSTANT_VALUES_LOWERED =
        "controlFlowFlattening.stringConstantValuesLowered";
    protected static final int CLASS_KEY_TABLE_SIZE = 64;
    public static final int CLASS_KEY_WORD_SEAL = 0x4B1D5EED;
    protected static final int TOKEN_MATERIAL_TABLE_SIZE = 16_384;
    protected static final int TOKEN_MATERIAL_ROW_WORDS = 13;
    protected static final int TOKEN_MATERIAL_ROW_LONGS = (TOKEN_MATERIAL_ROW_WORDS + 1) / 2;
    protected static final int TOKEN_MATERIAL_OBJECT_WORDS = 6;
    protected static final int TOKEN_MATERIAL_CONTROL_WORDS = 3;
    protected static final int TOKEN_MATERIAL_OBJECT_WORD_OFFSET =
        TOKEN_MATERIAL_ROW_WORDS - TOKEN_MATERIAL_OBJECT_WORDS - TOKEN_MATERIAL_CONTROL_WORDS;
    protected static final int TRANSITION_MATERIAL_TABLE_SIZE = 16_384;
    protected static final int TRANSITION_MATERIAL_ROW_WORDS = 57;
    protected static final int TRANSITION_MATERIAL_ROW_LONGS = (TRANSITION_MATERIAL_ROW_WORDS + 1) / 2;
    protected static final int TOKEN_MATERIAL_WORDS_SLOT = CLASS_KEY_TABLE_SIZE;
    public static final int CLASS_KEY_WORDS_SLOT = CLASS_KEY_TABLE_SIZE + 1;
    public static final int STRING_MATERIAL_SLOT = CLASS_KEY_TABLE_SIZE + 2;
    public static final int INDY_MATERIAL_SLOT = CLASS_KEY_TABLE_SIZE + 3;
    public static final int STRING_MATERIAL_ALIAS_SLOT = CLASS_KEY_TABLE_SIZE + 4;
    public static final int STRING_MATERIAL_SELECTOR_SLOT = CLASS_KEY_TABLE_SIZE + 5;
    public static final int INDY_MATERIAL_ALIAS_SLOT = CLASS_KEY_TABLE_SIZE + 6;
    public static final int INDY_MATERIAL_SELECTOR_SLOT = CLASS_KEY_TABLE_SIZE + 7;
    public static final int CLASS_KEY_WORDS_ALIAS_SLOT = CLASS_KEY_TABLE_SIZE + 8;
    public static final int CLASS_KEY_WORDS_SELECTOR_SLOT = CLASS_KEY_TABLE_SIZE + 9;
    public static final int INDY_CACHE_SLOT = CLASS_KEY_TABLE_SIZE + 10;
    protected static final int TRANSITION_MATERIAL_SLOT = CLASS_KEY_TABLE_SIZE + 11;
    protected static final int STEP_MATERIAL_SLOT = CLASS_KEY_TABLE_SIZE + 12;
    protected static final int CFF_ISLAND_MATERIAL_SLOT = CLASS_KEY_TABLE_SIZE + 13;
    public static final int RUNTIME_VARIABLE_FRAME_SLOT = CLASS_KEY_TABLE_SIZE + 14;
    protected static final int TOKEN_MATERIAL_CARRIER_SIZE = CLASS_KEY_TABLE_SIZE + 15;
    protected static final int TOKEN_MATERIAL_INIT_CHUNK_SIZE = 1024;
    protected static final int TRANSITION_MATERIAL_INIT_CHUNK_SIZE = 96;
    protected static final int STEP_MATERIAL_TABLE_SIZE = 8_192;
    protected static final int STEP_MATERIAL_ROW_WORDS = 8;
    protected static final int STEP_MATERIAL_ROW_LONGS = STEP_MATERIAL_ROW_WORDS / 2;
    protected static final int STEP_MATERIAL_INIT_CHUNK_LONGS = 512;
    protected static final int CFF_ISLAND_MATERIAL_TABLE_SIZE = 16_384;
    protected static final int CFF_ISLAND_MATERIAL_INIT_CHUNK_SIZE = 128;
    protected static final String TOKEN_MATERIAL_OBJECT_HELPER_DESC =
        "([Ljava/lang/Object;[JIIII)I";
    protected static final String TRANSITION_MATERIAL_HELPER_DESC =
        "(JIII[Ljava/lang/Object;II[J)J";
    protected static final String TRANSITION_MATERIAL_BASE_HELPER_DESC =
        "(JI[Ljava/lang/Object;[IIII)I";
    protected static final String TRANSITION_MATERIAL_WORD_HELPER_DESC =
        "([IIII)I";
    protected static final String TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC =
        "([IIIII)I";
    protected static final String STEP_MATERIAL_HELPER_DESC =
        "(JIII[Ljava/lang/Object;I[J)J";
    protected static final String KEY_TRANSFER_MATERIAL_HELPER_DESC =
        "(JIII[Ljava/lang/Object;II)J";
    protected static final String KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC =
        "(JIIII)I";
    protected static final String CFF_ISLAND_MATERIAL_HELPER_DESC =
        "(JIII[Ljava/lang/Object;III)I";
    protected static final String CFF_ISLAND_RUNTIME_SOURCE_HELPER_DESC =
        "(JIIIIII)I";
    protected static final String CFF_ISLAND_MATERIAL_UNPACK_HELPER_DESC =
        "([Ljava/lang/String;)[I";
    protected static final String CFF_STACK_MIX_HELPER_DESC =
        "(ILjava/util/stream/Stream;)Ljava/lang/Integer;";
    protected static final String CLASS_INTEGRITY_HELPER_DESC =
        "(IJJLjava/lang/Class;JJ)J";
    protected static final int CLASS_INTEGRITY_TICKET_ISSUE_MODE = -1;
    protected static final int CLASS_INTEGRITY_TICKET_CONSUME_MODE = -2;
    protected static final int CLASS_INTEGRITY_TICKET_OBSERVE_MODE = -3;
    protected static final int CLASS_INTEGRITY_TICKET_DEFER_MODE = -4;
    protected static final long KEY_TRANSFER_MATERIAL_HIGH_METHOD_SEED =
        0x4B58464552484931L;
    protected static final long KEY_TRANSFER_MATERIAL_LOW_METHOD_SEED =
        0x4B584645524C4F31L;
    protected static final int KEY_TRANSFER_RUNTIME_SOURCE_NONE = 0;
    protected static final int KEY_TRANSFER_RUNTIME_SOURCE_THREAD = 1;
    protected static final int KEY_TRANSFER_RUNTIME_SOURCE_STACK = 2;
    protected static final int KEY_TRANSFER_RUNTIME_SOURCE_BUCKETS = 4;
    protected static final int KEY_TRANSFER_CURSOR_MODE_SHIFT = 24;
    protected static final int KEY_TRANSFER_CURSOR_TICKET_DEFER_FLAG = 0x80000000;
    protected static final int KEY_TRANSFER_CURSOR_MODE_MASK = 0x7FFFFFFF;
    protected static final int KEY_TRANSFER_CURSOR_INDEX_MASK =
        (1 << KEY_TRANSFER_CURSOR_MODE_SHIFT) - 1;
    protected static final int CFF_ISLAND_RUNTIME_SOURCE_NONE = 0;
    protected static final int CFF_ISLAND_RUNTIME_SOURCE_THREAD = 1;
    protected static final int CFF_ISLAND_RUNTIME_SOURCE_STACK = 2;
    protected static final int CFF_ISLAND_RUNTIME_SOURCE_BUCKETS = 4;
    protected static final int CFF_ISLAND_CURSOR_MODE_SHIFT = 24;
    protected static final int CFF_ISLAND_CURSOR_INDEX_MASK =
        (1 << CFF_ISLAND_CURSOR_MODE_SHIFT) - 1;
    protected static final int TRANSITION_MATERIAL_BASE_CLASS_INDEX = 0;
    protected static final int TRANSITION_MATERIAL_BASE_CLASS_BLOCK = 1;
    protected static final int TRANSITION_MATERIAL_BASE_CLASS_DIGEST = 2;
    protected static final int TRANSITION_MATERIAL_BASE_PATH = 3;
    protected static final int TRANSITION_MATERIAL_BASE_BLOCK = 4;
    protected static final int TRANSITION_MATERIAL_BASE_METHOD_HIGH = 5;
    protected static final int TRANSITION_MATERIAL_BASE_METHOD_ADD = 6;
    protected static final int TRANSITION_MATERIAL_BASE_METHOD_SHIFT = 7;
    protected static final int TRANSITION_MATERIAL_BASE_SHIFT = 8;
    protected static final int TRANSITION_MATERIAL_WORDS_BASE = 9;
    protected static final int TRANSITION_MATERIAL_WORD_STRIDE = 4;
    protected static final int TRANSITION_MATERIAL_GUARD_WORD = 0;
    protected static final int TRANSITION_MATERIAL_PATH_WORD = 1;
    protected static final int TRANSITION_MATERIAL_BLOCK_WORD = 2;
    protected static final int TRANSITION_MATERIAL_PC_WORD = 3;
    protected static final int TRANSITION_MATERIAL_METHOD_HIGH_WORD = 4;
    protected static final int TRANSITION_MATERIAL_METHOD_LOW_WORD = 5;
    protected static final int TRANSITION_MATERIAL_DOMAIN_WORD = 6;
    protected static final int TRANSITION_MATERIAL_DISPATCH_ADD_WORD = 7;
    protected static final int TRANSITION_MATERIAL_DISPATCH_SHIFT_A_WORD = 8;
    protected static final int TRANSITION_MATERIAL_DISPATCH_MUL_WORD = 9;
    protected static final int TRANSITION_MATERIAL_DISPATCH_SHIFT_B_WORD = 10;
    protected static final int TRANSITION_MATERIAL_DISPATCH_FINAL_ADD_WORD = 11;
    protected static final int TRANSITION_MATERIAL_ENCRYPTED = 0;
    protected static final int TRANSITION_MATERIAL_MASK = 1;
    protected static final int TRANSITION_MATERIAL_ADD = 2;
    protected static final int TRANSITION_MATERIAL_SHIFT = 3;
    protected static final int DISPATCH_OUTLINER_ESTIMATED_CODE_PRESSURE = 4_000;
    protected static final int DISPATCH_OUTLINER_BLOCK_THRESHOLD = 12;
    protected static final int DISPATCH_OUTLINER_EDGE_THRESHOLD = 16;
    protected static final int DISPATCH_OUTLINER_HANDLER_THRESHOLD = 4;
    protected static final int TRANSITION_OUTLINER_ESTIMATED_CODE_PRESSURE = 24_000;
    protected static final int COMPACT_TRANSITION_WRAPPER_CODE_PRESSURE = 60_000;
    protected static final int TRANSITION_OUTLINER_BLOCK_THRESHOLD = 48;
    protected static final int TRANSITION_OUTLINER_EDGE_THRESHOLD = 80;
    protected static final int TRANSITION_OUTLINER_HANDLER_THRESHOLD = 8;
    protected static final int SMALL_TOKEN_DISPATCH_CASES = 4;
    protected static final int LARGE_METHOD_TOKEN_DISPATCH_CODE_PRESSURE = 60_000;
    protected static final int LARGE_METHOD_SMALL_TOKEN_DISPATCH_CASES = 5;
    protected static final int HOTSPOT_HUGE_METHOD_LIMIT_BYTES = 8_000;
    protected static final int JIT_BUDGET_TOKEN_DISPATCH_CASES = 2;
    protected static final int JIT_BUDGET_METHOD_BYTES = 7_200;
    protected static final int JIT_BUDGET_BLOCK_BYTES = 360;
    protected static final int JIT_BUDGET_EDGE_BYTES = 300;
    protected static final int JIT_BUDGET_HANDLER_BYTES = 540;
    protected static final int JIT_BUDGET_OUTLINED_BLOCK_BYTES = 180;
    protected static final int JIT_BUDGET_OUTLINED_EDGE_BYTES = 24;
    protected static final int JIT_BUDGET_OUTLINED_HANDLER_BYTES = 240;
    protected static final int JIT_BUDGET_MIN_POST_CFF_RESERVE_BYTES = 512;
    protected static final int JIT_BUDGET_POST_CFF_RESERVE_BYTES = 1_500;
    protected static final int OUTLINED_TRANSITION_CALLSITE_ESTIMATED_BYTES = 28;
    protected static final long METHOD_KEY_PC_MIX = 0x9E3779B97F4A7C15L;
    protected static final int CFF_ISLAND_REAL_DISPATCH_ROW_WORDS = 12;
    protected static final int CFF_ISLAND_FAKE_DISPATCH_ROW_WORDS = 14;
    protected static final int CFF_ISLAND_RESULT_ROW_WORDS = 10;
    protected static final int CFF_ISLAND_FAKE_BOUNCE_ROW_WORDS = 16;
    protected static final int CFF_ISLAND_POISON_ROW_WORDS = 10;
    protected static final int CFF_ISLAND_DENSE_ROUTER_ROW_WORDS = 2;
    protected static final int CFF_ISLAND_SPARSE_ROUTER_ROW_WORDS = 3;
    protected static final int CFF_ISLAND_SHARED_CALLSITE_EXTRA_INSNS = 3;
    protected static final int CFF_ISLAND_SHARED_HELPER_FIXED_INSNS = 96;
    protected static final int CFF_ISLAND_SHARED_DENSE_ROUTER_INSNS = 42;
    protected static final int CFF_ISLAND_SHARED_SPARSE_ROUTER_INSNS = 58;
    protected static final int CFF_ISLAND_COMPRESSED_BLOB_CHUNK_BYTES = 8192;
    protected static final int CFF_ISLAND_COMPRESSED_BLOB_CHUNK_CHARS = 8192;
    protected static final int CFF_ISLAND_COMPRESSED_INIT_FIXED_INSNS = 96;
    protected static final int CFF_ISLAND_COMPRESSED_INIT_CHUNK_INSNS = 24;
    protected static final int CFF_ISLAND_COMPRESSED_UNPACK_FIXED_INSNS = 180;
    protected static final int CFF_ISLAND_COMPRESSED_UNPACK_CHUNK_INSNS = 6;
    protected CffClassKeyTable activeKeyTable;

    public static final String CFF_ISLAND_DRY_RUN_STATS =
        "controlFlowFlattening.islandDryRunStats";
    public static final String CFF_ISLAND_MATERIAL_OP_DRY_RUN_STATS =
        "controlFlowFlattening.islandMaterialOpDryRunStats";

    protected static CffIslandDryRunStats cffIslandDryRunStats(PipelineContext pctx) {
        CffIslandDryRunStats stats = pctx.getPassData(CFF_ISLAND_DRY_RUN_STATS);
        if (stats == null) {
            stats = new CffIslandDryRunStats();
            pctx.putPassData(CFF_ISLAND_DRY_RUN_STATS, stats);
        }
        return stats;
    }

    protected static CffIslandMaterialOpDryRunStats cffIslandMaterialOpDryRunStats(
        PipelineContext pctx
    ) {
        CffIslandMaterialOpDryRunStats stats = pctx.getPassData(
            CFF_ISLAND_MATERIAL_OP_DRY_RUN_STATS
        );
        if (stats == null) {
            stats = new CffIslandMaterialOpDryRunStats();
            pctx.putPassData(CFF_ISLAND_MATERIAL_OP_DRY_RUN_STATS, stats);
        }
        return stats;
    }


    @SuppressWarnings("unchecked")
    protected void publishGeneratedHelperFlowKey(
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



    record BranchOperand(int storeOpcode, int loadOpcode, int size) {
        static final BranchOperand INT = new BranchOperand(
            Opcodes.ISTORE,
            Opcodes.ILOAD,
            1
        );
        static final BranchOperand REF = new BranchOperand(
            Opcodes.ASTORE,
            Opcodes.ALOAD,
            1
        );
    }

    record EdgeTarget(LabelNode label, AbstractInsnNode framePoint) {}

    record EdgeTargets(List<EdgeTarget> labels, int consumedValues) {}

    record EdgeStackSpill(StackSpill spill, int consumedValues) {}

    public record CffMethodMetadata(
        long methodSeed,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        Set<AbstractInsnNode> applicationInstructions,
        Map<AbstractInsnNode, CffInstructionState> instructionStates,
        CffClassKeyTable classKeyTable
    ) {}

    public record CffInstructionState(
        int blockIndex,
        int state,
        long selectorSeed,
        int guardKey,
        int pathKey,
        int blockKey,
        int pcToken,
        long methodKey,
        long methodSalt
    ) {}

    record CffBlockKeyState(
        int guardKey,
        int pathKey,
        int blockKey,
        int pcToken,
        long methodKey,
        long methodSalt
    ) {}

    record StackSpill(List<BasicValue> values, int[] locals) {}

    record ReflectiveTarget(String owner, String name) {}

    record CffClassIntegrityState(
        String owner,
        String globalFieldName,
        String nodeFieldName,
        String ownerRegistryFieldName,
        String helperName,
        String ticketHelperName,
        boolean interfaceOwner,
        int capacity,
        long rootMask,
        long globalInitial,
        long globalMutationMask,
        long nodeMutationMask,
        long layoutFingerprint,
        int[] nextClassIndex,
        long[] compileGlobalState,
        int[] compileRegistrySize,
        long[] compileLoadedBloom
    ) {
        int allocateClassIndex() {
            int index = nextClassIndex[0]++;
            if (index >= capacity) {
                throw new IllegalStateException(
                    "Class-integrity class index " + index + " exceeds capacity " + capacity
                );
            }
            return index;
        }

        long allocateExpectedRoot(
            int index,
            long initial,
            long delta,
            String owner,
            long requiredBloom,
            long classCodeHash
        ) {
            long globalOld = compileGlobalState[0];
            int ownerHash = owner.replace('/', '.').hashCode();
            int registrySize = ++compileRegistrySize[0];
            long loadedOld = compileLoadedBloom[0];
            long root = classIntegrityOrderRoot(
                initial,
                loadedOld & requiredBloom,
                delta,
                rootMask,
                layoutFingerprint,
                ownerHash,
                index,
                classCodeHash
            );
            compileGlobalState[0] =
                globalOld ^
                root ^
                delta ^
                Integer.toUnsignedLong(index) ^
                (long) ownerHash ^
                layoutFingerprint ^
                classCodeHash ^
                globalMutationMask;
            compileLoadedBloom[0] = loadedOld | classIntegrityLoadBit(index, ownerHash);
            return root;
        }

        static long classIntegrityOrderRoot(
            long nodeOld,
            long orderOld,
            long delta,
            long rootMask,
            long layoutFingerprint,
            int ownerHash,
            int index,
            long classCodeHash
        ) {
            return classIntegrityProjection(
                nodeOld ^
                orderOld ^
                delta ^
                layoutFingerprint ^
                classCodeHash ^
                rootMask ^
                (long) ownerHash ^
                Integer.toUnsignedLong(index)
            );
        }

        static long classIntegrityProjection(long value) {
            long x = value;
            x ^= x >>> 33;
            x *= 0xff51afd7ed558ccdL;
            x ^= x >>> 29;
            x *= 0xc4ceb9fe1a85ec53L;
            x ^= x >>> 32;
            return x & 0x0000FFFFFFFFFFFFL;
        }

        static long classIntegrityLoadBit(int index, int ownerHash) {
            int a = index * 31 + ownerHash;
            int b = index * 17 + Integer.rotateLeft(ownerHash, 11);
            int c = index * 43 + Integer.rotateLeft(ownerHash, 19);
            int d = index * 59 + Integer.rotateLeft(ownerHash, 5);
            return (1L << (a & 63)) |
                (1L << (b & 63)) |
                (1L << (c & 63)) |
                (1L << (d & 63));
        }
    }

    public record CffClassKeyTable(
        String owner,
        PipelineContext pctx,
        L1Class clazz,
        String objectFieldName,
        String intHelperName,
        String intHelperOwner,
        boolean intHelperInterfaceOwner,
        String objectHelperName,
        String controlHelperName,
        String tokenHelperName,
        String tokenMaterialHelperName,
        String tokenMaterialHelperOwner,
        boolean tokenMaterialHelperInterfaceOwner,
        String transitionMaterialHelperName,
        String transitionMaterialHelperOwner,
        boolean transitionMaterialHelperInterfaceOwner,
        String stepMaterialHelperName,
        String stepMaterialHelperOwner,
        boolean stepMaterialHelperInterfaceOwner,
        String keyTransferMaterialHelperName,
        String keyTransferMaterialHelperOwner,
        boolean keyTransferMaterialHelperInterfaceOwner,
        String keyTransferNoRuntimeMaterialHelperName,
        String keyTransferNoRuntimeMaterialHelperOwner,
        boolean keyTransferNoRuntimeMaterialHelperInterfaceOwner,
        String islandRuntimeSourceHelperName,
        String islandRuntimeSourceHelperOwner,
        boolean islandRuntimeSourceHelperInterfaceOwner,
        String islandMaterialHelperName,
        String islandMaterialHelperOwner,
        boolean islandMaterialHelperInterfaceOwner,
        String islandMaterialUnpackHelperName,
        String islandMaterialUnpackHelperOwner,
        boolean islandMaterialUnpackHelperInterfaceOwner,
        String digestHelperName,
        String dispatchHelperName,
        String methodKeyHelperName,
        String methodKeyHelperOwner,
        boolean methodKeyHelperInterfaceOwner,
        int[] tokenHelperCounter,
        List<MethodNode> tokenMaterialInitHelpers,
        int[] transitionMaterialCounter,
        List<MethodNode> transitionMaterialInitHelpers,
        int[] stepMaterialCounter,
        List<MethodNode> stepMaterialInitHelpers,
        int[] islandMaterialCounter,
        List<MethodNode> islandMaterialInitHelpers,
        int[] values,
        int[] objectValues,
        int clinitMask,
        int initCarrierLocal,
        LabelNode initStart,
        LabelNode initEnd,
        boolean generatedClinit,
        boolean interfaceOwner,
        CffClassIntegrityState classIntegrityState,
        int classIntegrityClassIndex,
        long classIntegrityRequiredOrderBloom,
        long classIntegrityExpectedRoot,
        int classCodeDigestLocal
    ) {
        int token(int value, long siteSeed) {
            long mixed = JvmPassBytecode.mix(siteSeed, value);
            return (int) (mixed & (values.length - 1));
        }
    }

    record CffSharedClassHelpers(
        String intHelperOwner,
        String intHelperName,
        boolean intHelperInterfaceOwner,
        String tokenMaterialHelperOwner,
        String tokenMaterialHelperName,
        boolean tokenMaterialHelperInterfaceOwner,
        String transitionMaterialHelperOwner,
        String transitionMaterialHelperName,
        boolean transitionMaterialHelperInterfaceOwner,
        String keyTransferMaterialHelperOwner,
        String keyTransferMaterialHelperName,
        boolean keyTransferMaterialHelperInterfaceOwner,
        String keyTransferNoRuntimeMaterialHelperOwner,
        String keyTransferNoRuntimeMaterialHelperName,
        boolean keyTransferNoRuntimeMaterialHelperInterfaceOwner,
        String stepMaterialHelperOwner,
        String stepMaterialHelperName,
        boolean stepMaterialHelperInterfaceOwner,
        String islandRuntimeSourceHelperOwner,
        String islandRuntimeSourceHelperName,
        boolean islandRuntimeSourceHelperInterfaceOwner,
        String islandMaterialHelperOwner,
        String islandMaterialHelperName,
        boolean islandMaterialHelperInterfaceOwner,
        String islandMaterialUnpackHelperOwner,
        String islandMaterialUnpackHelperName,
        boolean islandMaterialUnpackHelperInterfaceOwner,
        String methodKeyHelperOwner,
        String methodKeyHelperName,
        boolean methodKeyHelperInterfaceOwner
    ) {}

    record StepDryRun(
        int firstTinyUpdates,
        int secondTinyUpdates,
        int methodKeyUpdates
    ) {}

    record CompressedIslandMaterialBlob(
        int[] words,
        CffBlockKeyState[] decodeStates
    ) {}

    record IslandDispatchHelperPlan(
        String name,
        int dispatchCases,
        int helperInstructions
    ) {}

    public abstract String id();
    public abstract String name();
    public abstract TransformPhase phase();
    public abstract IRLevel requiredLevel();
    public abstract Set<String> dependsOn();
    public abstract void transformClass(TransformContext ctx);
    public abstract void transformMethod(TransformContext ctx);
    protected abstract void logIslandDryRunMethodStats(PipelineContext pctx, String methodKey);
    protected abstract boolean isApplicationMethod(
        PipelineContext pctx,
        L1Class clazz,
        L1Method method
    );
    protected abstract boolean hasApplicationCode(PipelineContext pctx, L1Class clazz);
    protected abstract void lowerStringConstantValuesForStringPass(PipelineContext pctx);
    protected abstract void lowerStringConstantValues(L1Class clazz);
    protected abstract boolean isStringConstantValue(FieldNode field);
    protected abstract void prepareClassKeyTables(PipelineContext pctx);
    protected abstract CffClassKeyTable ensureClassKeyTable(
        PipelineContext pctx,
        L1Class clazz
    );
    protected abstract CffSharedClassHelpers ensureSharedClassHelpers(
        PipelineContext pctx,
        L1Class clazz,
        long seed
    );
    protected abstract List<CffClassKeyTable> classKeyTables(PipelineContext pctx);
    protected abstract Set<LabelNode> rewriteInjectedMemberReflection(
        PipelineContext pctx,
        MethodNode mn
    );
    protected abstract boolean isGeneratedTableClassInit(
        PipelineContext pctx,
        L1Class clazz
    );
    protected abstract String uniqueFieldName(L1Class clazz, String base);
    protected abstract String uniqueMethodName(L1Class clazz, String base, String desc);
    protected abstract String packageName(String owner);
    protected abstract boolean hasAsmMethod(L1Class clazz, String name, String desc);
    protected abstract int[] classKeyTable(long seed);
    protected abstract int[] classKeyObjectTable(long seed, int[] classWords);
    protected abstract void installClassKeyTableInit(
        PipelineContext pctx,
        L1Class clazz,
        CffClassKeyTable table
    );
    protected abstract void installClassKeyIntHelper(
        PipelineContext pctx,
        L1Class clazz,
        String intHelperName,
        int access
    );
    protected abstract void installEncryptedTokenMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String tokenMaterialHelperName,
        int access
    );
    protected abstract void installStepMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    );
    protected abstract void emitStepMaterialWordLoad(
        InsnList insns,
        int wordsLocal,
        int baseLocal,
        int word
    );
    protected abstract void emitStepMaterialDecodedWordLoad(
        InsnList insns,
        int wordsLocal,
        int baseLocal,
        int decodeBaseLocal,
        int word
    );
    protected abstract void emitStepMaterialDecodeBase(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int wordsLocal,
        int baseLocal
    );
    protected abstract void emitStepMaterialRuntimeSource(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int threadLocal,
        int sourceLocal,
        int stackLocal,
        int stackLengthLocal,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    );
    protected abstract void emitStepMaterialWordMask(
        InsnList insns,
        int wordsLocal,
        int baseLocal,
        int decodeBaseLocal,
        int word
    );
    protected abstract void emitStepTinyUpdateFromMaterial(
        InsnList insns,
        int flagsLocal,
        int dstShift,
        int sourceShift,
        int opShift,
        int wordsLocal,
        int baseLocal,
        int decodeBaseLocal,
        int constantWord,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int valueLocal,
        int indexLocal,
        int sourceIndexLocal,
        int opLocal
    );
    protected abstract void emitStepMaterialTinyUpdate(
        InsnList insns,
        int dstIndexLocal,
        int sourceIndexLocal,
        int opLocal,
        int wordsLocal,
        int baseLocal,
        int decodeBaseLocal,
        int constantWord,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int valueLocal
    );
    protected abstract void emitLoadStepIndexedInt(
        InsnList insns,
        int indexLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal
    );
    protected abstract void emitStoreStepIndexedInt(
        InsnList insns,
        int indexLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int valueLocal
    );
    protected abstract void emitStepMaterialMethodConstantLoad(
        InsnList insns,
        int wordsLocal,
        int baseLocal,
        int decodeBaseLocal
    );
    protected abstract void emitStepMaterialMethodKeyUpdate(
        InsnList insns,
        int keyLocal,
        int sourceLocal,
        int opLocal
    );
    protected abstract void installTransitionMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String intHelperOwner,
        String intHelperName,
        boolean intHelperInterfaceOwner
    );
    protected abstract void installKeyTransferMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String tokenMaterialHelperOwner,
        String tokenMaterialHelperName,
        boolean tokenMaterialHelperInterfaceOwner,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    );
    protected abstract void installKeyTransferNoRuntimeMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String tokenMaterialHelperOwner,
        String tokenMaterialHelperName,
        boolean tokenMaterialHelperInterfaceOwner
    );
    protected abstract void insnDecodeKeyTransferWord(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int materialLocal,
        int cursorLocal,
        int baseCursorLocal,
        int modeLocal,
        int sourceLocal,
        int threadLocal,
        int stackLocal,
        int stackLengthLocal,
        String tokenMaterialHelperOwner,
        String tokenMaterialHelperName,
        boolean tokenMaterialHelperInterfaceOwner,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    );
    protected abstract void installCompressedIslandMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access
    );
    protected abstract void installCffIslandRuntimeSourceHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    );
    protected abstract void emitCffIslandRuntimeSourceCursorFromLocal(
        InsnList insns,
        int cursorLocal,
        int modeLocal,
        int sourceLocal
    );
    protected abstract void emitCffIslandCallsiteRuntimeSource(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int pcLocal,
        int domainLocal,
        int outLocal,
        int encodedCursor
    );
    protected abstract void emitCffIslandRuntimeSourceCursor(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int cursorLocal,
        int modeLocal,
        int sourceLocal,
        int threadLocal,
        int stackLocal,
        int stackLengthLocal,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    );
    protected abstract void installCompressedIslandMaterialUnpackHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access
    );
    protected abstract void emitKeyTransferRuntimeSourceCursor(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int baseCursorLocal,
        int modeLocal,
        int cursorLocal,
        int sourceLocal,
        int threadLocal,
        int stackLocal,
        int stackLengthLocal,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    );
    protected abstract void emitKeyTransferRuntimeBucketOffset(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int modeLocal,
        int offsetLocal,
        int sourceLocal,
        int threadLocal,
        int stackLocal,
        int stackLengthLocal,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    );
    protected abstract void emitKeyTransferMaterialDecodedWord(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int materialLocal,
        int cursorLocal,
        long methodSeed,
        String tokenMaterialHelperOwner,
        String tokenMaterialHelperName,
        boolean tokenMaterialHelperInterfaceOwner
    );
    protected abstract void emitTransitionMaterialBase(
        InsnList insns,
        int objectMaterialLocal,
        String intHelperOwner,
        String intHelperName,
        boolean intHelperInterfaceOwner,
        int materialLocal,
        int rowLocal,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int baseLocal,
        TransitionMaterialRowCursor rowCursor
    );
    protected abstract void emitTransitionMaterialMethodKeyFold(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int keyLocal,
        TransitionMaterialRowCursor rowCursor
    );
    protected abstract void emitTransitionMaterialDecodedWord(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int word,
        TransitionMaterialRowCursor rowCursor
    );
    protected abstract void emitTransitionMaterialMaskFromBase(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int word,
        TransitionMaterialRowCursor rowCursor
    );
    protected abstract void emitTransitionMaterialWordLoad(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int offset,
        TransitionMaterialRowCursor rowCursor
    );
    protected abstract void emitTokenMaterialWordLoad(InsnList insns, int rowLocal, int cursorLocal);
    protected abstract void emitPackedMaterialWordLoad(InsnList insns);
    protected abstract void emitTokenMaterialClassMask(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal
    );
    protected abstract void emitTokenMaterialObjectMask(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int indexLocal,
        int packedLocal,
        int epochLocal,
        int encodedLocal,
        int resultLocal,
        int nextEpochLocal,
        int nextEncodedLocal,
        int cellLocal,
        int currentMaskLocal
    );
    protected abstract void emitTokenMaterialControlMask(
        InsnList insns,
        int rowLocal,
        int baseLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal
    );
    protected abstract int registerEncryptedTokenMaterial(
        CffClassKeyTable table,
        int encrypted,
        long seed
    );
    protected abstract MethodNode tokenMaterialInitHelper(
        CffClassKeyTable table,
        int chunk
    );
    protected abstract int registerTransitionMaterialRow(
        CffClassKeyTable table,
        int state,
        DispatchTarget target,
        EdgeKind edgeKind,
        CffBlockKeyState sourceKeys,
        CffBlockKeyState targetKeys,
        long methodSeed,
        long stepSeed,
        long targetDispatchSeed,
        EdgeRole role
    );
    protected abstract void emitPackedMaterialLongStores(
        InsnList init,
        int arrayLocal,
        int base,
        int[] values
    );
    protected abstract int[] transitionMaterialValues(
        int state,
        DispatchTarget target,
        EdgeKind edgeKind,
        CffBlockKeyState sourceKeys,
        CffBlockKeyState targetKeys,
        long methodSeed,
        long stepSeed,
        long targetDispatchSeed,
        EdgeRole role
    );
    protected abstract void putTransitionMaterialWord(
        int[] values,
        int word,
        int targetWord,
        int sourceBase,
        long seed
    );
    protected abstract int transitionMaterialWordOffset(int word, int part);
    protected abstract MethodNode transitionMaterialInitHelper(
        CffClassKeyTable table,
        int chunk
    );
    protected abstract int registerStepMaterialRow(
        CffClassKeyTable table,
        long seed,
        EdgeRole role
    );
    protected abstract int[] stepMaterialValues(long seed, EdgeRole role);
    protected abstract int stepMaterialDecodeBase(
        long key,
        int guard,
        int path,
        int block,
        int add,
        int multiply,
        int shift
    );
    protected abstract int stepMaterialWordMask(
        int base,
        int add,
        int multiply,
        int shift,
        int word
    );
    protected abstract MethodNode stepMaterialInitHelper(
        CffClassKeyTable table,
        int chunk
    );
    protected abstract int registerCompressedIslandMaterialBlob(
        CffClassKeyTable table,
        CompressedIslandMaterialBlob blob,
        long seed
    );
    protected abstract int cffIslandRuntimeSourceMode(int materialWords);
    protected abstract int cffIslandRuntimeSourceBucketCount(int runtimeSourceMode);
    protected abstract int encodeCffIslandMaterialCursor(
        int cursor,
        int runtimeSourceMode
    );
    protected abstract String[] encodeCompressedIslandMaterialBlob(
        CffClassKeyTable table,
        CompressedIslandMaterialBlob blob,
        long seed,
        int cursor
    );
    protected abstract int compressedIslandMaterialRuntimeMask(
        CffClassKeyTable table,
        CffBlockKeyState keyState,
        int cursor,
        int wordIndex
    );
    protected abstract int compressedIslandMaterialStaticMask(long seed, int wordIndex);
    protected abstract void emitCompressedIslandMaterialWordDecode(
        InsnList insns,
        CffClassKeyTable table,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int sourceLocal,
        int cursor,
        int wordIndex,
        int resultLocal
    );
    protected abstract MethodNode islandMaterialInitHelper(
        CffClassKeyTable table,
        int chunk
    );
    protected abstract void installMethodKeyFromStateHelper(
        PipelineContext pctx,
        L1Class clazz,
        String methodKeyHelperName,
        int access
    );
    protected abstract MethodNode findOrCreateClassInit(L1Class clazz);
    protected abstract MethodNode findClassInit(L1Class clazz);
    protected abstract LabelNode protectedStartLabel(
        L1Class clazz,
        L1Method method,
        MethodNode mn,
        int keyLocal
    );
    protected abstract AbstractInsnNode firstRealAfterKeyInit(
        MethodNode mn,
        int keyLocal
    );
    protected abstract void publishMethodMetadata(
        PipelineContext pctx,
        L1Class clazz,
        L1Method method,
        long methodSeed,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        List<Block> blocks,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, DispatchTarget> dispatchByLabel,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        CffClassKeyTable classKeyTable
    );
    protected abstract AbstractInsnNode constructorInitInsn(L1Class clazz, MethodNode mn);
    protected abstract Map<LabelNode, String> handlerReachableDomains(
        MethodNode mn,
        List<Block> blocks,
        Map<LabelNode, LabelNode> aliases,
        Set<LabelNode> handlerBodies
    );
    protected abstract void addHandlerDomain(
        Map<LabelNode, String> domains,
        LabelNode label,
        String token
    );
    protected abstract Set<LabelNode> reachableFrom(
        MethodNode mn,
        LabelNode start,
        Set<LabelNode> blockLabels,
        Map<LabelNode, Block> byLabel,
        Map<LabelNode, LabelNode> nextByLabel,
        Map<LabelNode, LabelNode> aliases
    );
    protected abstract List<LabelNode> blockSuccessors(
        MethodNode mn,
        Block block,
        Map<LabelNode, LabelNode> nextByLabel
    );
    protected abstract LabelNode canonicalLabel(
        LabelNode label,
        Map<LabelNode, LabelNode> aliases
    );
    protected abstract void completeBlockLabelAliases(
        MethodNode mn,
        LabelNode start,
        List<Block> blocks,
        Map<LabelNode, LabelNode> aliases
    );
    protected abstract boolean isZeroStackLabel(
        LabelNode label,
        Set<LabelNode> zeroStackLabels
    );
    protected abstract BlockPlan buildBlocks(
        MethodNode mn,
        LabelNode start,
        Set<LabelNode> extraLeaders,
        Set<LabelNode> zeroStackLabels,
        Set<LabelNode> linearLeaders,
        CffFrameAnalysis frames
    );
    protected abstract boolean hasRealInstruction(
        LabelNode label,
        AbstractInsnNode endExclusive
    );
    protected abstract boolean useSubdispatcherOutliner(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    );
    protected abstract boolean useTransitionOutliner(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    );
    protected abstract boolean useOutliner(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges,
        int blockThreshold,
        int edgeThreshold,
        int handlerThreshold,
        int codePressureThreshold
    );
    protected abstract int estimatedOutlinerCodePressure(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    );
    protected abstract int smallTokenDispatchCaseLimit(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    );
    protected abstract boolean hasBackwardBlockEdge(MethodNode mn, List<Block> blocks);
    protected abstract boolean isBackwardBlockTarget(
        Map<LabelNode, Integer> blockIndex,
        int sourceIndex,
        LabelNode target
    );
    protected abstract Set<LabelNode> linearZeroStackLeaders(
        MethodNode mn,
        LabelNode start,
        CffFrameAnalysis frames
    );
    protected abstract boolean normalizeNonZeroStackControlTargets(
        PipelineContext pctx,
        MethodNode mn,
        LabelNode start,
        CffFrameAnalysis frames
    );
    protected abstract EdgeTargets controlEdgeTargets(
        MethodNode mn,
        AbstractInsnNode insn
    );
    protected abstract int consumedStackValueCount(int opcode);
    protected abstract StackSpill spillForStackShape(
        MethodNode mn,
        List<BasicValue> stack,
        Map<String, StackSpill> spillsByShape
    );
    protected abstract String stackShapeSignature(List<BasicValue> stack);
    protected abstract InsnList spillStoresBeforeControl(
        MethodNode mn,
        AbstractInsnNode control,
        StackSpill spill,
        int consumedValues
    );
    protected abstract BranchOperand[] branchOperands(AbstractInsnNode control, int consumedValues);
    protected abstract int[] allocateOperandLocals(MethodNode mn, BranchOperand[] operands);
    protected abstract StackSpill allocateStackSpill(MethodNode mn, List<BasicValue> stack);
    protected abstract InsnList spillStores(StackSpill spill);
    protected abstract InsnList spillLoads(StackSpill spill);
    protected abstract int maxSpillSlots(Map<LabelNode, StackSpill> spills);
    protected abstract int storeOpcode(BasicValue value);
    protected abstract int loadOpcode(BasicValue value);
    protected abstract int typedOpcode(BasicValue value, int baseOpcode);
    protected abstract boolean allSwitchTargetsZero(
        LabelNode dflt,
        List<LabelNode> labels,
        Set<LabelNode> zeroStackLabels
    );
    protected abstract void insertHandlerBridges(
        MethodNode mn,
        List<HandlerBridge> handlerBridges,
        int exceptionLocal,
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
        Map<LabelNode, DispatchTarget> dispatchByLabel,
        Map<DispatchTarget, Long> dispatchSeedByTarget,
        Set<LabelNode> runtimeKeyLabels,
        long methodSeed,
        long salt,
        CffTransitionOutliner.TransitionOutliner dispatcherOutliner,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    );
    protected abstract void insertIslandDispatchers(
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
    );
    protected abstract void rewriteBlockExit(
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
    );
    protected abstract void rewriteLookupSwitch(
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
    );
    protected abstract void rewriteTableSwitch(
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
    );
    protected abstract <T> T labelValue(Map<LabelNode, T> values, LabelNode label);
    protected abstract int requireState(LabelNode target, Integer state);
    protected abstract DispatchTarget requireTarget(
        LabelNode label,
        DispatchTarget target
    );
    protected abstract CffBlockKeyState requireBlockKey(
        LabelNode label,
        CffBlockKeyState keyState
    );
    protected abstract InsnList transition(
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
    );
    protected abstract LabelNode transitionJumpTarget(
        DispatchTarget target,
        EdgeKind edgeKind,
        long edgeSeed
    );
    protected abstract void emitTransitionCore(
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
    );
    protected abstract InsnList buildIslandDispatcher(
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
    );
    protected abstract void emitFakeCaseBounce(
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
    );
    protected abstract long caseSelectorSeed(
        IslandGroup group,
        LabelNode label,
        int state,
        int island
    );
    protected abstract long fakeCaseSelectorSeed(
        IslandGroup group,
        int fakeState,
        int island,
        int fakeIndex
    );
    protected abstract InsnList aliasHub(
        IslandGroup group,
        int alias,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal
    );
    protected abstract void emitOpaqueHubBranch(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        LabelNode hub
    );
    protected abstract void emitDomainDispatch(
        InsnList insns,
        int domainLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        IslandGroup group,
        LabelNode poison
    );
    protected abstract void emitEncodedDomainIfChain(
        InsnList insns,
        int domainLocal,
        LabelNode[] islandLabels,
        LabelNode poison,
        long orderSeed
    );
    protected abstract void emitTokenDispatch(
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
    );
    protected abstract void emitSmallTokenDispatch(
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
    );
    protected abstract long tokenDispatchSeed(long groupSalt, int island);
    protected abstract long tokenDispatchSeed(
        IslandGroup group,
        int island,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel
    );
    protected abstract int maskedDispatchToken(
        int token,
        CffBlockKeyState keyState,
        long seed
    );
    protected abstract int dispatchTokenMask(
        int token,
        CffBlockKeyState keyState,
        long seed
    );
    protected abstract int dispatchMethodKeyFold(long keyValue, long seed);
    protected abstract void emitDispatchTokenMask(
        InsnList insns,
        int pcLocal,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int dataLocal,
        long seed,
        int scratchLocal
    );
    protected abstract void emitDispatchMethodKeyFold(InsnList insns, int keyLocal, long seed);
    protected abstract void emitInitKeys(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract void emitClassKeyMixIntoLocals(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract void emitClassKeyWord(
        InsnList insns,
        CffClassKeyTable table,
        int keyLocal,
        int token,
        long seed,
        int scratchLocal
    );
    protected abstract void emitInitPathKey(
        InsnList insns,
        int pathKeyLocal,
        int keyLocal,
        long seed
    );
    protected abstract void emitInitBlockKey(
        InsnList insns,
        int blockKeyLocal,
        int guardLocal,
        int keyLocal,
        long seed
    );
    protected abstract void emitInitGuard(
        InsnList insns,
        int guardLocal,
        int keyLocal,
        long seed
    );
    protected abstract void emitInitGuardHighLow(InsnList insns, int keyLocal);
    protected abstract void emitInitGuardLowHigh(InsnList insns, int keyLocal);
    protected abstract void emitInitGuardSeededXor(
        InsnList insns,
        int keyLocal,
        long seed
    );
    protected abstract void emitInitGuardSeededAdd(
        InsnList insns,
        int keyLocal,
        long seed
    );
    protected abstract void foldTopInt16(InsnList insns);
    protected abstract void emitStorePc(
        InsnList insns,
        int pcLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyLocal,
        int state,
        CffBlockKeyState targetKeys,
        long methodSeed,
        long selectorSeed,
        int scratchLocal
    );
    protected abstract void emitStoreDomain(
        InsnList insns,
        int domainLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyLocal,
        int island,
        int domainToken,
        CffBlockKeyState targetKeys,
        long methodSeed,
        long domainSeed,
        int scratchLocal
    );
    protected abstract long routeTokenSeed(
        long methodSeed,
        long stepSeed,
        int state,
        DispatchTarget target
    );
    protected abstract int routeTokenBase(CffBlockKeyState keyState, long seed);
    protected abstract int routeTokenMask(
        CffBlockKeyState keyState,
        long routeSeed,
        long tokenSeed
    );
    protected abstract int routeTokenMaskFromBase(int base, long tokenSeed);
    protected abstract void emitRouteTokenBase(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int routeBaseLocal,
        long seed,
        int scratchLocal
    );
    protected abstract void emitStoreRouteToken(
        InsnList insns,
        int dstLocal,
        int token,
        CffBlockKeyState targetKeys,
        int routeBaseLocal,
        long routeSeed,
        long tokenSeed
    );
    protected abstract void emitStoreTransitionBaseToken(
        InsnList insns,
        int dstLocal,
        int token,
        CffBlockKeyState sourceKeys,
        int keyBaseLocal,
        long baseSeed,
        long tokenSeed
    );
    protected abstract void emitRouteTokenMaskFromBase(
        InsnList insns,
        int routeBaseLocal,
        long tokenSeed
    );
    protected abstract void emitStoreMethodKey(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        CffBlockKeyState targetKeys
    );
    protected abstract void emitStoreMethodKeyFromBase(
        InsnList insns,
        int keyLocal,
        int keyBaseLocal,
        CffBlockKeyState sourceKeys,
        CffBlockKeyState targetKeys,
        long baseSeed,
        long seed
    );
    protected abstract void emitDecodedMethodKeyWordFromBase(
        InsnList insns,
        int targetWord,
        CffBlockKeyState sourceKeys,
        long baseSeed,
        int keyBaseLocal,
        long seed
    );
    protected abstract void emitMethodKeyFromDecodedState(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        long methodSalt
    );
    protected abstract long methodKeyLongMask(CffBlockKeyState keyState, long seed);
    protected abstract void emitMethodKeyLongMask(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        long seed
    );
    protected abstract void emitEncryptedToken(
        InsnList insns,
        int token,
        CffBlockKeyState expectedKeys,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract int classTokenMask(CffBlockKeyState keyState, long seed);
    protected abstract int classObjectTokenMask(CffBlockKeyState keyState, long seed);
    protected abstract void emitClassTokenMask(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract void emitClassKeyWordsLoad(InsnList insns, CffClassKeyTable table);
    protected abstract void emitClassKeyWordsLoad(InsnList insns, int objectMaterialLocal);
    protected abstract void emitClassObjectTokenMaskAndUpdate(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract int cffObjectCellEpoch(int mask, int index);
    protected abstract int cffObjectCellMask(int epoch);
    protected abstract void emitCffObjectCellMask(InsnList insns);
    protected abstract int classStateTableIndex(CffBlockKeyState keyState, long seed);
    protected abstract void emitClassStateTableIndex(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract int classStateDigest(CffBlockKeyState keyState, long seed);
    protected abstract void emitClassStateDigest(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    );
    protected abstract CffBlockKeyState initialKeyState(long keyValue, long seed);
    protected abstract int initialGuardKey(long keyValue, long seed);
    protected abstract int foldInt16(int value);
    protected abstract int initialPathKey(long keyValue, long seed);
    protected abstract int initialBlockKey(long keyValue, int guardKey, long seed);
    protected abstract int classKeyWord(CffClassKeyTable table, long keyValue, long seed);
    protected abstract int keyMixInt(long keyValue, long siteSeed);
    protected abstract int methodKeyFold(long keyValue, long seed);
    protected abstract void emitMethodKeyFold(InsnList insns, int keyLocal, long seed);
    protected abstract void emitDecodeBlockKeys(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int keyTmpLocal,
        int keyBaseLocal,
        CffBlockKeyState sourceKeys,
        CffBlockKeyState targetKeys,
        long methodSeed,
        long seed,
        EdgeRole role
    );
    protected abstract long transitionBaseSeed(long seed, EdgeRole role);
    protected abstract void emitDecodeBlockKeyWordCompact(
        InsnList insns,
        int dstLocal,
        int targetWord,
        CffBlockKeyState sourceKeys,
        long baseSeed,
        int keyBaseLocal,
        long seed
    );
    protected abstract void emitCommitDecodedKeys(
        InsnList insns,
        int keyTmpLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal
    );
    protected abstract CffBlockKeyState transitionBridgeKeyState(
        CffBlockKeyState sourceKeys,
        CffBlockKeyState targetKeys,
        long methodSeed,
        long seed,
        EdgeRole role
    );
    protected abstract void emitDecodeBlockKeyWord(
        InsnList insns,
        int dstLocal,
        int targetWord,
        CffBlockKeyState sourceKeys,
        long baseSeed,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyBaseLocal,
        long seed
    );
    protected abstract int controlTokenBase(
        CffBlockKeyState keyState,
        long seed
    );
    protected abstract int controlTokenMaskFromBase(int base, long seed);
    protected abstract int compactControlTokenBase(
        CffBlockKeyState keyState,
        long seed
    );
    protected abstract void emitCompactControlTokenBase(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyBaseLocal,
        long seed,
        int scratchLocal
    );
    protected abstract int controlTokenMask(
        CffBlockKeyState keyState,
        long seed
    );
    protected abstract void emitControlTokenMask(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    );
    protected abstract void emitControlTokenBase(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyBaseLocal,
        long seed
    );
    protected abstract void emitControlTokenMaskFromBase(
        InsnList insns,
        int keyBaseLocal,
        long seed
    );
    protected abstract void emitEncodedStateValue(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int state,
        long selectorSeed
    );
    protected abstract void emitEncodedDomainValue(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int island,
        long domainSeed
    );
    protected abstract void emitKeyPredicate(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    );
    protected abstract void emitEncodedKeyedValue(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int value,
        long seed
    );
    protected abstract void emitClassDecodedInt(
        InsnList insns,
        int value,
        long siteSeed
    );
    protected abstract void emitKeyedTableIndex(
        InsnList insns,
        int keyLocal,
        int token,
        long siteSeed
    );
    protected abstract void emitKeyMixInt(InsnList insns, int keyLocal, long siteSeed);
    protected abstract void emitKeyDigest(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    );
    protected abstract void emitMaterializedStepKeys(
        InsnList insns,
        CffClassKeyTable table,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int outLocal,
        long seed,
        EdgeRole role
    );
    protected abstract void emitStepKeys(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        EdgeRole role
    );
    protected abstract StepDryRun stepDryRun(long seed, EdgeRole role);
    protected abstract void emitStoreKeyTiny(
        InsnList insns,
        int dstLocal,
        int sourceLocal,
        long seed
    );
    protected abstract int selectStepKeyIndex(long seed);
    protected abstract int selectDifferentStepKeyIndex(int firstIndex, long seed);
    protected abstract int stepKeyLocal(
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int index
    );
    protected abstract int stepSourceKeyLocal(
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int dstIndex,
        long seed
    );
    protected abstract void emitStepMethodKeyTiny(
        InsnList insns,
        int keyLocal,
        int sourceLocal,
        long seed
    );
    protected abstract int nonZeroInt(long value);
    protected abstract long nonZeroLong(long value);
    protected abstract DispatchPlan buildDispatchPlan(
        List<Block> blocks,
        CffFrameAnalysis frames,
        long salt,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, String> handlerDomains,
        SyntheticNoiseBudget syntheticNoiseBudget
    );
    protected abstract Map<LabelNode, CffBlockKeyState> buildBlockKeyStates(
        List<Block> blocks,
        Map<LabelNode, LabelNode> aliases,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, DispatchTarget> dispatchByLabel,
        long salt
    );
    protected abstract Map<DispatchTarget, Long> buildDispatchSeedByTarget(
        DispatchPlan dispatchPlan,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel
    );
    protected abstract long requireDispatchSeed(
        DispatchTarget target,
        Map<DispatchTarget, Long> dispatchSeedByTarget
    );
    protected abstract void installEntryKeyState(
        List<Block> blocks,
        DispatchPlan dispatchPlan,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long methodSeed,
        boolean externalEntrySeed
    );
    protected abstract long entryInitSeed(
        long groupSalt,
        boolean externalEntrySeed,
        long methodSeed
    );
    protected abstract Set<LabelNode> runtimeKeyLabels(
        PipelineContext pctx,
        MethodNode mn,
        List<Block> blocks,
        Map<LabelNode, LabelNode> aliases
    );
    protected abstract boolean requiresRuntimeKeys(PipelineContext pctx, AbstractInsnNode insn);
    protected abstract boolean isNumericConstantSite(AbstractInsnNode insn);
    protected abstract void rewriteKeyedCallTransfers(
        PipelineContext pctx,
        MethodNode mn,
        List<Block> blocks,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long salt
    );
    protected abstract void rewriteDetachedPackedKeyedCallTransfers(
        PipelineContext pctx,
        MethodNode mn,
        Map<AbstractInsnNode, Block> blockByInstruction,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long salt
    );
    protected abstract Map<AbstractInsnNode, Long> generatedKeyLoadTargetSeeds(PipelineContext pctx);
    protected abstract void rewritePackedGeneratedKeyLoads(
        PipelineContext pctx,
        MethodNode mn,
        AbstractInsnNode call,
        int keyLocal,
        Map<AbstractInsnNode, Block> blockByInstruction,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long targetSeed,
        int methodKeyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        long salt
    );
    protected abstract boolean rewriteStoredPackedGeneratedKeyLoad(
        PipelineContext pctx,
        MethodNode mn,
        AbstractInsnNode call,
        int storedLocal,
        Map<AbstractInsnNode, Block> blockByInstruction,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long targetSeed,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        long salt
    );
    protected abstract Map<AbstractInsnNode, Block> instructionBlockMap(List<Block> blocks);
    protected abstract void rewriteDetachedGeneratedKeyLoads(
        PipelineContext pctx,
        MethodNode mn,
        Map<AbstractInsnNode, Long> generatedKeyLoadSeeds,
        Map<AbstractInsnNode, Block> blockByInstruction,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long salt
    );
    protected abstract boolean isLiveInstruction(MethodNode mn, AbstractInsnNode insn);
    protected abstract Block nearbyBlock(
        AbstractInsnNode insn,
        Map<AbstractInsnNode, Block> blockByInstruction
    );
    protected abstract void rewriteReflectiveGeneratedKeyLoads(
        PipelineContext pctx,
        MethodNode mn,
        Map<AbstractInsnNode, Long> generatedKeyLoadSeeds,
        Map<AbstractInsnNode, Block> blockByInstruction,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long salt
    );
    protected abstract Long reflectivePackedTargetSeed(PipelineContext pctx, AbstractInsnNode keyLoad);
    protected abstract MethodInsnNode nextReflectiveInvoke(AbstractInsnNode keyLoad);
    protected abstract MethodInsnNode previousReflectiveLookup(MethodInsnNode invoke);
    protected abstract ReflectiveTarget reflectiveTarget(MethodInsnNode lookup);
    protected abstract InsnList cloneInsnList(InsnList source);
    protected abstract Long keyedTargetSeed(PipelineContext pctx, AbstractInsnNode insn);
    protected abstract Long keyedTargetSeed(
        PipelineContext pctx,
        String owner,
        String name,
        String desc
    );
    protected abstract Long packedCallTargetSeed(PipelineContext pctx, String owner, String name, String desc);
    protected abstract boolean isVirtualFamilyMethod(L1Class clazz, L1Method method);
    protected abstract L1Method findAsmMethod(L1Class clazz, String name, String desc);
    protected abstract boolean usesExternalEntrySeed(PipelineContext pctx, L1Class clazz, L1Method method);
    protected abstract AbstractInsnNode previousReal(AbstractInsnNode start);
    protected abstract boolean isGeneratedKeyLoad(
        PipelineContext pctx,
        AbstractInsnNode insn,
        int keyLocal
    );
    protected abstract boolean isKeyLocalLoad(AbstractInsnNode insn, int keyLocal);
    protected abstract long incomingRawForCanonical(long targetSeed);
    protected abstract InsnList buildKeyTransferReplacementForLoad(
        PipelineContext pctx,
        AbstractInsnNode keyLoad,
        Map<AbstractInsnNode, Block> blockByInstruction,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long targetSeed,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        long salt
    );
    protected abstract InsnList buildKeyTransferReplacement(
        PipelineContext pctx,
        Block block,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        long value,
        long targetSeed,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyTmpLocal,
        long salt,
        AbstractInsnNode sourceInsn
    );
    protected abstract void emitMaterializedDynamicBoundDecodedLong(
        InsnList insns,
        PipelineContext pctx,
        long value,
        long targetSeed,
        CffBlockKeyState expectedKeys,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        AbstractInsnNode sourceInsn,
        int scratchLocal
    );
    protected abstract long keyTransferSourceSeed(AbstractInsnNode insn);
    protected abstract AbstractInsnNode keyTransferSourceContext(AbstractInsnNode insn);
    protected abstract boolean isLongBoxCall(AbstractInsnNode insn);
    protected abstract boolean isLambdaMetafactory(InvokeDynamicInsnNode indy);
    protected abstract boolean isReflectiveInvokeCall(MethodInsnNode call);
    protected abstract boolean isReflectiveLookupCall(MethodInsnNode call);
    protected abstract boolean isAsyncBoundaryCall(MethodInsnNode call);
    protected abstract boolean isStackTraceBoundaryCall(MethodInsnNode call);
    protected abstract boolean isExceptionBoundaryCall(MethodInsnNode call);
    protected abstract boolean isAsyncCarrierType(String internalName);
    protected abstract int keyTransferRuntimeSourceMode(AbstractInsnNode insn);
    protected abstract int registerKeyTransferMaterialWord(
        CffClassKeyTable table,
        int word,
        CffBlockKeyState expectedKeys,
        long materialSeed,
        long methodSeed,
        int runtimeSourceMode
    );
    protected abstract int registerKeyTransferMaterialWordBucket(
        CffClassKeyTable table,
        int word,
        CffBlockKeyState expectedKeys,
        long materialSeed,
        long methodSeed
    );
    protected abstract int keyTransferRuntimeSourceBucketCount(int runtimeSourceMode);
    protected abstract long keyTransferRuntimeSourceBucketSeed(
        long materialSeed,
        int runtimeSourceMode,
        int bucket
    );
    protected abstract int encodeKeyTransferMaterialCursor(
        int cursor,
        int runtimeSourceMode
    );
    protected abstract void emitDynamicBoundDecodedLong(
        InsnList insns,
        long value,
        CffBlockKeyState expectedKeys,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract void emitEncryptedBoundToken(
        InsnList insns,
        int token,
        CffBlockKeyState expectedKeys,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract void emitDynamicDecodedLong(
        InsnList insns,
        long value,
        CffBlockKeyState expectedKeys,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    );
    protected abstract CffBlockKeyState syntheticHandlerSourceKey(
        long methodSeed,
        long salt,
        LabelNode handler
    );
    protected abstract CffBlockKeyState blockKeyState(long seed, int pcToken);
    protected abstract long methodKeyFromBlock(
        int guardKey,
        int pathKey,
        int blockKey,
        int pcToken,
        long methodSalt
    );
    protected abstract CffBlockKeyState firstIslandKeyState(
        IslandGroup group,
        int island,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel
    );
    protected abstract LabelNode firstIslandLabel(IslandGroup group, int island);
    protected abstract int domainToken(long groupSalt, int island);
    protected abstract int fakeDispatchToken(
        long groupSalt,
        int fakeState,
        int island,
        int fakeIndex
    );
    protected abstract long caseSelectorSeed(
        long groupSalt,
        LabelNode label,
        int state,
        int island
    );
    protected abstract Block firstNonHandler(List<Block> blocks);
    protected abstract int shift(long seed, int base);
    protected abstract LabelNode ensureLabelBefore(MethodNode mn, AbstractInsnNode node);
    protected abstract LabelNode ensureLabelAfter(MethodNode mn, AbstractInsnNode node);
    protected abstract AbstractInsnNode firstReal(MethodNode mn);
    protected abstract AbstractInsnNode nextReal(AbstractInsnNode start);
    protected abstract AbstractInsnNode lastRealBefore(MethodNode mn, AbstractInsnNode endExclusive);
    protected abstract boolean before(AbstractInsnNode left, AbstractInsnNode right);
    protected abstract boolean terminates(int opcode);
    protected abstract boolean isControlTransfer(AbstractInsnNode insn);
    protected abstract int invertJumpOpcode(int opcode);
    protected abstract void emitInitTransitionOut(InsnList insns, int outLocal);
    protected abstract void emitTransitionOutStores(
        InsnList insns,
        int outLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal
    );
    protected abstract void emitTransitionOutStores(
        InsnList insns,
        int outLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        boolean includeDomain
    );
    protected abstract void emitTransitionOutStoresWithResult(
        InsnList insns,
        int outLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int resultToken
    );
    protected abstract void emitTransitionOutStoresWithResultLocal(
        InsnList insns,
        int outLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int resultLocal
    );
    protected abstract void emitTransitionOutStoresWithMaskedResult(
        InsnList insns,
        int outLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int keyLocal,
        int resultOrdinal,
        long resultMaskSeed
    );
    protected abstract void emitTransitionOutStoresWithMaskedResultLocal(
        InsnList insns,
        int outLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int keyLocal,
        int resultLocal,
        long resultMaskSeed
    );
    protected abstract void emitResultRouteMask(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        long seed
    );
    protected abstract void emitTransitionOutPairStore(
        InsnList insns,
        int outLocal,
        int index,
        int highLocal,
        int lowLocal
    );
    protected abstract void emitTransitionOutHighStore(
        InsnList insns,
        int outLocal,
        int index,
        int highLocal
    );
    protected abstract void emitTransitionOutPairStoreConstLow(
        InsnList insns,
        int outLocal,
        int index,
        int highLocal,
        int low
    );
    protected abstract void emitTransitionOutPairStoreLocalLow(
        InsnList insns,
        int outLocal,
        int index,
        int highLocal,
        int lowLocal
    );
    protected abstract void emitTransitionOutLoads(
        InsnList insns,
        int outLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal
    );
    protected abstract void emitTransitionOutLoads(
        InsnList insns,
        int outLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        boolean includeDomain
    );
    protected abstract void emitTransitionOutPairLoad(
        InsnList insns,
        int outLocal,
        int index,
        int highLocal,
        int lowLocal
    );
    protected abstract void emitTransitionOutHighLoad(
        InsnList insns,
        int outLocal,
        int index,
        int highLocal
    );
    protected abstract void emitTransitionOutLowLoad(
        InsnList insns,
        int outLocal,
        int index,
        int lowLocal
    );
    protected abstract void emitPackedTransitionOutLoads(
        InsnList insns,
        int outLocal,
        int tokenLocal,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal
    );
    protected abstract void emitPackedTransitionOutLoad(
        InsnList insns,
        int outLocal,
        int tokenLocal,
        int index,
        int dstLocal
    );
    protected abstract void emitPackedTransitionOutValue(
        InsnList insns,
        int outLocal,
        int tokenLocal,
        int index
    );
    protected abstract void emitPackedTransitionOutStore(
        InsnList insns,
        int outLocal,
        int tokenLocal,
        int index,
        int valueLocal
    );
    protected abstract void emitPackedTransitionOutStoreConst(
        InsnList insns,
        int outLocal,
        int tokenLocal,
        int index,
        int value
    );
    protected abstract void emitTransitionTokenMask(
        InsnList insns,
        int tokenLocal,
        int index
    );
}
