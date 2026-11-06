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


abstract class CffMaterialTables extends CffClassSetup {

    protected void installClassKeyTableInit(
        PipelineContext pctx,
        L1Class clazz,
        CffClassKeyTable table
    ) {
        MethodNode clinit = findOrCreateClassInit(clazz);
        InsnList init = new InsnList();
        int arrayLocal = table.initCarrierLocal();
        int classWordsLocal = arrayLocal + 1;
        int classIntegrityRootLocal = classWordsLocal + 1;
        long initialState = classIntegrityInitialState(table);
        long rootDelta = JvmPassBytecode.mix(table.clinitMask(), 0x47313844454C5441L);
        init.add(table.initStart());
        JvmPassBytecode.pushInt(init, TOKEN_MATERIAL_CARRIER_SIZE);
        init.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        init.add(new VarInsnNode(Opcodes.ASTORE, arrayLocal));
        for (int i = 0; i < table.objectValues().length; i++) {
            int epoch = cffObjectCellEpoch(table.clinitMask(), i);
            int encoded = table.objectValues()[i] ^ cffObjectCellMask(epoch);
            long packed = (((long) encoded) << 32) ^ Integer.toUnsignedLong(epoch);
            init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
            JvmPassBytecode.pushInt(init, i);
            init.add(new TypeInsnNode(Opcodes.NEW, "java/util/concurrent/atomic/AtomicLong"));
            init.add(new InsnNode(Opcodes.DUP));
            JvmPassBytecode.pushLong(init, packed);
            init.add(new MethodInsnNode(
                Opcodes.INVOKESPECIAL,
                "java/util/concurrent/atomic/AtomicLong",
                "<init>",
                "(J)V",
                false
            ));
            init.add(new InsnNode(Opcodes.AASTORE));
        }
        emitClassIntegrityRootInit(init, classIntegrityRootLocal, table, initialState, rootDelta);
        JvmPassBytecode.pushInt(init, table.values().length);
        init.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        init.add(new VarInsnNode(Opcodes.ASTORE, classWordsLocal));
        for (int i = 0; i < table.values().length; i++) {
            init.add(new VarInsnNode(Opcodes.ALOAD, classWordsLocal));
            JvmPassBytecode.pushInt(init, i);
            emitPatchableIntNoLdc(init);
            emitClassKeyWordMask(init, classIntegrityRootLocal, i);
            init.add(new InsnNode(Opcodes.IXOR));
            JvmPassBytecode.pushInt(init, CLASS_KEY_WORD_SEAL);
            init.add(new InsnNode(Opcodes.IXOR));
            init.add(new InsnNode(Opcodes.IASTORE));
        }
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(init, TOKEN_MATERIAL_WORDS_SLOT);
        JvmPassBytecode.pushInt(init, TOKEN_MATERIAL_TABLE_SIZE * TOKEN_MATERIAL_ROW_LONGS);
        init.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
        init.add(new InsnNode(Opcodes.AASTORE));
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(init, TRANSITION_MATERIAL_SLOT);
        JvmPassBytecode.pushInt(init, TRANSITION_MATERIAL_TABLE_SIZE * TRANSITION_MATERIAL_ROW_WORDS);
        init.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        init.add(new InsnNode(Opcodes.AASTORE));
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(init, STEP_MATERIAL_SLOT);
        JvmPassBytecode.pushInt(init, STEP_MATERIAL_TABLE_SIZE * STEP_MATERIAL_ROW_LONGS);
        init.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
        init.add(new InsnNode(Opcodes.AASTORE));
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(init, CFF_ISLAND_MATERIAL_SLOT);
        JvmPassBytecode.pushInt(init, CFF_ISLAND_MATERIAL_TABLE_SIZE);
        init.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        init.add(new InsnNode(Opcodes.AASTORE));
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(init, RUNTIME_VARIABLE_FRAME_SLOT);
        init.add(new TypeInsnNode(Opcodes.NEW, "java/lang/ThreadLocal"));
        init.add(new InsnNode(Opcodes.DUP));
        init.add(new MethodInsnNode(
            Opcodes.INVOKESPECIAL,
            "java/lang/ThreadLocal",
            "<init>",
            "()V",
            false
        ));
        init.add(new InsnNode(Opcodes.AASTORE));
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(init, CLASS_KEY_WORDS_SLOT);
        init.add(new VarInsnNode(Opcodes.ALOAD, classWordsLocal));
        init.add(new InsnNode(Opcodes.AASTORE));
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(init, CLASS_KEY_WORDS_ALIAS_SLOT);
        init.add(new VarInsnNode(Opcodes.ALOAD, classWordsLocal));
        init.add(new InsnNode(Opcodes.AASTORE));
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        JvmPassBytecode.pushInt(init, CLASS_KEY_WORDS_SELECTOR_SLOT);
        JvmPassBytecode.pushInt(init, 2);
        init.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        init.add(new InsnNode(Opcodes.DUP));
        init.add(new InsnNode(Opcodes.ICONST_0));
        JvmPassBytecode.pushInt(init, CLASS_KEY_WORDS_SLOT);
        init.add(new InsnNode(Opcodes.IASTORE));
        init.add(new InsnNode(Opcodes.DUP));
        init.add(new InsnNode(Opcodes.ICONST_1));
        JvmPassBytecode.pushInt(init, CLASS_KEY_WORDS_ALIAS_SLOT);
        init.add(new InsnNode(Opcodes.IASTORE));
        init.add(new InsnNode(Opcodes.AASTORE));
        init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        init.add(new FieldInsnNode(
            Opcodes.PUTSTATIC,
            clazz.name(),
            table.objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        init.add(table.initEnd());
        JvmKeyDispatchPass.markGenerated(pctx, init);
        AbstractInsnNode first = firstReal(clinit);
        if (first == null) {
            clinit.instructions.add(init);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        } else {
            clinit.instructions.insertBefore(first, init);
        }
        clinit.maxLocals = Math.max(clinit.maxLocals, classIntegrityRootLocal + 2);
        clinit.maxStack = Math.max(clinit.maxStack, 10);
    }

    private long classIntegrityInitialState(CffClassKeyTable table) {
        return classIntegrityInitialState(table.owner(), table.clinitMask(), table.objectValues(), table.values());
    }

    private long classIntegrityClassRoot(long state) {
        long x = state;
        x ^= x >>> 33;
        x *= 0xff51afd7ed558ccdL;
        x ^= x >>> 29;
        x *= 0xc4ceb9fe1a85ec53L;
        x ^= x >>> 32;
        return x & 0x0000FFFFFFFFFFFFL;
    }

    private void emitClassIntegrityRootInit(
        InsnList init,
        int rootLocal,
        CffClassKeyTable table,
        long initialState,
        long rootDelta
    ) {
        JvmPassBytecode.pushInt(init, table.classIntegrityClassIndex());
        JvmPassBytecode.pushLong(init, initialState);
        JvmPassBytecode.pushLong(init, rootDelta);
        init.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/invoke/MethodHandles",
            "lookup",
            "()Ljava/lang/invoke/MethodHandles$Lookup;",
            false
        ));
        init.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/invoke/MethodHandles$Lookup",
            "lookupClass",
            "()Ljava/lang/Class;",
            false
        ));
        JvmPassBytecode.pushLong(init, table.classIntegrityRequiredOrderBloom());
        emitPatchableLongNoLdc(init);
        init.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            table.classIntegrityState().owner(),
            table.classIntegrityState().helperName(),
            CLASS_INTEGRITY_HELPER_DESC,
            table.classIntegrityState().interfaceOwner()
        ));
        init.add(new VarInsnNode(Opcodes.LSTORE, rootLocal));
    }

    private void emitClassKeyWordMask(InsnList insns, int rootLocal, int index) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, rootLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, rootLocal));
        JvmPassBytecode.pushLong(insns, 0x0000FFFFFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(0x473138574F524431L, index)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 13);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(0x4731384D554C3131L, index)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void installClassKeyIntHelper(
        PipelineContext pctx,
        L1Class clazz,
        String intHelperName,
        int access
    ) {
        MethodNode helper = new MethodNode(
            access,
            intHelperName,
            "([IIIIIII)I",
            null,
            null
        );
        int tableLocal = 0;
        int guardLocal = 1;
        int pathLocal = 2;
        int blockLocal = 3;
        int indexMixLocal = 4;
        int blockMixLocal = 5;
        int digestMixLocal = 6;
        InsnList insns = helper.instructions;
        insns.add(new VarInsnNode(Opcodes.ALOAD, tableLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexMixLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockMixLocal));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_TABLE_SIZE - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        emitDecodedClassKeyWordFromConstantSeal(insns, CLASS_KEY_WORD_SEAL);
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, digestMixLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 7;
        helper.maxStack = 8;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }

    protected void emitDecodedClassKeyWordFromConstantSeal(InsnList insns, int seal) {
        insns.add(new InsnNode(Opcodes.IALOAD));
        JvmPassBytecode.pushInt(insns, seal);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void installEncryptedTokenMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String tokenMaterialHelperName,
        int access
    ) {
        String objectHelperName = uniqueMethodName(
            clazz,
            tokenMaterialHelperName + "$obj",
            TOKEN_MATERIAL_OBJECT_HELPER_DESC
        );
        installEncryptedTokenMaterialObjectHelper(pctx, clazz, objectHelperName, access);
        MethodNode helper = new MethodNode(
            access,
            tokenMaterialHelperName,
            "([Ljava/lang/Object;IIII)I",
            null,
            null
        );
        int materialLocal = 0;
        int indexLocal = 1;
        int guardLocal = 2;
        int pathLocal = 3;
        int blockLocal = 4;
        int rowLocal = 5;
        int accumulatorLocal = 6;
        InsnList insns = helper.instructions;
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        JvmPassBytecode.pushInt(insns, TOKEN_MATERIAL_WORDS_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, rowLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        int wordOffset = 0;
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, indexLocal, wordOffset++);
        wordOffset = emitAlignedTokenMaterialClassMask(
            insns,
            materialLocal,
            rowLocal,
            indexLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            wordOffset
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, accumulatorLocal));
        emitAlignedTokenMaterialObjectMaskCall(
            insns,
            materialLocal,
            rowLocal,
            indexLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            clazz.name(),
            objectHelperName,
            clazz.isInterface()
        );
        wordOffset += TOKEN_MATERIAL_OBJECT_WORDS;
        insns.add(new VarInsnNode(Opcodes.ILOAD, accumulatorLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        wordOffset = emitAlignedTokenMaterialControlMask(
            insns,
            rowLocal,
            indexLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            wordOffset
        );
        if (wordOffset != TOKEN_MATERIAL_ROW_WORDS) {
            throw new IllegalStateException("CFF token material helper consumed " + wordOffset + " words");
        }
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 7;
        helper.maxStack = 24;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }

    protected void installEncryptedTokenMaterialObjectHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            TOKEN_MATERIAL_OBJECT_HELPER_DESC,
            null,
            null
        );
        int materialLocal = 0;
        int rowLocal = 1;
        int rowBaseLongLocal = 2;
        int guardLocal = 3;
        int pathLocal = 4;
        int blockLocal = 5;
        int objectIndexLocal = 6;
        int packedLocal = 7;
        int epochLocal = 9;
        int objectResultLocal = 10;
        int nextEpochLocal = 11;
        int objectCellLocal = 12;
        int currentMaskLocal = 13;
        int wordOffset = TOKEN_MATERIAL_OBJECT_WORD_OFFSET;
        wordOffset = emitAlignedTokenMaterialObjectMask(
            helper.instructions,
            materialLocal,
            rowLocal,
            rowBaseLongLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            objectIndexLocal,
            packedLocal,
            epochLocal,
            objectResultLocal,
            nextEpochLocal,
            objectCellLocal,
            currentMaskLocal,
            wordOffset
        );
        if (wordOffset != TOKEN_MATERIAL_OBJECT_WORD_OFFSET + TOKEN_MATERIAL_OBJECT_WORDS) {
            throw new IllegalStateException(
                "CFF token material object helper consumed " + wordOffset + " words"
            );
        }
        helper.instructions.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 14;
        helper.maxStack = 24;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }

    protected void emitAlignedTokenMaterialObjectMaskCall(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int rowBaseLongLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        String helperOwner,
        String helperName,
        boolean helperInterfaceOwner
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, rowLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowBaseLongLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            helperOwner,
            helperName,
            TOKEN_MATERIAL_OBJECT_HELPER_DESC,
            helperInterfaceOwner
        ));
    }

    private void emitAlignedTokenMaterialWordLoad(
        InsnList insns,
        int rowLocal,
        int rowBaseLongLocal,
        int wordOffset
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, rowLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowBaseLongLocal));
        int longOffset = wordOffset / 2;
        if (longOffset != 0) {
            JvmPassBytecode.pushInt(insns, longOffset);
            insns.add(new InsnNode(Opcodes.IADD));
        }
        insns.add(new InsnNode(Opcodes.LALOAD));
        if ((wordOffset & 1) == 0) {
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LUSHR));
        }
        insns.add(new InsnNode(Opcodes.L2I));
    }

    private int emitAlignedTokenMaterialClassMask(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int rowBaseLongLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int wordOffset
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_WORDS_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, 63);
        insns.add(new InsnNode(Opcodes.IAND));
        emitDecodedClassKeyWordFromConstantSeal(insns, CLASS_KEY_WORD_SEAL);
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        return wordOffset;
    }

    private int emitAlignedTokenMaterialObjectMask(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int rowBaseLongLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int indexLocal,
        int packedLocal,
        int epochLocal,
        int resultLocal,
        int nextEpochLocal,
        int cellLocal,
        int currentMaskLocal,
        int wordOffset
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_TABLE_SIZE - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/util/concurrent/atomic/AtomicLong"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, cellLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cellLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/util/concurrent/atomic/AtomicLong",
            "getPlain",
            "()J",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.LSTORE, packedLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, packedLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ISTORE, epochLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, packedLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ILOAD, epochLocal));
        emitCffObjectCellMask(insns);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, currentMaskLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, currentMaskLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, resultLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, epochLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, nextEpochLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, cellLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, currentMaskLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, nextEpochLocal));
        emitCffObjectCellMask(insns);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, nextEpochLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/util/concurrent/atomic/AtomicLong",
            "setPlain",
            "(J)V",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ILOAD, resultLocal));
        return wordOffset;
    }

    private int emitAlignedTokenMaterialControlMask(
        InsnList insns,
        int rowLocal,
        int rowBaseLongLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int wordOffset
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitAlignedTokenMaterialWordLoad(insns, rowLocal, rowBaseLongLocal, wordOffset++);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        return wordOffset;
    }

    protected void installStepMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            STEP_MATERIAL_HELPER_DESC,
            null,
            null
        );
        int keyLocal = 0;
        int guardLocal = 2;
        int pathLocal = 3;
        int blockLocal = 4;
        int materialLocal = 5;
        int rowLocal = 6;
        int outLocal = 7;
        int wordsLocal = 8;
        int baseLocal = 9;
        int flagsLocal = 10;
        int valueLocal = 11;
        int indexLocal = 12;
        int sourceIndexLocal = 13;
        int opLocal = 14;
        int decodeBaseLocal = 15;
        int runtimeSourceLocal = 16;
        int threadLocal = 17;
        int stackLocal = 18;
        int stackLengthLocal = 19;
        InsnList insns = helper.instructions;
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        JvmPassBytecode.pushInt(insns, STEP_MATERIAL_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, wordsLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowLocal));
        JvmPassBytecode.pushInt(insns, STEP_MATERIAL_ROW_LONGS);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, baseLocal));
        emitStepMaterialDecodeBase(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            wordsLocal,
            baseLocal
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, decodeBaseLocal));
        emitStepMaterialRuntimeSource(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            threadLocal,
            sourceIndexLocal,
            stackLocal,
            stackLengthLocal,
            stackMixOwner,
            stackMixName,
            stackMixInterfaceOwner
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, runtimeSourceLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, decodeBaseLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, runtimeSourceLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, decodeBaseLocal));
        emitStepMaterialDecodedWordLoad(
            insns,
            wordsLocal,
            baseLocal,
            decodeBaseLocal,
            0
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, flagsLocal));
        emitStepTinyUpdateFromMaterial(
            insns,
            flagsLocal,
            0,
            2,
            4,
            wordsLocal,
            baseLocal,
            decodeBaseLocal,
            1,
            guardLocal,
            pathLocal,
            blockLocal,
            valueLocal,
            indexLocal,
            sourceIndexLocal,
            opLocal
        );
        LabelNode noSecondTiny = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, flagsLocal));
        JvmPassBytecode.pushInt(insns, 1 << 6);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, noSecondTiny));
        emitStepTinyUpdateFromMaterial(
            insns,
            flagsLocal,
            8,
            10,
            12,
            wordsLocal,
            baseLocal,
            decodeBaseLocal,
            2,
            guardLocal,
            pathLocal,
            blockLocal,
            valueLocal,
            indexLocal,
            sourceIndexLocal,
            opLocal
        );
        insns.add(noSecondTiny);
        LabelNode noMethodKey = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, flagsLocal));
        JvmPassBytecode.pushInt(insns, 1 << 7);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, noMethodKey));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flagsLocal));
        JvmPassBytecode.pushInt(insns, 10);
        insns.add(new InsnNode(Opcodes.IUSHR));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceIndexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flagsLocal));
        JvmPassBytecode.pushInt(insns, 12);
        insns.add(new InsnNode(Opcodes.IUSHR));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, opLocal));
        emitLoadStepIndexedInt(insns, sourceIndexLocal, guardLocal, pathLocal, blockLocal);
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        emitStepMaterialMethodConstantLoad(
            insns,
            wordsLocal,
            baseLocal,
            decodeBaseLocal
        );
        emitStepMaterialMethodKeyUpdate(insns, keyLocal, valueLocal, opLocal);
        insns.add(noMethodKey);
        emitTransitionOutPairStore(insns, outLocal, 0, guardLocal, pathLocal);
        emitTransitionOutHighStore(insns, outLocal, 1, blockLocal);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.LRETURN));
        helper.maxLocals = 20;
        helper.maxStack = 32;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        publishGeneratedHelperFlowKey(
            pctx,
            clazz.name(),
            helperName,
            STEP_MATERIAL_HELPER_DESC,
            keyLocal
        );
    }

    protected void emitStepMaterialWordLoad(
        InsnList insns,
        int wordsLocal,
        int baseLocal,
        int word
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, wordsLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, baseLocal));
        JvmPassBytecode.pushInt(insns, word / 2);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.LALOAD));
        if ((word & 1) == 0) {
            JvmPassBytecode.pushInt(insns, 32);
            insns.add(new InsnNode(Opcodes.LUSHR));
        }
        insns.add(new InsnNode(Opcodes.L2I));
    }

    protected void emitStepMaterialDecodedWordLoad(
        InsnList insns,
        int wordsLocal,
        int baseLocal,
        int decodeBaseLocal,
        int word
    ) {
        emitStepMaterialWordLoad(insns, wordsLocal, baseLocal, word);
        emitStepMaterialWordMask(insns, wordsLocal, baseLocal, decodeBaseLocal, word);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitStepMaterialDecodeBase(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int wordsLocal,
        int baseLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IADD));
        emitStepMaterialWordLoad(insns, wordsLocal, baseLocal, 5);
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStepMaterialWordLoad(insns, wordsLocal, baseLocal, 6);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        emitStepMaterialWordLoad(insns, wordsLocal, baseLocal, 7);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitStepMaterialRuntimeSource(
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
    ) {
        JvmPassBytecode.pushInt(insns, 0x53544550);
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/Thread",
            "currentThread",
            "()Ljava/lang/Thread;",
            false
        ));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ASTORE, threadLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            "java/lang/System",
            "identityHashCode",
            "(Ljava/lang/Object;)I",
            false
        ));
        insns.add(new InsnNode(Opcodes.IXOR));
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
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ALOAD, threadLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Object",
            "getClass",
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
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "hashCode",
            "()I",
            false
        ));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
        emitRuntimeStackSourceMix(
            insns,
            sourceLocal,
            threadLocal,
            stackLocal,
            stackLengthLocal,
            stackMixOwner,
            stackMixName,
            stackMixInterfaceOwner
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
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
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitStepMaterialWordMask(
        InsnList insns,
        int wordsLocal,
        int baseLocal,
        int decodeBaseLocal,
        int word
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, decodeBaseLocal));
        emitStepMaterialWordLoad(insns, wordsLocal, baseLocal, 5);
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStepMaterialWordLoad(insns, wordsLocal, baseLocal, 6);
        JvmPassBytecode.pushInt(insns, word + 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitStepMaterialWordLoad(insns, wordsLocal, baseLocal, 7);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, 0x45D9F3B * (word + 1));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitStepTinyUpdateFromMaterial(
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
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, flagsLocal));
        JvmPassBytecode.pushInt(insns, dstShift);
        insns.add(new InsnNode(Opcodes.IUSHR));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flagsLocal));
        JvmPassBytecode.pushInt(insns, sourceShift);
        insns.add(new InsnNode(Opcodes.IUSHR));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceIndexLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, flagsLocal));
        JvmPassBytecode.pushInt(insns, opShift);
        insns.add(new InsnNode(Opcodes.IUSHR));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, opLocal));
        emitStepMaterialTinyUpdate(
            insns,
            indexLocal,
            sourceIndexLocal,
            opLocal,
            wordsLocal,
            baseLocal,
            decodeBaseLocal,
            constantWord,
            guardLocal,
            pathLocal,
            blockLocal,
            valueLocal
        );
    }

    protected void emitStepMaterialTinyUpdate(
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
    ) {
        LabelNode case0 = new LabelNode();
        LabelNode case1 = new LabelNode();
        LabelNode case2 = new LabelNode();
        LabelNode case3 = new LabelNode();
        LabelNode done = new LabelNode();
        emitLoadStepIndexedInt(insns, dstIndexLocal, guardLocal, pathLocal, blockLocal);
        emitLoadStepIndexedInt(insns, sourceIndexLocal, guardLocal, pathLocal, blockLocal);
        emitStepMaterialDecodedWordLoad(
            insns,
            wordsLocal,
            baseLocal,
            decodeBaseLocal,
            constantWord
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, opLocal));
        insns.add(new TableSwitchInsnNode(0, 3, case3, case0, case1, case2, case3));
        insns.add(case0);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(case1);
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        insns.add(new InsnNode(Opcodes.SWAP));
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(case2);
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(case3);
        insns.add(new InsnNode(Opcodes.POP));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitStepMaterialDecodedWordLoad(
            insns,
            wordsLocal,
            baseLocal,
            decodeBaseLocal,
            constantWord
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        insns.add(done);
        emitStoreStepIndexedInt(insns, dstIndexLocal, guardLocal, pathLocal, blockLocal, valueLocal);
    }

    protected void emitLoadStepIndexedInt(
        InsnList insns,
        int indexLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal
    ) {
        LabelNode guard = new LabelNode();
        LabelNode path = new LabelNode();
        LabelNode block = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new TableSwitchInsnNode(0, 2, guard, guard, path, block));
        insns.add(guard);
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(path);
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(block);
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(done);
    }

    protected void emitStoreStepIndexedInt(
        InsnList insns,
        int indexLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int valueLocal
    ) {
        LabelNode guard = new LabelNode();
        LabelNode path = new LabelNode();
        LabelNode block = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new TableSwitchInsnNode(0, 2, guard, guard, path, block));
        insns.add(guard);
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, guardLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(path);
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pathLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(block);
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, blockLocal));
        insns.add(done);
    }

    protected void emitStepMaterialMethodConstantLoad(
        InsnList insns,
        int wordsLocal,
        int baseLocal,
        int decodeBaseLocal
    ) {
        emitStepMaterialDecodedWordLoad(
            insns,
            wordsLocal,
            baseLocal,
            decodeBaseLocal,
            3
        );
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        emitStepMaterialDecodedWordLoad(
            insns,
            wordsLocal,
            baseLocal,
            decodeBaseLocal,
            4
        );
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    protected void emitStepMaterialMethodKeyUpdate(
        InsnList insns,
        int keyLocal,
        int sourceLocal,
        int opLocal
    ) {
        LabelNode case0 = new LabelNode();
        LabelNode case1 = new LabelNode();
        LabelNode case2 = new LabelNode();
        LabelNode case3 = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, opLocal));
        insns.add(new TableSwitchInsnNode(0, 3, case3, case0, case1, case2, case3));
        insns.add(case0);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(case1);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(case2);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(case3);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        insns.add(done);
    }

    protected void installTransitionMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String intHelperOwner,
        String intHelperName,
        boolean intHelperInterfaceOwner
    ) {
        String baseHelperName = uniqueMethodName(
            clazz,
            helperName + "$base",
            TRANSITION_MATERIAL_BASE_HELPER_DESC
        );
        String wordHelperName = uniqueMethodName(
            clazz,
            helperName + "$word",
            TRANSITION_MATERIAL_WORD_HELPER_DESC
        );
        String pcDigestHelperName = uniqueMethodName(
            clazz,
            helperName + "$pc",
            TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC
        );
        installTransitionMaterialBaseHelper(
            pctx,
            clazz,
            baseHelperName,
            access,
            intHelperOwner,
            intHelperName,
            intHelperInterfaceOwner
        );
        installTransitionMaterialWordHelper(pctx, clazz, wordHelperName, access);
        installTransitionMaterialPcDigestHelper(
            pctx,
            clazz,
            pcDigestHelperName,
            access,
            clazz.name(),
            wordHelperName,
            clazz.isInterface()
        );
        MethodNode helper = new MethodNode(
            access,
            helperName,
            TRANSITION_MATERIAL_HELPER_DESC,
            null,
            null
        );
        int keyLocal = 0;
        int guardLocal = 2;
        int pathLocal = 3;
        int blockLocal = 4;
        int objectMaterialLocal = 5;
        int rowLocal = 6;
        int dataLocal = 7;
        int outLocal = 8;
        int pcLocal = 9;
        int materialLocal = 10;
        int baseLocal = 11;
        int domainLocal = 12;
        int rowBaseLocal = 13;
        InsnList insns = helper.instructions;
        insns.add(new VarInsnNode(Opcodes.ALOAD, objectMaterialLocal));
        JvmPassBytecode.pushInt(insns, TRANSITION_MATERIAL_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowLocal));
        JvmPassBytecode.pushInt(insns, TRANSITION_MATERIAL_ROW_WORDS);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new VarInsnNode(Opcodes.ISTORE, rowBaseLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, rowLocal));
        emitTransitionMaterialBaseCall(
            insns,
            keyLocal,
            rowBaseLocal,
            objectMaterialLocal,
            materialLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            baseLocal,
            clazz.name(),
            baseHelperName,
            clazz.isInterface()
        );
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowBaseLocal,
            baseLocal,
            TRANSITION_MATERIAL_GUARD_WORD,
            clazz.name(),
            wordHelperName,
            clazz.isInterface()
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, guardLocal));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowBaseLocal,
            baseLocal,
            TRANSITION_MATERIAL_PATH_WORD,
            clazz.name(),
            wordHelperName,
            clazz.isInterface()
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, pathLocal));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowBaseLocal,
            baseLocal,
            TRANSITION_MATERIAL_BLOCK_WORD,
            clazz.name(),
            wordHelperName,
            clazz.isInterface()
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, blockLocal));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowBaseLocal,
            baseLocal,
            TRANSITION_MATERIAL_PC_WORD,
            clazz.name(),
            wordHelperName,
            clazz.isInterface()
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowBaseLocal,
            baseLocal,
            TRANSITION_MATERIAL_METHOD_HIGH_WORD,
            clazz.name(),
            wordHelperName,
            clazz.isInterface()
        );
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowBaseLocal,
            baseLocal,
            TRANSITION_MATERIAL_METHOD_LOW_WORD,
            clazz.name(),
            wordHelperName,
            clazz.isInterface()
        );
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowBaseLocal,
            baseLocal,
            TRANSITION_MATERIAL_DOMAIN_WORD,
            clazz.name(),
            wordHelperName,
            clazz.isInterface()
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, domainLocal));
        emitBindTransitionMaterialPcToDataDigestCall(
            insns,
            materialLocal,
            rowBaseLocal,
            baseLocal,
            pcLocal,
            dataLocal,
            clazz.name(),
            pcDigestHelperName,
            clazz.isInterface()
        );
        emitTransitionOutStores(
            insns,
            outLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            pcLocal,
            domainLocal,
            true
        );
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.LRETURN));
        helper.maxLocals = 14;
        helper.maxStack = 32;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        publishGeneratedHelperFlowKey(
            pctx,
            clazz.name(),
            helperName,
            TRANSITION_MATERIAL_HELPER_DESC,
            keyLocal
        );
    }

    protected void installTransitionMaterialPcDigestHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String wordHelperOwner,
        String wordHelperName,
        boolean wordHelperInterfaceOwner
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC,
            null,
            null
        );
        int materialLocal = 0;
        int rowLocal = 1;
        int baseLocal = 2;
        int pcLocal = 3;
        int dataLocal = 4;
        int multiplierLocal = 5;
        emitBindTransitionMaterialPcToDataDigest(
            helper.instructions,
            materialLocal,
            rowLocal,
            baseLocal,
            pcLocal,
            dataLocal,
            multiplierLocal,
            wordHelperOwner,
            wordHelperName,
            wordHelperInterfaceOwner
        );
        helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        helper.instructions.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 6;
        helper.maxStack = 12;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }

    protected void emitBindTransitionMaterialPcToDataDigestCall(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int pcLocal,
        int dataLocal,
        String pcDigestHelperOwner,
        String pcDigestHelperName,
        boolean pcDigestHelperInterfaceOwner
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, baseLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            pcDigestHelperOwner,
            pcDigestHelperName,
            TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC,
            pcDigestHelperInterfaceOwner
        ));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
    }

    protected void installTransitionMaterialBaseHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String intHelperOwner,
        String intHelperName,
        boolean intHelperInterfaceOwner
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            TRANSITION_MATERIAL_BASE_HELPER_DESC,
            null,
            null
        );
        int keyLocal = 0;
        int rowLocal = 2;
        int objectMaterialLocal = 3;
        int materialLocal = 4;
        int guardLocal = 5;
        int pathLocal = 6;
        int blockLocal = 7;
        int baseLocal = 8;
        InsnList insns = helper.instructions;
        TransitionMaterialRowCursor rowCursor =
            new TransitionMaterialRowCursor(rowLocal);
        emitTransitionMaterialBase(
            insns,
            objectMaterialLocal,
            intHelperOwner,
            intHelperName,
            intHelperInterfaceOwner,
            materialLocal,
            rowLocal,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            baseLocal,
            rowCursor
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, baseLocal));
        insns.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 9;
        helper.maxStack = 32;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }

    protected void emitTransitionMaterialBaseCall(
        InsnList insns,
        int keyLocal,
        int rowLocal,
        int objectMaterialLocal,
        int materialLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int baseLocal,
        String baseHelperOwner,
        String baseHelperName,
        boolean baseHelperInterfaceOwner
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, objectMaterialLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            baseHelperOwner,
            baseHelperName,
            TRANSITION_MATERIAL_BASE_HELPER_DESC,
            baseHelperInterfaceOwner
        ));
        insns.add(new VarInsnNode(Opcodes.ISTORE, baseLocal));
    }

    protected void installTransitionMaterialWordHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            TRANSITION_MATERIAL_WORD_HELPER_DESC,
            null,
            null
        );
        int materialLocal = 0;
        int rowLocal = 1;
        int baseLocal = 2;
        int wordLocal = 3;
        int cursorLocal = 4;
        InsnList insns = helper.instructions;
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowLocal));
        JvmPassBytecode.pushInt(insns, TRANSITION_MATERIAL_WORDS_BASE);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
        JvmPassBytecode.pushInt(insns, TRANSITION_MATERIAL_WORD_STRIDE);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, cursorLocal));

        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, baseLocal));
        emitTransitionMaterialWordHelperLoad(insns, materialLocal, cursorLocal, TRANSITION_MATERIAL_MASK);
        insns.add(new InsnNode(Opcodes.IXOR));
        emitTransitionMaterialWordHelperLoad(insns, materialLocal, cursorLocal, TRANSITION_MATERIAL_ADD);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitTransitionMaterialWordHelperLoad(insns, materialLocal, cursorLocal, TRANSITION_MATERIAL_SHIFT);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 5;
        helper.maxStack = 6;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }

    private void emitTransitionMaterialWordHelperLoad(
        InsnList insns,
        int materialLocal,
        int cursorLocal,
        int offset
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        JvmPassBytecode.pushInt(insns, offset);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IALOAD));
    }

    protected void emitTransitionMaterialDecodedWordCall(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int word,
        String wordHelperOwner,
        String wordHelperName,
        boolean wordHelperInterfaceOwner
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, baseLocal));
        JvmPassBytecode.pushInt(insns, word);
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            wordHelperOwner,
            wordHelperName,
            TRANSITION_MATERIAL_WORD_HELPER_DESC,
            wordHelperInterfaceOwner
        ));
    }

    protected void emitBindTransitionMaterialPcToDataDigest(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int pcLocal,
        int dataLocal,
        int multiplierLocal,
        String wordHelperOwner,
        String wordHelperName,
        boolean wordHelperInterfaceOwner
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, dataLocal));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowLocal,
            baseLocal,
            TRANSITION_MATERIAL_DISPATCH_ADD_WORD,
            wordHelperOwner,
            wordHelperName,
            wordHelperInterfaceOwner
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowLocal,
            baseLocal,
            TRANSITION_MATERIAL_DISPATCH_SHIFT_A_WORD,
            wordHelperOwner,
            wordHelperName,
            wordHelperInterfaceOwner
        );
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowLocal,
            baseLocal,
            TRANSITION_MATERIAL_DISPATCH_MUL_WORD,
            wordHelperOwner,
            wordHelperName,
            wordHelperInterfaceOwner
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.DUP));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowLocal,
            baseLocal,
            TRANSITION_MATERIAL_DISPATCH_SHIFT_B_WORD,
            wordHelperOwner,
            wordHelperName,
            wordHelperInterfaceOwner
        );
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitTransitionMaterialDecodedWordCall(
            insns,
            materialLocal,
            rowLocal,
            baseLocal,
            TRANSITION_MATERIAL_DISPATCH_FINAL_ADD_WORD,
            wordHelperOwner,
            wordHelperName,
            wordHelperInterfaceOwner
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, multiplierLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, multiplierLocal));
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
    }

    protected void installKeyTransferMaterialHelper(
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
    ) {
        String runtimeBucketHelperName = uniqueMethodName(
            clazz,
            helperName + "$src",
            KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC
        );
        installKeyTransferRuntimeBucketHelper(
            pctx,
            clazz,
            runtimeBucketHelperName,
            access,
            stackMixOwner,
            stackMixName,
            stackMixInterfaceOwner
        );
        MethodNode helper = new MethodNode(
            access,
            helperName,
            KEY_TRANSFER_MATERIAL_HELPER_DESC,
            null,
            null
        );
        int keyLocal = 0;
        int guardLocal = 2;
        int pathLocal = 3;
        int blockLocal = 4;
        int materialLocal = 5;
        int highCursorLocal = 6;
        int lowCursorLocal = 7;
        int highWordLocal = 8;
        int baseCursorLocal = 9;
        int modeLocal = 10;
        int lowBaseCursorLocal = 11;
        int bucketOffsetLocal = 12;
        int ticketLocal = 13;
        int ticketDeferLocal = 15;
        InsnList insns = helper.instructions;
        LabelNode threadLocalTicket = new LabelNode();
        LabelNode ticketModeReady = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, highCursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_TICKET_DEFER_FLAG);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, ticketDeferLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, highCursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_MODE_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, highCursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, highCursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_INDEX_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, baseCursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, highCursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_MODE_SHIFT);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, modeLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lowCursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_INDEX_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, lowBaseCursorLocal));
        emitKeyTransferRuntimeBucketCall(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            modeLocal,
            bucketOffsetLocal,
            clazz.name(),
            runtimeBucketHelperName,
            clazz.isInterface()
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, baseCursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, bucketOffsetLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, highCursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lowBaseCursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, bucketOffsetLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, lowCursorLocal));
        emitKeyTransferMaterialDecodedWord(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            materialLocal,
            highCursorLocal,
            KEY_TRANSFER_MATERIAL_HIGH_METHOD_SEED,
            tokenMaterialHelperOwner,
            tokenMaterialHelperName,
            tokenMaterialHelperInterfaceOwner
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, highWordLocal));
        emitKeyTransferMaterialDecodedWord(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            materialLocal,
            lowCursorLocal,
            KEY_TRANSFER_MATERIAL_HIGH_METHOD_SEED,
            tokenMaterialHelperOwner,
            tokenMaterialHelperName,
            tokenMaterialHelperInterfaceOwner
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, highWordLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, materialLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, ticketLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, ticketDeferLocal));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, threadLocalTicket));
        JvmPassBytecode.pushInt(insns, CLASS_INTEGRITY_TICKET_DEFER_MODE);
        insns.add(new JumpInsnNode(Opcodes.GOTO, ticketModeReady));
        insns.add(threadLocalTicket);
        JvmPassBytecode.pushInt(insns, CLASS_INTEGRITY_TICKET_ISSUE_MODE);
        insns.add(ticketModeReady);
        insns.add(new VarInsnNode(Opcodes.LLOAD, ticketLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, ticketLocal));
        insns.add(new LdcInsnNode(Type.getObjectType(clazz.name())));
        insns.add(new InsnNode(Opcodes.LCONST_0));
        insns.add(new InsnNode(Opcodes.LCONST_0));
        CffClassIntegrityState classIntegrityState = pctx.getPassData(CLASS_INTEGRITY_STATE);
        if (classIntegrityState == null) {
            throw new IllegalStateException("CFF key-transfer ticket helper requires class-integrity state");
        }
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            classIntegrityState.owner(),
            classIntegrityState.ticketHelperName(),
            CLASS_INTEGRITY_HELPER_DESC,
            classIntegrityState.interfaceOwner()
        ));
        insns.add(new InsnNode(Opcodes.LRETURN));
        helper.maxLocals = 16;
        helper.maxStack = 24;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        publishGeneratedHelperFlowKey(
            pctx,
            clazz.name(),
            helperName,
            KEY_TRANSFER_MATERIAL_HELPER_DESC,
            keyLocal
        );
    }

    protected void installKeyTransferRuntimeBucketHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String stackMixOwner,
        String stackMixName,
        boolean stackMixInterfaceOwner
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC,
            null,
            null
        );
        int keyLocal = 0;
        int guardLocal = 2;
        int pathLocal = 3;
        int blockLocal = 4;
        int modeLocal = 5;
        int offsetLocal = 6;
        int sourceLocal = 7;
        int threadLocal = 8;
        int stackLocal = 9;
        int stackLengthLocal = 10;
        emitKeyTransferRuntimeBucketOffset(
            helper.instructions,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            modeLocal,
            offsetLocal,
            sourceLocal,
            threadLocal,
            stackLocal,
            stackLengthLocal,
            stackMixOwner,
            stackMixName,
            stackMixInterfaceOwner
        );
        helper.instructions.add(new VarInsnNode(Opcodes.ILOAD, offsetLocal));
        helper.instructions.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 11;
        helper.maxStack = 24;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }

    protected void emitKeyTransferRuntimeBucketCall(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int modeLocal,
        int bucketOffsetLocal,
        String helperOwner,
        String helperName,
        boolean helperInterfaceOwner
    ) {
        LabelNode computeSource = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        insns.add(new JumpInsnNode(Opcodes.IFNE, computeSource));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, bucketOffsetLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));

        insns.add(computeSource);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            helperOwner,
            helperName,
            KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC,
            helperInterfaceOwner
        ));
        insns.add(new VarInsnNode(Opcodes.ISTORE, bucketOffsetLocal));
        insns.add(done);
    }

    protected void installKeyTransferNoRuntimeMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access,
        String tokenMaterialHelperOwner,
        String tokenMaterialHelperName,
        boolean tokenMaterialHelperInterfaceOwner
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            KEY_TRANSFER_MATERIAL_HELPER_DESC,
            null,
            null
        );
        int keyLocal = 0;
        int guardLocal = 2;
        int pathLocal = 3;
        int blockLocal = 4;
        int materialLocal = 5;
        int highCursorLocal = 6;
        int lowCursorLocal = 7;
        int highWordLocal = 8;
        int ticketLocal = 9;
        int ticketDeferLocal = 11;
        InsnList insns = helper.instructions;
        LabelNode threadLocalTicket = new LabelNode();
        LabelNode ticketModeReady = new LabelNode();

        insns.add(new VarInsnNode(Opcodes.ILOAD, highCursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_TICKET_DEFER_FLAG);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, ticketDeferLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, highCursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_INDEX_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, highCursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lowCursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_INDEX_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, lowCursorLocal));

        emitKeyTransferMaterialDecodedWord(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            materialLocal,
            highCursorLocal,
            KEY_TRANSFER_MATERIAL_HIGH_METHOD_SEED,
            tokenMaterialHelperOwner,
            tokenMaterialHelperName,
            tokenMaterialHelperInterfaceOwner
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, highWordLocal));
        emitKeyTransferMaterialDecodedWord(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            materialLocal,
            lowCursorLocal,
            KEY_TRANSFER_MATERIAL_HIGH_METHOD_SEED,
            tokenMaterialHelperOwner,
            tokenMaterialHelperName,
            tokenMaterialHelperInterfaceOwner
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, highWordLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, materialLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, ticketLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, ticketDeferLocal));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, threadLocalTicket));
        JvmPassBytecode.pushInt(insns, CLASS_INTEGRITY_TICKET_DEFER_MODE);
        insns.add(new JumpInsnNode(Opcodes.GOTO, ticketModeReady));
        insns.add(threadLocalTicket);
        JvmPassBytecode.pushInt(insns, CLASS_INTEGRITY_TICKET_ISSUE_MODE);
        insns.add(ticketModeReady);
        insns.add(new VarInsnNode(Opcodes.LLOAD, ticketLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, ticketLocal));
        insns.add(new LdcInsnNode(Type.getObjectType(clazz.name())));
        insns.add(new InsnNode(Opcodes.LCONST_0));
        insns.add(new InsnNode(Opcodes.LCONST_0));
        CffClassIntegrityState classIntegrityState = pctx.getPassData(CLASS_INTEGRITY_STATE);
        if (classIntegrityState == null) {
            throw new IllegalStateException("CFF key-transfer ticket helper requires class-integrity state");
        }
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            classIntegrityState.owner(),
            classIntegrityState.ticketHelperName(),
            CLASS_INTEGRITY_HELPER_DESC,
            classIntegrityState.interfaceOwner()
        ));
        insns.add(new InsnNode(Opcodes.LRETURN));
        helper.maxLocals = 12;
        helper.maxStack = 24;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        publishGeneratedHelperFlowKey(
            pctx,
            clazz.name(),
            helperName,
            KEY_TRANSFER_MATERIAL_HELPER_DESC,
            keyLocal
        );
    }

    protected void insnDecodeKeyTransferWord(
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
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_INDEX_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, baseCursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_CURSOR_MODE_SHIFT);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, modeLocal));
        emitKeyTransferRuntimeSourceCursor(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            baseCursorLocal,
            modeLocal,
            cursorLocal,
            sourceLocal,
            threadLocal,
            stackLocal,
            stackLengthLocal,
            stackMixOwner,
            stackMixName,
            stackMixInterfaceOwner
        );
        emitKeyTransferMaterialDecodedWord(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            materialLocal,
            cursorLocal,
            KEY_TRANSFER_MATERIAL_HIGH_METHOD_SEED,
            tokenMaterialHelperOwner,
            tokenMaterialHelperName,
            tokenMaterialHelperInterfaceOwner
        );
    }

    protected int registerEncryptedTokenMaterial(
        CffClassKeyTable table,
        int encrypted,
        long seed
    ) {
        int index = table.tokenHelperCounter()[0]++;
        if (index >= TOKEN_MATERIAL_TABLE_SIZE) {
            throw new IllegalStateException(
                "CFF token material table exhausted for " + table.owner()
            );
        }
        long classSeed = seed ^ 0x434646434C544B31L;
        long objectSeed = seed ^ 0x4346464F544B31L;
        int[] values = new int[] {
            encrypted,
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C535449445831L)),
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C5354424C4B31L)) | 1,
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C535444494731L)),
            nonZeroInt(JvmPassBytecode.mix(objectSeed, 0x434C535449445831L)),
            nonZeroInt(JvmPassBytecode.mix(objectSeed, 0x434C5354424C4B31L)) | 1,
            nonZeroInt(JvmPassBytecode.mix(objectSeed, 0x434C535444494731L)),
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4346464F455031L)),
            shift(seed, 11),
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4346464F455032L)) | 1,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4354504D31L)),
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D31L)),
            shift(seed, 9)
        };
        MethodNode initHelper = tokenMaterialInitHelper(
            table,
            index / TOKEN_MATERIAL_INIT_CHUNK_SIZE
        );
        InsnList init = new InsnList();
        emitPackedMaterialLongStores(init, 1, index * TOKEN_MATERIAL_ROW_LONGS, values);
        JvmKeyDispatchPass.markGenerated(table.pctx(), init);
        initHelper.instructions.insertBefore(initHelper.instructions.getLast(), init);
        initHelper.maxStack = Math.max(initHelper.maxStack, 4);
        table.clazz().markDirty();
        return index * TOKEN_MATERIAL_ROW_LONGS * 2;
    }

    protected MethodNode tokenMaterialInitHelper(
        CffClassKeyTable table,
        int chunk
    ) {
        while (table.tokenMaterialInitHelpers().size() <= chunk) {
            int next = table.tokenMaterialInitHelpers().size();
            String desc = "([Ljava/lang/Object;)V";
            String helperName = uniqueMethodName(
                table.clazz(),
                "__neko_cff_tmat_init$" + Integer.toUnsignedString(next, 36),
                desc
            );
            int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            access |= table.interfaceOwner() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
            MethodNode helper = new MethodNode(access, helperName, desc, null, null);
            helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            JvmPassBytecode.pushInt(helper.instructions, TOKEN_MATERIAL_WORDS_SLOT);
            helper.instructions.add(new InsnNode(Opcodes.AALOAD));
            helper.instructions.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
            helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
            helper.instructions.add(new InsnNode(Opcodes.RETURN));
            helper.maxLocals = 2;
            helper.maxStack = 2;
            table.tokenMaterialInitHelpers().add(helper);
            table.clazz().asmNode().methods.add(helper);

            InsnList call = new InsnList();
            call.add(new VarInsnNode(Opcodes.ALOAD, table.initCarrierLocal()));
            call.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                table.owner(),
                helperName,
                desc,
                table.interfaceOwner()
            ));
            JvmKeyDispatchPass.markGenerated(table.pctx(), call);
            MethodNode clinit = findOrCreateClassInit(table.clazz());
            clinit.instructions.insertBefore(table.initEnd(), call);
            clinit.maxStack = Math.max(clinit.maxStack, 1);
            table.clazz().markDirty();
        }
        return table.tokenMaterialInitHelpers().get(chunk);
    }

    protected int registerTransitionMaterialRow(
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
    ) {
        int index = table.transitionMaterialCounter()[0]++;
        if (index >= TRANSITION_MATERIAL_TABLE_SIZE) {
            throw new IllegalStateException(
                "CFF transition material table exhausted for " + table.owner()
            );
        }
        int base = index * TRANSITION_MATERIAL_ROW_WORDS;
        int[] values = transitionMaterialValues(
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
        MethodNode initHelper = transitionMaterialInitHelper(
            table,
            index / TRANSITION_MATERIAL_INIT_CHUNK_SIZE
        );
        InsnList init = new InsnList();
        for (int i = 0; i < values.length; i++) {
            init.add(new VarInsnNode(Opcodes.ALOAD, 1));
            JvmPassBytecode.pushInt(init, base + i);
            JvmPassBytecode.pushInt(init, values[i]);
            init.add(new InsnNode(Opcodes.IASTORE));
        }
        JvmKeyDispatchPass.markGenerated(table.pctx(), init);
        initHelper.instructions.insertBefore(initHelper.instructions.getLast(), init);
        initHelper.maxStack = Math.max(initHelper.maxStack, 3);
        table.clazz().markDirty();
        return index;
    }

    protected void emitPackedMaterialLongStores(
        InsnList init,
        int arrayLocal,
        int base,
        int[] values
    ) {
        for (int i = 0; i < values.length; i += 2) {
            long packed = ((long) values[i] << 32);
            if (i + 1 < values.length) {
                packed |= ((long) values[i + 1]) & 0xffffffffL;
            }
            init.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
            JvmPassBytecode.pushInt(init, base + (i / 2));
            JvmPassBytecode.pushLong(init, packed);
            init.add(new InsnNode(Opcodes.LASTORE));
        }
    }

    protected int[] transitionMaterialValues(
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
        int[] values = new int[TRANSITION_MATERIAL_ROW_WORDS];
        long baseSeed = transitionBaseSeed(stepSeed, role);
        long classSeed =
            (baseSeed ^ 0x4347434C41535331L) ^ 0x434646434C544B31L;
        values[TRANSITION_MATERIAL_BASE_CLASS_INDEX] =
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C535449445831L));
        values[TRANSITION_MATERIAL_BASE_CLASS_BLOCK] =
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C5354424C4B31L)) | 1;
        values[TRANSITION_MATERIAL_BASE_CLASS_DIGEST] =
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C535444494731L));
        values[TRANSITION_MATERIAL_BASE_PATH] =
            nonZeroInt(JvmPassBytecode.mix(baseSeed, 0x43475041544831L));
        values[TRANSITION_MATERIAL_BASE_BLOCK] =
            nonZeroInt(JvmPassBytecode.mix(baseSeed, 0x4347424C4F434B31L)) | 1;
        long methodFoldSeed = baseSeed ^ 0x43474D45544831L;
        values[TRANSITION_MATERIAL_BASE_METHOD_HIGH] =
            (int) (methodFoldSeed >>> 32);
        values[TRANSITION_MATERIAL_BASE_METHOD_ADD] =
            nonZeroInt(JvmPassBytecode.mix(methodFoldSeed, 0x4D4B464F4C4431L));
        values[TRANSITION_MATERIAL_BASE_METHOD_SHIFT] =
            shift(methodFoldSeed, 13);
        values[TRANSITION_MATERIAL_BASE_SHIFT] = shift(baseSeed, 11);
        int sourceBase = compactControlTokenBase(sourceKeys, baseSeed);
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_GUARD_WORD,
            targetKeys.guardKey(),
            sourceBase,
            stepSeed ^ 0x47554152444B31L ^ role.ordinal()
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_PATH_WORD,
            targetKeys.pathKey(),
            sourceBase,
            stepSeed ^ 0x504154484B455931L ^ role.ordinal()
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_BLOCK_WORD,
            targetKeys.blockKey(),
            sourceBase,
            stepSeed ^ 0x424C4F434B4B31L ^ role.ordinal()
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_PC_WORD,
            targetKeys.pcToken(),
            sourceBase,
            target.selectorSeed() ^ state ^ 0x5043544F4B454E31L
        );
        long methodWordSeed =
            stepSeed ^ 0x4D45544844454331L ^ role.ordinal();
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_METHOD_HIGH_WORD,
            (int) (targetKeys.methodKey() >>> 32),
            sourceBase,
            methodWordSeed ^ 0x4849474831L
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_METHOD_LOW_WORD,
            (int) targetKeys.methodKey(),
            sourceBase,
            methodWordSeed ^ 0x4C4F5731L
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_DOMAIN_WORD,
            target.domainToken(),
            sourceBase,
            target.domainSeed() ^ target.island() ^ 0x444F4D544F4B31L
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_DISPATCH_ADD_WORD,
            nonZeroInt(JvmPassBytecode.mix(targetDispatchSeed, 0x4454444D554C4131L)),
            sourceBase,
            targetDispatchSeed ^ stepSeed ^ 0x4454444D41544431L
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_DISPATCH_SHIFT_A_WORD,
            shift(targetDispatchSeed, 3),
            sourceBase,
            targetDispatchSeed ^ stepSeed ^ 0x4454444D41545331L
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_DISPATCH_MUL_WORD,
            nonZeroInt(JvmPassBytecode.mix(targetDispatchSeed, 0x4454444D554C4D31L)) | 1,
            sourceBase,
            targetDispatchSeed ^ stepSeed ^ 0x4454444D4D554C31L
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_DISPATCH_SHIFT_B_WORD,
            shift(targetDispatchSeed, 19),
            sourceBase,
            targetDispatchSeed ^ stepSeed ^ 0x4454444D42545331L
        );
        putTransitionMaterialWord(
            values,
            TRANSITION_MATERIAL_DISPATCH_FINAL_ADD_WORD,
            nonZeroInt(JvmPassBytecode.mix(targetDispatchSeed, 0x4454444D554C4631L)),
            sourceBase,
            targetDispatchSeed ^ stepSeed ^ 0x4454444D46414431L
        );
        return values;
    }

    protected void putTransitionMaterialWord(
        int[] values,
        int word,
        int targetWord,
        int sourceBase,
        long seed
    ) {
        int offset = transitionMaterialWordOffset(word, 0);
        values[offset + TRANSITION_MATERIAL_ENCRYPTED] =
            targetWord ^ controlTokenMaskFromBase(sourceBase, seed);
        values[offset + TRANSITION_MATERIAL_MASK] =
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D534B31L));
        values[offset + TRANSITION_MATERIAL_ADD] =
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D414431L)) | 1;
        values[offset + TRANSITION_MATERIAL_SHIFT] = shift(seed, 13);
    }

    protected int transitionMaterialWordOffset(int word, int part) {
        return TRANSITION_MATERIAL_WORDS_BASE +
            (word * TRANSITION_MATERIAL_WORD_STRIDE) +
            part;
    }

    protected MethodNode transitionMaterialInitHelper(
        CffClassKeyTable table,
        int chunk
    ) {
        while (table.transitionMaterialInitHelpers().size() <= chunk) {
            int next = table.transitionMaterialInitHelpers().size();
            String desc = "([Ljava/lang/Object;)V";
            String helperName = uniqueMethodName(
                table.clazz(),
                "__neko_cff_xmat_init$" + Integer.toUnsignedString(next, 36),
                desc
            );
            int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            access |= table.interfaceOwner() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
            MethodNode helper = new MethodNode(access, helperName, desc, null, null);
            helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            JvmPassBytecode.pushInt(helper.instructions, TRANSITION_MATERIAL_SLOT);
            helper.instructions.add(new InsnNode(Opcodes.AALOAD));
            helper.instructions.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
            helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
            helper.instructions.add(new InsnNode(Opcodes.RETURN));
            helper.maxLocals = 2;
            helper.maxStack = 2;
            table.transitionMaterialInitHelpers().add(helper);
            table.clazz().asmNode().methods.add(helper);

            InsnList call = new InsnList();
            call.add(new VarInsnNode(Opcodes.ALOAD, table.initCarrierLocal()));
            call.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                table.owner(),
                helperName,
                desc,
                table.interfaceOwner()
            ));
            JvmKeyDispatchPass.markGenerated(table.pctx(), call);
            MethodNode clinit = findOrCreateClassInit(table.clazz());
            clinit.instructions.insertBefore(table.initEnd(), call);
            clinit.maxStack = Math.max(clinit.maxStack, 1);
            table.clazz().markDirty();
        }
        return table.transitionMaterialInitHelpers().get(chunk);
    }

    protected int registerStepMaterialRow(
        CffClassKeyTable table,
        long seed,
        EdgeRole role
    ) {
        int index = table.stepMaterialCounter()[0]++;
        if (index >= STEP_MATERIAL_TABLE_SIZE) {
            throw new IllegalStateException(
                "CFF step material table exhausted for " + table.owner()
            );
        }
        int[] values = stepMaterialValues(seed, role);
        MethodNode initHelper = stepMaterialInitHelper(
            table,
            (index * STEP_MATERIAL_ROW_LONGS) / STEP_MATERIAL_INIT_CHUNK_LONGS
        );
        InsnList init = new InsnList();
        emitPackedMaterialLongStores(
            init,
            1,
            index * STEP_MATERIAL_ROW_LONGS,
            values
        );
        JvmKeyDispatchPass.markGenerated(table.pctx(), init);
        initHelper.instructions.insertBefore(initHelper.instructions.getLast(), init);
        initHelper.maxStack = Math.max(initHelper.maxStack, 4);
        table.clazz().markDirty();
        return index;
    }

    protected int[] stepMaterialValues(long seed, EdgeRole role) {
        int[] values = new int[STEP_MATERIAL_ROW_WORDS];
        long roleSeed = seed ^ ((long) role.ordinal() * 0x9E3779B97F4A7C15L);
        int firstIndex = selectStepKeyIndex(roleSeed);
        int firstSourceIndex = selectDifferentStepKeyIndex(
            firstIndex,
            roleSeed ^ 0x4653544B455931L
        );
        int firstOp = (int) ((roleSeed >>> 45) & 3L);
        int flags =
            firstIndex |
                (firstSourceIndex << 2) |
                (firstOp << 4);
        values[1] = nonZeroInt(JvmPassBytecode.mix(roleSeed, 0x54494E594B455931L));

        long secondSeed = JvmPassBytecode.mix(roleSeed, 0x5345434F4E444B31L);
        if (((roleSeed >>> 61) & 1L) != 0L) {
            if (((roleSeed >>> 59) & 1L) == 0L) {
                int secondIndex = selectDifferentStepKeyIndex(firstIndex, secondSeed);
                int secondSourceIndex = (((secondSeed >>> 23) & 1L) == 0L)
                    ? firstIndex
                    : selectDifferentStepKeyIndex(
                          secondIndex,
                          secondSeed ^ 0x5345435352434B31L
                      );
                int secondOp = (int) ((secondSeed >>> 45) & 3L);
                flags |=
                    (1 << 6) |
                        (secondIndex << 8) |
                        (secondSourceIndex << 10) |
                        (secondOp << 12);
                values[2] = nonZeroInt(
                    JvmPassBytecode.mix(secondSeed, 0x54494E594B455931L)
                );
            } else {
                int methodOp = (int) ((secondSeed >>> 51) & 3L);
                long methodConst = nonZeroLong(
                    JvmPassBytecode.mix(secondSeed, 0x4D4554484B455931L)
                );
                flags |= (1 << 7) | (firstIndex << 10) | (methodOp << 12);
                values[3] = (int) (methodConst >>> 32);
                values[4] = (int) methodConst;
            }
        }
        values[0] = flags;
        long maskSeed = JvmPassBytecode.mix(
            roleSeed ^ ((long) flags << 32),
            0x535445504D41534BL
        );
        values[5] = nonZeroInt(JvmPassBytecode.mix(maskSeed, 0x53544D41444431L));
        values[6] = nonZeroInt(JvmPassBytecode.mix(maskSeed, 0x53544D4D554C31L)) | 1;
        values[7] = shift(maskSeed, 9);
        int probeBase = stepMaterialDecodeBase(0L, 0, 0, 0, values[5], values[6], values[7]);
        for (int i = 0; i < 5; i++) {
            values[i] ^= stepMaterialWordMask(
                probeBase,
                values[5],
                values[6],
                values[7],
                i
            );
        }
        return values;
    }

    protected int stepMaterialDecodeBase(
        long key,
        int guard,
        int path,
        int block,
        int add,
        int multiply,
        int shift
    ) {
        int x = (guard ^ path) + block;
        x ^= (int) key;
        x += (int) (key >>> 32);
        x ^= add;
        x *= multiply;
        x ^= x >>> shift;
        return x;
    }

    protected int stepMaterialWordMask(
        int base,
        int add,
        int multiply,
        int shift,
        int word
    ) {
        int x = base ^ add;
        x += multiply * (word + 1);
        x ^= x >>> shift;
        x ^= 0x45D9F3B * (word + 1);
        return x;
    }

    protected MethodNode stepMaterialInitHelper(
        CffClassKeyTable table,
        int chunk
    ) {
        while (table.stepMaterialInitHelpers().size() <= chunk) {
            int next = table.stepMaterialInitHelpers().size();
            String desc = "([Ljava/lang/Object;)V";
            String helperName = uniqueMethodName(
                table.clazz(),
                "__neko_cff_step_init$" + Integer.toUnsignedString(next, 36),
                desc
            );
            int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            access |= table.interfaceOwner() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
            MethodNode helper = new MethodNode(access, helperName, desc, null, null);
            helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            JvmPassBytecode.pushInt(helper.instructions, STEP_MATERIAL_SLOT);
            helper.instructions.add(new InsnNode(Opcodes.AALOAD));
            helper.instructions.add(new TypeInsnNode(Opcodes.CHECKCAST, "[J"));
            helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
            helper.instructions.add(new InsnNode(Opcodes.RETURN));
            helper.maxLocals = 2;
            helper.maxStack = 2;
            table.stepMaterialInitHelpers().add(helper);
            table.clazz().asmNode().methods.add(helper);

            InsnList call = new InsnList();
            call.add(new VarInsnNode(Opcodes.ALOAD, table.initCarrierLocal()));
            call.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                table.owner(),
                helperName,
                desc,
                table.interfaceOwner()
            ));
            JvmKeyDispatchPass.markGenerated(table.pctx(), call);
            MethodNode clinit = findOrCreateClassInit(table.clazz());
            clinit.instructions.insertBefore(table.initEnd(), call);
            clinit.maxStack = Math.max(clinit.maxStack, 1);
            table.clazz().markDirty();
        }
        return table.stepMaterialInitHelpers().get(chunk);
    }

    protected int registerCompressedIslandMaterialBlob(
        CffClassKeyTable table,
        CompressedIslandMaterialBlob blob,
        long seed
    ) {
        int runtimeSourceMode = cffIslandRuntimeSourceMode(blob.words().length);
        int bucketCount = cffIslandRuntimeSourceBucketCount(runtimeSourceMode);
        int index = table.islandMaterialCounter()[0];
        table.islandMaterialCounter()[0] += bucketCount;
        if (index + bucketCount > CFF_ISLAND_MATERIAL_TABLE_SIZE) {
            throw new IllegalStateException(
                "CFF island material table exhausted for " + table.owner()
            );
        }
        MethodNode initHelper = islandMaterialInitHelper(
            table,
            index / CFF_ISLAND_MATERIAL_INIT_CHUNK_SIZE
        );
        for (int bucket = 0; bucket < bucketCount; bucket++) {
            int bucketIndex = index + bucket;
            String[] chunks = encodeCompressedIslandMaterialBlob(table, blob, seed, bucketIndex);
            InsnList init = new InsnList();
            init.add(new VarInsnNode(Opcodes.ALOAD, 1));
            JvmPassBytecode.pushInt(init, bucketIndex);
            JvmPassBytecode.pushInt(init, chunks.length);
            init.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
            for (int i = 0; i < chunks.length; i++) {
                init.add(new InsnNode(Opcodes.DUP));
                JvmPassBytecode.pushInt(init, i);
                init.add(new LdcInsnNode(chunks[i]));
                init.add(new InsnNode(Opcodes.AASTORE));
            }
            init.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                table.islandMaterialUnpackHelperOwner(),
                table.islandMaterialUnpackHelperName(),
                CFF_ISLAND_MATERIAL_UNPACK_HELPER_DESC,
                table.islandMaterialUnpackHelperInterfaceOwner()
            ));
            init.add(new InsnNode(Opcodes.AASTORE));
            JvmKeyDispatchPass.markGenerated(table.pctx(), init);
            initHelper.instructions.insertBefore(initHelper.instructions.getLast(), init);
        }
        initHelper.maxStack = Math.max(initHelper.maxStack, 6);
        table.clazz().markDirty();
        return encodeCffIslandMaterialCursor(index, runtimeSourceMode);
    }

    protected int cffIslandRuntimeSourceMode(int materialWords) {
        return CFF_ISLAND_RUNTIME_SOURCE_THREAD;
    }

    protected int cffIslandRuntimeSourceBucketCount(int runtimeSourceMode) {
        return runtimeSourceMode == CFF_ISLAND_RUNTIME_SOURCE_NONE
            ? 1
            : CFF_ISLAND_RUNTIME_SOURCE_BUCKETS;
    }

    protected int encodeCffIslandMaterialCursor(
        int cursor,
        int runtimeSourceMode
    ) {
        if ((cursor & ~CFF_ISLAND_CURSOR_INDEX_MASK) != 0) {
            throw new IllegalStateException(
                "CFF island material cursor exceeds encoded range: " + cursor
            );
        }
        return cursor | (runtimeSourceMode << CFF_ISLAND_CURSOR_MODE_SHIFT);
    }

    protected String[] encodeCompressedIslandMaterialBlob(
        CffClassKeyTable table,
        CompressedIslandMaterialBlob blob,
        long seed,
        int cursor
    ) {
        int[] words = blob.words();
        CffBlockKeyState[] decodeStates = blob.decodeStates();
        List<String> chunks = new ArrayList<>();
        StringBuilder chunk = new StringBuilder(
            Math.min(CFF_ISLAND_COMPRESSED_BLOB_CHUNK_CHARS, Math.max(16, words.length * 4))
        );
        for (int wordIndex = 0; wordIndex < words.length; wordIndex++) {
            CffBlockKeyState decodeState = decodeStates[wordIndex];
            int mask = decodeState == null
                ? compressedIslandMaterialStaticMask(seed, wordIndex)
                : compressedIslandMaterialRuntimeMask(table, decodeState, cursor, wordIndex);
            int encrypted = words[wordIndex] ^ mask;
            for (int shift = 24; shift >= 0; shift -= 8) {
                if (chunk.length() >= CFF_ISLAND_COMPRESSED_BLOB_CHUNK_CHARS) {
                    chunks.add(chunk.toString());
                    chunk = new StringBuilder(CFF_ISLAND_COMPRESSED_BLOB_CHUNK_CHARS);
                }
                int encodedByte = (encrypted >>> shift) & 0xFF;
                chunk.append((char) encodedByte);
            }
        }
        chunks.add(chunk.toString());
        return chunks.toArray(new String[0]);
    }

    protected int compressedIslandMaterialRuntimeMask(
        CffClassKeyTable table,
        CffBlockKeyState keyState,
        int cursor,
        int wordIndex
    ) {
        int mask = (keyState.guardKey() ^ keyState.pathKey()) + keyState.blockKey();
        mask ^= (int) keyState.methodKey();
        mask += (int) (keyState.methodKey() >>> 32);
        mask ^= cursor * 0x45D9F3B;
        mask += wordIndex * 0x119DE1F3;
        mask ^= table.values()[mask & (CLASS_KEY_TABLE_SIZE - 1)];
        mask ^= mask >>> 16;
        return mask;
    }

    protected int compressedIslandMaterialStaticMask(long seed, int wordIndex) {
        long mixed = JvmPassBytecode.mix(
            seed ^ ((long) wordIndex * 0x9E3779B97F4A7C15L),
            0x434646494D41544CL ^ wordIndex
        );
        int mask = ((int) mixed) ^ ((int) (mixed >>> 32));
        mask ^= mask >>> 15;
        mask *= 0x45D9F3B;
        mask ^= mask >>> 16;
        return mask;
    }

    protected void emitCompressedIslandMaterialWordDecode(
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
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            table.owner(),
            table.objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        JvmPassBytecode.pushInt(insns, cursor);
        JvmPassBytecode.pushInt(insns, wordIndex);
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            table.islandMaterialHelperOwner(),
            table.islandMaterialHelperName(),
            CFF_ISLAND_MATERIAL_HELPER_DESC,
            table.islandMaterialHelperInterfaceOwner()
        ));
        insns.add(new VarInsnNode(Opcodes.ISTORE, resultLocal));
    }

    protected static void addMaterialLong(List<Integer> words, long value) {
        words.add((int) (value >>> 32));
        words.add((int) value);
    }

    protected static void addMaterialKeyState(
        List<Integer> words,
        CffBlockKeyState keyState
    ) {
        words.add(keyState.guardKey());
        words.add(keyState.pathKey());
        words.add(keyState.blockKey());
        words.add(keyState.pcToken());
        addMaterialLong(words, keyState.methodKey());
        addMaterialLong(words, keyState.methodSalt());
    }

    protected static void addMaterialWords(List<Integer> words, int[] values) {
        for (int value : values) {
            words.add(value);
        }
    }

    protected static void addLiveMaterialKeyState(
        List<Integer> words,
        Map<Integer, CffBlockKeyState> decodeStates,
        CffBlockKeyState keyState
    ) {
        addLiveDecodedMaterialWord(words, decodeStates, keyState, keyState.guardKey());
        addLiveDecodedMaterialWord(words, decodeStates, keyState, keyState.pathKey());
        addLiveDecodedMaterialWord(words, decodeStates, keyState, keyState.blockKey());
        addLiveDecodedMaterialWord(words, decodeStates, keyState, keyState.pcToken());
        addLiveDecodedMaterialWord(
            words,
            decodeStates,
            keyState,
            (int) (keyState.methodKey() >>> 32)
        );
        addLiveDecodedMaterialWord(words, decodeStates, keyState, (int) keyState.methodKey());
        addLiveDecodedMaterialWord(
            words,
            decodeStates,
            keyState,
            (int) (keyState.methodSalt() >>> 32)
        );
        addLiveDecodedMaterialWord(words, decodeStates, keyState, (int) keyState.methodSalt());
    }

    protected static void addLiveDecodedMaterialWord(
        List<Integer> words,
        Map<Integer, CffBlockKeyState> decodeStates,
        CffBlockKeyState keyState,
        int value
    ) {
        decodeStates.put(words.size(), keyState);
        words.add(value);
    }

    protected MethodNode islandMaterialInitHelper(
        CffClassKeyTable table,
        int chunk
    ) {
        while (table.islandMaterialInitHelpers().size() <= chunk) {
            int next = table.islandMaterialInitHelpers().size();
            String desc = "([Ljava/lang/Object;)V";
            String helperName = uniqueMethodName(
                table.clazz(),
                "__neko_cff_imat_init$" + Integer.toUnsignedString(next, 36),
                desc
            );
            int access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            access |= table.interfaceOwner() ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PRIVATE;
            MethodNode helper = new MethodNode(access, helperName, desc, null, null);
            helper.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            JvmPassBytecode.pushInt(helper.instructions, CFF_ISLAND_MATERIAL_SLOT);
            helper.instructions.add(new InsnNode(Opcodes.AALOAD));
            helper.instructions.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
            helper.instructions.add(new VarInsnNode(Opcodes.ASTORE, 1));
            helper.instructions.add(new InsnNode(Opcodes.RETURN));
            helper.maxLocals = 2;
            helper.maxStack = 2;
            table.islandMaterialInitHelpers().add(helper);
            table.clazz().asmNode().methods.add(helper);

            InsnList call = new InsnList();
            call.add(new VarInsnNode(Opcodes.ALOAD, table.initCarrierLocal()));
            call.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                table.owner(),
                helperName,
                desc,
                table.interfaceOwner()
            ));
            JvmKeyDispatchPass.markGenerated(table.pctx(), call);
            MethodNode clinit = findOrCreateClassInit(table.clazz());
            clinit.instructions.insertBefore(table.initEnd(), call);
            clinit.maxStack = Math.max(clinit.maxStack, 1);
            table.clazz().markDirty();
        }
        return table.islandMaterialInitHelpers().get(chunk);
    }

    protected void installMethodKeyFromStateHelper(
        PipelineContext pctx,
        L1Class clazz,
        String methodKeyHelperName,
        int access
    ) {
        MethodNode helper = new MethodNode(
            access,
            methodKeyHelperName,
            "(IIIIJJ)J",
            null,
            null
        );
        int guardLocal = 0;
        int pathLocal = 1;
        int blockLocal = 2;
        int pcLocal = 3;
        int saltMaskedLocal = 4;
        int saltMaskLocal = 6;
        LabelNode nonZero = new LabelNode();
        InsnList insns = helper.instructions;
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        insns.add(new VarInsnNode(Opcodes.LLOAD, saltMaskedLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, saltMaskLocal));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.LADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        JvmPassBytecode.pushLong(insns, METHOD_KEY_PC_MIX);
        insns.add(new InsnNode(Opcodes.LMUL));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.DUP2));
        insns.add(new InsnNode(Opcodes.LCONST_0));
        insns.add(new InsnNode(Opcodes.LCMP));
        insns.add(new JumpInsnNode(Opcodes.IFNE, nonZero));
        insns.add(new InsnNode(Opcodes.POP2));
        JvmPassBytecode.pushLong(insns, 0xD1B54A32D192ED03L);
        insns.add(nonZero);
        insns.add(new InsnNode(Opcodes.LRETURN));
        helper.maxLocals = 8;
        helper.maxStack = 8;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }
}
