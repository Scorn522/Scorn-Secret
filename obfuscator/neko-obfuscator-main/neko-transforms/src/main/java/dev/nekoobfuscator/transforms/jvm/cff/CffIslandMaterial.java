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


abstract class CffIslandMaterial extends CffMaterialTables {

    protected void installCompressedIslandMaterialHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            CFF_ISLAND_MATERIAL_HELPER_DESC,
            null,
            null
        );
        int keyLocal = 0;
        int guardLocal = 2;
        int pathLocal = 3;
        int blockLocal = 4;
        int materialLocal = 5;
        int sourceLocal = 6;
        int cursorLocal = 7;
        int wordLocal = 8;
        int entriesLocal = 9;
        int wordsLocal = 10;
        int valueLocal = 11;
        int maskLocal = 12;
        int classWordsLocal = 13;
        int modeLocal = 14;
        InsnList insns = helper.instructions;
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        JvmPassBytecode.pushInt(insns, CFF_ISLAND_CURSOR_MODE_SHIFT);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, modeLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        JvmPassBytecode.pushInt(insns, CFF_ISLAND_CURSOR_INDEX_MASK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ISTORE, cursorLocal));
        emitCffIslandRuntimeSourceCursorFromLocal(
            insns,
            cursorLocal,
            modeLocal,
            sourceLocal
        );
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        JvmPassBytecode.pushInt(insns, CFF_ISLAND_MATERIAL_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[Ljava/lang/Object;"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, entriesLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, entriesLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, wordsLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, wordsLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
        insns.add(new InsnNode(Opcodes.IALOAD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
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
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        JvmPassBytecode.pushInt(insns, 0x45D9F3B);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
        JvmPassBytecode.pushInt(insns, 0x119DE1F3);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, maskLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_WORDS_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, classWordsLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, maskLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, classWordsLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, maskLocal));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_TABLE_SIZE - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        emitDecodedClassKeyWordFromConstantSeal(insns, CLASS_KEY_WORD_SEAL);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, maskLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, maskLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 15;
        helper.maxStack = 16;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        publishGeneratedHelperFlowKey(
            pctx,
            clazz.name(),
            helperName,
            CFF_ISLAND_MATERIAL_HELPER_DESC,
            keyLocal
        );
    }
    protected void installCffIslandRuntimeSourceHelper(
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
            CFF_ISLAND_RUNTIME_SOURCE_HELPER_DESC,
            null,
            null
        );
        int keyLocal = 0;
        int guardLocal = 2;
        int pathLocal = 3;
        int blockLocal = 4;
        int cursorLocal = 5;
        int modeLocal = 6;
        int sourceLocal = 7;
        int threadLocal = 8;
        int stackLocal = 9;
        int stackLengthLocal = 10;
        InsnList insns = helper.instructions;
        emitCffIslandRuntimeSourceCursor(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
            cursorLocal,
            modeLocal,
            sourceLocal,
            threadLocal,
            stackLocal,
            stackLengthLocal,
            stackMixOwner,
            stackMixName,
            stackMixInterfaceOwner
        );
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        insns.add(new InsnNode(Opcodes.IRETURN));
        helper.maxLocals = 11;
        helper.maxStack = 10;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
        publishGeneratedHelperFlowKey(
            pctx,
            clazz.name(),
            helperName,
            CFF_ISLAND_RUNTIME_SOURCE_HELPER_DESC,
            keyLocal
        );
    }


    protected void emitCffIslandRuntimeSourceCursorFromLocal(
        InsnList insns,
        int cursorLocal,
        int modeLocal,
        int sourceLocal
    ) {
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, done));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, CFF_ISLAND_RUNTIME_SOURCE_BUCKETS - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, cursorLocal));
        insns.add(done);
    }

    protected void emitCffIslandCallsiteRuntimeSource(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal,
        int pcLocal,
        int domainLocal,
        int outLocal,
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
            insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
            JvmPassBytecode.pushInt(insns, 3);
            insns.add(new InsnNode(Opcodes.LALOAD));
            insns.add(new InsnNode(Opcodes.L2I));
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


    protected void emitCffIslandRuntimeSourceCursor(
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
    ) {
        LabelNode computeSource = new LabelNode();
        LabelNode threadDone = new LabelNode();
        LabelNode stackDone = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        insns.add(new JumpInsnNode(Opcodes.IFNE, computeSource));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));

        insns.add(computeSource);
        JvmPassBytecode.pushInt(insns, 0x43464953);
        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        JvmPassBytecode.pushInt(insns, 0x45D9F3B);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        JvmPassBytecode.pushInt(insns, CFF_ISLAND_RUNTIME_SOURCE_THREAD);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, threadDone));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
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
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
        insns.add(threadDone);

        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        JvmPassBytecode.pushInt(insns, CFF_ISLAND_RUNTIME_SOURCE_STACK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, stackDone));
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
        insns.add(stackDone);

        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
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
        JvmPassBytecode.pushInt(insns, CFF_ISLAND_RUNTIME_SOURCE_BUCKETS - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, cursorLocal));
        insns.add(done);
    }

    protected void installCompressedIslandMaterialUnpackHelper(
        PipelineContext pctx,
        L1Class clazz,
        String helperName,
        int access
    ) {
        MethodNode helper = new MethodNode(
            access,
            helperName,
            CFF_ISLAND_MATERIAL_UNPACK_HELPER_DESC,
            null,
            null
        );
        int chunksLocal = 0;
        int totalLocal = 1;
        int indexLocal = 2;
        int chunkLocal = 3;
        int offsetLocal = 4;
        int outLocal = 5;
        int wordLocal = 6;
        int byteLocal = 7;
        int valueLocal = 8;
        int lengthLocal = 9;
        LabelNode countLoop = new LabelNode();
        LabelNode countDone = new LabelNode();
        LabelNode outerLoop = new LabelNode();
        LabelNode returnLabel = new LabelNode();
        LabelNode innerLoop = new LabelNode();
        LabelNode nextChunk = new LabelNode();
        LabelNode skipStore = new LabelNode();
        InsnList insns = helper.instructions;

        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, totalLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));
        insns.add(countLoop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, chunksLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, countDone));
        insns.add(new VarInsnNode(Opcodes.ILOAD, totalLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, chunksLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "length",
            "()I",
            false
        ));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, totalLocal));
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, countLoop));

        insns.add(countDone);
        insns.add(new VarInsnNode(Opcodes.ILOAD, totalLocal));
        JvmPassBytecode.pushInt(insns, 2);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        insns.add(new VarInsnNode(Opcodes.ASTORE, outLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, wordLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, byteLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, indexLocal));

        insns.add(outerLoop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, chunksLocal));
        insns.add(new InsnNode(Opcodes.ARRAYLENGTH));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, returnLabel));
        insns.add(new VarInsnNode(Opcodes.ALOAD, chunksLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, indexLocal));
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new VarInsnNode(Opcodes.ASTORE, chunkLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, chunkLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "length",
            "()I",
            false
        ));
        insns.add(new VarInsnNode(Opcodes.ISTORE, lengthLocal));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, offsetLocal));

        insns.add(innerLoop);
        insns.add(new VarInsnNode(Opcodes.ILOAD, offsetLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, lengthLocal));
        insns.add(new JumpInsnNode(Opcodes.IF_ICMPGE, nextChunk));
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        JvmPassBytecode.pushInt(insns, 8);
        insns.add(new InsnNode(Opcodes.ISHL));
        insns.add(new VarInsnNode(Opcodes.ALOAD, chunkLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, offsetLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/String",
            "charAt",
            "(I)C",
            false
        ));
        JvmPassBytecode.pushInt(insns, 0xFF);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new InsnNode(Opcodes.IOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        insns.add(new IincInsnNode(byteLocal, 1));
        insns.add(new VarInsnNode(Opcodes.ILOAD, byteLocal));
        JvmPassBytecode.pushInt(insns, 3);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFNE, skipStore));
        insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, wordLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, valueLocal));
        insns.add(new InsnNode(Opcodes.IASTORE));
        insns.add(new IincInsnNode(wordLocal, 1));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, valueLocal));
        insns.add(skipStore);
        insns.add(new IincInsnNode(offsetLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, innerLoop));

        insns.add(nextChunk);
        insns.add(new IincInsnNode(indexLocal, 1));
        insns.add(new JumpInsnNode(Opcodes.GOTO, outerLoop));
        insns.add(returnLabel);
        insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
        insns.add(new InsnNode(Opcodes.ARETURN));
        helper.maxLocals = 10;
        helper.maxStack = 6;
        JvmKeyDispatchPass.markGenerated(pctx, helper.instructions);
        clazz.asmNode().methods.add(helper);
    }

    protected void emitKeyTransferRuntimeSourceCursor(
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
    ) {
        emitKeyTransferRuntimeBucketOffset(
            insns,
            keyLocal,
            guardLocal,
            pathLocal,
            blockLocal,
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
        insns.add(new VarInsnNode(Opcodes.ILOAD, baseCursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, cursorLocal));
    }

    protected void emitKeyTransferRuntimeBucketOffset(
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
    ) {
        LabelNode computeSource = new LabelNode();
        LabelNode threadDone = new LabelNode();
        LabelNode stackDone = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        insns.add(new JumpInsnNode(Opcodes.IFNE, computeSource));
        JvmPassBytecode.pushInt(insns, 0);
        insns.add(new VarInsnNode(Opcodes.ISTORE, offsetLocal));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));

        insns.add(computeSource);
        JvmPassBytecode.pushInt(insns, 0x4B584653);
        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        JvmPassBytecode.pushInt(insns, 0x45D9F3B);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));

        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_RUNTIME_SOURCE_THREAD);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, threadDone));
        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
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
        insns.add(new VarInsnNode(Opcodes.ISTORE, sourceLocal));
        insns.add(threadDone);

        insns.add(new VarInsnNode(Opcodes.ILOAD, modeLocal));
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_RUNTIME_SOURCE_STACK);
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFEQ, stackDone));
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
        insns.add(stackDone);

        insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
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
        JvmPassBytecode.pushInt(insns, KEY_TRANSFER_RUNTIME_SOURCE_BUCKETS - 1);
        insns.add(new InsnNode(Opcodes.IAND));
        JvmPassBytecode.pushInt(insns, TOKEN_MATERIAL_ROW_LONGS * 2);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new VarInsnNode(Opcodes.ISTORE, offsetLocal));
        insns.add(done);
    }

    protected void emitKeyTransferMaterialDecodedWord(
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
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            tokenMaterialHelperOwner,
            tokenMaterialHelperName,
            "([Ljava/lang/Object;IIII)I",
            tokenMaterialHelperInterfaceOwner
        ));
        emitMethodKeyFold(insns, keyLocal, methodSeed);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitTransitionMaterialBase(
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
    ) {
        JvmPassBytecode.pushInt(insns, 0);
        emitClassKeyWordsLoad(insns, objectMaterialLocal);
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_CLASS_INDEX,
            rowCursor
        );
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_CLASS_BLOCK,
            rowCursor
        );
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_CLASS_DIGEST,
            rowCursor
        );
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            intHelperOwner,
            intHelperName,
            "([IIIIIII)I",
            intHelperInterfaceOwner
        ));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_PATH,
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_BLOCK,
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitTransitionMaterialMethodKeyFold(
            insns,
            materialLocal,
            rowLocal,
            keyLocal,
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_SHIFT,
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, baseLocal));
    }

    protected void emitTransitionMaterialMethodKeyFold(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int keyLocal,
        TransitionMaterialRowCursor rowCursor
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_METHOD_HIGH,
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_METHOD_ADD,
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            TRANSITION_MATERIAL_BASE_METHOD_SHIFT,
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitTransitionMaterialDecodedWord(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int word,
        TransitionMaterialRowCursor rowCursor
    ) {
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            transitionMaterialWordOffset(word, TRANSITION_MATERIAL_ENCRYPTED),
            rowCursor
        );
        emitTransitionMaterialMaskFromBase(
            insns,
            materialLocal,
            rowLocal,
            baseLocal,
            word,
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitTransitionMaterialMaskFromBase(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int word,
        TransitionMaterialRowCursor rowCursor
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, baseLocal));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            transitionMaterialWordOffset(word, TRANSITION_MATERIAL_MASK),
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            transitionMaterialWordOffset(word, TRANSITION_MATERIAL_ADD),
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        emitTransitionMaterialWordLoad(
            insns,
            materialLocal,
            rowLocal,
            transitionMaterialWordOffset(word, TRANSITION_MATERIAL_SHIFT),
            rowCursor
        );
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitTransitionMaterialWordLoad(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int offset,
        TransitionMaterialRowCursor rowCursor
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        int delta = offset - rowCursor.offset;
        if (delta != 0) {
            insns.add(new IincInsnNode(rowCursor.local, delta));
            rowCursor.offset = offset;
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, rowCursor.local));
        insns.add(new InsnNode(Opcodes.IALOAD));
    }

    protected void emitTokenMaterialWordLoad(InsnList insns, int rowLocal, int cursorLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, rowLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, cursorLocal));
        emitPackedMaterialWordLoad(insns);
        insns.add(new IincInsnNode(cursorLocal, 1));
    }

    protected void emitPackedMaterialWordLoad(InsnList insns) {
        LabelNode lowWord = new LabelNode();
        LabelNode done = new LabelNode();
        insns.add(new InsnNode(Opcodes.DUP));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IAND));
        insns.add(new JumpInsnNode(Opcodes.IFNE, lowWord));
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.LALOAD));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new JumpInsnNode(Opcodes.GOTO, done));
        insns.add(lowWord);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.LALOAD));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(done);
    }

    protected void emitTokenMaterialClassMask(
        InsnList insns,
        int materialLocal,
        int rowLocal,
        int baseLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, materialLocal));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_WORDS_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, 63);
        insns.add(new InsnNode(Opcodes.IAND));
        emitDecodedClassKeyWordFromConstantSeal(insns, CLASS_KEY_WORD_SEAL);
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitTokenMaterialObjectMask(
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
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
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
        insns.add(new VarInsnNode(Opcodes.ISTORE, encodedLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, epochLocal));
        emitCffObjectCellMask(insns);
        insns.add(new VarInsnNode(Opcodes.ILOAD, encodedLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, currentMaskLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, currentMaskLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
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
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
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
    }

    protected void emitTokenMaterialControlMask(
        InsnList insns,
        int rowLocal,
        int baseLocal,
        int guardLocal,
        int pathLocal,
        int blockLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathLocal));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockLocal));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        emitTokenMaterialWordLoad(insns, rowLocal, baseLocal);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }
}
