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


abstract class CffKeyStateEmitter extends CffDispatchEmitter {

    protected void emitInitKeys(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyLocal,
        long seed,
        int scratchLocal
    ) {
        emitInitGuard(insns, guardLocal, keyLocal, seed);
        emitInitPathKey(
            insns,
            pathKeyLocal,
            keyLocal,
            seed ^ 0x504154484B455931L
        );
        emitInitBlockKey(
            insns,
            blockKeyLocal,
            guardLocal,
            keyLocal,
            seed ^ 0x424C4F434B455931L
        );
        emitClassKeyMixIntoLocals(
            insns,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            keyLocal,
            seed ^ 0x434C4153534B31L,
            scratchLocal
        );
    }

    protected void emitClassKeyMixIntoLocals(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyLocal,
        long seed,
        int scratchLocal
    ) {
        CffClassKeyTable table = activeKeyTable;
        if (table == null) return;
        int token = table.token(nonZeroInt(seed), seed);
        emitClassKeyWord(insns, table, keyLocal, token, seed, scratchLocal);

        // guard = guard + (classWord ^ c)
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x47554152444D4958L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, guardLocal));

        // path = (path ^ guard) + c
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x504154484D49584BL))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pathKeyLocal));

        // block = (block + path) ^ classWord
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, blockKeyLocal));
    }

    protected void emitClassKeyWord(
        InsnList insns,
        CffClassKeyTable table,
        int keyLocal,
        int token,
        long seed,
        int scratchLocal
    ) {
        emitClassKeyWordsLoad(insns, table);
        emitKeyedTableIndex(insns, keyLocal, token, seed);
        emitDecodedClassKeyWordFromConstantSeal(insns, CLASS_KEY_WORD_SEAL);
        emitKeyMixInt(insns, keyLocal, seed ^ 0x574F52444B455931L);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 23));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitInitPathKey(
        InsnList insns,
        int pathKeyLocal,
        int keyLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        JvmPassBytecode.pushInt(insns, (int) seed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 5));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pathKeyLocal));
    }

    protected void emitInitBlockKey(
        InsnList insns,
        int blockKeyLocal,
        int guardLocal,
        int keyLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, (int) (seed >>> 32));
        insns.add(new InsnNode(Opcodes.IXOR));
        foldTopInt16(insns);
        insns.add(new VarInsnNode(Opcodes.ISTORE, blockKeyLocal));
    }

    protected void emitInitGuard(
        InsnList insns,
        int guardLocal,
        int keyLocal,
        long seed
    ) {
        // fold32(long): compute the method guard once from the incoming key.
        switch ((int) ((seed >>> 53) & 3L)) {
            case 0 -> emitInitGuardHighLow(insns, keyLocal);
            case 1 -> emitInitGuardLowHigh(insns, keyLocal);
            case 2 -> emitInitGuardSeededXor(insns, keyLocal, seed);
            default -> emitInitGuardSeededAdd(insns, keyLocal, seed);
        }
        insns.add(new VarInsnNode(Opcodes.ISTORE, guardLocal));
    }

    protected void emitInitGuardHighLow(InsnList insns, int keyLocal) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.DUP2));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new InsnNode(Opcodes.L2I));
        foldTopInt16(insns);
    }

    protected void emitInitGuardLowHigh(InsnList insns, int keyLocal) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        foldTopInt16(insns);
    }

    protected void emitInitGuardSeededXor(
        InsnList insns,
        int keyLocal,
        long seed
    ) {
        emitInitGuardHighLow(insns, keyLocal);
        JvmPassBytecode.pushInt(insns, (int) seed);
        insns.add(new InsnNode(Opcodes.IXOR));
        foldTopInt16(insns);
    }

    protected void emitInitGuardSeededAdd(
        InsnList insns,
        int keyLocal,
        long seed
    ) {
        emitInitGuardLowHigh(insns, keyLocal);
        JvmPassBytecode.pushInt(insns, (int) (seed >>> 32));
        insns.add(new InsnNode(Opcodes.IADD));
        foldTopInt16(insns);
    }

    protected void foldTopInt16(InsnList insns) {
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 16);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitStorePc(
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
    ) {
        emitEncryptedToken(
            insns,
            targetKeys.pcToken(),
            targetKeys,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            selectorSeed ^ state ^ 0x5043544F4B454E31L,
            scratchLocal
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
    }

    protected void emitStoreDomain(
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
    ) {
        emitEncryptedToken(
            insns,
            domainToken,
            targetKeys,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            domainSeed ^ island ^ 0x444F4D544F4B31L,
            scratchLocal
        );
        insns.add(new VarInsnNode(Opcodes.ISTORE, domainLocal));
    }

    protected long routeTokenSeed(
        long methodSeed,
        long stepSeed,
        int state,
        DispatchTarget target
    ) {
        long seed = stepSeed ^ methodSeed ^ 0x52544F4B42415331L;
        seed = JvmPassBytecode.mix(seed, target.selectorSeed() ^ state);
        seed = JvmPassBytecode.mix(
            seed,
            target.domainSeed() ^ ((long) target.island() << 32) ^ target.domainToken()
        );
        return seed;
    }

    protected int routeTokenBase(CffBlockKeyState keyState, long seed) {
        int x = classTokenMask(keyState, seed ^ 0x5254434C41535331L);
        x ^= keyState.guardKey() +
            (keyState.pathKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x52545041544831L)));
        x ^= keyState.blockKey() *
            (nonZeroInt(JvmPassBytecode.mix(seed, 0x5254424C4F434B31L)) | 1);
        x ^= x >>> shift(seed, 7);
        return x;
    }

    protected int routeTokenMask(
        CffBlockKeyState keyState,
        long routeSeed,
        long tokenSeed
    ) {
        return routeTokenMaskFromBase(routeTokenBase(keyState, routeSeed), tokenSeed);
    }

    protected int routeTokenMaskFromBase(int base, long tokenSeed) {
        int x = base ^
            nonZeroInt(JvmPassBytecode.mix(tokenSeed, 0x52544D534B31L));
        x += nonZeroInt(JvmPassBytecode.mix(tokenSeed, 0x525441444431L)) | 1;
        x ^= x >>> shift(tokenSeed, 13);
        return x;
    }

    protected void emitRouteTokenBase(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int routeBaseLocal,
        long seed,
        int scratchLocal
    ) {
        if (activeKeyTable == null) {
            JvmPassBytecode.pushInt(insns, 0);
        } else {
            JvmPassBytecode.pushInt(insns, 0);
            emitClassTokenMask(
                insns,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                seed ^ 0x5254434C41535331L,
                scratchLocal
            );
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x52545041544831L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x5254424C4F434B31L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 7));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, routeBaseLocal));
    }

    protected void emitStoreRouteToken(
        InsnList insns,
        int dstLocal,
        int token,
        CffBlockKeyState targetKeys,
        int routeBaseLocal,
        long routeSeed,
        long tokenSeed
    ) {
        int encrypted = token ^ routeTokenMask(targetKeys, routeSeed, tokenSeed);
        JvmPassBytecode.pushInt(insns, encrypted);
        emitRouteTokenMaskFromBase(insns, routeBaseLocal, tokenSeed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dstLocal));
    }

    protected void emitStoreTransitionBaseToken(
        InsnList insns,
        int dstLocal,
        int token,
        CffBlockKeyState sourceKeys,
        int keyBaseLocal,
        long baseSeed,
        long tokenSeed
    ) {
        int encrypted =
            token ^
            controlTokenMaskFromBase(compactControlTokenBase(sourceKeys, baseSeed), tokenSeed);
        JvmPassBytecode.pushInt(insns, encrypted);
        emitControlTokenMaskFromBase(insns, keyBaseLocal, tokenSeed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dstLocal));
    }

    protected void emitRouteTokenMaskFromBase(
        InsnList insns,
        int routeBaseLocal,
        long tokenSeed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, routeBaseLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(tokenSeed, 0x52544D534B31L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(tokenSeed, 0x525441444431L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(tokenSeed, 13));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitStoreMethodKey(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        CffBlockKeyState targetKeys
    ) {
        emitMethodKeyFromDecodedState(
            insns,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            pcLocal,
            targetKeys.methodSalt()
        );
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
    }

    protected void emitStoreMethodKeyFromBase(
        InsnList insns,
        int keyLocal,
        int keyBaseLocal,
        CffBlockKeyState sourceKeys,
        CffBlockKeyState targetKeys,
        long baseSeed,
        long seed
    ) {
        emitDecodedMethodKeyWordFromBase(
            insns,
            (int) (targetKeys.methodKey() >>> 32),
            sourceKeys,
            baseSeed,
            keyBaseLocal,
            seed ^ 0x4849474831L
        );
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        emitDecodedMethodKeyWordFromBase(
            insns,
            (int) targetKeys.methodKey(),
            sourceKeys,
            baseSeed,
            keyBaseLocal,
            seed ^ 0x4C4F5731L
        );
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
    }

    protected void emitDecodedMethodKeyWordFromBase(
        InsnList insns,
        int targetWord,
        CffBlockKeyState sourceKeys,
        long baseSeed,
        int keyBaseLocal,
        long seed
    ) {
        int encrypted =
            targetWord ^
            controlTokenMaskFromBase(compactControlTokenBase(sourceKeys, baseSeed), seed);
        JvmPassBytecode.pushInt(insns, encrypted);
        emitControlTokenMaskFromBase(insns, keyBaseLocal, seed);
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitMethodKeyFromDecodedState(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        long methodSalt
    ) {
        long saltMask = JvmPassBytecode.mix(methodSalt, 0x4D4B46524F4D5354L);
        CffClassKeyTable table = activeKeyTable;
        if (table != null) {
            insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
            JvmPassBytecode.pushLong(insns, methodSalt ^ saltMask);
            JvmPassBytecode.pushLong(insns, saltMask);
            insns.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                table.methodKeyHelperOwner(),
                table.methodKeyHelperName(),
                "(IIIIJJ)J",
                table.methodKeyHelperInterfaceOwner()
            ));
            return;
        }
        LabelNode nonZero = new LabelNode();
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, methodSalt ^ saltMask);
        JvmPassBytecode.pushLong(insns, saltMask);
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
    }

    protected long methodKeyLongMask(CffBlockKeyState keyState, long seed) {
        int high = keyState.guardKey() +
            (keyState.pathKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B4850415448L)));
        high ^= keyState.blockKey() *
            (nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B48424C4F43L)) | 1);
        high ^= keyState.pcToken() +
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B48504331L));
        high ^= high >>> shift(seed, 9);
        int low = keyState.blockKey() +
            keyState.pcToken() *
                (nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B4C504331L)) | 1);
        low ^= keyState.pathKey() ^
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B4C50415448L));
        low += keyState.guardKey();
        low ^= low >>> shift(seed, 15);
        return (((long) high) << 32) | (((long) low) & 0xFFFFFFFFL);
    }

    protected void emitMethodKeyLongMask(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B4850415448L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B48424C4F43L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B48504331L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 9));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LSHL));

        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pcLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B4C504331L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B4C50415448L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 15));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.I2L));
        JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
        insns.add(new InsnNode(Opcodes.LAND));
        insns.add(new InsnNode(Opcodes.LOR));
    }

    protected void emitEncryptedToken(
        InsnList insns,
        int token,
        CffBlockKeyState expectedKeys,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    ) {
        int encrypted = token ^
            classTokenMask(expectedKeys, seed) ^
            classObjectTokenMask(expectedKeys, seed) ^
            controlTokenMask(expectedKeys, seed);
        CffClassKeyTable table = activeKeyTable;
        if (table != null) {
            insns.add(new FieldInsnNode(
                Opcodes.GETSTATIC,
                table.owner(),
                table.objectFieldName(),
                "[Ljava/lang/Object;"
            ));
            JvmPassBytecode.pushInt(insns, registerEncryptedTokenMaterial(table, encrypted, seed));
            insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
            insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
            insns.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC,
                table.tokenMaterialHelperOwner(),
                table.tokenMaterialHelperName(),
                "([Ljava/lang/Object;IIII)I",
                table.tokenMaterialHelperInterfaceOwner()
            ));
            return;
        }
        JvmPassBytecode.pushInt(insns, encrypted);
        emitClassTokenMask(insns, guardLocal, pathKeyLocal, blockKeyLocal, seed, scratchLocal);
        emitClassObjectTokenMaskAndUpdate(insns, guardLocal, pathKeyLocal, blockKeyLocal, seed, scratchLocal);
        emitControlTokenMask(
            insns,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            seed
        );
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected int classTokenMask(CffBlockKeyState keyState, long seed) {
        CffClassKeyTable table = activeKeyTable;
        if (table == null) return 0;
        long classSeed = seed ^ 0x434646434C544B31L;
        int word = table.values()[classStateTableIndex(keyState, classSeed)] ^
            classStateDigest(keyState, classSeed);
        return word;
    }

    protected int classObjectTokenMask(CffBlockKeyState keyState, long seed) {
        CffClassKeyTable table = activeKeyTable;
        if (table == null) return 0;
        long classSeed = seed ^ 0x4346464F544B31L;
        int word = table.objectValues()[classStateTableIndex(keyState, classSeed)] ^
            classStateDigest(keyState, classSeed);
        return word;
    }

    protected void emitClassTokenMask(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    ) {
        CffClassKeyTable table = activeKeyTable;
        if (table == null) return;
        long classSeed = seed ^ 0x434646434C544B31L;
        emitClassKeyWordsLoad(insns, table);
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C535449445831L))
        );
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C5354424C4B31L)) | 1
        );
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C535444494731L))
        );
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            table.intHelperOwner(),
            table.intHelperName(),
            "([IIIIIII)I",
            table.intHelperInterfaceOwner()
        ));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitClassKeyWordsLoad(InsnList insns, CffClassKeyTable table) {
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            table.owner(),
            table.objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_WORDS_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
    }

    protected void emitClassKeyWordsLoad(InsnList insns, int objectMaterialLocal) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, objectMaterialLocal));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_WORDS_SLOT);
        insns.add(new InsnNode(Opcodes.AALOAD));
        insns.add(new TypeInsnNode(Opcodes.CHECKCAST, "[I"));
    }

    protected void emitClassObjectTokenMaskAndUpdate(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    ) {
        CffClassKeyTable table = activeKeyTable;
        if (table == null) return;
        long classSeed = seed ^ 0x4346464F544B31L;
        insns.add(new FieldInsnNode(Opcodes.GETSTATIC, table.owner(), table.objectFieldName(), "[Ljava/lang/Object;"));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C535449445831L))
        );
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C5354424C4B31L)) | 1
        );
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(classSeed, 0x434C535444494731L))
        );
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x4346464F455031L)));
        JvmPassBytecode.pushInt(insns, shift(seed, 11));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x4346464F455032L)) | 1);
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            table.owner(),
            table.objectHelperName(),
            "([Ljava/lang/Object;IIIIIIIII)I",
            table.interfaceOwner()
        ));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected int cffObjectCellEpoch(int mask, int index) {
        return nonZeroInt(JvmPassBytecode.mix(mask, index ^ 0x4346464F45504F43L));
    }

    protected int cffObjectCellMask(int epoch) {
        int x = epoch ^ nonZeroInt(JvmPassBytecode.mix(0x4346464F4D415331L, 0x43454C4C31L));
        x ^= x >>> 9;
        x *= nonZeroInt(JvmPassBytecode.mix(0x4346464F4D554C31L, 0x43454C4C31L)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(0x4346464F46494E31L, 0x43454C4C31L));
    }

    protected void emitCffObjectCellMask(InsnList insns) {
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(0x4346464F4D415331L, 0x43454C4C31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, 9);
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(0x4346464F4D554C31L, 0x43454C4C31L)) | 1);
        insns.add(new InsnNode(Opcodes.IMUL));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(0x4346464F46494E31L, 0x43454C4C31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected int classStateTableIndex(CffBlockKeyState keyState, long seed) {
        int value = keyState.guardKey() +
            (keyState.pathKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x434C535449445831L)));
        value += keyState.blockKey() *
            (nonZeroInt(JvmPassBytecode.mix(seed, 0x434C5354424C4B31L)) | 1);
        return value & (CLASS_KEY_TABLE_SIZE - 1);
    }

    protected void emitClassStateTableIndex(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        int scratchLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x434C535449445831L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x434C5354424C4B31L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_TABLE_SIZE - 1);
        insns.add(new InsnNode(Opcodes.IAND));
    }

    protected int classStateDigest(CffBlockKeyState keyState, long seed) {
        return (keyState.blockKey() ^ keyState.pathKey()) +
            (keyState.guardKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x434C535444494731L)));
    }

    protected void emitClassStateDigest(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x434C535444494731L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
    }

    protected CffBlockKeyState initialKeyState(long keyValue, long seed) {
        int guardKey = initialGuardKey(keyValue, seed);
        int pathKey = initialPathKey(keyValue, seed ^ 0x504154484B455931L);
        int blockKey = initialBlockKey(keyValue, guardKey, seed ^ 0x424C4F434B455931L);
        CffClassKeyTable table = activeKeyTable;
        if (table != null) {
            long classSeed = seed ^ 0x434C4153534B31L;
            int classWord = classKeyWord(table, keyValue, classSeed);
            guardKey += classWord ^ nonZeroInt(JvmPassBytecode.mix(classSeed, 0x47554152444D4958L));
            pathKey = (pathKey ^ guardKey) + nonZeroInt(JvmPassBytecode.mix(classSeed, 0x504154484D49584BL));
            blockKey = (blockKey + pathKey) ^ classWord;
        }
        long methodSalt = nonZeroLong(JvmPassBytecode.mix(seed, 0x494E49544D455448L));
        return new CffBlockKeyState(
            guardKey,
            pathKey,
            blockKey,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x494E49545043544BL)),
            methodKeyFromBlock(
                guardKey,
                pathKey,
                blockKey,
                nonZeroInt(JvmPassBytecode.mix(seed, 0x494E49545043544BL)),
                methodSalt
            ),
            methodSalt
        );
    }

    protected int initialGuardKey(long keyValue, long seed) {
        int value;
        switch ((int) ((seed >>> 53) & 3L)) {
            case 0 -> value = foldInt16((int) (keyValue ^ (keyValue >>> 32)));
            case 1 -> value = foldInt16(((int) keyValue) ^ (int) (keyValue >>> 32));
            case 2 -> {
                value = foldInt16((int) (keyValue ^ (keyValue >>> 32)));
                value ^= (int) seed;
                value = foldInt16(value);
            }
            default -> {
                value = foldInt16(((int) keyValue) ^ (int) (keyValue >>> 32));
                value += (int) (seed >>> 32);
                value = foldInt16(value);
            }
        }
        return value;
    }

    protected int foldInt16(int value) {
        return value ^ (value >>> 16);
    }

    protected int initialPathKey(long keyValue, long seed) {
        int value = ((int) keyValue) ^ (int) seed;
        return value ^ (value >>> shift(seed, 5));
    }

    protected int initialBlockKey(long keyValue, int guardKey, long seed) {
        int value = ((int) (keyValue >>> 32)) ^ guardKey ^ (int) (seed >>> 32);
        return value ^ (value >>> 16);
    }

    protected int classKeyWord(CffClassKeyTable table, long keyValue, long seed) {
        int token = table.token(nonZeroInt(seed), seed);
        int index = (keyMixInt(keyValue, seed ^ 0x4944584B455931L) ^ token) &
            (CLASS_KEY_TABLE_SIZE - 1);
        int value = table.values()[index] ^
            keyMixInt(keyValue, seed ^ 0x574F52444B455931L);
        return value ^ (value >>> shift(seed, 23));
    }

    protected int keyMixInt(long keyValue, long siteSeed) {
        int value = ((int) keyValue) ^ (int) (keyValue >>> 32);
        value += nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x4B45594D49584B31L));
        return value ^ (value >>> shift(siteSeed, 5));
    }

    protected int methodKeyFold(long keyValue, long seed) {
        int value = ((int) keyValue) ^ (int) (keyValue >>> 32);
        value ^= (int) (seed >>> 32);
        value += nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B464F4C4431L));
        value ^= value >>> shift(seed, 13);
        return value;
    }

    protected void emitMethodKeyFold(InsnList insns, int keyLocal, long seed) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, (int) (seed >>> 32));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4D4B464F4C4431L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 13));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitDecodeBlockKeys(
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
        emitDecodeBlockKeyWordCompact(
            insns,
            keyTmpLocal,
            targetKeys.guardKey(),
            sourceKeys,
            baseSeed,
            keyBaseLocal,
            seed ^ 0x47554152444B31L ^ role.ordinal()
        );
        emitDecodeBlockKeyWordCompact(
            insns,
            keyTmpLocal + 1,
            targetKeys.pathKey(),
            sourceKeys,
            baseSeed,
            keyBaseLocal,
            seed ^ 0x504154484B455931L ^ role.ordinal()
        );
        emitDecodeBlockKeyWordCompact(
            insns,
            keyTmpLocal + 2,
            targetKeys.blockKey(),
            sourceKeys,
            baseSeed,
            keyBaseLocal,
            seed ^ 0x424C4F434B4B31L ^ role.ordinal()
        );
        emitCommitDecodedKeys(
            insns,
            keyTmpLocal,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal
        );
    }

    protected long transitionBaseSeed(long seed, EdgeRole role) {
        return seed ^ 0x5452414E534B4559L ^ role.ordinal();
    }

    protected void emitDecodeBlockKeyWordCompact(
        InsnList insns,
        int dstLocal,
        int targetWord,
        CffBlockKeyState sourceKeys,
        long baseSeed,
        int keyBaseLocal,
        long seed
    ) {
        int encrypted =
            targetWord ^
            controlTokenMaskFromBase(compactControlTokenBase(sourceKeys, baseSeed), seed);
        JvmPassBytecode.pushInt(insns, encrypted);
        emitControlTokenMaskFromBase(insns, keyBaseLocal, seed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dstLocal));
    }

    protected void emitCommitDecodedKeys(
        InsnList insns,
        int keyTmpLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal));
        insns.add(new VarInsnNode(Opcodes.ISTORE, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal + 1));
        insns.add(new VarInsnNode(Opcodes.ISTORE, pathKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, keyTmpLocal + 2));
        insns.add(new VarInsnNode(Opcodes.ISTORE, blockKeyLocal));
    }

    protected CffBlockKeyState transitionBridgeKeyState(
        CffBlockKeyState sourceKeys,
        CffBlockKeyState targetKeys,
        long methodSeed,
        long seed,
        EdgeRole role
    ) {
        long bridgeSeed = JvmPassBytecode.mix(
            seed ^ 0x4252494447454B31L ^ role.ordinal(),
            sourceKeys.methodSalt() ^ targetKeys.methodSalt() ^ methodSeed
        );
        bridgeSeed = JvmPassBytecode.mix(
            bridgeSeed,
            (((long) sourceKeys.guardKey()) << 32) ^
                (((long) targetKeys.pathKey()) & 0xFFFFFFFFL)
        );
        bridgeSeed = JvmPassBytecode.mix(
            bridgeSeed,
            (((long) sourceKeys.blockKey()) << 32) ^
                (((long) targetKeys.guardKey()) & 0xFFFFFFFFL)
        );
        int guardKey = nonZeroInt(
            JvmPassBytecode.mix(bridgeSeed, 0x4252475541524431L)
        );
        int pathKey = nonZeroInt(
            JvmPassBytecode.mix(bridgeSeed, 0x42525041544831L)
        );
        int blockKey = nonZeroInt(
            JvmPassBytecode.mix(bridgeSeed, 0x4252424C4F434B31L)
        );
        int pcToken = nonZeroInt(
            targetKeys.pcToken() ^ JvmPassBytecode.mix(bridgeSeed, 0x42525043544F4B31L)
        );
        long methodSalt = nonZeroLong(
            JvmPassBytecode.mix(bridgeSeed, 0x42524D45544831L)
        );
        return new CffBlockKeyState(
            guardKey,
            pathKey,
            blockKey,
            pcToken,
            methodKeyFromBlock(guardKey, pathKey, blockKey, pcToken, methodSalt),
            methodSalt
        );
    }

    protected void emitDecodeBlockKeyWord(
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
    ) {
        int encrypted =
            targetWord ^
            controlTokenMaskFromBase(controlTokenBase(sourceKeys, baseSeed), seed);
        JvmPassBytecode.pushInt(insns, encrypted);
        emitControlTokenMaskFromBase(insns, keyBaseLocal, seed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, dstLocal));
    }

    protected int controlTokenBase(
        CffBlockKeyState keyState,
        long seed
    ) {
        int x = keyState.guardKey() ^
            nonZeroInt(JvmPassBytecode.mix(seed, 0x43544241534731L));
        x += keyState.pathKey() *
            (nonZeroInt(JvmPassBytecode.mix(seed, 0x43544241535031L)) | 1);
        x ^= keyState.blockKey() +
            nonZeroInt(JvmPassBytecode.mix(seed, 0x43544241534231L));
        x ^= x >>> shift(seed, 11);
        x += methodKeyFold(keyState.methodKey(), seed ^ 0x4354424D45544831L);
        x ^= x >>> shift(seed, 17);
        return x;
    }

    protected int controlTokenMaskFromBase(int base, long seed) {
        int x = base ^
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D534B31L));
        x += nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D414431L)) | 1;
        x ^= x >>> shift(seed, 13);
        return x;
    }

    protected int compactControlTokenBase(
        CffBlockKeyState keyState,
        long seed
    ) {
        int x = classTokenMask(keyState, seed ^ 0x4347434C41535331L);
        x ^= keyState.guardKey() +
            (keyState.pathKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x43475041544831L)));
        x ^= keyState.blockKey() *
            (nonZeroInt(JvmPassBytecode.mix(seed, 0x4347424C4F434B31L)) | 1);
        x += methodKeyFold(keyState.methodKey(), seed ^ 0x43474D45544831L);
        x ^= x >>> shift(seed, 11);
        return x;
    }

    protected void emitCompactControlTokenBase(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyBaseLocal,
        long seed,
        int scratchLocal
    ) {
        if (activeKeyTable == null) {
            JvmPassBytecode.pushInt(insns, 0);
        } else {
            JvmPassBytecode.pushInt(insns, 0);
            emitClassTokenMask(
                insns,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                seed ^ 0x4347434C41535331L,
                scratchLocal
            );
        }
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x43475041544831L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4347424C4F434B31L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitMethodKeyFold(insns, keyLocal, seed ^ 0x43474D45544831L);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 11));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, keyBaseLocal));
    }

    protected int controlTokenMask(
        CffBlockKeyState keyState,
        long seed
    ) {
        int x = keyState.guardKey() +
            (keyState.pathKey() ^ nonZeroInt(JvmPassBytecode.mix(seed, 0x4354504D31L)));
        x ^= keyState.blockKey() +
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D31L));
        x ^= x >>> shift(seed, 9);
        return x;
    }

    protected void emitControlTokenMask(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x4354504D31L)));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(insns, nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D31L)));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 9));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitControlTokenBase(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int keyBaseLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x43544241534731L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x43544241535031L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IMUL));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x43544241534231L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 11));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        emitMethodKeyFold(insns, keyLocal, seed ^ 0x4354424D45544831L);
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 17));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, keyBaseLocal));
    }

    protected void emitControlTokenMaskFromBase(
        InsnList insns,
        int keyBaseLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, keyBaseLocal));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D534B31L))
        );
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(seed, 0x4354424D414431L)) | 1
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 13));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitEncodedStateValue(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int state,
        long selectorSeed
    ) {
        emitEncodedKeyedValue(
            insns,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            state,
            selectorSeed ^ 0x53544154454B5631L
        );
    }

    protected void emitEncodedDomainValue(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int island,
        long domainSeed
    ) {
        emitEncodedKeyedValue(
            insns,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            island,
            domainSeed ^ 0x444F4D41494B5631L
        );
    }

    protected void emitKeyPredicate(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    ) {
        emitKeyDigest(
            insns,
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            seed ^ 0x5052454449434154L
        );
    }

    protected void emitEncodedKeyedValue(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int value,
        long seed
    ) {
        switch ((int) ((seed >>> 41) & 3L)) {
            case 0 -> {
                emitClassDecodedInt(insns, value + (int) seed, seed);
                insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
                insns.add(new InsnNode(Opcodes.IADD));
                insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
                emitClassDecodedInt(
                    insns,
                    (int) (seed >>> 32),
                    seed ^ 0x484947484B31L
                );
                insns.add(new InsnNode(Opcodes.IADD));
                insns.add(new InsnNode(Opcodes.IXOR));
            }
            case 1 -> {
                insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
                emitClassDecodedInt(insns, (int) seed, seed);
                insns.add(new InsnNode(Opcodes.IADD));
                emitClassDecodedInt(
                    insns,
                    value ^ (int) (seed >>> 32),
                    seed ^ 0x535441544B31L
                );
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
                insns.add(new InsnNode(Opcodes.IADD));
                insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
                emitClassDecodedInt(
                    insns,
                    (int) JvmPassBytecode.mix(seed, 0x50415448L),
                    seed ^ 0x504154484B31L
                );
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new InsnNode(Opcodes.IXOR));
            }
            case 2 -> {
                insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
                emitClassDecodedInt(
                    insns,
                    value + (int) (seed >>> 32),
                    seed ^ 0x56414C324B31L
                );
                insns.add(new InsnNode(Opcodes.IADD));
                insns.add(new InsnNode(Opcodes.DUP));
                JvmPassBytecode.pushInt(insns, shift(seed, 7));
                insns.add(new InsnNode(Opcodes.IUSHR));
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
                emitClassDecodedInt(
                    insns,
                    (int) JvmPassBytecode.mix(seed, 0x424C4F43L),
                    seed ^ 0x424C4F434B31L
                );
                insns.add(new InsnNode(Opcodes.IADD));
                insns.add(new InsnNode(Opcodes.IADD));
            }
            default -> {
                emitClassDecodedInt(
                    insns,
                    value ^ (int) JvmPassBytecode.mix(seed, 0x56414C5545L),
                    seed ^ 0x56414C554B31L
                );
                insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
                insns.add(new InsnNode(Opcodes.IADD));
                insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
                emitClassDecodedInt(
                    insns,
                    (int) (seed >>> 32),
                    seed ^ 0x444546484B31L
                );
                insns.add(new InsnNode(Opcodes.IADD));
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
                insns.add(new InsnNode(Opcodes.IADD));
                emitClassDecodedInt(insns, (int) seed, seed ^ 0x4445464B31L);
                insns.add(new InsnNode(Opcodes.IXOR));
            }
        }
    }

    protected void emitClassDecodedInt(
        InsnList insns,
        int value,
        long siteSeed
    ) {
        JvmPassBytecode.pushInt(insns, value);
    }

    protected void emitKeyedTableIndex(
        InsnList insns,
        int keyLocal,
        int token,
        long siteSeed
    ) {
        emitKeyMixInt(insns, keyLocal, siteSeed ^ 0x4944584B455931L);
        JvmPassBytecode.pushInt(insns, token);
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(insns, CLASS_KEY_TABLE_SIZE - 1);
        insns.add(new InsnNode(Opcodes.IAND));
    }

    protected void emitKeyMixInt(InsnList insns, int keyLocal, long siteSeed) {
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        JvmPassBytecode.pushInt(insns, 32);
        insns.add(new InsnNode(Opcodes.LUSHR));
        insns.add(new InsnNode(Opcodes.L2I));
        insns.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(
            insns,
            nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x4B45594D49584B31L))
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(siteSeed, 5));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitKeyDigest(
        InsnList insns,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed
    ) {
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        JvmPassBytecode.pushInt(insns, (int) seed);
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.DUP));
        JvmPassBytecode.pushInt(insns, shift(seed, 13));
        insns.add(new InsnNode(Opcodes.IUSHR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        JvmPassBytecode.pushInt(
            insns,
            (int) JvmPassBytecode.mix(seed, 0x44494745L)
        );
        insns.add(new InsnNode(Opcodes.IADD));
        insns.add(new InsnNode(Opcodes.IXOR));
    }

    protected void emitMaterializedStepKeys(
        InsnList insns,
        CffClassKeyTable table,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int outLocal,
        long seed,
        EdgeRole role
    ) {
        int row = registerStepMaterialRow(table, seed, role);
        insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, guardLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, pathKeyLocal));
        insns.add(new VarInsnNode(Opcodes.ILOAD, blockKeyLocal));
        insns.add(new FieldInsnNode(
            Opcodes.GETSTATIC,
            table.owner(),
            table.objectFieldName(),
            "[Ljava/lang/Object;"
        ));
        JvmPassBytecode.pushInt(insns, row);
        insns.add(new VarInsnNode(Opcodes.ALOAD, outLocal));
        insns.add(new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            table.stepMaterialHelperOwner(),
            table.stepMaterialHelperName(),
            STEP_MATERIAL_HELPER_DESC,
            table.stepMaterialHelperInterfaceOwner()
        ));
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
        emitTransitionOutPairLoad(
            insns,
            outLocal,
            0,
            guardLocal,
            pathKeyLocal
        );
        emitTransitionOutHighLoad(insns, outLocal, 1, blockKeyLocal);
    }

    protected void emitStepKeys(
        InsnList insns,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        long seed,
        EdgeRole role
    ) {
        long roleSeed = seed ^ ((long) role.ordinal() * 0x9E3779B97F4A7C15L);
        int firstIndex = selectStepKeyIndex(roleSeed);
        int firstLocal = stepKeyLocal(
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            firstIndex
        );
        int firstSource = stepSourceKeyLocal(
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            firstIndex,
            roleSeed ^ 0x4653544B455931L
        );
        emitStoreKeyTiny(insns, firstLocal, firstSource, roleSeed);

        long secondSeed = JvmPassBytecode.mix(roleSeed, 0x5345434F4E444B31L);
        if (((roleSeed >>> 61) & 1L) != 0L) {
            if (((roleSeed >>> 59) & 1L) == 0L) {
                int secondIndex = selectDifferentStepKeyIndex(
                    firstIndex,
                    secondSeed
                );
                int secondLocal = stepKeyLocal(
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    secondIndex
                );
                int secondSource = (((secondSeed >>> 23) & 1L) == 0L)
                    ? firstLocal
                    : stepSourceKeyLocal(
                          guardLocal,
                          pathKeyLocal,
                          blockKeyLocal,
                          secondIndex,
                          secondSeed ^ 0x5345435352434B31L
                      );
                emitStoreKeyTiny(insns, secondLocal, secondSource, secondSeed);
            } else {
                emitStepMethodKeyTiny(insns, keyLocal, firstLocal, secondSeed);
            }
        }
    }

    protected StepDryRun stepDryRun(long seed, EdgeRole role) {
        long roleSeed = seed ^ ((long) role.ordinal() * 0x9E3779B97F4A7C15L);
        int firstTinyUpdates = 1;
        int secondTinyUpdates = 0;
        int methodKeyUpdates = 0;
        if (((roleSeed >>> 61) & 1L) != 0L) {
            if (((roleSeed >>> 59) & 1L) == 0L) {
                secondTinyUpdates = 1;
            } else {
                methodKeyUpdates = 1;
            }
        }
        return new StepDryRun(firstTinyUpdates, secondTinyUpdates, methodKeyUpdates);
    }

    protected void emitStoreKeyTiny(
        InsnList insns,
        int dstLocal,
        int sourceLocal,
        long seed
    ) {
        int c = nonZeroInt(JvmPassBytecode.mix(seed, 0x54494E594B455931L));
        switch ((int) ((seed >>> 45) & 3L)) {
            case 0 -> {
                // dst = dst + (source ^ c)
                insns.add(new VarInsnNode(Opcodes.ILOAD, dstLocal));
                insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
                JvmPassBytecode.pushInt(insns, c);
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new InsnNode(Opcodes.IADD));
            }
            case 1 -> {
                // dst = (dst ^ c) + source
                insns.add(new VarInsnNode(Opcodes.ILOAD, dstLocal));
                JvmPassBytecode.pushInt(insns, c);
                insns.add(new InsnNode(Opcodes.IXOR));
                insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
                insns.add(new InsnNode(Opcodes.IADD));
            }
            case 2 -> {
                // dst = (dst + source) ^ c
                insns.add(new VarInsnNode(Opcodes.ILOAD, dstLocal));
                insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
                insns.add(new InsnNode(Opcodes.IADD));
                JvmPassBytecode.pushInt(insns, c);
                insns.add(new InsnNode(Opcodes.IXOR));
            }
            default -> {
                // dst = (dst ^ source) + c
                insns.add(new VarInsnNode(Opcodes.ILOAD, dstLocal));
                insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
                insns.add(new InsnNode(Opcodes.IXOR));
                JvmPassBytecode.pushInt(insns, c);
                insns.add(new InsnNode(Opcodes.IADD));
            }
        }
        insns.add(new VarInsnNode(Opcodes.ISTORE, dstLocal));
    }

    protected int selectStepKeyIndex(long seed) {
        return (int) Long.remainderUnsigned(seed >>> 54, 3L);
    }

    protected int selectDifferentStepKeyIndex(int firstIndex, long seed) {
        int offset = 1 + (int) ((seed >>> 57) & 1L);
        return (firstIndex + offset) % 3;
    }

    protected int stepKeyLocal(
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int index
    ) {
        return switch (index) {
            case 0 -> guardLocal;
            case 1 -> pathKeyLocal;
            default -> blockKeyLocal;
        };
    }

    protected int stepSourceKeyLocal(
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int dstIndex,
        long seed
    ) {
        int sourceIndex = selectDifferentStepKeyIndex(dstIndex, seed);
        return stepKeyLocal(
            guardLocal,
            pathKeyLocal,
            blockKeyLocal,
            sourceIndex
        );
    }

    protected void emitStepMethodKeyTiny(
        InsnList insns,
        int keyLocal,
        int sourceLocal,
        long seed
    ) {
        long c = nonZeroLong(JvmPassBytecode.mix(seed, 0x4D4554484B455931L));
        switch ((int) ((seed >>> 51) & 3L)) {
            case 0 -> {
                // key = key + (source & 0xffffffffL) ^ c
                insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
                insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
                insns.add(new InsnNode(Opcodes.I2L));
                JvmPassBytecode.pushLong(insns, 0xFFFFFFFFL);
                insns.add(new InsnNode(Opcodes.LAND));
                insns.add(new InsnNode(Opcodes.LADD));
                JvmPassBytecode.pushLong(insns, c);
                insns.add(new InsnNode(Opcodes.LXOR));
            }
            case 1 -> {
                // key = (key ^ c) + source
                insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
                JvmPassBytecode.pushLong(insns, c);
                insns.add(new InsnNode(Opcodes.LXOR));
                insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
                insns.add(new InsnNode(Opcodes.I2L));
                insns.add(new InsnNode(Opcodes.LADD));
            }
            case 2 -> {
                // key = key ^ ((long) source << 32) + c
                insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
                insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
                insns.add(new InsnNode(Opcodes.I2L));
                JvmPassBytecode.pushInt(insns, 32);
                insns.add(new InsnNode(Opcodes.LSHL));
                insns.add(new InsnNode(Opcodes.LXOR));
                JvmPassBytecode.pushLong(insns, c);
                insns.add(new InsnNode(Opcodes.LADD));
            }
            default -> {
                // key = key + c ^ source
                insns.add(new VarInsnNode(Opcodes.LLOAD, keyLocal));
                JvmPassBytecode.pushLong(insns, c);
                insns.add(new InsnNode(Opcodes.LADD));
                insns.add(new VarInsnNode(Opcodes.ILOAD, sourceLocal));
                insns.add(new InsnNode(Opcodes.I2L));
                insns.add(new InsnNode(Opcodes.LXOR));
            }
        }
        insns.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
    }

    protected int nonZeroInt(long value) {
        int v = (int) value;
        return v == 0 ? 0x6D2B79F5 : v;
    }

    protected long nonZeroLong(long value) {
        return value == 0L ? 0xD1B54A32D192ED03L : value;
    }

    protected DispatchPlan buildDispatchPlan(
        List<Block> blocks,
        CffFrameAnalysis frames,
        long salt,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, String> handlerDomains,
        SyntheticNoiseBudget syntheticNoiseBudget
    ) {
        // Split dispatchers must not merge blocks that require different local
        // initialization states. This preserves verifier compatibility without
        // falling back to unflattened bytecode.
        Map<String, List<Block>> byFrame = new LinkedHashMap<>();
        for (Block block : blocks) {
            if (block.handler()) continue;
            String signature =
                handlerDomains.getOrDefault(block.label(), "N") +
                ':' +
                frames.localsSignature(block.label());
            byFrame
                .computeIfAbsent(signature, ignored -> new ArrayList<>())
                .add(block);
        }

        List<IslandGroup> groups = new ArrayList<>();
        Map<LabelNode, DispatchTarget> targets = new IdentityHashMap<>();
        int groupIndex = 0;
        for (Map.Entry<String, List<Block>> entry : byFrame.entrySet()) {
            List<Block> groupBlocks = entry.getValue();
            int islandCount = islandCount(groupBlocks.size());
            LabelNode hub = new LabelNode();
            LabelNode[] islandLabels = new LabelNode[islandCount];
            for (int i = 0; i < islandCount; i++) {
                islandLabels[i] = new LabelNode();
            }
            LabelNode[] aliasHubs = new LabelNode[aliasHubCount(
                groupBlocks.size(),
                syntheticNoiseBudget
            )];
            for (int i = 0; i < aliasHubs.length; i++) {
                aliasHubs[i] = new LabelNode();
            }
            Map<LabelNode, Integer> islands = new IdentityHashMap<>();
            long groupSalt = JvmPassBytecode.mix(
                salt ^ entry.getKey().hashCode(),
                groupIndex++ ^ groupBlocks.size()
            );
            long groupDomainSeed = groupSalt ^ 0x444F4D41494E4B31L;
            for (int i = 0; i < groupBlocks.size(); i++) {
                Block block = groupBlocks.get(i);
                int island = islandFor(i, groupBlocks.size(), islandCount);
                int state = requireState(block.label(), stateByLabel.get(block.label()));
                islands.put(block.label(), island);
                targets.put(
                    block.label(),
                    new DispatchTarget(
                        hub,
                        islandLabels,
                        aliasHubs,
                        island,
                        caseSelectorSeed(
                            groupSalt,
                            block.label(),
                            state,
                            island
                        ),
                        groupDomainSeed,
                        domainToken(groupSalt, island)
                    )
                );
            }
            groups.add(
                new IslandGroup(
                    hub,
                    islandLabels,
                    aliasHubs,
                    groupBlocks,
                    islands,
                    groupSalt
                )
            );
        }
        return new DispatchPlan(groups, targets);
    }

    protected Map<LabelNode, CffBlockKeyState> buildBlockKeyStates(
        List<Block> blocks,
        Map<LabelNode, LabelNode> aliases,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, DispatchTarget> dispatchByLabel,
        long salt
    ) {
        Map<LabelNode, CffBlockKeyState> keyStates = new IdentityHashMap<>();
        Set<Integer> usedPcTokens = new HashSet<>();
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            Integer state = stateByLabel.get(block.label());
            DispatchTarget target = dispatchByLabel.get(block.label());
            if (state == null || target == null) continue;
            long seed = JvmPassBytecode.mix(
                salt ^ 0x424C4F434B535431L,
                state ^ i
            );
            seed = JvmPassBytecode.mix(seed, System.identityHashCode(block.label()));
            int pcToken = nonZeroInt(JvmPassBytecode.mix(seed, 0x5043544F4B31L));
            while (!usedPcTokens.add(pcToken)) {
                pcToken = nonZeroInt(JvmPassBytecode.mix(pcToken, usedPcTokens.size() + 1L));
            }
            keyStates.put(
                block.label(),
                blockKeyState(seed, pcToken)
            );
        }
        for (Map.Entry<LabelNode, LabelNode> alias : aliases.entrySet()) {
            LabelNode canonicalLabel = canonicalLabel(alias.getValue(), aliases);
            CffBlockKeyState canonical = keyStates.get(canonicalLabel);
            if (canonical != null) keyStates.put(alias.getKey(), canonical);
        }
        return keyStates;
    }
}
