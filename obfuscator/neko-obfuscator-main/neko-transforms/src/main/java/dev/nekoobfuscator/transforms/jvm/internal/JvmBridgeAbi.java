package dev.nekoobfuscator.transforms.jvm.internal;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.MethodNode;

import java.util.HashSet;
import java.util.Set;

public final class JvmBridgeAbi {
    private JvmBridgeAbi() {
    }

    public static boolean isBridgeMethod(L1Method method) {
        return method != null && isBridgeMethod(method.asmNode());
    }

    public static boolean isBridgeMethod(MethodNode method) {
        return method != null && (method.access & Opcodes.ACC_BRIDGE) != 0;
    }

    public static boolean isBridgeFamilyMethod(PipelineContext pctx, L1Class clazz, L1Method method) {
        return method != null && isBridgeFamilyMethod(pctx, clazz, method.asmNode());
    }

    public static boolean isBridgeFamilyMethod(PipelineContext pctx, L1Class clazz, MethodNode method) {
        if (pctx == null || clazz == null || method == null) return false;
        if (isBridgeMethod(method)) return true;
        if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) return false;
        for (L1Class candidate : pctx.classMap().values()) {
            if (!related(pctx, clazz.name(), candidate.name())) continue;
            for (L1Method candidateMethod : candidate.methods()) {
                MethodNode candidateNode = candidateMethod.asmNode();
                if (!method.name.equals(candidateNode.name)) continue;
                if (isBridgeMethod(candidateNode)) return true;
            }
        }
        return false;
    }

    private static boolean related(PipelineContext pctx, String left, String right) {
        return left.equals(right)
            || reaches(pctx, left, right, new HashSet<>())
            || reaches(pctx, right, left, new HashSet<>());
    }

    private static boolean reaches(PipelineContext pctx, String start, String target, Set<String> seen) {
        if (start == null || !seen.add(start)) return false;
        if (start.equals(target)) return true;
        L1Class clazz = pctx.classMap().get(start);
        if (clazz == null) return false;
        if (reaches(pctx, clazz.superName(), target, seen)) return true;
        for (String iface : clazz.interfaces()) {
            if (reaches(pctx, iface, target, seen)) return true;
        }
        return false;
    }
}
