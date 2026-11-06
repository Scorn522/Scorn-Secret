package dev.nekoobfuscator.native_.translator;

import dev.nekoobfuscator.core.ir.l1.L1Method;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;

import java.util.List;
import java.util.Set;

/**
 * Rejects methods whose bytecode patterns are not yet safely supported by the native translator.
 */
public final class NativeTranslationSafetyChecker {
    public boolean isSafe(L1Method method, List<String> reasons) {
        return isSafe(method, reasons, Set.of(), Set.of());
    }

    public boolean isSafe(
        L1Method method,
        List<String> reasons,
        Set<String> applicationMethodKeys,
        Set<String> nativeManifestMethods
    ) {
        if (method.isClassInit()) {
            reasons.add("class initializers are not translated");
        }
        if (method.isConstructor()) {
            reasons.add("constructors remain in bytecode form");
        }
        if ((method.access() & Opcodes.ACC_BRIDGE) != 0) {
            reasons.add("bridge methods are skipped");
        }
        if (method.isAbstract() || method.isNative() || !method.hasCode()) {
            reasons.add("method has no translatable bytecode body");
        }

        for (AbstractInsnNode insn = method.instructions().getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            switch (opcode) {
                case Opcodes.JSR, Opcodes.RET -> reasons.add("JSR/RET bytecode is not supported");
                default -> {
                }
            }
            if (insn instanceof MethodInsnNode methodInsn
                && !"<init>".equals(methodInsn.name)
                && !"<clinit>".equals(methodInsn.name)) {
                String calleeKey = methodKey(methodInsn.owner, methodInsn.name, methodInsn.desc);
                if (applicationMethodKeys.contains(calleeKey) && !nativeManifestMethods.contains(calleeKey)) {
                    reasons.add("callee not in native manifest: " + calleeKey);
                }
            }
            if (insn instanceof InvokeDynamicInsnNode indy && !isSupportedInvokeDynamic(indy)) {
                reasons.add("unsupported invokedynamic bootstrap: " + indy.bsm.getOwner() + "."
                    + indy.bsm.getName() + indy.bsm.getDesc());
            }
        }

        return reasons.isEmpty();
    }

    private boolean isSupportedInvokeDynamic(InvokeDynamicInsnNode indy) {
        String owner = indy.bsm.getOwner();
        String name = indy.bsm.getName();
        return ("java/lang/invoke/StringConcatFactory".equals(owner) && "makeConcatWithConstants".equals(name))
            || ("java/lang/invoke/LambdaMetafactory".equals(owner)
                && ("metafactory".equals(name) || "altMetafactory".equals(name)))
            || ("java/lang/runtime/ObjectMethods".equals(owner) && "bootstrap".equals(name))
            || ("java/lang/runtime/SwitchBootstraps".equals(owner)
                && ("typeSwitch".equals(name) || "enumSwitch".equals(name)));
    }

    private String methodKey(String owner, String name, String desc) {
        return owner + '#' + name + desc;
    }
}
