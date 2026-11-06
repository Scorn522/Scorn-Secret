package dev.nekoobfuscator.transforms.jvm.internal;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

public final class JvmEnumAbi {
    private JvmEnumAbi() {
    }

    public static boolean isEnumClass(L1Class clazz) {
        if (clazz == null) return false;
        return (clazz.asmNode().access & Opcodes.ACC_ENUM) != 0
            || "java/lang/Enum".equals(clazz.superName());
    }

    public static boolean isEnumConstantField(L1Class clazz, FieldNode field) {
        if (field == null || !isEnumClass(clazz)) return false;
        return (field.access & Opcodes.ACC_ENUM) != 0
            && (field.access & Opcodes.ACC_STATIC) != 0
            && enumDescriptor(clazz).equals(field.desc);
    }

    public static boolean isEnumAbiMethod(L1Class clazz, L1Method method) {
        return method != null && isEnumAbiMethod(clazz, method.asmNode());
    }

    public static boolean isEnumAbiMethod(L1Class clazz, MethodNode method) {
        return isEnumValuesMethod(clazz, method)
            || isEnumValueOfMethod(clazz, method)
            || isEnumConstructor(clazz, method);
    }

    public static boolean isEnumValuesMethod(L1Class clazz, L1Method method) {
        return method != null && isEnumValuesMethod(clazz, method.asmNode());
    }

    public static boolean isEnumValuesMethod(L1Class clazz, MethodNode method) {
        if (method == null || !isEnumClass(clazz)) return false;
        return "values".equals(method.name)
            && Type.getMethodDescriptor(Type.getType("[" + enumDescriptor(clazz))).equals(method.desc)
            && (method.access & Opcodes.ACC_STATIC) != 0;
    }

    public static boolean isEnumValueOfMethod(L1Class clazz, L1Method method) {
        return method != null && isEnumValueOfMethod(clazz, method.asmNode());
    }

    public static boolean isEnumValueOfMethod(L1Class clazz, MethodNode method) {
        if (method == null || !isEnumClass(clazz)) return false;
        return "valueOf".equals(method.name)
            && Type.getMethodDescriptor(Type.getObjectType(clazz.name()), Type.getType(String.class)).equals(method.desc)
            && (method.access & Opcodes.ACC_STATIC) != 0;
    }

    public static boolean isEnumConstructor(L1Class clazz, L1Method method) {
        return method != null && isEnumConstructor(clazz, method.asmNode());
    }

    public static boolean isEnumConstructor(L1Class clazz, MethodNode method) {
        if (method == null || !"<init>".equals(method.name) || !isEnumClass(clazz)) return false;
        Type[] args = Type.getArgumentTypes(method.desc);
        return args.length >= 2 && Type.getType(String.class).equals(args[0]) && Type.INT_TYPE.equals(args[1]);
    }

    private static String enumDescriptor(L1Class clazz) {
        return Type.getObjectType(clazz.name()).getDescriptor();
    }
}
