package dev.nekoobfuscator.transforms.jvm.internal;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.RecordComponentNode;

import java.util.List;

public final class JvmRecordAbi {
    private JvmRecordAbi() {
    }

    public static boolean isRecordClass(L1Class clazz) {
        if (clazz == null) return false;
        return (clazz.asmNode().access & Opcodes.ACC_RECORD) != 0
            || "java/lang/Record".equals(clazz.superName())
            || clazz.asmNode().recordComponents != null;
    }

    public static boolean isRecordComponentField(L1Class clazz, FieldNode field) {
        if (field == null) return false;
        return isRecordComponent(clazz, field.name, field.desc);
    }

    public static boolean isRecordComponentAccessor(L1Class clazz, L1Method method) {
        return method != null && isRecordComponentAccessor(clazz, method.asmNode());
    }

    public static boolean isRecordComponentAccessor(L1Class clazz, MethodNode method) {
        if (method == null || !isRecordClass(clazz)) return false;
        if ((method.access & Opcodes.ACC_STATIC) != 0) return false;
        return isRecordComponent(clazz, method.name, Type.getReturnType(method.desc).getDescriptor())
            && Type.getArgumentTypes(method.desc).length == 0;
    }

    public static boolean isRecordCanonicalConstructor(L1Class clazz, L1Method method) {
        return method != null && isRecordCanonicalConstructor(clazz, method.asmNode());
    }

    public static boolean isRecordCanonicalConstructor(L1Class clazz, MethodNode method) {
        if (method == null || !"<init>".equals(method.name) || !isRecordClass(clazz)) return false;
        return method.desc.equals(canonicalConstructorDescriptor(clazz));
    }

    public static boolean isRecordAbiMethod(L1Class clazz, L1Method method) {
        return isRecordComponentAccessor(clazz, method) || isRecordCanonicalConstructor(clazz, method);
    }

    public static boolean isRecordComponent(L1Class clazz, String name, String descriptor) {
        if (!isRecordClass(clazz) || name == null || descriptor == null) return false;
        for (RecordComponentNode component : recordComponents(clazz)) {
            if (name.equals(component.name) && descriptor.equals(component.descriptor)) {
                return true;
            }
        }
        return false;
    }

    private static String canonicalConstructorDescriptor(L1Class clazz) {
        List<RecordComponentNode> components = recordComponents(clazz);
        Type[] args = new Type[components.size()];
        for (int i = 0; i < components.size(); i++) {
            args[i] = Type.getType(components.get(i).descriptor);
        }
        return Type.getMethodDescriptor(Type.VOID_TYPE, args);
    }

    @SuppressWarnings("unchecked")
    private static List<RecordComponentNode> recordComponents(L1Class clazz) {
        if (clazz == null || clazz.asmNode().recordComponents == null) return List.of();
        return (List<RecordComponentNode>) clazz.asmNode().recordComponents;
    }
}
