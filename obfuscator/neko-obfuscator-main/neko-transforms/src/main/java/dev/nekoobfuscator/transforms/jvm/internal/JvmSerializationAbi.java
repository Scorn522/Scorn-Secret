package dev.nekoobfuscator.transforms.jvm.internal;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.HashSet;
import java.util.Set;

public final class JvmSerializationAbi {
    private JvmSerializationAbi() {
    }

    public static boolean isSerializationMagicMethod(PipelineContext pctx, L1Class clazz, L1Method method) {
        return method != null && isSerializationMagicMethod(pctx, clazz, method.asmNode());
    }

    public static boolean isSerializationMagicMethod(PipelineContext pctx, L1Class clazz, MethodNode method) {
        if (method == null || clazz == null || !isSerializableClass(pctx, clazz)) return false;
        if ((method.access & Opcodes.ACC_STATIC) != 0) return false;
        return switch (method.name) {
            case "writeObject" -> "(Ljava/io/ObjectOutputStream;)V".equals(method.desc);
            case "readObject" -> "(Ljava/io/ObjectInputStream;)V".equals(method.desc);
            case "readObjectNoData" -> "()V".equals(method.desc);
            case "writeReplace", "readResolve" -> "()Ljava/lang/Object;".equals(method.desc);
            default -> false;
        };
    }

    public static boolean isSerializationAbiField(PipelineContext pctx, L1Class clazz, FieldNode field) {
        if (field == null) return false;
        if (isSerialVersionUidField(field) || isSerialPersistentFieldsField(field)) return true;
        if (clazz == null || !isSerializableClass(pctx, clazz)) return false;
        int access = field.access;
        return (access & (Opcodes.ACC_STATIC | Opcodes.ACC_TRANSIENT)) == 0;
    }

    public static boolean isSerialVersionUidField(FieldNode field) {
        return field != null
            && "serialVersionUID".equals(field.name)
            && "J".equals(field.desc)
            && (field.access & Opcodes.ACC_STATIC) != 0;
    }

    private static boolean isSerialPersistentFieldsField(FieldNode field) {
        return field != null
            && "serialPersistentFields".equals(field.name)
            && "[Ljava/io/ObjectStreamField;".equals(field.desc)
            && (field.access & Opcodes.ACC_STATIC) != 0;
    }

    public static boolean isSerializableClass(PipelineContext pctx, L1Class clazz) {
        return isSerializableClass(pctx, clazz, new HashSet<>());
    }

    private static boolean isSerializableClass(PipelineContext pctx, L1Class clazz, Set<String> seen) {
        if (clazz == null || !seen.add(clazz.name())) return false;
        if (containsSerializable(clazz.interfaces())) return true;
        if (pctx == null) return false;
        for (String iface : clazz.interfaces()) {
            if (isSerializableClass(pctx, pctx.classMap().get(iface), seen)) return true;
        }
        return isSerializableClass(pctx, pctx.classMap().get(clazz.superName()), seen);
    }

    private static boolean containsSerializable(Iterable<String> interfaces) {
        if (interfaces == null) return false;
        for (String iface : interfaces) {
            if ("java/io/Serializable".equals(iface) || "java/io/Externalizable".equals(iface)) {
                return true;
            }
        }
        return false;
    }
}
