package dev.nekoobfuscator.transforms.jvm.constants;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Records original static primitive array literals before CFF destroys their
 * straightforward initialization shape.
 */
public final class JvmStaticArrayMaterial {
    public static final String PASS_DATA_KEY = "constantObfuscation.staticPrimitiveArrayMaterial";

    private static final String RECORDED_CLASSES_KEY =
        "constantObfuscation.staticPrimitiveArrayMaterial.recordedClasses";
    private static final String USE_SUMMARIES_KEY =
        "constantObfuscation.staticPrimitiveArrayMaterial.useSummaries";
    private static final String ORIGINAL_FIELD_REFLECTION_KEY =
        "constantObfuscation.staticPrimitiveArrayMaterial.originalFieldReflection";
    private static final String ORIGINAL_DYNAMIC_FIELD_ACCESS_KEY =
        "constantObfuscation.staticPrimitiveArrayMaterial.originalDynamicFieldAccess";

    private JvmStaticArrayMaterial() {}

    public static void recordClass(PipelineContext pctx, L1Class clazz) {
        if (clazz == null || TransformGuards.isRuntimeClass(clazz)) return;
        Set<String> recorded = recordedClasses(pctx);
        if (!recorded.add(clazz.name())) return;
        recordFieldUses(clazz, useSummaries(pctx));
        recordDynamicAccessGuards(pctx, clazz);
        MethodNode clinit = classInit(clazz);
        if (clinit == null || clinit.instructions == null) return;
        Map<String, Material> materials = materials(pctx);
        AbstractInsnNode cursor = clinit.instructions.getFirst();
        while (cursor != null) {
            Material material = materialAt(clazz, cursor);
            if (material != null) {
                materials.putIfAbsent(material.key(), material);
            }
            cursor = cursor.getNext();
        }
    }

    public static Map<String, Material> materials(PipelineContext pctx) {
        Map<String, Material> materials = pctx.getPassData(PASS_DATA_KEY);
        if (materials == null) {
            materials = new HashMap<>();
            pctx.putPassData(PASS_DATA_KEY, materials);
        }
        return materials;
    }

    public static Material materialFor(PipelineContext pctx, String owner, String name, String desc) {
        return materials(pctx).get(key(owner, name, desc));
    }

    public static Map<String, UseSummary> useSummaries(PipelineContext pctx) {
        Map<String, UseSummary> uses = pctx.getPassData(USE_SUMMARIES_KEY);
        if (uses == null) {
            uses = new HashMap<>();
            pctx.putPassData(USE_SUMMARIES_KEY, uses);
        }
        return uses;
    }

    public static boolean hasOriginalFieldReflection(PipelineContext pctx) {
        return Boolean.TRUE.equals(pctx.getPassData(ORIGINAL_FIELD_REFLECTION_KEY));
    }

    public static boolean hasOriginalDynamicFieldAccess(PipelineContext pctx) {
        return Boolean.TRUE.equals(pctx.getPassData(ORIGINAL_DYNAMIC_FIELD_ACCESS_KEY));
    }

    public static String key(String owner, String name, String desc) {
        return owner + "." + name + ":" + desc;
    }

    private static Set<String> recordedClasses(PipelineContext pctx) {
        Set<String> recorded = pctx.getPassData(RECORDED_CLASSES_KEY);
        if (recorded == null) {
            recorded = new HashSet<>();
            pctx.putPassData(RECORDED_CLASSES_KEY, recorded);
        }
        return recorded;
    }

    private static MethodNode classInit(L1Class clazz) {
        for (MethodNode method : clazz.asmNode().methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        return null;
    }

    private static Material materialAt(L1Class clazz, AbstractInsnNode lengthInsn) {
        Integer length = intLiteral(lengthInsn);
        if (length == null || length < 0) return null;
        AbstractInsnNode arrayInsn = nextReal(lengthInsn.getNext());
        if (!(arrayInsn instanceof IntInsnNode newArray) || newArray.getOpcode() != Opcodes.NEWARRAY) {
            return null;
        }
        PrimitiveArrayKind kind = PrimitiveArrayKind.fromNewArrayOperand(newArray.operand);
        if (kind == null) return null;
        long[] values = new long[length];
        boolean[] seen = new boolean[length];
        int count = 0;
        AbstractInsnNode cursor = nextReal(arrayInsn.getNext());
        while (cursor != null && cursor.getOpcode() == Opcodes.DUP) {
            AbstractInsnNode indexInsn = nextReal(cursor.getNext());
            Integer index = intLiteral(indexInsn);
            if (index == null || index < 0 || index >= length || seen[index]) return null;
            AbstractInsnNode valueInsn = nextReal(indexInsn.getNext());
            Long bits = arrayElementBits(kind, valueInsn);
            if (bits == null) return null;
            AbstractInsnNode storeInsn = nextReal(valueInsn.getNext());
            if (storeInsn == null || storeInsn.getOpcode() != kind.storeOpcode()) return null;
            values[index] = bits;
            seen[index] = true;
            count++;
            cursor = nextReal(storeInsn.getNext());
        }
        if (count != length) return null;
        if (!(cursor instanceof FieldInsnNode put) ||
            put.getOpcode() != Opcodes.PUTSTATIC ||
            !clazz.name().equals(put.owner) ||
            !kind.descriptor().equals(put.desc)) {
            return null;
        }
        FieldNode field = field(clazz, put.name, put.desc);
        if (field == null || (field.access & Opcodes.ACC_STATIC) == 0) return null;
        return new Material(put.owner, put.name, put.desc, kind, values);
    }

    private static FieldNode field(L1Class clazz, String name, String desc) {
        for (FieldNode field : clazz.asmNode().fields) {
            if (field.name.equals(name) && field.desc.equals(desc)) return field;
        }
        return null;
    }

    private static void recordFieldUses(L1Class clazz, Map<String, UseSummary> uses) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (TransformGuards.isGeneratedMethod(method)) continue;
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!(insn instanceof FieldInsnNode field)) continue;
                PrimitiveArrayKind kind = PrimitiveArrayKind.fromDescriptor(field.desc);
                if (kind == null) continue;
                UseSummary summary = uses.computeIfAbsent(key(field.owner, field.name, field.desc), ignored -> new UseSummary());
                int opcode = field.getOpcode();
                if (opcode == Opcodes.GETSTATIC) {
                    summary.recordGet(isReadOnlyPrimitiveArrayGetUse(field, kind));
                } else if (opcode == Opcodes.PUTSTATIC) {
                    summary.recordPut(clazz.name().equals(field.owner) && isClassInit(method));
                } else {
                    summary.recordUnsafe();
                }
            }
        }
    }

    private static void recordDynamicAccessGuards(PipelineContext pctx, L1Class clazz) {
        for (MethodNode method : clazz.asmNode().methods) {
            if (TransformGuards.isGeneratedMethod(method)) continue;
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode call) {
                    if (isReflectiveFieldAccess(call)) {
                        pctx.putPassData(ORIGINAL_FIELD_REFLECTION_KEY, Boolean.TRUE);
                    }
                    if (isMethodHandleFieldAccess(call)) {
                        pctx.putPassData(ORIGINAL_DYNAMIC_FIELD_ACCESS_KEY, Boolean.TRUE);
                    }
                } else if (insn instanceof LdcInsnNode ldc) {
                    if (containsDynamicFieldAccess(ldc.cst)) {
                        pctx.putPassData(ORIGINAL_DYNAMIC_FIELD_ACCESS_KEY, Boolean.TRUE);
                    }
                } else if (insn instanceof org.objectweb.asm.tree.InvokeDynamicInsnNode indy) {
                    if (containsDynamicFieldAccess(indy.bsm) ||
                        indyProtocolMayResolvePrimitiveArrayField(indy.name, indy.desc, indy.bsmArgs)) {
                        pctx.putPassData(ORIGINAL_DYNAMIC_FIELD_ACCESS_KEY, Boolean.TRUE);
                    }
                    for (Object arg : indy.bsmArgs) {
                        if (containsDynamicFieldAccess(arg)) {
                            pctx.putPassData(ORIGINAL_DYNAMIC_FIELD_ACCESS_KEY, Boolean.TRUE);
                            break;
                        }
                    }
                }
            }
        }
    }

    private static boolean isReflectiveFieldAccess(MethodInsnNode call) {
        if ("java/lang/reflect/Field".equals(call.owner)) return true;
        if (!"java/lang/Class".equals(call.owner)) return false;
        if (("getField".equals(call.name) || "getDeclaredField".equals(call.name)) &&
            "(Ljava/lang/String;)Ljava/lang/reflect/Field;".equals(call.desc)) {
            return true;
        }
        return ("getFields".equals(call.name) || "getDeclaredFields".equals(call.name)) &&
            "()[Ljava/lang/reflect/Field;".equals(call.desc);
    }

    private static boolean isMethodHandleFieldAccess(MethodInsnNode call) {
        if ("java/lang/invoke/VarHandle".equals(call.owner)) return true;
        if (!"java/lang/invoke/MethodHandles$Lookup".equals(call.owner)) return false;
        return switch (call.name) {
            case "findGetter", "findSetter", "findStaticGetter", "findStaticSetter",
                "findVarHandle", "findStaticVarHandle", "unreflectGetter",
                "unreflectSetter", "unreflectVarHandle" -> true;
            default -> false;
        };
    }

    private static boolean containsDynamicFieldAccess(Object value) {
        if (value instanceof Handle handle) {
            return isFieldHandle(handle) || isKnownFieldResolvingBootstrap(handle);
        }
        if (value instanceof ConstantDynamic dynamic) {
            if (PrimitiveArrayKind.fromDescriptor(dynamic.getDescriptor()) != null) {
                return true;
            }
            if (containsDynamicFieldAccess(dynamic.getBootstrapMethod())) return true;
            boolean hasString = protocolNameMayCarryFieldName(dynamic.getName());
            boolean hasPrimitiveArrayType = false;
            for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
                Object argument = dynamic.getBootstrapMethodArgument(i);
                if (containsDynamicFieldAccess(argument)) {
                    return true;
                }
                hasString |= containsString(argument);
                hasPrimitiveArrayType |= containsPrimitiveArrayType(argument);
            }
            return hasString && hasPrimitiveArrayType;
        }
        return false;
    }

    private static boolean indyProtocolMayResolvePrimitiveArrayField(String name, String desc, Object[] args) {
        boolean descriptorMentionsPrimitiveArray = methodDescriptorMentionsPrimitiveArray(desc);
        boolean hasString = protocolNameMayCarryFieldName(name);
        boolean hasPrimitiveArrayType = false;
        for (Object arg : args) {
            hasString |= containsString(arg);
            hasPrimitiveArrayType |= containsPrimitiveArrayType(arg);
            if (containsDynamicFieldAccess(arg)) return true;
        }
        return hasString && (hasPrimitiveArrayType || descriptorMentionsPrimitiveArray);
    }

    private static boolean protocolNameMayCarryFieldName(String name) {
        return name != null && !name.isEmpty();
    }

    private static boolean containsString(Object value) {
        if (value instanceof String) return true;
        if (value instanceof ConstantDynamic dynamic) {
            for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
                if (containsString(dynamic.getBootstrapMethodArgument(i))) return true;
            }
        }
        return false;
    }

    private static boolean containsPrimitiveArrayType(Object value) {
        if (value instanceof Type type) {
            if (type.getSort() == Type.ARRAY) {
                return PrimitiveArrayKind.fromDescriptor(type.getDescriptor()) != null;
            }
            if (type.getSort() == Type.METHOD) {
                if (isPrimitiveArrayType(type.getReturnType())) return true;
                for (Type argument : type.getArgumentTypes()) {
                    if (isPrimitiveArrayType(argument)) return true;
                }
            }
        }
        if (value instanceof String text) {
            return PrimitiveArrayKind.fromDescriptor(text) != null;
        }
        if (value instanceof ConstantDynamic dynamic) {
            if (PrimitiveArrayKind.fromDescriptor(dynamic.getDescriptor()) != null) return true;
            for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
                if (containsPrimitiveArrayType(dynamic.getBootstrapMethodArgument(i))) return true;
            }
        }
        return false;
    }

    private static boolean methodDescriptorMentionsPrimitiveArray(String desc) {
        Type method = Type.getMethodType(desc);
        if (isPrimitiveArrayType(method.getReturnType())) return true;
        for (Type arg : method.getArgumentTypes()) {
            if (isPrimitiveArrayType(arg)) return true;
        }
        return false;
    }

    private static boolean isPrimitiveArrayType(Type type) {
        return type.getSort() == Type.ARRAY &&
            PrimitiveArrayKind.fromDescriptor(type.getDescriptor()) != null;
    }

    private static boolean isFieldHandle(Handle handle) {
        return switch (handle.getTag()) {
            case Opcodes.H_GETFIELD, Opcodes.H_GETSTATIC, Opcodes.H_PUTFIELD, Opcodes.H_PUTSTATIC ->
                PrimitiveArrayKind.fromDescriptor(handle.getDesc()) != null;
            default -> false;
        };
    }

    private static boolean isKnownFieldResolvingBootstrap(Handle handle) {
        return handle.getTag() == Opcodes.H_INVOKESTATIC &&
            "java/lang/invoke/ConstantBootstraps".equals(handle.getOwner()) &&
            switch (handle.getName()) {
                case "getStaticFinal", "fieldVarHandle", "staticFieldVarHandle" -> true;
                default -> false;
            };
    }

    private static boolean isClassInit(MethodNode method) {
        return "<clinit>".equals(method.name) && "()V".equals(method.desc);
    }

    private static boolean isReadOnlyPrimitiveArrayGetUse(FieldInsnNode get, PrimitiveArrayKind kind) {
        AbstractInsnNode first = nextReal(get.getNext());
        if (first == null) return false;
        if (first.getOpcode() == Opcodes.ARRAYLENGTH) {
            return true;
        }
        if (first instanceof MethodInsnNode call && isKnownReadOnlyPrimitiveArrayConsumer(call, kind)) {
            return true;
        }

        int depthAboveArray = 0;
        int scanned = 0;
        for (AbstractInsnNode cursor = first; cursor != null && scanned++ < 64; cursor = nextReal(cursor.getNext())) {
            int opcode = cursor.getOpcode();
            if (opcode == kind.loadOpcode()) {
                return depthAboveArray == 1;
            }
            IntStackEffect effect = intIndexStackEffect(cursor);
            if (effect == null || depthAboveArray < effect.consumes()) {
                return false;
            }
            depthAboveArray = depthAboveArray - effect.consumes() + effect.produces();
            if (depthAboveArray > 8) {
                return false;
            }
        }
        return false;
    }

    private static boolean isKnownReadOnlyPrimitiveArrayConsumer(MethodInsnNode call, PrimitiveArrayKind kind) {
        return kind == PrimitiveArrayKind.BYTE &&
            call.getOpcode() == Opcodes.INVOKEVIRTUAL &&
            "java/security/MessageDigest".equals(call.owner) &&
            "update".equals(call.name) &&
            "([B)V".equals(call.desc);
    }

    private static IntStackEffect intIndexStackEffect(AbstractInsnNode insn) {
        if (insn == null) return null;
        int opcode = insn.getOpcode();
        if ((opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) ||
            opcode == Opcodes.BIPUSH ||
            opcode == Opcodes.SIPUSH ||
            opcode == Opcodes.ILOAD ||
            (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer)) {
            return new IntStackEffect(0, 1);
        }
        if (opcode == Opcodes.IINC) {
            return new IntStackEffect(0, 0);
        }
        if (opcode == Opcodes.INEG ||
            opcode == Opcodes.I2B ||
            opcode == Opcodes.I2C ||
            opcode == Opcodes.I2S) {
            return new IntStackEffect(1, 1);
        }
        if (opcode == Opcodes.IADD ||
            opcode == Opcodes.ISUB ||
            opcode == Opcodes.IMUL ||
            opcode == Opcodes.IDIV ||
            opcode == Opcodes.IREM ||
            opcode == Opcodes.ISHL ||
            opcode == Opcodes.ISHR ||
            opcode == Opcodes.IUSHR ||
            opcode == Opcodes.IAND ||
            opcode == Opcodes.IOR ||
            opcode == Opcodes.IXOR) {
            return new IntStackEffect(2, 1);
        }
        return null;
    }

    private static Long arrayElementBits(PrimitiveArrayKind kind, AbstractInsnNode insn) {
        return switch (kind) {
            case BOOLEAN -> {
                Integer value = intLiteral(insn);
                yield value == null ? null : (long) (value == 0 ? 0 : 1);
            }
            case BYTE -> {
                Integer value = intLiteral(insn);
                yield value == null ? null : (long) (byte) value.intValue();
            }
            case CHAR -> {
                Integer value = intLiteral(insn);
                yield value == null ? null : (long) (char) value.intValue();
            }
            case SHORT -> {
                Integer value = intLiteral(insn);
                yield value == null ? null : (long) (short) value.intValue();
            }
            case INT -> {
                Integer value = intLiteral(insn);
                yield value == null ? null : value.longValue();
            }
            case LONG -> longLiteral(insn);
            case FLOAT -> {
                Float value = floatLiteral(insn);
                yield value == null ? null : (long) Float.floatToRawIntBits(value);
            }
            case DOUBLE -> {
                Double value = doubleLiteral(insn);
                yield value == null ? null : Double.doubleToRawLongBits(value);
            }
        };
    }

    private static Integer intLiteral(AbstractInsnNode insn) {
        if (insn == null) return null;
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return opcode - Opcodes.ICONST_0;
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return ((IntInsnNode) insn).operand;
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) {
            return value;
        }
        return null;
    }

    private static Long longLiteral(AbstractInsnNode insn) {
        if (insn == null) return null;
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.LCONST_0) return 0L;
        if (opcode == Opcodes.LCONST_1) return 1L;
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Long value) {
            return value;
        }
        return null;
    }

    private static Float floatLiteral(AbstractInsnNode insn) {
        if (insn == null) return null;
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.FCONST_0 && opcode <= Opcodes.FCONST_2) {
            return (float) (opcode - Opcodes.FCONST_0);
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Float value) {
            return value;
        }
        return null;
    }

    private static Double doubleLiteral(AbstractInsnNode insn) {
        if (insn == null) return null;
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.DCONST_0) return 0.0d;
        if (opcode == Opcodes.DCONST_1) return 1.0d;
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Double value) {
            return value;
        }
        return null;
    }

    private static AbstractInsnNode nextReal(AbstractInsnNode insn) {
        AbstractInsnNode cursor = insn;
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getNext();
        }
        return cursor;
    }

    public record Material(
        String owner,
        String name,
        String desc,
        PrimitiveArrayKind kind,
        long[] values
    ) {
        public String key() {
            return JvmStaticArrayMaterial.key(owner, name, desc);
        }
    }

    public static final class UseSummary {
        private int gets;
        private int puts;
        private boolean unsafe;

        public int gets() {
            return gets;
        }

        public int puts() {
            return puts;
        }

        public boolean unsafe() {
            return unsafe;
        }

        private void recordGet(boolean safe) {
            gets++;
            if (!safe) unsafe = true;
        }

        private void recordPut(boolean safe) {
            puts++;
            if (!safe) unsafe = true;
        }

        private void recordUnsafe() {
            unsafe = true;
        }
    }

    private record IntStackEffect(int consumes, int produces) {}

    public enum PrimitiveArrayKind {
        BOOLEAN("[Z", Opcodes.T_BOOLEAN, Opcodes.BASTORE, Opcodes.BALOAD),
        BYTE("[B", Opcodes.T_BYTE, Opcodes.BASTORE, Opcodes.BALOAD),
        CHAR("[C", Opcodes.T_CHAR, Opcodes.CASTORE, Opcodes.CALOAD),
        SHORT("[S", Opcodes.T_SHORT, Opcodes.SASTORE, Opcodes.SALOAD),
        INT("[I", Opcodes.T_INT, Opcodes.IASTORE, Opcodes.IALOAD),
        LONG("[J", Opcodes.T_LONG, Opcodes.LASTORE, Opcodes.LALOAD),
        FLOAT("[F", Opcodes.T_FLOAT, Opcodes.FASTORE, Opcodes.FALOAD),
        DOUBLE("[D", Opcodes.T_DOUBLE, Opcodes.DASTORE, Opcodes.DALOAD);

        private final String descriptor;
        private final int newArrayOperand;
        private final int storeOpcode;
        private final int loadOpcode;

        PrimitiveArrayKind(String descriptor, int newArrayOperand, int storeOpcode, int loadOpcode) {
            this.descriptor = descriptor;
            this.newArrayOperand = newArrayOperand;
            this.storeOpcode = storeOpcode;
            this.loadOpcode = loadOpcode;
        }

        public String descriptor() {
            return descriptor;
        }

        public int newArrayOperand() {
            return newArrayOperand;
        }

        public int storeOpcode() {
            return storeOpcode;
        }

        public int loadOpcode() {
            return loadOpcode;
        }

        public static PrimitiveArrayKind fromNewArrayOperand(int operand) {
            for (PrimitiveArrayKind kind : values()) {
                if (kind.newArrayOperand == operand) return kind;
            }
            return null;
        }

        public static PrimitiveArrayKind fromDescriptor(String desc) {
            for (PrimitiveArrayKind kind : values()) {
                if (kind.descriptor.equals(desc)) return kind;
            }
            return null;
        }
    }
}
