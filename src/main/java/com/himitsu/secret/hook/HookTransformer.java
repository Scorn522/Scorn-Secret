package com.himitsu.secret.hook;

import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.himitsu.secret.transform.LoaderAwareClassWriter;
import com.himitsu.secret.util.DynamicMethodLookup;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

public final class HookTransformer {
    private static final String RESULT_CANCELLED_METHOD = DynamicMethodLookup.findInstance(
        HookResult.class, boolean.class
    ).getName();
    private static final String RESULT_VALUE_METHOD = DynamicMethodLookup.findInstance(
        HookResult.class, Object.class
    ).getName();

    private HookTransformer() {
    }

    public static byte[] transform(
        ClassLoader loader,
        String className,
        Class<?> classBeingRedefined,
        ProtectionDomain protectionDomain,
        byte[] classfileBuffer
    ) {
        if (classfileBuffer == null || (!HookRegistry.hasTarget(className) && !HookRegistry.hasSubclassTargets())) {
            return classfileBuffer;
        }
        ClassNode classNode = new ClassNode(Opcodes.ASM9);
        new ClassReader(classfileBuffer).accept(classNode, ClassReader.EXPAND_FRAMES);
        HookRegistry.recordClass(className);
        Set<String> ancestors = ancestors(loader, classNode);
        if (classBeingRedefined != null) {
            collectReflectionAncestors(classBeingRedefined, ancestors);
        }
        Collection<HookDefinition> definitions = HookRegistry.hooksFor(className, ancestors);
        if (definitions.isEmpty()) return classfileBuffer;

        Map<String, List<HookDefinition>> byMethod = new HashMap<>();
        for (HookDefinition definition : definitions) {
            for (String targetMethod : definition.targetMethods()) {
                byMethod.computeIfAbsent(methodKey(targetMethod, definition.targetDescriptor()), ignored -> new ArrayList<>())
                    .add(definition);
            }
        }

        boolean changed = false;
        for (MethodNode method : classNode.methods) {
            List<HookDefinition> hooks = byMethod.get(methodKey(method.name, method.desc));
            if (hooks != null) {
                hooks.forEach(HookRegistry::recordMatch);
                changed |= applyHooks(method, hooks);
            }
        }
        if (!changed) {
            return classfileBuffer;
        }

        int writerFlags = requiresNewFrames(definitions)
            ? ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS
            : ClassWriter.COMPUTE_MAXS;
        ClassWriter writer = new LoaderAwareClassWriter(writerFlags, loader);
        classNode.accept(writer);
        byte[] transformed = writer.toByteArray();
        validateSchema(classfileBuffer, transformed, className);
        return transformed;
    }

    private static boolean requiresNewFrames(Collection<HookDefinition> definitions) {
        for (HookDefinition definition : definitions) {
            if (definition.mode() == HookMode.GUARD || definition.mode() == HookMode.SCOPE || definition.cancellable()) {
                return true;
            }
        }
        return false;
    }

    private static void validateSchema(byte[] original, byte[] transformed, String requestedName) {
        ClassNode before = structuralNode(original);
        ClassNode after = structuralNode(transformed);
        if (!before.name.equals(after.name)
            || !before.name.equals(requestedName.replace('.', '/'))
            || !java.util.Objects.equals(before.superName, after.superName)
            || !before.interfaces.equals(after.interfaces)
            || !memberKeys(before.fields).equals(memberKeys(after.fields))
            || !memberKeys(before.methods).equals(memberKeys(after.methods))) {
            throw new IllegalStateException("Hook transformation changed class schema: " + requestedName);
        }
    }

    private static ClassNode structuralNode(byte[] bytes) {
        ClassNode node = new ClassNode(Opcodes.ASM9);
        new ClassReader(bytes).accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return node;
    }

    private static Set<String> memberKeys(Collection<?> members) {
        Set<String> keys = new HashSet<>();
        for (Object member : members) {
            if (member instanceof org.objectweb.asm.tree.FieldNode field) {
                keys.add("F:" + field.name + field.desc);
            } else if (member instanceof MethodNode method) {
                keys.add("M:" + method.name + method.desc);
            }
        }
        return keys;
    }

    private static boolean applyHooks(MethodNode method, List<HookDefinition> hooks) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }

        HookDefinition terminal = null;
        for (HookDefinition hook : hooks) {
            if (hook.mode() == HookMode.OVERRIDE || hook.mode() == HookMode.CLEAR) {
                if (terminal != null) {
                    throw new IllegalStateException("Multiple terminal hooks target " + method.name + method.desc);
                }
                terminal = hook;
            }
        }

        if (terminal != null) {
            method.instructions.clear();
            method.tryCatchBlocks.clear();
            method.localVariables = null;
            method.visibleLocalVariableAnnotations = null;
            method.invisibleLocalVariableAnnotations = null;
            if (terminal.mode() == HookMode.OVERRIDE) {
                method.instructions.add(loadArguments(method, terminal));
                method.instructions.add(callbackCall(terminal));
                method.instructions.add(new InsnNode(Type.getReturnType(method.desc).getOpcode(Opcodes.IRETURN)));
            } else {
                method.instructions.add(defaultReturn(Type.getReturnType(method.desc)));
            }
            return true;
        }

        boolean changed = false;
        Set<String> insertedCallbacks = new HashSet<>();
        InsnList entry = new InsnList();
        for (HookDefinition hook : hooks) {
            String callbackKey = callbackKey(hook);
            if (hook.isHeadMode()
                && insertedCallbacks.add(callbackKey)
                && !containsCallback(method, hook)) {
                entry.add(loadArguments(method, hook));
                entry.add(callbackCall(hook));
                if (hook.cancellable()) entry.add(cancellableReturn(Type.getReturnType(method.desc)));
                changed = true;
            }
        }
        method.instructions.insert(entry);

        Set<String> guardedCallbacks = new HashSet<>();
        InsnList guards = new InsnList();
        for (HookDefinition hook : hooks) {
            String callbackKey = callbackKey(hook);
            if (hook.mode() == HookMode.GUARD
                && guardedCallbacks.add(callbackKey)
                && !containsCallback(method, hook)) {
                LabelNode proceed = new LabelNode();
                guards.add(loadArguments(method, hook));
                guards.add(callbackCall(hook));
                guards.add(new JumpInsnNode(Opcodes.IFEQ, proceed));
                guards.add(defaultReturn(Type.getReturnType(method.desc)));
                guards.add(proceed);
                changed = true;
            }
        }
        method.instructions.insert(guards);

        Set<String> appendedCallbacks = new HashSet<>();
        List<HookDefinition> appendHooks = new ArrayList<>();
        for (HookDefinition hook : hooks) {
            String callbackKey = callbackKey(hook);
            if (hook.isReturnMode()
                && appendedCallbacks.add(callbackKey)
                && !hasDominantReturnCallback(method, hook)) {
                appendHooks.add(hook);
            }
        }
        for (AbstractInsnNode instruction = method.instructions.getFirst(); instruction != null; ) {
            AbstractInsnNode next = instruction.getNext();
            if (isReturn(instruction.getOpcode()) && !appendHooks.isEmpty()) {
                InsnList append = new InsnList();
                Type returnType = Type.getReturnType(method.desc);
                int resultLocal = method.maxLocals;
                if (returnType.getSort() != Type.VOID) {
                    method.maxLocals += returnType.getSize();
                    append.add(new VarInsnNode(returnType.getOpcode(Opcodes.ISTORE), resultLocal));
                }
                for (HookDefinition hook : appendHooks) {
                    append.add(loadArguments(method, hook));
                    if (hook.includeResult()) {
                        append.add(new VarInsnNode(returnType.getOpcode(Opcodes.ILOAD), resultLocal));
                    }
                    append.add(callbackCall(hook));
                    if (hook.cancellable()) {
                        append.add(resolveReturnResult(returnType, resultLocal));
                    }
                }
                if (returnType.getSort() != Type.VOID) {
                    append.add(new VarInsnNode(returnType.getOpcode(Opcodes.ILOAD), resultLocal));
                }
                method.instructions.insertBefore(instruction, append);
                changed = true;
            }
            instruction = next;
        }
        for (HookDefinition hook : hooks) {
            if (hook.mode() == HookMode.SCOPE && !containsCallback(method, hook)) {
                scope(method, hook); changed = true;
            }
        }
        return changed;
    }

    /** One finally edge covers normal returns and exceptions; no leaked permission after a failed click. */
    private static void scope(MethodNode method, HookDefinition hook) {
        InsnList entry = new InsnList();
        Type[] args = Type.getArgumentTypes(method.desc);
        java.util.List<Integer> saved = new java.util.ArrayList<>();
        java.util.List<Type> types = new java.util.ArrayList<>();
        int original = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        if (hook.includeThis()) {
            types.add(Type.getObjectType(hook.targetClass()));
            int slot = method.maxLocals++; saved.add(slot);
            entry.add(new VarInsnNode(Opcodes.ALOAD, 0)); entry.add(new VarInsnNode(Opcodes.ASTORE, slot));
        }
        for (Type type : args) {
            types.add(type); int slot = method.maxLocals; method.maxLocals += type.getSize(); saved.add(slot);
            entry.add(new VarInsnNode(type.getOpcode(Opcodes.ILOAD), original));
            entry.add(new VarInsnNode(type.getOpcode(Opcodes.ISTORE), slot)); original += type.getSize();
        }
        entry.add(scopeCall(hook, types, saved, true));
        LabelNode start = new LabelNode(), end = new LabelNode(), success = new LabelNode(), failure = new LabelNode();
        entry.add(start); method.instructions.insert(entry);
        Type result = Type.getReturnType(method.desc);
        int resultSlot = method.maxLocals; method.maxLocals += result.getSize();
        int errorSlot = method.maxLocals++;
        for (AbstractInsnNode insn = start.getNext(); insn != null;) {
            AbstractInsnNode next = insn.getNext();
            if (isReturn(insn.getOpcode())) {
                InsnList exit = new InsnList();
                if (result.getSort() != Type.VOID) exit.add(new VarInsnNode(result.getOpcode(Opcodes.ISTORE), resultSlot));
                exit.add(new JumpInsnNode(Opcodes.GOTO, success)); method.instructions.insertBefore(insn, exit); method.instructions.remove(insn);
            }
            insn = next;
        }
        method.instructions.add(end); method.instructions.add(success);
        method.instructions.add(scopeCall(hook, types, saved, false));
        if (result.getSort() != Type.VOID) method.instructions.add(new VarInsnNode(result.getOpcode(Opcodes.ILOAD), resultSlot));
        method.instructions.add(new InsnNode(result.getOpcode(Opcodes.IRETURN)));
        method.instructions.add(failure); method.instructions.add(new VarInsnNode(Opcodes.ASTORE, errorSlot));
        method.instructions.add(scopeCall(hook, types, saved, false));
        method.instructions.add(new VarInsnNode(Opcodes.ALOAD, errorSlot)); method.instructions.add(new InsnNode(Opcodes.ATHROW));
        method.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(start, end, failure, null));
    }

    private static InsnList scopeCall(HookDefinition hook, java.util.List<Type> types, java.util.List<Integer> saved, boolean enter) {
        InsnList code = new InsnList();
        for (int i=0; i<types.size(); i++) code.add(new VarInsnNode(types.get(i).getOpcode(Opcodes.ILOAD), saved.get(i)));
        code.add(new InsnNode(enter ? Opcodes.ICONST_1 : Opcodes.ICONST_0)); code.add(callbackCall(hook)); return code;
    }

    private static InsnList loadArguments(MethodNode method, HookDefinition hook) {
        InsnList instructions = new InsnList();
        boolean instanceMethod = (method.access & Opcodes.ACC_STATIC) == 0;
        if (hook.includeThis()) {
            if (!instanceMethod) {
                throw new IllegalStateException("Cannot pass this for static method " + method.name + method.desc);
            }
            instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        }
        int local = instanceMethod ? 1 : 0;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            instructions.add(new VarInsnNode(argument.getOpcode(Opcodes.ILOAD), local));
            local += argument.getSize();
        }
        return instructions;
    }

    private static MethodInsnNode callbackCall(HookDefinition hook) {
        return new MethodInsnNode(
            Opcodes.INVOKESTATIC,
            hook.callbackOwner(),
            hook.callbackName(),
            hook.callbackDescriptor(),
            false
        );
    }

    private static InsnList cancellableReturn(Type returnType) {
        InsnList instructions = new InsnList();
        LabelNode proceed = new LabelNode();
        instructions.add(new InsnNode(Opcodes.DUP));
        instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, Type.getInternalName(HookResult.class),
            RESULT_CANCELLED_METHOD, "()Z", false));
        instructions.add(new JumpInsnNode(Opcodes.IFEQ, proceed));
        instructions.add(unboxResult(returnType));
        instructions.add(new InsnNode(returnType.getOpcode(Opcodes.IRETURN)));
        instructions.add(proceed);
        instructions.add(new InsnNode(Opcodes.POP));
        return instructions;
    }

    private static InsnList resolveReturnResult(Type returnType, int resultLocal) {
        InsnList instructions = new InsnList();
        LabelNode unchanged = new LabelNode();
        LabelNode done = new LabelNode();
        instructions.add(new InsnNode(Opcodes.DUP));
        instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, Type.getInternalName(HookResult.class),
            RESULT_CANCELLED_METHOD, "()Z", false));
        instructions.add(new JumpInsnNode(Opcodes.IFEQ, unchanged));
        instructions.add(unboxResult(returnType));
        if (returnType.getSort() != Type.VOID) {
            instructions.add(new VarInsnNode(returnType.getOpcode(Opcodes.ISTORE), resultLocal));
        }
        instructions.add(new JumpInsnNode(Opcodes.GOTO, done));
        instructions.add(unchanged);
        instructions.add(new InsnNode(Opcodes.POP));
        instructions.add(done);
        return instructions;
    }

    private static InsnList unboxResult(Type type) {
        InsnList instructions = new InsnList();
        instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, Type.getInternalName(HookResult.class),
            RESULT_VALUE_METHOD, "()Ljava/lang/Object;", false));
        if (type.getSort() == Type.VOID) {
            instructions.add(new InsnNode(Opcodes.POP));
            return instructions;
        }
        if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
            instructions.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.CHECKCAST, type.getInternalName()));
            return instructions;
        }
        Type boxed = boxedType(type);
        instructions.add(new org.objectweb.asm.tree.TypeInsnNode(Opcodes.CHECKCAST, boxed.getInternalName()));
        instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, boxed.getInternalName(),
            unboxMethod(type), "()" + type.getDescriptor(), false));
        return instructions;
    }

    private static Type boxedType(Type type) {
        return switch (type.getSort()) {
            case Type.BOOLEAN -> Type.getType(Boolean.class);
            case Type.BYTE -> Type.getType(Byte.class);
            case Type.CHAR -> Type.getType(Character.class);
            case Type.SHORT -> Type.getType(Short.class);
            case Type.INT -> Type.getType(Integer.class);
            case Type.FLOAT -> Type.getType(Float.class);
            case Type.LONG -> Type.getType(Long.class);
            case Type.DOUBLE -> Type.getType(Double.class);
            default -> throw new IllegalArgumentException("Not primitive: " + type);
        };
    }

    private static String unboxMethod(Type type) {
        return switch (type.getSort()) {
            case Type.BOOLEAN -> "booleanValue";
            case Type.BYTE -> "byteValue";
            case Type.CHAR -> "charValue";
            case Type.SHORT -> "shortValue";
            case Type.INT -> "intValue";
            case Type.FLOAT -> "floatValue";
            case Type.LONG -> "longValue";
            case Type.DOUBLE -> "doubleValue";
            default -> throw new IllegalArgumentException("Not primitive: " + type);
        };
    }

    private static Set<String> ancestors(ClassLoader loader, ClassNode node) {
        Set<String> ancestors = new HashSet<>();
        List<String> pending = new ArrayList<>();
        if (node.superName != null) pending.add(node.superName);
        pending.addAll(node.interfaces);
        ClassLoader effectiveLoader = loader != null ? loader : HookTransformer.class.getClassLoader();
        while (!pending.isEmpty()) {
            String name = pending.remove(pending.size() - 1);
            if (!ancestors.add(name)) continue;
            try (java.io.InputStream input = effectiveLoader.getResourceAsStream(name + ".class")) {
                if (input == null) continue;
                ClassReader reader = new ClassReader(input);
                if (reader.getSuperName() != null) pending.add(reader.getSuperName());
                pending.addAll(java.util.Arrays.asList(reader.getInterfaces()));
            } catch (java.io.IOException ignored) {
            }
        }
        return ancestors;
    }

    private static void collectReflectionAncestors(Class<?> type, Set<String> ancestors) {
        if (type == null) return;
        Class<?> parent = type.getSuperclass();
        if (parent != null && ancestors.add(parent.getName().replace('.', '/'))) {
            collectReflectionAncestors(parent, ancestors);
        }
        for (Class<?> contract : type.getInterfaces()) {
            if (ancestors.add(contract.getName().replace('.', '/'))) {
                collectReflectionAncestors(contract, ancestors);
            }
        }
    }

    private static boolean containsCallback(MethodNode method, HookDefinition hook) {
        for (AbstractInsnNode instruction = method.instructions.getFirst(); instruction != null; instruction = instruction.getNext()) {
            if (instruction instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKESTATIC
                && call.owner.equals(hook.callbackOwner())
                && call.name.equals(hook.callbackName())
                && call.desc.equals(hook.callbackDescriptor())) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasDominantReturnCallback(MethodNode method, HookDefinition hook) {
        boolean foundReturn = false;
        for (AbstractInsnNode instruction = method.instructions.getFirst();
             instruction != null;
             instruction = instruction.getNext()) {
            if (!isReturn(instruction.getOpcode())) continue;
            foundReturn = true;
            if (!hasDominantReturnCallback(instruction, hook)) return false;
        }
        return foundReturn;
    }

    private static boolean hasDominantReturnCallback(AbstractInsnNode returnInstruction, HookDefinition hook) {
        int inspected = 0;
        for (AbstractInsnNode instruction = returnInstruction.getPrevious();
             instruction != null && inspected++ < 48;
             instruction = instruction.getPrevious()) {
            int opcode = instruction.getOpcode();
            if (isReturn(opcode) || opcode == Opcodes.ATHROW) return false;
            if (instruction instanceof MethodInsnNode call) {
                if (call.getOpcode() == Opcodes.INVOKESTATIC
                    && call.owner.equals(hook.callbackOwner())
                    && call.name.equals(hook.callbackName())
                    && call.desc.equals(hook.callbackDescriptor())) {
                    return true;
                }
                if (call.getOpcode() == Opcodes.INVOKEVIRTUAL
                    && call.owner.equals(Type.getInternalName(HookResult.class))
                    && (call.name.equals(RESULT_CANCELLED_METHOD) || call.name.equals(RESULT_VALUE_METHOD))) {
                    continue;
                }
                if (isPrimitiveUnboxCall(call)) continue;
                return false;
            }
            if (opcode < 0
                || opcode == Opcodes.NOP
                || opcode == Opcodes.DUP
                || opcode == Opcodes.POP
                || opcode == Opcodes.GOTO
                || opcode == Opcodes.IFEQ
                || opcode == Opcodes.CHECKCAST
                || opcode >= Opcodes.ILOAD && opcode <= Opcodes.ALOAD
                || opcode >= Opcodes.ISTORE && opcode <= Opcodes.ASTORE) {
                continue;
            }
            return false;
        }
        return false;
    }

    private static boolean isPrimitiveUnboxCall(MethodInsnNode call) {
        if (call.getOpcode() != Opcodes.INVOKEVIRTUAL) return false;
        return switch (call.owner) {
            case "java/lang/Boolean" -> call.name.equals("booleanValue") && call.desc.equals("()Z");
            case "java/lang/Byte" -> call.name.equals("byteValue") && call.desc.equals("()B");
            case "java/lang/Character" -> call.name.equals("charValue") && call.desc.equals("()C");
            case "java/lang/Short" -> call.name.equals("shortValue") && call.desc.equals("()S");
            case "java/lang/Integer" -> call.name.equals("intValue") && call.desc.equals("()I");
            case "java/lang/Float" -> call.name.equals("floatValue") && call.desc.equals("()F");
            case "java/lang/Long" -> call.name.equals("longValue") && call.desc.equals("()J");
            case "java/lang/Double" -> call.name.equals("doubleValue") && call.desc.equals("()D");
            default -> false;
        };
    }

    private static String callbackKey(HookDefinition hook) {
        return hook.callbackOwner() + '.' + hook.callbackName() + hook.callbackDescriptor();
    }

    private static InsnList defaultReturn(Type returnType) {
        InsnList instructions = new InsnList();
        switch (returnType.getSort()) {
            case Type.VOID:
                instructions.add(new InsnNode(Opcodes.RETURN));
                break;
            case Type.LONG:
                instructions.add(new InsnNode(Opcodes.LCONST_0));
                instructions.add(new InsnNode(Opcodes.LRETURN));
                break;
            case Type.FLOAT:
                instructions.add(new InsnNode(Opcodes.FCONST_0));
                instructions.add(new InsnNode(Opcodes.FRETURN));
                break;
            case Type.DOUBLE:
                instructions.add(new InsnNode(Opcodes.DCONST_0));
                instructions.add(new InsnNode(Opcodes.DRETURN));
                break;
            case Type.ARRAY:
            case Type.OBJECT:
                instructions.add(new InsnNode(Opcodes.ACONST_NULL));
                instructions.add(new InsnNode(Opcodes.ARETURN));
                break;
            default:
                instructions.add(new InsnNode(Opcodes.ICONST_0));
                instructions.add(new InsnNode(Opcodes.IRETURN));
        }
        return instructions;
    }

    private static boolean isReturn(int opcode) {
        return opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN;
    }

    private static String methodKey(String name, String descriptor) {
        return name + descriptor;
    }

}
