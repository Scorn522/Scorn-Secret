package com.himitsu.secret.core;

import com.himitsu.secret.transform.LoaderAwareClassWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.Textifier;
import org.objectweb.asm.util.TraceMethodVisitor;

public final class MethodDefense {
    private MethodDefense() {
    }

    public static boolean differs(ClassLoader loader, byte[] common, byte[] current) {
        return !restorations(loader, node(common), node(current), true).isEmpty();
    }

    public static byte[] restore(ClassLoader loader, byte[] runtime, byte[] common, byte[] current) {
        ClassNode runtimeNode = node(runtime);
        Map<String, MethodNode> replacements = restorations(loader, node(common), node(current), false);
        if (replacements.isEmpty()) return runtime;
        for (MethodNode method : runtimeNode.methods) {
            MethodNode replacement = replacements.get(key(method));
            if (replacement == null) continue;
            method.instructions.clear();
            method.instructions.add(replacement.instructions);
            method.tryCatchBlocks = replacement.tryCatchBlocks == null ? new ArrayList<>() : new ArrayList<>(replacement.tryCatchBlocks);
            method.localVariables = replacement.localVariables == null ? null : new ArrayList<>(replacement.localVariables);
        }
        ClassWriter writer = new LoaderAwareClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, loader, runtimeNode);
        runtimeNode.accept(writer);
        return writer.toByteArray();
    }

    private static Map<String, MethodNode> restorations(
        ClassLoader loader,
        ClassNode common,
        ClassNode current,
        boolean checkOnly
    ) {
        Map<String, MethodNode> commonMethods = methods(common);
        Map<String, MethodNode> result = new HashMap<>();
        for (MethodNode method : current.methods) {
            if ((method.access & Opcodes.ACC_STATIC) != 0) continue;
            MethodNode baseline = commonMethods.get(key(method));
            if (baseline != null) {
                if (!instructions(baseline).equals(instructions(method))) result.put(key(method), baseline);
            } else if (checkOnly) {
                result.put(key(method), method);
            } else {
                MethodNode delegate = inheritedDelegate(loader, current, method);
                if (delegate != null) result.put(key(method), delegate);
            }
        }
        return result;
    }

    private static MethodNode inheritedDelegate(ClassLoader loader, ClassNode owner, MethodNode method) {
        ArrayDeque<String> pending = new ArrayDeque<>();
        if (owner.superName != null) pending.add(owner.superName);
        pending.addAll(owner.interfaces);
        Set<String> visited = new HashSet<>();
        while (!pending.isEmpty()) {
            String name = pending.removeFirst();
            if (!visited.add(name)) continue;
            byte[] bytes = read(loader, name);
            if (bytes == null) continue;
            ClassNode parent = node(bytes);
            MethodNode inherited = methods(parent).get(key(method));
            boolean interfaceOwner = (parent.access & Opcodes.ACC_INTERFACE) != 0;
            if (inherited != null && (inherited.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) == 0) {
                MethodNode delegate = new MethodNode(Opcodes.ASM9, method.access, method.name, method.desc, method.signature,
                    method.exceptions.toArray(String[]::new));
                delegate.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
                int slot = 1;
                for (Type argument : Type.getArgumentTypes(method.desc)) {
                    delegate.instructions.add(new VarInsnNode(argument.getOpcode(Opcodes.ILOAD), slot));
                    slot += argument.getSize();
                }
                delegate.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, name, method.name, method.desc, interfaceOwner));
                delegate.instructions.add(new InsnNode(Type.getReturnType(method.desc).getOpcode(Opcodes.IRETURN)));
                return delegate;
            }
            if (parent.superName != null) pending.addLast(parent.superName);
            pending.addAll(parent.interfaces);
        }
        return null;
    }

    private static byte[] read(ClassLoader loader, String internalName) {
        ClassLoader effective = loader == null ? ClassLoader.getSystemClassLoader() : loader;
        try (var input = effective.getResourceAsStream(internalName + ".class")) {
            return input == null ? null : input.readAllBytes();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static ClassNode node(byte[] bytes) {
        ClassNode node = new ClassNode(Opcodes.ASM9);
        new ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES);
        return node;
    }

    private static Map<String, MethodNode> methods(ClassNode node) {
        Map<String, MethodNode> result = new HashMap<>();
        for (MethodNode method : node.methods) result.put(key(method), method);
        return result;
    }

    private static String key(MethodNode method) {
        return method.name + method.desc;
    }

    private static String instructions(MethodNode method) {
        Textifier textifier = new Textifier();
        method.instructions.accept(new TraceMethodVisitor(textifier));
        StringWriter output = new StringWriter();
        textifier.print(new PrintWriter(output));
        return output.toString();
    }
}
