package com.himitsu.secret.transform;

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;

public final class BytecodeHierarchy {
    private final ClassLoader loader;
    private final ConcurrentHashMap<String, ClassInfo> classes = new ConcurrentHashMap<>();

    public BytecodeHierarchy(ClassLoader loader) {
        this.loader = loader;
    }

    public String commonSuperClass(String first, String second) {
        if (first.equals(second)) return first;
        if (isAssignableFrom(first, second)) return first;
        if (isAssignableFrom(second, first)) return second;
        ClassInfo firstInfo = info(first);
        ClassInfo secondInfo = info(second);
        if (firstInfo == null || secondInfo == null || firstInfo.isInterface() || secondInfo.isInterface()) {
            return "java/lang/Object";
        }
        String current = firstInfo.superName();
        while (current != null) {
            if (isAssignableFrom(current, second)) return current;
            ClassInfo currentInfo = info(current);
            current = currentInfo == null ? null : currentInfo.superName();
        }
        return "java/lang/Object";
    }

    private boolean isAssignableFrom(String target, String candidate) {
        if (target.equals(candidate) || "java/lang/Object".equals(target)) return true;
        Set<String> visited = new HashSet<>();
        ArrayDeque<String> pending = new ArrayDeque<>();
        pending.add(candidate);
        while (!pending.isEmpty()) {
            String name = pending.removeFirst();
            if (!visited.add(name)) continue;
            ClassInfo current = info(name);
            if (current == null) continue;
            if (target.equals(current.superName())) return true;
            if (current.superName() != null) pending.addLast(current.superName());
            for (String interfaceName : current.interfaces()) {
                if (target.equals(interfaceName)) return true;
                pending.addLast(interfaceName);
            }
        }
        return false;
    }

    private ClassInfo info(String internalName) {
        return classes.computeIfAbsent(internalName, name -> {
            byte[] bytes = ClassByteSource.read(loader, name);
            if (bytes == null) return ClassInfo.MISSING;
            ClassReader reader = new ClassReader(bytes);
            return ClassInfo.present(reader.getSuperName(), reader.getInterfaces(),
                (reader.getAccess() & Opcodes.ACC_INTERFACE) != 0);
        }).present() ? classes.get(internalName) : null;
    }

    private record ClassInfo(String superName, String[] interfaces, boolean isInterface, boolean present) {
        private static final ClassInfo MISSING = new ClassInfo(null, new String[0], false, false);

        private static ClassInfo present(String superName, String[] interfaces, boolean isInterface) {
            return new ClassInfo(superName, interfaces.clone(), isInterface, true);
        }
    }
}
