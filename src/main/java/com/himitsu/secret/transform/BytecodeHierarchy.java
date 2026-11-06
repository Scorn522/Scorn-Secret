package com.himitsu.secret.transform;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.lang.ref.WeakReference;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;

public final class BytecodeHierarchy {
    private final ClassLoader loader;
    private static final ArrayList<WeakReference<ClassLoader>> LOADERS=new ArrayList<>();
    private static final ArrayList<ConcurrentHashMap<String,ClassInfo>> CACHES=new ArrayList<>();
    private static final ConcurrentHashMap<String,ClassInfo> BOOTSTRAP=new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ClassInfo> classes;

    public BytecodeHierarchy(ClassLoader loader) {
        this.loader = loader;
        this.classes=cache(loader);
    }

    private static synchronized ConcurrentHashMap<String,ClassInfo> cache(ClassLoader loader) {
        if(loader==null) return BOOTSTRAP;
        for(int i=LOADERS.size()-1;i>=0;i--) {
            ClassLoader key=LOADERS.get(i).get();
            if(key==null) {LOADERS.remove(i);CACHES.remove(i);}
            else if(key==loader) return CACHES.get(i);
        }
        var cache=new ConcurrentHashMap<String,ClassInfo>();
        LOADERS.add(new WeakReference<>(loader));CACHES.add(cache);return cache;
    }
    public void remember(org.objectweb.asm.tree.ClassNode node) {
        classes.put(node.name,ClassInfo.present(node.superName,node.interfaces.toArray(String[]::new),
            (node.access&Opcodes.ACC_INTERFACE)!=0));
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
        ClassInfo known=classes.get(internalName);
        if(known!=null) return known;
        // Class-loader I/O stays outside both cache locks and CHM reservations.
        byte[] bytes=ClassByteSource.read(loader,internalName);
        if(bytes==null) return null; // A later class definition must remain visible.
        ClassReader reader=new ClassReader(bytes);
        ClassInfo parsed=ClassInfo.present(reader.getSuperName(),reader.getInterfaces(),
            (reader.getAccess()&Opcodes.ACC_INTERFACE)!=0);
        ClassInfo raced=classes.putIfAbsent(internalName,parsed);
        return raced==null?parsed:raced;
    }
    private record ClassInfo(String superName,String[] interfaces,boolean isInterface) {
        private static ClassInfo present(String superName,String[] interfaces,boolean isInterface) {
            return new ClassInfo(superName,interfaces.clone(),isInterface);
        }
    }
}
