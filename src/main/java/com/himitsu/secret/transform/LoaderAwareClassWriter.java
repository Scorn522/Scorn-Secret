package com.himitsu.secret.transform;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

public final class LoaderAwareClassWriter extends ClassWriter {
    private final BytecodeHierarchy hierarchy;

    public LoaderAwareClassWriter(ClassReader reader, int flags, ClassLoader loader) {
        super(reader, flags);
        hierarchy = new BytecodeHierarchy(loader);
    }

    public LoaderAwareClassWriter(int flags, ClassLoader loader) {
        super(flags);
        hierarchy = new BytecodeHierarchy(loader);
    }

    public LoaderAwareClassWriter(int flags,ClassLoader loader,org.objectweb.asm.tree.ClassNode node) {
        this(flags,loader);
        hierarchy.remember(node);
    }

    @Override
    protected String getCommonSuperClass(String type1, String type2) {
        return hierarchy.commonSuperClass(type1, type2);
    }
}
