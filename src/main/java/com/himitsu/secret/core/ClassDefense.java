package com.himitsu.secret.core;

import com.himitsu.secret.bridge.SecretNative;
import com.himitsu.secret.config.SecretConfig;
import com.himitsu.secret.hook.HookTransformer;
import java.io.IOException;
import java.io.InputStream;
import java.security.ProtectionDomain;
import java.util.Map;
import org.objectweb.asm.ClassReader;

public final class ClassDefense {
    private static volatile Map<String, byte[]> sourceClasses = Map.of();
    private static volatile String defenseMode = "mixin";

    private ClassDefense() {
    }

    /** Publish the same protection policy before enabling the class hook, without requesting VM changes. */
    public static void prepare(SecretConfig config, Map<String, byte[]> baselines) {
        sourceClasses = Map.copyOf(baselines);
        defenseMode = config.classDefense();
    }

    /** SourceShield already handles owned images; initialization never requests VM class changes. */
    public static void initialize(SecretConfig config, Map<String, byte[]> baselines) {
        if (!SecretNative.isLoaded()) throw new IllegalStateException("Native bridge is not ready");
        prepare(config, baselines);
        System.out.println("[Secret/ClassDefense] Source shield configuration ready");
    }

    public static byte[] transformOrRestore(
        ClassLoader loader,
        String className,
        Class<?> classBeingRedefined,
        ProtectionDomain protectionDomain,
        byte[] classFileBuffer
    ) {
        if (className == null || classFileBuffer == null) return null;
        String internalName = className.replace('.', '/');
        String binaryName = internalName.replace('/', '.').replace('+', '/');
        if (skip(binaryName)) return null;
        byte[] restored = classFileBuffer;
        byte[] sourceOverride = sourceClasses.get(internalName);
        if (sourceOverride != null && sourceOverride.length != 0) {
            restored = sourceOverride.clone();
        } else if (!internalName.startsWith("com/himitsu/secret/")) {
            // The native shield supplies verified outer bootstrap bytes. Replaying
            // third-party launch plugins here would reintroduce their edits.
            try {
                ClassReader reader = new ClassReader(classFileBuffer);
                if (loader != null && isModuleClassLoader(loader) && !"false".equals(defenseMode)) {
                    byte[] source = sourceBytes(loader, reader.getClassName());
                    if (source != null) {
                        byte[] common = LaunchPipelineReplay.common(loader, source);
                        byte[] current = "all".equals(defenseMode)
                            ? classFileBuffer
                            : LaunchPipelineReplay.mixin(loader, common);
                        restored = MethodDefense.restore(loader, classFileBuffer, common, current);
                    }
                }
            } catch (Throwable ignored) {
            }
        }

        try {
            return HookTransformer.transform(loader, internalName, classBeingRedefined, protectionDomain, restored);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean skip(String name) {
        return name.contains("$$Lambda$")
            || name.equals("java.lang.ClassCircularityError")
            || name.startsWith("java.lang.Throwable")
            || name.startsWith("java.io.DataOutputStream");
    }

    private static boolean isModuleClassLoader(ClassLoader loader) {
        for (Class<?> type = loader == null ? null : loader.getClass(); type != null; type = type.getSuperclass()) {
            if (type.getName().equals("cpw.mods.cl.ModuleClassLoader")) return true;
        }
        return false;
    }

    private static byte[] sourceBytes(ClassLoader loader, String internalName) {
        try (InputStream input = loader.getResourceAsStream(internalName + ".class")) {
            return input == null ? null : input.readAllBytes();
        } catch (IOException | RuntimeException ignored) {
            return null;
        }
    }

}
