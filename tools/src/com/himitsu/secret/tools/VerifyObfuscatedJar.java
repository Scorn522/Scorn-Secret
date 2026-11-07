package com.himitsu.secret.tools;

import java.nio.file.Path;
import java.nio.file.Files;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Collections;
import java.util.Set;
import java.util.jar.JarFile;

public final class VerifyObfuscatedJar {
    private VerifyObfuscatedJar() {
    }

    public static void main(String[] args) throws Exception {
        Path input = Path.of(args[0]);
        int verified = 0;
        try (JarFile jar = new JarFile(input.toFile())) {
            for (var entry : Collections.list(jar.entries())) {
                if (entry.getName().equals("module-info.class")) {
                    try(var stream=jar.getInputStream(entry)) {
                        var module=java.lang.module.ModuleDescriptor.read(stream);
                        if(!module.name().equals("secret.bootstrap")) throw new IllegalStateException("Unexpected service module: "+module.name());
                    }
                    continue;
                }
                if (!entry.getName().endsWith(".class")) {
                    continue;
                }
                String binaryName = entry.getName()
                    .substring(0, entry.getName().length() - ".class".length())
                    .replace('/', '.');
                Class.forName(binaryName, false, ClassLoader.getSystemClassLoader());
                verified++;
            }
        }
        if (args.length > 1) {
            Path mapping = Path.of(args[1]);
            verifyDynamicHookNames(mapping);
            verifyBootstrapRuntimeLookup(input, mapping);
            verifyScreenTypeBindings(input, mapping);
            verifyNoRenamedSrgMethods(mapping);
        }
        System.out.println("Verified obfuscated classes: " + verified);
    }

    private static void verifyDynamicHookNames(Path mapping) throws Exception {
        String transformer = null;
        Set<String> expectedNames = new HashSet<>(Set.of("isCancelled","value"));
        for (String line : Files.readAllLines(mapping)) {
            if (line.startsWith("CLASS com/himitsu/secret/hook/HookTransformer -> ")) {
                transformer = line.substring(line.indexOf(" -> ") + 4).replace('/', '.');
            } else if (line.startsWith("METHOD com/himitsu/secret/hook/HookResult.isCancelled()Z -> ")
                || line.startsWith("METHOD com/himitsu/secret/hook/HookResult.value()Ljava/lang/Object; -> ")) {
                expectedNames.remove(line.contains(".isCancelled(") ? "isCancelled" : "value");
                expectedNames.add(line.substring(line.indexOf(" -> ") + 4));
            }
        }
        if (transformer == null || expectedNames.size() != 2) {
            throw new IllegalStateException("Missing dynamic-hook entries in mapping");
        }
        Class<?> transformerType = Class.forName(transformer, true, ClassLoader.getSystemClassLoader());
        Set<String> resolvedNames = new HashSet<>();
        for (var field : transformerType.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                field.setAccessible(true);
                Object value = field.get(null);
                if (value instanceof String name) {
                    resolvedNames.add(name);
                }
            }
        }
        if (!resolvedNames.containsAll(expectedNames)) {
            throw new IllegalStateException(
                "Runtime hook names do not match mapping: expected=" + expectedNames + ", resolved=" + resolvedNames
            );
        }
        System.out.println("Verified dynamic hook names: " + expectedNames);
    }

    private static void verifyBootstrapRuntimeLookup(Path input, Path mapping) throws Exception {
        String runtimeClass = mappedClass(mapping, "com/himitsu/secret/util/SecretRuntime");
        try (JarFile jar = new JarFile(input.toFile())) {
            byte[] bootstrap = jar.getInputStream(
                jar.getJarEntry("com/himitsu/secret/code/BootstrapPayload.class")
            ).readAllBytes();
            if (!contains(bootstrap, runtimeClass)
                || !runtimeClass.equals("com/himitsu/secret/util/SecretRuntime") && contains(bootstrap, "com/himitsu/secret/util/SecretRuntime")) {
                throw new IllegalStateException("Bootstrap runtime lookup was not remapped");
            }
        }
        System.out.println("Verified bootstrap runtime lookup: " + runtimeClass);
    }

    private static void verifyScreenTypeBindings(Path input, Path mapping) throws Exception {
        String civilization = mappedClass(mapping, "com/himitsu/secret/core/CivilizationSurvivalHooks");
        String compatibility = mappedClass(mapping, "com/himitsu/secret/core/RuntimeCompatibilityHooks");
        String configScreen = mappedClass(mapping, "com/himitsu/secret/client/screen/SecretConfigScreen");
        String deathScreen = mappedClass(mapping, "com/himitsu/secret/client/screen/SecretDeathScreen");
        try (JarFile jar = new JarFile(input.toFile())) {
            for (String owner : Set.of(civilization, compatibility)) {
                byte[] bytes = jar.getInputStream(jar.getJarEntry(owner + ".class")).readAllBytes();
                if (!contains(bytes, configScreen) || !contains(bytes, deathScreen)) {
                    throw new IllegalStateException("Screen type binding was not remapped in " + owner);
                }
            }
        }
        System.out.println("Verified obfuscated screen type bindings");
    }

    private static void verifyNoRenamedSrgMethods(Path mapping) throws Exception {
        for (String line : Files.readAllLines(mapping)) {
            if (line.startsWith("METHOD ")) {
                int separator = line.indexOf(" -> ");
                int open = line.indexOf('(');
                int dot = open < 0 ? -1 : line.lastIndexOf('.', open);
                if (separator > 0 && dot > 0) {
                    String name = line.substring(dot + 1, open);
                    if (name.matches("m_\\d+_")) {
                        throw new IllegalStateException("External SRG override was renamed: " + line);
                    }
                }
            }
        }
        System.out.println("Verified external SRG override names");
    }

    private static String mappedClass(Path mapping, String original) throws Exception {
        String prefix = "CLASS " + original + " -> ";
        for (String line : Files.readAllLines(mapping)) {
            if (line.startsWith(prefix)) return line.substring(prefix.length());
        }
        throw new IllegalStateException("Missing class mapping for " + original);
    }

    private static boolean contains(byte[] bytes, String text) {
        byte[] needle = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        outer:
        for (int i = 0; i <= bytes.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (bytes[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}

