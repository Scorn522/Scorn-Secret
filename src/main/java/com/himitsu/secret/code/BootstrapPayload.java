package com.himitsu.secret.code;

import com.himitsu.secret.SecretMod;
import com.himitsu.secret.bridge.SecretNative;
import java.io.IOException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import net.minecraftforge.eventbus.api.IEventBus;
import org.objectweb.asm.ClassReader;

public final class BootstrapPayload {
    public static final String PAYLOAD_ENTRY = "himitsu.jar";

    private BootstrapPayload() {
    }

    public static File locateSource(String rawLocation) throws FileNotFoundException {
        String location = rawLocation;
        int jarEnd = location.toLowerCase(java.util.Locale.ROOT).lastIndexOf(".jar");
        if (jarEnd >= 0) {
            location = location.substring(0, jarEnd + 4);
        }

        File source = new File(location).getAbsoluteFile();
        if (!source.isFile() && location.matches("^/[A-Za-z]:/.*")) {
            source = new File(location.substring(1)).getAbsoluteFile();
        }
        if (!source.exists()) {
            throw new FileNotFoundException(
                "Cannot resolve Secret mod archive from CodeSource: " + location
            );
        }
        return source;
    }

    public static void boot(IEventBus modBus, Path gameDirectory, Path modPath) throws Throwable {
        SecretNative.load(gameDirectory, java.time.Duration.ofSeconds(10));
        SecretNative.configure(gameDirectory, modPath);

        Map<String, byte[]> classes = readClasses(SecretMod.MODFILE.getValue());
        if (classes.isEmpty()) {
            throw new IOException(
                "No encrypted payload classes were found in " + SecretMod.MODFILE.getKey()
            );
        }
        Map<String, Class<?>> definedClasses = defineAll(
            classes,
            SecretMod.class.getClassLoader()
        );
        Class<?> runtime = definedClasses.get("com/himitsu/secret/util/SecretRuntime");
        if (runtime == null) {
            throw new ClassNotFoundException(
                "Encrypted payload did not define com.himitsu.secret.util.SecretRuntime"
            );
        }
        try {
            runtime.getMethod(
                "boot",
                IEventBus.class,
                Path.class,
                Path.class
            ).invoke(null, modBus, gameDirectory, modPath);
        } catch (java.lang.reflect.InvocationTargetException exception) {
            throw exception.getCause();
        } finally {
            classes.clear();
        }
    }

    private static Map<String, byte[]> readClasses(JarFile jar) throws Exception {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        if (jar == null) {
            return classes;
        }
        JarEntry encryptedPayload = jar.getJarEntry(PAYLOAD_ENTRY);
        if (encryptedPayload == null || encryptedPayload.isDirectory()) return classes;
        Object decryptedPayload = SecretNative.invokeChecked(
            "DecryptPayloadJar",
            jar.getInputStream(encryptedPayload).readAllBytes()
        );
        if (!(decryptedPayload instanceof byte[] payloadBytes)) {
            throw new IOException("Native payload JAR decryption failed");
        }
        try (JarInputStream payload = new JarInputStream(new ByteArrayInputStream(payloadBytes))) {
            JarEntry entry;
            while ((entry = payload.getNextJarEntry()) != null) {
                if (entry.isDirectory() || !entry.getName().endsWith(".bin")) continue;
                Object decryptedClass = SecretNative.invokeChecked(
                    "DecryptPayloadClass",
                    payload.readAllBytes()
                );
                if (!(decryptedClass instanceof byte[] decoded) || !isClass(decoded)) {
                    throw new IOException("Native class payload decryption failed: " + entry.getName());
                }
                String className = new ClassReader(decoded).getClassName();
                if (classes.putIfAbsent(className, decoded) != null) {
                    throw new IOException("Duplicate encrypted payload class: " + className);
                }
            }
        }
        return classes;
    }

    private static Map<String, Class<?>> defineAll(
        Map<String, byte[]> classes,
        ClassLoader loader
    ) {
        Map<String, Class<?>> defined = new LinkedHashMap<>();
        for (String name : dependencyOrder(classes)) {
            Object result = SecretNative.invokeChecked("DefineClass", name, loader, classes.get(name));
            if (!(result instanceof Class<?> type)) {
                throw new IllegalStateException(
                    "Native DefineClass returned "
                        + (result == null ? "null" : result.getClass().getName())
                        + " for " + name
                );
            }
            defined.put(name, type);
        }
        return Map.copyOf(defined);
    }

    private static List<String> dependencyOrder(Map<String, byte[]> classes) {
        Map<String, Set<String>> dependencies = new HashMap<>();
        Map<String, Set<String>> dependents = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            ClassReader reader = new ClassReader(entry.getValue());
            Set<String> parents = new LinkedHashSet<>();
            if (reader.getSuperName() != null && classes.containsKey(reader.getSuperName())) {
                parents.add(reader.getSuperName());
            }
            for (String interfaceName : reader.getInterfaces()) {
                if (classes.containsKey(interfaceName)) {
                    parents.add(interfaceName);
                }
            }
            dependencies.put(entry.getKey(), parents);
            dependents.putIfAbsent(entry.getKey(), new LinkedHashSet<>());
            for (String parent : parents) {
                dependents.computeIfAbsent(parent, ignored -> new LinkedHashSet<>()).add(entry.getKey());
            }
        }

        ArrayDeque<String> ready = new ArrayDeque<>();
        dependencies.entrySet().stream()
            .filter(entry -> entry.getValue().isEmpty())
            .map(Map.Entry::getKey)
            .sorted()
            .forEach(ready::add);
        List<String> ordered = new ArrayList<>();
        while (!ready.isEmpty()) {
            String name = ready.removeFirst();
            ordered.add(name);
            List<String> children = new ArrayList<>(dependents.getOrDefault(name, Set.of()));
            children.sort(Comparator.naturalOrder());
            for (String child : children) {
                Set<String> parents = dependencies.get(child);
                parents.remove(name);
                if (parents.isEmpty()) {
                    ready.addLast(child);
                }
            }
        }
        classes.keySet().stream()
            .filter(name -> !ordered.contains(name))
            .sorted()
            .forEach(ordered::add);
        return ordered;
    }

    private static boolean isClass(byte[] data) {
        return data.length >= 4
            && data[0] == (byte)0xCA
            && data[1] == (byte)0xFE
            && data[2] == (byte)0xBA
            && data[3] == (byte)0xBE;
    }
}
