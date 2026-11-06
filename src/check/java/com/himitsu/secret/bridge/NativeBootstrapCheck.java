package com.himitsu.secret.bridge;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;

/** Exercises the packaged bootstrap without loading any native code or game. */
public final class NativeBootstrapCheck {
    private static final String BOOTSTRAP = "com.himitsu.secret.bridge.SecretNative";
    private static final String IMAGE = "himitsu.dll";
    private static final String DIGEST = "META-INF/secret-native.sha256";

    public static final class LiteralFixture {
        public static String resource() { return "/himitsu.dll"; }
    }

    private record Rewritten(byte[] bytes, int changes) {}

    // Reproduces MyXformer2.tranNodes_dllString for a selected target class.
    // Do not initialize another mod's transformer or native watcher in a check JVM.
    private static Rewritten rewriteDllLiterals(byte[] original) {
        ClassNode node = new ClassNode();
        new ClassReader(original).accept(node, 0);
        int changes = 0;
        for (var method : node.methods) for (var instruction : method.instructions) {
            if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof String value
                    && value.toLowerCase(Locale.ROOT).endsWith(".dll")) {
                ldc.cst = value.replaceAll("(?i)\\.dll", ".d11");
                changes++;
            }
        }
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        return new Rewritten(writer.toByteArray(), changes);
    }

    private static final class Isolated extends ClassLoader {
        private final String target;
        private final byte[] bytes;
        private final Map<String, byte[]> resources;
        Isolated(String target, byte[] bytes, Map<String, byte[]> resources) {
            super(NativeBootstrapCheck.class.getClassLoader());
            this.target = target;
            this.bytes = bytes;
            this.resources = resources;
        }
        @Override protected synchronized Class<?> loadClass(String name, boolean resolve)
                throws ClassNotFoundException {
            if (!name.equals(target)) return super.loadClass(name, resolve);
            Class<?> type = findLoadedClass(name);
            if (type == null) type = defineClass(name, bytes, 0, bytes.length);
            if (resolve) resolveClass(type);
            return type;
        }
        @Override public InputStream getResourceAsStream(String name) {
            // Never fall back to the real classpath for deliberately missing resources.
            if (name.startsWith("himitsu.") || name.equals(DIGEST)) {
                byte[] value = resources.get(name);
                return value == null ? null : new ByteArrayInputStream(value);
            }
            return super.getResourceAsStream(name);
        }
    }

    private static Class<?> bootstrap(byte[] bytes, Map<String, byte[]> resources) throws Exception {
        return new Isolated(BOOTSTRAP, bytes, resources).loadClass(BOOTSTRAP);
    }

    private static Path prepare(Class<?> bootstrap, Path directory) throws Exception {
        var method = bootstrap.getDeclaredMethod("prepareNativeLibrary", Path.class);
        method.setAccessible(true);
        try {
            return (Path) method.invoke(null, directory);
        } catch (InvocationTargetException failure) {
            if (failure.getCause() instanceof Exception exception) throw exception;
            throw failure;
        }
    }

    private static void check(boolean condition, String detail) {
        if (!condition) throw new AssertionError(detail);
    }

    private static void reject(byte[] bytes, Map<String, byte[]> resources, Path directory,
                               byte[] installed, String reason) throws Exception {
        try {
            prepare(bootstrap(bytes, resources), directory);
            throw new AssertionError("Accepted " + reason);
        } catch (IOException expected) {
            check(expected.getMessage().contains(reason), "Unexpected rejection: " + expected);
        }
        check(Arrays.equals(Files.readAllBytes(directory.resolve("secret/native/" + IMAGE)), installed),
            "Invalid package replaced existing native image");
    }

    public static void main(String[] args) throws Exception {
        check(System.mapLibraryName("himitsu").equals(IMAGE), "Windows native package required");
        byte[] original;
        Map<String, byte[]> resources = new HashMap<>();
        try (ZipFile zip = new ZipFile(args[0])) {
            try (InputStream input = zip.getInputStream(zip.getEntry(BOOTSTRAP.replace('.', '/') + ".class"))) {
                original = input.readAllBytes();
            }
            for (String name : new String[]{IMAGE, DIGEST}) {
                check(zip.getEntry(name) != null, "Missing packaged " + name);
                try (InputStream input = zip.getInputStream(zip.getEntry(name))) {
                    resources.put(name, input.readAllBytes());
                }
            }
        }
        byte[] fixture;
        String fixtureName = LiteralFixture.class.getName();
        try (InputStream input = NativeBootstrapCheck.class.getResourceAsStream(
                "/" + fixtureName.replace('.', '/') + ".class")) {
            fixture = input.readAllBytes();
        }
        Rewritten broken = rewriteDllLiterals(fixture);
        check(broken.changes() == 1, "DLL rewrite fixture was not exercised");
        Class<?> fixtureType = new Isolated(fixtureName, broken.bytes(), Map.of()).loadClass(fixtureName);
        check(fixtureType.getMethod("resource").invoke(null).equals("/himitsu.d11"), "Rewrite model mismatch");
        Rewritten hardened = rewriteDllLiterals(original);
        check(hardened.changes() == 0, "Packaged bootstrap still exposes DLL string literals");

        Path directory = Files.createTempDirectory("secret-bootstrap-check-");
        Path nativeDirectory = directory.resolve("secret/native");
        try {
            Class<?> type = bootstrap(hardened.bytes(), resources);
            Path extracted = prepare(type, directory);
            byte[] image = resources.get(IMAGE);
            check(extracted.equals(nativeDirectory.resolve(IMAGE)), "Unexpected native path");
            check(Arrays.equals(Files.readAllBytes(extracted), image), "Extracted native image differs");
            prepare(type, directory); // Replacing an unloaded old candidate remains supported.
            check(!(Boolean) type.getMethod("isLoaded").invoke(null), "Check must not load native code");

            Map<String, byte[]> missing = new HashMap<>(resources);
            missing.remove(IMAGE);
            missing.put("himitsu.d11", image); // A renamed fallback must not hide a broken package.
            reject(hardened.bytes(), missing, directory, image, "Missing native resource:");
            Map<String, byte[]> corrupt = new HashMap<>(resources);
            byte[] damaged = image.clone(); damaged[damaged.length / 2] ^= 1;
            corrupt.put(IMAGE, damaged);
            reject(hardened.bytes(), corrupt, directory, image, "integrity verification failed");
            Map<String, byte[]> badDigest = new HashMap<>(resources);
            badDigest.put(DIGEST, "Z".repeat(64).getBytes(StandardCharsets.US_ASCII));
            reject(hardened.bytes(), badDigest, directory, image, "Invalid native resource digest");
            badDigest.put(DIGEST, "0".repeat(66).getBytes(StandardCharsets.US_ASCII));
            reject(hardened.bytes(), badDigest, directory, image, "Invalid native resource digest");
            badDigest.remove(DIGEST);
            reject(hardened.bytes(), badDigest, directory, image, "Missing native resource digest");
            // A failed replacement must leave no staging file or damage the existing target.
            Files.delete(extracted);
            Files.createDirectory(extracted);
            try {
                Files.writeString(extracted.resolve("occupied"), "keep");
                try {
                    prepare(type, directory);
                    throw new AssertionError("Replaced an occupied directory");
                } catch (IOException expected) {
                    check(Files.readString(extracted.resolve("occupied")).equals("keep"), "Damaged destination");
                }
            } finally { Files.delete(extracted.resolve("occupied")); Files.delete(extracted); }
            try (var entries = Files.list(nativeDirectory)) {
                check(entries.findAny().isEmpty(), "Leaked extraction staging file");
            }
        } finally {
            // Only the known files/directories created by this check; no recursive delete.
            Files.deleteIfExists(nativeDirectory.resolve(IMAGE));
            Files.deleteIfExists(nativeDirectory);
            Files.deleteIfExists(directory.resolve("secret"));
            Files.deleteIfExists(directory);
        }
        System.out.println("NATIVE_BOOTSTRAP_PASS packaged_class dll_literal_rewrite extraction digest_rejection failed_replace_cleanup NO_NATIVE_LOAD_NO_GAME");
    }
}
