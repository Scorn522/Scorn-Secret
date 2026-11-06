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
        private java.security.ProtectionDomain source;
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
            if (type == null) type = defineClass(name, bytes, 0, bytes.length, source);
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

    private static void checkDiscovery(Path archive) throws Exception {
        archive=archive.toAbsolutePath().normalize();
        String name="com.himitsu.secret.bridge.EarlyBootstrapService";
        byte[] bytes;
        try(var zip=new ZipFile(archive.toFile())) {
            check(zip.getEntry("META-INF/services/net.minecraftforge.forgespi.locating.IModLocator")!=null,"service jar lacks a Forge locator");
            try(var in=zip.getInputStream(zip.getEntry(name.replace('.','/')+".class"))) {bytes=in.readAllBytes();}
        }
        var loader=new Isolated(name,bytes,Map.of());
        loader.source=new java.security.ProtectionDomain(new java.security.CodeSource(archive.toUri().toURL(),(java.security.cert.Certificate[])null),null);
        var locator=(net.minecraftforge.forgespi.locating.IModLocator)loader.loadClass(name).getConstructor().newInstance();
        var version=net.minecraftforge.fml.loading.FMLLoader.class.getDeclaredField("versionInfo");
        version.setAccessible(true);
        version.set(null,new net.minecraftforge.fml.loading.VersionInfo("47.4.23","1.20.1","20230612.114412","net.minecraftforge"));
        var found=locator.scanMods();
        check(found.size()==1 && found.get(0).ex()==null,"self locator did not return a valid mod: "+found);
        var mod=found.get(0).file();
        check(mod.getModInfos().size()==1 && mod.getModInfos().get(0).getModId().equals("secret"),"Secret was not registered as a game mod");
        check(mod.getFilePath().toAbsolutePath().normalize().equals(archive),"locator changed another mod path");
        try(var jar=new java.util.jar.JarFile(archive.toFile())) {
            check(mod.getModInfos().get(0).getVersion().toString().equals(jar.getManifest().getMainAttributes().getValue("Implementation-Version")),"Forge version does not match the packaged implementation");
        }
        var serviceJar=cpw.mods.jarhandling.SecureJar.from(archive);
        check(serviceJar.name().equals("secret.bootstrap") && mod.getSecureJar().name().equals("secret"),"service/game module names not isolated");
        check(serviceJar.moduleDataProvider().descriptor().exports().isEmpty(),"service exports game packages");
        // Only the parent module identities are modeled; Forge's real parser and game metadata are used above.
        var parents=new HashMap<String,java.lang.module.ModuleReference>();
        for(String dependency:java.util.List.of("cpw.mods.modlauncher","fmlloader","net.minecraftforge.forgespi")) {
            var descriptor=java.lang.module.ModuleDescriptor.newModule(dependency);
            descriptor.exports(dependency.equals("cpw.mods.modlauncher") ? "cpw.mods.modlauncher.api"
                : dependency.equals("net.minecraftforge.forgespi") ? "net.minecraftforge.forgespi.locating" : "net.minecraftforge.fml.loading.moddiscovery");
            var reference=new java.lang.module.ModuleReference(descriptor.build(),java.net.URI.create("check:/"+dependency)) {
                @Override public java.lang.module.ModuleReader open() throws IOException {throw new IOException("descriptor-only fixture");}
            };
            parents.put(dependency,reference);
        }
        var parentFinder=new java.lang.module.ModuleFinder() {
            public java.util.Optional<java.lang.module.ModuleReference> find(String n) {return java.util.Optional.ofNullable(parents.get(n));}
            public java.util.Set<java.lang.module.ModuleReference> findAll() {return java.util.Set.copyOf(parents.values());}
        };
        var parentConfiguration=ModuleLayer.boot().configuration().resolve(parentFinder,java.lang.module.ModuleFinder.of(),parents.keySet());
        var parentLayer=ModuleLayer.boot().defineModulesWithOneLoader(parentConfiguration,NativeBootstrapCheck.class.getClassLoader());
        var serviceConfiguration=parentConfiguration.resolveAndBind(cpw.mods.cl.JarModuleFinder.of(serviceJar,serviceJar),java.lang.module.ModuleFinder.of(),java.util.List.of("secret.bootstrap"));
        var service=parentLayer.defineModulesWithOneLoader(serviceConfiguration,NativeBootstrapCheck.class.getClassLoader());
        var gameConfiguration=serviceConfiguration.resolveAndBind(cpw.mods.cl.JarModuleFinder.of(mod.getSecureJar()),java.lang.module.ModuleFinder.of(),java.util.List.of("secret"));
        var game=service.defineModulesWithOneLoader(gameConfiguration,NativeBootstrapCheck.class.getClassLoader());
        Class<?> early=Class.forName(BOOTSTRAP,false,service.findLoader("secret.bootstrap"));
        Class<?> runtime=Class.forName(BOOTSTRAP,false,game.findLoader("secret"));
        check(early!=runtime && early.getModule().getLayer()==service && runtime.getModule().getLayer()==game,"service/game bridge class ownership collapsed");
        check(!SecretNative.isLoaded(),"discovery check initialized native code");
        System.out.println("MOD_DISCOVERY_PASS secret_registered duplicate_service_paths game_layer_separate NO_GAME_NO_NATIVE_LOAD");
    }

    public static void main(String[] args) throws Exception {
        checkDiscovery(Path.of(args[0]));
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
