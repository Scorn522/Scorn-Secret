package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.MethodNode;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JvmGenericSignatureObfuscationIntegrationTest {
    @Test
    void fullJvmObfuscationDoesNotKeepStaleGenericMethodSignatures() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-generics"));
        Path source = work.resolve("GenericShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("generic-shapes.jar");
        writeJar(inputJar, classes, "pkg.GenericShapes");
        String original = runJar(inputJar);

        Path renamerJar = work.resolve("generic-shapes-renamed.jar");
        runRenamerOnly(inputJar, renamerJar);
        String renamed = runJar(renamerJar);

        Path fullJar = work.resolve("generic-shapes-full-jvm.jar");
        runFullJvmObfuscation(inputJar, fullJar);
        String full = runJar(fullJar);

        assertEquals(original, renamed);
        assertEquals(original, full);
        assertTrue(full.contains("GENERICS OK"), full);
        assertRenamerRewritesGenericSignatures(renamerJar);
        assertNoPackedMethodKeepsOriginalGenericSignature(fullJar);
    }

    private void runRenamerOnly(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        config.setTransforms(Map.of(
            "renamer",
            new TransformConfig(true, 1.0, Map.of("packagePrefix", "z/"))
        ));
        config.keyConfig().setMasterSeed(0x47454E4552494331L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void runFullJvmObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("renamer", new TransformConfig(true, 1.0, Map.of("packagePrefix", "z/")));
        transforms.put("keyDispatch", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("methodParameterObfuscation", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("validationSinkHardening", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("invokeDynamic", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("constantObfuscation", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("stringObfuscation", new TransformConfig(true, 1.0, Map.of()));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x47454E4552494332L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void assertRenamerRewritesGenericSignatures(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        boolean sawRenamedSignature = false;
        for (var clazz : input.classMap().values()) {
            if (clazz.asmNode().signature != null) {
                assertFalse(clazz.asmNode().signature.contains("pkg/GenericShapes"), clazz.asmNode().signature);
                if (clazz.asmNode().signature.contains("z/")) {
                    sawRenamedSignature = true;
                }
            }
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.signature == null) continue;
                assertFalse(method.signature.contains("pkg/GenericShapes"), method.signature);
                if (method.signature.contains("z/")) {
                    sawRenamedSignature = true;
                }
            }
        }
        assertTrue(sawRenamedSignature, "fixture did not exercise renamed generic signatures");
    }

    private void assertNoPackedMethodKeepsOriginalGenericSignature(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        boolean sawPackedApplicationMethod = false;
        for (var clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("z/")) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                if (!isPackedApplicationMethod(method)) continue;
                sawPackedApplicationMethod = true;
                assertEquals(
                    null,
                    method.signature,
                    () -> "packed method retained stale generic signature: "
                        + clazz.name() + "." + method.name + method.desc + " signature=" + method.signature
                );
            }
        }
        assertTrue(sawPackedApplicationMethod, "fixture did not exercise packed generic application methods");
    }

    private boolean isPackedApplicationMethod(MethodNode method) {
        if ("<init>".equals(method.name) || "<clinit>".equals(method.name) || "main".equals(method.name)) {
            return false;
        }
        Type[] args = Type.getArgumentTypes(method.desc);
        return args.length >= 1
            && "[Ljava/lang/Object;".equals(args[0].getDescriptor());
    }

    private void writeJar(Path jar, Path classes, String mainClass) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", mainClass);
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            List<Path> files = new ArrayList<>();
            try (var stream = Files.walk(classes)) {
                stream.filter(Files::isRegularFile).forEach(files::add);
            }
            for (Path file : files) {
                String name = classes.relativize(file).toString().replace('\\', '/');
                jos.putNextEntry(new JarEntry(name));
                jos.write(Files.readAllBytes(file));
                jos.closeEntry();
            }
        }
    }

    private String runJar(Path jar) throws Exception {
        return run(List.of("java", "-XX:-UsePerfData", "-jar", jar.toString()), Duration.ofSeconds(30));
    }

    private String run(List<String> command, Duration timeout) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean exited = process.waitFor(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(exited, "command timed out: " + command);
        assertEquals(0, process.exitValue(), "command failed: " + command + "\n" + output);
        return output;
    }

    private String sourceText() {
        return """
            package pkg;

            import java.lang.reflect.Method;
            import java.util.ArrayList;
            import java.util.List;
            import java.util.Objects;
            import java.util.function.Function;

            public class GenericShapes {
                interface Box<T extends CharSequence> {
                    T value();
                }

                static class StringBox implements Box<String> {
                    private final String value;

                    StringBox(String value) {
                        this.value = value;
                    }

                    public String value() {
                        return value;
                    }
                }

                static final class Pair<K, V extends Number> {
                    final K key;
                    final V value;

                    Pair(K key, V value) {
                        this.key = key;
                        this.value = value;
                    }
                }

                private static <T extends CharSequence, R extends Number> String combine(
                        List<? extends Box<T>> boxes,
                        Pair<T, R> pair,
                        Function<? super T, String> mapper) {
                    StringBuilder out = new StringBuilder();
                    for (Box<T> box : boxes) {
                        out.append(mapper.apply(box.value()));
                    }
                    out.append(':').append(pair.key).append(':').append(pair.value.intValue());
                    return out.toString();
                }

                public static void main(String[] args) throws Exception {
                    List<Box<String>> boxes = new ArrayList<>();
                    boxes.add(new StringBox("A"));
                    boxes.add(new StringBox("B"));
                    Pair<String, Integer> pair = new Pair<>("C", 7);
                    String out = combine(boxes, pair, value -> value.toLowerCase());

                    Method generic = null;
                    for (Method method : GenericShapes.class.getDeclaredMethods()) {
                        int genericParameterCount = method.getGenericParameterTypes().length;
                        Class<?>[] parameterTypes = method.getParameterTypes();
                        boolean originalGenericAbi = genericParameterCount == 3;
                        boolean packedObfuscatedAbi = parameterTypes.length == 1
                                && parameterTypes[0] == Object[].class;
                        if ((originalGenericAbi || packedObfuscatedAbi)
                                && Objects.equals(method.getGenericReturnType().getTypeName(), "java.lang.String")) {
                            generic = method;
                            break;
                        }
                    }
                    if (generic == null) {
                        throw new AssertionError("missing generic method");
                    }
                    System.out.println(out);
                    if (!"ab:C:7".equals(out)) {
                        throw new AssertionError(out);
                    }
                    System.out.println("GENERICS OK");
                }
            }
            """;
    }
}
