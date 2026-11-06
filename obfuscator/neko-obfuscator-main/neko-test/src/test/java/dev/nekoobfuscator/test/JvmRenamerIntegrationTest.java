package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.jar.ClassHierarchy;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningPass;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.FileOutputStream;
import java.lang.reflect.Method;
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

public class JvmRenamerIntegrationTest {
    @Test
    void renamerSupportsPinnedClassNamesAndPreservedMembers() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-renamer-compat"));
        Path source = work.resolve("RenameShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));
        Files.writeString(classes.resolve("rename.properties"), "target=pkg.RenameShapes$Target\n", StandardCharsets.UTF_8);

        Path inputJar = work.resolve("rename-shapes.jar");
        writeJar(inputJar, classes, "pkg.RenameShapes");
        Path outputJar = work.resolve("rename-shapes-obf.jar");
        runCompatibilityObfuscation(inputJar, outputJar);

        assertEquals(runJar(inputJar), runJar(outputJar));
        String mapping = Files.readString(outputJar.resolveSibling(outputJar.getFileName() + ".map"));
        assertTrue(mapping.contains("CLASS pkg/RenameShapes$Target -> pkg/RenameShapes$Target"), mapping);
        assertFalse(mapping.contains("METHOD "), mapping);
        assertFalse(mapping.contains("FIELD "), mapping);
    }

    @Test
    void renamerRewritesApplicationClassesMembersReflectionAndResources() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-renamer"));
        Path source = work.resolve("RenameShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));
        Files.writeString(classes.resolve("rename.properties"), "target=pkg.RenameShapes$Target\n", StandardCharsets.UTF_8);

        Path inputJar = work.resolve("rename-shapes.jar");
        writeJar(inputJar, classes, "pkg.RenameShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("rename-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("RENAMER OK"), obfuscated);
        assertRenamed(outputJar);
        assertMappingWritten(outputJar);
    }

    @Test
    void renamerNormalizesGeneratedHelperFieldNamesAfterLaterPasses() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-renamer-generated"));
        Path source = work.resolve("GeneratedNames.java");
        Files.writeString(source, generatedNamesSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("generated-names.jar");
        writeJar(inputJar, classes, "pkg.GeneratedNames");
        String original = runJar(inputJar);
        assertTrue(original.contains("alpha:beta:gamma"), original);

        Path outputJar = work.resolve("generated-names-obf.jar");
        runFullObfuscation(inputJar, outputJar);

        assertNoGeneratedDollarFields(outputJar);
    }

    @Test
    void renamerKeepsCffGeneratedFieldsHiddenFromCrossClassReflection() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-renamer-counter"));
        Path source = work.resolve("CounterShape.java");
        Files.writeString(source, counterShapeSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("counter-shape.jar");
        writeJar(inputJar, classes, "pkg.CounterShape");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("counter-shape-obf.jar");
        runCffObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("COUNTER OK"), obfuscated);
        assertNoGeneratedDollarFields(outputJar);
    }

    @Test
    void renamerStyleCffHelperHostsStayInPackageWithoutDollarNames() throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setTransforms(Map.of("renamer", new TransformConfig(true, 1.0, Map.of("packagePrefix", "z/"))));
        ClassHierarchy hierarchy = new ClassHierarchy();
        Map<String, L1Class> classes = new LinkedHashMap<>();
        for (String name : List.of("z/a", "z/b", "z/e")) {
            L1Class clazz = new L1Class(emptyClass(name));
            classes.put(name, clazz);
            hierarchy.addClass(clazz);
        }
        PipelineContext pctx = new PipelineContext(config, hierarchy, classes);

        Method allocator = Class
            .forName("dev.nekoobfuscator.transforms.jvm.cff.CffClassSetup")
            .getDeclaredMethod("uniqueCffHelperHostName", PipelineContext.class, String.class);
        allocator.setAccessible(true);

        String helperHost = (String) allocator.invoke(new ControlFlowFlatteningPass(), pctx, "z/e");

        assertEquals("z/c", helperHost);
        assertFalse(helperHost.substring(helperHost.lastIndexOf('/') + 1).contains("$"), helperHost);
    }

    private ClassNode emptyClass(String name) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V17;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = name;
        node.superName = "java/lang/Object";
        node.methods = new ArrayList<>();
        node.fields = new ArrayList<>();
        return node;
    }

    private void runObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("renamer", new TransformConfig(true, 1.0, Map.of("packagePrefix", "z/")));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x52454E414D45524CL);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void runCompatibilityObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        config.setTransforms(Map.of("renamer", new TransformConfig(true, 1.0, Map.of(
            "packagePrefix", "z/",
            "renameMembers", false,
            "keepClassNames", List.of("pkg.RenameShapes$Target")
        ))));
        config.keyConfig().setMasterSeed(0x434F4D5041544942L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void runFullObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("renamer", new TransformConfig(true, 1.0, Map.of("packagePrefix", "z/")));
        transforms.put("keyDispatch", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("stringObfuscation", new TransformConfig(true, 1.0, Map.of()));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x47454E4E414D4553L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void runCffObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("renamer", new TransformConfig(true, 1.0, Map.of("packagePrefix", "z/")));
        transforms.put("keyDispatch", new TransformConfig(true, 1.0, Map.of()));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0, Map.of()));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x434F554E54455231L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void assertRenamed(Path jar) throws Exception {
        for (String entry : NativeObfuscationHelper.jarEntries(jar)) {
            assertFalse(entry.startsWith("pkg/RenameShapes"), "old class entry survived: " + entry);
            assertFalse(entry.startsWith("dev/nekoobfuscator/runtime/"), "runtime helper class injected: " + entry);
        }
        byte[] resource = NativeObfuscationHelper.extractEntry(jar, "rename.properties");
        String resourceText = new String(resource, StandardCharsets.UTF_8);
        assertFalse(resourceText.contains("pkg.RenameShapes"), resourceText);
        assertTrue(resourceText.contains("z."), resourceText);

        JarInput input = new JarInput(jar);
        for (var clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("z/")) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                assertFalse("hiddenAdd".equals(method.name), "old method name survived");
                assertFalse("join".equals(method.name), "old method name survived");
                assertFalse("compute".equals(method.name), "old interface method name survived");
            }
        }

        byte[] combined = combinedClassBytes(jar);
        String text = new String(combined, StandardCharsets.ISO_8859_1);
        assertFalse(text.contains("pkg/RenameShapes"), "old internal class name survived");
        assertFalse(text.contains("pkg.RenameShapes"), "old dotted class name survived");
        assertFalse(text.contains("hiddenAdd"), "old reflective method name survived");
        assertFalse(text.contains("secret"), "old reflective field name survived");
        assertFalse(text.contains("compute"), "old interface method name survived");
    }

    private void assertMappingWritten(Path outputJar) throws Exception {
        Path map = outputJar.resolveSibling(outputJar.getFileName() + ".map");
        assertTrue(Files.exists(map), "mapping file was not written");
        String text = Files.readString(map);
        assertTrue(text.contains("CLASS pkg/RenameShapes -> z/"), text);
        assertTrue(text.contains("METHOD pkg/RenameShapes$Target.hiddenAdd"), text);
        assertTrue(text.contains("FIELD pkg/RenameShapes$Target.secret"), text);
    }

    private void assertNoGeneratedDollarFields(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        boolean sawSyntheticHelperField = false;
        for (var clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("z/")) continue;
            for (FieldNode field : clazz.asmNode().fields) {
                assertFalse(field.name.startsWith("$"), "generated helper field kept raw name: " + clazz.name() + "." + field.name);
                if ((field.access & org.objectweb.asm.Opcodes.ACC_SYNTHETIC) != 0) {
                    sawSyntheticHelperField = true;
                }
            }
        }
        assertTrue(sawSyntheticHelperField, "fixture did not exercise generated helper fields");
    }

    private byte[] combinedClassBytes(Path jar) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (String entry : NativeObfuscationHelper.jarEntries(jar)) {
            if (entry.endsWith(".class")) {
                out.write(NativeObfuscationHelper.extractEntry(jar, entry));
            }
        }
        return out.toByteArray();
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

            import java.io.InputStream;
            import java.lang.reflect.Field;
            import java.lang.reflect.Method;
            import java.util.Properties;

            public class RenameShapes {
                interface Worker {
                    int compute(int value);
                }

                static class Target implements Worker {
                    private int secret = 7;

                    public int compute(int value) {
                        return hiddenAdd(value) + secret;
                    }

                    private int hiddenAdd(int value) {
                        return value + 3;
                    }

                    String join(String prefix, int value) {
                        return prefix + ":" + value;
                    }
                }

                public static void main(String[] args) throws Exception {
                    Worker worker = new Target();
                    int direct = worker.compute(5);

                    Class<?> type = Class.forName("pkg.RenameShapes$Target");
                    Object target = type.getDeclaredConstructor().newInstance();
                    Field field = type.getDeclaredField("secret");
                    field.setAccessible(true);
                    field.setInt(target, 11);
                    Method method = type.getDeclaredMethod("hiddenAdd", int.class);
                    method.setAccessible(true);
                    int reflected = ((Integer) method.invoke(target, 13)).intValue();

                    Properties properties = new Properties();
                    try (InputStream in = RenameShapes.class.getClassLoader().getResourceAsStream("rename.properties")) {
                        properties.load(in);
                    }
                    Class<?> resourceType = Class.forName(properties.getProperty("target"));
                    Object resourceTarget = resourceType.getDeclaredConstructor().newInstance();

                    String out = ((Target) resourceTarget).join("total", direct + reflected + field.getInt(target));
                    System.out.println(out);
                    if (!out.equals("total:42")) {
                        throw new AssertionError(out);
                    }
                    System.out.println("RENAMER OK");
                }
            }
            """;
    }

    private String generatedNamesSourceText() {
        return """
            package pkg;

            public class GeneratedNames {
                public static void main(String[] args) {
                    String out = part();
                    System.out.println(out);
                    if (!"alpha:beta:gamma".equals(out)) {
                        throw new RuntimeException(out);
                    }
                }

                private static String part() {
                    return "alpha:beta:gamma";
                }
            }
            """;
    }

    private String counterShapeSourceText() {
        return """
            package pkg;

            public class CounterShape {
                public static void main(String[] args) {
                    Target target = new Target();
                    if (target.sum() != 3) {
                        throw new RuntimeException("sum");
                    }
                    int fields = Target.class.getDeclaredFields().length;
                    if (fields != 2) {
                        throw new RuntimeException("fields=" + fields);
                    }
                    System.out.println("COUNTER OK");
                }
            }

            class Target {
                private int left = 1;
                private int right = 2;

                int sum() {
                    return left + right;
                }
            }
            """;
    }
}
