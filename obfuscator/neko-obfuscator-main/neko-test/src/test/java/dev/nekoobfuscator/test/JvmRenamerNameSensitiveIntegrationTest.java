package dev.nekoobfuscator.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
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
import org.junit.jupiter.api.Test;

public class JvmRenamerNameSensitiveIntegrationTest {
    @Test
    void renamerRewritesSimpleClassNameLiteralsTiedToStackWalkerAndClassValue() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-renamer-name-sensitive"));
        Path source = work.resolve("NameSensitiveShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("name-sensitive-shapes.jar");
        writeJar(inputJar, classes, "pkg.NameSensitiveShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("name-sensitive-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("RENAMER NAME OK"), obfuscated);
        byte[] combined = combinedClassBytes(outputJar);
        String text = new String(combined, StandardCharsets.ISO_8859_1);
        assertFalse(text.contains("NameSensitiveShapes"), "old simple class-name literal survived");
    }

    private void runObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("renamer", new TransformConfig(true, 1.0, Map.of("packagePrefix", "z/")));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x4E414D4553454E53L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
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

            public class NameSensitiveShapes {
                private static final ClassValue<String> SIMPLE_NAME = new ClassValue<>() {
                    @Override
                    protected String computeValue(Class<?> type) {
                        return type.getSimpleName();
                    }
                };

                public static void main(String[] args) {
                    String stackClass = StackWalker.getInstance().walk(stream ->
                        stream
                            .map(StackWalker.StackFrame::getClassName)
                            .filter(name -> name.endsWith("NameSensitiveShapes"))
                            .findFirst()
                            .orElse(""));
                    if (!stackClass.endsWith("NameSensitiveShapes")) {
                        throw new AssertionError("stack walker class name");
                    }
                    if (!"NameSensitiveShapes".equals(SIMPLE_NAME.get(NameSensitiveShapes.class))) {
                        throw new AssertionError("class value simple name");
                    }
                    System.out.println("RENAMER NAME OK");
                }
            }
            """;
    }
}
