package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import org.junit.jupiter.api.Test;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JvmRenamerDynamicProxyIntegrationTest {
    @Test
    void dynamicProxyHandlerMethodGetNameUsesRenamedApplicationInterfaceNameUnderFullProfile() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-renamer-dynamic-proxy-handler"));
        Path source = work.resolve("DynamicProxyHandlerNameEntry.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("dynamic-proxy-handler-name-entry.jar");
        writeJar(inputJar, classes, "DynamicProxyHandlerNameEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("dynamic-proxy-handler-name-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("DYNAMIC PROXY HANDLER NAME OK"), obfuscated);
    }

    @Test
    void dynamicProxyHandlerArgumentsUseOriginalViewUnderFullProfile() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-renamer-dynamic-proxy-args"));
        Path source = work.resolve("DynamicProxyHandlerArgumentsEntry.java");
        Files.writeString(source, argumentSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("dynamic-proxy-handler-arguments-entry.jar");
        writeJar(inputJar, classes, "DynamicProxyHandlerArgumentsEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("dynamic-proxy-handler-arguments-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("DYNAMIC PROXY HANDLER ARGS OK"), obfuscated);
    }

    private void runFullProfileObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("renamer", new TransformConfig(true, 1.0, Map.of("packagePrefix", "a/")));
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("methodParameterObfuscation", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("validationSinkHardening", new TransformConfig(true, 1.0));
        transforms.put("invokeDynamic", new TransformConfig(true, 1.0));
        transforms.put("constantObfuscation", new TransformConfig(true, 1.0));
        transforms.put("stringObfuscation", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x44594E50524F5859L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void writeJar(Path jar, Path classes, String mainClass) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", mainClass);
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            try (var stream = Files.walk(classes)) {
                for (Path classFile : stream.filter(path -> path.toString().endsWith(".class")).toList()) {
                    String name = classes.relativize(classFile).toString().replace('\\', '/');
                    jos.putNextEntry(new JarEntry(name));
                    jos.write(Files.readAllBytes(classFile));
                    jos.closeEntry();
                }
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
            import java.lang.reflect.Proxy;

            public class DynamicProxyHandlerNameEntry {
                interface Calculator {
                    int answer();
                }

                public static void main(String[] args) {
                    Calculator calculator = (Calculator) Proxy.newProxyInstance(
                        Calculator.class.getClassLoader(),
                        new Class<?>[] {Calculator.class},
                        (proxy, method, values) -> {
                            if ("answer".equals(method.getName())) {
                                return 42;
                            }
                            if ("toString".equals(method.getName())) {
                                return "proxy-object";
                            }
                            throw new UnsupportedOperationException(method.toString());
                        }
                    );

                    if (calculator.answer() != 42) {
                        throw new AssertionError("proxy-answer");
                    }
                    if (!"proxy-object".equals(calculator.toString())) {
                        throw new AssertionError("proxy-toString");
                    }
                    System.out.println("DYNAMIC PROXY HANDLER NAME OK");
                }
            }
            """;
    }

    private String argumentSourceText() {
        return """
            import java.lang.reflect.Proxy;

            public class DynamicProxyHandlerArgumentsEntry {
                interface Calculator {
                    int add(int left, int right);
                }

                public static void main(String[] args) {
                    Calculator calculator = (Calculator) Proxy.newProxyInstance(
                        Calculator.class.getClassLoader(),
                        new Class<?>[] {Calculator.class},
                        (proxy, method, values) -> {
                            if ("add".equals(method.getName())) {
                                if (values == null || values.length != 2) {
                                    throw new AssertionError("proxy-args-shape");
                                }
                                return ((Integer) values[0]).intValue() + ((Integer) values[1]).intValue();
                            }
                            if ("toString".equals(method.getName())) {
                                return "proxy-object";
                            }
                            throw new UnsupportedOperationException(method.toString());
                        }
                    );

                    if (calculator.add(19, 23) != 42) {
                        throw new AssertionError("proxy-add");
                    }
                    if (!"proxy-object".equals(calculator.toString())) {
                        throw new AssertionError("proxy-toString");
                    }
                    System.out.println("DYNAMIC PROXY HANDLER ARGS OK");
                }
            }
            """;
    }
}
