package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.ir.l2.ControlFlowGraph;
import dev.nekoobfuscator.core.ir.l2.SSAForm;
import dev.nekoobfuscator.core.ir.lift.L1ToL2Lifter;
import dev.nekoobfuscator.core.jar.ClassHierarchy;
import dev.nekoobfuscator.core.jar.ClasspathResolver;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.jar.JarOutput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests that still match the rebuilt JVM pipeline.
 */
public class ObfuscationIntegrationTest {
    private static Path testJar;
    private static Path tempDir;

    @BeforeAll
    static void setup() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path testTmpRoot = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test"));
        tempDir = Files.createTempDirectory(testTmpRoot, "neko_test_");

        Path srcFile = tempDir.resolve("TestSample.java");
        try (InputStream is = ObfuscationIntegrationTest.class.getResourceAsStream("/TestSample.java")) {
            if (is != null) {
                Files.copy(is, srcFile, StandardCopyOption.REPLACE_EXISTING);
            } else {
                Path fallback = projectRoot.resolve("neko-test/src/test/resources/TestSample.java");
                assertTrue(Files.exists(fallback), "TestSample.java resource not found: " + fallback);
                Files.copy(fallback, srcFile, StandardCopyOption.REPLACE_EXISTING);
            }
        }

        Path classDir = tempDir.resolve("classes");
        Files.createDirectories(classDir);
        ProcessBuilder javac = new ProcessBuilder("javac", "-d", classDir.toString(), srcFile.toString());
        javac.redirectErrorStream(true);
        Process proc = javac.start();
        String output = new String(proc.getInputStream().readAllBytes());
        int exitCode = proc.waitFor();
        assertEquals(0, exitCode, "javac failed: " + output);

        testJar = tempDir.resolve("test-sample.jar");
        Manifest mf = new Manifest();
        mf.getMainAttributes().putValue("Manifest-Version", "1.0");
        mf.getMainAttributes().putValue("Main-Class", "TestSample");

        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(testJar.toFile()), mf)) {
            jos.putNextEntry(new JarEntry("TestSample.class"));
            jos.write(Files.readAllBytes(classDir.resolve("TestSample.class")));
            jos.closeEntry();
        }

        JarInput verifyInput = new JarInput(testJar);
        assertFalse(verifyInput.classes().isEmpty(), "Test JAR should contain classes");
    }

    @AfterAll
    static void cleanup() {
        // Leave temp dir for debugging.
    }

    @Test
    void testJarRoundTrip() throws Exception {
        JarInput input = new JarInput(testJar);
        assertFalse(input.classes().isEmpty(), "No classes loaded");
        assertEquals(1, input.classes().size());
        assertEquals("TestSample", input.classes().get(0).name());

        Path outputJar = tempDir.resolve("roundtrip.jar");
        ClassHierarchy hierarchy = new ClassHierarchy();
        for (L1Class l1 : input.classes()) hierarchy.addClass(l1);
        new ClasspathResolver(List.of()).populateHierarchy(hierarchy);

        new JarOutput(hierarchy).write(outputJar, input.classes(), input.resources(), input.manifest());

        JarInput roundtripped = new JarInput(outputJar);
        assertEquals(input.classes().size(), roundtripped.classes().size(), "Roundtrip should preserve class count");
        assertEquals(input.classes().get(0).name(), roundtripped.classes().get(0).name());
    }

    @Test
    void testCFGConstruction() throws Exception {
        JarInput input = new JarInput(testJar);
        L1Class clazz = input.classes().get(0);
        L1Method fibonacci = clazz.findMethod("fibonacci", "(I)I");
        assertNotNull(fibonacci, "fibonacci method not found");

        ControlFlowGraph cfg = ControlFlowGraph.build(fibonacci);
        assertNotNull(cfg);
        assertTrue(cfg.blockCount() >= 2, "Expected at least 2 blocks in fibonacci CFG");
        assertNotNull(cfg.entryBlock());
    }

    @Test
    void testSSAConstruction() throws Exception {
        JarInput input = new JarInput(testJar);
        L1Class clazz = input.classes().get(0);
        L1Method fibonacci = clazz.findMethod("fibonacci", "(I)I");
        assertNotNull(fibonacci, "fibonacci method not found");

        SSAForm ssa = new L1ToL2Lifter().lift(fibonacci);
        assertNotNull(ssa);
        assertNotNull(ssa.cfg());
    }

    @Test
    void testControlFlowFlatteningDoesNotInjectRuntime() throws Exception {
        Path outputJar = tempDir.resolve("cf-flattened.jar");
        runObfuscation(testJar, outputJar, Map.of(
            "controlFlowFlattening", new TransformConfig(true, 1.0)
        ));

        JarInput obfuscated = new JarInput(outputJar);
        assertFalse(obfuscated.classes().isEmpty());
        assertFalse(hasClass(outputJar, "dev/nekoobfuscator/runtime/NekoContext"));
        assertFalse(hasClass(outputJar, "dev/nekoobfuscator/runtime/NekoKeyDerivation"));
        assertFalse(hasClass(outputJar, "dev/nekoobfuscator/runtime/NekoResourceLoader"));
    }

    private void runObfuscation(Path input, Path output, Map<String, TransformConfig> transforms)
            throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        config.setTransforms(new LinkedHashMap<>(transforms));
        config.keyConfig().setMasterSeed(12345678L);

        ObfuscationPipeline pipeline = new ObfuscationPipeline(config, new PassRegistry());
        pipeline.execute(input, output);
    }

    private boolean hasClass(Path jar, String className) throws Exception {
        JarInput input = new JarInput(jar);
        for (L1Class clazz : input.classes()) {
            if (className.equals(clazz.name())) return true;
        }
        return false;
    }
}
