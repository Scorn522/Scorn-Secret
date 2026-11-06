package dev.nekoobfuscator.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeObfuscationIntegrationTest {
    private static final Set<String> FORBIDDEN_RUNTIME_CLASSES = Set.of(
        "dev/nekoobfuscator/runtime/NekoBootstrap.class",
        "dev/nekoobfuscator/runtime/NekoKeyDerivation.class",
        "dev/nekoobfuscator/runtime/NekoStringDecryptor.class",
        "dev/nekoobfuscator/runtime/NekoFlowException.class",
        "dev/nekoobfuscator/runtime/NekoContext.class",
        "dev/nekoobfuscator/runtime/NekoClassLoader.class",
        "dev/nekoobfuscator/runtime/NekoJarLauncher.class",
        "dev/nekoobfuscator/runtime/NekoResourceLoader.class",
        "dev/nekoobfuscator/runtime/NekoUnsafe.class",
        "dev/nekoobfuscator/runtime/NekoIndyDispatch.class"
    );
    private static final Pattern HELPER_NAME_PATTERN = Pattern.compile("neko_impl_helper_.*");

    @BeforeAll
    static void prepareFixtures() throws Exception {
        NativeObfuscationHelper.ensureObfuscatedFixtures();
    }

    @Test
    @Timeout(2)
    void nativeObfuscation_TEST_calcUnder150ms() throws Exception {
        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runCachedObfuscated("TEST", List.of(), List.of(), Duration.ofMinutes(2));

        assertEquals(0, result.exitCode(), () -> result.combinedOutput());
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        long calcMillis = NativeObfuscationHelper.parseCalcMillis(result.combinedOutput());
        assertTrue(calcMillis <= 150, () -> "Expected Calc benchmark <= 150ms but got " + calcMillis + "ms\n" + result.combinedOutput());
    }

    @Test
    @Timeout(2)
    void nativeObfuscation_TEST_allTestsExceptSecurityPass() throws Exception {
        NativeObfuscationHelper.JarRunResult original = NativeObfuscationHelper.runCachedOriginal("TEST", List.of(), List.of(), Duration.ofMinutes(2));
        NativeObfuscationHelper.JarRunResult nativeRun = NativeObfuscationHelper.runCachedObfuscated("TEST", List.of(), List.of(), Duration.ofMinutes(2));

        assertEquals(0, original.exitCode(), () -> original.combinedOutput());
        assertEquals(0, nativeRun.exitCode(), () -> nativeRun.combinedOutput());
        NativeObfuscationHelper.assertNoFatalNativeCrash(nativeRun);

        String originalOutput = original.combinedOutput();
        String nativeOutput = nativeRun.combinedOutput();

        List<String> expectedPassLines = List.of(
            "Test 1.1: Inheritance PASS",
            "Test 1.2: Cross PASS",
            "Test 1.3: Throw PASS",
            "Test 1.4: Accuracy PASS",
            "Test 1.5: SubClass PASS",
            "Test 1.6: Pool PASS",
            "Test 1.7: InnerClass PASS",
            "Test 2.1: Counter PASS",
            "Test 2.3: Resource PASS",
            "Test 2.4: Field PASS",
            "Test 2.5: Loader PASS",
            "Test 2.6: ReTrace PASS",
            "Test 2.7: Annotation PASS"
        );

        for (String expectedPassLine : expectedPassLines) {
            assertTrue(originalOutput.contains(expectedPassLine), () -> "Original TEST.jar output missing baseline line: " + expectedPassLine + "\n" + originalOutput);
            assertTrue(nativeOutput.contains(expectedPassLine), () -> "Native TEST.jar output missing pass line: " + expectedPassLine + "\n" + nativeOutput);
        }

        assertTrue(originalOutput.contains("Test 2.2: Chinese"), () -> originalOutput);
        assertTrue(nativeOutput.contains("Test 2.2: Chinese"), () -> nativeOutput);
        assertTrue(nativeOutput.contains("Test 2.8: Sec ERROR"), () -> "Expected known Test 2.8 baseline failure to remain visible\n" + nativeOutput);
    }

    @Test
    @Timeout(2)
    void nativeObfuscation_obfusjack_reachesCompletion() throws Exception {
        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runCachedObfuscated("obfusjack", List.of(), List.of(), Duration.ofMinutes(2));

        assertEquals(0, result.exitCode(), () -> result.combinedOutput());
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        assertTrue(result.combinedOutput().contains("=== All tests completed ==="), () -> result.combinedOutput());
    }

    @Test
    @Timeout(45)
    void nativeObfuscation_obfusjack_debugRuntimeStable() throws Exception {
        NativeObfuscationHelper.NativeArtifact artifact = NativeObfuscationHelper.artifact("obfusjack");
        Path stdout = NativeObfuscationHelper.nativeWorkDir().resolve("native_obfusjack_debug_stability.stdout.log");
        Path stderr = NativeObfuscationHelper.nativeWorkDir().resolve("native_obfusjack_debug_stability.stderr.log");
        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runJar(
            artifact.outputJar(),
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            stdout,
            stderr,
            Duration.ofSeconds(30),
            Map.of("NEKO_PATCH_DEBUG", "1")
        );

        String combined = result.combinedOutput();
        assertEquals(0, result.exitCode(), () -> combined);
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        assertFalse(combined.contains("TLAB byte[] allocation failed"), () -> combined);
        assertFalse(combined.contains("TLAB String allocation failed"), () -> combined);
        assertFalse(combined.contains("NEW TLAB allocation failed"), () -> combined);
        assertTrue(combined.contains("Virtual threads:"), () -> combined);
        assertTrue(combined.contains("=== All tests completed ==="), () -> combined);
    }

    @Test
    @Timeout(180)
    void nativeObfuscation_randomRuntimeStableTenRuns() throws Exception {
        NativeObfuscationHelper.NativeArtifact testArtifact = NativeObfuscationHelper.artifact("TEST");
        NativeObfuscationHelper.NativeArtifact obfusjackArtifact = NativeObfuscationHelper.artifact("obfusjack");
        Path workDir = NativeObfuscationHelper.nativeWorkDir();

        for (int i = 1; i <= 10; i++) {
            final int run = i;
            NativeObfuscationHelper.JarRunResult testRun = NativeObfuscationHelper.runJar(
                testArtifact.outputJar(),
                List.of("-XX:+PerfDisableSharedMem"),
                List.of(),
                workDir.resolve("native_TEST_stability_" + i + ".stdout.log"),
                workDir.resolve("native_TEST_stability_" + i + ".stderr.log"),
                Duration.ofSeconds(30)
            );
            String testCombined = testRun.combinedOutput();
            assertEquals(0, testRun.exitCode(), () -> "TEST stability run " + run + "\n" + testCombined);
            NativeObfuscationHelper.assertNoFatalNativeCrash(testRun);
            assertFalse(testCombined.contains("TLAB byte[] allocation failed"), () -> testCombined);
            assertFalse(testCombined.contains("TLAB String allocation failed"), () -> testCombined);
            assertFalse(testCombined.contains("NEW TLAB allocation failed"), () -> testCombined);
            assertTrue(testCombined.contains("Test 1.6: Pool PASS"), () -> testCombined);
            assertTrue(testCombined.contains("-------------Tests r Finished-------------"), () -> testCombined);

            NativeObfuscationHelper.JarRunResult obfusjackRun = NativeObfuscationHelper.runJar(
                obfusjackArtifact.outputJar(),
                List.of("-XX:+PerfDisableSharedMem"),
                List.of(),
                workDir.resolve("native_obfusjack_stability_" + i + ".stdout.log"),
                workDir.resolve("native_obfusjack_stability_" + i + ".stderr.log"),
                Duration.ofSeconds(45)
            );
            String obfusjackCombined = obfusjackRun.combinedOutput();
            assertEquals(0, obfusjackRun.exitCode(), () -> "obfusjack stability run " + run + "\n" + obfusjackCombined);
            NativeObfuscationHelper.assertNoFatalNativeCrash(obfusjackRun);
            assertFalse(obfusjackCombined.contains("TLAB byte[] allocation failed"), () -> obfusjackCombined);
            assertFalse(obfusjackCombined.contains("TLAB String allocation failed"), () -> obfusjackCombined);
            assertFalse(obfusjackCombined.contains("NEW TLAB allocation failed"), () -> obfusjackCombined);
            assertTrue(obfusjackCombined.contains("Virtual threads:"), () -> obfusjackCombined);
            assertTrue(obfusjackCombined.contains("=== All tests completed ==="), () -> obfusjackCombined);
        }
    }

    @Test
    @Timeout(2)
    void nativeObfuscation_objectFieldAndStaticStoresRun() throws Exception {
        Path workDir = NativeObfuscationHelper.nativeWorkDir();
        Path input = workDir.resolve("object-field-store.jar");
        Path output = workDir.resolve("object-field-store-native.jar");
        writeObjectFieldStoreJar(input);

        NativeObfuscationHelper.ObfuscationRunResult obfuscation = NativeObfuscationHelper.obfuscateJar(
            input,
            output,
            NativeObfuscationHelper.configsDir().resolve("native-test.yml"),
            Duration.ofMinutes(2)
        );
        String obfuscationLog = obfuscation.combinedOutput();
        assertTrue(obfuscationLog.contains("Native stage: translated="), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("Native compilation produced no libraries"), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("translated=0"), () -> obfuscationLog);

        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("object-field-store-native.stdout.log"),
            workDir.resolve("object-field-store-native.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_PATCH_DEBUG", "1")
        );

        String combined = result.combinedOutput();
        assertEquals(0, result.exitCode(), () -> combined);
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        assertTrue(combined.contains("object-store-ok"), () -> combined);
    }

    @Test
    @Timeout(2)
    void nativeObfuscation_objectArrayLoadStoreRun() throws Exception {
        Path workDir = NativeObfuscationHelper.nativeWorkDir();
        Path input = workDir.resolve("object-array-access.jar");
        Path output = workDir.resolve("object-array-access-native.jar");
        writeObjectArrayAccessJar(input);

        NativeObfuscationHelper.ObfuscationRunResult obfuscation = NativeObfuscationHelper.obfuscateJar(
            input,
            output,
            NativeObfuscationHelper.configsDir().resolve("native-test.yml"),
            Duration.ofMinutes(2)
        );
        String obfuscationLog = obfuscation.combinedOutput();
        assertTrue(obfuscationLog.contains("Native stage: translated="), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("Native compilation produced no libraries"), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("translated=0"), () -> obfuscationLog);

        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("object-array-access-native.stdout.log"),
            workDir.resolve("object-array-access-native.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_PATCH_DEBUG", "1")
        );

        String combined = result.combinedOutput();
        assertEquals(0, result.exitCode(), () -> combined);
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        assertTrue(combined.contains("object-array-ok"), () -> combined);
    }

    @Test
    @Timeout(value = 2, unit = TimeUnit.MINUTES)
    void nativeObfuscation_methodTypeLdcUsesDescriptorNjxPath() throws Exception {
        Path workDir = NativeObfuscationHelper.nativeWorkDir();
        Path input = workDir.resolve("methodtype-ldc.jar");
        Path output = workDir.resolve("methodtype-ldc-native.jar");
        writeMethodTypeLdcJar(input);

        NativeObfuscationHelper.ObfuscationRunResult obfuscation = NativeObfuscationHelper.obfuscateJar(
            input,
            output,
            NativeObfuscationHelper.configsDir().resolve("native-test.yml"),
            Duration.ofMinutes(2)
        );
        String obfuscationLog = obfuscation.combinedOutput();
        assertTrue(obfuscationLog.contains("Native stage: translated="), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("Native compilation produced no libraries"), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("translated=0"), () -> obfuscationLog);

        NativeObfuscationHelper.JarRunResult ok = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("methodtype-ldc-native.stdout.log"),
            workDir.resolve("methodtype-ldc-native.stderr.log"),
            Duration.ofSeconds(30)
        );
        String okCombined = ok.combinedOutput();
        assertEquals(0, ok.exitCode(), () -> okCombined);
        NativeObfuscationHelper.assertNoFatalNativeCrash(ok);
        assertTrue(okCombined.contains("methodtype-ldc-ok"), () -> okCombined);

        NativeObfuscationHelper.JarRunResult negative = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("methodtype-ldc-negative.stdout.log"),
            workDir.resolve("methodtype-ldc-negative.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_NATIVE_DIAG_FAIL_METHODTYPE_DESCRIPTOR_ENTRY", "1")
        );
        String negativeCombined = negative.combinedOutput();
        assertTrue(negative.exitCode() != 0, () -> negativeCombined);
        assertTrue(negativeCombined.contains("MethodType.fromMethodDescriptorString entry unavailable"), () -> negativeCombined);

        NativeObfuscationHelper.JarRunResult parameterNegative = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("methodtype-ldc-parameter-negative.stdout.log"),
            workDir.resolve("methodtype-ldc-parameter-negative.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_NATIVE_DIAG_FAIL_METHODTYPE_PARAMETER_ARRAY_ENTRY", "1")
        );
        String parameterNegativeCombined = parameterNegative.combinedOutput();
        assertTrue(parameterNegative.exitCode() != 0, () -> parameterNegativeCombined);
        assertTrue(parameterNegativeCombined.contains("MethodType.parameterArray entry unavailable"), () -> parameterNegativeCombined);

        NativeObfuscationHelper.JarRunResult bootstrapNegative = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("methodtype-ldc-bootstrap-negative.stdout.log"),
            workDir.resolve("methodtype-ldc-bootstrap-negative.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_NATIVE_DIAG_FAIL_BOOTSTRAP_GET_DECLARED_METHOD_ENTRY", "1")
        );
        String bootstrapNegativeCombined = bootstrapNegative.combinedOutput();
        assertTrue(bootstrapNegative.exitCode() != 0, () -> bootstrapNegativeCombined);
        assertTrue(bootstrapNegativeCombined.contains("Bootstrap Class.getDeclaredMethod entry unavailable"), () -> bootstrapNegativeCombined);

        NativeObfuscationHelper.JarRunResult condyArrayNegative = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("methodtype-ldc-condy-array-negative.stdout.log"),
            workDir.resolve("methodtype-ldc-condy-array-negative.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_NATIVE_DIAG_FAIL_CONDY_OBJ_ARRAY_ALLOC", "1")
        );
        String condyArrayNegativeCombined = condyArrayNegative.combinedOutput();
        assertTrue(condyArrayNegative.exitCode() != 0, () -> condyArrayNegativeCombined);
        assertTrue(condyArrayNegativeCombined.contains("ConstantDynamic object-array direct allocation unavailable"),
            () -> condyArrayNegativeCombined);

        NativeObfuscationHelper.JarRunResult implLookupNegative = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("methodtype-ldc-impl-lookup-negative.stdout.log"),
            workDir.resolve("methodtype-ldc-impl-lookup-negative.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_NATIVE_DIAG_FAIL_IMPL_LOOKUP_SLOT", "1")
        );
        String implLookupNegativeCombined = implLookupNegative.combinedOutput();
        assertTrue(implLookupNegative.exitCode() != 0, () -> implLookupNegativeCombined);
        assertTrue(implLookupNegativeCombined.contains("IMPL_LOOKUP direct local handle unavailable"),
            () -> implLookupNegativeCombined);

        NativeObfuscationHelper.JarRunResult privateLookupNegative = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("methodtype-ldc-private-lookup-negative.stdout.log"),
            workDir.resolve("methodtype-ldc-private-lookup-negative.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_NATIVE_DIAG_FAIL_PRIVATE_LOOKUP_ENTRY", "1")
        );
        String privateLookupNegativeCombined = privateLookupNegative.combinedOutput();
        assertTrue(privateLookupNegative.exitCode() != 0, () -> privateLookupNegativeCombined);
        assertTrue(privateLookupNegativeCombined.contains("MethodHandles.privateLookupIn entry unavailable"),
            () -> privateLookupNegativeCombined);
    }

    @Test
    @Timeout(2)
    void nativeObfuscation_implicitExceptionsRun() throws Exception {
        Path workDir = NativeObfuscationHelper.nativeWorkDir();
        Path input = workDir.resolve("implicit-exceptions.jar");
        Path output = workDir.resolve("implicit-exceptions-native.jar");
        writeImplicitExceptionsJar(input);

        NativeObfuscationHelper.ObfuscationRunResult obfuscation = NativeObfuscationHelper.obfuscateJar(
            input,
            output,
            NativeObfuscationHelper.configsDir().resolve("native-test.yml"),
            Duration.ofMinutes(2)
        );
        String obfuscationLog = obfuscation.combinedOutput();
        assertTrue(obfuscationLog.contains("Native stage: translated="), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("Native compilation produced no libraries"), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("translated=0"), () -> obfuscationLog);

        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("implicit-exceptions-native.stdout.log"),
            workDir.resolve("implicit-exceptions-native.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_PATCH_DEBUG", "1")
        );

        String combined = result.combinedOutput();
        assertEquals(0, result.exitCode(), () -> combined);
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        assertTrue(combined.contains("implicit-exceptions-ok"), () -> combined);
    }

    @Test
    @Timeout(2)
    void nativeObfuscation_rawStringGraphOptInRunsConcatShapes() throws Exception {
        Path workDir = NativeObfuscationHelper.nativeWorkDir();
        Path input = workDir.resolve("raw-string-graph.jar");
        Path output = workDir.resolve("raw-string-graph-native.jar");
        writeRawStringGraphJar(input);

        NativeObfuscationHelper.ObfuscationRunResult obfuscation = NativeObfuscationHelper.obfuscateJar(
            input,
            output,
            NativeObfuscationHelper.configsDir().resolve("native-test.yml"),
            Duration.ofMinutes(2)
        );
        String obfuscationLog = obfuscation.combinedOutput();
        assertTrue(obfuscationLog.contains("Native stage: translated="), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("Native compilation produced no libraries"), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("translated=0"), () -> obfuscationLog);

        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runJar(
            output,
            List.of("-XX:+PerfDisableSharedMem"),
            List.of(),
            workDir.resolve("raw-string-graph-native.stdout.log"),
            workDir.resolve("raw-string-graph-native.stderr.log"),
            Duration.ofSeconds(30),
            Map.of("NEKO_RAW_STRING_GRAPH_PREREQ", "1")
        );

        String combined = result.combinedOutput();
        assertEquals(0, result.exitCode(), () -> combined);
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        assertTrue(combined.contains("raw-string-graph-ok"), () -> combined);
    }

    @Test
    @Timeout(5)
    void nativeObfuscation_dependencyCallerObservesTranslatedStackTrace() throws Exception {
        Path workDir = NativeObfuscationHelper.nativeWorkDir();
        Path input = workDir.resolve("dependency-shadow-target.jar");
        Path dependency = workDir.resolve("dependency-shadow-caller.jar");
        Path output = workDir.resolve("dependency-shadow-target-native.jar");
        writeDependencyShadowStackJars(input, dependency);

        NativeObfuscationHelper.ObfuscationRunResult obfuscation = NativeObfuscationHelper.obfuscateJar(
            input,
            output,
            NativeObfuscationHelper.configsDir().resolve("native-test.yml"),
            Duration.ofMinutes(2)
        );
        String obfuscationLog = obfuscation.combinedOutput();
        assertTrue(obfuscationLog.contains("Native stage: translated="), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("Native compilation produced no libraries"), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("translated=0"), () -> obfuscationLog);

        Path stdout = workDir.resolve("dependency-shadow-native.stdout.log");
        Path stderr = workDir.resolve("dependency-shadow-native.stderr.log");
        NativeObfuscationHelper.JarRunResult result = runDependencyShadowJar(
            output,
            dependency,
            stdout,
            stderr,
            Map.of()
        );
        String combined = result.combinedOutput();
        assertEquals(0, result.exitCode(), () -> combined);
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        assertTrue(combined.contains("dependency-stacktrace-ok"), () -> combined);

        NativeObfuscationHelper.JarRunResult arrayNegative = runDependencyShadowJar(
            output,
            dependency,
            workDir.resolve("dependency-shadow-array-negative.stdout.log"),
            workDir.resolve("dependency-shadow-array-negative.stderr.log"),
            Map.of("NEKO_NATIVE_DIAG_FAIL_SHADOW_TRACE_ARRAY_ALLOC", "1")
        );
        String arrayNegativeCombined = arrayNegative.combinedOutput();
        assertTrue(arrayNegative.exitCode() != 0, () -> arrayNegativeCombined);
        assertTrue(arrayNegativeCombined.contains("StackTraceElement array direct allocation unavailable"),
            () -> arrayNegativeCombined);

        NativeObfuscationHelper.JarRunResult ctorNegative = runDependencyShadowJar(
            output,
            dependency,
            workDir.resolve("dependency-shadow-ctor-negative.stdout.log"),
            workDir.resolve("dependency-shadow-ctor-negative.stderr.log"),
            Map.of("NEKO_NATIVE_DIAG_FAIL_SHADOW_STE_CTOR_ENTRY", "1")
        );
        String ctorNegativeCombined = ctorNegative.combinedOutput();
        assertTrue(ctorNegative.exitCode() != 0, () -> ctorNegativeCombined);
        assertTrue(ctorNegativeCombined.contains("StackTraceElement.<init> entry unavailable"),
            () -> ctorNegativeCombined);
    }

    private static NativeObfuscationHelper.JarRunResult runDependencyShadowJar(
        Path output,
        Path dependency,
        Path stdout,
        Path stderr,
        Map<String, String> environment
    ) throws Exception {
        ProcessBuilder processBuilder = new ProcessBuilder(
            "java",
            "-XX:+PerfDisableSharedMem",
            "-cp",
            output + java.io.File.pathSeparator + dependency,
            "dep.ExternalStackCaller"
        );
        processBuilder.directory(NativeObfuscationHelper.projectRoot().toFile());
        processBuilder.environment().putAll(environment);
        processBuilder.redirectOutput(stdout.toFile());
        processBuilder.redirectError(stderr.toFile());
        long start = System.nanoTime();
        Process process = processBuilder.start();
        boolean finished = process.waitFor(Duration.ofSeconds(30).toMillis(), TimeUnit.MILLISECONDS);
        if (!finished) {
            process.destroyForcibly();
        }
        assertTrue(finished, "Timed out running dependency shadow-stack fixture");
        return new NativeObfuscationHelper.JarRunResult(
            output,
            stdout,
            stderr,
            Files.readString(stdout),
            Files.readString(stderr),
            process.exitValue(),
            Duration.ofNanos(System.nanoTime() - start)
        );
    }

    @Test
    @Timeout(2)
    void nativeObfuscation_SnakeGame_headlessExceptionOnly() throws Exception {
        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runCachedObfuscated(
            "SnakeGame",
            List.of("-Djava.awt.headless=true"),
            List.of(),
            Duration.ofMinutes(2)
        );

        String combined = result.combinedOutput();
        assertFalse(combined.contains("UnsatisfiedLinkError"), () -> combined);
        assertFalse(combined.contains("ClassFormatError"), () -> combined);
        assertTrue(combined.contains("HeadlessException"), () -> combined);
    }

    @Test
    void nativeObfuscation_noHelperMethodsInOutput() throws Exception {
        for (NativeObfuscationHelper.NativeArtifact artifact : NativeObfuscationHelper.ensureObfuscatedFixtures().values()) {
            List<String> offendingMethods = new ArrayList<>();
            for (ClassNode classNode : NativeObfuscationHelper.readAllClasses(artifact.outputJar())) {
                for (MethodNode method : classNode.methods) {
                    if (HELPER_NAME_PATTERN.matcher(method.name).matches()) {
                        offendingMethods.add(classNode.name + '#' + method.name + method.desc);
                    }
                }
            }
            assertTrue(offendingMethods.isEmpty(), () -> "Found helper methods in " + artifact.outputJar() + ": " + offendingMethods);
        }
    }

    @Test
    void nativeObfuscation_noClassesListInOutput() throws Exception {
        for (NativeObfuscationHelper.NativeArtifact artifact : NativeObfuscationHelper.ensureObfuscatedFixtures().values()) {
            Set<String> entries = NativeObfuscationHelper.jarEntries(artifact.outputJar());
            assertFalse(entries.contains("classes.list"), () -> "Unexpected classes.list in " + artifact.outputJar());
            assertFalse(entries.contains("neko/native/classes.list"), () -> "Unexpected native classes.list in " + artifact.outputJar());
        }
    }

    @Test
    void nativeObfuscation_onlyNekoNativeLoaderInjected() throws Exception {
        for (NativeObfuscationHelper.NativeArtifact artifact : NativeObfuscationHelper.ensureObfuscatedFixtures().values()) {
            Set<String> entries = NativeObfuscationHelper.jarEntries(artifact.outputJar());
            assertTrue(entries.contains("dev/nekoobfuscator/runtime/NekoNativeLoader.class"), () -> "Missing NekoNativeLoader in " + artifact.outputJar());
            for (String forbidden : FORBIDDEN_RUNTIME_CLASSES) {
                assertFalse(entries.contains(forbidden), () -> "Unexpected runtime class " + forbidden + " in " + artifact.outputJar());
            }
        }
    }

    @Test
    void nativeObfuscation_sharedLibraryPresent() throws Exception {
        String expectedEntry = NativeObfuscationHelper.platformLibraryEntryName();
        for (NativeObfuscationHelper.NativeArtifact artifact : NativeObfuscationHelper.ensureObfuscatedFixtures().values()) {
            Set<String> entries = NativeObfuscationHelper.jarEntries(artifact.outputJar());
            long count = entries.stream().filter(expectedEntry::equals).count();
            assertEquals(1L, count, () -> "Expected exactly one native library entry `" + expectedEntry + "` in " + artifact.outputJar() + " but found " + count + " entries: " + entries);
        }
    }

    @Test
    void nativeObfuscation_TEST_translatedMethodsAreNative() throws Exception {
        byte[] calcClass = NativeObfuscationHelper.extractEntry(NativeObfuscationHelper.artifact("TEST").outputJar(), "pack/tests/bench/Calc.class");

        NativeObfuscationHelper.assertClassHasNativeMethod(calcClass, "runAll", "()V");
        NativeObfuscationHelper.assertClassHasNativeMethod(calcClass, "call", "(I)V");
        NativeObfuscationHelper.assertClassHasNativeMethod(calcClass, "runAdd", "()V");
        NativeObfuscationHelper.assertClassHasNativeMethod(calcClass, "runStr", "()V");
    }

    @Test
    void nativeObfuscation_isIdempotent() throws Exception {
        Path workDir = NativeObfuscationHelper.nativeWorkDir();
        Path firstOutput = workDir.resolve("TEST-idempotent-1.jar");
        Path secondOutput = workDir.resolve("TEST-idempotent-2.jar");
        Path config = NativeObfuscationHelper.configsDir().resolve("native-test.yml");
        Path input = NativeObfuscationHelper.inputJarFor("TEST");

        NativeObfuscationHelper.obfuscateJar(input, firstOutput, config);
        NativeObfuscationHelper.obfuscateJar(input, secondOutput, config);

        long firstNativeCount = NativeObfuscationHelper.countNativeMethods(firstOutput);
        long secondNativeCount = NativeObfuscationHelper.countNativeMethods(secondOutput);

        assertTrue(firstNativeCount > 0, "Expected first obfuscated jar to contain native methods");
        assertEquals(firstNativeCount, secondNativeCount, "Expected repeated obfuscation to preserve native method count");
    }

    @Test
    void nativeObfuscation_nativeMethodsHaveOriginalSignatures() throws Exception {
        byte[] originalCalc = NativeObfuscationHelper.extractEntry(NativeObfuscationHelper.inputJarFor("TEST"), "pack/tests/bench/Calc.class");
        byte[] nativeCalc = NativeObfuscationHelper.extractEntry(NativeObfuscationHelper.artifact("TEST").outputJar(), "pack/tests/bench/Calc.class");

        Map<String, Integer> originalMethods = methodAccessBySignature(originalCalc, List.of(
            "runAll()V",
            "call(I)V",
            "runAdd()V",
            "runStr()V"
        ));
        Map<String, Integer> nativeMethods = methodAccessBySignature(nativeCalc, List.of(
            "runAll()V",
            "call(I)V",
            "runAdd()V",
            "runStr()V"
        ));

        assertEquals(originalMethods.keySet(), nativeMethods.keySet(), "Method signatures changed during native rewrite");
        for (Map.Entry<String, Integer> entry : nativeMethods.entrySet()) {
            assertEquals(0, entry.getValue() & Opcodes.ACC_NATIVE,
                () -> "Expected method to NOT be ACC_NATIVE (no-native-keyword refactor): " + entry.getKey());
        }
    }

    private static void writeObjectFieldStoreJar(Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "pkg.ObjectStoreRuntime");

        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
            out.putNextEntry(new JarEntry("pkg/ObjectStoreRuntime.class"));
            out.write(objectFieldStoreClassBytes());
            out.closeEntry();
        }
    }

    private static void writeObjectArrayAccessJar(Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "pkg.ObjectArrayRuntime");

        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
            out.putNextEntry(new JarEntry("pkg/ObjectArrayRuntime.class"));
            out.write(objectArrayAccessClassBytes());
            out.closeEntry();
        }
    }

    private static void writeMethodTypeLdcJar(Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "pkg.MethodTypeLdcRuntime");

        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
            out.putNextEntry(new JarEntry("pkg/MethodTypeLdcRuntime.class"));
            out.write(methodTypeLdcClassBytes());
            out.closeEntry();
        }
    }

    private static void writeImplicitExceptionsJar(Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "pkg.ImplicitExceptionRuntime");

        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
            out.putNextEntry(new JarEntry("pkg/ImplicitExceptionRuntime.class"));
            out.write(implicitExceptionsClassBytes());
            out.closeEntry();
        }
    }

    private static void writeRawStringGraphJar(Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "pkg.RawStringGraphRuntime");

        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
            out.putNextEntry(new JarEntry("pkg/RawStringGraphRuntime.class"));
            out.write(rawStringGraphClassBytes());
            out.closeEntry();
        }
    }

    private static void writeDependencyShadowStackJars(Path targetJar, Path dependencyJar) throws Exception {
        Files.createDirectories(targetJar.getParent());
        Manifest targetManifest = new Manifest();
        targetManifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(targetJar), targetManifest)) {
            out.putNextEntry(new JarEntry("pkg/NativeStackTarget.class"));
            out.write(nativeStackTargetClassBytes());
            out.closeEntry();
        }

        Manifest depManifest = new Manifest();
        depManifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        depManifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, "dep.ExternalStackCaller");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(dependencyJar), depManifest)) {
            out.putNextEntry(new JarEntry("dep/ExternalStackCaller.class"));
            out.write(externalStackCallerClassBytes());
            out.closeEntry();
        }
    }

    private static byte[] nativeStackTargetClassBytes() {
        String owner = "pkg/NativeStackTarget";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);

        var init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        var capture = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "capture", "()Ljava/lang/String;", null, null);
        capture.visitCode();
        capture.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "leaf", "()[Ljava/lang/StackTraceElement;", false);
        capture.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Arrays", "toString", "([Ljava/lang/Object;)Ljava/lang/String;", false);
        capture.visitInsn(Opcodes.ARETURN);
        capture.visitMaxs(0, 0);
        capture.visitEnd();

        var leaf = cw.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "leaf", "()[Ljava/lang/StackTraceElement;", null, null);
        leaf.visitCode();
        leaf.visitTypeInsn(Opcodes.NEW, "java/lang/Throwable");
        leaf.visitInsn(Opcodes.DUP);
        leaf.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Throwable", "<init>", "()V", false);
        leaf.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Throwable", "getStackTrace", "()[Ljava/lang/StackTraceElement;", false);
        leaf.visitInsn(Opcodes.ARETURN);
        leaf.visitMaxs(0, 0);
        leaf.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] methodTypeLdcClassBytes() {
        String owner = "pkg/MethodTypeLdcRuntime";
        String descriptor = "(Ljava/lang/String;I)Ljava/lang/String;";
        String bootstrapDesc = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/String;";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);

        var init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        var main = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
        Label fail = new Label();
        main.visitCode();
        main.visitLdcInsn(Type.getMethodType(descriptor));
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodType", "toMethodDescriptorString", "()Ljava/lang/String;", false);
        main.visitLdcInsn(descriptor);
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        main.visitJumpInsn(Opcodes.IFEQ, fail);
        main.visitLdcInsn(new ConstantDynamic(
            "dyn",
            "Ljava/lang/String;",
            new Handle(Opcodes.H_INVOKESTATIC, owner, "bootstrap", bootstrapDesc, false)
        ));
        main.visitLdcInsn("condy-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        main.visitJumpInsn(Opcodes.IFEQ, fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("methodtype-ldc-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitLabel(fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("methodtype-ldc-bad");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.ICONST_1);
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(0, 0);
        main.visitEnd();

        var bootstrap = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "bootstrap", bootstrapDesc, null, null);
        bootstrap.visitCode();
        bootstrap.visitLdcInsn("condy-ok");
        bootstrap.visitInsn(Opcodes.ARETURN);
        bootstrap.visitMaxs(0, 0);
        bootstrap.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] externalStackCallerClassBytes() {
        String owner = "dep/ExternalStackCaller";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);

        var init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        var main = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
        Label fail = new Label();
        main.visitCode();
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "pkg/NativeStackTarget", "capture", "()Ljava/lang/String;", false);
        main.visitVarInsn(Opcodes.ASTORE, 1);
        main.visitVarInsn(Opcodes.ALOAD, 1);
        main.visitLdcInsn("pkg.NativeStackTarget.leaf");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "contains", "(Ljava/lang/CharSequence;)Z", false);
        main.visitJumpInsn(Opcodes.IFEQ, fail);
        main.visitVarInsn(Opcodes.ALOAD, 1);
        main.visitLdcInsn("pkg.NativeStackTarget.capture");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "contains", "(Ljava/lang/CharSequence;)Z", false);
        main.visitJumpInsn(Opcodes.IFEQ, fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("dependency-stacktrace-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitLabel(fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitVarInsn(Opcodes.ALOAD, 1);
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.ICONST_1);
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(0, 0);
        main.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] implicitExceptionsClassBytes() {
        String owner = "pkg/ImplicitExceptionRuntime";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);

        var init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        var main = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
        Label fail = new Label();
        main.visitCode();
        main.visitInsn(Opcodes.ICONST_0);
        main.visitVarInsn(Opcodes.ISTORE, 1);
        main.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "lengths", "()I", false);
        main.visitIntInsn(Opcodes.BIPUSH, 11);
        main.visitJumpInsn(Opcodes.IF_ICMPNE, fail);
        emitExceptionProbe(main, owner, "npe", "java/lang/NullPointerException", fail);
        emitExceptionProbe(main, owner, "aioobe", "java/lang/ArrayIndexOutOfBoundsException", fail);
        emitExceptionProbe(main, owner, "arith", "java/lang/ArithmeticException", fail);
        emitExceptionProbe(main, owner, "cce", "java/lang/ClassCastException", fail);
        main.visitVarInsn(Opcodes.ILOAD, 1);
        main.visitInsn(Opcodes.ICONST_4);
        main.visitJumpInsn(Opcodes.IF_ICMPNE, fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("implicit-exceptions-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitLabel(fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("implicit-exceptions-bad");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.ICONST_1);
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(0, 0);
        main.visitEnd();

        emitStringLengthMethod(cw, owner);
        emitNpeMethod(cw, owner);
        emitAioobeMethod(cw, owner);
        emitArithmeticMethod(cw, owner);
        emitCceMethod(cw, owner);

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void emitExceptionProbe(MethodVisitor main, String owner, String methodName, String exceptionType, Label fail) {
        Label start = new Label();
        Label end = new Label();
        Label handler = new Label();
        Label done = new Label();
        main.visitTryCatchBlock(start, end, handler, exceptionType);
        main.visitLabel(start);
        main.visitMethodInsn(Opcodes.INVOKESTATIC, owner, methodName, "()V", false);
        main.visitLabel(end);
        main.visitJumpInsn(Opcodes.GOTO, fail);
        main.visitLabel(handler);
        main.visitVarInsn(Opcodes.ASTORE, 2);
        main.visitIincInsn(1, 1);
        main.visitLabel(done);
    }

    private static void emitStringLengthMethod(ClassWriter cw, String owner) {
        var mv = cw.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "lengths", "()I", null, null);
        mv.visitCode();
        mv.visitLdcInsn("hello");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        mv.visitLdcInsn("水星");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        mv.visitInsn(Opcodes.IADD);
        mv.visitLdcInsn("ab");
        mv.visitLdcInsn("cd");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat", "(Ljava/lang/String;)Ljava/lang/String;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void emitNpeMethod(ClassWriter cw, String owner) {
        var mv = cw.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "npe", "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void emitAioobeMethod(ClassWriter cw, String owner) {
        var mv = cw.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "aioobe", "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_INT);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.IALOAD);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void emitArithmeticMethod(ClassWriter cw, String owner) {
        var mv = cw.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "arith", "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitInsn(Opcodes.IDIV);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void emitCceMethod(ClassWriter cw, String owner) {
        var mv = cw.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "cce", "()V", null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static byte[] objectArrayAccessClassBytes() {
        String owner = "pkg/ObjectArrayRuntime";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);

        var init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        var main = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
        Label fail = new Label();
        main.visitCode();
        main.visitInsn(Opcodes.ICONST_1);
        main.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        main.visitVarInsn(Opcodes.ASTORE, 1);
        main.visitVarInsn(Opcodes.ALOAD, 1);
        main.visitInsn(Opcodes.ICONST_0);
        main.visitLdcInsn("array-ok");
        main.visitInsn(Opcodes.AASTORE);
        main.visitVarInsn(Opcodes.ALOAD, 1);
        main.visitInsn(Opcodes.ICONST_0);
        main.visitInsn(Opcodes.AALOAD);
        main.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
        main.visitLdcInsn("array-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        main.visitJumpInsn(Opcodes.IFEQ, fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("object-array-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitLabel(fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("object-array-bad");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.ICONST_1);
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(0, 0);
        main.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] rawStringGraphClassBytes() {
        String owner = "pkg/RawStringGraphRuntime";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);

        var init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        var main = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
        Label fail = new Label();
        main.visitCode();
        emitStringConcatCase(main, fail, "ab", "cd", "abcd", 1);
        emitStringConcatCase(main, fail, "ab", "水星", "ab水星", 1);
        emitStringConcatCase(main, fail, "", "rhs", "rhs", 1);
        emitStringConcatCase(main, fail, "lhs", "", "lhs", 1);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("raw-string-graph-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitLabel(fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("raw-string-graph-bad");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.ICONST_1);
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(0, 0);
        main.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void emitStringConcatCase(
        MethodVisitor main,
        Label fail,
        String left,
        String right,
        String expected,
        int local
    ) {
        main.visitLdcInsn(left);
        main.visitLdcInsn(right);
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat", "(Ljava/lang/String;)Ljava/lang/String;", false);
        main.visitVarInsn(Opcodes.ASTORE, local);
        main.visitVarInsn(Opcodes.ALOAD, local);
        main.visitLdcInsn(expected);
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        main.visitJumpInsn(Opcodes.IFEQ, fail);
        main.visitVarInsn(Opcodes.ALOAD, local);
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        main.visitLdcInsn(expected.length());
        main.visitJumpInsn(Opcodes.IF_ICMPNE, fail);
    }

    private static byte[] objectFieldStoreClassBytes() {
        String owner = "pkg/ObjectStoreRuntime";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);
        cw.visitField(Opcodes.ACC_PRIVATE, "value", "Ljava/lang/String;", null, null).visitEnd();
        cw.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "STATIC_VALUE", "Ljava/lang/String;", null, null).visitEnd();

        var clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitLdcInsn("init");
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, owner, "STATIC_VALUE", "Ljava/lang/String;");
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();

        var init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitLdcInsn("init");
        init.visitFieldInsn(Opcodes.PUTFIELD, owner, "value", "Ljava/lang/String;");
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        var main = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
        Label fail = new Label();
        main.visitCode();
        main.visitTypeInsn(Opcodes.NEW, owner);
        main.visitInsn(Opcodes.DUP);
        main.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, "<init>", "()V", false);
        main.visitVarInsn(Opcodes.ASTORE, 1);
        main.visitVarInsn(Opcodes.ALOAD, 1);
        main.visitLdcInsn("field-ok");
        main.visitFieldInsn(Opcodes.PUTFIELD, owner, "value", "Ljava/lang/String;");
        main.visitLdcInsn("static-ok");
        main.visitFieldInsn(Opcodes.PUTSTATIC, owner, "STATIC_VALUE", "Ljava/lang/String;");
        main.visitVarInsn(Opcodes.ALOAD, 1);
        main.visitFieldInsn(Opcodes.GETFIELD, owner, "value", "Ljava/lang/String;");
        main.visitLdcInsn("field-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        main.visitJumpInsn(Opcodes.IFEQ, fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, owner, "STATIC_VALUE", "Ljava/lang/String;");
        main.visitLdcInsn("static-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        main.visitJumpInsn(Opcodes.IFEQ, fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("object-store-ok");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitLabel(fail);
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        main.visitLdcInsn("object-store-bad");
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        main.visitInsn(Opcodes.ICONST_1);
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(0, 0);
        main.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static Map<String, Integer> methodAccessBySignature(byte[] classBytes, List<String> signatures) {
        ClassNode classNode = NativeObfuscationHelper.readClass(classBytes);
        Map<String, Integer> result = new LinkedHashMap<>();
        for (String signature : signatures) {
            MethodNode method = classNode.methods.stream()
                .filter(candidate -> (candidate.name + candidate.desc).equals(signature))
                .findFirst()
                .orElse(null);
            assertNotNull(method, () -> "Missing method `" + signature + "` in class " + classNode.name);
            result.put(signature, method.access);
        }
        return result;
    }
}
