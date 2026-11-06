package dev.nekoobfuscator.test;

import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.transforms.jvm.internal.JvmCodeSizeEstimator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Captures a JVM-only full-obfuscation performance baseline for the repository
 * sample jars. This is a baseline gate: it records timings and requires fresh
 * full-obf artifacts to run where the fixture has a non-interactive perf path.
 */
class JvmFullObfuscationPerfTest {
    private static final Pattern PERF_TOPIC_PATTERN = Pattern.compile(
        "(?i)(calc|matrix|seq|thread|virtual|parallel|vthreads|time)"
    );
    private static final Pattern PERF_TIME_PATTERN = Pattern.compile(
        "(?i)\\b\\d+(?:\\.\\d+)?\\s*(?:ns|us|micros?|ms|milliseconds?|s|seconds?)\\b"
    );
    private static final Pattern MISSING_FLOWKEY_HELPERS_PATTERN = Pattern.compile(
        "Control-flow generated helpers missing flow keys: candidates=(\\d+) keyed=(\\d+)"
    );
    private static final Pattern DRY_RUN_METRIC_PATTERN = Pattern.compile(
        "([A-Za-z][A-Za-z0-9]*)=(-?\\d+)"
    );
    private static final Pattern OBFUSJACK_TIMING_PATTERN = Pattern.compile(
        "(Platform threads|Virtual threads|Seq|Parallel|VThreads):\\s*(\\d+)\\s+ms"
    );

    private static final String STRING_TAIL_DESC = "([Ljava/lang/Object;IJI)Ljava/lang/String;";
    private static final String INDY_FLOW_DESC = "(IIIII[Ljava/lang/Object;IJ)J";
    private static final String CFF_OUTLINED_DISPATCH_DESC = "(JIIIII[J)J";
    private static final String CFF_SHARED_GROUP_DISPATCH_DESC = "(JIIIIII[J)J";
    private static final String CFF_TRANSITION_MATERIAL_DESC = "(JIII[Ljava/lang/Object;II[J)J";
    private static final String CFF_STEP_MATERIAL_DESC = "(JIII[Ljava/lang/Object;I[J)J";
    private static final String CFF_ISLAND_MATERIAL_DESC = "(JIII[Ljava/lang/Object;III)I";
    private static final int ABLATION_REPEATS = 3;
    private static final String CFF_ONLY_STACK_CONFIG = """
        version: 1

        transforms:
          renamer: { enabled: true, packagePrefix: a/ }
          keyDispatch: { enabled: true }
          methodParameterObfuscation: { enabled: true }
          controlFlowFlattening: { enabled: true, intensity: 1.0 }
          validationSinkHardening: { enabled: true }
          invokeDynamic: { enabled: false }
          constantObfuscation: { enabled: false }
          stringObfuscation: { enabled: false }

        native:
          enabled: false

        keys:
          masterSeed: auto
        """;
    private static final String FULL_NO_INDY_CONFIG = """
        version: 1

        transforms:
          renamer: { enabled: true, packagePrefix: a/ }
          keyDispatch: { enabled: true }
          methodParameterObfuscation: { enabled: true }
          controlFlowFlattening: { enabled: true, intensity: 1.0 }
          validationSinkHardening: { enabled: true }
          invokeDynamic: { enabled: false }
          constantObfuscation: { enabled: true, intensity: 1.0 }
          stringObfuscation: { enabled: true, intensity: 1.0 }

        native:
          enabled: false

        keys:
          masterSeed: auto
        """;
    private static final String FULL_NO_CONST_STRING_CONFIG = """
        version: 1

        transforms:
          renamer: { enabled: true, packagePrefix: a/ }
          keyDispatch: { enabled: true }
          methodParameterObfuscation: { enabled: true }
          controlFlowFlattening: { enabled: true, intensity: 1.0 }
          validationSinkHardening: { enabled: true }
          invokeDynamic: { enabled: true }
          constantObfuscation: { enabled: false }
          stringObfuscation: { enabled: false }

        native:
          enabled: false

        keys:
          masterSeed: auto
        """;

    @Test
    @Timeout(value = 5, unit = TimeUnit.MINUTES)
    void fullJvmObfuscationPerformanceBaseline() throws Exception {
        Path workDir = Files.createDirectories(
            NativeObfuscationHelper.projectRoot()
                .resolve("build")
                .resolve("test-jvm-full-obf-perf")
        );
        Path config = NativeObfuscationHelper.jarsDir().resolve("full-jvm-obf.yml");
        assertTrue(Files.exists(config), () -> "Missing full JVM obfuscation config: " + config);

        List<Fixture> fixtures = List.of(
            new Fixture("TEST", "test.jar", BehaviorMode.TEST_PERF),
            new Fixture("obfusjack", "test21.jar", BehaviorMode.OBFUSJACK_PERF),
            new Fixture("SnakeGame", "snake.jar", BehaviorMode.HEADLESS_GUI),
            new Fixture("evaluator", "evaluator.jar", BehaviorMode.EVALUATOR)
        );

        List<PerfRecord> records = new ArrayList<>();
        for (Fixture fixture : fixtures) {
            Path input = NativeObfuscationHelper.jarsDir().resolve(fixture.jarName());
            assertTrue(Files.exists(input), () -> "Missing fixture jar: " + input);
            Path output = workDir.resolve(stripJarExtension(input.getFileName().toString()) + "-obf.jar");
            NativeObfuscationHelper.ObfuscationRunResult obfuscation =
                NativeObfuscationHelper.obfuscateJar(input, output, config, Duration.ofMinutes(2));
            assertNoStaticGeneratedHelperHardening(fixture, obfuscation);
            RunRecord originalRun = runFixture(workDir, fixture, input, "original");
            RunRecord obfuscatedRun = runFixture(workDir, fixture, output, "full-obf");
            if (fixture.strictStructuralAudit()) {
                assertNoForbiddenFullObfMarkers(output);
            }
            records.add(new PerfRecord(fixture, input, output, obfuscation, originalRun, obfuscatedRun));
        }

        Path report = workDir.resolve("jvm-full-obf-performance-baseline.json");
        Files.writeString(report, renderReport(config, records), StandardCharsets.UTF_8);
        assertTrue(Files.exists(report), () -> "Missing JVM full-obf perf report: " + report);
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.MINUTES)
    void jvmRuntimeAblationReport() throws Exception {
        Path workDir = Files.createDirectories(
            NativeObfuscationHelper.projectRoot()
                .resolve("build")
                .resolve("test-jvm-runtime-ablation")
        );
        Path fullConfig = NativeObfuscationHelper.jarsDir().resolve("full-jvm-obf.yml");
        assertTrue(Files.exists(fullConfig), () -> "Missing full JVM obfuscation config: " + fullConfig);

        List<Fixture> fixtures = List.of(
            new Fixture("TEST", "test.jar", BehaviorMode.TEST_PERF),
            new Fixture("obfusjack", "test21.jar", BehaviorMode.OBFUSJACK_PERF)
        );
        List<AblationVariant> variants = List.of(
            new AblationVariant("original", null, null),
            new AblationVariant("cff-only-stack", CFF_ONLY_STACK_CONFIG, null),
            new AblationVariant("full-no-indy", FULL_NO_INDY_CONFIG, null),
            new AblationVariant("full-no-const-string", FULL_NO_CONST_STRING_CONFIG, null),
            new AblationVariant("full", null, fullConfig)
        );

        List<AblationRecord> records = new ArrayList<>();
        for (Fixture fixture : fixtures) {
            Path input = NativeObfuscationHelper.jarsDir().resolve(fixture.jarName());
            assertTrue(Files.exists(input), () -> "Missing fixture jar: " + input);
            for (AblationVariant variant : variants) {
                Path config = resolveAblationConfig(workDir, variant);
                Path artifact = input;
                NativeObfuscationHelper.ObfuscationRunResult obfuscation = null;
                if (variant.obfuscates()) {
                    artifact = workDir.resolve(fixture.name() + "-" + variant.name() + ".jar");
                    obfuscation = NativeObfuscationHelper.obfuscateJar(
                        input,
                        artifact,
                        config,
                        Duration.ofMinutes(2)
                    );
                    assertNoStaticGeneratedHelperHardening(fixture, obfuscation);
                }
                List<AblationRunRecord> runs = runAblationVariant(workDir, fixture, variant, artifact);
                records.add(new AblationRecord(
                    fixture,
                    variant.name(),
                    input,
                    artifact,
                    config,
                    obfuscation,
                    analyzeTopology(artifact),
                    runs,
                    validMedians(runs)
                ));
            }
        }

        Path report = workDir.resolve("jvm-runtime-ablation-report.json");
        Files.writeString(report, renderAblationReport(records), StandardCharsets.UTF_8);
        assertTrue(Files.exists(report), () -> "Missing JVM runtime ablation report: " + report);
        assertEquals(
            fixtures.size() * variants.size(),
            records.size(),
            () -> "Incomplete JVM runtime ablation report: " + report
        );
    }

    private static RunRecord runFixture(
        Path workDir,
        Fixture fixture,
        Path jar,
        String variant
    )
        throws Exception {
        Path stdout = workDir.resolve(fixture.name() + "." + variant + ".run.stdout.log");
        Path stderr = workDir.resolve(fixture.name() + "." + variant + ".run.stderr.log");
        NativeObfuscationHelper.JarRunResult run = NativeObfuscationHelper.runJar(
            jar,
            fixture.jvmArgs(),
            List.of(),
            stdout,
            stderr,
            Duration.ofMinutes(2)
        );
        String combined = NativeObfuscationHelper.combinedOutput(run);
        Long calcMillis = validateRun(fixture, variant, run, combined);
        return new RunRecord(run, calcMillis, extractPerformanceTimingLines(combined));
    }

    private static Path resolveAblationConfig(Path workDir, AblationVariant variant)
        throws Exception {
        if (!variant.obfuscates()) return null;
        if (variant.existingConfig() != null) return variant.existingConfig();
        Path configDir = Files.createDirectories(workDir.resolve("configs"));
        Path config = configDir.resolve(variant.name() + ".yml");
        Files.writeString(config, variant.configText(), StandardCharsets.UTF_8);
        return config;
    }

    private static List<AblationRunRecord> runAblationVariant(
        Path workDir,
        Fixture fixture,
        AblationVariant variant,
        Path jar
    )
        throws Exception {
        Path runDir = Files.createDirectories(workDir.resolve("runs"));
        List<AblationRunRecord> runs = new ArrayList<>();
        for (int index = 1; index <= ABLATION_REPEATS; index++) {
            Path stdout = runDir.resolve(fixture.name() + "." + variant.name() + "." + index + ".stdout.log");
            Path stderr = runDir.resolve(fixture.name() + "." + variant.name() + "." + index + ".stderr.log");
            NativeObfuscationHelper.JarRunResult run = NativeObfuscationHelper.runJar(
                jar,
                fixture.jvmArgs(),
                List.of(),
                stdout,
                stderr,
                Duration.ofMinutes(2)
            );
            String combined = NativeObfuscationHelper.combinedOutput(run);
            RunValidity validity = validateAblationRun(fixture, run, combined);
            Map<String, Long> timingMillis = validity.valid()
                ? parseTimingMillis(fixture, combined)
                : Map.of();
            runs.add(new AblationRunRecord(
                index,
                run,
                validity.valid(),
                validity.reason(),
                timingMillis,
                extractPerformanceTimingLines(combined)
            ));
        }
        return runs;
    }

    private static RunValidity validateAblationRun(
        Fixture fixture,
        NativeObfuscationHelper.JarRunResult run,
        String combined
    ) {
        if (run.exitCode() != 0) {
            return new RunValidity(false, "exitCode=" + run.exitCode());
        }
        return switch (fixture.behaviorMode()) {
            case TEST_PERF -> missingExpectedRows(testExpectedRows(), combined);
            case OBFUSJACK_PERF -> combined.contains("=== All tests completed ===")
                ? new RunValidity(true, null)
                : new RunValidity(false, "missing obfusjack completion marker");
            case HEADLESS_GUI -> new RunValidity(false, "headless GUI fixture is not part of the ablation matrix");
            case EVALUATOR -> new RunValidity(false, "evaluator fixture is not part of the ablation matrix");
        };
    }

    private static RunValidity missingExpectedRows(List<String> expectedRows, String combined) {
        for (String expected : expectedRows) {
            if (!combined.contains(expected)) {
                return new RunValidity(false, "missing marker: " + expected);
            }
        }
        return new RunValidity(true, null);
    }

    private static Map<String, Long> parseTimingMillis(Fixture fixture, String combined) {
        Map<String, Long> timings = new LinkedHashMap<>();
        if (fixture.behaviorMode() == BehaviorMode.TEST_PERF) {
            Long calc = NativeObfuscationHelper.parseCalcMillis(combined);
            if (calc != null) timings.put("Calc", calc);
            return timings;
        }
        if (fixture.behaviorMode() == BehaviorMode.OBFUSJACK_PERF) {
            Matcher matcher = OBFUSJACK_TIMING_PATTERN.matcher(combined);
            while (matcher.find()) {
                timings.put(obfusjackMetricName(matcher.group(1)), Long.parseLong(matcher.group(2)));
            }
        }
        return timings;
    }

    private static String obfusjackMetricName(String label) {
        return switch (label) {
            case "Platform threads" -> "Platform";
            case "Virtual threads" -> "Virtual";
            default -> label;
        };
    }

    private static Map<String, Long> validMedians(List<AblationRunRecord> runs) {
        Map<String, List<Long>> valuesByMetric = new LinkedHashMap<>();
        for (AblationRunRecord run : runs) {
            if (!run.valid()) continue;
            for (Map.Entry<String, Long> entry : run.timingMillis().entrySet()) {
                valuesByMetric.computeIfAbsent(entry.getKey(), ignored -> new ArrayList<>()).add(entry.getValue());
            }
        }
        Map<String, Long> medians = new LinkedHashMap<>();
        for (Map.Entry<String, List<Long>> entry : valuesByMetric.entrySet()) {
            List<Long> values = entry.getValue();
            values.sort(Long::compareTo);
            medians.put(entry.getKey(), values.get(values.size() / 2));
        }
        return medians;
    }

    private static Long validateRun(
        Fixture fixture,
        String variant,
        NativeObfuscationHelper.JarRunResult run,
        String combined
    ) {
        return switch (fixture.behaviorMode()) {
            case TEST_PERF -> {
                assertEquals(0, run.exitCode(), () -> fixture.name() + " " + variant + " run failed\n" + combined);
                assertTestRows(fixture, variant, combined);
                yield NativeObfuscationHelper.parseCalcMillis(combined);
            }
            case OBFUSJACK_PERF -> {
                assertEquals(0, run.exitCode(), () -> fixture.name() + " " + variant + " run failed\n" + combined);
                assertTrue(
                    combined.contains("=== All tests completed ==="),
                    () -> fixture.name() + " " + variant + " run did not complete\n" + combined
                );
                yield null;
            }
            case HEADLESS_GUI -> {
                assertEquals(1, run.exitCode(), () -> fixture.name() + " " + variant + " should fail closed in headless AWT\n" + combined);
                assertTrue(
                    combined.contains("java.awt.HeadlessException"),
                    () -> fixture.name() + " " + variant + " did not preserve headless GUI startup behavior\n" + combined
                );
                yield null;
            }
            case EVALUATOR -> {
                assertEquals(0, run.exitCode(), () -> fixture.name() + " " + variant + " run failed\n" + combined);
                assertEvaluatorRows(fixture, variant, combined);
                yield null;
            }
        };
    }

    private static void assertTestRows(Fixture fixture, String variant, String combined) {
        for (String expected : testExpectedRows()) {
            assertTrue(
                combined.contains(expected),
                () -> fixture.name() + " " + variant + " missing baseline row " + expected + "\n" + combined
            );
        }
    }

    private static List<String> testExpectedRows() {
        return List.of(
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
            "Test 2.7: Annotation PASS",
            "Test 2.8: Sec ERROR",
            "-------------Tests r Finished-------------"
        );
    }

    private static void assertEvaluatorRows(Fixture fixture, String variant, String combined) {
        for (String expected : List.of(
            "Today's date is",
            "Performing small int test...",
            "Performing random math operations...",
            "Computing statistics",
            "Loaded 4 tests",
            "Testing annotations",
            "Original Text:Hello World",
            "Descrypted Text:Hello World",
            "Passed string encryption test with",
            "Testing cryptography (Blowfish)",
            "Testing large string",
            "Successfully compared strings",
            "Successfully decrypted hello world 123 1605479835458"
        )) {
            assertTrue(
                combined.contains(expected),
                () -> fixture.name() + " " + variant + " missing baseline marker " + expected + "\n" + combined
            );
        }
    }

    private static void assertNoForbiddenFullObfMarkers(Path jar) throws Exception {
        for (String entry : NativeObfuscationHelper.jarEntries(jar)) {
            assertTrue(
                !entry.startsWith("dev/nekoobfuscator/runtime/"),
                () -> "runtime helper class injected in full-obf artifact: " + entry
            );
        }

        JarInput input = new JarInput(jar);
        Map<String, Integer> helperPrefixCounts = new LinkedHashMap<>();
        Map<String, Integer> helperDescriptorCounts = new LinkedHashMap<>();
        int syntheticObjectCarriers = 0;
        for (var clazz : input.classMap().values()) {
            int classSyntheticObjectCarriers = 0;
            for (var field : clazz.asmNode().fields) {
                assertTrue(!"[I".equals(field.desc), () -> "standalone int[] field survived in " + clazz.name());
                assertTrue(!"[J".equals(field.desc), () -> "standalone long[] field survived in " + clazz.name());
                assertTrue(!"Ljavax/crypto/Cipher;".equals(field.desc), () -> "standalone Cipher field survived in " + clazz.name());
                if ((field.access & Opcodes.ACC_SYNTHETIC) != 0) {
                    if ((field.access & Opcodes.ACC_STATIC) != 0 && "[Ljava/lang/Object;".equals(field.desc)) {
                        syntheticObjectCarriers++;
                        classSyntheticObjectCarriers++;
                    }
                    assertTrue(!"[B".equals(field.desc), () -> "synthetic byte[] static material survived in " + clazz.name());
                    assertTrue(!"J".equals(field.desc), () -> "synthetic long static cache material survived in " + clazz.name());
                    assertTrue(
                        !"Ljava/lang/String;".equals(field.desc),
                        () -> "synthetic String static cache material survived in " + clazz.name()
                    );
                }
                assertTrue(
                    !"Ljava/util/concurrent/ConcurrentHashMap;".equals(field.desc),
                    () -> "standalone indy cache field survived in " + clazz.name()
                );
            }
            assertTrue(
                classSyntheticObjectCarriers <= 1,
                () -> "multiple synthetic Object[] carrier fields in " + clazz.name()
            );
            for (var method : clazz.asmNode().methods) {
                recordHelperPrefix(helperPrefixCounts, method.name);
                helperDescriptorCounts.merge(method.desc, 1, Integer::sum);
                assertTrue(!method.name.startsWith("__neko_strkey"), () -> "string key init helper survived in " + clazz.name());
                assertTrue(!method.name.startsWith("__neko_strstream"), () -> "string stream helper survived in " + clazz.name());
                assertTrue(!method.name.startsWith("__neko_indy_mix"), () -> "indy mix helper survived in " + clazz.name());
                assertTrue(!method.name.startsWith("__neko_cff_didx"), () -> "direct-index CFF helper survived in " + clazz.name());
                assertTrue(!method.name.startsWith("__neko_cff_relay$"), () -> "relocated CFF relay survived in " + clazz.name());
                assertTrue(!method.name.startsWith("__neko_indy_bsm_shared"), () -> "shared indy BSM registry route survived in " + clazz.name());
                assertTrue(!method.name.startsWith("__neko_indy_register"), () -> "indy carrier registry helper survived in " + clazz.name());
                assertTrue(!"(IIJJ)I".equals(method.desc), () -> "old string stream helper ABI survived in " + clazz.name());
                assertTrue(!"(JJ)J".equals(method.desc), () -> "old indy mix helper ABI survived in " + clazz.name());
                if (method.instructions == null) continue;
                for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode call && call.getOpcode() == org.objectweb.asm.Opcodes.INVOKESTATIC) {
                        assertTrue(!"(IIJJ)I".equals(call.desc), () -> "old string stream helper call survived in " + clazz.name());
                        assertTrue(!"(JJ)J".equals(call.desc), () -> "old indy mix helper call survived in " + clazz.name());
                        assertTrue(!call.name.startsWith("__neko_cff_relay$"), () -> "relocated CFF relay call survived in " + clazz.name());
                    }
                }
            }
        }
        assertTrue(
            syntheticObjectCarriers > 0,
            () -> "missing class-owned synthetic Object[] carrier surface in full-obf artifact: " + jar
        );
        assertAcceptedSharedHelperCounts(jar, helperPrefixCounts, helperDescriptorCounts);
    }

    private static void assertNoStaticGeneratedHelperHardening(
        Fixture fixture,
        NativeObfuscationHelper.ObfuscationRunResult obfuscation
    ) {
        String combined = obfuscation.combinedOutput();
        var matcher = MISSING_FLOWKEY_HELPERS_PATTERN.matcher(combined);
        while (matcher.find()) {
            int keyed = Integer.parseInt(matcher.group(2));
            assertEquals(
                0,
                keyed,
                () -> fixture.name() + " generated helper without live flowkey was keyed by CFF"
            );
        }
    }

    private static void recordHelperPrefix(Map<String, Integer> counts, String methodName) {
        for (String prefix : List.of(
            "__neko_strtail$",
            "__neko_indy_resolve",
            "__neko_indy_flow",
            "__neko_indy_guard",
            "__neko_cff_mkey$",
            "__neko_cff_int$",
            "__neko_cff_tmat$"
        )) {
            if (methodName.startsWith(prefix)) {
                counts.merge(prefix, 1, Integer::sum);
                return;
            }
        }
    }

    private static void assertAcceptedSharedHelperCounts(
        Path jar,
        Map<String, Integer> helperPrefixCounts,
        Map<String, Integer> helperDescriptorCounts
    ) {
        for (String prefix : List.of(
            "__neko_strtail$",
            "__neko_indy_resolve",
            "__neko_indy_flow",
            "__neko_indy_guard",
            "__neko_cff_mkey$",
            "__neko_cff_int$",
            "__neko_cff_tmat$"
        )) {
            int count = helperPrefixCounts.getOrDefault(prefix, 0);
            assertTrue(
                count <= 1,
                () -> "accepted shared helper regressed in " + jar + ": " + prefix + " count=" + count
            );
        }
        for (String desc : List.of(
            "([Ljava/lang/Object;IJI)Ljava/lang/String;",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;I[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/invoke/MutableCallSite;Ljava/lang/invoke/MethodType;Ljava/lang/String;I[Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
            "(IIIII[Ljava/lang/Object;IJ)J",
            "(JJ)Z",
            "(IIIIJJ)J",
            "([IIIIIII)I",
            "([Ljava/lang/Object;IIII)I"
        )) {
            int count = helperDescriptorCounts.getOrDefault(desc, 0);
            assertTrue(
                count <= 1,
                () -> "accepted shared helper descriptor regressed in " + jar + ": " + desc + " count=" + count
            );
        }
    }

    private static List<String> extractPerformanceTimingLines(String output) {
        return output.lines()
            .filter(line -> PERF_TOPIC_PATTERN.matcher(line).find())
            .filter(line -> PERF_TIME_PATTERN.matcher(line).find())
            .toList();
    }

    private static String stripJarExtension(String fileName) {
        return fileName.endsWith(".jar") ? fileName.substring(0, fileName.length() - 4) : fileName;
    }

    private static String renderReport(Path config, List<PerfRecord> records)
        throws Exception {
        StringBuilder sb = new StringBuilder(8192);
        sb.append("{\n");
        sb.append("  \"capturedAt\": ").append(json(Instant.now().toString())).append(",\n");
        sb.append("  \"config\": ").append(json(config.toString())).append(",\n");
        sb.append("  \"jdk\": {\n");
        sb.append("    \"javaVersion\": ").append(json(System.getProperty("java.version"))).append(",\n");
        sb.append("    \"javaVendor\": ").append(json(System.getProperty("java.vendor"))).append(",\n");
        sb.append("    \"javaVmName\": ").append(json(System.getProperty("java.vm.name"))).append("\n");
        sb.append("  },\n");
        sb.append("  \"fixtures\": [\n");
        for (int i = 0; i < records.size(); i++) {
            appendRecord(sb, records.get(i), "    ");
            if (i + 1 < records.size()) sb.append(',');
            sb.append('\n');
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String renderAblationReport(List<AblationRecord> records)
        throws Exception {
        StringBuilder sb = new StringBuilder(16384);
        sb.append("{\n");
        sb.append("  \"capturedAt\": ").append(json(Instant.now().toString())).append(",\n");
        sb.append("  \"repeatCount\": ").append(ABLATION_REPEATS).append(",\n");
        sb.append("  \"jdk\": {\n");
        sb.append("    \"javaVersion\": ").append(json(System.getProperty("java.version"))).append(",\n");
        sb.append("    \"javaVendor\": ").append(json(System.getProperty("java.vendor"))).append(",\n");
        sb.append("    \"javaVmName\": ").append(json(System.getProperty("java.vm.name"))).append("\n");
        sb.append("  },\n");
        sb.append("  \"records\": [\n");
        for (int i = 0; i < records.size(); i++) {
            appendAblationRecord(sb, records.get(i), "    ");
            if (i + 1 < records.size()) sb.append(',');
            sb.append('\n');
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static void appendRecord(StringBuilder sb, PerfRecord record, String indent)
        throws Exception {
        sb.append(indent).append("{\n");
        sb.append(indent).append("  \"name\": ").append(json(record.fixture().name())).append(",\n");
        sb.append(indent).append("  \"inputJar\": ").append(json(record.inputJar().toString())).append(",\n");
        sb.append(indent).append("  \"outputJar\": ").append(json(record.outputJar().toString())).append(",\n");
        sb.append(indent).append("  \"inputBytes\": ").append(Files.size(record.inputJar())).append(",\n");
        sb.append(indent).append("  \"outputBytes\": ").append(Files.size(record.outputJar())).append(",\n");
        sb.append(indent).append("  \"obfuscationMillis\": ")
            .append(record.obfuscation().duration().toMillis()).append(",\n");
        sb.append(indent).append("  \"obfuscationStdout\": ")
            .append(json(record.obfuscation().stdoutPath().toString())).append(",\n");
        sb.append(indent).append("  \"obfuscationStderr\": ")
            .append(json(record.obfuscation().stderrPath().toString())).append(",\n");
        appendTopology(sb, analyzeTopology(record.outputJar()), indent + "  ");
        sb.append(",\n");
        appendDryRunMetrics(sb, parseCffDryRunMetrics(record.obfuscation().combinedOutput()), indent + "  ");
        if (record.originalRun() != null) {
            sb.append(",\n");
            appendRun(sb, "originalRun", record.originalRun(), indent + "  ");
            sb.append(",\n");
            appendRun(sb, "fullObfRun", record.fullObfRun(), indent + "  ");
            sb.append('\n');
        } else {
            sb.append('\n');
        }
        sb.append(indent).append('}');
    }

    private static void appendAblationRecord(StringBuilder sb, AblationRecord record, String indent)
        throws Exception {
        long validRuns = record.runs().stream().filter(AblationRunRecord::valid).count();
        sb.append(indent).append("{\n");
        sb.append(indent).append("  \"fixture\": ").append(json(record.fixture().name())).append(",\n");
        sb.append(indent).append("  \"variant\": ").append(json(record.variant())).append(",\n");
        sb.append(indent).append("  \"inputJar\": ").append(json(record.inputJar().toString())).append(",\n");
        sb.append(indent).append("  \"artifactJar\": ").append(json(record.artifactJar().toString())).append(",\n");
        sb.append(indent).append("  \"config\": ");
        appendNullableJson(sb, record.configPath() == null ? null : record.configPath().toString());
        sb.append(",\n");
        sb.append(indent).append("  \"inputBytes\": ").append(Files.size(record.inputJar())).append(",\n");
        sb.append(indent).append("  \"artifactBytes\": ").append(Files.size(record.artifactJar())).append(",\n");
        sb.append(indent).append("  \"validRunCount\": ").append(validRuns).append(",\n");
        appendLongMap(sb, "validMedianMillis", record.validMedianMillis(), indent + "  ");
        sb.append(",\n");
        if (record.obfuscation() == null) {
            sb.append(indent).append("  \"obfuscation\": null,\n");
        } else {
            sb.append(indent).append("  \"obfuscation\": {\n");
            sb.append(indent).append("    \"durationMillis\": ")
                .append(record.obfuscation().duration().toMillis()).append(",\n");
            sb.append(indent).append("    \"stdout\": ")
                .append(json(record.obfuscation().stdoutPath().toString())).append(",\n");
            sb.append(indent).append("    \"stderr\": ")
                .append(json(record.obfuscation().stderrPath().toString())).append("\n");
            sb.append(indent).append("  },\n");
        }
        appendTopology(sb, record.topology(), indent + "  ");
        sb.append(",\n");
        sb.append(indent).append("  \"runs\": [\n");
        for (int i = 0; i < record.runs().size(); i++) {
            appendAblationRun(sb, record.runs().get(i), indent + "    ");
            if (i + 1 < record.runs().size()) sb.append(',');
            sb.append('\n');
        }
        sb.append(indent).append("  ]\n");
        sb.append(indent).append('}');
    }

    private static void appendAblationRun(StringBuilder sb, AblationRunRecord run, String indent) {
        sb.append(indent).append("{\n");
        sb.append(indent).append("  \"index\": ").append(run.index()).append(",\n");
        sb.append(indent).append("  \"valid\": ").append(run.valid()).append(",\n");
        sb.append(indent).append("  \"invalidReason\": ");
        appendNullableJson(sb, run.invalidReason());
        sb.append(",\n");
        sb.append(indent).append("  \"durationMillis\": ").append(run.result().duration().toMillis()).append(",\n");
        sb.append(indent).append("  \"exitCode\": ").append(run.result().exitCode()).append(",\n");
        sb.append(indent).append("  \"stdout\": ").append(json(run.result().stdoutPath().toString())).append(",\n");
        sb.append(indent).append("  \"stderr\": ").append(json(run.result().stderrPath().toString())).append(",\n");
        appendLongMap(sb, "timingMillis", run.timingMillis(), indent + "  ");
        sb.append(",\n");
        sb.append(indent).append("  \"timingLines\": [");
        for (int i = 0; i < run.timingLines().size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(json(run.timingLines().get(i)));
        }
        sb.append("]\n");
        sb.append(indent).append('}');
    }

    private static TopologyReport analyzeTopology(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        TopologyBuilder builder = new TopologyBuilder();
        for (var clazz : input.classMap().values()) {
            builder.classCount++;
            for (var method : clazz.asmNode().methods) {
                builder.methodCount++;
                builder.helperDescriptorCounts.merge(method.desc, 1, Integer::sum);
                if (method.instructions == null || method.instructions.size() == 0) continue;
                builder.methodsWithCode++;
                MethodMetrics metrics = methodMetrics(clazz.name(), method);
                builder.totalEstimatedMethodBytes += metrics.estimatedBytes();
                builder.totalInstructions += metrics.instructions();
                builder.totalInvokeDynamicInstructions += metrics.invokeDynamicInstructions();
                builder.totalStringTailCalls += metrics.stringTailCalls();
                builder.totalIndyFlowCalls += metrics.indyFlowCalls();
                builder.totalCffOutlinedDispatchCalls += metrics.cffOutlinedDispatchCalls();
                builder.totalCffSharedGroupDispatchCalls += metrics.cffSharedGroupDispatchCalls();
                builder.totalCffTransitionMaterialCalls += metrics.cffTransitionMaterialCalls();
                builder.totalCffStepMaterialCalls += metrics.cffStepMaterialCalls();
                builder.totalCffIslandMaterialCalls += metrics.cffIslandMaterialCalls();
                builder.topMethods.add(metrics);
            }
        }
        builder.topMethods.sort(
            Comparator.comparingInt(MethodMetrics::estimatedBytes)
                .reversed()
                .thenComparing(MethodMetrics::owner)
                .thenComparing(MethodMetrics::name)
                .thenComparing(MethodMetrics::desc)
        );
        List<MethodMetrics> topMethods = builder.topMethods.size() <= 20
            ? List.copyOf(builder.topMethods)
            : List.copyOf(builder.topMethods.subList(0, 20));
        return new TopologyReport(
            builder.classCount,
            builder.methodCount,
            builder.methodsWithCode,
            builder.totalEstimatedMethodBytes,
            builder.totalInstructions,
            builder.totalInvokeDynamicInstructions,
            builder.totalStringTailCalls,
            builder.totalIndyFlowCalls,
            builder.totalCffOutlinedDispatchCalls,
            builder.totalCffSharedGroupDispatchCalls,
            builder.totalCffTransitionMaterialCalls,
            builder.totalCffStepMaterialCalls,
            builder.totalCffIslandMaterialCalls,
            new LinkedHashMap<>(builder.helperDescriptorCounts),
            topMethods
        );
    }

    private static MethodMetrics methodMetrics(String owner, MethodNode method) {
        int instructions = 0;
        int jumps = 0;
        int switches = 0;
        int invokeDynamicInstructions = 0;
        int stringTailCalls = 0;
        int indyFlowCalls = 0;
        int cffOutlinedDispatchCalls = 0;
        int cffSharedGroupDispatchCalls = 0;
        int cffTransitionMaterialCalls = 0;
        int cffStepMaterialCalls = 0;
        int cffIslandMaterialCalls = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) instructions++;
            if (insn instanceof JumpInsnNode) jumps++;
            if (insn instanceof LookupSwitchInsnNode || insn instanceof TableSwitchInsnNode) switches++;
            if (insn instanceof InvokeDynamicInsnNode) invokeDynamicInstructions++;
            if (insn instanceof MethodInsnNode call) {
                if (STRING_TAIL_DESC.equals(call.desc)) stringTailCalls++;
                if (INDY_FLOW_DESC.equals(call.desc)) indyFlowCalls++;
                if (CFF_OUTLINED_DISPATCH_DESC.equals(call.desc)) cffOutlinedDispatchCalls++;
                if (CFF_SHARED_GROUP_DISPATCH_DESC.equals(call.desc)) cffSharedGroupDispatchCalls++;
                if (CFF_TRANSITION_MATERIAL_DESC.equals(call.desc)) cffTransitionMaterialCalls++;
                if (CFF_STEP_MATERIAL_DESC.equals(call.desc)) cffStepMaterialCalls++;
                if (CFF_ISLAND_MATERIAL_DESC.equals(call.desc)) cffIslandMaterialCalls++;
            }
        }
        return new MethodMetrics(
            owner,
            method.name,
            method.desc,
            JvmCodeSizeEstimator.estimateMethodBytes(method),
            instructions,
            jumps,
            switches,
            invokeDynamicInstructions,
            stringTailCalls,
            indyFlowCalls,
            cffOutlinedDispatchCalls,
            cffSharedGroupDispatchCalls,
            cffTransitionMaterialCalls,
            cffStepMaterialCalls,
            cffIslandMaterialCalls
        );
    }

    private static DryRunMetrics parseCffDryRunMetrics(String output) {
        DryRunBuilder builder = new DryRunBuilder();
        for (String line : output.lines().toList()) {
            if (!line.contains("CFF island") || !line.contains("dry-run:")) continue;
            builder.lines++;
            var matcher = DRY_RUN_METRIC_PATTERN.matcher(line);
            while (matcher.find()) {
                String key = matcher.group(1);
                long value = Long.parseLong(matcher.group(2));
                builder.sums.merge(key, value, Long::sum);
                builder.maxes.merge(key, value, Math::max);
            }
        }
        return new DryRunMetrics(builder.lines, new LinkedHashMap<>(builder.sums), new LinkedHashMap<>(builder.maxes));
    }

    private static void appendTopology(StringBuilder sb, TopologyReport report, String indent) {
        sb.append(indent).append("\"topology\": {\n");
        sb.append(indent).append("  \"classCount\": ").append(report.classCount()).append(",\n");
        sb.append(indent).append("  \"methodCount\": ").append(report.methodCount()).append(",\n");
        sb.append(indent).append("  \"methodsWithCode\": ").append(report.methodsWithCode()).append(",\n");
        sb.append(indent).append("  \"totalEstimatedMethodBytes\": ").append(report.totalEstimatedMethodBytes()).append(",\n");
        sb.append(indent).append("  \"totalInstructions\": ").append(report.totalInstructions()).append(",\n");
        sb.append(indent).append("  \"totalInvokeDynamicInstructions\": ").append(report.totalInvokeDynamicInstructions()).append(",\n");
        sb.append(indent).append("  \"totalStringTailCalls\": ").append(report.totalStringTailCalls()).append(",\n");
        sb.append(indent).append("  \"totalIndyFlowCalls\": ").append(report.totalIndyFlowCalls()).append(",\n");
        sb.append(indent).append("  \"totalCffOutlinedDispatchCalls\": ").append(report.totalCffOutlinedDispatchCalls()).append(",\n");
        sb.append(indent).append("  \"totalCffSharedGroupDispatchCalls\": ").append(report.totalCffSharedGroupDispatchCalls()).append(",\n");
        sb.append(indent).append("  \"totalCffTransitionMaterialCalls\": ").append(report.totalCffTransitionMaterialCalls()).append(",\n");
        sb.append(indent).append("  \"totalCffStepMaterialCalls\": ").append(report.totalCffStepMaterialCalls()).append(",\n");
        sb.append(indent).append("  \"totalCffIslandMaterialCalls\": ").append(report.totalCffIslandMaterialCalls()).append(",\n");
        appendIntMap(sb, "helperDescriptorCounts", report.helperDescriptorCounts(), indent + "  ");
        sb.append(",\n");
        sb.append(indent).append("  \"largestMethods\": [\n");
        for (int i = 0; i < report.largestMethods().size(); i++) {
            appendMethodMetrics(sb, report.largestMethods().get(i), indent + "    ");
            if (i + 1 < report.largestMethods().size()) sb.append(',');
            sb.append('\n');
        }
        sb.append(indent).append("  ]\n");
        sb.append(indent).append('}');
    }

    private static void appendMethodMetrics(StringBuilder sb, MethodMetrics metrics, String indent) {
        sb.append(indent).append("{\n");
        sb.append(indent).append("  \"owner\": ").append(json(metrics.owner())).append(",\n");
        sb.append(indent).append("  \"name\": ").append(json(metrics.name())).append(",\n");
        sb.append(indent).append("  \"desc\": ").append(json(metrics.desc())).append(",\n");
        sb.append(indent).append("  \"estimatedBytes\": ").append(metrics.estimatedBytes()).append(",\n");
        sb.append(indent).append("  \"instructions\": ").append(metrics.instructions()).append(",\n");
        sb.append(indent).append("  \"jumps\": ").append(metrics.jumps()).append(",\n");
        sb.append(indent).append("  \"switches\": ").append(metrics.switches()).append(",\n");
        sb.append(indent).append("  \"invokeDynamicInstructions\": ").append(metrics.invokeDynamicInstructions()).append(",\n");
        sb.append(indent).append("  \"stringTailCalls\": ").append(metrics.stringTailCalls()).append(",\n");
        sb.append(indent).append("  \"indyFlowCalls\": ").append(metrics.indyFlowCalls()).append(",\n");
        sb.append(indent).append("  \"cffOutlinedDispatchCalls\": ").append(metrics.cffOutlinedDispatchCalls()).append(",\n");
        sb.append(indent).append("  \"cffSharedGroupDispatchCalls\": ").append(metrics.cffSharedGroupDispatchCalls()).append(",\n");
        sb.append(indent).append("  \"cffTransitionMaterialCalls\": ").append(metrics.cffTransitionMaterialCalls()).append(",\n");
        sb.append(indent).append("  \"cffStepMaterialCalls\": ").append(metrics.cffStepMaterialCalls()).append(",\n");
        sb.append(indent).append("  \"cffIslandMaterialCalls\": ").append(metrics.cffIslandMaterialCalls()).append('\n');
        sb.append(indent).append('}');
    }

    private static void appendDryRunMetrics(StringBuilder sb, DryRunMetrics metrics, String indent) {
        sb.append(indent).append("\"cffDryRunMetrics\": {\n");
        sb.append(indent).append("  \"lineCount\": ").append(metrics.lineCount()).append(",\n");
        appendLongMap(sb, "sums", metrics.sums(), indent + "  ");
        sb.append(",\n");
        appendLongMap(sb, "maxes", metrics.maxes(), indent + "  ");
        sb.append('\n');
        sb.append(indent).append('}');
    }

    private static void appendIntMap(StringBuilder sb, String name, Map<String, Integer> values, String indent) {
        sb.append(indent).append(json(name)).append(": {\n");
        int index = 0;
        for (Map.Entry<String, Integer> entry : values.entrySet()) {
            sb.append(indent).append("  ").append(json(entry.getKey())).append(": ").append(entry.getValue());
            if (++index < values.size()) sb.append(',');
            sb.append('\n');
        }
        sb.append(indent).append('}');
    }

    private static void appendLongMap(StringBuilder sb, String name, Map<String, Long> values, String indent) {
        sb.append(indent).append(json(name)).append(": {\n");
        int index = 0;
        for (Map.Entry<String, Long> entry : values.entrySet()) {
            sb.append(indent).append("  ").append(json(entry.getKey())).append(": ").append(entry.getValue());
            if (++index < values.size()) sb.append(',');
            sb.append('\n');
        }
        sb.append(indent).append('}');
    }

    private static void appendRun(StringBuilder sb, String name, RunRecord run, String indent) {
        sb.append(indent).append(json(name)).append(": {\n");
        sb.append(indent).append("  \"durationMillis\": ").append(run.result().duration().toMillis()).append(",\n");
        sb.append(indent).append("  \"exitCode\": ").append(run.result().exitCode()).append(",\n");
        sb.append(indent).append("  \"stdout\": ").append(json(run.result().stdoutPath().toString())).append(",\n");
        sb.append(indent).append("  \"stderr\": ").append(json(run.result().stderrPath().toString())).append(",\n");
        sb.append(indent).append("  \"calcMillis\": ")
            .append(run.calcMillis() == null ? "null" : run.calcMillis()).append(",\n");
        sb.append(indent).append("  \"timingLines\": [");
        for (int i = 0; i < run.timingLines().size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(json(run.timingLines().get(i)));
        }
        sb.append("]\n");
        sb.append(indent).append('}');
    }

    private static void appendNullableJson(StringBuilder sb, String value) {
        if (value == null) {
            sb.append("null");
        } else {
            sb.append(json(value));
        }
    }

    private static String json(String value) {
        Objects.requireNonNull(value, "value");
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private enum BehaviorMode {
        TEST_PERF,
        OBFUSJACK_PERF,
        HEADLESS_GUI,
        EVALUATOR
    }

    private record Fixture(
        String name,
        String jarName,
        BehaviorMode behaviorMode
    ) {
        List<String> jvmArgs() {
            List<String> args = new ArrayList<>();
            args.add("-XX:-UsePerfData");
            if (behaviorMode == BehaviorMode.HEADLESS_GUI) {
                args.add("-Djava.awt.headless=true");
            }
            return args;
        }
        boolean strictStructuralAudit() {
            return behaviorMode == BehaviorMode.TEST_PERF || behaviorMode == BehaviorMode.OBFUSJACK_PERF;
        }
    }

    private record RunRecord(
        NativeObfuscationHelper.JarRunResult result,
        Long calcMillis,
        List<String> timingLines
    ) {}

    private record PerfRecord(
        Fixture fixture,
        Path inputJar,
        Path outputJar,
        NativeObfuscationHelper.ObfuscationRunResult obfuscation,
        RunRecord originalRun,
        RunRecord fullObfRun
    ) {}

    private record AblationVariant(
        String name,
        String configText,
        Path existingConfig
    ) {
        boolean obfuscates() {
            return configText != null || existingConfig != null;
        }
    }

    private record AblationRunRecord(
        int index,
        NativeObfuscationHelper.JarRunResult result,
        boolean valid,
        String invalidReason,
        Map<String, Long> timingMillis,
        List<String> timingLines
    ) {}

    private record AblationRecord(
        Fixture fixture,
        String variant,
        Path inputJar,
        Path artifactJar,
        Path configPath,
        NativeObfuscationHelper.ObfuscationRunResult obfuscation,
        TopologyReport topology,
        List<AblationRunRecord> runs,
        Map<String, Long> validMedianMillis
    ) {}

    private record RunValidity(
        boolean valid,
        String reason
    ) {}

    private static final class TopologyBuilder {
        int classCount;
        int methodCount;
        int methodsWithCode;
        long totalEstimatedMethodBytes;
        long totalInstructions;
        long totalInvokeDynamicInstructions;
        long totalStringTailCalls;
        long totalIndyFlowCalls;
        long totalCffOutlinedDispatchCalls;
        long totalCffSharedGroupDispatchCalls;
        long totalCffTransitionMaterialCalls;
        long totalCffStepMaterialCalls;
        long totalCffIslandMaterialCalls;
        final Map<String, Integer> helperDescriptorCounts = new LinkedHashMap<>();
        final List<MethodMetrics> topMethods = new ArrayList<>();
    }

    private static final class DryRunBuilder {
        long lines;
        final Map<String, Long> sums = new LinkedHashMap<>();
        final Map<String, Long> maxes = new LinkedHashMap<>();
    }

    private record TopologyReport(
        int classCount,
        int methodCount,
        int methodsWithCode,
        long totalEstimatedMethodBytes,
        long totalInstructions,
        long totalInvokeDynamicInstructions,
        long totalStringTailCalls,
        long totalIndyFlowCalls,
        long totalCffOutlinedDispatchCalls,
        long totalCffSharedGroupDispatchCalls,
        long totalCffTransitionMaterialCalls,
        long totalCffStepMaterialCalls,
        long totalCffIslandMaterialCalls,
        Map<String, Integer> helperDescriptorCounts,
        List<MethodMetrics> largestMethods
    ) {}

    private record MethodMetrics(
        String owner,
        String name,
        String desc,
        int estimatedBytes,
        int instructions,
        int jumps,
        int switches,
        int invokeDynamicInstructions,
        int stringTailCalls,
        int indyFlowCalls,
        int cffOutlinedDispatchCalls,
        int cffSharedGroupDispatchCalls,
        int cffTransitionMaterialCalls,
        int cffStepMaterialCalls,
        int cffIslandMaterialCalls
    ) {}

    private record DryRunMetrics(
        long lineCount,
        Map<String, Long> sums,
        Map<String, Long> maxes
    ) {}
}
