package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import dev.nekoobfuscator.transforms.jvm.internal.JvmCodeSizeEstimator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ControlFlowFlatteningAlgebraicAuditTest {
    private static final String VALIDATION_HELPER_DESC = "(Ljava/lang/String;JI)J";
    private static final String OLD_VALIDATION_HELPER_DESC = "(Ljava/lang/String;JJII)Z";
    private static final String VALIDATION_LENGTH_STAGE_DESC = "(Ljava/lang/String;I)I";
    private static final String VALIDATION_SEED_STAGE_DESC = "(JII)J";
    private static final String VALIDATION_CHAR_STAGE_DESC = "(Ljava/lang/String;JIII)J";
    private static final String VALIDATION_FINAL_STAGE_DESC = "(JJI)Z";
    private static final String VALIDATION_FINAL_STAGE_INDY_DESC = "(JJIJJ)Z";
    private static final String VALIDATION_PRIMITIVE_ENTRY_DESC = "(IIJ)I";
    private static final String VALIDATION_PRIMITIVE_ENTRY_INDY_DESC = "(IIJJJ)I";
    private static final String VALIDATION_PRIMITIVE_VALUE_STAGE_DESC = "(IIJ)J";
    private static final String VALIDATION_PRIMITIVE_GUARD_STAGE_DESC = "(J)J";
    private static final String VALIDATION_PRIMITIVE_DATA_STAGE_DESC = "(J)I";
    private static final String VALIDATION_PRIMITIVE_FINAL_STAGE_DESC = "(JJ)I";
    private static final String CLASS_INTEGRITY_HELPER_DESC =
        "(IJJLjava/lang/Class;JJ)J";
    private static final String CLASS_INTEGRITY_TICKET_ISSUE_HELPER_DESC =
        "(IJJ[Ljava/lang/Object;)J";
    private static final String CLASS_INTEGRITY_TICKET_MODE_HELPER_DESC =
        "(JJ[Ljava/lang/Object;)J";
    private static final String CFF_SIDECAR_HELPER_DESC =
        "([Ljava/lang/Object;IIIIIIIII)I";
    private static final String CFF_TOKEN_MATERIAL_HELPER_DESC =
        "([Ljava/lang/Object;IIII)I";
    private static final String CFF_TOKEN_MATERIAL_OBJECT_HELPER_DESC =
        "([Ljava/lang/Object;[JIIII)I";
    private static final String CFF_LEGACY_INT_TOKEN_HELPER_DESC =
        "([I[Ljava/lang/Object;IIIIIIIIIIIIIIII)I";
    private static final String CFF_DISPATCH_HELPER_DESC = "(JIIIIII[J)J";
    private static final String CFF_COMPACT_DISPATCH_HELPER_DESC = "(JIIIIII[I)J";

    @Test
    void symbolicAuditRecognizesSelfCancelingAndLinearKeyShapes() {
        MethodNode method = syntheticLeakingMethod();
        List<Finding> findings = AlgebraicAudit.audit("Synthetic", method);

        assertTrue(
            findings.stream().anyMatch(f -> f.kind() == FindingKind.XOR_SELF_CANCELLATION),
            () -> "expected xor self-cancellation finding, got " + findings
        );
        assertTrue(
            findings.stream().anyMatch(f -> f.kind() == FindingKind.LINEAR_KEY_OVERWRITE),
            () -> "expected linear key overwrite finding, got " + findings
        );
    }

    @Test
    void cffOutputDoesNotExposeLinearOrSelfCancelingDispatcherAlgebra()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-audit"));
        Path source = work.resolve("CffAuditShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("cff-audit-shapes.jar");
        writeJar(inputJar, classes, "CffAuditShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("cff-audit-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);
        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("CFF AUDIT OK"), obfuscated);
        Path tamperedJar = work.resolve("cff-audit-shapes-obf-tampered.jar");
        tamperMainMethodCode(outputJar, tamperedJar);
        assertTamperedJarPoisonsProtectedFlow(tamperedJar);
        assertClassIntegrityCodeRootPoisonsWithoutStandaloneVerifier(outputJar);
        assertClassIntegrityTicketUsesDedicatedHelper(outputJar);
        assertGeneratedCffPoisonDoesNotThrow(outputJar);
        assertRuntimeTokenDecodingUsesClassKeyTables(outputJar);
        assertStepMaterialHelperUsesLiveKeyTableDispatch(outputJar);
        assertCffDataDigestInitializedFromEntryData(outputJar);
        assertCffDataDigestUpdatedFromPrimitiveFlow(outputJar);
        assertCffDispatchConsumesDataDigest(outputJar);

        List<Finding> findings = auditJar(outputJar);
        assertFalse(
            findings.isEmpty(),
            "audit fixture did not exercise CFF integer dispatcher/key algebra"
        );
        List<Finding> rejected = findings
            .stream()
            .filter(Finding::rejectsVariant)
            .toList();
        assertTrue(
            rejected.isEmpty(),
            () -> "CFF emitted algebraically collapsible dispatcher/key shapes:\n" +
                summarize(rejected)
        );
    }

    @Test
    void packedObjectArrayMethodTamperFailsClassCodeIntegrity()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-packed-integrity"));
        Path source = work.resolve("CffAuditShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("cff-audit-shapes.jar");
        writeJar(inputJar, classes, "CffAuditShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("cff-audit-shapes-obf.jar");
        runPackedObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);
        assertEquals(original, obfuscated);

        Path tamperedJar = work.resolve("cff-audit-shapes-obf-packed-tampered.jar");
        tamperFirstPackedApplicationMethod(outputJar, tamperedJar);
        assertTamperedJarPoisonsProtectedFlow(tamperedJar);
        assertGeneratedCffPoisonDoesNotThrow(outputJar);
    }

    @Test
    void directStaticProtectedMethodPatchFailsClassCodeIntegrity()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-direct-integrity"));
        Path source = work.resolve("CffAuditShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("cff-audit-shapes.jar");
        writeJar(inputJar, classes, "CffAuditShapes");

        Path outputJar = work.resolve("cff-audit-shapes-obf.jar");
        runPackedObfuscation(inputJar, outputJar);
        assertTrue(runJar(outputJar).contains("CFF AUDIT OK"));

        Path tamperedJar = work.resolve("cff-audit-shapes-obf-direct-tampered.jar");
        tamperFirstStaticBooleanApplicationMethod(outputJar, tamperedJar);
        assertTamperedJarPoisonsProtectedFlow(tamperedJar);
        assertGeneratedCffPoisonDoesNotThrow(outputJar);
    }

    @Test
    void cyclicPrimitiveDigestSelectionKeepsLiveFlowWithoutRepeatedFloatingHash()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-loop-digest"));
        Path source = work.resolve("CffLoopDigestShape.java");
        Files.writeString(source, loopDigestSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("cff-loop-digest-shape.jar");
        writeJar(inputJar, classes, "CffLoopDigestShape");
        assertTrue(runJar(inputJar).contains("CFF LOOP DIGEST OK"));

        Path outputJar = work.resolve("cff-loop-digest-shape-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);
        assertTrue(obfuscated.contains("CFF LOOP DIGEST OK"), obfuscated);

        MethodNode value = method(outputJar, "CffLoopDigestShape", "value");
        assertCffDataDigestUpdatedFromLivePrimitiveLocal(value);
        assertTrue(
            doubleHashCalls(value) <= 1,
            "cyclic CFF primitive digest selected repeated floating stack hashes in loop-shaped method"
        );
    }

    @Test
    void cyclicLoopNearJitBudgetUsesOutlinedTransitions()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-cyclic-jit-budget"));
        Path source = work.resolve("CffCyclicJitBudgetShape.java");
        Files.writeString(source, cyclicJitBudgetSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("cff-cyclic-jit-budget.jar");
        writeJar(inputJar, classes, "CffCyclicJitBudgetShape");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("cff-cyclic-jit-budget-obf.jar");
        runCffOnlyObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);
        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("CFF CYCLIC JIT OK"), obfuscated);

        MethodNode hot = method(outputJar, "CffCyclicJitBudgetShape", "hot");
        int transformedBytes = JvmCodeSizeEstimator.estimateMethodBytes(hot);
        assertTrue(
            transformedBytes < 8_000,
            "cyclic CFF hot method exceeds HotSpot huge-method budget: " + transformedBytes
        );
        assertTrue(
            callsCffOutlinerHelper(hot),
            "cyclic CFF hot method did not use the outlined live-keyed helper path"
        );
    }

    @Test
    void wrongClassIntegrityLoadOrderPoisonsKeyTable()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-order-poison"));
        Path source = work.resolve("CffAuditShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("cff-audit-shapes.jar");
        writeJar(inputJar, classes, "CffAuditShapes");

        Path outputJar = work.resolve("cff-audit-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        assertTrue(runJar(outputJar).contains("CFF AUDIT OK"));
        assertGeneratedCffPoisonDoesNotThrow(outputJar);

        assertWrongPreloadPoisonsMain(outputJar, "CffAuditPeerB", "CffAuditShapes");
    }

    @Test
    void cffClassIntegrityRootSurvivesZgcReferenceLayout()
        throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
            jvmAccepts(List.of("-XX:+UseZGC")),
            "ZGC is not available on this JVM"
        );
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-zgc-layout"));
        Path source = work.resolve("ZgcCffProbe.java");
        Files.writeString(source, zgcCffProbeSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("zgc-cff-probe.jar");
        writeJar(inputJar, classes, "ZgcCffProbe");

        Path outputJar = work.resolve("zgc-cff-probe-obf.jar");
        runCffOnlyObfuscation(inputJar, outputJar);
        List<String> args = List.of("--probe", "ZGC");
        assertTrue(
            runJar(outputJar, List.of("-XX:+UseG1GC"), args).contains("ZGC CFF OK ZGC"),
            "G1 reference layout did not reach the protected probe"
        );
        assertTrue(
            runJar(outputJar, List.of("-XX:+UseZGC"), args).contains("ZGC CFF OK ZGC"),
            "ZGC reference layout did not reach the protected probe"
        );
    }

    @Test
    void validationSinkHardeningRemovesPlainStringEqualsTarget()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-validation-sink"));
        Path source = work.resolve("ValidationSinkShape.java");
        Files.writeString(source, validationSinkSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("validation-sink-shape.jar");
        writeJar(inputJar, classes, "ValidationSinkShape");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("validation-sink-shape-obf.jar");
        runValidationSinkObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("VALIDATION SINK OK"), obfuscated);
        assertValidationSinkUsesKeyedTag(outputJar);
    }

    private static MethodNode syntheticLeakingMethod() {
        MethodNode method = new MethodNode(
            Opcodes.ACC_STATIC,
            "synthetic",
            "()I",
            null,
            null
        );
        InsnList insns = method.instructions;
        LabelNode ok = new LabelNode();
        LabelNode poison = new LabelNode();

        insns.add(new VarInsnNode(Opcodes.ILOAD, 8));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 9));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new LdcInsnNode(0x11223344));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 10));

        insns.add(new VarInsnNode(Opcodes.ILOAD, 10));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 9));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new LdcInsnNode(0x55667788));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 8));

        insns.add(new VarInsnNode(Opcodes.ILOAD, 8));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 9));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new LdcInsnNode(0x36FD211E));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new VarInsnNode(Opcodes.ISTORE, 11));

        insns.add(new VarInsnNode(Opcodes.ILOAD, 11));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 8));
        insns.add(new VarInsnNode(Opcodes.ILOAD, 9));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new LdcInsnNode(0x36FD211E));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new InsnNode(Opcodes.IXOR));
        insns.add(new LookupSwitchInsnNode(poison, new int[] {0}, new LabelNode[] {ok}));
        insns.add(ok);
        insns.add(new InsnNode(Opcodes.ICONST_1));
        insns.add(new InsnNode(Opcodes.IRETURN));
        insns.add(poison);
        insns.add(new InsnNode(Opcodes.ICONST_M1));
        insns.add(new InsnNode(Opcodes.IRETURN));

        method.maxLocals = 12;
        method.maxStack = 4;
        return method;
    }

    private static List<Finding> auditJar(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        List<Finding> findings = new ArrayList<>();
        for (var clazz : input.classes()) {
            ClassNode node = clazz.asmNode();
            for (var method : node.methods) {
                findings.addAll(AlgebraicAudit.audit(node.name, method));
            }
        }
        return findings;
    }

    private static void tamperMainMethodCode(Path inputJar, Path outputJar)
        throws Exception {
        boolean[] tampered = { false };
        try (JarFile jar = new JarFile(inputJar.toFile());
             JarOutputStream jos = new JarOutputStream(new FileOutputStream(outputJar.toFile()))) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                byte[] data;
                try (var in = jar.getInputStream(entry)) {
                    data = in.readAllBytes();
                }
                if (!tampered[0] && entry.getName().endsWith(".class")) {
                    ClassReader reader = new ClassReader(data);
                    ClassNode node = new ClassNode();
                    reader.accept(node, ClassReader.EXPAND_FRAMES);
                    MethodNode target = null;
                    for (MethodNode method : node.methods) {
                        if ("main".equals(method.name)
                            && method.instructions != null
                            && method.instructions.size() > 0) {
                            target = method;
                            break;
                        }
                    }
                    if (target != null) {
                        target.instructions.insert(new InsnNode(Opcodes.NOP));
                        ClassWriter writer = new ClassWriter(0);
                        node.accept(writer);
                        data = writer.toByteArray();
                        tampered[0] = true;
                    }
                }
                JarEntry out = new JarEntry(entry.getName());
                jos.putNextEntry(out);
                jos.write(data);
                jos.closeEntry();
            }
        }
        assertTrue(tampered[0], "tamper fixture did not find a main method");
    }

    private static void tamperFirstPackedApplicationMethod(Path inputJar, Path outputJar)
        throws Exception {
        boolean[] tampered = { false };
        try (JarFile jar = new JarFile(inputJar.toFile());
             JarOutputStream jos = new JarOutputStream(new FileOutputStream(outputJar.toFile()))) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                byte[] data;
                try (var in = jar.getInputStream(entry)) {
                    data = in.readAllBytes();
                }
                if (!tampered[0] && entry.getName().endsWith(".class")) {
                    ClassReader reader = new ClassReader(data);
                    ClassNode node = new ClassNode();
                    reader.accept(node, ClassReader.EXPAND_FRAMES);
                    MethodNode target = null;
                    for (MethodNode method : node.methods) {
                        if (method.name.startsWith("__neko_")) continue;
                        if (!method.desc.startsWith("([Ljava/lang/Object;)")) continue;
                        if (method.instructions == null || method.instructions.size() == 0) continue;
                        target = method;
                        break;
                    }
                    if (target != null) {
                        target.instructions.insert(new InsnNode(Opcodes.NOP));
                        ClassWriter writer = new ClassWriter(0);
                        node.accept(writer);
                        data = writer.toByteArray();
                        tampered[0] = true;
                    }
                }
                JarEntry out = new JarEntry(entry.getName());
                jos.putNextEntry(out);
                jos.write(data);
                jos.closeEntry();
            }
        }
        assertTrue(tampered[0], "tamper fixture did not find a packed Object[] application method");
    }

    private static void tamperFirstStaticBooleanApplicationMethod(Path inputJar, Path outputJar)
        throws Exception {
        boolean[] tampered = { false };
        try (JarFile jar = new JarFile(inputJar.toFile());
             JarOutputStream jos = new JarOutputStream(new FileOutputStream(outputJar.toFile()))) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                jos.putNextEntry(new JarEntry(entry.getName()));
                byte[] bytes = jar.getInputStream(entry).readAllBytes();
                if (!tampered[0] && entry.getName().endsWith(".class")) {
                    ClassNode node = new ClassNode();
                    new ClassReader(bytes).accept(node, 0);
                    for (MethodNode method : node.methods) {
                        if ((method.access & Opcodes.ACC_STATIC) == 0) continue;
                        if (!method.desc.endsWith(")Z")) continue;
                        if ("main".equals(method.name) || "<clinit>".equals(method.name)) continue;
                        if (method.name.startsWith("__neko_")) continue;
                        if (method.instructions == null || method.instructions.size() == 0) continue;
                        method.instructions.clear();
                        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
                        method.instructions.add(new InsnNode(Opcodes.IRETURN));
                        method.tryCatchBlocks.clear();
                        method.localVariables = null;
                        method.maxStack = Math.max(method.maxStack, 1);
                        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
                        node.accept(writer);
                        bytes = writer.toByteArray();
                        tampered[0] = true;
                        break;
                    }
                }
                jos.write(bytes);
                jos.closeEntry();
            }
        }
        assertTrue(tampered[0], "tamper fixture did not find a static boolean application method");
    }

    private static void assertTamperedJarPoisonsProtectedFlow(Path jar) throws Exception {
        Process process = new ProcessBuilder(
            "java",
            "-XX:-UsePerfData",
            "-jar",
            jar.toString()
        ).redirectErrorStream(true).start();
        boolean exited = process.waitFor(30, TimeUnit.SECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(exited, "tampered command timed out");
        assertTrue(
            process.exitValue() != 0 || !output.contains("CFF AUDIT OK"),
            "tampered jar unexpectedly preserved the protected result:\n" + output
        );
    }

    private static void assertClassIntegrityCodeRootPoisonsWithoutStandaloneVerifier(Path jar)
        throws Exception {
        JarInput input = new JarInput(jar);
        boolean sawClassIntegrityRootHelper = false;
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                assertFalse(
                    isStandaloneClassCodeVerifier(method),
                    "class-code integrity must be rooted in the class-integrity helper, not a standalone verifier"
                );
                if (!isClassIntegrityCodeRootHelper(method)) continue;
                sawClassIntegrityRootHelper = true;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    assertTrue(
                        insn.getOpcode() != Opcodes.ATHROW,
                        "class-integrity class-code root must poison key material instead of throwing"
                    );
                    if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.NEW) {
                        assertTrue(
                            !"java/lang/IllegalStateException".equals(type.desc),
                            "class-integrity class-code root must not construct a manual mismatch exception"
                        );
                    }
                }
            }
        }
        assertTrue(sawClassIntegrityRootHelper, "class-integrity class-code root helper was not generated");
    }

    private static void assertClassIntegrityTicketUsesDedicatedHelper(Path jar)
        throws Exception {
        JarInput input = new JarInput(jar);
        Set<String> rootHelpers = new LinkedHashSet<>();
        Set<String> ticketEntryHelpers = new LinkedHashSet<>();
        Set<String> ticketStateHelpers = new LinkedHashSet<>();
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                String ref = methodRef(clazz.name(), method);
                if (method.instructions == null) continue;
                if (CLASS_INTEGRITY_HELPER_DESC.equals(method.desc)
                    && methodContainsClassResourceRead(method)) {
                    rootHelpers.add(ref);
                    continue;
                }
                if ((CLASS_INTEGRITY_TICKET_ISSUE_HELPER_DESC.equals(method.desc)
                    || CLASS_INTEGRITY_TICKET_MODE_HELPER_DESC.equals(method.desc))
                    && methodContainsTicketState(method)) {
                    ticketStateHelpers.add(ref);
                }
            }
        }
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (!CLASS_INTEGRITY_HELPER_DESC.equals(method.desc)
                    || method.instructions == null
                    || methodContainsClassResourceRead(method)) {
                    continue;
                }
                if (methodCallsAny(method, ticketStateHelpers)) {
                    ticketEntryHelpers.add(methodRef(clazz.name(), method));
                }
            }
        }
        assertFalse(rootHelpers.isEmpty(), "class-integrity root helper was not generated");
        assertFalse(ticketEntryHelpers.isEmpty(), "dedicated class-integrity ticket entry helper was not generated");
        assertFalse(ticketStateHelpers.isEmpty(), "split class-integrity ticket state helpers were not generated");

        boolean sawTicketCall = false;
        boolean sawRootInitCall = false;
        boolean sawTicketStateCall = false;
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                String caller = methodRef(clazz.name(), method);
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode call)) continue;
                    String callee = methodRef(call.owner, call.name, call.desc);
                    if (ticketStateHelpers.contains(callee)) {
                        assertTrue(
                            ticketEntryHelpers.contains(caller),
                            "non-entry method calls split class-integrity ticket state helper directly: " +
                                caller + " -> " + callee
                        );
                        sawTicketStateCall = true;
                    }
                    if (!CLASS_INTEGRITY_HELPER_DESC.equals(call.desc)) continue;
                    if (ticketEntryHelpers.contains(callee)) {
                        sawTicketCall = true;
                    }
                    if (!rootHelpers.contains(callee)) {
                        continue;
                    }
                    if ("<clinit>".equals(method.name)) {
                        sawRootInitCall = true;
                        continue;
                    }
                    assertTrue(
                        ticketEntryHelpers.contains(caller),
                        "non-ticket method calls class-integrity root helper directly: " +
                            caller + " -> " + callee
                    );
                }
            }
        }
        assertTrue(sawTicketCall, "ticket issue/consume callsites did not use the dedicated helper");
        assertTrue(sawTicketStateCall, "ticket entry helper did not route through split state helpers");
        assertTrue(sawRootInitCall, "class-root initialization did not use the root helper");
    }

    private static void assertGeneratedCffPoisonDoesNotThrow(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                boolean constructsIllegalState = false;
                boolean throwsValue = false;
                for (
                    AbstractInsnNode insn = method.instructions.getFirst();
                    insn != null;
                    insn = insn.getNext()
                ) {
                    if (insn instanceof TypeInsnNode type
                        && type.getOpcode() == Opcodes.NEW
                        && "java/lang/IllegalStateException".equals(type.desc)) {
                        constructsIllegalState = true;
                    }
                    if (insn.getOpcode() == Opcodes.ATHROW) {
                        throwsValue = true;
                    }
                }
                assertFalse(
                    constructsIllegalState && throwsValue,
                    "generated CFF output must divert poison flow instead of throwing IllegalStateException in "
                        + clazz.name() + "." + method.name + method.desc
                );
            }
        }
    }

    private static boolean isStandaloneClassCodeVerifier(MethodNode method) {
        if (!"(Ljava/lang/Class;JJ)J".equals(method.desc) || method.instructions == null) return false;
        return methodContainsClassResourceRead(method);
    }

    private static boolean isClassIntegrityCodeRootHelper(MethodNode method) {
        if (!CLASS_INTEGRITY_HELPER_DESC.equals(method.desc) || method.instructions == null) return false;
        return methodContainsClassResourceRead(method);
    }

    private static boolean methodContainsTicketState(MethodNode method) {
        boolean sawThreadLocal = false;
        boolean sawGlobalTicketMap = false;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof MethodInsnNode call)) continue;
            if ("java/lang/ThreadLocal".equals(call.owner)
                && ("get".equals(call.name) || "set".equals(call.name))) {
                sawThreadLocal = true;
            }
            if ("java/util/concurrent/ConcurrentHashMap".equals(call.owner)
                && ("put".equals(call.name) ||
                    "containsKey".equals(call.name) ||
                    "remove".equals(call.name))) {
                sawGlobalTicketMap = true;
            }
        }
        return sawThreadLocal && sawGlobalTicketMap;
    }

    private static boolean methodCallsAny(MethodNode method, Set<String> callees) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof MethodInsnNode call)) continue;
            if (callees.contains(methodRef(call.owner, call.name, call.desc))) {
                return true;
            }
        }
        return false;
    }

    private static String methodRef(String owner, MethodNode method) {
        return methodRef(owner, method.name, method.desc);
    }

    private static String methodRef(String owner, String name, String desc) {
        return owner + "." + name + desc;
    }

    private static boolean methodContainsClassResourceRead(MethodNode method) {
        boolean sawClassResource = false;
        boolean sawReadAllBytes = false;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                && "java/lang/Class".equals(call.owner)
                && "getResourceAsStream".equals(call.name)
                && "(Ljava/lang/String;)Ljava/io/InputStream;".equals(call.desc)) {
                sawClassResource = true;
            }
            if (insn instanceof MethodInsnNode call
                && "java/io/InputStream".equals(call.owner)
                && "readAllBytes".equals(call.name)
                && "()[B".equals(call.desc)) {
                sawReadAllBytes = true;
            }
        }
        return sawClassResource && sawReadAllBytes;
    }

    private static void assertWrongPreloadPoisonsMain(Path jar, String preloadClass, String mainClass)
        throws Exception {
        try (URLClassLoader loader = new URLClassLoader(
            new URL[] { jar.toUri().toURL() },
            ClassLoader.getPlatformClassLoader()
        )) {
            Class.forName(preloadClass, true, loader);
            Class<?> main = Class.forName(mainClass, true, loader);
            Method entry = main.getMethod("main", String[].class);
            PrintStream originalOut = System.out;
            ByteArrayOutputStream captured = new ByteArrayOutputStream();
            Throwable failure = null;
            try {
                System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
                entry.invoke(null, (Object) new String[0]);
            } catch (Throwable thrown) {
                failure = thrown;
            } finally {
                System.setOut(originalOut);
            }
            String output = captured.toString(StandardCharsets.UTF_8);
            assertTrue(
                failure != null || !output.contains("CFF AUDIT OK"),
                "wrong class-load order unexpectedly preserved the protected result:\n" + output
            );
        }
    }

    private static void assertRuntimeTokenDecodingUsesClassKeyTables(Path jar)
        throws Exception {
        JarInput input = new JarInput(jar);
        boolean sawIntTableField = false;
        boolean sawObjectSidecarField = false;
        boolean sawRuntimeIntTableLoad = false;
        boolean sawRuntimeSidecarHelperCall = false;
        boolean sawSidecarHelperUpdate = false;
        for (var clazz : input.classes()) {
            for (var field : clazz.asmNode().fields) {
                if ("[I".equals(field.desc)) {
                    sawIntTableField = true;
                }
                if ("[Ljava/lang/Object;".equals(field.desc)) {
                    sawObjectSidecarField = true;
                }
            }
            for (var method : clazz.asmNode().methods) {
                if (method.instructions == null || "<clinit>".equals(method.name)) {
                    continue;
                }
                for (
                    AbstractInsnNode insn = method.instructions.getFirst();
                    insn != null;
                    insn = insn.getNext()
                ) {
                    if (insn instanceof FieldInsnNode field
                        && field.getOpcode() == Opcodes.GETSTATIC
                        && "[I".equals(field.desc)
                        && (hasNearbyIntArrayLoad(field) || hasNearbyEncryptedTokenHelperCall(field))) {
                            sawRuntimeIntTableLoad = true;
                    }
                    if (insn instanceof TypeInsnNode type
                        && type.getOpcode() == Opcodes.CHECKCAST
                        && "[I".equals(type.desc)) {
                        sawRuntimeIntTableLoad = true;
                    }
                    if (insn instanceof MethodInsnNode call
                        && call.getOpcode() == Opcodes.INVOKESTATIC
                        && call.owner.equals(clazz.asmNode().name)
                        && (CFF_SIDECAR_HELPER_DESC.equals(call.desc)
                            || CFF_TOKEN_MATERIAL_OBJECT_HELPER_DESC.equals(call.desc))) {
                        sawRuntimeSidecarHelperCall = true;
                    }
                    if (insn instanceof MethodInsnNode call
                        && call.getOpcode() == Opcodes.INVOKESTATIC
                        && call.owner.equals(clazz.asmNode().name)
                        && CFF_LEGACY_INT_TOKEN_HELPER_DESC.equals(call.desc)) {
                        sawRuntimeIntTableLoad = true;
                    }
                }
                if (updatesSidecarCell(method)) {
                    sawSidecarHelperUpdate = true;
                }
            }
        }
        assertFalse(sawIntTableField, "CFF class key int[] table should be coalesced into the Object[] sidecar");
        assertTrue(sawObjectSidecarField, "CFF class should register an Object[] sidecar key table");
        assertTrue(sawRuntimeIntTableLoad, "CFF runtime token decode did not use the int[] class key table");
        assertTrue(
            sawRuntimeSidecarHelperCall || sawSidecarHelperUpdate,
            "CFF runtime token decode did not use the Object[] sidecar path"
        );
        assertTrue(sawSidecarHelperUpdate, "CFF sidecar helper did not update the Object[] sidecar key cell");
    }

    private static void assertStepMaterialHelperUsesLiveKeyTableDispatch(Path jar)
        throws Exception {
        assertStepMaterialHelperUsesRuntimeSources(jar);
        try (URLClassLoader loader = new URLClassLoader(
            new URL[] {jar.toUri().toURL()},
            ClassLoader.getPlatformClassLoader()
        )) {
            Class<?> clazz = Class.forName("CffAuditShapes", true, loader);
            Object[] carrier = cffObjectCarrier(clazz);
            Method helper = cffStepMaterialHelper(clazz);
            StepMaterialResult zero = invokeStepMaterialHelper(
                helper,
                carrier,
                0L,
                0,
                0,
                0
            );
            assertTrue(
                zero.hasNonZeroState(),
                "step-material helper did not execute a materialized row"
            );
            StepMaterialResult live = invokeStepMaterialHelper(
                helper,
                carrier,
                0x1122334455667788L,
                0x13579BDF,
                0x2468ACE0,
                0x10203040
            );
            assertTrue(
                !zero.equals(live),
                "step-material helper output did not depend on live key/control state"
            );
            StepMaterialResult pooled = invokeStepMaterialHelperFromThreadPool(
                helper,
                carrier,
                0x1122334455667788L,
                0x13579BDF,
                0x2468ACE0,
                0x10203040
            );
            assertTrue(
                pooled.hasNonZeroState(),
                "thread-pool path did not execute the step-material helper"
            );
        }
    }

    private static void assertStepMaterialHelperUsesRuntimeSources(Path jar)
        throws Exception {
        JarInput input = new JarInput(jar);
        boolean sawCurrentThread = false;
        boolean sawIdentityHash = false;
        boolean sawThreadName = false;
        boolean sawStackTrace = false;
        boolean sawStackElementHash = false;
        for (var clazz : input.classes()) {
            for (var method : clazz.asmNode().methods) {
                if (!"(JIII[Ljava/lang/Object;I[J)J".equals(method.desc)) {
                    continue;
                }
                for (
                    AbstractInsnNode insn = method.instructions.getFirst();
                    insn != null;
                    insn = insn.getNext()
                ) {
                    if (!(insn instanceof MethodInsnNode call)) {
                        continue;
                    }
                    sawCurrentThread |= call.owner.equals("java/lang/Thread")
                        && call.name.equals("currentThread")
                        && call.desc.equals("()Ljava/lang/Thread;");
                    sawIdentityHash |= call.owner.equals("java/lang/System")
                        && call.name.equals("identityHashCode")
                        && call.desc.equals("(Ljava/lang/Object;)I");
                    sawThreadName |= call.owner.equals("java/lang/Thread")
                        && call.name.equals("getName")
                        && call.desc.equals("()Ljava/lang/String;");
                    sawStackTrace |= call.owner.equals("java/lang/Thread")
                        && call.name.equals("getStackTrace")
                        && call.desc.equals("()[Ljava/lang/StackTraceElement;");
                    sawStackElementHash |= call.owner.equals("java/lang/StackTraceElement")
                        && call.name.equals("hashCode")
                        && call.desc.equals("()I");
                }
            }
        }
        assertTrue(sawCurrentThread, "step-material helper does not read current thread");
        assertTrue(sawIdentityHash, "step-material helper does not fold thread identity");
        assertTrue(sawThreadName, "step-material helper does not fold thread name");
        assertTrue(sawStackTrace, "step-material helper does not read stack trace");
        assertTrue(sawStackElementHash, "step-material helper does not fold stack frame hash");
    }

    private static void assertCffDataDigestInitializedFromEntryData(Path jar)
        throws Exception {
        CffEntryDigestProof proof = cffEntryDigestProof(cffAuditValueMethod(jar));
        assertTrue(proof.digestLocal() >= 0, "CFF entry digest local was not identified");
    }

    private static void assertCffDataDigestUpdatedFromPrimitiveFlow(Path jar)
        throws Exception {
        MethodNode value = cffAuditValueMethod(jar);
        CffEntryDigestProof proof = cffEntryDigestProof(value);
        AbstractInsnNode[] insns = value.instructions.toArray();
        boolean sawPrimitiveFlowUpdate = false;
        for (int i = proof.firstBranch() + 1; i < insns.length; i++) {
            if (!(insns[i] instanceof VarInsnNode load)
                || load.getOpcode() != Opcodes.ILOAD
                || !proof.intArgLocals().contains(load.var)) {
                continue;
            }
            boolean sawNonlinearMix = false;
            for (int j = i + 1; j < insns.length && j < i + 28; j++) {
                int opcode = insns[j].getOpcode();
                sawNonlinearMix |= opcode == Opcodes.IMUL
                    || opcode == Opcodes.IUSHR
                    || opcode == Opcodes.IXOR;
                if (insns[j] instanceof VarInsnNode store
                    && store.getOpcode() == Opcodes.ISTORE
                    && store.var == proof.digestLocal()
                    && sawNonlinearMix) {
                    sawPrimitiveFlowUpdate = true;
                    break;
                }
            }
            if (sawPrimitiveFlowUpdate) break;
        }
        assertTrue(
            sawPrimitiveFlowUpdate,
            "CFF data digest was not updated from primitive argument flow after dispatch"
        );
    }

    private static void assertCffDataDigestUpdatedFromLivePrimitiveLocal(MethodNode value) {
        CffEntryDigestProof proof = cffEntryDigestProof(value);
        AbstractInsnNode[] insns = value.instructions.toArray();
        int pcLocal = proof.digestLocal() - 5;
        assertTrue(pcLocal > 0, "CFF data digest local did not match published pc/data local layout");
        boolean sawPrimitiveFlowUpdate = false;
        for (int i = proof.firstBranch() + 1; i < insns.length; i++) {
            if (!(insns[i] instanceof VarInsnNode load)
                || load.getOpcode() != Opcodes.ILOAD
                || load.var >= pcLocal) {
                continue;
            }
            boolean sawNonlinearMix = false;
            for (int j = i + 1; j < insns.length && j < i + 32; j++) {
                int opcode = insns[j].getOpcode();
                sawNonlinearMix |= isNonlinearIntMixOpcode(opcode);
                if (insns[j] instanceof VarInsnNode store
                    && store.getOpcode() == Opcodes.ISTORE
                    && store.var == proof.digestLocal()
                    && sawNonlinearMix) {
                    sawPrimitiveFlowUpdate = true;
                    break;
                }
            }
            if (sawPrimitiveFlowUpdate) break;
        }
        assertTrue(
            sawPrimitiveFlowUpdate,
            "CFF cyclic data digest was not updated from a live primitive local after dispatch"
        );
    }

    private static int doubleHashCalls(MethodNode method) {
        int calls = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                && "java/lang/Double".equals(call.owner)
                && "hashCode".equals(call.name)
                && "(D)I".equals(call.desc)) {
                calls++;
            }
        }
        return calls;
    }

    private static void assertCffDispatchConsumesDataDigest(Path jar)
        throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("CffAuditShapes");
        assertTrue(clazz != null, "missing CFF audit fixture class");
        MethodNode value = cffAuditValueMethod(clazz);
        CffEntryDigestProof proof = cffEntryDigestProof(value);
        int pcLocal = proof.digestLocal() - 5;
        assertTrue(pcLocal >= 0, "CFF data digest local did not match published pc/data local layout");

        int checkedDispatchBranches = countDispatchSelectorBranches(
            value,
            proof.firstBranch(),
            pcLocal,
            proof.digestLocal()
        );
        for (MethodNode method : clazz.asmNode().methods) {
            if (!method.name.startsWith("__neko_cff$")) continue;
            if (!isCffDispatchHelperDesc(method.desc)) continue;
            checkedDispatchBranches += countDispatchSelectorBranches(method, 0, 5, 7);
        }
        assertTrue(
            checkedDispatchBranches > 0,
            "CFF audit fixture did not expose a pc-token dispatch selector"
        );
    }

    private static int countDispatchSelectorBranches(
        MethodNode method,
        int firstIndex,
        int pcLocal,
        int dataLocal
    ) {
        AbstractInsnNode[] insns = method.instructions.toArray();
        int checked = 0;
        for (int i = Math.max(0, firstIndex); i < insns.length; i++) {
            if (!isDispatchSelectorBranch(insns[i])) {
                continue;
            }
            if (dispatchSelectorConsumesDataDigest(insns, i, pcLocal, dataLocal)) {
                checked++;
            }
        }
        return checked;
    }

    private static boolean dispatchSelectorConsumesDataDigest(
        AbstractInsnNode[] insns,
        int branchIndex,
        int pcLocal,
        int dataLocal
    ) {
        int sliceStart = previousBranchIndex(insns, branchIndex) + 1;
        int pcLoad = firstVarLoadIndex(insns, Opcodes.ILOAD, pcLocal, sliceStart, branchIndex);
        if (pcLoad >= 0) {
            return hasDataDigestMix(insns, pcLoad + 1, branchIndex, dataLocal);
        }
        int selectorLoad = lastVarLoadIndex(insns, sliceStart, branchIndex);
        if (selectorLoad < 0) return false;
        int selectorLocal = ((VarInsnNode) insns[selectorLoad]).var;
        int selectorStore = previousVarStoreIndex(insns, selectorLocal, selectorLoad);
        if (selectorStore < 0) return false;
        int storeSliceStart = previousBranchIndex(insns, selectorStore) + 1;
        pcLoad = firstVarLoadIndex(insns, Opcodes.ILOAD, pcLocal, storeSliceStart, selectorStore);
        return pcLoad >= 0 && hasDataDigestMix(insns, pcLoad + 1, selectorStore, dataLocal);
    }

    private static boolean hasDataDigestMix(
        AbstractInsnNode[] insns,
        int start,
        int end,
        int dataLocal
    ) {
        boolean sawDataDigest = false;
        boolean sawNonlinearAfterDigest = false;
        for (int i = start; i < end; i++) {
            if (insns[i] instanceof VarInsnNode load
                && load.getOpcode() == Opcodes.ILOAD
                && load.var == dataLocal) {
                sawDataDigest = true;
            }
            if (sawDataDigest && isNonlinearIntMixOpcode(insns[i].getOpcode())) {
                sawNonlinearAfterDigest = true;
            }
        }
        return sawDataDigest && sawNonlinearAfterDigest;
    }

    private static boolean isDispatchSelectorBranch(AbstractInsnNode insn) {
        if (insn instanceof LookupSwitchInsnNode || insn instanceof TableSwitchInsnNode) {
            return true;
        }
        if (!(insn instanceof JumpInsnNode)) {
            return false;
        }
        int opcode = insn.getOpcode();
        return opcode == Opcodes.IF_ICMPEQ || opcode == Opcodes.IF_ICMPNE;
    }

    private static int previousBranchIndex(AbstractInsnNode[] insns, int index) {
        for (int i = index - 1; i >= 0; i--) {
            if (insns[i] instanceof JumpInsnNode
                || insns[i] instanceof LookupSwitchInsnNode
                || insns[i] instanceof TableSwitchInsnNode) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isNonlinearIntMixOpcode(int opcode) {
        return opcode == Opcodes.IMUL
            || opcode == Opcodes.IUSHR
            || opcode == Opcodes.IXOR;
    }

    private static MethodNode cffAuditValueMethod(Path jar)
        throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("CffAuditShapes");
        assertTrue(clazz != null, "missing CFF audit fixture class");
        return cffAuditValueMethod(clazz);
    }

    private static MethodNode cffAuditValueMethod(L1Class clazz) {
        MethodNode value = null;
        for (MethodNode method : clazz.asmNode().methods) {
            if ("value".equals(method.name)
                && method.instructions != null
                && method.instructions.size() > 0) {
                value = method;
                break;
            }
        }
        assertTrue(value != null, "missing transformed CFF value method");
        return value;
    }

    private static MethodNode method(Path jar, String owner, String name)
        throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        assertTrue(clazz != null, "missing class " + owner);
        for (MethodNode method : clazz.asmNode().methods) {
            if (name.equals(method.name)
                && method.instructions != null
                && method.instructions.size() > 0) {
                return method;
            }
        }
        throw new AssertionError("missing transformed method " + owner + "." + name);
    }

    private static boolean callsCffOutlinerHelper(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof MethodInsnNode call)) continue;
            if (!call.name.startsWith("__neko_cff")) continue;
            if (isCffDispatchHelperDesc(call.desc)) return true;
            if ("(JIII[Ljava/lang/Object;II[J)J".equals(call.desc)) return true;
            if ("(JIIII[J)J".equals(call.desc)) return true;
            if ("(JIIII[J[I)J".equals(call.desc)) return true;
        }
        return false;
    }

    private static boolean isCffDispatchHelperDesc(String desc) {
        return CFF_DISPATCH_HELPER_DESC.equals(desc)
            || CFF_COMPACT_DISPATCH_HELPER_DESC.equals(desc);
    }

    private static CffEntryDigestProof cffEntryDigestProof(MethodNode value) {
        Type[] args = Type.getArgumentTypes(value.desc);
        List<Integer> intArgLocals = new ArrayList<>();
        int keyLocal = -1;
        int local = (value.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type arg : args) {
            if (arg.getSort() == Type.INT) {
                intArgLocals.add(local);
            } else if (arg.getSort() == Type.LONG) {
                keyLocal = local;
            }
            local += arg.getSize();
        }
        int argumentLimit = local;
        assertTrue(
            intArgLocals.size() >= 2 && keyLocal >= 0,
            "fixture value method did not expose two primitive args plus hidden key: " + value.desc
        );

        AbstractInsnNode[] insns = value.instructions.toArray();
        int firstBranch = firstBranchIndex(insns);
        assertTrue(firstBranch > 0, "transformed value method has no dispatcher branch");
        int firstX = firstVarLoadIndex(insns, Opcodes.ILOAD, intArgLocals.get(0), firstBranch);
        int firstY = firstVarLoadIndex(insns, Opcodes.ILOAD, intArgLocals.get(1), firstBranch);
        int firstKey = firstVarLoadIndex(insns, Opcodes.LLOAD, keyLocal, firstBranch);
        assertTrue(firstX >= 0, "CFF entry digest did not read first int argument before dispatch");
        assertTrue(firstY >= 0, "CFF entry digest did not read second int argument before dispatch");
        assertTrue(firstKey >= 0, "CFF entry digest did not read hidden method key before dispatch");

        int allEntryDataSeen = Math.max(firstKey, Math.max(firstX, firstY));
        Set<Integer> earlierStores = new LinkedHashSet<>();
        for (int i = 0; i < allEntryDataSeen; i++) {
            if (insns[i] instanceof VarInsnNode var
                && var.getOpcode() == Opcodes.ISTORE
                && var.var >= argumentLimit) {
                earlierStores.add(var.var);
            }
        }
        int digestLocal = -1;
        for (int i = allEntryDataSeen + 1; i < firstBranch; i++) {
            if (insns[i] instanceof VarInsnNode var
                && var.getOpcode() == Opcodes.ISTORE
                && earlierStores.contains(var.var)) {
                digestLocal = var.var;
                break;
            }
        }
        assertTrue(
            digestLocal >= 0,
            "CFF entry digest did not store a protected local after reading entry data"
        );
        return new CffEntryDigestProof(
            firstBranch,
            digestLocal,
            List.copyOf(intArgLocals),
            keyLocal
        );
    }

    private static int firstBranchIndex(AbstractInsnNode[] insns) {
        for (int i = 0; i < insns.length; i++) {
            if (insns[i] instanceof JumpInsnNode
                || insns[i] instanceof LookupSwitchInsnNode
                || insns[i] instanceof TableSwitchInsnNode) {
                return i;
            }
        }
        return -1;
    }

    private static int firstVarLoadIndex(
        AbstractInsnNode[] insns,
        int opcode,
        int local,
        int limitExclusive
    ) {
        return firstVarLoadIndex(insns, opcode, local, 0, limitExclusive);
    }

    private static int firstVarLoadIndex(
        AbstractInsnNode[] insns,
        int opcode,
        int local,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof VarInsnNode var
                && var.getOpcode() == opcode
                && var.var == local) {
                return i;
            }
        }
        return -1;
    }

    private static int lastVarLoadIndex(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = Math.min(limitExclusive, insns.length) - 1; i >= startInclusive; i--) {
            if (insns[i] instanceof VarInsnNode var
                && var.getOpcode() == Opcodes.ILOAD) {
                return i;
            }
        }
        return -1;
    }

    private static int previousVarStoreIndex(
        AbstractInsnNode[] insns,
        int local,
        int beforeExclusive
    ) {
        for (int i = Math.min(beforeExclusive, insns.length) - 1; i >= 0; i--) {
            if (insns[i] instanceof VarInsnNode var
                && var.getOpcode() == Opcodes.ISTORE
                && var.var == local) {
                return i;
            }
        }
        return -1;
    }

    private static int firstOpcodeIndex(
        AbstractInsnNode[] insns,
        int opcode,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i].getOpcode() == opcode) {
                return i;
            }
        }
        return -1;
    }

    private static Object[] cffObjectCarrier(Class<?> clazz) throws Exception {
        List<Field> carriers = new ArrayList<>();
        for (Field field : clazz.getDeclaredFields()) {
            if (field.getType().equals(Object[].class)
                && Modifier.isStatic(field.getModifiers())) {
                carriers.add(field);
            }
        }
        assertEquals(1, carriers.size(), "expected one generated Object[] carrier field");
        Field carrier = carriers.get(0);
        carrier.setAccessible(true);
        return (Object[]) carrier.get(null);
    }

    private static Method cffStepMaterialHelper(Class<?> clazz) {
        Class<?>[] expected = new Class<?>[] {
            long.class,
            int.class,
            int.class,
            int.class,
            Object[].class,
            int.class,
            long[].class
        };
        List<Method> helpers = new ArrayList<>();
        for (Method method : clazz.getDeclaredMethods()) {
            if (method.getReturnType().equals(long.class)
                && java.util.Arrays.equals(method.getParameterTypes(), expected)) {
                helpers.add(method);
            }
        }
        assertEquals(1, helpers.size(), "expected one generated step-material helper");
        Method helper = helpers.get(0);
        helper.setAccessible(true);
        return helper;
    }

    private static StepMaterialResult invokeStepMaterialHelper(
        Method helper,
        Object[] carrier,
        long key,
        int guard,
        int path,
        int block
    ) throws Exception {
        long[] out = new long[3];
        long resultKey = (Long) helper.invoke(
            null,
            key,
            guard,
            path,
            block,
            carrier,
            0,
            out
        );
        return new StepMaterialResult(resultKey, out[0], out[1]);
    }

    private static StepMaterialResult invokeStepMaterialHelperFromThreadPool(
        Method helper,
        Object[] carrier,
        long key,
        int guard,
        int path,
        int block
    ) throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "neko-cff-step-material-proof");
            thread.setDaemon(true);
            return thread;
        });
        try {
            Future<StepMaterialResult> future = executor.submit(
                () -> invokeStepMaterialHelper(
                    helper,
                    carrier,
                    key,
                    guard,
                    path,
                    block
                )
            );
            return future.get(30, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
    }

    private static boolean hasNearbyIntArrayLoad(AbstractInsnNode start) {
        int scanned = 0;
        for (
            AbstractInsnNode scan = start.getNext();
            scan != null && scanned++ < 96;
            scan = scan.getNext()
        ) {
            if (scan.getOpcode() == Opcodes.IALOAD) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasNearbySidecarHelperCall(AbstractInsnNode start) {
        int scanned = 0;
        for (
            AbstractInsnNode scan = start.getNext();
            scan != null && scanned++ < 24;
            scan = scan.getNext()
        ) {
            if (scan instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKESTATIC
                && (CFF_SIDECAR_HELPER_DESC.equals(call.desc)
                    || CFF_TOKEN_MATERIAL_OBJECT_HELPER_DESC.equals(call.desc))) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasNearbyEncryptedTokenHelperCall(AbstractInsnNode start) {
        int scanned = 0;
        for (
            AbstractInsnNode scan = start.getNext();
            scan != null && scanned++ < 32;
            scan = scan.getNext()
        ) {
            if (scan instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKESTATIC
                && (CFF_LEGACY_INT_TOKEN_HELPER_DESC.equals(call.desc)
                    || CFF_TOKEN_MATERIAL_HELPER_DESC.equals(call.desc)
                    || CFF_TOKEN_MATERIAL_OBJECT_HELPER_DESC.equals(call.desc)
                    || "(IIII)I".equals(call.desc))) {
                return true;
            }
        }
        return false;
    }

    private static boolean updatesSidecarCell(MethodNode method) {
        if (!(CFF_SIDECAR_HELPER_DESC.equals(method.desc)
            || CFF_TOKEN_MATERIAL_HELPER_DESC.equals(method.desc)
            || CFF_TOKEN_MATERIAL_OBJECT_HELPER_DESC.equals(method.desc))
            || method.instructions == null) {
            return false;
        }
        boolean sawAaload = false;
        boolean sawLongCellCast = false;
        boolean sawAtomicLongCellCast = false;
        boolean sawAtomicLongRead = false;
        boolean sawAtomicLongWrite = false;
        int stores = 0;
        for (
            AbstractInsnNode scan = method.instructions.getFirst();
            scan != null;
            scan = scan.getNext()
        ) {
            if (scan.getOpcode() == Opcodes.AALOAD) {
                sawAaload = true;
            }
            if (scan instanceof TypeInsnNode type
                && scan.getOpcode() == Opcodes.CHECKCAST
                && "java/lang/Long".equals(type.desc)) {
                sawLongCellCast = true;
            }
            if (scan instanceof TypeInsnNode type
                && scan.getOpcode() == Opcodes.CHECKCAST
                && "java/util/concurrent/atomic/AtomicLong".equals(type.desc)) {
                sawAtomicLongCellCast = true;
            }
            if (scan instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKEVIRTUAL
                && "java/util/concurrent/atomic/AtomicLong".equals(call.owner)
                && ("get".equals(call.name) || "getPlain".equals(call.name))
                && "()J".equals(call.desc)) {
                sawAtomicLongRead = true;
            }
            if (scan instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKEVIRTUAL
                && "java/util/concurrent/atomic/AtomicLong".equals(call.owner)
                && ("lazySet".equals(call.name) || "set".equals(call.name) || "setPlain".equals(call.name))
                && "(J)V".equals(call.desc)) {
                sawAtomicLongWrite = true;
            }
            if (scan.getOpcode() == Opcodes.AASTORE) {
                stores++;
            }
        }
        return sawAaload
            && ((sawLongCellCast && stores >= 1)
                || (sawAtomicLongCellCast && sawAtomicLongRead && sawAtomicLongWrite));
    }

    private void runObfuscation(Path input, Path output) throws Exception {
        runObfuscation(input, output, false);
    }

    private void runPackedObfuscation(Path input, Path output) throws Exception {
        runObfuscation(input, output, true);
    }

    private void runValidationSinkObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("validationSinkHardening", new TransformConfig(true, 1.0));
        transforms.put("invokeDynamic", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x515EED51A11L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void runCffOnlyObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x5A6C0FFEE11L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void runObfuscation(Path input, Path output, boolean packedParameters) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        if (packedParameters) {
            transforms.put("methodParameterObfuscation", new TransformConfig(true, 1.0));
        }
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x5EEDCFFAL);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private static void assertValidationSinkUsesKeyedTag(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ValidationSinkShape");
        MethodNode check = null;
        for (MethodNode method : clazz.asmNode().methods) {
            if ("check".equals(method.name) && method.desc.startsWith("(Ljava/lang/String;")) {
                check = method;
                break;
            }
        }
        assertTrue(check != null, "missing validation sink fixture method");
        String helperName = null;
        boolean sawOldHelperDesc = false;
        for (AbstractInsnNode insn = check.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LdcInsnNode ldc && "swordfish-validated-flow".equals(ldc.cst)) {
                throw new AssertionError("validation sink retained plaintext target in check method");
            }
            if (insn instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKEVIRTUAL
                && "java/lang/String".equals(call.owner)
                && "equals".equals(call.name)
                && "(Ljava/lang/Object;)Z".equals(call.desc)) {
                throw new AssertionError("validation sink retained String.equals compare");
            }
            if (insn instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKESTATIC
                && "ValidationSinkShape".equals(call.owner)
                && VALIDATION_HELPER_DESC.equals(call.desc)) {
                helperName = call.name;
            }
            if (insn instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKESTATIC
                && "ValidationSinkShape".equals(call.owner)
                && OLD_VALIDATION_HELPER_DESC.equals(call.desc)) {
                sawOldHelperDesc = true;
            }
        }
        assertFalse(sawOldHelperDesc, "validation sink retained expanded helper ABI");
        assertTrue(helperName != null, "validation sink did not call keyed tag helper");
        assertValidationLiveWordConsumesDataDigest(clazz);
        assertValidationSinkPredicateIsStaged(clazz);
        assertValidationSinkStagesUseCffDataDigest(clazz);
        assertValidationFinalStageUsesInvokeDynamic(clazz);
        assertValidationSinkHelperHasNoPlainTarget(clazz, helperName);
        assertValidationSinkUsesFormulaVariants(clazz);
        assertValidationSinkHasNoStandaloneTargetCarriers(clazz);
        assertPrimitiveValidationTableCompareIsStaged(clazz);
    }

    private static void assertValidationSinkHelperHasNoPlainTarget(L1Class clazz, String helperName) {
        MethodNode helper = null;
        for (MethodNode method : clazz.asmNode().methods) {
            if (helperName.equals(method.name) && VALIDATION_HELPER_DESC.equals(method.desc)) {
                helper = method;
                break;
            }
        }
        assertTrue(helper != null, "missing validation sink helper body");
        for (AbstractInsnNode insn = helper.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LdcInsnNode ldc && "swordfish-validated-flow".equals(ldc.cst)) {
                throw new AssertionError("validation sink helper retained plaintext target");
            }
            if (insn instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKEVIRTUAL
                && "java/lang/String".equals(call.owner)
                && "equals".equals(call.name)
                && "(Ljava/lang/Object;)Z".equals(call.desc)) {
                throw new AssertionError("validation sink helper retained String.equals compare");
            }
        }
    }

    private static void assertValidationSinkUsesFormulaVariants(L1Class clazz) {
        boolean sawVariantZero = false;
        boolean sawVariantOne = false;
        Set<String> protectedTargets = Set.of(
            "swordfish-validated-flow",
            "swordfish-variant-two"
        );
        for (MethodNode method : clazz.asmNode().methods) {
            if (!VALIDATION_HELPER_DESC.equals(method.desc)) continue;
            sawVariantZero |= method.name.startsWith("__neko_vsink0$");
            sawVariantOne |= method.name.startsWith("__neko_vsink1$");
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode ldc && protectedTargets.contains(ldc.cst)) {
                    throw new AssertionError("validation sink variant helper retained plaintext target");
                }
            }
        }
        assertTrue(sawVariantZero, "validation sink did not emit formula variant 0 helper");
        assertTrue(sawVariantOne, "validation sink did not emit formula variant 1 helper");
    }

    private static void assertValidationSinkPredicateIsStaged(L1Class clazz) {
        int entryHelpers = 0;
        Set<String> stageCalls = new LinkedHashSet<>();
        for (MethodNode method : clazz.asmNode().methods) {
            if (!VALIDATION_HELPER_DESC.equals(method.desc) || !method.name.startsWith("__neko_vsink")) continue;
            entryHelpers++;
            boolean sawLength = false;
            boolean sawSeed = false;
            boolean sawChar = false;
            boolean sawFinal = false;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn.getOpcode() == Opcodes.LCMP) {
                    throw new AssertionError("validation sink entry helper retained final compare");
                }
                if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKEVIRTUAL
                    && "java/lang/String".equals(call.owner)
                    && ("length".equals(call.name) || "charAt".equals(call.name))) {
                    throw new AssertionError("validation sink entry helper retained String predicate operation");
                }
                if (!(insn instanceof MethodInsnNode call)
                    || call.getOpcode() != Opcodes.INVOKESTATIC
                    || !"ValidationSinkShape".equals(call.owner)) {
                    continue;
                }
                sawLength |= VALIDATION_LENGTH_STAGE_DESC.equals(call.desc);
                sawSeed |= VALIDATION_SEED_STAGE_DESC.equals(call.desc);
                sawChar |= VALIDATION_CHAR_STAGE_DESC.equals(call.desc);
                sawFinal |= VALIDATION_FINAL_STAGE_DESC.equals(call.desc);
                if (isValidationStageDesc(call.desc)) {
                    assertTrue(
                        stageCalls.add(call.name + call.desc),
                        "validation sink stage helper was reused across entries: " + call.name + call.desc
                    );
                }
            }
            assertTrue(sawLength, "validation sink entry helper did not call length stage");
            assertTrue(sawSeed, "validation sink entry helper did not call seed stage");
            assertTrue(sawChar, "validation sink entry helper did not call char stage");
            assertFalse(sawFinal, "validation sink entry helper retained direct final stage");
        }
        assertTrue(entryHelpers >= 2, "validation sink fixture did not emit per-site entry helpers");
        assertTrue(
            stageCalls.size() >= entryHelpers * 3,
            "validation sink stages were not independently emitted per entry"
        );
    }

    private static void assertValidationSinkStagesUseCffDataDigest(L1Class clazz) {
        Map<String, Integer> stageCounts = new HashMap<>();
        for (MethodNode method : clazz.asmNode().methods) {
            if (!isValidationStageDesc(method.desc)) continue;
            int dataWordLocal = validationStageDataWordLocal(method.desc);
            assertTrue(
                stageLoadsDataWord(method, dataWordLocal),
                "validation sink stage did not consume data word: " + method.name + method.desc
            );
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode ldc
                    && ("swordfish-validated-flow".equals(ldc.cst) || "swordfish-variant-two".equals(ldc.cst))) {
                    throw new AssertionError("validation sink stage retained plaintext target");
                }
                if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKEVIRTUAL
                    && "java/lang/String".equals(call.owner)
                    && "equals".equals(call.name)
                    && "(Ljava/lang/Object;)Z".equals(call.desc)) {
                    throw new AssertionError("validation sink stage retained String.equals compare");
                }
            }
            stageCounts.merge(method.desc, 1, Integer::sum);
        }
        assertTrue(stageCounts.getOrDefault(VALIDATION_LENGTH_STAGE_DESC, 0) >= 2,
            "validation sink did not emit per-site length stages");
        assertTrue(stageCounts.getOrDefault(VALIDATION_SEED_STAGE_DESC, 0) >= 2,
            "validation sink did not emit per-site seed stages");
        assertTrue(stageCounts.getOrDefault(VALIDATION_CHAR_STAGE_DESC, 0) >= 2,
            "validation sink did not emit per-site char stages");
        assertTrue(stageCounts.getOrDefault(VALIDATION_FINAL_STAGE_DESC, 0) >= 2,
            "validation sink did not emit per-site final stages");
    }

    private static boolean isValidationStageDesc(String desc) {
        return VALIDATION_LENGTH_STAGE_DESC.equals(desc)
            || VALIDATION_SEED_STAGE_DESC.equals(desc)
            || VALIDATION_CHAR_STAGE_DESC.equals(desc)
            || VALIDATION_FINAL_STAGE_DESC.equals(desc);
    }

    private static int validationStageDataWordLocal(String desc) {
        if (VALIDATION_LENGTH_STAGE_DESC.equals(desc)) return 1;
        if (VALIDATION_FINAL_STAGE_DESC.equals(desc)) return 4;
        return 3;
    }

    private static boolean stageLoadsDataWord(MethodNode method, int dataWordLocal) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode load
                && load.getOpcode() == Opcodes.ILOAD
                && load.var == dataWordLocal) {
                return true;
            }
        }
        return false;
    }

    private static boolean stageLoadsLong(MethodNode method, int local) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode load
                && load.getOpcode() == Opcodes.LLOAD
                && load.var == local) {
                return true;
            }
        }
        return false;
    }

    private static void assertValidationFinalStageUsesInvokeDynamic(L1Class clazz) {
        int checked = 0;
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null || method.name.startsWith("__neko_")) continue;
            boolean sawValidationEntry = false;
            boolean sawIndyFinal = false;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKESTATIC
                    && "ValidationSinkShape".equals(call.owner)
                    && call.name.startsWith("__neko_vsink")
                    && VALIDATION_HELPER_DESC.equals(call.desc)) {
                    sawValidationEntry = true;
                }
                if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKESTATIC
                    && "ValidationSinkShape".equals(call.owner)
                    && call.name.startsWith("__neko_vsend")
                    && VALIDATION_FINAL_STAGE_DESC.equals(call.desc)) {
                    throw new AssertionError("validation final stage remained direct invokestatic");
                }
                if (!(insn instanceof InvokeDynamicInsnNode indy)
                    || !VALIDATION_FINAL_STAGE_INDY_DESC.equals(indy.desc)) {
                    continue;
                }
                sawIndyFinal = true;
                assertTrue(
                    indy.bsm.getOwner().equals("ValidationSinkShape")
                        && indy.bsm.getName().startsWith("__neko_indy_bsm"),
                    "validation final stage did not use existing indy bootstrap"
                );
                assertValidationIndyArgsHideFinalStageMaterial(indy);
            }
            if (!sawValidationEntry) continue;
            assertTrue(sawIndyFinal, "validation sink method did not route final stage through invokedynamic");
            checked++;
        }
        assertTrue(checked >= 2, "validation sink fixture did not expose both indy-protected final stages");
    }

    private static void assertPrimitiveValidationTableCompareIsStaged(L1Class clazz) {
        boolean sawEntryStage = false;
        boolean sawValueStage = false;
        boolean sawGuardStage = false;
        boolean sawDataStage = false;
        boolean sawFinalStage = false;
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.name.startsWith("__neko_vsx") && VALIDATION_PRIMITIVE_ENTRY_DESC.equals(method.desc)) {
                sawEntryStage = true;
                assertTrue(
                    stageLoadsLong(method, 2),
                    "primitive validation entry did not consume live key: " + method.name + method.desc
                );
            }
            if (method.name.startsWith("__neko_vsxval") &&
                VALIDATION_PRIMITIVE_VALUE_STAGE_DESC.equals(method.desc)) {
                sawValueStage = true;
                assertTrue(
                    stageLoadsLong(method, 2),
                    "primitive validation value stage did not consume live key: " + method.name + method.desc
                );
            }
            if (method.name.startsWith("__neko_vsxguard") &&
                VALIDATION_PRIMITIVE_GUARD_STAGE_DESC.equals(method.desc)) {
                sawGuardStage = true;
                assertTrue(
                    stageLoadsLong(method, 0),
                    "primitive validation guard stage did not consume live key: " + method.name + method.desc
                );
            }
            if (method.name.startsWith("__neko_vsxdata") &&
                VALIDATION_PRIMITIVE_DATA_STAGE_DESC.equals(method.desc)) {
                sawDataStage = true;
                assertTrue(
                    stageLoadsLong(method, 0),
                    "primitive validation data stage did not consume live key: " + method.name + method.desc
                );
            }
            if (method.name.startsWith("__neko_vsxend") &&
                VALIDATION_PRIMITIVE_FINAL_STAGE_DESC.equals(method.desc)) {
                sawFinalStage = true;
                assertTrue(
                    stageLoadsLong(method, 2),
                    "primitive validation final stage did not consume live key: " + method.name + method.desc
                );
            }
        }
        assertTrue(sawEntryStage, "primitive validation table compare did not emit entry stage");
        assertTrue(sawValueStage, "primitive validation table compare did not emit value stage");
        assertTrue(sawGuardStage, "primitive validation table compare did not emit guard stage");
        assertTrue(sawDataStage, "primitive validation table compare did not emit data stage");
        assertTrue(sawFinalStage, "primitive validation table compare did not emit final stage");

        boolean sawApplicationPrimitiveEntry = false;
        boolean sawPrimitiveEntryIndy = false;
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            boolean applicationMethod = !method.name.startsWith("__neko_");
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKESTATIC
                    && "java/lang/Integer".equals(call.owner)
                    && "sum".equals(call.name)
                    && "(II)I".equals(call.desc)) {
                    throw new AssertionError("primitive validation retained placeholder Integer.sum");
                }
                if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKESTATIC
                    && "ValidationSinkShape".equals(call.owner)
                    && call.name.startsWith("__neko_vsx")
                    && VALIDATION_PRIMITIVE_ENTRY_DESC.equals(call.desc)) {
                    if (applicationMethod) {
                        throw new AssertionError("primitive validation entry remained direct invokestatic");
                    }
                }
                if (insn instanceof MethodInsnNode call
                    && applicationMethod
                    && call.getOpcode() == Opcodes.INVOKESTATIC
                    && "ValidationSinkShape".equals(call.owner)
                    && call.name.startsWith("__neko_vsxend")
                    && VALIDATION_PRIMITIVE_FINAL_STAGE_DESC.equals(call.desc)) {
                    throw new AssertionError("primitive validation final stage remained direct application call");
                }
                if (!(insn instanceof InvokeDynamicInsnNode indy)
                    || !VALIDATION_PRIMITIVE_ENTRY_INDY_DESC.equals(indy.desc)) {
                    continue;
                }
                sawApplicationPrimitiveEntry |= applicationMethod;
                sawPrimitiveEntryIndy = true;
                assertTrue(
                    indy.bsm.getOwner().equals("ValidationSinkShape")
                        && indy.bsm.getName().startsWith("__neko_indy_bsm"),
                    "primitive validation entry did not use existing indy bootstrap"
                );
            }
        }
        assertTrue(
            sawApplicationPrimitiveEntry,
            "primitive validation fixture did not expose a protected table compare"
        );
        assertTrue(
            sawPrimitiveEntryIndy,
            "primitive validation table compare did not route entry through invokedynamic"
        );
    }

    private static void assertValidationIndyArgsHideFinalStageMaterial(InvokeDynamicInsnNode indy) {
        boolean sawCarrierHandle = false;
        for (Object arg : indy.bsmArgs) {
            if (arg instanceof String text) {
                assertFalse(text.contains("__neko_vsend"), "validation final indy exposed helper name");
                assertFalse(text.contains(VALIDATION_FINAL_STAGE_DESC), "validation final indy exposed helper desc");
                assertFalse(text.contains("swordfish-validated-flow"), "validation final indy exposed target text");
                assertFalse(text.contains("swordfish-variant-two"), "validation final indy exposed variant target text");
            }
            if (arg instanceof org.objectweb.asm.Handle handle
                && handle.getTag() == Opcodes.H_GETSTATIC
                && "ValidationSinkShape".equals(handle.getOwner())
                && "[Ljava/lang/Object;".equals(handle.getDesc())) {
                sawCarrierHandle = true;
            }
        }
        assertTrue(sawCarrierHandle, "validation final indy did not carry class-key material handle");
    }

    private static void assertValidationLiveWordConsumesDataDigest(L1Class clazz) {
        int checkedCalls = 0;
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null || method.name.startsWith("__neko_")) continue;
            AbstractInsnNode[] insns = method.instructions.toArray();
            for (int i = 0; i < insns.length; i++) {
                if (!(insns[i] instanceof MethodInsnNode call)
                    || call.getOpcode() != Opcodes.INVOKESTATIC
                    || !"ValidationSinkShape".equals(call.owner)) {
                    continue;
                }
                if (OLD_VALIDATION_HELPER_DESC.equals(call.desc)) {
                    throw new AssertionError("validation sink retained expanded helper call ABI");
                }
                if (!VALIDATION_HELPER_DESC.equals(call.desc)) continue;
                assertTrue(
                    validationHelperCallConsumesDataDigest(insns, i),
                    "validation helper call material did not consume CFF data digest in " +
                        method.name + method.desc
                );
                checkedCalls++;
            }
        }
        assertTrue(checkedCalls >= 2, "validation sink fixture did not expose both protected helper calls");
    }

    private static boolean validationHelperCallConsumesDataDigest(AbstractInsnNode[] insns, int callIndex) {
        int start = Math.max(0, callIndex - 1800);
        for (int i = start; i < callIndex; i++) {
            if (!(insns[i] instanceof VarInsnNode load)
                || load.getOpcode() != Opcodes.ILOAD
                || load.var < 5) {
                continue;
            }
            if (!validationDataWordPattern(insns, i, callIndex)) continue;
            int dataWordStore = firstVarStoreIndex(insns, load.var, i + 1, Math.min(callIndex, i + 96));
            if (dataWordStore < 0) continue;
            int dataWordLocal = ((VarInsnNode) insns[dataWordStore]).var;
            if (varLoadCount(insns, dataWordLocal, dataWordStore + 1, callIndex) < 3) {
                continue;
            }
            if (firstVarLoadIndex(
                insns,
                Opcodes.ILOAD,
                dataWordLocal,
                Math.max(dataWordStore + 1, callIndex - 24),
                callIndex
            ) < 0) {
                continue;
            }
            return true;
        }
        return preparedValidationHelperCallConsumesDataDigest(insns, callIndex);
    }

    private static boolean preparedValidationHelperCallConsumesDataDigest(
        AbstractInsnNode[] insns,
        int callIndex
    ) {
        AbstractInsnNode previous = previousReal(insns, callIndex - 1);
        if (!(previous instanceof VarInsnNode dataWordLoad)
            || dataWordLoad.getOpcode() != Opcodes.ILOAD) {
            return false;
        }
        int dataWordLocal = dataWordLoad.var;
        int start = Math.max(0, callIndex - 2400);
        if (varLoadCount(insns, dataWordLocal, start, callIndex) < 3) return false;
        if (firstOpcodeIndex(insns, Opcodes.IXOR, start, callIndex) < 0) return false;
        if (firstOpcodeIndex(insns, Opcodes.IUSHR, start, callIndex) < 0) return false;
        if (firstOpcodeIndex(insns, Opcodes.IMUL, start, callIndex) < 0) return false;
        if (firstOpcodeIndex(insns, Opcodes.IADD, start, callIndex) < 0) return false;
        for (int i = start; i < callIndex; i++) {
            if (!(insns[i] instanceof VarInsnNode dataLoad)
                || dataLoad.getOpcode() != Opcodes.ILOAD
                || dataLoad.var < 5
                || dataLoad.var == dataWordLocal) {
                continue;
            }
            int dataLocal = dataLoad.var;
            if (firstVarLoadIndex(insns, Opcodes.ILOAD, dataLocal - 4, i + 1, callIndex) >= 0
                && firstVarLoadIndex(insns, Opcodes.ILOAD, dataLocal - 3, i + 1, callIndex) >= 0
                && firstVarLoadIndex(insns, Opcodes.ILOAD, dataLocal - 2, i + 1, callIndex) >= 0
                && firstVarLoadIndex(insns, Opcodes.ILOAD, dataLocal - 5, i + 1, callIndex) >= 0
                && firstOpcodeIndex(insns, Opcodes.LLOAD, i + 1, callIndex) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static AbstractInsnNode previousReal(AbstractInsnNode[] insns, int start) {
        for (int i = Math.min(start, insns.length - 1); i >= 0; i--) {
            if (insns[i].getOpcode() >= 0) return insns[i];
        }
        return null;
    }

    private static boolean validationDataWordPattern(AbstractInsnNode[] insns, int start, int limitExclusive) {
        VarInsnNode dataLoad = (VarInsnNode) insns[start];
        int dataLocal = dataLoad.var;
        int end = Math.min(limitExclusive, start + 80);
        int guardLoad = firstVarLoadIndex(insns, Opcodes.ILOAD, dataLocal - 4, start + 1, end);
        if (guardLoad < 0) return false;
        int pathLoad = firstVarLoadIndex(insns, Opcodes.ILOAD, dataLocal - 3, guardLoad + 1, end);
        if (pathLoad < 0) return false;
        int blockLoad = firstVarLoadIndex(insns, Opcodes.ILOAD, dataLocal - 2, pathLoad + 1, end);
        if (blockLoad < 0) return false;
        int keyLoad = firstOpcodeIndex(insns, Opcodes.LLOAD, blockLoad + 1, end);
        if (keyLoad < 0) return false;
        int pcLoad = firstVarLoadIndex(insns, Opcodes.ILOAD, dataLocal - 5, keyLoad + 1, end);
        if (pcLoad < 0) return false;
        return firstOpcodeIndex(insns, Opcodes.IXOR, start + 1, end) >= 0
            && firstOpcodeIndex(insns, Opcodes.IUSHR, start + 1, end) >= 0
            && firstOpcodeIndex(insns, Opcodes.IMUL, start + 1, end) >= 0
            && firstOpcodeIndex(insns, Opcodes.IADD, start + 1, end) >= 0;
    }

    private static int firstVarStoreIndex(
        AbstractInsnNode[] insns,
        int excludedLocal,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof VarInsnNode store
                && store.getOpcode() == Opcodes.ISTORE
                && store.var != excludedLocal) {
                return i;
            }
        }
        return -1;
    }

    private static int varLoadCount(
        AbstractInsnNode[] insns,
        int local,
        int startInclusive,
        int limitExclusive
    ) {
        int count = 0;
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof VarInsnNode load
                && load.getOpcode() == Opcodes.ILOAD
                && load.var == local) {
                count++;
            }
        }
        return count;
    }

    private static void assertValidationSinkHasNoStandaloneTargetCarriers(L1Class clazz) {
        for (FieldNode field : clazz.asmNode().fields) {
            boolean generatedStatic = (field.access & Opcodes.ACC_SYNTHETIC) != 0
                && (field.access & Opcodes.ACC_STATIC) != 0;
            if (!generatedStatic) continue;
            assertFalse(
                "[B".equals(field.desc)
                    || "J".equals(field.desc)
                    || "Ljava/lang/String;".equals(field.desc)
                    || "[Ljava/lang/String;".equals(field.desc),
                "validation sink emitted standalone target carrier field: " + field.name + field.desc
            );
        }
    }

    private static Path recreateWork(Path work) throws Exception {
        if (Files.exists(work)) {
            try (var stream = Files.walk(work)) {
                for (Path path : stream.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
        return Files.createDirectories(work);
    }

    private static void writeJar(Path jar, Path classes, String mainClass)
        throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", mainClass);
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            List<Path> classFiles = new ArrayList<>();
            try (var stream = Files.walk(classes)) {
                stream.filter(path -> path.toString().endsWith(".class")).forEach(classFiles::add);
            }
            for (Path classFile : classFiles) {
                String name = classes.relativize(classFile).toString().replace('\\', '/');
                jos.putNextEntry(new JarEntry(name));
                jos.write(Files.readAllBytes(classFile));
                jos.closeEntry();
            }
        }
    }

    private static String runJar(Path jar) throws Exception {
        return run(
            List.of("java", "-XX:-UsePerfData", "-jar", jar.toString()),
            Duration.ofSeconds(30)
        );
    }

    private static String runJar(Path jar, List<String> jvmArgs, List<String> appArgs) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-XX:-UsePerfData");
        command.addAll(jvmArgs);
        command.add("-jar");
        command.add(jar.toString());
        command.addAll(appArgs);
        return run(command, Duration.ofSeconds(30));
    }

    private static boolean jvmAccepts(List<String> jvmArgs) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("java");
        command.add("-XX:-UsePerfData");
        command.addAll(jvmArgs);
        command.add("-version");
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean exited = process.waitFor(30, TimeUnit.SECONDS);
        return exited && process.exitValue() == 0;
    }

    private static String run(List<String> command, Duration timeout)
        throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean exited = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(exited, "command timed out: " + command);
        assertEquals(0, process.exitValue(), "command failed: " + command + "\n" + output);
        return output;
    }

    private static String summarize(List<Finding> findings) {
        int limit = Math.min(20, findings.size());
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < limit; i++) {
            out.append(findings.get(i)).append('\n');
        }
        if (findings.size() > limit) {
            out.append("... ").append(findings.size() - limit).append(" more\n");
        }
        return out.toString();
    }

    private static String validationSinkSourceText() {
        return """
            public class ValidationSinkShape {
                private static final int[] TABLE_CHECK = {24, 112, 64, 248, 128};

                public static void main(String[] args) {
                    if (!check("swordfish-validated-flow")) {
                        throw new AssertionError("accepted value rejected");
                    }
                    if (check("swordfish-validated-flaw")) {
                        throw new AssertionError("wrong value accepted");
                    }
                    if (!checkAlt("swordfish-variant-two")) {
                        throw new AssertionError("variant value rejected");
                    }
                    if (checkAlt("swordfish-variant-too")) {
                        throw new AssertionError("wrong variant accepted");
                    }
                    if (checkSwitch("case42") != 42) {
                        throw new AssertionError("string switch accepted value rejected");
                    }
                    if (checkSwitch("case43") != -1) {
                        throw new AssertionError("string switch wrong value accepted");
                    }
                    if (!checkTable(new int[] {18, 44, 91, 123, 5})) {
                        throw new AssertionError("table value rejected");
                    }
                    if (checkTable(new int[] {18, 44, 91, 124, 5})) {
                        throw new AssertionError("wrong table value accepted");
                    }
                    System.out.println("VALIDATION SINK OK");
                }

                static boolean check(String value) {
                    int noise = value.length() * 17;
                    if ((noise & 3) == 1) {
                        noise ^= 0x13579BDF;
                    }
                    return value.equals("swordfish-validated-flow");
                }

                static boolean checkAlt(String value) {
                    int noise = value.length() * 31;
                    if ((noise & 5) == 4) {
                        noise ^= 0x2468ACE0;
                    }
                    return value.equals("swordfish-variant-two");
                }

                static int checkSwitch(String value) {
                    switch (value) {
                        case "case42":
                            return 42;
                        default:
                            return -1;
                    }
                }

                static boolean checkTable(int[] values) {
                    if (values == null || values.length != TABLE_CHECK.length) {
                        return false;
                    }
                    int acc = 0;
                    for (int i = 0; i < values.length; i++) {
                        int mixed = (values[i] ^ (0x31 + i * 17)) & 255;
                        mixed = Integer.rotateLeft(mixed, 3) & 255;
                        acc |= mixed ^ TABLE_CHECK[i];
                    }
                    return acc == 0;
                }
            }
            """;
    }

    private static String loopDigestSourceText() {
        return """
            public class CffLoopDigestShape {
                public static int value(int x, int y) {
                    int acc = x ^ y;
                    double wave = x + 0.25d;
                    for (int i = 0; i < 256; i++) {
                        wave += (i * 0.125d) - (acc & 7);
                        acc = (acc * 31) ^ i ^ x ^ y ^ (int) wave;
                    }
                    return acc ^ (int) (wave * 3.0d);
                }

                public static void main(String[] args) {
                    int first = value(17, 23);
                    int second = value(17, 23);
                    if (first != second) {
                        throw new AssertionError(first + ":" + second);
                    }
                    System.out.println("CFF LOOP DIGEST OK " + first);
                }
            }
            """;
    }

    private static String cyclicJitBudgetSourceText() {
        return """
            public class CffCyclicJitBudgetShape {
                public static void main(String[] args) {
                    int out = hot(41);
                    System.out.println("CFF CYCLIC JIT OK " + out);
                    if (out == 0x12345678) {
                        throw new AssertionError(out);
                    }
                }

                static int hot(int seed) {
                    int v = seed;
                    int a = 3;
                    int b = 5;
                    int c = 7;
                    int d = 11;
                    for (int i = 0; i < 96; i++) {
                        v = (v * 1103515245 + 12345) ^ i;
                        if ((v & 1) == 0) {
                            a += v ^ i;
                        } else {
                            b ^= v + i;
                        }
                        if ((v & 2) == 0) {
                            c += a ^ b;
                        } else {
                            d ^= c + i;
                        }
                        if ((v & 4) == 0) {
                            b += d ^ (v >>> 3);
                        } else {
                            c ^= b + (v << 1);
                        }
                        if ((v & 8) == 0) {
                            d += a ^ (c >>> 1);
                        } else {
                            a ^= d + (b << 2);
                        }
                        v ^= a + b + c + d;
                    }
                    return v ^ a ^ b ^ c ^ d;
                }
            }
            """;
    }

    private static String zgcCffProbeSourceText() {
        return """
            public class ZgcCffProbe {
                public static void main(String[] args) {
                    if (args.length == 2 && "--probe".equals(args[0])) {
                        System.out.println(Probe.run(args[1]));
                        return;
                    }
                    throw new AssertionError("probe arguments not routed");
                }

                static final class Probe {
                    static String run(String collector) {
                        System.gc();
                        long checksum = 0;
                        for (int i = 0; i < 64; i++) {
                            checksum += (i * 31L) ^ collector.length();
                        }
                        return "ZGC CFF OK " + collector + " " + checksum;
                    }
                }
            }
            """;
    }

    private static String sourceText() {
        return """
            public class CffAuditShapes {
                public static void main(String[] args) {
                    CffAuditShapes shapes = new CffAuditShapes();
                    int a = shapes.value(7, 11);
                    int b = shapes.value(19, 5);
                    int c = shapes.nested(13);
                    int d = CffAuditPeerA.peer(7);
                    int e = CffAuditPeerB.peer(5);
                    String out = a + ":" + b + ":" + c + ":" + d + ":" + e;
                    System.out.println(out);
                    if (!check(out)) {
                        throw new AssertionError(out);
                    }
                    System.out.println("CFF AUDIT OK");
                }

                private static boolean check(String value) {
                    return value.equals("63:97:58:628:3104");
                }

                int value(int x, int y) {
                    int r = x * 3 + y;
                    for (int i = 0; i < 5; i++) {
                        if (((r ^ i) & 1) == 0) {
                            r += y + i;
                        } else {
                            r ^= x + i;
                        }
                    }
                    switch (r & 3) {
                        case 0:
                            return r + 17;
                        case 1:
                            return r - 9;
                        case 2:
                            return r ^ 0x55;
                        default:
                            return r + x - y;
                    }
                }

                int nested(int seed) {
                    int acc = seed;
                    for (int i = 0; i < 4; i++) {
                        switch ((acc + i) & 3) {
                            case 0:
                                acc += i * 7;
                                break;
                            case 1:
                                acc ^= i + 31;
                                break;
                            case 2:
                                acc -= i + 5;
                                break;
                            default:
                                acc += seed ^ i;
                                break;
                        }
                    }
                    return acc;
                }
            }

            class CffAuditPeerA {
                static int peer(int value) {
                    int out = value;
                    for (int i = 0; i < 4; i++) {
                        out = out * 3 + i;
                    }
                    return out + 43;
                }
            }

            class CffAuditPeerB {
                static int peer(int value) {
                    int out = value;
                    for (int i = 0; i < 4; i++) {
                        out = out * 5 - i;
                    }
                    return out + 17;
                }
            }
            """;
    }

    private enum FindingKind {
        XOR_SELF_CANCELLATION,
        ADDITIVE_SELF_CANCELLATION,
        LINEAR_KEY_OVERWRITE,
        AUDITED_INTEGER_ALGEBRA
    }

    private record Finding(
        FindingKind kind,
        String owner,
        String method,
        int instruction,
        String detail
    ) {
        boolean rejectsVariant() {
            return kind != FindingKind.AUDITED_INTEGER_ALGEBRA;
        }

        @Override
        public String toString() {
            return owner + "." + method + " @" + instruction + " " + kind + ": " + detail;
        }
    }

    private static final class AlgebraicAudit {
        private static List<Finding> audit(String owner, MethodNode method) {
            List<Finding> findings = new ArrayList<>();
            if (method.instructions == null || method.instructions.size() == 0) {
                return findings;
            }
            auditLinearKeyOverwrite(owner, method, findings);
            auditSymbolic(owner, method, findings);
            return findings;
        }

        private static void auditLinearKeyOverwrite(
            String owner,
            MethodNode method,
            List<Finding> findings
        ) {
            List<AbstractInsnNode> insns = realInstructions(method);
            int highLocalStart = Math.max(0, method.maxLocals - 8);
            for (int i = 5; i < insns.size(); i++) {
                AbstractInsnNode n0 = insns.get(i - 5);
                AbstractInsnNode n1 = insns.get(i - 4);
                AbstractInsnNode n2 = insns.get(i - 3);
                AbstractInsnNode n3 = insns.get(i - 2);
                AbstractInsnNode n4 = insns.get(i - 1);
                AbstractInsnNode n5 = insns.get(i);
                if (!(n0 instanceof VarInsnNode left) || left.getOpcode() != Opcodes.ILOAD) continue;
                if (!(n1 instanceof VarInsnNode right) || right.getOpcode() != Opcodes.ILOAD) continue;
                if (n2.getOpcode() != Opcodes.IXOR) continue;
                if (intConstant(n3) == null) continue;
                if (n4.getOpcode() != Opcodes.IXOR) continue;
                if (!(n5 instanceof VarInsnNode dst) || dst.getOpcode() != Opcodes.ISTORE) continue;
                if (dst.var < highLocalStart || left.var < highLocalStart || right.var < highLocalStart) continue;
                if (dst.var == left.var || dst.var == right.var) continue;
                findings.add(
                    new Finding(
                        FindingKind.LINEAR_KEY_OVERWRITE,
                        owner,
                        method.name + method.desc,
                        i,
                        "v" + dst.var + " = v" + left.var + " ^ v" + right.var +
                            " ^ const loses old v" + dst.var
                    )
                );
            }
        }

        private static void auditSymbolic(
            String owner,
            MethodNode method,
            List<Finding> findings
        ) {
            ArrayDeque<Expr> stack = new ArrayDeque<>();
            Map<Integer, Expr> locals = new HashMap<>();
            List<AbstractInsnNode> insns = realInstructions(method);
            for (int index = 0; index < insns.size(); index++) {
                AbstractInsnNode insn = insns.get(index);
                Integer constant = intConstant(insn);
                if (constant != null) {
                    stack.push(Expr.constant(constant));
                    continue;
                }
                int opcode = insn.getOpcode();
                try {
                    switch (opcode) {
                        case Opcodes.ILOAD -> {
                            int local = ((VarInsnNode) insn).var;
                            stack.push(locals.getOrDefault(local, Expr.local(local)));
                        }
                        case Opcodes.ISTORE -> locals.put(((VarInsnNode) insn).var, pop(stack));
                        case Opcodes.LLOAD -> stack.push(Expr.term("l" + ((VarInsnNode) insn).var, Set.of()));
                        case Opcodes.LSTORE -> pop(stack);
                        case Opcodes.L2I -> stack.push(Expr.term("l2i(" + pop(stack) + ")", Set.of()));
                        case Opcodes.LUSHR, Opcodes.LSHR, Opcodes.LSHL, Opcodes.LXOR -> binaryGeneric(stack, opcodeName(opcode));
                        case Opcodes.IXOR -> {
                            Expr right = pop(stack);
                            Expr left = pop(stack);
                            Set<String> repeated = left.repeatedXorTerms(right);
                            String cancellation = repeated.isEmpty()
                                ? null
                                : left + " ^ " + right + " repeats " + repeated;
                            stack.push(left.xor(right, cancellation));
                            findings.add(
                                new Finding(
                                    FindingKind.AUDITED_INTEGER_ALGEBRA,
                                    owner,
                                    method.name + method.desc,
                                    index,
                                    "ixor"
                                )
                            );
                        }
                        case Opcodes.IADD -> {
                            Expr right = pop(stack);
                            Expr left = pop(stack);
                            stack.push(Expr.op("add", left, right));
                            findings.add(audited(owner, method, index, "iadd"));
                        }
                        case Opcodes.ISUB -> {
                            Expr right = pop(stack);
                            Expr left = pop(stack);
                            if (left.equals(right) || left.addContains(right)) {
                                findings.add(
                                    new Finding(
                                        FindingKind.ADDITIVE_SELF_CANCELLATION,
                                        owner,
                                        method.name + method.desc,
                                        index,
                                        left + " - " + right
                                    )
                                );
                            }
                            stack.push(Expr.op("sub", left, right));
                            findings.add(audited(owner, method, index, "isub"));
                        }
                        case Opcodes.IMUL, Opcodes.IDIV, Opcodes.IREM, Opcodes.IAND,
                            Opcodes.IOR, Opcodes.ISHL, Opcodes.ISHR, Opcodes.IUSHR -> {
                            binaryGeneric(stack, opcodeName(opcode));
                            findings.add(audited(owner, method, index, opcodeName(opcode)));
                        }
                        case Opcodes.INEG -> stack.push(Expr.op("neg", pop(stack)));
                        case Opcodes.IINC -> locals.remove(((org.objectweb.asm.tree.IincInsnNode) insn).var);
                        case Opcodes.DUP -> stack.push(peek(stack));
                        case Opcodes.DUP2 -> stack.push(peek(stack));
                        case Opcodes.POP -> pop(stack);
                        case Opcodes.POP2 -> pop(stack);
                        case Opcodes.IRETURN, Opcodes.ARETURN, Opcodes.FRETURN -> pop(stack);
                        case Opcodes.LRETURN, Opcodes.DRETURN -> pop(stack);
                        case Opcodes.IFNULL, Opcodes.IFNONNULL, Opcodes.IFEQ, Opcodes.IFNE,
                            Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE -> pop(stack);
                        case Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT,
                            Opcodes.IF_ICMPGE, Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE,
                            Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE -> {
                            pop(stack);
                            pop(stack);
                        }
                        case Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH -> {
                            Expr selector = pop(stack);
                            if (selector.xorCancellation() != null) {
                                findings.add(
                                    new Finding(
                                        FindingKind.XOR_SELF_CANCELLATION,
                                        owner,
                                        method.name + method.desc,
                                        index,
                                        selector.xorCancellation()
                                    )
                                );
                            }
                        }
                        default -> {
                            if (opcode >= Opcodes.IALOAD && opcode <= Opcodes.SALOAD) {
                                pop(stack);
                                pop(stack);
                                stack.push(Expr.unknown("arrayLoad"));
                            } else if (opcode >= Opcodes.IASTORE && opcode <= Opcodes.SASTORE) {
                                pop(stack);
                                pop(stack);
                                pop(stack);
                            }
                        }
                    }
                } catch (StackUnderflow ignored) {
                    stack.clear();
                }
            }
        }

        private static Finding audited(
            String owner,
            MethodNode method,
            int instruction,
            String detail
        ) {
            return new Finding(
                FindingKind.AUDITED_INTEGER_ALGEBRA,
                owner,
                method.name + method.desc,
                instruction,
                detail
            );
        }

        private static void binaryGeneric(ArrayDeque<Expr> stack, String op) {
            Expr right = pop(stack);
            Expr left = pop(stack);
            stack.push(Expr.op(op, left, right));
        }

        private static Expr pop(ArrayDeque<Expr> stack) {
            Expr value = stack.pollFirst();
            if (value == null) throw new StackUnderflow();
            return value;
        }

        private static Expr peek(ArrayDeque<Expr> stack) {
            Expr value = stack.peekFirst();
            if (value == null) throw new StackUnderflow();
            return value;
        }

        private static List<AbstractInsnNode> realInstructions(MethodNode method) {
            List<AbstractInsnNode> insns = new ArrayList<>();
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn.getOpcode() >= 0) {
                    insns.add(insn);
                }
            }
            return insns;
        }

        private static Integer intConstant(AbstractInsnNode insn) {
            int opcode = insn.getOpcode();
            return switch (opcode) {
                case Opcodes.ICONST_M1 -> -1;
                case Opcodes.ICONST_0 -> 0;
                case Opcodes.ICONST_1 -> 1;
                case Opcodes.ICONST_2 -> 2;
                case Opcodes.ICONST_3 -> 3;
                case Opcodes.ICONST_4 -> 4;
                case Opcodes.ICONST_5 -> 5;
                case Opcodes.BIPUSH, Opcodes.SIPUSH -> ((IntInsnNode) insn).operand;
                case Opcodes.LDC -> ((LdcInsnNode) insn).cst instanceof Integer i ? i : null;
                default -> null;
            };
        }

        private static String opcodeName(int opcode) {
            return "op" + opcode;
        }
    }

    private record Expr(
        boolean linearXor,
        TreeSet<String> xorTerms,
        int xorConstant,
        String op,
        List<Expr> args,
        String display,
        String xorCancellation
    ) {
        static Expr constant(int value) {
            return new Expr(true, new TreeSet<>(), value, "const", List.of(), "#" + value, null);
        }

        static Expr local(int local) {
            return term("v" + local, Set.of("v" + local));
        }

        static Expr unknown(String label) {
            return term(label + "#" + System.identityHashCode(new Object()), Set.of());
        }

        static Expr term(String term, Set<String> refs) {
            TreeSet<String> terms = new TreeSet<>();
            String token = token(term);
            terms.add(token);
            return new Expr(true, terms, 0, "term", List.of(), token, null);
        }

        static Expr op(String op, Expr... args) {
            StringBuilder display = new StringBuilder(op).append('(');
            for (int i = 0; i < args.length; i++) {
                if (i > 0) display.append(',');
                display.append(args[i]);
            }
            display.append(')');
            TreeSet<String> terms = new TreeSet<>();
            String token = token(display.toString());
            terms.add(token);
            return new Expr(true, terms, 0, op, List.of(args), token, null);
        }

        Expr xor(Expr other, String cancellation) {
            TreeSet<String> terms = new TreeSet<>(xorTerms);
            for (String term : other.xorTerms) {
                if (!terms.add(term)) {
                    terms.remove(term);
                }
            }
            return new Expr(
                true,
                terms,
                xorConstant ^ other.xorConstant,
                "xor",
                List.of(this, other),
                formatXor(terms, xorConstant ^ other.xorConstant),
                cancellation != null ? cancellation : firstNonNull(xorCancellation, other.xorCancellation)
            );
        }

        Set<String> repeatedXorTerms(Expr other) {
            if (!linearXor || !other.linearXor) return Set.of();
            Set<String> repeated = new LinkedHashSet<>(xorTerms);
            repeated.retainAll(other.xorTerms);
            repeated.removeIf(term -> term.startsWith("#"));
            return repeated;
        }

        boolean addContains(Expr right) {
            return "add".equals(op) && args.contains(right);
        }

        @Override
        public String toString() {
            return display;
        }

        private static String formatXor(TreeSet<String> terms, int constant) {
            List<String> pieces = new ArrayList<>(terms);
            if (constant != 0 || pieces.isEmpty()) {
                pieces.add("#" + constant);
            }
            return token(String.join("^", pieces));
        }

        private static String token(String text) {
            if (text.length() <= 96) return text;
            return text.substring(0, 64) + "~" + Integer.toHexString(text.hashCode());
        }

        private static String firstNonNull(String first, String second) {
            return first != null ? first : second;
        }
    }

    record StepMaterialResult(long key, long out0, long out1) {
        boolean hasNonZeroState() {
            return key != 0L || out0 != 0L || out1 != 0L;
        }
    }

    record CffEntryDigestProof(
        int firstBranch,
        int digestLocal,
        List<Integer> intArgLocals,
        int keyLocal
    ) {}

    private static final class StackUnderflow extends RuntimeException {}
}
