package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import dev.nekoobfuscator.transforms.jvm.internal.JvmCodeSizeEstimator;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CffMaterialHelperHotPathTest {
    private static final String KEY_TRANSFER_MATERIAL_HELPER_DESC =
        "(JIII[Ljava/lang/Object;II)J";
    private static final String KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC =
        "(JIIII)I";
    private static final String TRANSITION_MATERIAL_HELPER_DESC =
        "(JIII[Ljava/lang/Object;II[J)J";
    private static final String TRANSITION_MATERIAL_BASE_HELPER_DESC =
        "(JI[Ljava/lang/Object;[IIII)I";
    private static final String TRANSITION_MATERIAL_WORD_HELPER_DESC =
        "([IIII)I";
    private static final String TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC =
        "([IIIII)I";
    private static final String TOKEN_MATERIAL_HELPER_DESC =
        "([Ljava/lang/Object;IIII)I";
    private static final String TOKEN_MATERIAL_OBJECT_HELPER_DESC =
        "([Ljava/lang/Object;[JIIII)I";

    @Test
    void keyTransferRuntimeMaterialHelperSharesRuntimeBucketForLongWords()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-kxfer-hotpath"));
        Path source = work.resolve("CffKeyTransferRuntimeShape.java");
        Files.writeString(source, keyTransferRuntimeSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(
            List.of("javac", "-d", classes.toString(), source.toString()),
            Duration.ofSeconds(30),
            work
        );

        Path inputJar = work.resolve("cff-kxfer-runtime.jar");
        writeJar(inputJar, classes, "CffKeyTransferRuntimeShape");
        String original = runJar(inputJar, work);
        assertTrue(original.contains("CFF KXFER RUNTIME OK"), original);

        Path outputJar = work.resolve("cff-kxfer-runtime-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar, work);
        assertEquals(original, obfuscated);

        JarInput input = new JarInput(outputJar);
        List<MethodRef> runtimeHelpers = new ArrayList<>();
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (!KEY_TRANSFER_MATERIAL_HELPER_DESC.equals(method.desc)) continue;
                if (methodCallCount(method, KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC) == 0) continue;
                runtimeHelpers.add(new MethodRef(clazz.name(), method.name, method.desc));
                assertEquals(
                    0,
                    currentThreadCallCount(method),
                    "key-transfer material helper still embeds thread/runtime source mixing"
                );
                assertTrue(
                    methodCallCount(method, KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC) == 1,
                    "key-transfer material helper should call one runtime bucket helper"
                );
                assertTrue(
                    tokenMaterialCallCount(method) >= 2,
                    "key-transfer runtime helper must decode independent high/low material words"
                );
                assertTrue(
                    JvmCodeSizeEstimator.estimateMethodBytes(method) < 340,
                    "key-transfer runtime helper stayed above the factored hot-path size budget"
                );
            }
        }
        assertFalse(runtimeHelpers.isEmpty(), "runtime key-transfer material helper was not generated");
        Set<MethodRef> runtimeBucketHelpers = helpers(input, KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC);
        assertGeneratedHelpersBelow(
            input,
            runtimeBucketHelpers,
            320,
            "key-transfer runtime bucket helper stayed above the split size budget"
        );
        for (MethodRef helper : runtimeBucketHelpers) {
            MethodNode method = method(input, helper);
            assertTrue(
                currentThreadCallCount(method) <= 2,
                "key-transfer runtime bucket helper recomputes thread source"
            );
        }
        assertTrue(
            callsAny(input, Set.copyOf(runtimeHelpers)),
            "application key-transfer callsites did not target the runtime material helper"
        );
        assertDescriptorCallsitesTargetHelpers(
            input,
            KEY_TRANSFER_MATERIAL_HELPER_DESC,
            helpers(input, KEY_TRANSFER_MATERIAL_HELPER_DESC),
            "key-transfer material"
        );
        assertDescriptorCallsitesTargetHelpers(
            input,
            KEY_TRANSFER_RUNTIME_BUCKET_HELPER_DESC,
            runtimeBucketHelpers,
            "key-transfer runtime bucket"
        );
        assertTokenMaterialHelperUsesSplitObjectMask(input);
        assertTransitionMaterialHelperUsesSplitWordDecoder(input);
    }

    @Test
    void transitionMaterialHelperCallsitesUseSplitWordDecoder()
        throws Exception {
        Path projectRoot = Path.of(
            System.getProperty("neko.test.projectRoot", System.getProperty("user.dir"))
        );
        Path work = recreateWork(projectRoot.resolve("build/tmp/neko-test-cff-xmat-hotpath"));
        Path source = work.resolve("CffTransitionMaterialShape.java");
        Files.writeString(source, transitionMaterialSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(
            List.of("javac", "-d", classes.toString(), source.toString()),
            Duration.ofSeconds(30),
            work
        );

        Path inputJar = work.resolve("cff-xmat-runtime.jar");
        writeJar(inputJar, classes, "CffTransitionMaterialShape");
        String original = runJar(inputJar, work);
        assertTrue(original.contains("CFF XMAT OK"), original);

        Path outputJar = work.resolve("cff-xmat-runtime-obf.jar");
        runObfuscation(inputJar, outputJar);
        assertEquals(original, runJar(outputJar, work));

        JarInput input = new JarInput(outputJar);
        Set<MethodRef> transitionHelpers = helpers(input, TRANSITION_MATERIAL_HELPER_DESC);
        Set<MethodRef> transitionBaseHelpers = helpers(input, TRANSITION_MATERIAL_BASE_HELPER_DESC);
        Set<MethodRef> transitionPcDigestHelpers = helpers(
            input,
            TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC
        );
        assertTokenMaterialHelperUsesSplitObjectMask(input);
        assertTransitionMaterialHelperUsesSplitWordDecoder(input);
        assertDescriptorCallsitesTargetHelpers(
            input,
            TRANSITION_MATERIAL_HELPER_DESC,
            transitionHelpers,
            "transition material"
        );
        assertDescriptorCallsitesTargetHelpers(
            input,
            TRANSITION_MATERIAL_BASE_HELPER_DESC,
            transitionBaseHelpers,
            "transition material base"
        );
        assertDescriptorCallsitesTargetHelpers(
            input,
            TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC,
            transitionPcDigestHelpers,
            "transition material pc digest"
        );
        assertGeneratedHelpersBelow(
            input,
            transitionBaseHelpers,
            320,
            "transition material base helper stayed above the split size budget"
        );
        assertGeneratedHelpersBelow(
            input,
            transitionPcDigestHelpers,
            220,
            "transition material PC digest helper stayed above the split size budget"
        );
    }

    private void runObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x6B58464552484F54L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private static boolean callsAny(JarInput input, Set<MethodRef> targets) {
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                MethodRef caller = new MethodRef(clazz.name(), method.name, method.desc);
                if (targets.contains(caller)) continue;
                for (
                    AbstractInsnNode insn = method.instructions.getFirst();
                    insn != null;
                    insn = insn.getNext()
                ) {
                    if (!(insn instanceof MethodInsnNode call)) continue;
                    if (targets.contains(new MethodRef(call.owner, call.name, call.desc))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static Set<MethodRef> helpers(JarInput input, String desc) {
        Set<MethodRef> helpers = new java.util.LinkedHashSet<>();
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (desc.equals(method.desc)) {
                    helpers.add(new MethodRef(clazz.name(), method.name, method.desc));
                }
            }
        }
        return helpers;
    }

    private static void assertDescriptorCallsitesTargetHelpers(
        JarInput input,
        String desc,
        Set<MethodRef> helpers,
        String label
    ) {
        assertFalse(helpers.isEmpty(), label + " helper was not generated");
        int calls = 0;
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                for (
                    AbstractInsnNode insn = method.instructions.getFirst();
                    insn != null;
                    insn = insn.getNext()
                ) {
                    if (!(insn instanceof MethodInsnNode call) || !desc.equals(call.desc)) {
                        continue;
                    }
                    MethodRef target = new MethodRef(call.owner, call.name, call.desc);
                    assertTrue(
                        helpers.contains(target),
                        label + " callsite targets unexpected helper " + target
                    );
                    calls++;
                }
            }
        }
        assertTrue(calls > 0, label + " helper was generated but no callsites targeted it");
    }

    private static void assertGeneratedHelpersBelow(
        JarInput input,
        Set<MethodRef> helpers,
        int maxBytes,
        String message
    ) {
        assertFalse(helpers.isEmpty(), message);
        for (MethodRef helper : helpers) {
            assertTrue(
                JvmCodeSizeEstimator.estimateMethodBytes(method(input, helper)) < maxBytes,
                message
            );
        }
    }

    private static MethodNode method(JarInput input, MethodRef ref) {
        var clazz = input.classMap().get(ref.owner);
        assertTrue(clazz != null, "missing helper owner " + ref.owner);
        for (MethodNode method : clazz.asmNode().methods) {
            if (ref.name.equals(method.name) && ref.desc.equals(method.desc)) {
                return method;
            }
        }
        throw new AssertionError("missing helper " + ref);
    }

    private static int currentThreadCallCount(MethodNode method) {
        return methodCallCount(method, "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;");
    }

    private static int tokenMaterialCallCount(MethodNode method) {
        return methodCallCount(method, TOKEN_MATERIAL_HELPER_DESC);
    }

    private static int methodCallCount(MethodNode method, String desc) {
        int count = 0;
        for (
            AbstractInsnNode insn = method.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn instanceof MethodInsnNode call && desc.equals(call.desc)) {
                count++;
            }
        }
        return count;
    }

    private static int methodCallCount(MethodNode method, String owner, String name, String desc) {
        int count = 0;
        for (
            AbstractInsnNode insn = method.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn instanceof MethodInsnNode call
                && owner.equals(call.owner)
                && name.equals(call.name)
                && desc.equals(call.desc)) {
                count++;
            }
        }
        return count;
    }

    private static void assertTransitionMaterialHelperUsesSplitWordDecoder(JarInput input) {
        List<MethodRef> transitionHelpers = new ArrayList<>();
        Set<MethodRef> transitionPcDigestHelpers = helpers(
            input,
            TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC
        );
        assertFalse(
            transitionPcDigestHelpers.isEmpty(),
            "transition-material PC digest helper was not generated"
        );
        for (var clazz : input.classes()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (!TRANSITION_MATERIAL_HELPER_DESC.equals(method.desc)) continue;
                transitionHelpers.add(new MethodRef(clazz.name(), method.name, method.desc));
                assertTrue(
                    transitionWordHelperCallCount(method) >= 7,
                    "transition-material helper did not route decoded words through split helper"
                );
                assertTrue(
                    methodCallCount(method, TRANSITION_MATERIAL_BASE_HELPER_DESC) == 1,
                    "transition-material helper did not route base through split helper"
                );
                assertEquals(
                    1,
                    methodCallCount(method, TRANSITION_MATERIAL_PC_DIGEST_HELPER_DESC),
                    "transition-material helper did not route PC/data digest through split helper"
                );
                assertTrue(
                    JvmCodeSizeEstimator.estimateMethodBytes(method) < 260,
                    "transition-material helper stayed above the split hot-path size budget"
                );
            }
        }
        for (MethodRef helper : transitionPcDigestHelpers) {
            MethodNode method = method(input, helper);
            assertEquals(
                5,
                transitionWordHelperCallCount(method),
                "transition-material PC digest helper must decode the data-bound PC words"
            );
            assertTrue(
                varLoadCount(method, Opcodes.ILOAD, 4) > 0,
                "transition-material PC digest helper no longer consumes live data"
            );
        }
        assertFalse(transitionHelpers.isEmpty(), "transition-material helper was not generated");
    }

    private static void assertTokenMaterialHelperUsesSplitObjectMask(JarInput input) {
        Set<MethodRef> tokenHelpers = helpers(input, TOKEN_MATERIAL_HELPER_DESC);
        Set<MethodRef> tokenObjectHelpers = helpers(input, TOKEN_MATERIAL_OBJECT_HELPER_DESC);
        assertFalse(tokenHelpers.isEmpty(), "token-material helper was not generated");
        assertGeneratedHelpersBelow(
            input,
            tokenObjectHelpers,
            260,
            "token-material object helper stayed above the split size budget"
        );
        assertDescriptorCallsitesTargetHelpers(
            input,
            TOKEN_MATERIAL_OBJECT_HELPER_DESC,
            tokenObjectHelpers,
            "token-material object"
        );
        for (MethodRef helper : tokenHelpers) {
            MethodNode method = method(input, helper);
            assertEquals(
                1,
                methodCallCount(method, TOKEN_MATERIAL_OBJECT_HELPER_DESC),
                "token-material helper did not route object epoch through split helper"
            );
            assertEquals(
                0,
                methodCallCount(
                    method,
                    "java/util/concurrent/atomic/AtomicLong",
                    "getPlain",
                    "()J"
                ),
                "token-material helper still embeds object cell read"
            );
            assertEquals(
                0,
                methodCallCount(
                    method,
                    "java/util/concurrent/atomic/AtomicLong",
                    "setPlain",
                    "(J)V"
                ),
                "token-material helper still embeds object cell write"
            );
            assertTrue(
                JvmCodeSizeEstimator.estimateMethodBytes(method) < 240,
                "token-material helper stayed above the split hot-path size budget"
            );
        }
        for (MethodRef helper : tokenObjectHelpers) {
            MethodNode method = method(input, helper);
            assertEquals(
                1,
                methodCallCount(
                    method,
                    "java/util/concurrent/atomic/AtomicLong",
                    "getPlain",
                    "()J"
                ),
                "token-material object helper lost object cell read"
            );
            assertEquals(
                1,
                methodCallCount(
                    method,
                    "java/util/concurrent/atomic/AtomicLong",
                    "setPlain",
                    "(J)V"
                ),
                "token-material object helper lost object cell write"
            );
        }
    }

    private static int transitionWordHelperCallCount(MethodNode method) {
        int count = 0;
        for (
            AbstractInsnNode insn = method.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn instanceof MethodInsnNode call
                && TRANSITION_MATERIAL_WORD_HELPER_DESC.equals(call.desc)) {
                count++;
            }
        }
        return count;
    }

    private static int varLoadCount(MethodNode method, int opcode, int var) {
        int count = 0;
        for (
            AbstractInsnNode insn = method.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn instanceof VarInsnNode load
                && load.getOpcode() == opcode
                && load.var == var) {
                count++;
            }
        }
        return count;
    }

    private static Path recreateWork(Path work) throws Exception {
        if (Files.exists(work)) {
            try (var stream = Files.walk(work)) {
                for (Path path : stream.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
        Files.createDirectories(work.resolve("javatmp"));
        return work;
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

    private static String runJar(Path jar, Path work) throws Exception {
        return run(
            List.of("java", "-XX:-UsePerfData", "-jar", jar.toString()),
            Duration.ofSeconds(30),
            work
        );
    }

    private static String run(List<String> command, Duration timeout, Path work)
        throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
        builder.environment().put(
            "JAVA_TOOL_OPTIONS",
            "-Djava.io.tmpdir=" + work.resolve("javatmp")
        );
        Process process = builder.start();
        boolean exited = process.waitFor(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(exited, "command timed out: " + command);
        assertEquals(0, process.exitValue(), "command failed: " + command + "\n" + output);
        return output;
    }

    private static String keyTransferRuntimeSourceText() {
        return """
            import java.util.concurrent.ExecutorService;
            import java.util.concurrent.Executors;
            import java.util.concurrent.Future;

            public class CffKeyTransferRuntimeShape {
                public static void main(String[] args) throws Exception {
                    ExecutorService executor = Executors.newSingleThreadExecutor();
                    try {
                        Future<Integer> future = executor.submit(() -> value(17));
                        int direct = value(17);
                        int async = future.get();
                        if (direct != async) {
                            throw new AssertionError(direct + ":" + async);
                        }
                        System.out.println("CFF KXFER RUNTIME OK " + async);
                    } finally {
                        executor.shutdownNow();
                    }
                }

                static int value(int seed) {
                    int out = seed;
                    for (int i = 0; i < 7; i++) {
                        if (((out ^ i) & 1) == 0) {
                            out = out * 3 + i;
                        } else {
                            out ^= seed + i * 11;
                        }
                    }
                    return out;
                }
            }
            """;
    }

    private static String transitionMaterialSourceText() {
        return """
            public class CffTransitionMaterialShape {
                public static void main(String[] args) {
                    int out = hot(41);
                    System.out.println("CFF XMAT OK " + out);
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

    private record MethodRef(String owner, String name, String desc) {}
}
