package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
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
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises CFF-live runtime local protection over the prefix-oracle shape that
 * stores and later compares a mismatch accumulator.
 */
public class JvmRuntimeVariableObfuscationIntegrationTest {
    @Test
    void runtimeVariableObfuscationProtectsAccumulatorAndMixedLocals() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-runtime-vars"));
        Path source = work.resolve("RuntimeVariableShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("runtime-variable-shapes.jar");
        writeJar(inputJar, classes, "RuntimeVariableShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("runtime-variable-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("RUNTIME VARS OK"), obfuscated);
        assertPrimitiveSlotsArePoisoned(outputJar);
        assertNoRuntimeVariableReferenceFrame(outputJar);
        assertNoStoredPrimitiveMaskInitialization(outputJar);
        assertPrimitiveMasksUseCffKeyOrPendingStack(outputJar);
        assertAccumulatorZeroBranchUsesTransientMaskCompare(outputJar);
    }

    private void runObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("validationSinkHardening", new TransformConfig(true, 1.0));
        transforms.put("runtimeVariableObfuscation", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x52564F5A45524F31L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void assertPrimitiveSlotsArePoisoned(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("RuntimeVariableShapes");
        boolean sawIntPoison = false;
        boolean sawLongPoison = false;
        boolean sawFloatPoison = false;
        boolean sawDoublePoison = false;
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof VarInsnNode store) {
                    AbstractInsnNode prev = previousReal(store.getPrevious());
                    if (store.getOpcode() == Opcodes.ISTORE && prev != null && prev.getOpcode() == Opcodes.ICONST_0) {
                        sawIntPoison = true;
                    }
                    if (store.getOpcode() == Opcodes.LSTORE && prev != null && prev.getOpcode() == Opcodes.LCONST_0) {
                        sawLongPoison = true;
                    }
                    if (store.getOpcode() == Opcodes.FSTORE && prev != null && prev.getOpcode() == Opcodes.FCONST_0) {
                        sawFloatPoison = true;
                    }
                    if (store.getOpcode() == Opcodes.DSTORE && prev != null && prev.getOpcode() == Opcodes.DCONST_0) {
                        sawDoublePoison = true;
                    }
                }
            }
        }
        assertTrue(sawIntPoison, "int-like locals should be poisoned after shadow encryption");
        assertTrue(sawLongPoison, "long locals should be poisoned after shadow encryption");
        assertTrue(sawFloatPoison, "float locals should be poisoned after shadow encryption");
        assertTrue(sawDoublePoison, "double locals should be poisoned after shadow encryption");
    }

    private void assertNoRuntimeVariableReferenceFrame(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("RuntimeVariableShapes");
        for (MethodNode method : clazz.asmNode().methods) {
            assertFalse(method.name.startsWith("__neko_rv_ref_handle"),
                "runtime-variable obfuscation must not emit reference handle helpers");
            if (!isFixtureApplicationMethod(method)) continue;
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode call
                        && "java/lang/ThreadLocal".equals(call.owner)
                        && ("get".equals(call.name) || "set".equals(call.name))) {
                    throw new AssertionError("runtime-variable obfuscation must not route fixture application locals through ThreadLocal frames in "
                        + method.name + method.desc);
                }
                if (insn instanceof TypeInsnNode type
                        && type.getOpcode() == Opcodes.ANEWARRAY
                        && "java/lang/Object".equals(type.desc)) {
                    throw new AssertionError("runtime-variable obfuscation must not emit per-call Object[] reference frames in "
                        + method.name + method.desc);
                }
            }
        }
    }

    private boolean isFixtureApplicationMethod(MethodNode method) {
        return !method.name.startsWith("__neko_") && !"<clinit>".equals(method.name);
    }

    private void assertNoStoredPrimitiveMaskInitialization(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("RuntimeVariableShapes");
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!isRuntimeMaskCall(insn)) continue;
                AbstractInsnNode next = nextReal(insn.getNext());
                assertFalse(next != null && (next.getOpcode() == Opcodes.DUP || next.getOpcode() == Opcodes.DUP2),
                    "runtime-variable primitive masks must not be duplicated into persistent local mask slots");
            }
        }
    }

    private void assertAccumulatorZeroBranchUsesTransientMaskCompare(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("RuntimeVariableShapes");
        boolean sawEncodedZeroCompare = false;
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof JumpInsnNode jump) {
                    if (jump.getOpcode() == Opcodes.IF_ICMPEQ || jump.getOpcode() == Opcodes.IF_ICMPNE) {
                        AbstractInsnNode right = previousReal(insn.getPrevious());
                        if (isRuntimeMaskCall(right)) {
                            sawEncodedZeroCompare = true;
                        }
                    }
                }
            }
        }
        assertTrue(sawEncodedZeroCompare,
            "accumulator zero branch should compare encoded shadow with a transiently recomputed mask");
    }

    private void assertPrimitiveMasksUseCffKeyOrPendingStack(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("RuntimeVariableShapes");
        Set<Integer> cffKeyLocals = new LinkedHashSet<>();
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!(insn instanceof MethodInsnNode call) || !call.name.startsWith("__neko_cff_mkey")) continue;
                AbstractInsnNode next = nextReal(insn.getNext());
                if (next instanceof VarInsnNode store && store.getOpcode() == Opcodes.LSTORE) {
                    cffKeyLocals.add(store.var);
                }
            }
        }
        assertFalse(cffKeyLocals.isEmpty(), "fixture should expose CFF key locals for runtime-mask audits");

        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!isRuntimeMaskCall(insn)) continue;
                AbstractInsnNode prev = previousReal(insn.getPrevious());
                if (prev instanceof VarInsnNode load && load.getOpcode() == Opcodes.LLOAD) {
                    assertTrue(cffKeyLocals.contains(load.var),
                        "runtime-variable primitive masks must load the live CFF key local, not a persisted derived seed");
                } else {
                    assertEquals(Opcodes.POP, prev == null ? -1 : prev.getOpcode(),
                        "runtime-variable primitive masks without a CFF key load must consume a pending stack key");
                }
            }
        }
    }

    private AbstractInsnNode previousReal(AbstractInsnNode insn) {
        AbstractInsnNode cursor = insn;
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getPrevious();
        }
        return cursor;
    }

    private AbstractInsnNode nextReal(AbstractInsnNode insn) {
        AbstractInsnNode cursor = insn;
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getNext();
        }
        return cursor;
    }

    private boolean isRuntimeMaskCall(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call
            && call.name.startsWith("__neko_rv_mask")
            && "(IJ)I".equals(call.desc);
    }

    private void writeJar(Path jar, Path classes, String mainClass) throws Exception {
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
            public class RuntimeVariableShapes {
                public static void main(String[] args) {
                    int ok = validate("open-sesame") ? 1 : 0;
                    int bad = validate("open-sesamf") ? 1 : 0;
                    long wide = wide(19L);
                    double d = doubles(3.25d);
                    String object = objectPath("nek");
                    if (ok != 1 || bad != 0 || wide != 0x223344557577L || d != 14.5d || !object.equals("neko:4")) {
                        throw new AssertionError(ok + ":" + bad + ":" + wide + ":" + d + ":" + object);
                    }
                    System.out.println("RUNTIME VARS OK");
                }

                static int getNumber(char input, char expected, int index) {
                    return (input ^ expected) + index;
                }

                static boolean validate(String input) {
                    String expected = "open-sesame";
                    int mismatch = 0;
                    for (int i = 0; i < expected.length(); i++) {
                        int x = getNumber(input.charAt(i), expected.charAt(i), i);
                        mismatch |= x - i;
                    }
                    return mismatch == 0;
                }

                static long wide(long seed) {
                    long x = seed;
                    x = (x << 8) ^ 0x223344556644L;
                    return x ^ 0x33L;
                }

                static double doubles(double input) {
                    float f = (float) input;
                    double d = f * 4.0d;
                    return d + 1.5d;
                }

                static String objectPath(String base) {
                    String text = base + "o";
                    Object obj = text;
                    String cast = (String) obj;
                    synchronized (cast) {
                        String[] arr = new String[] { cast };
                        return arr[0] + ":" + cast.length();
                    }
                }
            }
            """;
    }
}
