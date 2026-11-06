package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

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
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CffStrongEntrySeedRegressionTest {
    private static final long CFF_ENTRY_RESET_MASK = 0x4346464D45544831L;

    @Test
    void exactCalleesUseExternalEntrySeedWhileReflectiveEntriesRemainCanonical()
        throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-cff-strong-entry"));
        Path source = work.resolve("StrongEntrySeedShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("strong-entry-seed.jar");
        writeJar(inputJar, classes, "StrongEntrySeedShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("strong-entry-seed-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STRONG ENTRY OK"), obfuscated);
        assertNoRuntimeHelpers(outputJar);
        assertExactCallsitesPassCalleeSeed(outputJar);
        assertExactEntrySeedShape(outputJar);
        assertNoShallowCancellationHelpers(outputJar);
    }

    private static void assertExactCallsitesPassCalleeSeed(Path jar) throws Exception {
        ClassNode clazz = classNode(jar, "StrongEntrySeedShapes");
        MethodNode main = method(clazz, "main");

        boolean sawDirect = false;
        boolean sawFinal = false;
        boolean sawLambdaIndy = false;
        for (AbstractInsnNode insn = main.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                    && "StrongEntrySeedShapes".equals(call.owner)
                    && "direct".equals(call.name)) {
                sawDirect = true;
                assertEquals("(IJ)I", call.desc);
                assertDynamicFlowKeyDecodedLongImmediatelyPrecedes(main, call);
            }
            if (insn instanceof MethodInsnNode call
                    && "StrongEntrySeedShapes".equals(call.owner)
                    && "finalValue".equals(call.name)) {
                sawFinal = true;
                assertEquals("(IJ)I", call.desc);
                assertDynamicFlowKeyDecodedLongImmediatelyPrecedes(main, call);
            }
            if (insn instanceof InvokeDynamicInsnNode indy
                    && indy.desc.endsWith("J)Ljava/util/concurrent/Callable;")) {
                sawLambdaIndy = true;
                assertDynamicFlowKeyDecodedLongImmediatelyPrecedes(main, indy);
            }
        }

        assertTrue(sawDirect, "fixture did not exercise exact private static call");
        assertTrue(sawFinal, "fixture did not exercise exact final instance call");
        assertTrue(sawLambdaIndy, "fixture did not exercise exact invokedynamic call");
    }

    private static void assertExactEntrySeedShape(Path jar) throws Exception {
        ClassNode owner = classNode(jar, "StrongEntrySeedShapes");
        ClassNode target = classNode(jar, "StrongEntrySeedShapes$ReflectTarget");

        assertFalse(
            containsLong(owner, method(owner, "direct"), CFF_ENTRY_RESET_MASK),
            "exact private static callee reset its entry key to a fixed CFF seed"
        );
        assertFalse(
            containsLong(owner, method(owner, "finalValue"), CFF_ENTRY_RESET_MASK),
            "exact final callee reset its entry key to a fixed CFF seed"
        );
        assertFalse(
            containsLong(owner, method(owner, "lambda$main$0"), CFF_ENTRY_RESET_MASK),
            "exact lambda callee reset its entry key to a fixed CFF seed"
        );
        assertTrue(
            method(target, "add").desc.endsWith("J)V"),
            "literal reflective target should keep a keyed entry descriptor for Method.invoke"
        );
    }

    private static void assertNoShallowCancellationHelpers(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        for (var clazz : input.classes()) {
            for (var method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode call
                            && "java/lang/Integer".equals(call.owner)
                            && ("rotateLeft".equals(call.name) || "rotateRight".equals(call.name))) {
                        throw new AssertionError("self-cancelling rotate helper in " + clazz.name() + "." + method.name);
                    }
                }
            }
        }
    }

    private static void assertNoRuntimeHelpers(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        for (var clazz : input.classes()) {
            assertFalse(clazz.name().startsWith("dev/nekoobfuscator/runtime/"), clazz.name());
        }
    }

    private static void assertDynamicFlowKeyDecodedLongImmediatelyPrecedes(
        MethodNode method,
        AbstractInsnNode call
    ) {
        AbstractInsnNode p0 = previousReal(call.getPrevious());
        assertNotNull(p0, "missing key material before call");
        assertFalse(
            p0 instanceof VarInsnNode var && var.getOpcode() == Opcodes.LLOAD,
            "exact call still passes raw caller key instead of dynamically decoded target key in "
                + method.name + method.desc
        );
        int scanned = 0;
        boolean sawLongAssembly = false;
        boolean sawEncryptedMaterial = false;
        boolean sawLiveMethodKeyLoad = false;
        boolean sawNonlinearMix = false;
        Set<Integer> liveIntStateLocals = new LinkedHashSet<>();
        for (AbstractInsnNode scan = p0; scan != null && scanned++ < 128; scan = previousReal(scan.getPrevious())) {
            int opcode = scan.getOpcode();
            boolean keyTransferHelper = isKeyTransferMaterialHelperCall(scan);
            sawLongAssembly |= opcode == Opcodes.LOR || keyTransferHelper;
            sawEncryptedMaterial |= isLongLdc(scan) || isIntConstant(scan);
            sawNonlinearMix |= opcode == Opcodes.IXOR
                || opcode == Opcodes.LXOR
                || opcode == Opcodes.IADD
                || opcode == Opcodes.LADD
                || opcode == Opcodes.IMUL
                || opcode == Opcodes.LMUL
                || opcode == Opcodes.IUSHR
                || opcode == Opcodes.LUSHR
                || keyTransferHelper;
            if (scan instanceof VarInsnNode var) {
                if (opcode == Opcodes.LLOAD) {
                    sawLiveMethodKeyLoad = true;
                } else if (opcode == Opcodes.ILOAD) {
                    liveIntStateLocals.add(var.var);
                }
            }
        }
        assertTrue(sawLongAssembly, "callee seed should be assembled at callsite");
        assertTrue(sawEncryptedMaterial, "callee seed decode should use encrypted material");
        assertTrue(
            sawLiveMethodKeyLoad,
            "callee seed decode must depend on the live method-key flowkey local in "
                + method.name + method.desc
        );
        assertTrue(
            liveIntStateLocals.size() >= 3,
            "callee seed decode must depend on live CFF guard/path/block state in "
                + method.name + method.desc
        );
        assertTrue(
            sawNonlinearMix,
            "callee seed decode must mix live state nonlinearly in " + method.name + method.desc
        );
    }

    private static boolean isKeyTransferMaterialHelperCall(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call
            && call.getOpcode() == Opcodes.INVOKESTATIC
            && "(JIII[Ljava/lang/Object;II)J".equals(call.desc);
    }

    private static AbstractInsnNode previousReal(AbstractInsnNode start) {
        for (AbstractInsnNode insn = start; insn != null; insn = insn.getPrevious()) {
            if (insn.getOpcode() >= 0) return insn;
        }
        return null;
    }

    private static boolean containsLong(ClassNode clazz, MethodNode method, long value) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LdcInsnNode ldc && Long.valueOf(value).equals(ldc.cst)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isLongLdc(AbstractInsnNode insn) {
        return insn instanceof LdcInsnNode ldc && ldc.cst instanceof Long;
    }

    private static boolean isIntConstant(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return true;
        }
        if ((opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) && insn instanceof IntInsnNode) {
            return true;
        }
        return insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer;
    }

    private static ClassNode classNode(Path jar, String name) throws Exception {
        JarInput input = new JarInput(jar);
        var clazz = input.classMap().get(name);
        assertNotNull(clazz, "missing class " + name);
        return clazz.asmNode();
    }

    private static MethodNode method(ClassNode clazz, String name) {
        List<MethodNode> matches = clazz.methods.stream()
            .filter(method -> method.name.equals(name))
            .toList();
        assertEquals(1, matches.size(), "expected one method named " + clazz.name + "." + name);
        return matches.get(0);
    }

    private static void runObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("constantObfuscation", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x515EEDCFFL);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
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

    private static String run(List<String> command, Duration timeout)
        throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean exited = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(exited, "command timed out: " + command);
        assertEquals(0, process.exitValue(), "command failed: " + command + "\n" + output);
        return output;
    }

    private static String sourceText() {
        return """
            import java.lang.reflect.Method;
            import java.util.concurrent.Callable;

            public class StrongEntrySeedShapes {
                private final int base;

                public StrongEntrySeedShapes(int base) {
                    this.base = base;
                }

                public static void main(String[] args) throws Exception {
                    StrongEntrySeedShapes shapes = new StrongEntrySeedShapes(2);
                    int a = direct(5);
                    int b = shapes.finalValue(7);
                    Callable<Integer> callable = () -> lambdaValue(11);
                    int c = callable.call();

                    ReflectTarget target = new ReflectTarget(3);
                    Method method = ReflectTarget.class.getDeclaredMethod("add", (Class<?>[]) null);
                    method.setAccessible(true);
                    method.invoke(target, (Object[]) null);

                    String out = a + ":" + b + ":" + c + ":" + target.value();
                    System.out.println(out);
                    if (!out.equals("418:17:23:7")) {
                        throw new AssertionError(out);
                    }
                    System.out.println("STRONG ENTRY OK");
                }

                private static int direct(int x) {
                    int r = x;
                    for (int i = 0; i < 4; i++) {
                        r = (r * 3) ^ i;
                    }
                    return r + 17;
                }

                public final int finalValue(int x) {
                    return x + base * 5;
                }

                private static int lambdaValue(int x) {
                    return x * 2 + 1;
                }

                static final class ReflectTarget {
                    private int v;

                    private ReflectTarget(int v) {
                        this.v = v;
                    }

                    private void add() {
                        v += 4;
                    }

                    int value() {
                        return v;
                    }
                }
            }
            """;
    }
}
