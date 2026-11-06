package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises flow-keyed numeric constant obfuscation with CFF enabled. The
 * fixture covers bytecode push forms, {@code iinc}, static ConstantValue fields,
 * and all primitive numeric widths.
 */
public class JvmConstantObfuscationIntegrationTest {
    private static final String BASE_REFRESH_DESC = "(IIIIII)J";

    @Test
    void derivedNumericMaterialClassifierRejectsDirectAndSelfCancelingShapes() {
        InsnList derivedInt = new InsnList();
        JvmPassBytecode.pushDerivedIntMaterial(derivedInt, 3, 0x434F4E53544A5345L, 0x4E554D494E543031L);
        AbstractInsnNode[] derivedIntInsns = derivedInt.toArray();
        assertTrue(isProtectedNumericMaterial(derivedIntInsns, 0, derivedIntInsns.length));
        assertNoDirectLargeProtectedNumericMaterial(derivedIntInsns, 0, derivedIntInsns.length);
        assertNoSelfCancelingDerivedNumericMaterial(derivedIntInsns, 0, derivedIntInsns.length);

        InsnList derivedLong = new InsnList();
        JvmPassBytecode.pushDerivedLongMaterial(derivedLong, 4, 0x434F4E53544A5346L, 0x4E554D4C4F4E4731L);
        AbstractInsnNode[] derivedLongInsns = derivedLong.toArray();
        assertTrue(isProtectedNumericMaterial(derivedLongInsns, 0, derivedLongInsns.length));
        assertNoDirectLargeProtectedNumericMaterial(derivedLongInsns, 0, derivedLongInsns.length);
        assertNoSelfCancelingDerivedNumericMaterial(derivedLongInsns, 0, derivedLongInsns.length);

        InsnList directLarge = new InsnList();
        directLarge.add(new LdcInsnNode(0x6A09E667));
        AbstractInsnNode[] directLargeInsns = directLarge.toArray();
        assertFalse(isProtectedNumericMaterial(directLargeInsns, 0, directLargeInsns.length));
        assertThrows(
            AssertionError.class,
            () -> assertNoDirectLargeProtectedNumericMaterial(directLargeInsns, 0, directLargeInsns.length)
        );

        InsnList xorSelfCancel = new InsnList();
        xorSelfCancel.add(new VarInsnNode(Opcodes.ILOAD, 2));
        JvmPassBytecode.pushInt(xorSelfCancel, 0x13579BDF);
        xorSelfCancel.add(new InsnNode(Opcodes.IXOR));
        JvmPassBytecode.pushInt(xorSelfCancel, 0x13579BDF);
        xorSelfCancel.add(new InsnNode(Opcodes.IXOR));
        AbstractInsnNode[] xorSelfCancelInsns = xorSelfCancel.toArray();
        assertFalse(isProtectedNumericMaterial(xorSelfCancelInsns, 0, xorSelfCancelInsns.length));
        assertThrows(
            AssertionError.class,
            () -> assertNoSelfCancelingDerivedNumericMaterial(
                xorSelfCancelInsns,
                0,
                xorSelfCancelInsns.length
            )
        );

        InsnList inversePair = new InsnList();
        inversePair.add(new VarInsnNode(Opcodes.ILOAD, 2));
        JvmPassBytecode.pushInt(inversePair, 0x2468ACE0);
        inversePair.add(new InsnNode(Opcodes.IADD));
        JvmPassBytecode.pushInt(inversePair, 0x2468ACE0);
        inversePair.add(new InsnNode(Opcodes.ISUB));
        AbstractInsnNode[] inversePairInsns = inversePair.toArray();
        assertFalse(isProtectedNumericMaterial(inversePairInsns, 0, inversePairInsns.length));
        assertThrows(
            AssertionError.class,
            () -> assertNoSelfCancelingDerivedNumericMaterial(inversePairInsns, 0, inversePairInsns.length)
        );
    }

    @Test
    void constantObfuscationCoversJvmNumericShapesWithCff() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-constants"));
        Path source = work.resolve("ConstantShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("constant-shapes.jar");
        writeJar(inputJar, classes, "ConstantShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("constant-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("CONSTANT SHAPES OK"), obfuscated);
        assertNumericConstantValuesMovedToClinit(outputJar);
        assertStaticNumericMaterialIsFragmented(outputJar);
        assertFlowKeyDecodeUsed(outputJar);
        assertPrimitiveArrayPayloadsEncrypted(outputJar);
        assertConstantLiveWordConsumesDataDigest(outputJar);
        assertProtectedIntegerDecodeMaterialIsDerived(outputJar);
        assertProtectedLongDecodeMaterialIsDerived(outputJar);
        assertProtectedFloatingDecodeMaterialIsDerived(outputJar);
        assertProtectedNumericHelperConsumesRawBase(outputJar);
    }

    @Test
    void staticPrimitiveArrayTablesAreNotReflectablePlaintextWithIndy() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-static-array-material"));
        Path source = work.resolve("StaticArrayTables.java");
        Files.writeString(source, staticArrayTablesSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("static-array-tables.jar");
        writeJar(inputJar, classes, "StaticArrayTables");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("static-array-tables-obf.jar");
        runObfuscationWithInvokeDynamic(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STATIC ARRAY TABLES OK"), obfuscated);
        assertStaticArrayTablesNotReflectablePlaintext(outputJar);
    }

    @Test
    void staticPrimitiveArrayReferenceSemanticsAreNotMaterializedWithIndy() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-static-array-reference-semantics"));
        Path source = work.resolve("StaticArrayReferenceSemantics.java");
        Files.writeString(source, staticArrayReferenceSemanticsSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("static-array-reference-semantics.jar");
        writeJar(inputJar, classes, "StaticArrayReferenceSemantics");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("static-array-reference-semantics-obf.jar");
        runObfuscationWithInvokeDynamic(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STATIC ARRAY REFERENCE SEMANTICS OK"), obfuscated);
    }

    @Test
    void staticPrimitiveArrayDynamicFieldAccessIsNotMaterializedWithIndy() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-static-array-dynamic-access"));
        Path source = work.resolve("StaticArrayDynamicFieldAccess.java");
        Files.writeString(source, staticArrayDynamicFieldAccessSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("static-array-dynamic-access.jar");
        writeJar(inputJar, classes, "StaticArrayDynamicFieldAccess");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("static-array-dynamic-access-obf.jar");
        runObfuscationWithInvokeDynamic(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STATIC ARRAY DYNAMIC ACCESS OK"), obfuscated);
    }

    @Test
    void staticPrimitiveArrayUnreflectFieldAccessIsNotMaterializedWithIndy() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-static-array-unreflect-access"));
        Path providerSource = work.resolve("StaticArrayUnreflectFieldProvider.java");
        Path source = work.resolve("StaticArrayUnreflectAccess.java");
        Files.writeString(providerSource, staticArrayUnreflectFieldProviderSourceText(), StandardCharsets.UTF_8);
        Files.writeString(source, staticArrayUnreflectAccessSourceText(), StandardCharsets.UTF_8);

        Path providerClasses = Files.createDirectories(work.resolve("provider-classes"));
        run(List.of("javac", "-d", providerClasses.toString(), providerSource.toString()), Duration.ofSeconds(30));

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(
            List.of(
                "javac",
                "-cp",
                providerClasses.toString(),
                "-d",
                classes.toString(),
                source.toString()
            ),
            Duration.ofSeconds(30)
        );

        Path inputJar = work.resolve("static-array-unreflect-access.jar");
        writeJar(inputJar, classes, "StaticArrayUnreflectAccess");
        String original = runClass(inputJar, providerClasses, "StaticArrayUnreflectAccess");

        Path outputJar = work.resolve("static-array-unreflect-access-obf.jar");
        runObfuscationWithInvokeDynamic(inputJar, outputJar);
        String obfuscated = runClass(outputJar, providerClasses, "StaticArrayUnreflectAccess");

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STATIC ARRAY UNREFLECT ACCESS OK"), obfuscated);
        assertStaticIntArrayFieldPreserved(outputJar, "StaticArrayUnreflectAccess", "TABLE", new int[] {3, 5, 8});
    }

    @Test
    void staticPrimitiveArrayCondyFieldProtocolIsNotMaterializedWithIndy() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-static-array-condy-access"));

        Path classes = Files.createDirectories(work.resolve("classes"));
        Files.write(classes.resolve("StaticArrayCondyAccess.class"), staticArrayCondyAccessClassBytes());

        Path inputJar = work.resolve("static-array-condy-access.jar");
        writeJar(inputJar, classes, "StaticArrayCondyAccess");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("static-array-condy-access-obf.jar");
        runObfuscationWithInvokeDynamic(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STATIC ARRAY CONDY ACCESS OK"), obfuscated);
        assertStaticIntArrayFieldPreserved(outputJar, "StaticArrayCondyAccess", "TABLE", new int[] {3, 5, 8});
    }

    @Test
    void staticPrimitiveArrayCustomIndyFieldProtocolIsNotMaterializedWithIndy() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-static-array-indy-protocol"));

        Path classes = Files.createDirectories(work.resolve("classes"));
        Files.write(classes.resolve("StaticArrayIndyProtocolAccess.class"), staticArrayIndyProtocolAccessClassBytes());

        Path inputJar = work.resolve("static-array-indy-protocol.jar");
        writeJar(inputJar, classes, "StaticArrayIndyProtocolAccess");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("static-array-indy-protocol-obf.jar");
        runObfuscationWithInvokeDynamic(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STATIC ARRAY INDY PROTOCOL OK"), obfuscated);
        assertStaticIntArrayFieldPreserved(outputJar, "StaticArrayIndyProtocolAccess", "TABLE", new int[] {3, 5, 8});
    }

    @Test
    void staticPrimitiveArrayOriginalReflectionGuardRunsBeforeIndyMutation() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-static-array-original-reflection"));
        Path source = work.resolve("StaticArrayOriginalReflection.java");
        Files.writeString(source, staticArrayOriginalReflectionSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("static-array-original-reflection.jar");
        writeJar(inputJar, classes, "StaticArrayOriginalReflection");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("static-array-original-reflection-obf.jar");
        runObfuscationWithInvokeDynamic(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STATIC ARRAY ORIGINAL REFLECTION OK"), obfuscated);
    }

    private void runObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("constantObfuscation", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x1234ABCDL);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void runObfuscationWithInvokeDynamic(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("invokeDynamic", new TransformConfig(true, 1.0));
        transforms.put("constantObfuscation", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x1234ABCDL);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void assertStaticArrayTablesNotReflectablePlaintext(Path jar) throws Exception {
        try (URLClassLoader loader = new URLClassLoader(
            new java.net.URL[] { jar.toUri().toURL() },
            ClassLoader.getPlatformClassLoader()
        )) {
            Class<?> clazz = Class.forName("StaticArrayTables", true, loader);
            Method main = clazz.getMethod("main", String[].class);
            main.invoke(null, (Object) new String[0]);

            int[] mask = {49, 199, 90, 13, 132, 34, 225, 107};
            int[] check = {81, 98, 218, 155, 56, 108, 149, 118};
            byte[] salt = {66, 19, 55, 33, -64, 90, 126, 9};
            int matchedPlaintextTables = 0;
            for (Field field : clazz.getDeclaredFields()) {
                field.setAccessible(true);
                Object value = field.get(null);
                if (value instanceof int[] ints &&
                    (Arrays.equals(mask, ints) || Arrays.equals(check, ints))) {
                    matchedPlaintextTables++;
                } else if (value instanceof byte[] bytes && Arrays.equals(salt, bytes)) {
                    matchedPlaintextTables++;
                }
            }
            assertEquals(0, matchedPlaintextTables, "static primitive tables remained reflectable plaintext");
        }
    }

    private void assertStaticIntArrayFieldPreserved(
        Path jar,
        String className,
        String fieldName,
        int[] expected
    ) throws Exception {
        try (URLClassLoader loader = new URLClassLoader(
            new java.net.URL[] { jar.toUri().toURL() },
            ClassLoader.getPlatformClassLoader()
        )) {
            Class<?> clazz = Class.forName(className, true, loader);
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            Object value = field.get(null);
            assertTrue(value instanceof int[], "static primitive array field was not preserved");
            assertTrue(Arrays.equals(expected, (int[]) value), "static primitive array field changed value");
        }
    }

    private void assertNumericConstantValuesMovedToClinit(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        for (FieldNode field : clazz.asmNode().fields) {
            if (field.name.startsWith("STATIC_")) {
                assertEquals(null, field.value, "numeric ConstantValue remained on field " + field.name);
            }
        }
    }

    private void assertStaticNumericMaterialIsFragmented(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        MethodNode clinit = null;
        for (MethodNode method : clazz.asmNode().methods) {
            if ("<clinit>".equals(method.name)) {
                clinit = method;
                break;
            }
        }
        assertTrue(clinit != null && clinit.instructions != null, "constant fixture did not retain <clinit>");

        AbstractInsnNode[] insns = clinit.instructions.toArray();
        int checked = 0;
        for (int i = 0; i < insns.length; i++) {
            if (!(insns[i] instanceof FieldInsnNode put) ||
                put.getOpcode() != Opcodes.PUTSTATIC ||
                !"ConstantShapes".equals(put.owner) ||
                !put.name.startsWith("STATIC_")) {
                continue;
            }
            int start = previousStaticCarrierLoad(insns, i, 260);
            assertTrue(start >= 0, "static numeric material did not load class carrier for " + put.name);
            assertFalse(
                hasDirectLargeStaticNumericMaterial(insns, start, i + 1),
                "static numeric material retained direct large ldc for " + put.name
            );
            assertTrue(hasOpcode(insns, Opcodes.AALOAD, start, i), "static numeric material did not select carrier slot for " + put.name);
            assertTrue(hasIntArrayCast(insns, start, i), "static numeric material did not cast carrier slot to [I for " + put.name);
            assertTrue(hasOpcode(insns, Opcodes.IALOAD, start, i), "static numeric material did not read class key word for " + put.name);
            assertTrue(hasOpcode(insns, Opcodes.ISHL, start, i), "static numeric material did not assemble high fragments for " + put.name);
            assertTrue(hasOpcode(insns, Opcodes.IAND, start, i), "static numeric material did not mask low fragments for " + put.name);
            assertTrue(hasOpcode(insns, Opcodes.IOR, start, i), "static numeric material did not rejoin fragments for " + put.name);
            if ("J".equals(put.desc) || "D".equals(put.desc)) {
                assertTrue(hasOpcode(insns, Opcodes.LSHL, start, i), "static long material did not shift high word for " + put.name);
                assertTrue(hasOpcode(insns, Opcodes.LAND, start, i), "static long material did not mask low word for " + put.name);
                assertTrue(hasOpcode(insns, Opcodes.LOR, start, i), "static long material did not join words for " + put.name);
            }
            checked++;
        }
        assertEquals(4, checked, "constant fixture did not check every static numeric field");
    }

    private void assertFlowKeyDecodeUsed(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        boolean sawFloatDecode = false;
        boolean sawDoubleDecode = false;
        boolean sawEncryptedNumericLdc = false;
        boolean sawIntegerRotateDecode = false;
        for (var method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            boolean generatedHelper = method.name.startsWith("__neko_");
            for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode call
                        && "java/lang/Float".equals(call.owner)
                        && "intBitsToFloat".equals(call.name)) {
                    sawFloatDecode = true;
                }
                if (insn instanceof MethodInsnNode call
                        && "java/lang/Double".equals(call.owner)
                        && "longBitsToDouble".equals(call.name)) {
                    sawDoubleDecode = true;
                }
                if (insn instanceof MethodInsnNode call
                        && "java/lang/Integer".equals(call.owner)
                        && ("rotateLeft".equals(call.name) || "rotateRight".equals(call.name))
                        && !generatedHelper) {
                    sawIntegerRotateDecode = true;
                }
                if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Number) {
                    sawEncryptedNumericLdc = true;
                }
            }
        }
        assertTrue(sawFloatDecode, "float constants should decode from integer bits");
        assertTrue(sawDoubleDecode, "double constants should decode from long bits");
        assertTrue(sawEncryptedNumericLdc, "numeric literals should be replaced by encrypted numeric material");
        assertFalse(sawIntegerRotateDecode, "constant decode must not use rotateLeft/rotateRight self-cancelling masks");
    }

    private void assertPrimitiveArrayPayloadsEncrypted(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        for (var method : clazz.asmNode().methods) {
            if (!"arrays".equals(method.name) || method.instructions == null) continue;
            for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                Long plaintext = storeLiteralBits(insn.getOpcode(), previousReal(insn.getPrevious()));
                assertFalse(
                    plaintext != null && fixtureArrayPayload(insn.getOpcode(), plaintext),
                    "primitive array store retained plaintext payload before opcode " + insn.getOpcode()
                );
            }
        }
    }

    private void assertConstantLiveWordConsumesDataDigest(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        int checkedBaseLoads = 0;
        int checkedCompactCalls = 0;
        for (MethodNode method : clazz.asmNode().methods) {
            if (method.instructions == null || method.instructions.size() == 0) continue;
            if (method.name.startsWith("__neko_")) continue;
            AbstractInsnNode[] insns = method.instructions.toArray();
            for (int i = 0; i < insns.length; i++) {
                ConstantDecodeProof proof = constantDecodeProofAtRawStore(insns, i);
                if (proof != null) {
                    int limit = nextConstantRawStore(insns, i + 1, Math.min(insns.length, i + 760));
                    if (limit < 0) limit = Math.min(insns.length, i + 760);
                    int compactCall = firstCompactConstantDecodeCall(insns, i + 1, limit);
                    if (compactCall >= 0) {
                        assertTrue(
                            compactCallReceivesRuntimeDerivedMaterial(insns, compactCall, proof),
                            "compact constant decode call did not receive runtime-derived data material in " +
                                method.name + method.desc
                        );
                        checkedCompactCalls++;
                    } else {
                        assertTrue(
                            inlineDecodeReceivesRuntimeDerivedMaterial(insns, proof, limit),
                            "inline constant decode did not consume runtime-derived data material in " +
                                method.name + method.desc
                        );
                    }
                    checkedBaseLoads++;
                } else if (isCompactConstantDecodeCall(insns[i])) {
                    assertTrue(
                        compactCallReceivesRuntimeDerivedMaterial(
                            insns,
                            i,
                            previousConstantDecodeProof(insns, i)
                        ),
                        "compact constant decode call did not receive runtime-derived data material in " +
                            method.name + method.desc
                    );
                    checkedCompactCalls++;
                }
            }
        }
        assertTrue(
            checkedBaseLoads > 0,
            "constant fixture did not expose protected numeric decode base loads"
        );
        assertTrue(
            checkedCompactCalls > 0,
            "constant fixture did not expose compact protected numeric decode calls"
        );
    }

    private void assertProtectedIntegerDecodeMaterialIsDerived(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        MethodNode ints = null;
        for (MethodNode method : clazz.asmNode().methods) {
            if ("ints".equals(method.name) && method.desc.endsWith(")I")) {
                ints = method;
                break;
            }
        }
        assertTrue(ints != null && ints.instructions != null, "constant fixture did not retain ints() method");

        AbstractInsnNode[] insns = ints.instructions.toArray();
        int checkedDecodeCalls = 0;
        for (int i = 0; i < insns.length; i++) {
            assertFalse(insns[i].getOpcode() == Opcodes.IINC, "iinc survived protected integer replacement");
            if (!isNumericIntHelperCall(insns[i])) continue;
            assertTrue(isProtectedIntHelperCall(insns[i]), "protected integer decode used legacy compact helper");
            assertTrue(
                protectedCompactCallReceivesRuntimeDerivedMaterial(
                    insns,
                    i,
                    previousConstantDecodeProof(insns, i)
                ),
                "protected integer decode call was not live-derived in ints()"
            );
            checkedDecodeCalls++;
        }
        assertTrue(
            checkedDecodeCalls > 0,
            "constant fixture did not expose protected integer decode slices in ints()"
        );
    }

    private void assertProtectedLongDecodeMaterialIsDerived(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        MethodNode longs = null;
        for (MethodNode method : clazz.asmNode().methods) {
            if ("longs".equals(method.name) && method.desc.endsWith(")J")) {
                longs = method;
                break;
            }
        }
        assertTrue(longs != null && longs.instructions != null, "constant fixture did not retain longs() method");

        AbstractInsnNode[] insns = longs.instructions.toArray();
        int checkedCompositions = 0;
        for (int i = 0; i < insns.length; i++) {
            if (insns[i].getOpcode() != Opcodes.LOR) continue;
            int lowHelper = previousNumericIntHelperCall(insns, i, 96);
            if (lowHelper < 0) continue;
            int highHelper = previousNumericIntHelperCall(insns, lowHelper, 320);
            if (highHelper < 0) continue;
            if (!hasOpcode(insns, Opcodes.LSHL, highHelper, lowHelper)) continue;
            if (!hasOpcode(insns, Opcodes.LAND, lowHelper, i + 1)) continue;
            assertTrue(
                isProtectedIntHelperCall(insns[highHelper]),
                "protected long high word used legacy compact helper"
            );
            assertTrue(
                isProtectedIntHelperCall(insns[lowHelper]),
                "protected long low word used legacy compact helper"
            );

            ConstantDecodeProof highProof = previousConstantDecodeProof(insns, highHelper);
            ConstantDecodeProof lowProof = previousConstantDecodeProof(insns, lowHelper);
            assertTrue(
                protectedCompactCallReceivesRuntimeDerivedMaterial(insns, highHelper, highProof),
                "protected long high word was not live-derived"
            );
            assertTrue(
                protectedCompactCallReceivesRuntimeDerivedMaterial(insns, lowHelper, lowProof),
                "protected long low word was not live-derived"
            );
            assertTrue(
                !containsLargeLongLdc(insns, highHelper, i + 1),
                "protected long reconstruction retained a direct large long LdcInsnNode"
            );
            assertNoSelfCancelingDerivedNumericMaterial(insns, highHelper, i + 1);
            checkedCompositions++;
        }
        assertTrue(checkedCompositions > 0, "constant fixture did not expose protected long compositions");
    }

    private void assertProtectedFloatingDecodeMaterialIsDerived(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        MethodNode floats = null;
        MethodNode doubles = null;
        for (MethodNode method : clazz.asmNode().methods) {
            if ("floats".equals(method.name) && method.desc.endsWith(")F")) {
                floats = method;
            } else if ("doubles".equals(method.name) && method.desc.endsWith(")D")) {
                doubles = method;
            }
        }
        assertTrue(floats != null && floats.instructions != null, "constant fixture did not retain floats() method");
        assertTrue(doubles != null && doubles.instructions != null, "constant fixture did not retain doubles() method");

        AbstractInsnNode[] floatInsns = floats.instructions.toArray();
        int checkedFloats = 0;
        for (int i = 0; i < floatInsns.length; i++) {
            if (!(floatInsns[i] instanceof MethodInsnNode call)
                || !"java/lang/Float".equals(call.owner)
                || !"intBitsToFloat".equals(call.name)) {
                continue;
            }
            int helper = previousNumericIntHelperCall(floatInsns, i, 128);
            if (helper < 0) continue;
            assertTrue(isProtectedIntHelperCall(floatInsns[helper]), "float raw bits used legacy compact helper");
            assertTrue(
                protectedCompactCallReceivesRuntimeDerivedMaterial(
                    floatInsns,
                    helper,
                    previousConstantDecodeProof(floatInsns, helper)
                ),
                "protected float raw bits were not live-derived"
            );
            checkedFloats++;
        }
        assertTrue(checkedFloats > 0, "constant fixture did not expose protected float raw-bit decodes");

        AbstractInsnNode[] doubleInsns = doubles.instructions.toArray();
        int checkedDoubles = 0;
        for (int i = 0; i < doubleInsns.length; i++) {
            if (!(doubleInsns[i] instanceof MethodInsnNode call)
                || !"java/lang/Double".equals(call.owner)
                || !"longBitsToDouble".equals(call.name)) {
                continue;
            }
            int lor = previousOpcodeIndex(doubleInsns, i, Opcodes.LOR, 32);
            if (lor < 0) continue;
            int lowHelper = previousNumericIntHelperCall(doubleInsns, lor, 96);
            if (lowHelper < 0) continue;
            int highHelper = previousNumericIntHelperCall(doubleInsns, lowHelper, 320);
            if (highHelper < 0) continue;
            assertTrue(isProtectedIntHelperCall(doubleInsns[highHelper]), "double high raw word used legacy helper");
            assertTrue(isProtectedIntHelperCall(doubleInsns[lowHelper]), "double low raw word used legacy helper");
            assertTrue(
                protectedCompactCallReceivesRuntimeDerivedMaterial(
                    doubleInsns,
                    highHelper,
                    previousConstantDecodeProof(doubleInsns, highHelper)
                ),
                "protected double high raw word was not live-derived"
            );
            assertTrue(
                protectedCompactCallReceivesRuntimeDerivedMaterial(
                    doubleInsns,
                    lowHelper,
                    previousConstantDecodeProof(doubleInsns, lowHelper)
                ),
                "protected double low raw word was not live-derived"
            );
            assertTrue(
                !containsLargeLongLdc(doubleInsns, highHelper, i + 1),
                "protected double raw-bit reconstruction retained a direct large long LdcInsnNode"
            );
            checkedDoubles++;
        }
        assertTrue(checkedDoubles > 0, "constant fixture did not expose protected double raw-bit decodes");
    }

    private void assertProtectedNumericHelperConsumesRawBase(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("ConstantShapes");
        Map<String, MethodNode> methodsByName = new LinkedHashMap<>();
        for (MethodNode method : clazz.asmNode().methods) {
            methodsByName.put(method.name, method);
        }
        int checkedWrappers = 0;
        int checkedFinalizers = 0;
        for (MethodNode method : clazz.asmNode().methods) {
            if (!method.name.startsWith("__neko_num_ip")) continue;
            assertEquals("(IIIII)I", method.desc, "protected numeric helper descriptor drifted");
            assertTrue(method.instructions != null, "protected numeric helper had no instructions");
            AbstractInsnNode[] insns = method.instructions.toArray();
            assertTrue(
                varLoadCount(insns, 0, 0, insns.length) >= 1,
                "protected numeric wrapper did not consume raw base"
            );
            assertTrue(hasOpcode(insns, Opcodes.ISHL, 0, insns.length), "protected numeric wrapper lacked fragment high-word assembly");
            assertFalse(hasOpcode(insns, Opcodes.I2C, 0, insns.length), "protected numeric wrapper retained helper-side I2C low-word masking");
            assertFalse(hasOpcode(insns, Opcodes.IAND, 0, insns.length), "protected numeric wrapper retained helper-side IAND low-word masking");
            assertTrue(hasOpcode(insns, Opcodes.IOR, 0, insns.length), "protected numeric wrapper lacked fragment rejoin");
            MethodInsnNode finalizerCall = protectedNumericFinalizerCall(insns);
            assertTrue(finalizerCall != null, "protected numeric wrapper did not call finalizer");

            MethodNode finalizer = methodsByName.get(finalizerCall.name);
            assertTrue(finalizer != null && finalizer.instructions != null, "protected numeric finalizer was missing");
            assertEquals("(III)I", finalizer.desc, "protected numeric finalizer descriptor drifted");
            AbstractInsnNode[] finalizerInsns = finalizer.instructions.toArray();
            assertTrue(
                varLoadCount(finalizerInsns, 0, 0, finalizerInsns.length) >= 3,
                "protected numeric finalizer did not consume raw base"
            );
            assertTrue(
                hasVarStore(finalizerInsns, 3, 0, finalizerInsns.length),
                "protected numeric finalizer did not decode seed into a local"
            );
            assertTrue(hasOpcode(finalizerInsns, Opcodes.IMUL, 0, finalizerInsns.length), "protected numeric finalizer lacked multiply mix");
            assertTrue(hasOpcode(finalizerInsns, Opcodes.IUSHR, 0, finalizerInsns.length), "protected numeric finalizer lacked shift mix");
            assertTrue(hasOpcode(finalizerInsns, Opcodes.IXOR, 0, finalizerInsns.length), "protected numeric finalizer lacked xor mix");
            checkedWrappers++;
            checkedFinalizers++;
        }
        assertTrue(checkedWrappers > 0, "constant fixture did not expose protected numeric wrappers");
        assertTrue(checkedFinalizers > 0, "constant fixture did not expose protected numeric finalizers");
    }

    private boolean fixtureArrayPayload(int storeOpcode, long bits) {
        return switch (storeOpcode) {
            case Opcodes.BASTORE -> bits == -128L || bits == 0L || bits == 1L || bits == 127L;
            case Opcodes.SASTORE -> bits == -30000L || bits == 12345L;
            case Opcodes.CASTORE -> bits == 65L || bits == 0x1234L;
            case Opcodes.IASTORE -> bits == -7L || bits == 0L || bits == 42L || bits == 123456789L;
            case Opcodes.LASTORE -> bits == 0x1020304050607080L || bits == -5L || bits == 9L;
            case Opcodes.FASTORE -> bits == (long) Float.floatToRawIntBits(-1.5f) ||
                bits == (long) Float.floatToRawIntBits(0.25f) ||
                bits == (long) Float.floatToRawIntBits(3.75f);
            case Opcodes.DASTORE -> bits == Double.doubleToRawLongBits(-2.5d) ||
                bits == Double.doubleToRawLongBits(6.5d);
            default -> false;
        };
    }

    private Long storeLiteralBits(int storeOpcode, AbstractInsnNode valueInsn) {
        if (valueInsn == null) return null;
        return switch (storeOpcode) {
            case Opcodes.BASTORE, Opcodes.SASTORE, Opcodes.CASTORE, Opcodes.IASTORE -> intLiteral(valueInsn);
            case Opcodes.LASTORE -> longLiteral(valueInsn);
            case Opcodes.FASTORE -> floatLiteralBits(valueInsn);
            case Opcodes.DASTORE -> doubleLiteralBits(valueInsn);
            default -> null;
        };
    }

    private Long intLiteral(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return (long) (opcode - Opcodes.ICONST_0);
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return (long) ((IntInsnNode) insn).operand;
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) {
            return value.longValue();
        }
        return null;
    }

    private Long longLiteral(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.LCONST_0) return 0L;
        if (opcode == Opcodes.LCONST_1) return 1L;
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Long value) {
            return value;
        }
        return null;
    }

    private Long floatLiteralBits(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.FCONST_0 && opcode <= Opcodes.FCONST_2) {
            return (long) Float.floatToRawIntBits((float) (opcode - Opcodes.FCONST_0));
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Float value) {
            return (long) Float.floatToRawIntBits(value);
        }
        return null;
    }

    private Long doubleLiteralBits(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.DCONST_0) return Double.doubleToRawLongBits(0.0d);
        if (opcode == Opcodes.DCONST_1) return Double.doubleToRawLongBits(1.0d);
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Double value) {
            return Double.doubleToRawLongBits(value);
        }
        return null;
    }

    private int previousStaticCarrierLoad(AbstractInsnNode[] insns, int fromExclusive, int maxDistance) {
        int start = Math.max(0, fromExclusive - maxDistance);
        int result = -1;
        for (int i = start; i < fromExclusive; i++) {
            if (insns[i] instanceof FieldInsnNode get &&
                get.getOpcode() == Opcodes.GETSTATIC &&
                "ConstantShapes".equals(get.owner) &&
                "[Ljava/lang/Object;".equals(get.desc)) {
                result = result < 0 ? i : result;
            }
        }
        return result;
    }

    private boolean hasIntArrayCast(AbstractInsnNode[] insns, int startInclusive, int limitExclusive) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof TypeInsnNode cast &&
                cast.getOpcode() == Opcodes.CHECKCAST &&
                "[I".equals(cast.desc)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasDirectLargeStaticNumericMaterial(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (!(insns[i] instanceof LdcInsnNode ldc) || !(ldc.cst instanceof Number value)) continue;
            if (value instanceof Integer intValue &&
                intValue >= Short.MIN_VALUE &&
                intValue <= Short.MAX_VALUE) {
                continue;
            }
            return true;
        }
        return false;
    }

    private AbstractInsnNode previousReal(AbstractInsnNode insn) {
        AbstractInsnNode cursor = insn;
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getPrevious();
        }
        return cursor;
    }

    private int previousRealIndex(AbstractInsnNode[] insns, int fromExclusive) {
        for (int i = fromExclusive - 1; i >= 0; i--) {
            if (insns[i].getOpcode() >= 0) return i;
        }
        return -1;
    }

    private int nextRealIndex(AbstractInsnNode[] insns, int fromInclusive, int limitExclusive) {
        for (int i = fromInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i].getOpcode() >= 0) return i;
        }
        return -1;
    }

    private ConstantDecodeProof constantDecodeProofAtRawStore(AbstractInsnNode[] insns, int rawStoreIndex) {
        if (!(insns[rawStoreIndex] instanceof VarInsnNode rawStore)
            || rawStore.getOpcode() != Opcodes.ISTORE) {
            return null;
        }
        int dataStoreIndex = previousRealIndex(insns, rawStoreIndex);
        if (dataStoreIndex < 0) return null;
        if (!(insns[dataStoreIndex] instanceof VarInsnNode dataStore)
            || dataStore.getOpcode() != Opcodes.ISTORE
            || dataStore.var == rawStore.var) {
            return null;
        }
        int dataLoadIndex = previousRealIndex(insns, dataStoreIndex);
        if (dataLoadIndex < 0) return null;
        if (!(insns[dataLoadIndex] instanceof VarInsnNode dataLoad)
            || dataLoad.getOpcode() != Opcodes.ILOAD
            || dataLoad.var == rawStore.var) {
            return null;
        }
        int baseStoreIndex = previousRealIndex(insns, dataLoadIndex);
        if (baseStoreIndex < 0) return null;
        if (!(insns[baseStoreIndex] instanceof VarInsnNode baseStore)
            || baseStore.getOpcode() != Opcodes.ISTORE
            || baseStore.var == rawStore.var
            || baseStore.var == dataLoad.var) {
            return packedBaseRefreshProofAtRawStore(insns, rawStoreIndex, rawStore, dataStore, dataLoadIndex);
        }
        int currentDataLoad = previousVarLoadIndex(
            insns,
            dataLoad.var,
            Math.max(0, baseStoreIndex - 120),
            baseStoreIndex
        );
        if (currentDataLoad < 0) {
            return null;
        }
        if (!hasNonlinearMixAfter(insns, currentDataLoad + 1, baseStoreIndex)
            && !baseRefreshHelperReceivesRuntimeData(insns, currentDataLoad, baseStoreIndex)) {
            return null;
        }
        return new ConstantDecodeProof(rawStore.var, dataLoad.var, rawStoreIndex);
    }

    private ConstantDecodeProof packedBaseRefreshProofAtRawStore(
        AbstractInsnNode[] insns,
        int rawStoreIndex,
        VarInsnNode rawStore,
        VarInsnNode dataStore,
        int dataLoadIndex
    ) {
        int helperIndex = -1;
        for (int i = Math.max(0, rawStoreIndex - 64); i < rawStoreIndex; i++) {
            if (insns[i] instanceof MethodInsnNode call
                && call.name.startsWith("__neko_num_base")
                && BASE_REFRESH_DESC.equals(call.desc)) {
                helperIndex = i;
            }
        }
        if (helperIndex < 0) return null;
        int liveLoads = 0;
        for (int i = Math.max(0, helperIndex - 40); i < helperIndex; i++) {
            if (insns[i] instanceof VarInsnNode load && load.getOpcode() == Opcodes.ILOAD) {
                liveLoads++;
            }
        }
        if (liveLoads < 5) return null;
        if (!hasOpcode(insns, Opcodes.DUP2, helperIndex + 1, rawStoreIndex)
            || !hasOpcode(insns, Opcodes.LUSHR, helperIndex + 1, rawStoreIndex)
            || !hasOpcode(insns, Opcodes.L2I, helperIndex + 1, rawStoreIndex)) {
            return null;
        }
        boolean sawBaseStore = false;
        for (int i = helperIndex + 1; i < dataLoadIndex; i++) {
            if (insns[i] instanceof VarInsnNode store
                && store.getOpcode() == Opcodes.ISTORE
                && store.var != rawStore.var
                && store.var != dataStore.var) {
                sawBaseStore = true;
                break;
            }
        }
        if (!sawBaseStore) return null;
        return new ConstantDecodeProof(rawStore.var, dataStore.var, rawStoreIndex);
    }

    private boolean baseRefreshHelperReceivesRuntimeData(
        AbstractInsnNode[] insns,
        int currentDataLoad,
        int baseStoreIndex
    ) {
        for (int i = currentDataLoad + 1; i < baseStoreIndex; i++) {
            if (!(insns[i] instanceof MethodInsnNode call)
                || !call.name.startsWith("__neko_num_base")
                || !BASE_REFRESH_DESC.equals(call.desc)) {
                continue;
            }
            int liveLoads = 0;
            for (int j = Math.max(0, i - 40); j < i; j++) {
                if (insns[j] instanceof VarInsnNode load && load.getOpcode() == Opcodes.ILOAD) {
                    liveLoads++;
                }
            }
            return liveLoads >= 5;
        }
        return false;
    }

    private boolean isCompactConstantDecodeCall(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call
            && call.name.startsWith("__neko_num_i")
            && ("(III)I".equals(call.desc) || "(IIIII)I".equals(call.desc));
    }

    private boolean compactCallReceivesRuntimeDerivedMaterial(
        AbstractInsnNode[] insns,
        int callIndex,
        ConstantDecodeProof proof
    ) {
        if (compactCallUsesRecentBaseHelper(insns, callIndex)) {
            return true;
        }
        if (proof == null) return false;
        if (compactCallUsesRefreshedBaseHelper(insns, callIndex, proof)) {
            return true;
        }
        if (insns[callIndex] instanceof MethodInsnNode call && call.name.startsWith("__neko_num_ip")) {
            return protectedCompactCallReceivesRuntimeDerivedMaterial(insns, callIndex, proof);
        }
        int seedIndex = previousRealIndex(insns, callIndex);
        if (seedIndex < 0) return false;
        int swapIndex;
        if (intLiteral(insns[seedIndex]) != null) {
            swapIndex = previousRealIndex(insns, seedIndex);
        } else {
            int seedStart = previousDerivedIntMaterialStart(insns, proof.rawBaseLocal, callIndex, 32);
            if (seedStart < 0) return false;
            swapIndex = previousRealIndex(insns, seedStart);
        }
        if (swapIndex < 0 || insns[swapIndex].getOpcode() != Opcodes.SWAP) return false;
        MaterialNoiseProof noise = materialNoiseProof(insns, proof, swapIndex);
        if (noise == null) return false;
        int helperBoundStart = previousBoundBaseStart(insns, proof.rawBaseLocal, noise.local, swapIndex, 96);
        if (helperBoundStart < 0) return false;
        int materialEnd = previousRealIndex(insns, helperBoundStart);
        if (materialEnd < 0 || insns[materialEnd].getOpcode() != Opcodes.IXOR) return false;
        if (!materialSliceConsumesRuntimeBoundMask(insns, proof, noise, materialEnd)) {
            return false;
        }
        return boundBaseSliceConsumesNoise(insns, proof.rawBaseLocal, noise.local, helperBoundStart, swapIndex);
    }

    private boolean compactCallUsesRecentBaseHelper(AbstractInsnNode[] insns, int callIndex) {
        for (int i = Math.max(0, callIndex - 240); i < callIndex; i++) {
            if (!(insns[i] instanceof MethodInsnNode call)
                || !call.name.startsWith("__neko_num_base")
                || !BASE_REFRESH_DESC.equals(call.desc)) {
                continue;
            }
            int liveLoads = 0;
            for (int j = Math.max(0, i - 40); j < i; j++) {
                if (insns[j] instanceof VarInsnNode load && load.getOpcode() == Opcodes.ILOAD) {
                    liveLoads++;
                }
            }
            return liveLoads >= 5
                && intLiteralCount(insns, i + 1, callIndex) >= 2
                && selfCancelingNumericMaterialIndex(insns, i + 1, callIndex) < 0;
        }
        return false;
    }

    private boolean compactCallUsesRefreshedBaseHelper(
        AbstractInsnNode[] insns,
        int callIndex,
        ConstantDecodeProof proof
    ) {
        boolean sawRefresh = false;
        for (int i = Math.max(0, proof.rawStoreIndex - 80); i < proof.rawStoreIndex; i++) {
            if (insns[i] instanceof MethodInsnNode call
                && call.name.startsWith("__neko_num_base")
                && BASE_REFRESH_DESC.equals(call.desc)) {
                sawRefresh = true;
                break;
            }
        }
        return sawRefresh
            && varLoadCount(insns, proof.rawBaseLocal, proof.rawStoreIndex + 1, callIndex) >= 1
            && intLiteralCount(insns, proof.rawStoreIndex + 1, callIndex) >= 2
            && selfCancelingNumericMaterialIndex(insns, proof.rawStoreIndex + 1, callIndex) < 0;
    }

    private boolean protectedCompactCallReceivesRuntimeDerivedMaterial(
        AbstractInsnNode[] insns,
        int callIndex,
        ConstantDecodeProof proof
    ) {
        if (proof == null) return false;
        if (!isProtectedIntHelperCall(insns[callIndex])) return false;
        return varLoadCount(insns, proof.rawBaseLocal, proof.rawStoreIndex + 1, callIndex) >= 1
            && !containsLargeNumericLdcOutsideProtectedUnsignedFragments(
                insns,
                proof.rawStoreIndex + 1,
                callIndex
            )
            && intLiteralCount(insns, proof.rawStoreIndex + 1, callIndex) >= 4
            && selfCancelingNumericMaterialIndex(insns, proof.rawStoreIndex + 1, callIndex) < 0;
    }

    private boolean containsLargeNumericLdcOutsideProtectedUnsignedFragments(
        AbstractInsnNode[] insns,
        int startInclusive,
        int callIndex
    ) {
        for (int i = startInclusive; i < callIndex && i < insns.length; i++) {
            if (!(insns[i] instanceof LdcInsnNode) || !isLargeNumericLiteral(insns[i])) {
                continue;
            }
            if (!isProtectedUnsignedFragmentLiteralInWindow(insns, i, i + 1, callIndex + 1)) {
                return true;
            }
        }
        return false;
    }

    private boolean isProtectedUnsignedFragmentLiteralInWindow(
        AbstractInsnNode[] insns,
        int literalIndex,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (isProtectedIntHelperCall(insns[i])
                && isProtectedUnsignedFragmentLiteral(insns, literalIndex, i)) {
                return true;
            }
        }
        return false;
    }

    private boolean isProtectedUnsignedFragmentLiteral(
        AbstractInsnNode[] insns,
        int literalIndex,
        int callIndex
    ) {
        int cursor = callIndex;
        for (int argument = 0; argument < 5; argument++) {
            cursor = previousRealIndex(insns, cursor);
            if (cursor < 0) return false;
            if (cursor != literalIndex) continue;
            Long value = numericLiteralBits(insns[cursor]);
            return argument < 4 && value != null && value >= 0L && value <= 0xFFFFL;
        }
        return false;
    }

    private boolean noUncoveredLargeNumericLdc(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive,
        List<DerivedMaterialWindow> windows
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof LdcInsnNode && isLargeNumericLiteral(insns[i]) && !coveredByWindow(i, windows)) {
                return false;
            }
        }
        return true;
    }

    private boolean containsLargeNumericLdc(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof LdcInsnNode && isLargeNumericLiteral(insns[i])) {
                return true;
            }
        }
        return false;
    }

    private boolean coveredByWindow(int index, List<DerivedMaterialWindow> windows) {
        for (DerivedMaterialWindow window : windows) {
            if (index >= window.startInclusive && index < window.endExclusive) {
                return true;
            }
        }
        return false;
    }

    private int previousNumericIntHelperCall(
        AbstractInsnNode[] insns,
        int fromExclusive,
        int maxDistance
    ) {
        int start = Math.max(0, fromExclusive - maxDistance);
        for (int i = fromExclusive - 1; i >= start; i--) {
            if (isNumericIntHelperCall(insns[i])) {
                return i;
            }
        }
        return -1;
    }

    private int previousOpcodeIndex(
        AbstractInsnNode[] insns,
        int fromExclusive,
        int opcode,
        int maxDistance
    ) {
        int start = Math.max(0, fromExclusive - maxDistance);
        for (int i = fromExclusive - 1; i >= start; i--) {
            if (insns[i].getOpcode() == opcode) {
                return i;
            }
        }
        return -1;
    }

    private boolean isNumericIntHelperCall(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call
            && call.name.startsWith("__neko_num_i")
            && ("(III)I".equals(call.desc) || "(IIIII)I".equals(call.desc));
    }

    private boolean isProtectedIntHelperCall(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call
            && call.name.startsWith("__neko_num_ip")
            && "(IIIII)I".equals(call.desc);
    }

    private MethodInsnNode protectedNumericFinalizerCall(AbstractInsnNode[] insns) {
        for (AbstractInsnNode insn : insns) {
            if (insn instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKESTATIC
                && call.name.startsWith("__neko_num_pf")
                && "(III)I".equals(call.desc)) {
                return call;
            }
        }
        return null;
    }

    private boolean containsLargeLongLdc(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof LdcInsnNode ldc
                && ldc.cst instanceof Long value
                && (value > Short.MAX_VALUE || value < Short.MIN_VALUE)) {
                return true;
            }
        }
        return false;
    }

    private boolean inlineDecodeReceivesRuntimeDerivedMaterial(
        AbstractInsnNode[] insns,
        ConstantDecodeProof proof,
        int limitExclusive
    ) {
        MaterialNoiseProof noise = materialNoiseProof(insns, proof, limitExclusive);
        if (noise == null) return false;
        List<Integer> boundStarts = boundBaseStarts(
            insns,
            proof.rawBaseLocal,
            noise.local,
            noise.storeIndex + 1,
            limitExclusive
        );
        if (boundStarts.size() < 6) return false;
        int materialEnd = previousRealIndex(insns, boundStarts.get(3));
        if (materialEnd < 0 || insns[materialEnd].getOpcode() != Opcodes.IXOR) return false;
        return materialSliceConsumesRuntimeBoundMask(insns, proof, noise, materialEnd)
            && boundBaseSliceConsumesNoise(
                insns,
                proof.rawBaseLocal,
                noise.local,
                boundStarts.get(3),
                boundStarts.get(4)
            )
            && boundBaseSliceConsumesNoise(
                insns,
                proof.rawBaseLocal,
                noise.local,
                boundStarts.get(4),
                boundStarts.get(5)
            )
            && boundBaseSliceConsumesNoise(
                insns,
                proof.rawBaseLocal,
                noise.local,
                boundStarts.get(5),
                limitExclusive
            )
            && hasOpcode(insns, Opcodes.ISUB, boundStarts.get(3), limitExclusive)
            && hasOpcode(insns, Opcodes.IOR, boundStarts.get(3), limitExclusive)
            && hasOpcode(insns, Opcodes.IXOR, boundStarts.get(5), limitExclusive);
    }

    private int firstCompactConstantDecodeCall(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (isCompactConstantDecodeCall(insns[i])) return i;
        }
        return -1;
    }

    private ConstantDecodeProof previousConstantDecodeProof(AbstractInsnNode[] insns, int limitExclusive) {
        int start = Math.max(0, limitExclusive - 760);
        for (int i = limitExclusive - 1; i >= start; i--) {
            ConstantDecodeProof proof = constantDecodeProofAtRawStore(insns, i);
            if (proof != null) return proof;
        }
        return null;
    }

    private int nextConstantRawStore(AbstractInsnNode[] insns, int startInclusive, int limitExclusive) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (constantDecodeProofAtRawStore(insns, i) != null) return i;
        }
        return -1;
    }

    private boolean hasOpcode(
        AbstractInsnNode[] insns,
        int opcode,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i].getOpcode() == opcode) {
                return true;
            }
        }
        return false;
    }

    private boolean hasVarStore(
        AbstractInsnNode[] insns,
        int local,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof VarInsnNode store
                && store.getOpcode() == Opcodes.ISTORE
                && store.var == local) {
                return true;
            }
        }
        return false;
    }

    private static boolean isProtectedNumericMaterial(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        if (hasDirectLargeProtectedNumericMaterial(insns, startInclusive, limitExclusive)) {
            return false;
        }
        if (selfCancelingNumericMaterialIndex(insns, startInclusive, limitExclusive) >= 0) {
            return false;
        }
        boolean sawLiveLoad = false;
        boolean sawMultiply = false;
        boolean sawShift = false;
        boolean sawMix = false;
        int literals = 0;
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            AbstractInsnNode insn = insns[i];
            if (insn instanceof VarInsnNode var
                && (var.getOpcode() == Opcodes.ILOAD || var.getOpcode() == Opcodes.LLOAD)) {
                sawLiveLoad = true;
            }
            if (numericLiteralBits(insn) != null) {
                literals++;
            }
            int opcode = insn.getOpcode();
            sawMultiply |= opcode == Opcodes.IMUL || opcode == Opcodes.LMUL;
            sawShift |= opcode == Opcodes.IUSHR || opcode == Opcodes.LUSHR || opcode == Opcodes.LSHL;
            sawMix |= opcode == Opcodes.IXOR
                || opcode == Opcodes.LXOR
                || opcode == Opcodes.IADD
                || opcode == Opcodes.LADD
                || opcode == Opcodes.IOR
                || opcode == Opcodes.LOR;
        }
        return sawLiveLoad && sawMultiply && sawShift && sawMix && literals >= 3;
    }

    private static void assertNoDirectLargeProtectedNumericMaterial(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        assertFalse(
            hasDirectLargeProtectedNumericMaterial(insns, startInclusive, limitExclusive),
            "direct large protected numeric LdcInsnNode material survived"
        );
    }

    private static void assertNoSelfCancelingDerivedNumericMaterial(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        assertEquals(
            -1,
            selfCancelingNumericMaterialIndex(insns, startInclusive, limitExclusive),
            "self-canceling derived numeric material survived"
        );
    }

    private static boolean hasDirectLargeProtectedNumericMaterial(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        int realInsns = 0;
        int largeLdc = 0;
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            AbstractInsnNode insn = insns[i];
            if (insn.getOpcode() < 0) continue;
            realInsns++;
            if (insn instanceof LdcInsnNode && isLargeNumericLiteral(insn)) {
                largeLdc++;
            }
        }
        return realInsns == 1 && largeLdc == 1;
    }

    private static int selfCancelingNumericMaterialIndex(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        int limit = Math.min(limitExclusive, insns.length);
        for (int i = startInclusive; i < limit; i++) {
            Long first = numericLiteralBits(insns[i]);
            if (first == null) continue;
            int opAIndex = nextRealIndexStatic(insns, i + 1, limit);
            if (opAIndex < 0) continue;
            int literalBIndex = nextNumericLiteralIndex(insns, opAIndex + 1, Math.min(limit, opAIndex + 5));
            if (literalBIndex < 0) continue;
            Long second = numericLiteralBits(insns[literalBIndex]);
            if (!first.equals(second)) continue;
            int opBIndex = nextRealIndexStatic(insns, literalBIndex + 1, limit);
            if (opBIndex < 0) continue;
            if (isSelfCancelingPair(insns[opAIndex].getOpcode(), insns[opBIndex].getOpcode())) {
                return i;
            }
        }
        return -1;
    }

    private static int nextNumericLiteralIndex(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (numericLiteralBits(insns[i]) != null) return i;
        }
        return -1;
    }

    private static int nextRealIndexStatic(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i].getOpcode() >= 0) return i;
        }
        return -1;
    }

    private static boolean isSelfCancelingPair(int opcodeA, int opcodeB) {
        return (opcodeA == Opcodes.IXOR && opcodeB == Opcodes.IXOR)
            || (opcodeA == Opcodes.LXOR && opcodeB == Opcodes.LXOR)
            || (opcodeA == Opcodes.IADD && opcodeB == Opcodes.ISUB)
            || (opcodeA == Opcodes.ISUB && opcodeB == Opcodes.IADD)
            || (opcodeA == Opcodes.LADD && opcodeB == Opcodes.LSUB)
            || (opcodeA == Opcodes.LSUB && opcodeB == Opcodes.LADD);
    }

    private static boolean isLargeNumericLiteral(AbstractInsnNode insn) {
        Long bits = numericLiteralBits(insn);
        return bits != null && (bits > Short.MAX_VALUE || bits < Short.MIN_VALUE);
    }

    private static Long numericLiteralBits(AbstractInsnNode insn) {
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Number value) {
            if (value instanceof Integer i) return i.longValue();
            if (value instanceof Long l) return l;
            if (value instanceof Float f) return (long) Float.floatToRawIntBits(f);
            if (value instanceof Double d) return Double.doubleToRawLongBits(d);
        }
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return (long) (opcode - Opcodes.ICONST_0);
        }
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return (long) ((IntInsnNode) insn).operand;
        }
        if (opcode == Opcodes.LCONST_0) return 0L;
        if (opcode == Opcodes.LCONST_1) return 1L;
        return null;
    }

    private int previousVarLoadIndex(
        AbstractInsnNode[] insns,
        int local,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = limitExclusive - 1; i >= startInclusive && i >= 0; i--) {
            if (insns[i] instanceof VarInsnNode load
                && load.getOpcode() == Opcodes.ILOAD
                && load.var == local) {
                return i;
            }
        }
        return -1;
    }

    private MaterialNoiseProof materialNoiseProof(
        AbstractInsnNode[] insns,
        ConstantDecodeProof proof,
        int limitExclusive
    ) {
        int limit = Math.min(insns.length, limitExclusive);
        for (int i = proof.rawStoreIndex + 1; i < limit; i++) {
            if (!(insns[i] instanceof VarInsnNode store) || store.getOpcode() != Opcodes.ISTORE) {
                continue;
            }
            if (store.var == proof.rawBaseLocal || store.var == proof.dataLocal) {
                continue;
            }
            if (storeHasNonlinearSpecificDataInput(
                insns,
                proof.rawStoreIndex + 1,
                i,
                store.var,
                proof.dataLocal
            )) {
                return new MaterialNoiseProof(store.var, i);
            }
        }
        return null;
    }

    private boolean storeHasNonlinearSpecificDataInput(
        AbstractInsnNode[] insns,
        int startInclusive,
        int storeIndex,
        int storedLocal,
        int dataLocal
    ) {
        boolean sawData = false;
        boolean sawMul = false;
        boolean sawShift = false;
        boolean sawXor = false;
        for (int i = startInclusive; i < storeIndex; i++) {
            if (insns[i] instanceof VarInsnNode load
                && load.getOpcode() == Opcodes.ILOAD
                && load.var == dataLocal) {
                sawData = true;
            }
            if (!sawData) continue;
            if (insns[i].getOpcode() == Opcodes.IMUL) {
                sawMul = true;
            } else if (insns[i].getOpcode() == Opcodes.IUSHR) {
                sawShift = true;
            } else if (insns[i].getOpcode() == Opcodes.IXOR) {
                sawXor = true;
            }
        }
        return sawData && sawMul && sawShift && sawXor
            && insns[storeIndex] instanceof VarInsnNode store
            && store.var == storedLocal;
    }

    private boolean materialSliceConsumesRuntimeBoundMask(
        AbstractInsnNode[] insns,
        ConstantDecodeProof proof,
        MaterialNoiseProof noise,
        int materialEnd
    ) {
        int materialBoundStart = previousBoundBaseStart(
            insns,
            proof.rawBaseLocal,
            noise.local,
            materialEnd,
            260
        );
        if (materialBoundStart <= noise.storeIndex) return false;
        return varLoadCount(insns, proof.rawBaseLocal, noise.storeIndex + 1, materialBoundStart) >= 1
            && boundBaseSliceConsumesNoise(insns, proof.rawBaseLocal, noise.local, materialBoundStart, materialEnd)
            && intLiteralCount(insns, noise.storeIndex + 1, materialEnd + 1) >= 10
            && hasOpcode(insns, Opcodes.IADD, noise.storeIndex + 1, materialEnd + 1)
            && hasOpcode(insns, Opcodes.IMUL, noise.storeIndex + 1, materialEnd + 1)
            && hasOpcode(insns, Opcodes.IXOR, noise.storeIndex + 1, materialEnd + 1);
    }

    private int firstBoundBaseStart(
        AbstractInsnNode[] insns,
        int rawBaseLocal,
        int noiseLocal,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (isBoundBaseStart(insns, i, rawBaseLocal, noiseLocal, limitExclusive)) return i;
        }
        return -1;
    }

    private List<Integer> boundBaseStarts(
        AbstractInsnNode[] insns,
        int rawBaseLocal,
        int noiseLocal,
        int startInclusive,
        int limitExclusive
    ) {
        List<Integer> starts = new ArrayList<>();
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (isBoundBaseStart(insns, i, rawBaseLocal, noiseLocal, limitExclusive)) {
                starts.add(i);
            }
        }
        return starts;
    }

    private int previousBoundBaseStart(
        AbstractInsnNode[] insns,
        int rawBaseLocal,
        int noiseLocal,
        int fromExclusive,
        int maxDistance
    ) {
        int start = Math.max(0, fromExclusive - maxDistance);
        for (int i = fromExclusive - 1; i >= start; i--) {
            if (isBoundBaseStart(insns, i, rawBaseLocal, noiseLocal, fromExclusive)) return i;
        }
        return -1;
    }

    private boolean isBoundBaseStart(
        AbstractInsnNode[] insns,
        int index,
        int rawBaseLocal,
        int noiseLocal,
        int limitExclusive
    ) {
        if (!(insns[index] instanceof VarInsnNode rawLoad)
            || rawLoad.getOpcode() != Opcodes.ILOAD
            || rawLoad.var != rawBaseLocal) {
            return false;
        }
        int next = nextRealIndex(insns, index + 1, limitExclusive);
        if (next < 0) return false;
        if (!(insns[next] instanceof VarInsnNode noiseLoad)
            || noiseLoad.getOpcode() != Opcodes.ILOAD
            || noiseLoad.var != noiseLocal) {
            return false;
        }
        int localLimit = Math.min(limitExclusive, index + 42);
        return hasOpcode(insns, Opcodes.IMUL, next + 1, localLimit)
            && hasOpcode(insns, Opcodes.IUSHR, next + 1, localLimit)
            && hasOpcode(insns, Opcodes.IADD, next + 1, localLimit)
            && hasOpcode(insns, Opcodes.IXOR, next + 1, localLimit)
            && varLoadCount(insns, noiseLocal, index, localLimit) >= 2;
    }

    private boolean boundBaseSliceConsumesNoise(
        AbstractInsnNode[] insns,
        int rawBaseLocal,
        int noiseLocal,
        int startInclusive,
        int limitExclusive
    ) {
        return isBoundBaseStart(insns, startInclusive, rawBaseLocal, noiseLocal, limitExclusive)
            && varLoadCount(insns, noiseLocal, startInclusive, limitExclusive) >= 2
            && hasOpcode(insns, Opcodes.IMUL, startInclusive, limitExclusive)
            && hasOpcode(insns, Opcodes.IUSHR, startInclusive, limitExclusive)
            && hasOpcode(insns, Opcodes.IXOR, startInclusive, limitExclusive);
    }

    private int varLoadCount(
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

    private int intLiteralCount(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        int count = 0;
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (intLiteral(insns[i]) != null) {
                count++;
            }
        }
        return count;
    }

    private List<DerivedMaterialWindow> derivedIntMaterialWindows(
        AbstractInsnNode[] insns,
        int liveLocal,
        int startInclusive,
        int limitExclusive
    ) {
        List<DerivedMaterialWindow> windows = new ArrayList<>();
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            int end = derivedIntMaterialEnd(insns, i, liveLocal, limitExclusive);
            if (end >= 0) {
                windows.add(new DerivedMaterialWindow(i, end));
                i = end - 1;
            }
        }
        return windows;
    }

    private int derivedIntMaterialEnd(
        AbstractInsnNode[] insns,
        int startIndex,
        int liveLocal,
        int limitExclusive
    ) {
        if (!(insns[startIndex] instanceof VarInsnNode liveLoad)
            || liveLoad.getOpcode() != Opcodes.ILOAD
            || liveLoad.var != liveLocal) {
            return -1;
        }
        int cursor = nextRealIndex(insns, startIndex + 1, limitExclusive);
        if (cursor < 0 || numericLiteralBits(insns[cursor]) == null) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.IXOR) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.DUP) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || numericLiteralBits(insns[cursor]) == null) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.IUSHR) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.IXOR) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || numericLiteralBits(insns[cursor]) == null) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.IMUL) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.DUP) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || numericLiteralBits(insns[cursor]) == null) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.IUSHR) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.IADD) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || numericLiteralBits(insns[cursor]) == null) return -1;
        cursor = nextRealIndex(insns, cursor + 1, limitExclusive);
        if (cursor < 0 || insns[cursor].getOpcode() != Opcodes.IXOR) return -1;
        return cursor + 1;
    }

    private int previousDerivedIntMaterialStart(
        AbstractInsnNode[] insns,
        int liveLocal,
        int fromExclusive,
        int maxDistance
    ) {
        int start = Math.max(0, fromExclusive - maxDistance);
        for (int i = fromExclusive - 1; i >= start; i--) {
            int end = derivedIntMaterialEnd(insns, i, liveLocal, fromExclusive);
            if (end < 0) continue;
            if (nextRealIndex(insns, end, fromExclusive) < 0) {
                return i;
            }
        }
        return -1;
    }

    private boolean hasNonlinearMixAfter(
        AbstractInsnNode[] insns,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (isNonlinearIntMixOpcode(insns[i].getOpcode())) {
                return true;
            }
        }
        return false;
    }

    private boolean isNonlinearIntMixOpcode(int opcode) {
        return opcode == Opcodes.IMUL
            || opcode == Opcodes.IUSHR
            || opcode == Opcodes.IXOR;
    }

    private static final class ConstantDecodeProof {
        private final int rawBaseLocal;
        private final int dataLocal;
        private final int rawStoreIndex;

        private ConstantDecodeProof(int rawBaseLocal, int dataLocal, int rawStoreIndex) {
            this.rawBaseLocal = rawBaseLocal;
            this.dataLocal = dataLocal;
            this.rawStoreIndex = rawStoreIndex;
        }
    }

    private static final class MaterialNoiseProof {
        private final int local;
        private final int storeIndex;

        private MaterialNoiseProof(int local, int storeIndex) {
            this.local = local;
            this.storeIndex = storeIndex;
        }
    }

    private static final class DerivedMaterialWindow {
        private final int startInclusive;
        private final int endExclusive;

        private DerivedMaterialWindow(int startInclusive, int endExclusive) {
            this.startInclusive = startInclusive;
            this.endExclusive = endExclusive;
        }
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

    private String runClass(Path jar, Path extraClasspath, String mainClass) throws Exception {
        String classpath = extraClasspath + System.getProperty("path.separator") + jar;
        return run(
            List.of("java", "-XX:-UsePerfData", "-cp", classpath, mainClass),
            Duration.ofSeconds(30)
        );
    }

    private String run(List<String> command, Duration timeout) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean exited = process.waitFor(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(exited, "command timed out: " + command);
        assertEquals(0, process.exitValue(), "command failed: " + command + "\n" + output);
        return output;
    }

    private String staticArrayTablesSourceText() {
        return """
            public class StaticArrayTables {
                private static final int[] MASK = new int[] {49, 199, 90, 13, 132, 34, 225, 107};
                private static final int[] CHECK = new int[] {81, 98, 218, 155, 56, 108, 149, 118};
                private static final byte[] SALT = new byte[] {66, 19, 55, 33, -64, 90, 126, 9};

                public static void main(String[] args) {
                    int value = score("swing-ga");
                    if (value != 57685) {
                        throw new AssertionError(value);
                    }
                    int digest = digestSalt();
                    if (digest != 662256384) {
                        throw new AssertionError(digest);
                    }
                    System.out.println("STATIC ARRAY TABLES OK");
                }

                static int score(String input) {
                    byte[] bytes = input.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    int acc = SALT.length;
                    for (int i = 0; i < MASK.length; i++) {
                        int b = bytes[i % bytes.length] & 255;
                        acc = (acc * 131) ^ ((b ^ MASK[i]) + CHECK[i]);
                        acc += SALT[i & 7] & 255;
                    }
                    return acc & 65535;
                }

                static int digestSalt() {
                    try {
                        java.security.MessageDigest digest =
                            java.security.MessageDigest.getInstance("SHA-256");
                        digest.update(SALT);
                        byte[] out = digest.digest();
                        return ((out[0] & 255) << 24)
                            | ((out[1] & 255) << 16)
                            | ((out[2] & 255) << 8)
                            | (out[3] & 255);
                    } catch (java.security.NoSuchAlgorithmException ex) {
                        throw new IllegalStateException(ex);
                    }
                }
            }
            """;
    }

    private String staticArrayReferenceSemanticsSourceText() {
        return """
            public class StaticArrayReferenceSemantics {
                private static final int[] TABLE = new int[] {7, 11, 13};

                public static void main(String[] args) throws Exception {
                    int[] first = table();
                    int[] second = TABLE;
                    if (first != second) {
                        throw new AssertionError("identity");
                    }
                    int hash = System.identityHashCode(TABLE);
                    mutate(first);
                    if (TABLE[0] != 12) {
                        throw new AssertionError("mutation");
                    }
                    synchronized (TABLE) {
                        TABLE[1] += 3;
                    }
                    if (TABLE[1] != 14) {
                        throw new AssertionError("monitor");
                    }
                    java.lang.reflect.Field field =
                        StaticArrayReferenceSemantics.class.getDeclaredField("TABLE");
                    field.setAccessible(true);
                    if (field.get(null) != TABLE) {
                        throw new AssertionError("reflection identity");
                    }
                    if (System.identityHashCode(TABLE) != hash) {
                        throw new AssertionError("identity hash");
                    }
                    System.out.println("STATIC ARRAY REFERENCE SEMANTICS OK");
                }

                private static int[] table() {
                    return TABLE;
                }

                private static void mutate(int[] value) {
                    value[0] += 5;
                }
            }
            """;
    }

    private String staticArrayDynamicFieldAccessSourceText() {
        return """
            public class StaticArrayDynamicFieldAccess {
                private static final int[] TABLE = new int[] {3, 5, 8};

                public static void main(String[] args) throws Throwable {
                    int direct = TABLE[1];
                    java.lang.invoke.MethodHandles.Lookup lookup =
                        java.lang.invoke.MethodHandles.lookup();
                    java.lang.invoke.MethodHandle getter = lookup.findStaticGetter(
                        StaticArrayDynamicFieldAccess.class,
                        "TABLE",
                        int[].class
                    );
                    int[] viaHandle = (int[]) getter.invokeExact();
                    java.lang.invoke.VarHandle varHandle = lookup.findStaticVarHandle(
                        StaticArrayDynamicFieldAccess.class,
                        "TABLE",
                        int[].class
                    );
                    int[] viaVarHandle = (int[]) varHandle.get();
                    if (viaHandle != TABLE || viaVarHandle != TABLE) {
                        throw new AssertionError("dynamic identity");
                    }
                    if (direct != 5 || viaHandle[2] != 8 || viaVarHandle[0] != 3) {
                        throw new AssertionError("dynamic values");
                    }
                    System.out.println("STATIC ARRAY DYNAMIC ACCESS OK");
                }
            }
            """;
    }

    private String staticArrayUnreflectFieldProviderSourceText() {
        return """
            public class StaticArrayUnreflectFieldProvider {
                public static java.lang.reflect.Field field(Class<?> owner, String name) throws Exception {
                    java.lang.reflect.Field field = owner.getDeclaredField(name);
                    field.setAccessible(true);
                    return field;
                }
            }
            """;
    }

    private String staticArrayUnreflectAccessSourceText() {
        return """
            public class StaticArrayUnreflectAccess {
                private static final int[] TABLE = new int[] {3, 5, 8};

                public static void main(String[] args) throws Throwable {
                    int direct = TABLE[1];
                    java.lang.reflect.Field field =
                        StaticArrayUnreflectFieldProvider.field(StaticArrayUnreflectAccess.class, "TABLE");
                    java.lang.invoke.MethodHandles.Lookup lookup =
                        java.lang.invoke.MethodHandles.lookup();
                    java.lang.invoke.MethodHandle getter = lookup.unreflectGetter(field);
                    int[] viaGetter = (int[]) getter.invokeExact();
                    java.lang.invoke.VarHandle varHandle = lookup.unreflectVarHandle(field);
                    int[] viaVarHandle = (int[]) varHandle.get();
                    if (viaGetter != TABLE || viaVarHandle != TABLE) {
                        throw new AssertionError("unreflect identity");
                    }
                    if (direct != 5 || viaGetter[2] != 8 || viaVarHandle[0] != 3) {
                        throw new AssertionError("unreflect values");
                    }
                    System.out.println("STATIC ARRAY UNREFLECT ACCESS OK");
                }
            }
            """;
    }

    private String staticArrayOriginalReflectionSourceText() {
        return """
            public class StaticArrayOriginalReflection {
                private static final int[] TABLE = new int[] {4, 6, 9};

                public static void main(String[] args) throws Exception {
                    if (first() != 4) {
                        throw new AssertionError("direct");
                    }
                    java.lang.reflect.Field field =
                        StaticArrayOriginalReflection.class.getDeclaredField("TABLE");
                    field.setAccessible(true);
                    if (field.get(null) != TABLE) {
                        throw new AssertionError("reflection identity");
                    }
                    System.out.println("STATIC ARRAY ORIGINAL REFLECTION OK");
                }

                private static int first() {
                    return TABLE[0];
                }
            }
            """;
    }

    private byte[] staticArrayCondyAccessClassBytes() {
        String owner = "StaticArrayCondyAccess";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);
        cw.visitField(
            Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
            "TABLE",
            "[I",
            null,
            null
        ).visitEnd();

        emitDefaultConstructor(cw);
        emitStaticIntTableClinit(cw, owner, new int[] {3, 5, 8});
        emitStaticArrayCondyBootstrap(cw);

        MethodVisitor mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "main",
            "([Ljava/lang/String;)V",
            null,
            new String[] {"java/lang/Throwable"}
        );
        mv.visitCode();
        mv.visitFieldInsn(Opcodes.GETSTATIC, owner, "TABLE", "[I");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IALOAD);
        mv.visitVarInsn(Opcodes.ISTORE, 1);

        Handle bsm = new Handle(
            Opcodes.H_INVOKESTATIC,
            owner,
            "__neko_condy",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Class;" +
                "Ljava/lang/invoke/MethodType;)" +
                "Ljava/lang/Object;",
            false
        );
        mv.visitLdcInsn(new ConstantDynamic(
            "TABLE",
            "Ljava/lang/Object;",
            bsm,
            Type.getObjectType(owner),
            Type.getMethodType("()[I")
        ));
        mv.visitVarInsn(Opcodes.ASTORE, 2);

        Label nonNull = new Label();
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitJumpInsn(Opcodes.IFNONNULL, nonNull);
        emitThrowAssertionError(mv, "condy null");
        mv.visitLabel(nonNull);

        Label directOk = new Label();
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.ICONST_5);
        mv.visitJumpInsn(Opcodes.IF_ICMPEQ, directOk);
        emitThrowAssertionError(mv, "direct value");
        mv.visitLabel(directOk);

        Label instanceOk = new Label();
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitTypeInsn(Opcodes.INSTANCEOF, "[I");
        mv.visitJumpInsn(Opcodes.IFNE, instanceOk);
        emitThrowAssertionError(mv, "condy type");
        mv.visitLabel(instanceOk);

        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "[I");
        mv.visitVarInsn(Opcodes.ASTORE, 2);

        Label tableOk = new Label();
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.IALOAD);
        mv.visitIntInsn(Opcodes.BIPUSH, 8);
        mv.visitJumpInsn(Opcodes.IF_ICMPEQ, tableOk);
        emitThrowAssertionError(mv, "condy value");
        mv.visitLabel(tableOk);

        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        mv.visitLdcInsn("STATIC ARRAY CONDY ACCESS OK");
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/io/PrintStream",
            "println",
            "(Ljava/lang/String;)V",
            false
        );
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private byte[] staticArrayIndyProtocolAccessClassBytes() {
        String owner = "StaticArrayIndyProtocolAccess";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null, "java/lang/Object", null);
        cw.visitField(
            Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
            "TABLE",
            "[I",
            null,
            null
        ).visitEnd();

        emitDefaultConstructor(cw);
        emitStaticIntTableClinit(cw, owner, new int[] {3, 5, 8});
        emitStaticArrayProtocolBootstrap(cw, owner);

        MethodVisitor mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "main",
            "([Ljava/lang/String;)V",
            null,
            new String[] {"java/lang/Throwable"}
        );
        mv.visitCode();
        mv.visitFieldInsn(Opcodes.GETSTATIC, owner, "TABLE", "[I");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IALOAD);
        mv.visitVarInsn(Opcodes.ISTORE, 1);

        Handle bsm = new Handle(
            Opcodes.H_INVOKESTATIC,
            owner,
            "__neko_bootstrap",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
                "Ljava/lang/Class;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
            false
        );
        mv.visitInvokeDynamicInsn(
            "TABLE",
            "()Ljava/lang/Object;",
            bsm,
            Type.getObjectType(owner),
            Type.getMethodType("()[I")
        );
        mv.visitVarInsn(Opcodes.ASTORE, 2);

        Label instanceOk = new Label();
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitTypeInsn(Opcodes.INSTANCEOF, "[I");
        mv.visitJumpInsn(Opcodes.IFNE, instanceOk);
        emitThrowAssertionError(mv, "indy protocol type");
        mv.visitLabel(instanceOk);

        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "[I");
        mv.visitVarInsn(Opcodes.ASTORE, 3);

        Label directOk = new Label();
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.ICONST_5);
        mv.visitJumpInsn(Opcodes.IF_ICMPEQ, directOk);
        emitThrowAssertionError(mv, "direct value");
        mv.visitLabel(directOk);

        Label indyOk = new Label();
        mv.visitVarInsn(Opcodes.ALOAD, 3);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.IALOAD);
        mv.visitIntInsn(Opcodes.BIPUSH, 8);
        mv.visitJumpInsn(Opcodes.IF_ICMPEQ, indyOk);
        emitThrowAssertionError(mv, "indy protocol value");
        mv.visitLabel(indyOk);

        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        mv.visitLdcInsn("STATIC ARRAY INDY PROTOCOL OK");
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/io/PrintStream",
            "println",
            "(Ljava/lang/String;)V",
            false
        );
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private void emitStaticArrayCondyBootstrap(ClassWriter cw) {
        MethodVisitor mv = cw.visitMethod(
            Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
            "__neko_condy",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Class;" +
                "Ljava/lang/invoke/MethodType;)Ljava/lang/Object;",
            null,
            new String[] {"java/lang/Throwable"}
        );
        mv.visitCode();
        emitNewIntArray(mv, new int[] {3, 5, 8});
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private void emitStaticArrayProtocolBootstrap(ClassWriter cw, String owner) {
        MethodVisitor mv = cw.visitMethod(
            Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
            "__neko_bootstrap",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
                "Ljava/lang/Class;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
            null,
            new String[] {"java/lang/Throwable"}
        );
        mv.visitCode();
        emitNewIntArray(mv, new int[] {3, 5, 8});
        mv.visitVarInsn(Opcodes.ASTORE, 5);

        mv.visitLdcInsn(Type.getType("Ljava/lang/Object;"));
        mv.visitVarInsn(Opcodes.ALOAD, 5);
        mv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            "java/lang/invoke/MethodHandles",
            "constant",
            "(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;",
            false
        );
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/invoke/MethodHandle",
            "asType",
            "(Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/MethodHandle;",
            false
        );
        mv.visitVarInsn(Opcodes.ASTORE, 6);

        mv.visitTypeInsn(Opcodes.NEW, "java/lang/invoke/ConstantCallSite");
        mv.visitInsn(Opcodes.DUP);
        mv.visitVarInsn(Opcodes.ALOAD, 6);
        mv.visitMethodInsn(
            Opcodes.INVOKESPECIAL,
            "java/lang/invoke/ConstantCallSite",
            "<init>",
            "(Ljava/lang/invoke/MethodHandle;)V",
            false
        );
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private void emitDefaultConstructor(ClassWriter cw) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private void emitStaticIntTableClinit(ClassWriter cw, String owner, int[] values) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        emitNewIntArray(mv, values);
        mv.visitFieldInsn(Opcodes.PUTSTATIC, owner, "TABLE", "[I");
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private void emitNewIntArray(MethodVisitor mv, int[] values) {
        emitPushInt(mv, values.length);
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_INT);
        for (int i = 0; i < values.length; i++) {
            mv.visitInsn(Opcodes.DUP);
            emitPushInt(mv, i);
            emitPushInt(mv, values[i]);
            mv.visitInsn(Opcodes.IASTORE);
        }
    }

    private void emitPushInt(MethodVisitor mv, int value) {
        if (value >= -1 && value <= 5) {
            mv.visitInsn(Opcodes.ICONST_0 + value);
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            mv.visitIntInsn(Opcodes.BIPUSH, value);
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            mv.visitIntInsn(Opcodes.SIPUSH, value);
        } else {
            mv.visitLdcInsn(value);
        }
    }

    private void emitThrowAssertionError(MethodVisitor mv, String message) {
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/AssertionError");
        mv.visitInsn(Opcodes.DUP);
        mv.visitLdcInsn(message);
        mv.visitMethodInsn(
            Opcodes.INVOKESPECIAL,
            "java/lang/AssertionError",
            "<init>",
            "(Ljava/lang/Object;)V",
            false
        );
        mv.visitInsn(Opcodes.ATHROW);
    }

    private String sourceText() {
        return """
            public class ConstantShapes {
                static final int STATIC_INT = -1234567;
                static final long STATIC_LONG = 0x123456789ABCDEFL;
                static final float STATIC_FLOAT = -3.5f;
                static final double STATIC_DOUBLE = 6.25d;

                public static void main(String[] args) {
                    ConstantShapes shapes = new ConstantShapes();
                    String out = shapes.all();
                    System.out.println(out);
                    if (!out.equals("123486954:81985529216486894:11.0:14.0:-1234567:81985529216486895:-3.5:6.25:" + shapes.arrays())) {
                        throw new AssertionError(out);
                    }
                    System.out.println("CONSTANT SHAPES OK");
                }

                String all() {
                    return ints() + ":" + longs() + ":" + floats() + ":" + doubles()
                        + ":" + STATIC_INT + ":" + STATIC_LONG + ":" + STATIC_FLOAT + ":" + STATIC_DOUBLE
                        + ":" + arrays();
                }

                long arrays() {
                    long total = 0L;
                    boolean[] flags = new boolean[] {true, false, true};
                    byte[] bytes = new byte[] {(byte) 0x80, 0, 127};
                    short[] shorts = new short[] {-30000, 12345};
                    char[] chars = new char[] {'A', 0x1234};
                    int[] ints = new int[] {-7, 0, 123456789, 42};
                    long[] longs = new long[] {0x1020304050607080L, -5L, 9L};
                    float[] floats = new float[] {-1.5f, 0.25f, 3.75f};
                    double[] doubles = new double[] {-2.5d, 6.5d};
                    int[] empty = new int[] {};
                    for (boolean v : flags) total = total * 31L + (v ? 1L : 0L);
                    for (byte v : bytes) total = total * 31L + v;
                    for (short v : shorts) total = total * 31L + v;
                    for (char v : chars) total = total * 31L + v;
                    for (int v : ints) total = total * 31L + v;
                    for (long v : longs) total = total * 31L + v;
                    for (float v : floats) total = total * 31L + Float.floatToRawIntBits(v);
                    for (double v : doubles) total = total * 31L + Double.doubleToRawLongBits(v);
                    return total + empty.length;
                }

                int ints() {
                    int v = -1 + 0 + 1 + 2 + 3 + 4 + 5;
                    v += 127;
                    v += 30000;
                    v += 123456789;
                    v++;
                    v += 7;
                    v -= 3;
                    for (int i = 0; i < 4; i++) {
                        v += i;
                    }
                    switch (v & 3) {
                        case 0:
                            return v + 11;
                        case 1:
                            return v + 13;
                        case 2:
                            return v + 17;
                        default:
                            return v + 19;
                    }
                }

                long longs() {
                    long a = 0L;
                    long b = 1L;
                    long c = 0x123456789ABCDEFL;
                    long d = -2L;
                    return a + b + c + d;
                }

                float floats() {
                    float a = 0.0f;
                    float b = 1.0f;
                    float c = 2.0f;
                    float d = 8.0f;
                    return a + b + c + d;
                }

                double doubles() {
                    double a = 0.0d;
                    double b = 1.0d;
                    double c = 2.5d;
                    double d = 10.5d;
                    return a + b + c + d;
                }
            }
            """;
    }
}
