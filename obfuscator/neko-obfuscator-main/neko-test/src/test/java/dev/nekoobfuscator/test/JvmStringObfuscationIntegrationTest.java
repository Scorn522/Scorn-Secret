package dev.nekoobfuscator.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;
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
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Exercises AES/DES plus XOR string obfuscation bound to CFF live key state.
 */
public class JvmStringObfuscationIntegrationTest {
    private static final int STRING_MATERIAL_SLOT = 66;
    private static final int STRING_MATERIAL_SELECTOR_SLOT = 69;
    private static final int CLASS_KEY_WORDS_SLOT = 65;
    private static final int CLASS_KEY_WORDS_SELECTOR_SLOT = 73;
    private static final int STRING_KEY_CELL_PAYLOAD_SLOT = 8;
    private static final int STRING_KEY_CELL_CACHE_SLOT = 9;
    private static final int STRING_KEY_CELL_LENGTH = 10;
    private static final int STRING_LOGICAL_KEY_WORDS = 4;
    private static final int STRING_KEY_CELL_DESCRIPTOR_SLOT = 0;
    private static final int STRING_KEY_CELL_PHYSICAL_MASK = 31;
    private static final int STRING_KEY_CELL_PHYSICAL_LENGTH = STRING_KEY_CELL_PHYSICAL_MASK + 2;
    private static final int STRING_KEY_CELL_OFFSET_SHIFT = 5;
    private static final int STRING_SELECTOR_LAYOUT_SHIFT = 8;
    private static final int STRING_SELECTOR_LAYOUT_MASK = 0x3F;
    private static final int STRING_SELECTOR_FINGERPRINT_SHIFT = 14;
    private static final int STRING_SELECTOR_FINGERPRINT_MASK = 0x3FFFF;
    private static final long STRING_KEY_CELL_PAYLOAD_MASK = 0x5354525041594C44L;
    private static final long STRING_KEY_CELL_CACHE_MASK = 0x5354524341434845L;
    private static final long STRING_KEY_CELL_LENGTH_MASK = 0x5354524C454E3031L;
    private static final List<String> SECRET_STRINGS = List.of(
        "alpha-secret-cff-flow-17",
        "omega-flow-tail-23",
        "beta-state-keydispatch-29",
        "gamma-aes-des-xor-31",
        "delta-domain-token-43",
        "epsilon-live-key-47",
        "zeta-static-final-field-59",
        "eta-unused-static-field-61",
        "STRING OBF OK",
        "alpha-secret-cff-flow-17|tail-23|beta-state-keydispatch-29|gamma-aes-des-xor-31:delta-domain-token-43:epsilon-live-key-47:zeta-static-final-field-59"
    );

    @Test
    void stringObfuscationUsesCffKeyedAesDesXorWithoutHelpers() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-strings"));
        Path source = work.resolve("StringShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("string-shapes.jar");
        writeJar(inputJar, classes, "StringShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("string-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STRING OBF OK"), obfuscated);
        assertPlaintextRemoved(outputJar);
        assertAesDesXorDecodeUsesCffState(outputJar);
        assertStringSitesHaveIndependentMaterialLayouts(outputJar);
        assertStringKeyMaterialHasNoFixedIntArrayCell(outputJar);
        assertStringProtectedMaterialIsDerived(outputJar);
    }

    @Test
    void stringObfuscationUsesDynamicTablesForInterfaceStringSites() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-interface-strings"));
        Path source = work.resolve("InterfaceStringShapes.java");
        Files.writeString(source, interfaceSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("interface-string-shapes.jar");
        writeJar(inputJar, classes, "InterfaceStringShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("interface-string-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("INTERFACE STRING OBF OK"), obfuscated);

        JarInput input = new JarInput(outputJar);
        L1Class iface = input.classMap().get("InterfaceStrings");
        int objectTables = 0;
        boolean sawBytePayloadField = false;
        for (var field : iface.asmNode().fields) {
            if ("[Ljava/lang/Object;".equals(field.desc)) {
                objectTables++;
                assertTrue((field.access & Opcodes.ACC_FINAL) != 0, "interface material table must be final");
            }
            if ("[B".equals(field.desc)) {
                sawBytePayloadField = true;
            }
        }
        assertTrue(objectTables >= 1, "interface string sites should use a coalesced string key object table");
        assertFalse(sawBytePayloadField, "interface string sites must not use per-site byte payload fields");
    }

    @Test
    void repeatedStringLiteralsPreserveJvmIdentityUnderFullStringProtection() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-string-identity"));
        Path source = work.resolve("StringIdentityShapes.java");
        Files.writeString(source, identitySourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("string-identity-shapes.jar");
        writeJar(inputJar, classes, "StringIdentityShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("string-identity-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STRING IDENTITY OBF OK"), obfuscated);
        byte[] classBytes = NativeObfuscationHelper.extractEntry(outputJar, "StringIdentityShapes.class");
        String classText = new String(classBytes, StandardCharsets.ISO_8859_1);
        assertFalse(classText.contains("identity-anchor-101"), "identity literal remained in class bytes");
        assertFalse(classText.contains("identity-replacement-103"), "replacement literal remained in class bytes");
    }

    @Test
    void sizePressureStringConcatUsesCompactLiveStateAbi() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-string-concat-pressure"));
        Path source = work.resolve("StringConcatPressureShapes.java");
        Files.writeString(source, concatPressureSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("string-concat-pressure.jar");
        writeJar(inputJar, classes, "StringConcatPressureShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("string-concat-pressure-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertCompactConcatAbi(outputJar, "StringConcatPressureShapes");
        assertCompactStringTailAbi(outputJar, "StringConcatPressureShapes");
    }

    private void runObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("constantObfuscation", new TransformConfig(true, 1.0));
        transforms.put("stringObfuscation", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x51724E6B5A11CFFL);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void assertPlaintextRemoved(Path jar) throws Exception {
        byte[] classBytes = NativeObfuscationHelper.extractEntry(jar, "StringShapes.class");
        String classText = new String(classBytes, StandardCharsets.ISO_8859_1);
        for (String secret : SECRET_STRINGS) {
            assertFalse(classText.contains(secret), "plaintext string remained in class bytes: " + secret);
        }

        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("StringShapes");
        for (var method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            boolean classInitPath = "<clinit>".equals(method.name)
                || method.name.startsWith("__neko_strinit$")
                || method.name.startsWith("__neko_strcipher$");
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String value) {
                    assertFalse(SECRET_STRINGS.contains(value), "secret String LDC survived: " + value);
                }
                if (insn instanceof InvokeDynamicInsnNode indy) {
                    for (Object arg : indy.bsmArgs) {
                        if (arg instanceof String value) {
                            assertFalse(SECRET_STRINGS.contains(value), "secret indy bootstrap string survived: " + value);
                        }
                    }
                }
            }
        }
        for (var field : clazz.asmNode().fields) {
            if ("Ljava/lang/String;".equals(field.desc)) {
                assertEquals(null, field.value, "String ConstantValue remained on field " + field.name);
            }
        }

        for (String entry : NativeObfuscationHelper.jarEntries(jar)) {
            assertFalse(entry.startsWith("dev/nekoobfuscator/runtime/"), "runtime helper class injected: " + entry);
        }
    }

    private void assertAesDesXorDecodeUsesCffState(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("StringShapes");
        boolean sawCipher = false;
        boolean sawSecretKeySpec = false;
        boolean sawDoFinal = false;
        boolean sawUtf8 = false;
        boolean sawClassKeyTableLoad = false;
        boolean sawMethodKeyLoad = false;
        int standaloneCipherCacheFields = 0;
        boolean sawPayloadCacheField = false;
        int objectMaterialTables = 0;
        boolean sawBoxedFingerprintCacheRead = false;
        boolean sawBoxedFingerprintCacheWrite = false;
        boolean sawCipherMonitor = false;
        boolean sawCacheCompare = false;
        boolean sawXor = false;
        boolean sawRotate = false;
        boolean sawKeyCellUpdate = false;
        boolean sawSiteHelperKeyCellUpdate = false;
        boolean sawSharedStringDecodeTail = false;
        boolean sawTailLoadsStringMaterialSelectorSlot = false;
        boolean sawTailDirectStringMaterialSlotLoad = false;
        boolean sawConcatLoadsClassKeySelectorSlot = false;
        boolean sawConcatDirectClassKeySlotLoad = false;
        boolean sawLiveFlowTailCall = false;
        boolean sawTailConsumesDataWord = false;
        boolean sawStringConcatFactoryRecipe = false;
        int siteHelperDoFinalCalls = 0;
        int tailDoFinalCalls = 0;
        int siteHelperTailCalls = 0;
        int oldSharedTailAbiCalls = 0;
        int checkedStringDataTailCalls = 0;
        int siteHelperCount = 0;
        int sharedTailCount = 0;
        int getInstanceCalls = 0;
        int clinitGetInstanceCalls = 0;
        int getBytesCalls = 0;
        int clinitGetBytesCalls = 0;
        int standaloneStringMaterialHelpers = 0;
        int standaloneCipherInitHelpers = 0;
        int standaloneStringKeyInitHelpers = 0;
        int standaloneStringStreamHelpers = 0;
        int oldStreamHelperMethods = 0;
        int oldStreamHelperCalls = 0;

        for (var field : clazz.asmNode().fields) {
            if ("Ljavax/crypto/Cipher;".equals(field.desc)) {
                standaloneCipherCacheFields++;
            }
            if ("[Ljava/lang/Object;".equals(field.desc)) {
                objectMaterialTables++;
                sawPayloadCacheField = true;
            }
        }
        for (var method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            AbstractInsnNode[] insns = method.instructions.toArray();
            boolean classInitPath = "<clinit>".equals(method.name)
                || method.name.startsWith("__neko_strinit$")
                || method.name.startsWith("__neko_strmat$")
                || method.name.startsWith("__neko_strkey$")
                || method.name.startsWith("__neko_strcache$")
                || method.name.startsWith("__neko_strcipher$");
            boolean stringDecodeHelper = method.name.startsWith("__neko_str$");
            boolean stringDecodeTail = method.name.startsWith("__neko_strtail$");
            boolean stringConcatHelper = method.name.startsWith("__neko_strcat$");
            if (method.name.startsWith("__neko_strmat$") || method.name.startsWith("__neko_strcache$")) {
                standaloneStringMaterialHelpers++;
            }
            if (method.name.startsWith("__neko_strcipher$")) {
                standaloneCipherInitHelpers++;
            }
            if (method.name.startsWith("__neko_strkey$")) {
                standaloneStringKeyInitHelpers++;
            }
            if (method.name.startsWith("__neko_strstream")) {
                standaloneStringStreamHelpers++;
            }
            if ("(IIJJ)I".equals(method.desc)) {
                oldStreamHelperMethods++;
            }
            if (stringDecodeHelper) {
                siteHelperCount++;
            }
            if (stringDecodeTail) {
                sawSharedStringDecodeTail = true;
                sharedTailCount++;
                if (tailSelectorDecodeConsumesDataWord(insns)) {
                    sawTailConsumesDataWord = true;
                }
            }
            for (int i = 0; i < insns.length; i++) {
                if (insns[i] instanceof MethodInsnNode call
                    && "StringShapes".equals(call.owner)
                    && call.name.startsWith("__neko_strtail$")
                    && "([Ljava/lang/Object;JIIIIII)Ljava/lang/String;".equals(call.desc)) {
                    sawLiveFlowTailCall = true;
                    assertTrue(
                        stringTailCallReceivesDataDigest(insns, i),
                        "string tail call does not receive a dataLocal-derived live word in " +
                            method.name + method.desc
                    );
                    checkedStringDataTailCalls++;
                }
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode indy
                    && indy.bsm != null
                    && "java/lang/invoke/StringConcatFactory".equals(indy.bsm.getOwner())
                    && "makeConcatWithConstants".equals(indy.bsm.getName())) {
                    sawStringConcatFactoryRecipe = true;
                }
                if (insn instanceof MethodInsnNode call
                    && "javax/crypto/Cipher".equals(call.owner)
                    && "getInstance".equals(call.name)) {
                    sawCipher = true;
                    getInstanceCalls++;
                    if (classInitPath) {
                        clinitGetInstanceCalls++;
                    }
                }
                if (insn instanceof MethodInsnNode call
                    && "java/lang/String".equals(call.owner)
                    && "getBytes".equals(call.name)
                    && "(Ljava/nio/charset/Charset;)[B".equals(call.desc)) {
                    getBytesCalls++;
                    if (classInitPath) {
                        clinitGetBytesCalls++;
                    }
                }
                if (insn instanceof MethodInsnNode call
                    && call.getOpcode() == Opcodes.INVOKESTATIC
                    && "(IIJJ)I".equals(call.desc)) {
                    oldStreamHelperCalls++;
                }
                if (insn instanceof MethodInsnNode call
                    && "javax/crypto/spec/SecretKeySpec".equals(call.owner)
                    && "<init>".equals(call.name)) {
                    sawSecretKeySpec = true;
                }
                if (insn instanceof MethodInsnNode call
                    && "javax/crypto/Cipher".equals(call.owner)
                    && "doFinal".equals(call.name)) {
                    sawDoFinal = true;
                    if (stringDecodeHelper) {
                        siteHelperDoFinalCalls++;
                    }
                    if (stringDecodeTail) {
                        tailDoFinalCalls++;
                    }
                }
                if (stringDecodeHelper
                    && insn instanceof MethodInsnNode call
                    && "StringShapes".equals(call.owner)
                    && call.name.startsWith("__neko_strtail$")
                    && "([Ljava/lang/Object;IJI)Ljava/lang/String;".equals(call.desc)) {
                    siteHelperTailCalls++;
                }
                if (insn instanceof MethodInsnNode call
                    && "StringShapes".equals(call.owner)
                    && call.name.startsWith("__neko_strtail$")
                    && ("([Ljava/lang/Object;IJIII)Ljava/lang/String;".equals(call.desc)
                        || "([Ljava/lang/Object;IJIIII)Ljava/lang/String;".equals(call.desc)
                        || "([Ljava/lang/Object;JIIIIIIII)Ljava/lang/String;".equals(call.desc)
                        || "([Ljava/lang/Object;JIIIIIII)Ljava/lang/String;".equals(call.desc))) {
                    oldSharedTailAbiCalls++;
                }
                if (insn instanceof MethodInsnNode call
                    && "java/lang/Long".equals(call.owner)
                    && "longValue".equals(call.name)
                    && "()J".equals(call.desc)) {
                    sawBoxedFingerprintCacheRead = true;
                }
                if (insn instanceof MethodInsnNode call
                    && "java/lang/Long".equals(call.owner)
                    && "valueOf".equals(call.name)
                    && "(J)Ljava/lang/Long;".equals(call.desc)) {
                    sawBoxedFingerprintCacheWrite = true;
                }
                if (insn instanceof FieldInsnNode field
                    && "java/nio/charset/StandardCharsets".equals(field.owner)
                    && "UTF_8".equals(field.name)) {
                    sawUtf8 = true;
                }
                if (insn instanceof FieldInsnNode field
                    && "[I".equals(field.desc)
                    && "StringShapes".equals(field.owner)) {
                    sawClassKeyTableLoad = true;
                }
                if (insn instanceof TypeInsnNode type
                    && type.getOpcode() == Opcodes.CHECKCAST
                    && "[I".equals(type.desc)) {
                    sawClassKeyTableLoad = true;
                }
                if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.LLOAD) {
                    sawMethodKeyLoad = true;
                }
                if (insn.getOpcode() == Opcodes.IXOR) {
                    sawXor = true;
                }
                if (stringDecodeTail && storesBoxedNumber(insn)) {
                    sawKeyCellUpdate = true;
                }
                if (stringDecodeTail
                    && pushesInt(insn, STRING_MATERIAL_SELECTOR_SLOT)
                    && insn.getNext() != null
                    && insn.getNext().getOpcode() == Opcodes.AALOAD) {
                    sawTailLoadsStringMaterialSelectorSlot = true;
                }
                if (stringDecodeTail
                    && pushesInt(insn, STRING_MATERIAL_SLOT)
                    && insn.getNext() != null
                    && insn.getNext().getOpcode() == Opcodes.AALOAD) {
                    sawTailDirectStringMaterialSlotLoad = true;
                }
                if (stringConcatHelper
                    && pushesInt(insn, CLASS_KEY_WORDS_SELECTOR_SLOT)
                    && insn.getNext() != null
                    && insn.getNext().getOpcode() == Opcodes.AALOAD) {
                    sawConcatLoadsClassKeySelectorSlot = true;
                }
                if (stringConcatHelper
                    && pushesInt(insn, CLASS_KEY_WORDS_SLOT)
                    && insn.getNext() != null
                    && insn.getNext().getOpcode() == Opcodes.AALOAD) {
                    sawConcatDirectClassKeySlotLoad = true;
                }
                if (stringDecodeHelper && storesBoxedNumber(insn)) {
                    sawSiteHelperKeyCellUpdate = true;
                }
                if (insn.getOpcode() == Opcodes.LCMP) {
                    sawCacheCompare = true;
                }
                if (insn.getOpcode() == Opcodes.MONITORENTER || insn.getOpcode() == Opcodes.MONITOREXIT) {
                    sawCipherMonitor = true;
                }
                if (insn instanceof MethodInsnNode call
                    && "java/lang/Integer".equals(call.owner)
                    && ("rotateLeft".equals(call.name) || "rotateRight".equals(call.name))) {
                    sawRotate = true;
                }
            }
        }

        assertTrue(sawCipher, "string pass should use JCE Cipher without helper injection");
        assertEquals(0, standaloneCipherCacheFields, "AES and DES Cipher instances should be coalesced into the string key object table");
        assertTrue(sawPayloadCacheField, "encrypted payload bytes should be loaded through class static state");
        assertTrue(objectMaterialTables >= 1, "string material should use a class object table");
        assertEquals(0, standaloneStringMaterialHelpers, "string payload/cache material should be coalesced into the key table");
        assertEquals(0, standaloneCipherInitHelpers, "string cipher cache setup should be coalesced into the key table init path");
        assertEquals(0, standaloneStringKeyInitHelpers, "string key material init should be inlined into <clinit>");
        assertEquals(0, standaloneStringStreamHelpers, "string stream helper should be inlined into the shared tail");
        assertEquals(0, oldStreamHelperMethods, "old string stream helper ABI should be absent");
        assertEquals(0, oldStreamHelperCalls, "shared string tail should not call old stream helper ABI");
        assertTrue(sawBoxedFingerprintCacheRead, "plaintext cache should read boxed live-key fingerprint state");
        assertTrue(sawBoxedFingerprintCacheWrite, "plaintext cache should write boxed live-key fingerprint state");
        assertTrue(sawCacheCompare, "plaintext cache should compare the current live-key fingerprint");
        assertTrue(sawCipherMonitor, "shared Cipher cache should be guarded for concurrent callers");
        assertEquals(clinitGetInstanceCalls, getInstanceCalls, "Cipher.getInstance should be limited to <clinit> cache setup");
        assertEquals(clinitGetBytesCalls, getBytesCalls, "encrypted payload getBytes should be limited to <clinit> setup");
        assertTrue(getInstanceCalls <= 2, "Cipher.getInstance should be per class algorithm, not per string site");
        assertTrue(sawSecretKeySpec, "string pass should build keys inline");
        assertTrue(sawDoFinal, "string pass should decrypt inline");
        assertTrue(sawSharedStringDecodeTail, "string decrypt body should be consolidated into shared tail helpers");
        assertTrue(sawTailLoadsStringMaterialSelectorSlot, "string shared tail should load a material selector from the passed CFF object carrier");
        assertFalse(sawTailDirectStringMaterialSlotLoad, "string shared tail should not directly load the fixed material slot");
        assertTrue(sawConcatLoadsClassKeySelectorSlot, "string concat helper should load class-key selector from the CFF object carrier");
        assertFalse(sawConcatDirectClassKeySlotLoad, "string concat helper should not directly load the fixed class-key slot");
        assertTrue(sawLiveFlowTailCall, "string shared tail calls should pass a live long flow key");
        assertTrue(checkedStringDataTailCalls > 0, "string shared tail calls should pass dataLocal-derived material");
        assertTrue(sawTailConsumesDataWord, "string shared tail should consume dataLocal-derived material");
        assertEquals(0, oldSharedTailAbiCalls, "string shared tail calls should not pass static payload/cache/length slots");
        assertTrue(sharedTailCount <= 1, "string shared tails should be selector-dispatched per class, not per algorithm/layer/order");
        assertEquals(0, siteHelperCount, "string decode should call shared tails directly instead of registering per-site wrappers");
        assertEquals(0, siteHelperDoFinalCalls, "per-site string wrappers should not duplicate Cipher.doFinal bodies");
        assertTrue(tailDoFinalCalls > 0, "shared string tail helpers should own Cipher.doFinal bodies");
        assertEquals(0, siteHelperTailCalls, "per-site string wrappers should be eliminated");
        assertTrue(sawUtf8, "decoded bytes should construct UTF-8 strings without UTF-8 LDC");
        assertTrue(sawClassKeyTableLoad, "decode should depend on CFF class key table");
        assertTrue(sawMethodKeyLoad, "decode should depend on keyDispatch/CFF method key local");
        assertTrue(sawXor, "decode should include XOR stream unmasking");
        assertTrue(sawKeyCellUpdate, "shared string tail should dynamically re-encode key material cells");
        assertFalse(sawSiteHelperKeyCellUpdate, "per-site string wrappers should pass key tables instead of owning key-cell updates");
        assertFalse(sawRotate, "string decode must not use rotate self-cancelling masks");
        assertFalse(sawStringConcatFactoryRecipe, "concat recipe strings should be rewritten and encrypted");
    }

    private void assertStringSitesHaveIndependentMaterialLayouts(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("StringShapes");
        List<StringMaterialCell> cells = new ArrayList<>();
        for (var method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            for (LiteralObjectArray rawCell : literalIntegerObjectArrays(method.instructions.toArray())) {
                StringMaterialCell decoded = decodeStringMaterialCell(rawCell);
                if (decoded != null) {
                    cells.add(decoded);
                }
            }
        }
        assertTrue(cells.size() >= 2, "string fixture should emit at least two string material cells");

        List<String> layoutFingerprints = new ArrayList<>();
        for (StringMaterialCell cell : cells) {
            String pair = cell.layoutId() + ":" + cell.fingerprint();
            if (!layoutFingerprints.contains(pair)) {
                layoutFingerprints.add(pair);
            }
        }
        assertTrue(
            layoutFingerprints.size() >= 2,
            "string sites should not share one layout/fingerprint pair: " + layoutFingerprints
        );

        boolean observedSeedDecodesEveryCell = false;
        for (StringMaterialCell candidate : cells) {
            boolean decodesEveryCell = true;
            for (StringMaterialCell cell : cells) {
                if (!decodesWords(cell.rawCell(), cell.words(), candidate.siteSeed(), cell.epoch())) {
                    decodesEveryCell = false;
                    break;
                }
            }
            if (decodesEveryCell) {
                observedSeedDecodesEveryCell = true;
                break;
            }
        }
        assertFalse(
            observedSeedDecodesEveryCell,
            "one observed string site seed decoded every material cell"
        );
    }

    private void assertStringKeyMaterialHasNoFixedIntArrayCell(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("StringShapes");
        int variableCells = 0;
        int fixedIntCells = 0;
        for (var method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            AbstractInsnNode[] insns = method.instructions.toArray();
            for (LiteralObjectArray rawCell : literalIntegerObjectArrays(insns)) {
                if (decodeStringMaterialCell(rawCell) != null) {
                    variableCells++;
                }
            }
            for (int[] rawCell : literalIntArrays(insns)) {
                if (rawCell.length == 11 && decodeFixedStringMaterialCell(rawCell) != null) {
                    fixedIntCells++;
                }
            }
        }
        assertTrue(variableCells >= 2, "string material should be emitted as variable Object[] cells");
        assertEquals(0, fixedIntCells, "fixed int[11] string key material cell survived");
    }

    private void assertStringProtectedMaterialIsDerived(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get("StringShapes");
        int materialCells = 0;
        int fragmentedWrites = 0;
        boolean sawTail = false;
        for (var method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            AbstractInsnNode[] insns = method.instructions.toArray();
            for (LiteralObjectArray rawCell : literalIntegerObjectArrays(insns)) {
                if (decodeStringMaterialCell(rawCell) == null) {
                    continue;
                }
                materialCells++;
                for (int i = 0; i < rawCell.values().length; i++) {
                    if (!rawCell.written()[i] || !(rawCell.values()[i] instanceof Number)) {
                        continue;
                    }
                    assertTrue(
                        rawCell.fragmented()[i],
                        "string material cell write used a direct boxed numeric constant at physical slot " + i
                    );
                    fragmentedWrites++;
                }
            }
            if (!method.name.startsWith("__neko_strtail$")) {
                continue;
            }
            sawTail = true;
            assertTrue(
                rootTransportConsumesDataWord(insns, 7, 0, insns.length),
                "shared string tail should derive material from input dataLocal"
            );
            assertTrue(
                methodKeyFoldStored(insns, 1, 3, 4, 5, 10),
                "shared string tail should fold hidden method key with CFF guard/path/block locals"
            );
            assertTrue(
                tailClassKeySelectionConsumesData(insns, 12),
                "shared string tail should select a class-key word through data-derived state"
            );
            assertTrue(
                tailDescriptorMaskConsumesDescriptor(insns, 44),
                "shared string token/selector masks should derive constants from the key-cell descriptor"
            );
        }
        assertTrue(materialCells >= 2, "string fixture should emit multiple derived string material cells");
        assertTrue(fragmentedWrites >= materialCells * 2, "string material cells should use fragmented numeric writes");
        assertTrue(sawTail, "string fixture should emit a shared string decode tail");
    }

    private void assertCompactConcatAbi(Path jar, String owner) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        int compactCalls = 0;
        int legacyStateCalls = 0;
        int compactHelpers = 0;
        boolean sawClassKeySelector = false;
        boolean sawLiveMethodKey = false;
        boolean sawLivePc = false;
        boolean sawRecoveredStateStores = false;
        for (var method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            AbstractInsnNode[] insns = method.instructions.toArray();
            boolean compactHelper = method.name.startsWith("__neko_strcat$")
                && method.desc.endsWith("JI)Ljava/lang/String;");
            if (compactHelper) {
                compactHelpers++;
                int intStores = 0;
                for (AbstractInsnNode insn : insns) {
                    if (pushesInt(insn, CLASS_KEY_WORDS_SELECTOR_SLOT)) {
                        sawClassKeySelector = true;
                    }
                    if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.LLOAD) {
                        sawLiveMethodKey = true;
                    }
                    if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ILOAD) {
                        sawLivePc = true;
                    }
                    if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ISTORE && var.var > 0) {
                        intStores++;
                    }
                }
                sawRecoveredStateStores |= intStores >= 4;
            }
            for (AbstractInsnNode insn : insns) {
                if (!(insn instanceof MethodInsnNode call)
                    || !owner.equals(call.owner)
                    || !call.name.startsWith("__neko_strcat$")) {
                    continue;
                }
                if (call.desc.endsWith("JI)Ljava/lang/String;")) {
                    compactCalls++;
                }
                if (call.desc.endsWith("JIIII)Ljava/lang/String;")) {
                    legacyStateCalls++;
                }
            }
        }
        assertTrue(compactCalls > 0, "size-pressure string concat fixture did not use compact concat ABI");
        assertEquals(0, legacyStateCalls, "size-pressure string concat callsites still pass guard/path/block locals");
        assertTrue(compactHelpers > 0, "compact concat helper was not emitted");
        assertTrue(sawClassKeySelector, "compact concat helper should select class-key words through the selector slot");
        assertTrue(sawLiveMethodKey, "compact concat helper should consume the live hidden method key");
        assertTrue(sawLivePc, "compact concat helper should consume the live pc token");
        assertTrue(sawRecoveredStateStores, "compact concat helper should recover state words into helper locals");
    }

    private void assertCompactStringTailAbi(Path jar, String owner) throws Exception {
        JarInput input = new JarInput(jar);
        L1Class clazz = input.classMap().get(owner);
        int compactCalls = 0;
        int legacyCallsInCompactMethods = 0;
        int compactTailHelpers = 0;
        boolean sawSelectorSlot = false;
        boolean sawRecoveredStateStores = false;
        boolean sawLiveMethodKey = false;
        for (var method : clazz.asmNode().methods) {
            if (method.instructions == null) continue;
            AbstractInsnNode[] insns = method.instructions.toArray();
            boolean compactTail = method.name.startsWith("__neko_strtail$")
                && "([Ljava/lang/Object;JIII)Ljava/lang/String;".equals(method.desc);
            if (compactTail) {
                compactTailHelpers++;
                int recoveredStores = 0;
                for (AbstractInsnNode insn : insns) {
                    if (pushesInt(insn, STRING_MATERIAL_SELECTOR_SLOT)) {
                        sawSelectorSlot = true;
                    }
                    if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.LLOAD && var.var == 1) {
                        sawLiveMethodKey = true;
                    }
                    if (insn instanceof VarInsnNode var
                        && var.getOpcode() == Opcodes.ISTORE
                        && (var.var == 6 || var.var == 7 || var.var == 8)) {
                        recoveredStores++;
                    }
                }
                sawRecoveredStateStores |= recoveredStores >= 3;
            }
            boolean generatedStringHelper = method.name.startsWith("__neko_strcat$")
                || method.name.startsWith("__neko_strtail$");
            boolean methodUsesCompactTail = false;
            int methodLegacyApplicationCalls = 0;
            for (AbstractInsnNode insn : insns) {
                if (!(insn instanceof MethodInsnNode call)
                    || !owner.equals(call.owner)
                    || !call.name.startsWith("__neko_strtail$")) {
                    continue;
                }
                if ("([Ljava/lang/Object;JIII)Ljava/lang/String;".equals(call.desc)) {
                    compactCalls++;
                    methodUsesCompactTail = true;
                }
                if (!generatedStringHelper && "([Ljava/lang/Object;JIIIIII)Ljava/lang/String;".equals(call.desc)) {
                    methodLegacyApplicationCalls++;
                }
            }
            if (methodUsesCompactTail) {
                legacyCallsInCompactMethods += methodLegacyApplicationCalls;
            }
        }
        assertTrue(compactCalls > 0, "size-pressure string fixture did not use compact string tail ABI");
        assertEquals(0, legacyCallsInCompactMethods, "compact string methods still pass guard/path/block locals");
        assertTrue(compactTailHelpers > 0, "compact string tail helper was not emitted");
        assertTrue(sawSelectorSlot, "compact string tail should still select string material through the selector slot");
        assertTrue(sawLiveMethodKey, "compact string tail should consume the live hidden method key");
        assertTrue(sawRecoveredStateStores, "compact string tail should recover guard/path/block locals from keyed metadata");
    }

    private List<int[]> literalIntArrays(AbstractInsnNode[] insns) {
        List<int[]> arrays = new ArrayList<>();
        for (int i = 0; i < insns.length; i++) {
            Integer length = pushedIntValue(insns[i]);
            if (length == null || length <= 0 || length > 256) continue;
            int newArray = nextRealIndex(insns, i + 1, insns.length);
            if (newArray < 0 ||
                !(insns[newArray] instanceof IntInsnNode arrayType) ||
                arrayType.getOpcode() != Opcodes.NEWARRAY ||
                arrayType.operand != Opcodes.T_INT) {
                continue;
            }
            int[] values = new int[length];
            boolean ok = true;
            int cursor = newArray + 1;
            for (int entry = 0; entry < length; entry++) {
                int dup = nextRealIndex(insns, cursor, insns.length);
                int indexInsn = dup < 0 ? -1 : nextRealIndex(insns, dup + 1, insns.length);
                int valueInsn = indexInsn < 0 ? -1 : nextRealIndex(insns, indexInsn + 1, insns.length);
                int store = valueInsn < 0 ? -1 : nextRealIndex(insns, valueInsn + 1, insns.length);
                Integer index = indexInsn < 0 ? null : pushedIntValue(insns[indexInsn]);
                Integer value = valueInsn < 0 ? null : pushedIntValue(insns[valueInsn]);
                if (dup < 0 ||
                    insns[dup].getOpcode() != Opcodes.DUP ||
                    index == null ||
                    value == null ||
                    index < 0 ||
                    index >= length ||
                    store < 0 ||
                    insns[store].getOpcode() != Opcodes.IASTORE) {
                    ok = false;
                    break;
                }
                values[index] = value;
                cursor = store + 1;
            }
            if (ok) {
                arrays.add(values);
                i = cursor;
            }
        }
        return arrays;
    }

    private List<LiteralObjectArray> literalIntegerObjectArrays(AbstractInsnNode[] insns) {
        List<LiteralObjectArray> arrays = new ArrayList<>();
        for (int i = 0; i < insns.length; i++) {
            Integer length = pushedIntValue(insns[i]);
            if (length == null || length <= 0 || length > 256) continue;
            int newArray = nextRealIndex(insns, i + 1, insns.length);
            if (newArray < 0 ||
                !(insns[newArray] instanceof TypeInsnNode arrayType) ||
                arrayType.getOpcode() != Opcodes.ANEWARRAY ||
                !"java/lang/Object".equals(arrayType.desc)) {
                continue;
            }
            Object[] values = new Object[length];
            boolean[] written = new boolean[length];
            boolean[] fragmented = new boolean[length];
            boolean ok = true;
            int cursor = newArray + 1;
            int stores = 0;
            while (true) {
                int dup = nextRealIndex(insns, cursor, insns.length);
                int indexInsn = dup < 0 ? -1 : nextRealIndex(insns, dup + 1, insns.length);
                int valueStart = indexInsn < 0 ? -1 : nextRealIndex(insns, indexInsn + 1, insns.length);
                int valueOf = valueStart < 0 ? -1 : nextBoxedNumberValueOfIndex(insns, valueStart, insns.length);
                int store = valueOf < 0 ? -1 : nextRealIndex(insns, valueOf + 1, insns.length);
                Integer index = indexInsn < 0 ? null : pushedIntValue(insns[indexInsn]);
                BoxedNumberLiteral literal = boxedNumberValue(insns, valueStart, valueOf);
                if (dup < 0 || insns[dup].getOpcode() != Opcodes.DUP) {
                    break;
                }
                if (index == null ||
                    literal == null ||
                    index < 0 ||
                    index >= length ||
                    valueOf < 0 ||
                    !isBoxedNumberValueOf(insns[valueOf]) ||
                    store < 0 ||
                    insns[store].getOpcode() != Opcodes.AASTORE) {
                    ok = false;
                    break;
                }
                values[index] = literal.value();
                written[index] = true;
                fragmented[index] = literal.fragmented();
                stores++;
                cursor = store + 1;
            }
            if (ok && stores > 0) {
                arrays.add(new LiteralObjectArray(values, written, fragmented));
                i = cursor;
            }
        }
        return arrays;
    }

    private boolean storesBoxedNumber(AbstractInsnNode insn) {
        if (!isBoxedNumberValueOf(insn)) return false;
        AbstractInsnNode cursor = insn.getNext();
        while (cursor != null && cursor.getOpcode() < 0) {
            cursor = cursor.getNext();
        }
        return cursor != null && cursor.getOpcode() == Opcodes.AASTORE;
    }

    private boolean isBoxedNumberValueOf(AbstractInsnNode insn) {
        if (!(insn instanceof MethodInsnNode call)) return false;
        if (call.getOpcode() != Opcodes.INVOKESTATIC || !"valueOf".equals(call.name)) return false;
        return ("java/lang/Integer".equals(call.owner) && "(I)Ljava/lang/Integer;".equals(call.desc))
            || ("java/lang/Long".equals(call.owner) && "(J)Ljava/lang/Long;".equals(call.desc));
    }

    private int nextBoxedNumberValueOfIndex(AbstractInsnNode[] insns, int fromInclusive, int limitExclusive) {
        for (int i = fromInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i].getOpcode() == Opcodes.AASTORE) {
                return -1;
            }
            if (isBoxedNumberValueOf(insns[i])) {
                return i;
            }
        }
        return -1;
    }

    private BoxedNumberLiteral boxedNumberValue(AbstractInsnNode[] insns, int valueStart, int valueOf) {
        if (valueStart < 0 || valueOf < 0 || !(insns[valueOf] instanceof MethodInsnNode call)) return null;
        if (call.getOpcode() != Opcodes.INVOKESTATIC || !"valueOf".equals(call.name)) return null;
        NumericValue value = evaluateNumericExpression(insns, valueStart, valueOf);
        if (value == null) return null;
        if ("java/lang/Integer".equals(call.owner) && "(I)Ljava/lang/Integer;".equals(call.desc)) {
            if (value.kind() != NumericKind.INT) return null;
            return new BoxedNumberLiteral((int) value.value(), value.fragmented());
        }
        if ("java/lang/Long".equals(call.owner) && "(J)Ljava/lang/Long;".equals(call.desc)) {
            if (value.kind() != NumericKind.LONG) return null;
            return new BoxedNumberLiteral(value.value(), value.fragmented());
        }
        return null;
    }

    private NumericValue evaluateNumericExpression(AbstractInsnNode[] insns, int startInclusive, int limitExclusive) {
        List<NumericValue> stack = new ArrayList<>();
        int realInsns = 0;
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            AbstractInsnNode insn = insns[i];
            int opcode = insn.getOpcode();
            if (opcode < 0) continue;
            realInsns++;
            Integer intValue = pushedIntValue(insn);
            if (intValue != null) {
                stack.add(new NumericValue(NumericKind.INT, intValue, false));
                continue;
            }
            Long longValue = pushedLongValue(insn);
            if (longValue != null) {
                stack.add(new NumericValue(NumericKind.LONG, longValue, false));
                continue;
            }
            NumericValue result = switch (opcode) {
                case Opcodes.I2L -> {
                    NumericValue value = popNumeric(stack, NumericKind.INT);
                    yield value == null ? null : new NumericValue(NumericKind.LONG, (long) (int) value.value(), true);
                }
                case Opcodes.IADD, Opcodes.ISUB, Opcodes.IMUL, Opcodes.IAND, Opcodes.IOR, Opcodes.IXOR,
                    Opcodes.ISHL, Opcodes.IUSHR -> evalIntBinary(stack, opcode);
                case Opcodes.LADD, Opcodes.LSUB, Opcodes.LMUL, Opcodes.LAND, Opcodes.LOR, Opcodes.LXOR ->
                    evalLongBinary(stack, opcode);
                case Opcodes.LSHL, Opcodes.LUSHR -> evalLongShift(stack, opcode);
                default -> null;
            };
            if (result == null) return null;
            stack.add(result);
        }
        if (stack.size() != 1) return null;
        NumericValue value = stack.get(0);
        return new NumericValue(value.kind(), value.value(), value.fragmented() || realInsns > 1);
    }

    private NumericValue evalIntBinary(List<NumericValue> stack, int opcode) {
        NumericValue right = popNumeric(stack, NumericKind.INT);
        NumericValue left = popNumeric(stack, NumericKind.INT);
        if (left == null || right == null) return null;
        int a = (int) left.value();
        int b = (int) right.value();
        int out = switch (opcode) {
            case Opcodes.IADD -> a + b;
            case Opcodes.ISUB -> a - b;
            case Opcodes.IMUL -> a * b;
            case Opcodes.IAND -> a & b;
            case Opcodes.IOR -> a | b;
            case Opcodes.IXOR -> a ^ b;
            case Opcodes.ISHL -> a << (b & 31);
            case Opcodes.IUSHR -> a >>> (b & 31);
            default -> throw new IllegalArgumentException("unexpected int opcode " + opcode);
        };
        return new NumericValue(NumericKind.INT, out, true);
    }

    private NumericValue evalLongBinary(List<NumericValue> stack, int opcode) {
        NumericValue right = popNumeric(stack, NumericKind.LONG);
        NumericValue left = popNumeric(stack, NumericKind.LONG);
        if (left == null || right == null) return null;
        long a = left.value();
        long b = right.value();
        long out = switch (opcode) {
            case Opcodes.LADD -> a + b;
            case Opcodes.LSUB -> a - b;
            case Opcodes.LMUL -> a * b;
            case Opcodes.LAND -> a & b;
            case Opcodes.LOR -> a | b;
            case Opcodes.LXOR -> a ^ b;
            default -> throw new IllegalArgumentException("unexpected long opcode " + opcode);
        };
        return new NumericValue(NumericKind.LONG, out, true);
    }

    private NumericValue evalLongShift(List<NumericValue> stack, int opcode) {
        NumericValue right = popNumeric(stack, NumericKind.INT);
        NumericValue left = popNumeric(stack, NumericKind.LONG);
        if (left == null || right == null) return null;
        int shift = ((int) right.value()) & 63;
        long out = opcode == Opcodes.LSHL ? left.value() << shift : left.value() >>> shift;
        return new NumericValue(NumericKind.LONG, out, true);
    }

    private NumericValue popNumeric(List<NumericValue> stack, NumericKind kind) {
        if (stack.isEmpty()) return null;
        NumericValue value = stack.remove(stack.size() - 1);
        return value.kind() == kind ? value : null;
    }

    private StringMaterialCell decodeStringMaterialCell(LiteralObjectArray rawCell) {
        Object[] values = rawCell.values();
        if (values.length != STRING_KEY_CELL_PHYSICAL_LENGTH) return null;
        if (!rawCell.written()[STRING_KEY_CELL_DESCRIPTOR_SLOT]) return null;
        if (!(values[STRING_KEY_CELL_DESCRIPTOR_SLOT] instanceof Integer descriptor)) return null;
        for (int logicalIndex = 0; logicalIndex <= STRING_KEY_CELL_LENGTH; logicalIndex++) {
            if (!rawCell.written()[stringKeyCellPackPhysicalIndex(descriptor, logicalIndex)]) {
                return null;
            }
        }
        int[] logicalValues = logicalStringCellValues(values, descriptor);
        int epoch = logicalValues[4];
        long siteSeed = ((long) (logicalValues[5] ^ stringSiteTokenCellMask(descriptor, epoch, 0)) << 32) |
            ((logicalValues[6] ^ stringSiteTokenCellMask(descriptor, epoch, 1)) & 0xFFFFFFFFL);
        int selector = logicalValues[7] ^ stringTailSelectorCellMask(descriptor, epoch);
        int layoutId = (selector >>> STRING_SELECTOR_LAYOUT_SHIFT) & STRING_SELECTOR_LAYOUT_MASK;
        int fingerprint = (selector >>> STRING_SELECTOR_FINGERPRINT_SHIFT) &
            STRING_SELECTOR_FINGERPRINT_MASK;
        if (layoutId == 0 || fingerprint == 0) return null;
        int payloadSlot = logicalValues[STRING_KEY_CELL_PAYLOAD_SLOT] ^ stringSiteMetadataCellMask(
            siteSeed,
            epoch,
            STRING_KEY_CELL_PAYLOAD_MASK
        );
        int cacheSlot = logicalValues[STRING_KEY_CELL_CACHE_SLOT] ^ stringSiteMetadataCellMask(
            siteSeed,
            epoch,
            STRING_KEY_CELL_CACHE_MASK
        );
        int encryptedLength = logicalValues[STRING_KEY_CELL_LENGTH] ^ stringSiteMetadataCellMask(
            siteSeed,
            epoch,
            STRING_KEY_CELL_LENGTH_MASK
        );
        if (payloadSlot < 0 || cacheSlot < 0 || encryptedLength <= 0 || encryptedLength > 4096) {
            return null;
        }
        int[] words = decodedWords(logicalValues, siteSeed, epoch);
        return new StringMaterialCell(logicalValues, siteSeed, epoch, layoutId, fingerprint, words);
    }

    private StringMaterialCell decodeFixedStringMaterialCell(int[] rawCell) {
        int epoch = rawCell[4];
        long siteSeed = ((long) (rawCell[5] ^ legacyStringSiteTokenCellMask(epoch, 0)) << 32) |
            ((rawCell[6] ^ legacyStringSiteTokenCellMask(epoch, 1)) & 0xFFFFFFFFL);
        int selector = rawCell[7] ^ legacyStringTailSelectorCellMask(epoch);
        int layoutId = (selector >>> STRING_SELECTOR_LAYOUT_SHIFT) & STRING_SELECTOR_LAYOUT_MASK;
        int fingerprint = (selector >>> STRING_SELECTOR_FINGERPRINT_SHIFT) &
            STRING_SELECTOR_FINGERPRINT_MASK;
        if (layoutId == 0 || fingerprint == 0) return null;
        int payloadSlot = rawCell[STRING_KEY_CELL_PAYLOAD_SLOT] ^ stringSiteMetadataCellMask(
            siteSeed,
            epoch,
            STRING_KEY_CELL_PAYLOAD_MASK
        );
        int cacheSlot = rawCell[STRING_KEY_CELL_CACHE_SLOT] ^ stringSiteMetadataCellMask(
            siteSeed,
            epoch,
            STRING_KEY_CELL_CACHE_MASK
        );
        int encryptedLength = rawCell[STRING_KEY_CELL_LENGTH] ^ stringSiteMetadataCellMask(
            siteSeed,
            epoch,
            STRING_KEY_CELL_LENGTH_MASK
        );
        if (payloadSlot < 0 || cacheSlot < 0 || encryptedLength <= 0 || encryptedLength > 4096) {
            return null;
        }
        int[] words = new int[STRING_LOGICAL_KEY_WORDS];
        for (int i = 0; i < words.length; i++) {
            words[i] = rawCell[i] ^ stringKeyCellMask(siteSeed, i, epoch);
        }
        return new StringMaterialCell(rawCell.clone(), siteSeed, epoch, layoutId, fingerprint, words);
    }

    private int[] decodedWords(int[] rawCell, long siteSeed, int epoch) {
        int[] words = new int[STRING_LOGICAL_KEY_WORDS];
        for (int i = 0; i < words.length; i++) {
            words[i] = rawCell[i] ^ stringKeyCellMask(siteSeed, i, epoch);
        }
        return words;
    }

    private boolean decodesWords(int[] rawCell, int[] expectedWords, long siteSeed, int epoch) {
        for (int i = 0; i < expectedWords.length; i++) {
            if ((rawCell[i] ^ stringKeyCellMask(siteSeed, i, epoch)) != expectedWords[i]) {
                return false;
            }
        }
        return true;
    }

    private int[] logicalStringCellValues(Object[] rawCell, int descriptor) {
        int[] values = new int[STRING_KEY_CELL_LENGTH + 1];
        for (int i = 0; i < values.length; i++) {
            values[i] = logicalCellValue(rawCell, descriptor, i);
        }
        return values;
    }

    private int logicalCellValue(Object[] rawCell, int descriptor, int logicalIndex) {
        Object value = rawCell[stringKeyCellPackPhysicalIndex(descriptor, logicalIndex)];
        if (!(value instanceof Number number)) {
            throw new IllegalArgumentException("missing numeric string cell pack");
        }
        long packed = number.longValue();
        if ((logicalIndex & 1) != 0) {
            packed >>>= 32;
        }
        return (int) packed;
    }

    private int stringKeyCellPackPhysicalIndex(int descriptor, int logicalIndex) {
        int stride = (descriptor & STRING_KEY_CELL_PHYSICAL_MASK) | 1;
        int offset = (descriptor >>> STRING_KEY_CELL_OFFSET_SHIFT) & STRING_KEY_CELL_PHYSICAL_MASK;
        return 1 + (((logicalIndex >>> 1) * stride + offset) & STRING_KEY_CELL_PHYSICAL_MASK);
    }

    private int stringKeyCellMask(long siteSeed, int wordIndex, int epoch) {
        int x = epoch ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354524B4D41534BL + wordIndex));
        x ^= x >>> shift(siteSeed, 9 + wordIndex);
        x *= nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354524B4D554C31L + wordIndex)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, 0x5354524B4D46494EL + wordIndex));
    }

    private int stringSiteTokenCellMask(int descriptor, int epoch, int wordIndex) {
        int x = epoch ^ stringDescriptorMaterial(descriptor, wordIndex, 0x5354525349544531L);
        x ^= x >>> (7 + wordIndex);
        x *= stringDescriptorMaterial(descriptor, wordIndex, 0x5354525349544532L) | 1;
        return x ^ stringDescriptorMaterial(descriptor, wordIndex, 0x5354525349544533L);
    }

    private int stringTailSelectorCellMask(int descriptor, int epoch) {
        int x = epoch ^ stringDescriptorMaterial(descriptor, 0x5441494C, 0x53545253454C3131L);
        x ^= x >>> 13;
        x *= stringDescriptorMaterial(descriptor, 0x5441494C, 0x53545253454C3132L) | 1;
        return x ^ stringDescriptorMaterial(descriptor, 0x5441494C, 0x53545253454C3133L);
    }

    private int stringDescriptorMaterial(int descriptor, int ordinal, long domain) {
        int x = descriptor ^ stringDescriptorMaterialWord(ordinal, domain, 0);
        x += descriptor >>> stringDescriptorMaterialShift(ordinal, 0);
        x ^= x >>> stringDescriptorMaterialShift(ordinal, 1);
        x *= stringDescriptorMaterialWord(ordinal, domain, 1) | 1;
        return x ^ stringDescriptorMaterialWord(ordinal, domain, 2);
    }

    private int stringDescriptorMaterialWord(int ordinal, long domain, int lane) {
        return nonZeroInt(JvmPassBytecode.mix(domain ^ ordinal, 0x5354524445534331L + lane));
    }

    private int stringDescriptorMaterialShift(int ordinal, int lane) {
        return 3 + ((ordinal + lane * 11) & 15);
    }

    private int legacyStringSiteTokenCellMask(int epoch, int wordIndex) {
        int x = epoch ^ nonZeroInt(JvmPassBytecode.mix(0x5354525349544531L, wordIndex));
        x ^= x >>> (7 + wordIndex);
        x *= nonZeroInt(JvmPassBytecode.mix(0x5354525349544532L, wordIndex)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(0x5354525349544533L, wordIndex));
    }

    private int legacyStringTailSelectorCellMask(int epoch) {
        int x = epoch ^ nonZeroInt(JvmPassBytecode.mix(0x53545253454C3131L, 0x5441494C53454CL));
        x ^= x >>> 13;
        x *= nonZeroInt(JvmPassBytecode.mix(0x53545253454C3132L, 0x5441494C53454CL)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(0x53545253454C3133L, 0x5441494C53454CL));
    }

    private int stringSiteMetadataCellMask(long siteSeed, int epoch, long maskSeed) {
        int x = epoch ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, maskSeed));
        x ^= x >>> shift(siteSeed, 11);
        x *= nonZeroInt(JvmPassBytecode.mix(siteSeed, maskSeed ^ 0x5354524D45544131L)) | 1;
        return x ^ nonZeroInt(JvmPassBytecode.mix(siteSeed, maskSeed ^ 0x5354524D45544132L));
    }

    private int shift(long seed, int base) {
        return 1 + (int) ((seed >>> base) & 30L);
    }

    private int nonZeroInt(long value) {
        int v = (int) value;
        return v == 0 ? 0x3D6B2A4F : v;
    }

    private boolean stringTailCallReceivesDataDigest(AbstractInsnNode[] insns, int callIndex) {
        int start = Math.max(0, callIndex - 40);
        int intLoads = 0;
        int longLoads = 0;
        int lastIntLoad = -1;
        for (int i = start; i < callIndex; i++) {
            if (insns[i] instanceof VarInsnNode load && load.getOpcode() == Opcodes.ILOAD) {
                intLoads++;
                lastIntLoad = i;
            } else if (insns[i] instanceof VarInsnNode load && load.getOpcode() == Opcodes.LLOAD) {
                longLoads++;
            }
        }
        if (longLoads == 0 || intLoads < 5 || lastIntLoad < 0) return false;
        int encodedSiteArgs = 0;
        for (int i = lastIntLoad + 1; i < callIndex; i++) {
            if (pushesAnyInt(insns[i])) {
                encodedSiteArgs++;
            }
        }
        return encodedSiteArgs >= 1;
    }

    private boolean tailSelectorDecodeConsumesDataWord(AbstractInsnNode[] insns) {
        int selectorLocal = 38;
        int dataWordLocal = 12;
        int siteSeedLocal = 22;
        return dataBoundSelectorBranchCount(insns, selectorLocal, dataWordLocal, siteSeedLocal) >= 4
            && plainSelectorBranchCount(insns, selectorLocal, dataWordLocal) == 0;
    }

    private boolean rootTransportConsumesDataWord(
        AbstractInsnNode[] insns,
        int dataLocal,
        int startInclusive,
        int limitExclusive
    ) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (!(insns[i] instanceof VarInsnNode load)
                || load.getOpcode() != Opcodes.ILOAD
                || load.var != dataLocal) {
                continue;
            }
            int limit = Math.min(limitExclusive, i + 80);
            if (hasOpcode(insns, Opcodes.IMUL, i + 1, limit)
                && hasOpcode(insns, Opcodes.IUSHR, i + 1, limit)
                && hasOpcode(insns, Opcodes.IOR, i + 1, limit)) {
                return true;
            }
        }
        return false;
    }

    private boolean methodKeyFoldStored(
        AbstractInsnNode[] insns,
        int methodKeyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int foldLocal
    ) {
        for (int i = 0; i < insns.length; i++) {
            if (!(insns[i] instanceof VarInsnNode store)
                || store.getOpcode() != Opcodes.ISTORE
                || store.var != foldLocal) {
                continue;
            }
            int start = Math.max(0, i - 24);
            if (longLoadCount(insns, methodKeyLocal, start, i) > 0
                && varLoadCount(insns, guardLocal, start, i) > 0
                && varLoadCount(insns, pathKeyLocal, start, i) > 0
                && varLoadCount(insns, blockKeyLocal, start, i) > 0
                && hasOpcode(insns, Opcodes.L2I, start, i)
                && hasOpcode(insns, Opcodes.IXOR, start, i)) {
                return true;
            }
        }
        return false;
    }

    private boolean tailClassKeySelectionConsumesData(AbstractInsnNode[] insns, int dataWordLocal) {
        for (int i = 0; i < insns.length; i++) {
            if (!pushesInt(insns[i], CLASS_KEY_WORDS_SELECTOR_SLOT)) {
                continue;
            }
            int limit = Math.min(insns.length, i + 120);
            if (varLoadCount(insns, dataWordLocal, i + 1, limit) == 0) continue;
            if (!hasOpcode(insns, Opcodes.IALOAD, i + 1, limit)) continue;
            if (!hasOpcode(insns, Opcodes.AALOAD, i + 1, limit)) continue;
            if (!hasTypeCast(insns, "[I", i + 1, limit)) continue;
            return true;
        }
        return false;
    }

    private boolean tailDescriptorMaskConsumesDescriptor(AbstractInsnNode[] insns, int descriptorLocal) {
        int derivedSlices = 0;
        for (int i = 0; i < insns.length; i++) {
            if (!(insns[i] instanceof VarInsnNode load)
                || load.getOpcode() != Opcodes.ILOAD
                || load.var != descriptorLocal) {
                continue;
            }
            int limit = Math.min(insns.length, i + 48);
            if (hasOpcode(insns, Opcodes.IXOR, i + 1, limit)
                && hasOpcode(insns, Opcodes.IUSHR, i + 1, limit)
                && hasOpcode(insns, Opcodes.IMUL, i + 1, limit)) {
                derivedSlices++;
            }
        }
        return derivedSlices >= 3;
    }

    private int dataBoundSelectorBranchCount(
        AbstractInsnNode[] insns,
        int selectorLocal,
        int dataWordLocal,
        int siteSeedLocal
    ) {
        int count = 0;
        for (int i = 0; i < insns.length; i++) {
            if (!(insns[i] instanceof VarInsnNode selectorLoad)
                || selectorLoad.getOpcode() != Opcodes.ILOAD
                || selectorLoad.var != selectorLocal) {
                continue;
            }
            int limit = Math.min(insns.length, i + 180);
            if (varLoadCount(insns, dataWordLocal, i + 1, limit) == 0) continue;
            if (longLoadCount(insns, siteSeedLocal, i + 1, limit) == 0) continue;
            if (!hasOpcode(insns, Opcodes.IAND, i + 1, limit)) continue;
            if (!hasOpcode(insns, Opcodes.IMUL, i + 1, limit)) continue;
            if (!hasOpcode(insns, Opcodes.IUSHR, i + 1, limit)) continue;
            if (!hasOpcode(insns, Opcodes.IXOR, i + 1, limit)) continue;
            int selectorBranch = firstSelectorBranch(insns, i + 1, limit);
            if (selectorBranch < 0) continue;
            if (opcodeCount(insns, Opcodes.IOR, i + 1, selectorBranch) < 2) continue;
            if (opcodeCount(insns, Opcodes.IMUL, i + 1, selectorBranch) < 2) continue;
            if (selectorBranch >= 0) {
                count++;
                i = selectorBranch;
            }
        }
        return count;
    }

    private int plainSelectorBranchCount(AbstractInsnNode[] insns, int selectorLocal, int dataWordLocal) {
        int count = 0;
        for (int i = 0; i < insns.length; i++) {
            if (!(insns[i] instanceof VarInsnNode selectorLoad)
                || selectorLoad.getOpcode() != Opcodes.ILOAD
                || selectorLoad.var != selectorLocal) {
                continue;
            }
            int limit = Math.min(insns.length, i + 80);
            if (varLoadCount(insns, dataWordLocal, i + 1, limit) != 0) continue;
            if (firstSelectorBranch(insns, i + 1, limit) >= 0) {
                count++;
            }
        }
        return count;
    }

    private int firstSelectorBranch(AbstractInsnNode[] insns, int startInclusive, int limitExclusive) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            int previous = previousRealIndex(insns, i);
            if (previous < 0) continue;
            if (insns[i].getOpcode() == Opcodes.IF_ICMPEQ
                && (pushesInt(insns[previous], 1) || pushesInt(insns[previous], 2))) {
                return i;
            }
            if (insns[i].getOpcode() == Opcodes.IFNE
                && insns[previous].getOpcode() == Opcodes.IAND) {
                return i;
            }
            if (insns[i].getOpcode() == Opcodes.IFEQ) {
                return i;
            }
        }
        return -1;
    }

    private int previousSelectorIand(AbstractInsnNode[] insns, int callIndex) {
        int start = Math.max(0, callIndex - 120);
        for (int i = callIndex - 1; i >= start; i--) {
            if (insns[i].getOpcode() != Opcodes.IAND) continue;
            int previous = previousRealIndex(insns, i);
            if (previous >= 0 && insns[previous].getOpcode() == Opcodes.ICONST_1) {
                return i;
            }
        }
        return -1;
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

    private boolean hasOpcode(AbstractInsnNode[] insns, int opcode, int startInclusive, int limitExclusive) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i].getOpcode() == opcode) return true;
        }
        return false;
    }

    private boolean hasTypeCast(AbstractInsnNode[] insns, String desc, int startInclusive, int limitExclusive) {
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof TypeInsnNode type
                && type.getOpcode() == Opcodes.CHECKCAST
                && desc.equals(type.desc)) {
                return true;
            }
        }
        return false;
    }

    private int opcodeCount(AbstractInsnNode[] insns, int opcode, int startInclusive, int limitExclusive) {
        int count = 0;
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i].getOpcode() == opcode) {
                count++;
            }
        }
        return count;
    }

    private int varLoadCount(AbstractInsnNode[] insns, int local, int startInclusive, int limitExclusive) {
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

    private int longLoadCount(AbstractInsnNode[] insns, int local, int startInclusive, int limitExclusive) {
        int count = 0;
        for (int i = startInclusive; i < limitExclusive && i < insns.length; i++) {
            if (insns[i] instanceof VarInsnNode load
                && load.getOpcode() == Opcodes.LLOAD
                && load.var == local) {
                count++;
            }
        }
        return count;
    }

    private static boolean pushesInt(AbstractInsnNode insn, int value) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return value == opcode - Opcodes.ICONST_0;
        }
        if (insn instanceof IntInsnNode intInsn) {
            return intInsn.operand == value;
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer intValue) {
            return intValue == value;
        }
        return false;
    }

    private static boolean pushesAnyInt(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5)
            || insn instanceof IntInsnNode
            || (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer);
    }

    private static Integer pushedIntValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return opcode - Opcodes.ICONST_0;
        }
        if (insn instanceof IntInsnNode intInsn) {
            return intInsn.operand;
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer intValue) {
            return intValue;
        }
        return null;
    }

    private static Long pushedLongValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.LCONST_0 || opcode == Opcodes.LCONST_1) {
            return (long) (opcode - Opcodes.LCONST_0);
        }
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Long longValue) {
            return longValue;
        }
        return null;
    }

    private record StringMaterialCell(
        int[] rawCell,
        long siteSeed,
        int epoch,
        int layoutId,
        int fingerprint,
        int[] words
    ) {}

    private record LiteralObjectArray(
        Object[] values,
        boolean[] written,
        boolean[] fragmented
    ) {}

    private enum NumericKind {
        INT,
        LONG
    }

    private record NumericValue(
        NumericKind kind,
        long value,
        boolean fragmented
    ) {}

    private record BoxedNumberLiteral(
        Object value,
        boolean fragmented
    ) {}

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

    private String concatPressureSourceText() {
        StringBuilder source = new StringBuilder();
        source.append("""
            public class StringConcatPressureShapes {
                public static void main(String[] args) {
                    String out = pressure(17);
                    System.out.println(out);
                    if (!out.startsWith("pressure:")) {
                        throw new AssertionError(out);
                    }
                }

                static String pressure(int seed) {
                    String s = "pressure-root";
                    int v = seed;
            """);
        for (int i = 0; i < 112; i++) {
            source.append("        v = (v * 1664525 + 1013904223) ^ ")
                .append(i)
                .append(";\n");
            source.append("        if ((v & ")
                .append((i % 7) + 1)
                .append(") == ")
                .append(i & 3)
                .append(") {\n");
            source.append("            v ^= s.length() + ")
                .append(i)
                .append(";\n");
            source.append("        } else {\n");
            source.append("            v += seed ^ ")
                .append(i)
                .append(";\n");
            source.append("        }\n");
            if (i % 5 == 0) {
                source.append("        s = s + \"|concat-pressure-")
                    .append(i)
                    .append("-\" + v;\n");
                source.append("        if (s.length() > 512) s = s.substring(s.length() - 256);\n");
            } else {
                source.append("        v ^= v >>> ")
                    .append((i % 11) + 1)
                    .append(";\n");
            }
        }
        source.append("""
                    return "pressure:" + s.length() + ":" + v + ":" + s.charAt(s.length() - 1);
                }
            }
            """);
        return source.toString();
    }

    private String sourceText() {
        return """
            public class StringShapes {
                private static final String FIELD_SECRET = "zeta-static-final-field-59";
                private static final String UNUSED_FIELD_SECRET = "eta-unused-static-field-61";

                public static void main(String[] args) {
                    String a = "alpha-secret-cff-flow-17";
                    String b = "omega-flow-tail-23";
                    String c = "beta-state-keydispatch-29";
                    String d = "gamma-aes-des-xor-31";
                    String e = "delta-domain-token-43";
                    String f = "epsilon-live-key-47";
                    String g = reflectedField();
                    String out = a + "|" + b.substring(11) + "|" + c + "|" + d + ":" + e + ":" + f + ":" + g;
                    System.out.println(out);
                    if (!out.equals("alpha-secret-cff-flow-17|tail-23|beta-state-keydispatch-29|gamma-aes-des-xor-31:delta-domain-token-43:epsilon-live-key-47:zeta-static-final-field-59")) {
                        throw new AssertionError(out);
                    }
                    System.out.println("STRING OBF OK");
                }

                private static String reflectedField() {
                    try {
                        java.lang.reflect.Field field = StringShapes.class.getDeclaredField("FIELD_SECRET");
                        field.setAccessible(true);
                        return (String) field.get(null);
                    } catch (ReflectiveOperationException ex) {
                        throw new AssertionError(ex);
                    }
                }
            }
            """;
    }

    private String interfaceSourceText() {
        return """
            interface InterfaceStrings {
                static String message() {
                    String left = "iface-flow-key-71";
                    String right = "iface-tail-73";
                    return left + ":" + right;
                }
            }

            public class InterfaceStringShapes {
                public static void main(String[] args) {
                    String out = InterfaceStrings.message();
                    System.out.println(out);
                    if (!out.equals("iface-flow-key-71:iface-tail-73")) {
                        throw new AssertionError(out);
                    }
                    System.out.println("INTERFACE STRING OBF OK");
                }
            }
            """;
    }

    private String identitySourceText() {
        return """
            public class StringIdentityShapes {
                public static void main(String[] args) {
                    String first = "identity-anchor-101";
                    String second = "identity-anchor-101";
                    if (first != second) {
                        throw new AssertionError("same-method literal identity");
                    }
                    java.util.concurrent.atomic.AtomicStampedReference<String> ref =
                        new java.util.concurrent.atomic.AtomicStampedReference<>("identity-anchor-101", 7);
                    if (!ref.compareAndSet("identity-anchor-101", "identity-replacement-103", 7, 8)) {
                        throw new AssertionError("atomic stamped reference identity");
                    }
                    System.out.println("STRING IDENTITY OBF OK");
                }
            }
            """;
    }
}
