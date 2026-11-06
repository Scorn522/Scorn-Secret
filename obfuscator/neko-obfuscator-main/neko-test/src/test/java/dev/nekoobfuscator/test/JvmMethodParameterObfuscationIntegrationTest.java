package dev.nekoobfuscator.test;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.jar.JarInput;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JvmMethodParameterObfuscationIntegrationTest {
    @Test
    void methodParameterObfuscationPacksEligibleMethodsIntoObjectArray() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-method-parameters"));
        Path source = work.resolve("ParameterShapes.java");
        Files.writeString(source, sourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("parameter-shapes.jar");
        writeJar(inputJar, classes, "ParameterShapes");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("parameter-shapes-obf.jar");
        runObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("PARAMETER OBF OK"), obfuscated);
        assertPackedDescriptors(outputJar);
        assertCallsUsePackedDescriptors(outputJar);
        assertCarrierIndexMarkersRemoved(outputJar);
        assertHiddenKeyCarrierReadsUseDecodedIndexes(outputJar);
        assertCarrierStoresUseDecodedIndexes(outputJar);
        assertCarrierAttestationValidationPresent(outputJar);
        assertForgedCarrierFails(work, outputJar);
    }

    private void runObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("methodParameterObfuscation", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("constantObfuscation", new TransformConfig(true, 1.0));
        transforms.put("stringObfuscation", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x4D504152414D31L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    @Test
    void interfaceDefaultPackedCarrierSurvivesFullProfileWrapping() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-interface-default-carrier"));
        Path source = work.resolve("PackedDefaultEntry.java");
        Files.writeString(source, interfaceDefaultCarrierSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("packed-default-entry.jar");
        writeJar(
            inputJar,
            classes,
            "PackedDefaultEntry",
            List.of(
                "PackedDefaultEntry$OverrideCase.class",
                "PackedDefaultEntry$SecondOverrideCase.class",
                "PackedDefaultEntry$CaseLike.class"
            )
        );
        String original = runJar(inputJar);

        Path outputJar = work.resolve("packed-default-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("DEFAULT ENTRY OK"), obfuscated);
    }

    @Test
    void topLevelFinalInterfaceCarrierSurvivesFullProfileWrapping() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-top-level-interface-carrier"));
        Path source = work.resolve("PackedTopLevelEntry.java");
        Files.writeString(source, topLevelInterfaceCarrierSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("packed-top-level-entry.jar");
        writeJar(
            inputJar,
            classes,
            "PackedTopLevelEntry",
            topLevelInterfaceCarrierFirstEntries()
        );
        String original = runJar(inputJar);

        Path outputJar = work.resolve("packed-top-level-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("TOP LEVEL ENTRY OK"), obfuscated);
    }

    @Test
    void recordMetadataAndCanonicalConstructorSurviveFullProfile() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-record-abi"));
        Path source = work.resolve("RecordAbiEntry.java");
        Files.writeString(source, recordAbiSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("record-abi-entry.jar");
        writeJar(inputJar, classes, "RecordAbiEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("record-abi-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("RECORD ABI OK"), obfuscated);
    }

    @Test
    void exactExternalReflectionLookupsKeepExternalAbiUnderFullProfile() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-external-reflection-abi"));
        Path source = work.resolve("ExternalReflectionAbiEntry.java");
        Files.writeString(source, externalReflectionAbiSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("external-reflection-abi-entry.jar");
        writeJar(inputJar, classes, "ExternalReflectionAbiEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("external-reflection-abi-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("EXTERNAL REFLECTION ABI OK"), obfuscated);
    }

    @Test
    void lambdaCapturedReflectiveMethodInvokeUsesPackedApplicationAbiUnderFullProfile() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-lambda-reflective-method"));
        Path source = work.resolve("LambdaReflectiveMethodEntry.java");
        Files.writeString(source, lambdaReflectiveMethodSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("lambda-reflective-method-entry.jar");
        writeJar(inputJar, classes, "LambdaReflectiveMethodEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("lambda-reflective-method-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("LAMBDA REFLECTIVE METHOD OK"), obfuscated);
    }

    @Test
    void childLoadedReflectiveConstructorUsesRuntimeCarrierTableUnderFullProfile() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-child-loader-reflective-carrier"));
        Path source = work.resolve("ChildLoaderReflectiveEntry.java");
        Files.writeString(source, childLoaderReflectiveCarrierSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("child-loader-reflective-carrier-entry.jar");
        writeJar(inputJar, classes, "ChildLoaderReflectiveEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("child-loader-reflective-carrier-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("CHILD LOADER REFLECTIVE CARRIER OK"), obfuscated);
    }

    @Test
    void interfaceDefaultReflectiveInvokeRuntimeCarrierHelperUsesJava8InterfaceAbi() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-interface-reflective-carrier"));
        Path source = work.resolve("InterfaceReflectiveCarrierEntry.java");
        Files.writeString(source, interfaceReflectiveCarrierSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(
            List.of("javac", "-J-XX:-UsePerfData", "--release", "8", "-d", classes.toString(), source.toString()),
            Duration.ofSeconds(30)
        );

        Path inputJar = work.resolve("interface-reflective-carrier-entry.jar");
        writeJar(inputJar, classes, "InterfaceReflectiveCarrierEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("interface-reflective-carrier-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("INTERFACE REFLECTIVE CARRIER OK"), obfuscated);
        assertNoInvalidRuntimeCarrierTableHelperInterfaceAbi(outputJar);
    }

    @Test
    void annotationEnumDefaultsSurviveFullProfileRenaming() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-annotation-enum-defaults"));
        Path source = work.resolve("AnnotationEnumDefaultEntry.java");
        Files.writeString(source, annotationEnumDefaultSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("annotation-enum-default-entry.jar");
        writeJar(inputJar, classes, "AnnotationEnumDefaultEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("annotation-enum-default-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("ANNOTATION ENUM DEFAULT OK"), obfuscated);
    }

    @Test
    void bridgeMethodsSurviveFullProfileAbiRewriting() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-bridge-abi"));
        Path source = work.resolve("BridgeAbiEntry.java");
        Files.writeString(source, bridgeAbiSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("bridge-abi-entry.jar");
        writeJar(inputJar, classes, "BridgeAbiEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("bridge-abi-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("BRIDGE ABI OK"), obfuscated);
    }

    @Test
    void serviceProviderConstructorsSurviveFullProfileAbiRewriting() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-service-abi"));
        Path source = work.resolve("ServiceLoaderAbiEntry.java");
        Files.writeString(source, serviceLoaderAbiSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("service-loader-abi-entry.jar");
        writeJar(
            inputJar,
            classes,
            "ServiceLoaderAbiEntry",
            Map.of("META-INF/services/ServiceLoaderAbiEntry$Greeting", "ServiceLoaderAbiEntry$Provider\n")
        );
        String original = runJar(inputJar);

        Path outputJar = work.resolve("service-loader-abi-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("SERVICE ABI OK"), obfuscated);
    }

    @Test
    void methodParametersMetadataSurvivesFullProfileAbiRewriting() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-method-parameters-abi"));
        Path source = work.resolve("MethodParametersAbiEntry.java");
        Files.writeString(source, methodParametersAbiSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-parameters", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("method-parameters-abi-entry.jar");
        writeJar(inputJar, classes, "MethodParametersAbiEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("method-parameters-abi-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("METHOD PARAMETERS ABI OK"), obfuscated);
    }

    @Test
    void serializationMagicMembersSurviveFullProfileAbiRewriting() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-serialization-abi"));
        Path source = work.resolve("SerializationAbiEntry.java");
        Files.writeString(source, serializationAbiSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("serialization-abi-entry.jar");
        writeJar(inputJar, classes, "SerializationAbiEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("serialization-abi-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("SERIALIZATION ABI OK"), obfuscated);
    }

    @Test
    void varargsMetadataIsConsistentAfterFullProfilePacking() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-varargs-metadata-abi"));
        Path source = work.resolve("VarargsMetadataAbiEntry.java");
        Files.writeString(source, varargsMetadataAbiSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("varargs-metadata-abi-entry.jar");
        writeJar(inputJar, classes, "VarargsMetadataAbiEntry");
        String original = runJar(inputJar);

        Path outputJar = work.resolve("varargs-metadata-abi-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("VARARGS METADATA ABI OK"), obfuscated);
        assertNoInvalidVarargsMetadata(outputJar);
    }

    @Test
    void packedInterfaceEntrySurvivesCrossClassStringTailDecode() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-cross-class-string-tail"));
        Path source = work.resolve("PackedStringTailEntry.java");
        Files.writeString(source, crossClassStringTailSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("packed-string-tail-entry.jar");
        writeJar(
            inputJar,
            classes,
            "PackedStringTailEntry",
            List.of(
                "PackedStringTailHostCase.class",
                "PackedStringTailOtherCase.class",
                "PackedStringTailCaseLike.class"
            )
        );
        String original = runJar(inputJar);

        Path outputJar = work.resolve("packed-string-tail-entry-obf.jar");
        runCffStringObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("STRING TAIL ENTRY OK"), obfuscated);
    }

    @Test
    void packedConstructorStringTailUsesLiveCffState() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-constructor-string-tail"));
        Path source = work.resolve("ConstructorStringTailEntry.java");
        Files.writeString(source, constructorStringTailSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("constructor-string-tail-entry.jar");
        writeJar(
            inputJar,
            classes,
            "ConstructorStringTailEntry",
            List.of(
                "ConstructorStringTailBase.class",
                "ConstructorStringTailChild.class"
            )
        );
        String original = runJar(inputJar);

        Path outputJar = work.resolve("constructor-string-tail-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("CONSTRUCTOR STRING TAIL OK"), obfuscated);
    }

    @Test
    void packedConcurrentStringTailDecodeIsThreadSafe() throws Exception {
        Path projectRoot = Path.of(System.getProperty("neko.test.projectRoot", System.getProperty("user.dir")));
        Path work = Files.createDirectories(projectRoot.resolve("build/tmp/neko-test-concurrent-string-tail"));
        Path source = work.resolve("ConcurrentStringTailEntry.java");
        Files.writeString(source, concurrentStringTailSourceText(), StandardCharsets.UTF_8);

        Path classes = Files.createDirectories(work.resolve("classes"));
        run(List.of("javac", "-d", classes.toString(), source.toString()), Duration.ofSeconds(30));

        Path inputJar = work.resolve("concurrent-string-tail-entry.jar");
        writeJar(inputJar, classes, "ConcurrentStringTailEntry", List.of());
        String original = runJar(inputJar);

        Path outputJar = work.resolve("concurrent-string-tail-entry-obf.jar");
        runFullProfileObfuscation(inputJar, outputJar);
        String obfuscated = runJar(outputJar);

        assertEquals(original, obfuscated);
        assertTrue(obfuscated.contains("CONCURRENT STRING TAIL OK"), obfuscated);
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
        config.keyConfig().setMasterSeed(0x44454641554C54L);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private void runCffStringObfuscation(Path input, Path output) throws Exception {
        ObfuscationConfig config = new ObfuscationConfig();
        config.setInputJar(input);
        config.setOutputJar(output);
        Map<String, TransformConfig> transforms = new LinkedHashMap<>();
        transforms.put("renamer", new TransformConfig(true, 1.0, Map.of("packagePrefix", "a/")));
        transforms.put("keyDispatch", new TransformConfig(true, 1.0));
        transforms.put("methodParameterObfuscation", new TransformConfig(true, 1.0));
        transforms.put("controlFlowFlattening", new TransformConfig(true, 1.0));
        transforms.put("validationSinkHardening", new TransformConfig(false, 1.0));
        transforms.put("invokeDynamic", new TransformConfig(false, 1.0));
        transforms.put("constantObfuscation", new TransformConfig(false, 1.0));
        transforms.put("stringObfuscation", new TransformConfig(true, 1.0));
        config.setTransforms(transforms);
        config.keyConfig().setMasterSeed(0x5354525441494CL);

        PassRegistry registry = new PassRegistry();
        StandardJvmPasses.register(registry);
        new ObfuscationPipeline(config, registry).execute(input, output);
    }

    private List<String> topLevelInterfaceCarrierFirstEntries() {
        List<String> entries = new ArrayList<>();
        for (int index = 0; index < 24; index++) {
            entries.add("PackedTopLevelCase%02d.class".formatted(index));
        }
        entries.add("PackedTopLevelClassLiteralCase.class");
        entries.add("PackedTopLevelSecondCase.class");
        entries.add("PackedTopLevelCaseLike.class");
        return entries;
    }

    private void assertPackedDescriptors(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        for (L1Class clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("ParameterShapes")) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                if ("<clinit>".equals(method.name)) continue;
                if ("main".equals(method.name) && "([Ljava/lang/String;)V".equals(method.desc)) continue;
                if (method.name.startsWith("__neko_")) continue;
                assertTrue(
                    isPackedParameterDescriptor(method.desc),
                    clazz.name() + "." + method.name + method.desc + " was not packed"
                );
            }
        }
    }

    private void assertCallsUsePackedDescriptors(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        for (L1Class clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("ParameterShapes")) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                if ("<clinit>".equals(method.name) || method.name.startsWith("__neko_")) continue;
                if ("main".equals(method.name) && "([Ljava/lang/String;)V".equals(method.desc)) continue;
                for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode call)) continue;
                    if (!call.owner.startsWith("ParameterShapes")) continue;
                    if ("<clinit>".equals(call.name)) continue;
                    if (call.name.startsWith("__neko_")) continue;
                    assertTrue(
                        isPackedParameterDescriptor(call.desc),
                        "application call was not packed: " + call.owner + "." + call.name + call.desc
                    );
                }
            }
        }
    }

    private void assertCarrierIndexMarkersRemoved(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        for (L1Class clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("ParameterShapes")) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                if ("<clinit>".equals(method.name) || method.name.startsWith("__neko_")) continue;
                if ("main".equals(method.name) && "([Ljava/lang/String;)V".equals(method.desc)) continue;
                for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode call)) continue;
                    assertTrue(
                        !"dev/nekoobfuscator/runtime/CarrierIndex".equals(call.owner),
                        "carrier index marker leaked into generated jar: " +
                            clazz.name() + "." + method.name + method.desc
                    );
                }
            }
        }
    }

    private void assertHiddenKeyCarrierReadsUseDecodedIndexes(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        int decodedHiddenKeyReads = 0;
        for (L1Class clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("ParameterShapes")) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                if ("<clinit>".equals(method.name) || method.name.startsWith("__neko_")) continue;
                if (method.instructions == null || !isPackedParameterDescriptor(method.desc)) continue;
                for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof TypeInsnNode cast) || !"java/lang/Long".equals(cast.desc)) continue;
                    AbstractInsnNode load = previousReal(insn.getPrevious());
                    if (!(load instanceof InsnNode aaload) || aaload.getOpcode() != Opcodes.AALOAD) continue;
                    AbstractInsnNode index = previousReal(load.getPrevious());
                    assertTrue(
                        index == null || !isIntConstant(index),
                        "hidden key carrier read still uses a literal index in " +
                            clazz.name() + "." + method.name + method.desc
                    );
                    assertTrue(
                        hasClassKeyObjectFieldLoadBefore(load),
                        "hidden key carrier read does not use class-key table material in " +
                            clazz.name() + "." + method.name + method.desc
                    );
                    decodedHiddenKeyReads++;
                }
            }
        }
        assertTrue(decodedHiddenKeyReads > 0, "no decoded hidden key carrier reads were found");
    }

    private void assertCarrierStoresUseDecodedIndexes(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        int decodedStores = 0;
        for (L1Class clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("ParameterShapes")) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                if ("<clinit>".equals(method.name) || method.name.startsWith("__neko_")) continue;
                for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof InsnNode store) || store.getOpcode() != Opcodes.AASTORE) continue;
                    AbstractInsnNode index = previousCarrierStoreIndex(store);
                    if (index == null) continue;
                    if (!isIntConstant(index) && hasClassKeyObjectFieldLoadBefore(store)) {
                        decodedStores++;
                    }
                }
            }
        }
        assertTrue(decodedStores >= 8, "expected decoded carrier stores for direct, virtual, MethodHandle, and reflection paths");
    }

    private void assertCarrierAttestationValidationPresent(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        int guardedPackedMethods = 0;
        for (L1Class clazz : input.classMap().values()) {
            if (!clazz.name().startsWith("ParameterShapes")) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                if ("<clinit>".equals(method.name) || method.name.startsWith("__neko_")) continue;
                if (method.instructions == null || !isPackedParameterDescriptor(method.desc)) continue;
                int longCarrierReads = countLongCarrierReads(method);
                if (longCarrierReads < 3) continue;
                assertTrue(
                    countLongCompareGuards(method) >= 2,
                    "packed carrier attestation did not compare a derived long tag in " +
                        clazz.name() + "." + method.name + method.desc
                );
                assertTrue(
                    hasHardFailThrow(method),
                    "packed carrier attestation did not hard-fail in " +
                        clazz.name() + "." + method.name + method.desc
                );
                guardedPackedMethods++;
            }
        }
        assertTrue(guardedPackedMethods > 0, "no packed carrier attestation guards were found");
    }

    private void assertNoInvalidVarargsMetadata(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        for (L1Class clazz : input.classMap().values()) {
            for (L1Method method : clazz.methods()) {
                MethodNode mn = method.asmNode();
                if ((mn.access & Opcodes.ACC_VARARGS) == 0) continue;
                Type[] args = Type.getArgumentTypes(mn.desc);
                assertTrue(
                    args.length > 0 && args[args.length - 1].getSort() == Type.ARRAY,
                    () -> "invalid ACC_VARARGS metadata in " + clazz.name() + "." + mn.name + mn.desc
                );
            }
        }
    }

    private void assertForgedCarrierFails(Path work, Path jar) throws Exception {
        Path source = work.resolve("ForgedCarrierProbe.java");
        Files.writeString(source, forgedCarrierProbeText(), StandardCharsets.UTF_8);
        Path classes = Files.createDirectories(work.resolve("probe-classes"));
        run(
            List.of(
                "javac",
                "-J-XX:-UsePerfData",
                "-cp",
                jar.toString(),
                "-d",
                classes.toString(),
                source.toString()
            ),
            Duration.ofSeconds(30)
        );
        String output = run(
            List.of(
                "java",
                "-XX:-UsePerfData",
                "-cp",
                classes + System.getProperty("path.separator") + jar,
                "ForgedCarrierProbe"
            ),
            Duration.ofSeconds(30)
        );
        assertTrue(output.contains("FORGED CARRIER REJECTED"), output);
    }

    private String forgedCarrierProbeText() {
        return """
            import java.lang.reflect.InvocationTargetException;
            import java.lang.reflect.Method;
            import java.util.Arrays;

            public final class ForgedCarrierProbe {
                public static void main(String[] args) throws Exception {
                    Method target = null;
                    for (Method method : ParameterShapes.class.getDeclaredMethods()) {
                        if (method.getName().equals("add")
                            && method.getParameterCount() >= 1
                            && method.getParameterTypes()[0].isArray()) {
                            target = method;
                            break;
                        }
                    }
                    if (target == null) {
                        throw new AssertionError("packed add missing");
                    }
                    target.setAccessible(true);
                    Object[] carrier = new Object[5];
                    Arrays.fill(carrier, Long.valueOf(0L));
                    Object[] invokeArgs = target.getParameterCount() == 2
                        ? new Object[] {carrier, Long.valueOf(0L)}
                        : new Object[] {carrier};
                    try {
                        target.invoke(null, invokeArgs);
                        throw new AssertionError("forged carrier accepted");
                    } catch (InvocationTargetException ex) {
                        Throwable cause = ex.getCause();
                        if (!(cause instanceof SecurityException)) {
                            throw new AssertionError("unexpected forged-carrier failure: " + cause, cause);
                        }
                    }
                    System.out.println("FORGED CARRIER REJECTED");
                }
            }
            """;
    }

    private int countLongCarrierReads(MethodNode method) {
        int reads = 0;
        for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof TypeInsnNode cast && "java/lang/Long".equals(cast.desc)) {
                AbstractInsnNode load = previousReal(insn.getPrevious());
                if (load instanceof InsnNode aaload && aaload.getOpcode() == Opcodes.AALOAD) {
                    reads++;
                }
            }
        }
        return reads;
    }

    private int countLongCompareGuards(MethodNode method) {
        int guards = 0;
        for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof InsnNode cmp) || cmp.getOpcode() != Opcodes.LCMP) continue;
            int scanned = 0;
            for (AbstractInsnNode next = insn.getNext(); next != null && scanned++ < 8; next = next.getNext()) {
                if (next.getOpcode() < 0) continue;
                int opcode = next.getOpcode();
                if (opcode == Opcodes.IFEQ || opcode == Opcodes.IFNE) {
                    guards++;
                    break;
                }
            }
        }
        return guards;
    }

    private boolean hasHardFailThrow(MethodNode method) {
        boolean sawSecurityException = false;
        for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof TypeInsnNode type
                && type.getOpcode() == Opcodes.NEW
                && "java/lang/SecurityException".equals(type.desc)) {
                sawSecurityException = true;
                continue;
            }
            if (sawSecurityException && insn.getOpcode() == Opcodes.ATHROW) return true;
            if (insn.getOpcode() == Opcodes.ATHROW) {
                AbstractInsnNode previous = previousReal(insn.getPrevious());
                if (previous != null && previous.getOpcode() == Opcodes.ACONST_NULL) return true;
            }
        }
        return false;
    }

    private AbstractInsnNode previousCarrierStoreIndex(AbstractInsnNode store) {
        AbstractInsnNode scan = store.getPrevious();
        for (int seen = 0; scan != null && seen++ < 96; scan = scan.getPrevious()) {
            if (scan.getOpcode() < 0) continue;
            if (!(scan instanceof InsnNode dup) || dup.getOpcode() != Opcodes.DUP) continue;
            AbstractInsnNode index = nextReal(dup.getNext());
            if (index == null || index == store) continue;
            AbstractInsnNode cursor = nextReal(index.getNext());
            while (cursor != null && cursor != store) {
                if (cursor.getOpcode() == Opcodes.AASTORE) break;
                cursor = nextReal(cursor.getNext());
            }
            if (cursor == store) return index;
        }
        return null;
    }

    private AbstractInsnNode nextReal(AbstractInsnNode start) {
        for (AbstractInsnNode insn = start; insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) return insn;
        }
        return null;
    }

    private AbstractInsnNode previousReal(AbstractInsnNode start) {
        for (AbstractInsnNode insn = start; insn != null; insn = insn.getPrevious()) {
            if (insn.getOpcode() >= 0) return insn;
        }
        return null;
    }

    private boolean hasClassKeyObjectFieldLoadBefore(AbstractInsnNode anchor) {
        int scanned = 0;
        for (AbstractInsnNode insn = anchor.getPrevious(); insn != null && scanned++ < 192; insn = insn.getPrevious()) {
            if (insn instanceof FieldInsnNode field
                && field.getOpcode() == Opcodes.GETSTATIC
                && "[Ljava/lang/Object;".equals(field.desc)) {
                return true;
            }
        }
        return false;
    }

    private boolean isIntConstant(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) return true;
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) return true;
        return insn instanceof org.objectweb.asm.tree.LdcInsnNode ldc && ldc.cst instanceof Integer;
    }

    private boolean isPackedParameterDescriptor(String desc) {
        Type[] args = Type.getArgumentTypes(desc);
        return args.length > 0 && "[Ljava/lang/Object;".equals(args[0].getDescriptor());
    }

    private void assertNoInvalidRuntimeCarrierTableHelperInterfaceAbi(Path jar) throws Exception {
        JarInput input = new JarInput(jar);
        for (L1Class clazz : input.classMap().values()) {
            if (!clazz.isInterface()) continue;
            for (MethodNode method : clazz.asmNode().methods) {
                if (!"(Ljava/lang/Object;Ljava/lang/Object;I)[Ljava/lang/Object;".equals(method.desc)) continue;
                if ((method.access & Opcodes.ACC_STATIC) == 0 || (method.access & Opcodes.ACC_SYNTHETIC) == 0) {
                    continue;
                }
                assertTrue(
                    (method.access & Opcodes.ACC_PUBLIC) != 0,
                    "runtime carrier table helper in interface is not public: " +
                        clazz.name() + "." + method.name + method.desc
                );
                assertTrue(
                    (method.access & Opcodes.ACC_PRIVATE) == 0,
                    "runtime carrier table helper in interface is private: " +
                        clazz.name() + "." + method.name + method.desc
                );
            }
        }
        for (L1Class clazz : input.classMap().values()) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                for (var insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode call)) continue;
                    if (call.getOpcode() != Opcodes.INVOKESTATIC) continue;
                    if (!"(Ljava/lang/Object;Ljava/lang/Object;I)[Ljava/lang/Object;".equals(call.desc)) continue;
                    L1Class owner = input.classMap().get(call.owner);
                    if (owner == null || !owner.isInterface()) continue;
                    assertTrue(
                        call.itf,
                        "runtime carrier table helper interface call is not marked as interface: " +
                            clazz.name() + "." + method.name + method.desc
                    );
                }
            }
        }
    }

    private void writeJar(Path jar, Path classes, String mainClass) throws Exception {
        writeJar(jar, classes, mainClass, List.of());
    }

    private void writeJar(Path jar, Path classes, String mainClass, Map<String, String> resources) throws Exception {
        writeJar(jar, classes, mainClass, List.of(), resources);
    }

    private void writeJar(Path jar, Path classes, String mainClass, List<String> firstEntries) throws Exception {
        writeJar(jar, classes, mainClass, firstEntries, Map.of());
    }

    private void writeJar(
        Path jar,
        Path classes,
        String mainClass,
        List<String> firstEntries,
        Map<String, String> resources
    ) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", mainClass);
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            List<Path> classFiles = new ArrayList<>();
            try (var stream = Files.walk(classes)) {
                stream.filter(path -> path.toString().endsWith(".class")).forEach(classFiles::add);
            }
            Map<String, Path> byEntry = new LinkedHashMap<>();
            for (Path classFile : classFiles) {
                String name = classes.relativize(classFile).toString().replace('\\', '/');
                byEntry.put(name, classFile);
            }
            for (String entryName : firstEntries) {
                Path classFile = byEntry.remove(entryName);
                if (classFile != null) {
                    writeJarEntry(jos, entryName, classFile);
                }
            }
            for (Map.Entry<String, Path> entry : byEntry.entrySet()) {
                writeJarEntry(jos, entry.getKey(), entry.getValue());
            }
            for (Map.Entry<String, String> entry : resources.entrySet()) {
                writeResourceEntry(jos, entry.getKey(), entry.getValue());
            }
        }
    }

    private void writeJarEntry(JarOutputStream jos, String name, Path classFile) throws Exception {
        jos.putNextEntry(new JarEntry(name));
        jos.write(Files.readAllBytes(classFile));
        jos.closeEntry();
    }

    private void writeResourceEntry(JarOutputStream jos, String name, String data) throws Exception {
        jos.putNextEntry(new JarEntry(name));
        jos.write(data.getBytes(StandardCharsets.UTF_8));
        jos.closeEntry();
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
            import java.lang.reflect.Constructor;
            import java.lang.reflect.Method;
            import java.lang.invoke.MethodHandle;
            import java.lang.invoke.MethodHandles;
            import java.lang.invoke.MethodType;
            import java.util.Arrays;
            import java.util.Locale;
            import java.util.Set;

            public class ParameterShapes {
                interface Worker {
                    int work(int value, String text);
                }

                interface ReflectInvoker {
                    int invoke(Method method, Object target, Object[] args) throws Throwable;
                }

                interface CaseLike {
                    String id();

                    default Set<String> tags() {
                        return Set.of();
                    }
                }

                static class Impl implements Worker {
                    public int work(int value, String text) {
                        return value + text.length();
                    }
                }

                static class DefaultCase implements CaseLike {
                    public String id() {
                        return "alpha-default";
                    }
                }

                static class Options {
                    boolean accepts(String value, Iterable<String> patterns) {
                        String lower = value.toLowerCase(Locale.ROOT);
                        int length = 0;
                        for (String pattern : patterns) {
                            length += pattern.toLowerCase(Locale.ROOT).length();
                        }
                        return lower.startsWith("alpha") && length == 0;
                    }
                }

                static class ReflectInvokerImpl implements ReflectInvoker {
                    public int invoke(Method method, Object target, Object[] args) throws Throwable {
                        method.setAccessible(true);
                        return ((Integer) method.invoke(target, args)).intValue();
                    }
                }

                static class Box {
                    private final int base;
                    private final String tag;

                    Box(int base) {
                        this(base, "q");
                    }

                    Box(int base, String tag) {
                        this.base = base;
                        this.tag = tag;
                    }

                    int mix(int a, long b, double c, Object[] values) {
                        return base + tag.length() + a + (int) b + (int) c + values.length;
                    }
                }

                static class SpecialBox extends Box {
                    SpecialBox(int base, String tag) {
                        super(base, tag);
                    }

                    int mix(int a, long b, double c, Object[] values) {
                        return -1000;
                    }

                    int callSuper(MethodHandle handle) throws Throwable {
                        return (int) handle.invokeExact(this, 5, 6L, 7.0d, new Object[] {"s"});
                    }
                }

                static class UnusedConstructor {
                    UnusedConstructor() {
                    }
                }

                static class TraceLike {
                    static int count;

                    private void bounce(int value) throws Throwable {
                        count++;
                        String name = new Throwable().getStackTrace()[1].getMethodName();
                        Method method = TraceLike.class.getDeclaredMethod(name, int.class);
                        method.setAccessible(true);
                        method.invoke(this, new Object[] {value - 1});
                    }

                    public void entry(int value) throws Throwable {
                        if (value == 0) return;
                        bounce(value);
                    }
                }

                static class NewInstanceTarget {
                    NewInstanceTarget() {
                    }

                    int value() {
                        return 11;
                    }
                }

                public static void main(String[] args) throws Throwable {
                    String out = runAll(args);
                    System.out.println(out);
                    if (!out.equals("total:420:true")) {
                        throw new AssertionError(out);
                    }
                    System.out.println("PARAMETER OBF OK");
                }

                static String runAll(String[] args) throws Throwable {
                    ParameterShapes shapes = new ParameterShapes();
                    Worker worker = new Impl();
                    Box box = new Box(3, "xy");
                    int direct = directAndReflectionPaths(shapes, worker, box);
                    if (direct != 291) {
                        throw new AssertionError("direct:" + direct);
                    }
                    int methodHandles = methodHandlePaths(box);
                    if (methodHandles != 67) {
                        throw new AssertionError("methodHandles:" + methodHandles);
                    }
                    int interfaces = interfacePaths(worker);
                    if (interfaces != 62) {
                        throw new AssertionError("interfaces:" + interfaces);
                    }
                    int total = direct + methodHandles + interfaces;
                    return join("total", total, Arrays.asList(args).isEmpty());
                }

                static int directAndReflectionPaths(ParameterShapes shapes, Worker worker, Box box) throws Throwable {
                    int direct = directCore(shapes, worker, box);
                    if (direct != 88) {
                        throw new AssertionError("direct-core:" + direct);
                    }
                    int reflectedMethods = reflectMethods();
                    if (reflectedMethods != 105) {
                        throw new AssertionError("reflect-methods:" + reflectedMethods);
                    }
                    int reflectedConstructor = reflectConstructor();
                    if (reflectedConstructor != 98) {
                        throw new AssertionError("reflect-constructor:" + reflectedConstructor);
                    }
                    int total = direct;
                    total += reflectedMethods;
                    total += reflectedConstructor;
                    return total;
                }

                static int directCore(ParameterShapes shapes, Worker worker, Box box) {
                    int total = add(4, 5);
                    if (total != 9) throw new AssertionError("core-add:" + total);
                    total += shapes.noArg();
                    if (total != 15) throw new AssertionError("core-noarg:" + total);
                    total += shapes.overload(7);
                    if (total != 23) throw new AssertionError("core-overload-int:" + total);
                    total += shapes.overload("abcd");
                    if (total != 29) throw new AssertionError("core-overload-string:" + total);
                    total += shapes.overload(2, 6);
                    if (total != 41) throw new AssertionError("core-overload-two:" + total);
                    total += worker.work(8, "abc");
                    if (total != 52) throw new AssertionError("core-worker:" + total);
                    total += box.mix(9, 10L, 11.0d, new Object[] {"z"});
                    return total;
                }

                static int reflectMethods() throws Throwable {
                    int total = 0;
                    Class<?> actualOwner = ParameterShapes.class;
                    String actualName = "reflectTarget";
                    Class<?>[] actualParams = new Class<?>[] {String.class, int.class};
                    Class<?> wrongOwner = Box.class;
                    String wrongName = "mix";
                    Class<?>[] wrongParams = new Class<?>[] {int.class, long.class, double.class, Object[].class};
                    if (wrongOwner == null || wrongName.length() == -1 || wrongParams.length == -1) {
                        total += 1000;
                    }
                    Method method = actualOwner.getDeclaredMethod(actualName, actualParams);
                    method.setAccessible(true);
                    total += ((Integer) method.invoke(null, new Object[] {"qr", 12})).intValue();
                    total += reflectSameLocalAfterThrow();
                    total += methodInvokeEscaped(method, null, new Object[] {"wx", 16});
                    ReflectInvoker invoker = new ReflectInvokerImpl();
                    total += invoker.invoke(method, null, new Object[] {"ij", 18});
                    total += stackTraceReflectPath();
                    total += classNewInstancePath();

                    Method[] actualMethods = ParameterShapes.class.getDeclaredMethods();
                    Method[] wrongMethods = Box.class.getDeclaredMethods();
                    if (wrongMethods.length == -1) {
                        total += wrongMethods.length;
                    }
                    for (Method candidate : actualMethods) {
                        if (candidate.getName().equals("reflectTarget")) {
                            candidate.setAccessible(true);
                            if (method.getName().equals("notReflectTarget")) {
                                total += 1000;
                            }
                            int reflected = ((Integer) candidate.invoke(null, new Object[] {"uv", 15})).intValue();
                            total += reflected;
                            break;
                        }
                    }
                    return total;
                }

                static int stackTraceReflectPath() throws Throwable {
                    TraceLike.count = 0;
                    new TraceLike().entry(4);
                    return TraceLike.count;
                }

                static int classNewInstancePath() throws Throwable {
                    Class<?> type = Class.forName("ParameterShapes$NewInstanceTarget");
                    Object instance = type.newInstance();
                    Method method = type.getDeclaredMethod("value");
                    method.setAccessible(true);
                    return ((Integer) method.invoke(instance, new Object[0])).intValue();
                }

                static int reflectSameLocalAfterThrow() throws Throwable {
                    Class<?>[] params = new Class<?>[] {String.class, int.class};
                    if (never()) {
                        params = new Class<?>[] {int.class};
                        throw new AssertionError("stale-params:" + params.length);
                    }
                    Method method = ParameterShapes.class.getDeclaredMethod("reflectTarget", params);
                    method.setAccessible(true);
                    return ((Integer) method.invoke(null, new Object[] {"sl", 19})).intValue();
                }

                static boolean never() {
                    return Boolean.getBoolean("neko.never") && System.nanoTime() == Long.MIN_VALUE;
                }

                static int methodInvokeEscaped(Method method, Object target, Object[] args) throws Throwable {
                    method.setAccessible(true);
                    return ((Integer) method.invoke(target, args)).intValue();
                }

                static int reflectConstructor() throws Throwable {
                    int total = 0;
                    Class<Box> ctorOwner = Box.class;
                    Class<?>[] ctorParams = new Class<?>[] {int.class, String.class};
                    Class<?> wrongCtorOwner = UnusedConstructor.class;
                    Class<?>[] wrongCtorParams = new Class<?>[] {};
                    if (wrongCtorOwner == null || wrongCtorParams.length == -1) {
                        total += 1000;
                    }
                    Constructor<Box> ctor = ctorOwner.getDeclaredConstructor(ctorParams);
                    ctor.setAccessible(true);
                    Box reflected = ctor.newInstance(new Object[] {13, "rs"});
                    total += reflected.mix(1, 2L, 3.0d, new Object[] {"a", "b"});

                    Object stored = Box.class.getDeclaredConstructor(int.class, String.class);
                    ((Constructor<?>) stored).setAccessible(true);
                    Box escapedBox = (Box) ((Constructor<?>) stored).newInstance(new Object[] {14, "tu"});
                    total += escapedBox.mix(1, 2L, 3.0d, new Object[] {"a", "b"});

                    Box arrayBox = boxFromConstructorArray();
                    total += arrayBox.mix(1, 2L, 3.0d, new Object[] {"a", "b"});

                    Box helperBox = constructEscaped(
                        Box.class.getDeclaredConstructor(int.class, String.class),
                        16,
                        "yz"
                    );
                    total += helperBox.mix(1, 2L, 3.0d, new Object[] {"a", "b"});
                    return total;
                }

                static Box constructEscaped(Constructor<?> constructor, int base, String tag) throws Throwable {
                    constructor.setAccessible(true);
                    return (Box) constructor.newInstance(new Object[] {base, tag});
                }

                static Box boxFromConstructorArray() throws Throwable {
                    Constructor<?>[] actualConstructors = Box.class.getDeclaredConstructors();
                    Constructor<?>[] wrongConstructors = UnusedConstructor.class.getDeclaredConstructors();
                    if (wrongConstructors.length == -1) {
                        throw new AssertionError(wrongConstructors.length);
                    }
                    for (Constructor<?> candidate : actualConstructors) {
                        Class<?>[] params = candidate.getParameterTypes();
                        if (params.length == 2 && params[0] == int.class && params[1] == String.class) {
                            candidate.setAccessible(true);
                            return (Box) candidate.newInstance(new Object[] {15, "vw"});
                        }
                        if (params.length == 3
                            && params[0].isArray()
                            && params[1] == long.class
                            && params[2] == long.class) {
                            candidate.setAccessible(true);
                            return (Box) candidate.newInstance(new Object[] {15, "vw"});
                        }
                    }
                    throw new AssertionError("constructor-array");
                }

                static int methodHandlePaths(Box box) throws Throwable {
                    int total = 0;
                    Class<?> staticOwner = ParameterShapes.class;
                    String staticName = "methodHandleTarget";
                    MethodType staticType = MethodType.methodType(int.class, String.class, int.class);
                    if (never()) {
                        Class<?> staleOwner = Box.class;
                        String staleName = "mix";
                        MethodType staleType = MethodType.methodType(
                            int.class,
                            int.class,
                            long.class,
                            double.class,
                            Object[].class
                        );
                        total += staleName.length() + staleType.parameterCount() + (staleOwner == null ? 1 : 0);
                    }
                    MethodHandle handle = MethodHandles.lookup().findStatic(
                        staticOwner,
                        staticName,
                        staticType
                    );
                    total += (int) handle.invokeExact("mh", 14);

                    MethodHandle virtualHandle = MethodHandles.lookup().findVirtual(
                        Box.class,
                        "mix",
                        MethodType.methodType(int.class, int.class, long.class, double.class, Object[].class)
                    );
                    total += (int) virtualHandle.invokeExact(box, 2, 3L, 4.0d, new Object[] {"v"});

                    MethodHandle specialHandle = MethodHandles.privateLookupIn(
                        SpecialBox.class,
                        MethodHandles.lookup()
                    ).findSpecial(
                        Box.class,
                        "mix",
                        MethodType.methodType(int.class, int.class, long.class, double.class, Object[].class),
                        SpecialBox.class
                    );
                    total += new SpecialBox(4, "sp").callSuper(specialHandle);

                    Class<?> ctorOwner = Box.class;
                    MethodType ctorType = MethodType.methodType(void.class, int.class, String.class);
                    if (never()) {
                        Class<?> staleCtorOwner = UnusedConstructor.class;
                        MethodType staleCtorType = MethodType.methodType(void.class);
                        total += staleCtorType.parameterCount() + (staleCtorOwner == null ? 1 : 0);
                    }
                    MethodHandle constructorHandle = MethodHandles.lookup().findConstructor(ctorOwner, ctorType);
                    Box constructed = (Box) constructorHandle.invokeExact(6, "hc");
                    total += constructed.mix(1, 1L, 1.0d, new Object[] {});

                    return total;
                }

                static int add(int left, int right) {
                    return left + right;
                }

                int noArg() {
                    return 6;
                }

                int overload(int value) {
                    return value + 1;
                }

                int overload(String value) {
                    return value.length() + 2;
                }

                int overload(int left, int right) {
                    return left * right;
                }

                static int reflectTarget(String text, int value) {
                    return text.length() + value;
                }

                static int methodHandleTarget(String text, int value) {
                    return text.length() + value;
                }

                static int callWorkerHandle(MethodHandle handle, Worker worker) throws Throwable {
                    return (int) handle.invokeExact(worker, 16, "iface");
                }

                static int interfacePaths(Worker worker) throws Throwable {
                    MethodHandle interfaceHandle = MethodHandles.lookup().findVirtual(
                        Worker.class,
                        "work",
                        MethodType.methodType(int.class, int.class, String.class)
                    );
                    Method interfaceMethod = Worker.class.getMethod("work", int.class, String.class);
                    return callWorkerHandle(interfaceHandle, worker)
                        + ((Integer) interfaceMethod.invoke(worker, new Object[] {17, "r"})).intValue()
                        + defaultInterfaceCarrierPath();
                }

                static int defaultInterfaceCarrierPath() {
                    CaseLike test = new DefaultCase();
                    Options options = new Options();
                    if (!options.accepts(test.id(), test.tags())) {
                        throw new AssertionError("default-interface-tags");
                    }
                    return 23;
                }

                static String join(String prefix, int value, boolean flag) {
                    return prefix + ":" + value + ":" + flag;
                }
            }
            """;
    }

    private String interfaceDefaultCarrierSourceText() {
        return """
            import java.util.List;
            import java.util.Locale;
            import java.util.Set;

            public class PackedDefaultEntry {
                interface CaseLike {
                    String id();

                    default Set<String> tags() {
                        return Set.of("default");
                    }
                }

                static final class DefaultCase implements CaseLike {
                    public String id() {
                        return "alpha-default";
                    }
                }

                static final class OverrideCase implements CaseLike {
                    public String id() {
                        return "alpha-override";
                    }

                    public Set<String> tags() {
                        return Set.of("feature", "jvm");
                    }
                }

                static final class SecondOverrideCase implements CaseLike {
                    public String id() {
                        return "alpha-second";
                    }

                    public Set<String> tags() {
                        return Set.of("runner", "case");
                    }
                }

                static final class FourTagOverrideCase implements CaseLike {
                    public String id() {
                        return "alpha-four";
                    }

                    public Set<String> tags() {
                        return Set.of("feature", "jvm", "class-literal", "array");
                    }
                }

                static final class Options {
                    boolean accepts(String value, Iterable<String> patterns) {
                        String lower = value.toLowerCase(Locale.ROOT);
                        int length = 0;
                        for (String pattern : patterns) {
                            length += pattern.toLowerCase(Locale.ROOT).length();
                        }
                        return lower.startsWith("alpha") && length >= 10;
                    }
                }

                public static void main(String[] args) {
                    String out = run();
                    System.out.println(out);
                    if (!out.equals("DEFAULT ENTRY OK")) {
                        throw new AssertionError(out);
                    }
                }

                static String run() {
                    Options options = new Options();
                    int accepted = 0;
                    for (CaseLike test : List.of(select(), new SecondOverrideCase(), new FourTagOverrideCase())) {
                        if (options.accepts(test.id(), test.tags())) {
                            accepted++;
                        }
                    }
                    return accepted == 3 ? "DEFAULT ENTRY OK" : "DEFAULT ENTRY FAIL";
                }

                static CaseLike select() {
                    return Boolean.getBoolean("neko.default.case")
                        ? new DefaultCase()
                        : new OverrideCase();
                }
            }
            """;
    }

    private String topLevelInterfaceCarrierSourceText() {
        StringBuilder listAdds = new StringBuilder();
        StringBuilder caseClasses = new StringBuilder();
        for (int index = 0; index < 24; index++) {
            if (index == 20) {
                listAdds.append("                    tests.add(new PackedTopLevelClassLiteralCase());\n");
            }
            listAdds.append("                    tests.add(new PackedTopLevelCase%02d());\n".formatted(index));
            caseClasses.append(
                """
                final class PackedTopLevelCase%1$02d implements PackedTopLevelCaseLike {
                    public String id() {
                        return "alpha-case-%1$02d";
                    }

                    public Set<String> tags() {
                        return Set.of("feature", "case", "slot%1$02d");
                    }
                }

                """.formatted(index)
            );
        }
        return """
            import java.util.ArrayList;
            import java.util.List;
            import java.util.Locale;
            import java.util.Set;

            public class PackedTopLevelEntry {
                public static void main(String[] args) {
                    String out = run();
                    System.out.println(out);
                    if (!out.equals("TOP LEVEL ENTRY OK")) {
                        throw new AssertionError(out);
                    }
                }

                static String run() {
                    PackedTopLevelOptions options = new PackedTopLevelOptions();
                    List<PackedTopLevelCaseLike> tests = new ArrayList<>();
%s
                    tests.add(new PackedTopLevelSecondCase());
                    int accepted = 0;
                    for (PackedTopLevelCaseLike test : tests) {
                        String marker = System.getProperty("packed.marker", "marker");
                        if (marker.toLowerCase(Locale.ROOT).contains("mark") && options.accepts(test.id(), test.tags())) {
                            accepted++;
                        }
                    }
                    return accepted == 26 ? "TOP LEVEL ENTRY OK" : "TOP LEVEL ENTRY FAIL";
                }
            }

%s
            final class PackedTopLevelClassLiteralCase implements PackedTopLevelCaseLike {
                public String id() {
                    return "alpha-classliteral-arrays";
                }

                public Set<String> tags() {
                    return Set.of("feature", "jvm", "class-literal", "array");
                }

                Class<?>[] literals() {
                    return new Class<?>[] {
                        int[][].class,
                        String[][].class,
                        java.lang.invoke.MethodHandle.class,
                        PackedTopLevelCaseLike.class
                    };
                }
            }

            final class PackedTopLevelSecondCase implements PackedTopLevelCaseLike {
                public String id() {
                    return "alpha-second";
                }

                public Set<String> tags() {
                    return Set.of("runner", "case", "interface");
                }
            }

            interface PackedTopLevelCaseLike {
                String id();

                default Set<String> tags() {
                    return Set.of("default");
                }
            }

            final class PackedTopLevelOptions {
                boolean accepts(String value, Iterable<String> patterns) {
                    String lower = value.toLowerCase(Locale.ROOT);
                    int length = 0;
                    for (String pattern : patterns) {
                        length += pattern.toLowerCase(Locale.ROOT).length();
                    }
                    return lower.startsWith("alpha") && length >= 13;
                }
            }
            """.formatted(listAdds, caseClasses);
    }

    private String recordAbiSourceText() {
        return """
            import java.io.ByteArrayInputStream;
            import java.io.ByteArrayOutputStream;
            import java.io.ObjectInputStream;
            import java.io.ObjectOutputStream;
            import java.io.Serializable;
            import java.lang.reflect.Constructor;
            import java.lang.reflect.Method;
            import java.lang.reflect.RecordComponent;

            public class RecordAbiEntry {
                public static void main(String[] args) throws Exception {
                    Person person = new Person("ada", 36);
                    if (!Person.class.isRecord()) {
                        throw new AssertionError("not-record");
                    }
                    RecordComponent[] components = Person.class.getRecordComponents();
                    if (components.length != 2) {
                        throw new AssertionError("components:" + components.length);
                    }
                    if (!"name".equals(components[0].getName()) || !"age".equals(components[1].getName())) {
                        throw new AssertionError("component-names:" + components[0].getName() + ":" + components[1].getName());
                    }
                    if (!"name".equals(components[0].getAccessor().getName()) ||
                        !"age".equals(components[1].getAccessor().getName())) {
                        throw new AssertionError("accessor-names");
                    }
                    if (components[0].getAccessor().getParameterCount() != 0 ||
                        components[1].getAccessor().getParameterCount() != 0) {
                        throw new AssertionError("accessor-parameters");
                    }
                    if (!"ada".equals(person.name()) || person.age() != 36) {
                        throw new AssertionError("accessor-values");
                    }
                    if (!"ada".equals(components[0].getAccessor().invoke(person, new Object[0])) ||
                        ((Integer) components[1].getAccessor().invoke(person, new Object[0])).intValue() != 36) {
                        throw new AssertionError("reflective-accessor-values");
                    }
                    Method declaredName = Person.class.getDeclaredMethod("name");
                    Method publicAge = Person.class.getMethod("age");
                    if (declaredName.getParameterCount() != 0 || publicAge.getParameterCount() != 0) {
                        throw new AssertionError("direct-reflective-accessor-parameters");
                    }
                    if (!"ada".equals(declaredName.invoke(person, new Object[0])) ||
                        ((Integer) publicAge.invoke(person, new Object[0])).intValue() != 36) {
                        throw new AssertionError("direct-reflective-accessor-values");
                    }
                    Method merged = args.length == 0
                        ? declaredName
                        : Helper.class.getDeclaredMethod("touch");
                    if (!"ada".equals(merged.invoke(person, new Object[0]))) {
                        throw new AssertionError("merged-reflective-accessor-values");
                    }
                    Constructor<Person> constructor = Person.class.getDeclaredConstructor(String.class, int.class);
                    Person constructed = constructor.newInstance("ada", 36);
                    if (!person.equals(constructed)) {
                        throw new AssertionError("canonical-constructor");
                    }
                    Object restored = read(write(person));
                    if (!person.equals(restored)) {
                        throw new AssertionError("record-serialization");
                    }
                    if (!"ada:36".equals(person.label())) {
                        throw new AssertionError("record-method");
                    }
                    System.out.println("RECORD ABI OK");
                }

                public record Person(String name, int age) implements Serializable {
                    public String label() {
                        return name + ":" + age;
                    }
                }

                static final class Helper {
                    private static int touched;

                    private static void touch() {
                        touched++;
                    }
                }

                static byte[] write(Object value) throws Exception {
                    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
                        out.writeObject(value);
                    }
                    return bytes.toByteArray();
                }

                static Object read(byte[] bytes) throws Exception {
                    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
                        return in.readObject();
                    }
                }
            }
            """;
    }

    private String externalReflectionAbiSourceText() {
        return """
            import java.lang.reflect.Method;
            import java.lang.invoke.MethodHandle;
            import java.lang.invoke.MethodHandles;
            import java.lang.invoke.MethodType;
            import java.util.concurrent.Callable;

            public class ExternalReflectionAbiEntry {
                public static void main(String[] args) throws Throwable {
                    Class<?> integerType = Class.forName("java.lang.Integer");
                    Class<?> threadType = Class.forName("java.lang.Thread");
                    Class<?> stringType = Class.forName("java.lang.String");
                    Class<?> callableType = Class.forName("java.util.concurrent.Callable");

                    Method parse = integerType.getMethod("parseInt", String.class);
                    int parsed = ((Integer) parse.invoke(null, "41")).intValue();

                    Method threadName = threadType.getMethod("getName");
                    String currentName = (String) threadName.invoke(Thread.currentThread(), new Object[0]);
                    if (currentName == null || currentName.isEmpty()) {
                        throw new AssertionError("thread-name");
                    }

                    Method charAt = stringType.getDeclaredMethod("charAt", int.class);
                    int code = ((Character) charAt.invoke("abc", 1)).charValue();

                    Method substring = runtimeExternalMethod(
                        "abcdef",
                        "substring",
                        new Class<?>[] {int.class, int.class}
                    );
                    if (!"bcd".equals(substring.invoke("abcdef", 1, 4))) {
                        throw new AssertionError("runtime-external-substring");
                    }

                    Method callableCall = callableType.getMethod("call");
                    Callable<String> callable = () -> "external-call";
                    if (!"external-call".equals(callableCall.invoke(callable))) {
                        throw new AssertionError("callable-call");
                    }

                    MethodHandles.Lookup lookup = MethodHandles.lookup();
                    MethodHandle parseHandle = lookup.findStatic(
                        integerType,
                        "parseInt",
                        MethodType.methodType(int.class, String.class)
                    );
                    if (((Integer) parseHandle.invoke("1")).intValue() != 1) {
                        throw new AssertionError("methodhandle-parse");
                    }
                    MethodHandle callableHandle = lookup.findVirtual(
                        callableType,
                        "call",
                        MethodType.methodType(Object.class)
                    );
                    if (!"external-call".equals(callableHandle.invoke(callable))) {
                        throw new AssertionError("methodhandle-call");
                    }

                    int total = parsed + code;
                    if (total != 139) {
                        throw new AssertionError("total:" + total);
                    }
                    if (!"local-call".equals(call())) {
                        throw new AssertionError("local-call");
                    }
                    System.out.println("EXTERNAL REFLECTION ABI OK");
                }

                static String call() {
                    return "local-call";
                }

                static Method runtimeExternalMethod(Object target, String name, Class<?>[] parameterTypes)
                    throws Exception {
                    return target.getClass().getMethod(name, parameterTypes);
                }
            }
            """;
    }

    private String lambdaReflectiveMethodSourceText() {
        return """
            import java.lang.reflect.Method;

            public class LambdaReflectiveMethodEntry {
                interface LongOperation {
                    long run() throws Exception;
                }

                public static void main(String[] args) throws Exception {
                    Target target = new Target();
                    Method method = Target.class.getMethod("add", int.class, int.class);
                    LongOperation operation = capture(8, method, target);
                    long result = operation.run();
                    if (result != 196L) {
                        throw new AssertionError("lambda-reflective-result:" + result);
                    }

                    Method external = String.class.getMethod("substring", int.class, int.class);
                    LongOperation externalOperation = () -> ((String) external.invoke("abcdef", 1, 4)).length();
                    long externalResult = externalOperation.run();
                    if (externalResult != 3L) {
                        throw new AssertionError("lambda-external-result:" + externalResult);
                    }

                    System.out.println("LAMBDA REFLECTIVE METHOD OK");
                }

                static LongOperation capture(int size, Method method, Target target) {
                    return () -> {
                        long checksum = 0L;
                        for (int i = 0; i < size; i++) {
                            checksum += ((Integer) method.invoke(target, new Object[] {i, 21})).intValue();
                        }
                        return checksum;
                    };
                }

                public static final class Target {
                    public int add(int left, int right) {
                        return left + right;
                    }
                }
            }
            """;
    }

    private String childLoaderReflectiveCarrierSourceText() {
        return """
            import java.io.InputStream;
            import java.lang.reflect.Constructor;
            import java.lang.reflect.Method;
            import java.util.HashMap;
            import java.util.Map;

            public class ChildLoaderReflectiveEntry {
                private static final String TARGET = "ChildLoaderReflectiveEntry$Target";

                public static void main(String[] args) throws Exception {
                    byte[] bytes = classBytes(TARGET);
                    Map<String, byte[]> definitions = Map.of(TARGET, bytes);
                    ChildFirstLoader first = new ChildFirstLoader(
                        ChildLoaderReflectiveEntry.class.getClassLoader(),
                        definitions
                    );
                    ChildFirstLoader second = new ChildFirstLoader(
                        ChildLoaderReflectiveEntry.class.getClassLoader(),
                        definitions
                    );

                    Class<?> firstClass = first.loadClass(TARGET);
                    Class<?> secondClass = second.loadClass(TARGET);
                    if (firstClass == Target.class || secondClass == Target.class || firstClass == secondClass) {
                        throw new AssertionError("loader isolation broken");
                    }

                    Constructor<?> firstConstructor = firstClass.getConstructor();
                    Constructor<?> secondConstructor = secondClass.getConstructor();
                    Object firstA = firstConstructor.newInstance(new Object[0]);
                    Object firstB = firstConstructor.newInstance(new Object[0]);
                    Object secondA = secondConstructor.newInstance(new Object[0]);
                    Method firstBump = firstClass.getMethod("bump");
                    Method secondBump = secondClass.getMethod("bump");

                    int firstValue = ((Integer) firstBump.invoke(firstA, new Object[0])).intValue();
                    int firstShared = ((Integer) firstBump.invoke(firstB, new Object[0])).intValue();
                    int secondValue = ((Integer) secondBump.invoke(secondA, new Object[0])).intValue();
                    if (firstValue != 8 || firstShared != 9 || secondValue != 8) {
                        throw new AssertionError(firstValue + ":" + firstShared + ":" + secondValue);
                    }
                    System.out.println("CHILD LOADER REFLECTIVE CARRIER OK");
                }

                private static byte[] classBytes(String binaryName) throws Exception {
                    String resource = binaryName.replace('.', '/') + ".class";
                    try (InputStream in = Thread.currentThread()
                        .getContextClassLoader()
                        .getResourceAsStream(resource)) {
                        if (in == null) {
                            throw new AssertionError(resource);
                        }
                        return in.readAllBytes();
                    }
                }

                public static final class Target {
                    private static int state = 7;

                    public Target() {
                    }

                    public int bump() {
                        state += 1;
                        return state;
                    }
                }

                static final class ChildFirstLoader extends ClassLoader {
                    private final Map<String, byte[]> definitions = new HashMap<>();

                    ChildFirstLoader(ClassLoader parent, Map<String, byte[]> definitions) {
                        super(parent);
                        this.definitions.putAll(definitions);
                    }

                    @Override
                    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                        synchronized (getClassLoadingLock(name)) {
                            Class<?> loaded = findLoadedClass(name);
                            if (loaded == null && definitions.containsKey(name)) {
                                loaded = findClass(name);
                            }
                            if (loaded == null) {
                                loaded = super.loadClass(name, false);
                            }
                            if (resolve) {
                                resolveClass(loaded);
                            }
                            return loaded;
                        }
                    }

                    @Override
                    protected Class<?> findClass(String name) throws ClassNotFoundException {
                        byte[] bytes = definitions.get(name);
                        if (bytes == null) {
                            throw new ClassNotFoundException(name);
                        }
                        return defineClass(name, bytes, 0, bytes.length);
                    }
                }
            }
            """;
    }

    private String interfaceReflectiveCarrierSourceText() {
        return """
            import java.lang.reflect.Method;

            public class InterfaceReflectiveCarrierEntry {
                public static void main(String[] args) throws Exception {
                    ReflectiveRunner runner = new RunnerImpl();
                    String out = runner.runReflective(new Target(5), 7, "v");
                    if (!"v:12".equals(out)) {
                        throw new AssertionError(out);
                    }
                    System.out.println("INTERFACE REFLECTIVE CARRIER OK");
                }

                interface ReflectiveRunner {
                    default String runReflective(Target target, int extra, String prefix) throws Exception {
                        Method method = Target.class.getDeclaredMethod("combine", int.class, String.class);
                        Object value = method.invoke(target, Integer.valueOf(extra), prefix);
                        return String.valueOf(value);
                    }
                }

                static final class RunnerImpl implements ReflectiveRunner {
                }

                public static final class Target {
                    private final int base;

                    public Target(int base) {
                        this.base = base;
                    }

                    public String combine(int extra, String prefix) {
                        return prefix + ":" + (base + extra);
                    }
                }
            }
            """;
    }

    private String annotationEnumDefaultSourceText() {
        return """
            import java.lang.annotation.Retention;
            import java.lang.annotation.RetentionPolicy;
            import java.lang.reflect.Method;

            public class AnnotationEnumDefaultEntry {
                enum Mode {
                    FIRST,
                    SECOND,
                    THIRD
                }

                @Retention(RetentionPolicy.RUNTIME)
                @interface Marker {
                    Mode mode() default Mode.SECOND;

                    Mode[] modes() default {Mode.FIRST, Mode.THIRD};

                    Nested nested() default @Nested(Mode.THIRD);
                }

                @Retention(RetentionPolicy.RUNTIME)
                @interface Nested {
                    Mode value() default Mode.FIRST;
                }

                @Marker(mode = Mode.THIRD, modes = {Mode.SECOND})
                static final class Annotated {
                }

                public static void main(String[] args) throws Exception {
                    Marker marker = Annotated.class.getAnnotation(Marker.class);
                    if (marker.mode() != Mode.THIRD) {
                        throw new AssertionError("explicit-mode:" + marker.mode());
                    }
                    if (marker.modes().length != 1 || marker.modes()[0] != Mode.SECOND) {
                        throw new AssertionError("explicit-array");
                    }
                    Method mode = Marker.class.getDeclaredMethod("mode");
                    if (mode.getDefaultValue() != Mode.SECOND) {
                        throw new AssertionError("default-mode:" + mode.getDefaultValue());
                    }
                    Method modes = Marker.class.getDeclaredMethod("modes");
                    Mode[] defaultModes = (Mode[]) modes.getDefaultValue();
                    if (defaultModes.length != 2 || defaultModes[0] != Mode.FIRST || defaultModes[1] != Mode.THIRD) {
                        throw new AssertionError("default-array");
                    }
                    Method nested = Marker.class.getDeclaredMethod("nested");
                    Nested nestedDefault = (Nested) nested.getDefaultValue();
                    if (nestedDefault.value() != Mode.THIRD) {
                        throw new AssertionError("nested-default:" + nestedDefault.value());
                    }
                    System.out.println("ANNOTATION ENUM DEFAULT OK");
                }
            }
            """;
    }

    private String bridgeAbiSourceText() {
        return """
            import java.lang.reflect.Method;
            import java.util.Arrays;

            public class BridgeAbiEntry {
                static class Parent {
                    Number value() {
                        return 1;
                    }
                }

                static final class Child extends Parent {
                    Integer value() {
                        return 42;
                    }
                }

                interface Getter<T> {
                    T get();
                }

                static final class StringGetter implements Getter<String> {
                    public String get() {
                        return "bridge";
                    }
                }

                public static void main(String[] args) {
                    Parent parent = new Child();
                    if (parent.value().intValue() != 42) {
                        throw new AssertionError("covariant-dispatch");
                    }
                    Getter<String> getter = new StringGetter();
                    if (!"bridge".equals(getter.get())) {
                        throw new AssertionError("generic-dispatch");
                    }
                    if (!hasBridge(Child.class, "value")) {
                        throw new AssertionError("covariant-bridge");
                    }
                    if (!hasBridge(StringGetter.class, "get")) {
                        throw new AssertionError("generic-bridge");
                    }
                    System.out.println("BRIDGE ABI OK");
                }

                static boolean hasBridge(Class<?> type, String name) {
                    return Arrays.stream(type.getDeclaredMethods())
                        .filter(method -> method.getName().equals(name))
                        .anyMatch(Method::isBridge);
                }
            }
            """;
    }

    private String serviceLoaderAbiSourceText() {
        return """
            import java.lang.reflect.Constructor;
            import java.util.ServiceLoader;

            public class ServiceLoaderAbiEntry {
                public interface Greeting {
                    String greet(String name);
                }

                public static final class Provider implements Greeting {
                    public Provider() {
                    }

                    public String greet(String name) {
                        return "svc:" + name;
                    }
                }

                public static void main(String[] args) throws Exception {
                    Greeting greeting = ServiceLoader.load(Greeting.class)
                        .findFirst()
                        .orElseThrow(() -> new AssertionError("provider missing"));
                    if (!"svc:jar".equals(greeting.greet("jar"))) {
                        throw new AssertionError("provider invocation");
                    }
                    Constructor<?> constructor = greeting.getClass().getConstructor();
                    if (constructor.getParameterCount() != 0) {
                        throw new AssertionError("provider constructor arity");
                    }
                    System.out.println("SERVICE ABI OK");
                }
            }
            """;
    }

    private String methodParametersAbiSourceText() {
        return """
            import java.lang.reflect.Constructor;
            import java.lang.reflect.Method;
            import java.lang.reflect.Parameter;

            public class MethodParametersAbiEntry {
                static final class Target {
                    private final String seed;

                    Target(String seedName) {
                        this.seed = seedName;
                    }

                    public String combine(String leftPart, int rightCount) {
                        return seed + ":" + leftPart + ":" + rightCount;
                    }
                }

                public static void main(String[] args) throws Exception {
                    Method method = Target.class.getDeclaredMethod("combine", String.class, int.class);
                    Parameter[] methodParameters = method.getParameters();
                    if (methodParameters.length != 2
                        || !methodParameters[0].isNamePresent()
                        || !methodParameters[1].isNamePresent()
                        || !"leftPart".equals(methodParameters[0].getName())
                        || !"rightCount".equals(methodParameters[1].getName())) {
                        throw new AssertionError("method-parameters");
                    }

                    Constructor<Target> constructor = Target.class.getDeclaredConstructor(String.class);
                    Parameter[] constructorParameters = constructor.getParameters();
                    if (constructorParameters.length != 1
                        || !constructorParameters[0].isNamePresent()
                        || !"seedName".equals(constructorParameters[0].getName())) {
                        throw new AssertionError("constructor-parameters");
                    }

                    Target target = constructor.newInstance("seed");
                    String value = (String) method.invoke(target, "value", 7);
                    if (!"seed:value:7".equals(value)) {
                        throw new AssertionError(value);
                    }
                    System.out.println("METHOD PARAMETERS ABI OK");
                }
            }
            """;
    }

    private String serializationAbiSourceText() {
        return """
            import java.io.ByteArrayInputStream;
            import java.io.ByteArrayOutputStream;
            import java.io.InvalidObjectException;
            import java.io.IOException;
            import java.io.ObjectInputStream;
            import java.io.ObjectOutputStream;
            import java.io.ObjectStreamClass;
            import java.io.ObjectStreamException;
            import java.io.Serializable;
            import java.util.Arrays;

            public class SerializationAbiEntry {
                static final class CustomData implements Serializable {
                    private static final long serialVersionUID = 221L;
                    private final String kept;
                    private transient String transientValue;

                    CustomData(String kept, String transientValue) {
                        this.kept = kept;
                        this.transientValue = transientValue;
                    }

                    String value() {
                        return kept + ":" + transientValue;
                    }

                    private void writeObject(ObjectOutputStream out) throws IOException {
                        out.defaultWriteObject();
                        out.writeUTF(transientValue);
                    }

                    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
                        in.defaultReadObject();
                        transientValue = in.readUTF();
                    }
                }

                static final class CanonicalSingleton implements Serializable {
                    static final CanonicalSingleton INSTANCE = new CanonicalSingleton();
                    private static final long serialVersionUID = 222L;

                    private Object readResolve() throws ObjectStreamException {
                        return INSTANCE;
                    }
                }

                static final class ProxyData implements Serializable {
                    private static final long serialVersionUID = 223L;
                    private final String value;

                    ProxyData(String value) {
                        this.value = value;
                    }

                    String value() {
                        return value;
                    }

                    private Object writeReplace() {
                        return new Proxy(value);
                    }

                    private void readObject(ObjectInputStream ignored) throws IOException {
                        throw new InvalidObjectException("proxy required");
                    }
                }

                static final class Proxy implements Serializable {
                    private static final long serialVersionUID = 224L;
                    private final String value;

                    Proxy(String value) {
                        this.value = value;
                    }

                    private Object readResolve() {
                        return new ProxyData(value);
                    }
                }

                static final class DefaultFields implements Serializable {
                    private static final long serialVersionUID = 225L;
                    public String publicValue = "public-field";
                    private int privateNumber = 21;
                    private transient int ignored = 7;
                }

                public static void main(String[] args) throws Exception {
                    ObjectStreamClass streamClass = ObjectStreamClass.lookup(DefaultFields.class);
                    if (streamClass.getSerialVersionUID() != 225L) {
                        throw new AssertionError("serialVersionUID=" + streamClass.getSerialVersionUID());
                    }
                    if (!Arrays.stream(streamClass.getFields()).anyMatch(field -> "publicValue".equals(field.getName()))) {
                        throw new AssertionError("publicValue");
                    }
                    if (!Arrays.stream(streamClass.getFields()).anyMatch(field -> "privateNumber".equals(field.getName()))) {
                        throw new AssertionError("privateNumber");
                    }
                    if (Arrays.stream(streamClass.getFields()).anyMatch(field -> "ignored".equals(field.getName()))) {
                        throw new AssertionError("ignored");
                    }

                    CustomData custom = (CustomData) roundTrip(new CustomData("head", "tail"));
                    if (!"head:tail".equals(custom.value())) {
                        throw new AssertionError(custom.value());
                    }

                    if (roundTrip(CanonicalSingleton.INSTANCE) != CanonicalSingleton.INSTANCE) {
                        throw new AssertionError("readResolve");
                    }

                    ProxyData proxy = (ProxyData) roundTrip(new ProxyData("secret"));
                    if (!"secret".equals(proxy.value())) {
                        throw new AssertionError(proxy.value());
                    }

                    System.out.println("SERIALIZATION ABI OK");
                }

                private static Object roundTrip(Serializable value) throws Exception {
                    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
                        out.writeObject(value);
                    }
                    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
                        return in.readObject();
                    }
                }
            }
            """;
    }

    private String varargsMetadataAbiSourceText() {
        return """
            import java.lang.invoke.MethodHandle;
            import java.lang.invoke.MethodHandles;
            import java.lang.invoke.MethodType;
            import java.lang.reflect.Method;

            public class VarargsMetadataAbiEntry {
                static final class Target {
                    static Object join(String prefix, Object... values) {
                        return prefix + ":" + values.length + ":" + values[0];
                    }
                }

                public static void main(String[] args) throws Throwable {
                    MethodHandle handle = MethodHandles.lookup().findStatic(
                        Target.class,
                        "join",
                        MethodType.methodType(Object.class, String.class, Object[].class)
                    );
                    Object handleValue = handle.invokeExact("mh", new Object[] {"x", Integer.valueOf(7)});
                    if (!"mh:2:x".equals(handleValue)) {
                        throw new AssertionError(handleValue);
                    }

                    Method reflected = Target.class.getDeclaredMethod("join", String.class, Object[].class);
                    Object reflectedValue = reflected.invoke(null, "rf", new Object[] {"y", Integer.valueOf(9)});
                    if (!"rf:2:y".equals(reflectedValue)) {
                        throw new AssertionError(reflectedValue);
                    }

                    System.out.println("VARARGS METADATA ABI OK");
                }
            }
            """;
    }

    private String crossClassStringTailSourceText() {
        return """
            import java.util.ArrayList;
            import java.util.List;
            import java.util.Locale;
            import java.util.Set;

            public class PackedStringTailEntry {
                public static void main(String[] args) {
                    String out = run();
                    System.out.println(out);
                    if (!out.equals("STRING TAIL ENTRY OK")) {
                        throw new AssertionError(out);
                    }
                }

                static String run() {
                    List<PackedStringTailCaseLike> tests = new ArrayList<>();
                    tests.add(new PackedStringTailHostCase());
                    tests.add(new PackedStringTailOtherCase());
                    int total = 0;
                    for (PackedStringTailCaseLike test : tests) {
                        String marker = System.getProperty("packed.string.tail.marker", "marker");
                        if (marker.toLowerCase(Locale.ROOT).contains("mark")) {
                            total += test.id().length();
                            total += test.tags().size();
                        }
                    }
                    return total == 21 ? "STRING TAIL ENTRY OK" : "STRING TAIL ENTRY FAIL";
                }
            }

            final class PackedStringTailHostCase implements PackedStringTailCaseLike {
                public String id() {
                    return "alpha-tail";
                }

                public Set<String> tags() {
                    return Set.of("tail");
                }
            }

            final class PackedStringTailOtherCase implements PackedStringTailCaseLike {
                public String id() {
                    return "beta-case";
                }

                public Set<String> tags() {
                    return Set.of("other");
                }
            }

            interface PackedStringTailCaseLike {
                String id();
                Set<String> tags();
            }
            """;
    }

    private String constructorStringTailSourceText() {
        return """
            public class ConstructorStringTailEntry {
                public static void main(String[] args) {
                    ConstructorStringTailChild second = new ConstructorStringTailChild();
                    String out = second.constructorName() + ":" + second.methodName() + ":" + ConstructorStringTailChild.staticName();
                    System.out.println(out);
                    if (!out.equals("child-field:child-method:child-static")) {
                        throw new AssertionError(out);
                    }
                    System.out.println("CONSTRUCTOR STRING TAIL OK");
                }
            }

            class ConstructorStringTailBase {
                ConstructorStringTailBase() {
                    String value = "base-field";
                    if (!value.equals("base-field")) {
                        throw new AssertionError(value);
                    }
                }

                String baseName() {
                    return "base-field";
                }

                String methodName() {
                    return "base-method";
                }

                static String staticName() {
                    return "base-static";
                }
            }

            final class ConstructorStringTailChild extends ConstructorStringTailBase {
                ConstructorStringTailChild() {
                    super();
                    String value = "child-field";
                    if (!value.equals("child-field")) {
                        throw new AssertionError(value);
                    }
                }

                String constructorName() {
                    return "child-field";
                }

                String methodName() {
                    return "child-method";
                }

                static String staticName() {
                    return "child-static";
                }
            }
            """;
    }

    private String concurrentStringTailSourceText() {
        return """
            import java.util.concurrent.atomic.AtomicReference;

            public class ConcurrentStringTailEntry {
                private static final int THREADS = 8;
                private static final int ITERATIONS = 1500;

                public static void main(String[] args) throws Exception {
                    AtomicReference<Throwable> error = new AtomicReference<>();
                    Thread[] threads = new Thread[THREADS];
                    for (int t = 0; t < THREADS; t++) {
                        final int id = t;
                        threads[t] = new Thread(() -> {
                            try {
                                long sum = 0;
                                for (int i = 0; i < ITERATIONS; i++) {
                                    String first = firstValue(i, id);
                                    String second = secondValue(id, i);
                                    if (!first.equals("shared-alpha")) {
                                        throw new AssertionError(first);
                                    }
                                    if (!second.equals("shared-beta")) {
                                        throw new AssertionError(second);
                                    }
                                    sum += first.length() + second.length();
                                    if ((i & 7) == 0) {
                                        Thread.yield();
                                    }
                                }
                                long expected = (long) ITERATIONS * ("shared-alpha".length() + "shared-beta".length());
                                if (sum != expected) {
                                    throw new AssertionError(Long.toString(sum));
                                }
                            } catch (Throwable ex) {
                                error.compareAndSet(null, ex);
                            }
                        }, "neko-string-tail-" + t);
                        threads[t].start();
                    }
                    for (Thread thread : threads) {
                        thread.join();
                    }
                    Throwable failure = error.get();
                    if (failure != null) {
                        throw new AssertionError("concurrent string tail", failure);
                    }
                    System.out.println("CONCURRENT STRING TAIL OK");
                }

                private static String firstValue(int i, int id) {
                    if ((i ^ id) == -1) {
                        return "never-alpha";
                    }
                    return "shared-alpha";
                }

                private static String secondValue(int id, int i) {
                    if ((id + i) == -1) {
                        return "never-beta";
                    }
                    return "shared-beta";
                }
            }
            """;
    }
}
