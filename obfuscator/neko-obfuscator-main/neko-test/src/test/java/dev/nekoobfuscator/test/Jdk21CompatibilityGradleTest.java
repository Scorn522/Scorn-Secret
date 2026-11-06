package dev.nekoobfuscator.test;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Jdk21CompatibilityGradleTest {
    private static final String MAIN_CLASS = "compat.Jdk21CompatMain";
    private static final String OK_PREFIX = "JDK21_COMPAT_OK checks=";
    private static final List<String> RUN_JVM_ARGS = List.of();

    @Test
    @Timeout(value = 5, unit = TimeUnit.MINUTES)
    void fullJvmJdk21Compatibility() throws Exception {
        Fixture fixture = buildFixture("full-jvm");
        Path output = fixture.workDir().resolve("jdk21-compat-full-jvm.jar");

        NativeObfuscationHelper.ObfuscationRunResult obfuscation = NativeObfuscationHelper.obfuscateJar(
            fixture.inputJar(),
            output,
            NativeObfuscationHelper.jarsDir().resolve("full-jvm-obf.yml"),
            Duration.ofMinutes(3)
        );
        assertFalse(obfuscation.combinedOutput().contains("Native stage:"), () -> obfuscation.combinedOutput());

        RunCheck original = runAndCheck(fixture.workDir(), fixture.inputJar(), "original-full-jvm");
        RunCheck obfuscated = runAndCheck(fixture.workDir(), output, "obfuscated-full-jvm");
        assertEquals(original.successLine(), obfuscated.successLine(), () -> obfuscated.combinedOutput());
        assertNoRuntimeHelpers(output);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.MINUTES)
    void nativeJdk21Compatibility() throws Exception {
        Fixture fixture = buildFixture("native");
        Path config = writeNativeConfig(fixture.workDir());
        Path output = fixture.workDir().resolve("jdk21-compat-native.jar");

        NativeObfuscationHelper.ObfuscationRunResult obfuscation = NativeObfuscationHelper.obfuscateJar(
            fixture.inputJar(),
            output,
            config,
            Duration.ofMinutes(3)
        );
        String obfuscationLog = obfuscation.combinedOutput();
        assertTrue(obfuscationLog.contains("Native stage: translated="), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("translated=0"), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("Native compilation produced no libraries"), () -> obfuscationLog);
        assertFalse(obfuscationLog.contains("skip-on-error"), () -> obfuscationLog);

        RunCheck original = runAndCheck(fixture.workDir(), fixture.inputJar(), "original-native");
        RunCheck nativeRun = runAndCheck(fixture.workDir(), output, "obfuscated-native");
        NativeObfuscationHelper.assertNoFatalNativeCrash(nativeRun.result());
        assertEquals(original.successLine(), nativeRun.successLine(), () -> nativeRun.combinedOutput());
        assertTrue(NativeObfuscationHelper.countNativeMethods(output) > 0, () -> "No native-patched methods found in " + output);
    }

    private static Fixture buildFixture(String variant) throws Exception {
        Path workDir = Files.createDirectories(
            NativeObfuscationHelper.projectRoot()
                .resolve("build")
                .resolve("jdk21-compat-gradle-test")
                .resolve(variant)
        );
        Path sourceDir = recreateDirectory(workDir.resolve("src"));
        Path packageDir = Files.createDirectories(sourceDir.resolve("compat"));
        Path classDir = recreateDirectory(workDir.resolve("classes"));
        Path resourcesDir = recreateDirectory(workDir.resolve("resources"));
        Path resourcePackageDir = Files.createDirectories(resourcesDir.resolve("compat"));

        Files.writeString(packageDir.resolve("Jdk21CompatMain.java"), MAIN_SOURCE, StandardCharsets.UTF_8);
        Files.writeString(resourcePackageDir.resolve("data.txt"), "resource-ok\n", StandardCharsets.UTF_8);

        List<String> command = new ArrayList<>();
        command.add("javac");
        command.add("--release");
        command.add("21");
        command.add("-d");
        command.add(classDir.toString());
        command.add(packageDir.resolve("Jdk21CompatMain.java").toString());

        ProcessBuilder javac = new ProcessBuilder(command);
        javac.directory(NativeObfuscationHelper.projectRoot().toFile());
        javac.redirectErrorStream(true);
        Process process = javac.start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), () -> "javac timed out\n" + output);
        assertEquals(0, process.exitValue(), () -> "javac failed\n" + output);

        Path inputJar = workDir.resolve("jdk21-compat-input.jar");
        writeJar(inputJar, classDir, resourcesDir);
        RunCheck original = runAndCheck(workDir, inputJar, "fixture-original-smoke");
        assertTrue(original.successLine().startsWith(OK_PREFIX), () -> original.combinedOutput());
        return new Fixture(workDir, inputJar);
    }

    private static Path writeNativeConfig(Path workDir) throws Exception {
        Path config = workDir.resolve("jdk21-native.yml");
        Files.writeString(config, """
            version: 1

            native:
              enabled: true
              targets:
                - LINUX_X64
              methods:
                - "**/*"
              excludePatterns: []
              includeAnnotated: true
              skipOnError: false
              outputPrefix: "neko_impl_jdk21_"
              resourceEncryption: false

            keys:
              masterSeed: 212121
            """, StandardCharsets.UTF_8);
        return config;
    }

    private static Path recreateDirectory(Path directory) throws Exception {
        if (Files.exists(directory)) {
            try (var paths = Files.walk(directory)) {
                List<Path> existing = paths.sorted(Comparator.reverseOrder()).toList();
                for (Path path : existing) {
                    Files.delete(path);
                }
            }
        }
        return Files.createDirectories(directory);
    }

    private static void writeJar(Path jar, Path classDir, Path resourcesDir) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Main-Class", MAIN_CLASS);

        try (JarOutputStream output = new JarOutputStream(new FileOutputStream(jar.toFile()), manifest)) {
            addTree(output, classDir, classDir);
            addTree(output, resourcesDir, resourcesDir);
        }
    }

    private static void addTree(JarOutputStream output, Path root, Path directory) throws Exception {
        if (!Files.exists(directory)) {
            return;
        }
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.filter(Files::isRegularFile).sorted().toList()) {
                String entryName = root.relativize(path).toString().replace('\\', '/');
                output.putNextEntry(new JarEntry(entryName));
                Files.copy(path, output);
                output.closeEntry();
            }
        }
    }

    private static RunCheck runAndCheck(Path workDir, Path jar, String name) throws Exception {
        NativeObfuscationHelper.JarRunResult result = NativeObfuscationHelper.runJar(
            jar,
            RUN_JVM_ARGS,
            List.of(),
            workDir.resolve(name + ".stdout.log"),
            workDir.resolve(name + ".stderr.log"),
            Duration.ofSeconds(45),
            Map.of("NEKO_PATCH_DEBUG", "1")
        );
        String combined = result.combinedOutput();
        assertEquals(0, result.exitCode(), () -> combined);
        NativeObfuscationHelper.assertNoFatalNativeCrash(result);
        String successLine = successLine(combined);
        assertTrue(successLine.startsWith(OK_PREFIX), () -> combined);
        return new RunCheck(result, combined, successLine);
    }

    private static String successLine(String output) {
        for (String line : output.split("\\R")) {
            if (line.startsWith(OK_PREFIX)) {
                return line;
            }
        }
        assertTrue(false, () -> "Missing success marker " + OK_PREFIX + " in output:\n" + output);
        return "";
    }

    private static void assertNoRuntimeHelpers(Path jar) throws Exception {
        for (String entry : NativeObfuscationHelper.jarEntries(jar)) {
            assertFalse(entry.startsWith("dev/nekoobfuscator/runtime/"), () -> "runtime helper class injected: " + entry);
        }
    }

    private static final String MAIN_SOURCE = """
        package compat;

        import java.io.ByteArrayInputStream;
        import java.io.ByteArrayOutputStream;
        import java.io.DataOutputStream;
        import java.io.ObjectInputStream;
        import java.io.ObjectOutputStream;
        import java.io.Serializable;
        import java.lang.annotation.Retention;
        import java.lang.annotation.RetentionPolicy;
        import java.lang.invoke.MethodHandle;
        import java.lang.invoke.MethodHandles;
        import java.lang.invoke.MethodType;
        import java.lang.invoke.VarHandle;
        import java.lang.reflect.Constructor;
        import java.lang.reflect.InvocationHandler;
        import java.lang.reflect.Method;
        import java.lang.reflect.Proxy;
        import java.nio.charset.StandardCharsets;
        import java.security.SecureRandom;
        import java.util.ArrayList;
        import java.util.Arrays;
        import java.util.LinkedHashMap;
        import java.util.LinkedHashSet;
        import java.util.List;
        import java.util.SequencedCollection;
        import java.util.SequencedMap;
        import java.util.SequencedSet;
        import java.util.concurrent.Callable;
        import java.util.concurrent.Executors;
        import java.util.concurrent.atomic.AtomicInteger;
        import java.util.function.Function;
        import javax.crypto.KEM;

        public final class Jdk21CompatMain {

            public static void main(String[] args) throws Throwable {
                Checksum checksum = new Checksum();
                recordsPatternsAndSwitch(checksum);
                sequencedCollections(checksum);
                lambdasAndMethodReferences(checksum);
                reflectionDynamicProxyMethodHandlesAndVarHandles(checksum);
                virtualThreads(checksum);
                kemApi(checksum);
                serialization(checksum);
                hiddenClasses(checksum);
                resources(checksum);
                enumsAndNestmates(checksum);
                System.out.println("JDK21_COMPAT_OK checks=" + checksum.count + " digest=" + checksum.digest);
            }

            private static void recordsPatternsAndSwitch(Checksum checksum) {
                Point point = new Point(7, 5);
                Box box = new Box(point);
                check(box instanceof Box(Point(int x, int y)) && x == 7 && y == 5, checksum, "record-pattern-instanceof");
                check(patternSwitch(new Rectangle(4, 4)) == 16, checksum, "pattern-switch-guard");
                check(patternSwitch(new Circle(3)) == 30, checksum, "sealed-record-switch");
                check(patternSwitch(box) == 2, checksum, "nested-record-switch");
                check(patternSwitch(null) == -1, checksum, "null-switch");
            }

            private static int patternSwitch(Object value) {
                return switch (value) {
                    case null -> -1;
                    case Rectangle(int width, int height) when width == height -> width * height;
                    case Rectangle(int width, int height) -> width + height;
                    case Circle(int radius) -> radius * 10;
                    case Box(Point(int x, int y)) -> x - y;
                    case String text -> text.length();
                    default -> 0;
                };
            }

            private static void sequencedCollections(Checksum checksum) {
                SequencedSet<String> set = new LinkedHashSet<>(List.of("alpha", "beta", "gamma"));
                check("gamma".equals(set.reversed().getFirst()), checksum, "sequenced-set-reversed");
                SequencedCollection<String> list = new ArrayList<>(List.of("left", "middle", "right"));
                check("right".equals(list.getLast()), checksum, "sequenced-list-last");
                SequencedMap<String, Integer> map = new LinkedHashMap<>();
                map.put("one", 1);
                map.put("two", 2);
                check(map.reversed().firstEntry().getValue() == 2, checksum, "sequenced-map-reversed");
            }

            private static void lambdasAndMethodReferences(Checksum checksum) throws Exception {
                IntCombiner combiner = (left, right) -> left * 31 + right;
                check(combiner.combine(2, 9) == 71, checksum, "lambda-capture");
                Function<String, String> trim = String::trim;
                check("lambda".equals(trim.apply("  lambda  ")), checksum, "method-reference");
                Callable<String> callable = new LambdaOwner("owner")::call;
                check("owner-call".equals(callable.call()), checksum, "bound-method-reference");
            }

            private static void reflectionDynamicProxyMethodHandlesAndVarHandles(Checksum checksum) throws Throwable {
                Constructor<ReflectTarget> constructor = ReflectTarget.class.getDeclaredConstructor(String.class);
                constructor.setAccessible(true);
                ReflectTarget target = constructor.newInstance("seed");

                Method method = ReflectTarget.class.getDeclaredMethod("join", String.class, int.class);
                method.setAccessible(true);
                check("seed:x:3".equals(method.invoke(target, "x", 3)), checksum, "reflection-method-invoke");
                check(ReflectTarget.class.getRecordComponents() == null, checksum, "class-record-components-null");
                Marker marker = ReflectTarget.class.getDeclaredAnnotation(Marker.class);
                check(marker != null && marker.value().equals("reflect") && Arrays.equals(marker.numbers(), new int[] {1, 2, 3}), checksum, "runtime-annotation");

                MethodHandles.Lookup lookup = MethodHandles.lookup();
                MethodHandle handle = lookup.findVirtual(ReflectTarget.class, "join", MethodType.methodType(String.class, String.class, int.class));
                check("seed:y:4".equals((String) handle.invoke(target, "y", 4)), checksum, "method-handle-virtual");

                VarHandle varHandle = MethodHandles.privateLookupIn(ReflectTarget.class, lookup)
                    .findVarHandle(ReflectTarget.class, "counter", int.class);
                varHandle.set(target, 41);
                check((int) varHandle.get(target) == 41, checksum, "var-handle-private-field");

                Greeter proxy = (Greeter) Proxy.newProxyInstance(
                    Jdk21CompatMain.class.getClassLoader(),
                    new Class<?>[] { Greeter.class },
                    proxyHandler()
                );
                check("hello neko".equals(proxy.greet("neko")), checksum, "dynamic-proxy");
            }

            private static InvocationHandler proxyHandler() {
                return (proxy, method, args) -> switch (method.getName()) {
                    case "greet" -> "hello " + args[0];
                    case "toString" -> "proxy";
                    case "hashCode" -> 42;
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.toString());
                };
            }

            private static void virtualThreads(Checksum checksum) throws Exception {
                AtomicInteger value = new AtomicInteger();
                Thread virtual = Thread.ofVirtual().name("jdk21-compat-virtual").start(() -> value.set(21));
                virtual.join();
                check(value.get() == 21 && virtual.isVirtual(), checksum, "virtual-thread");

                try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                    check(executor.submit(() -> Thread.currentThread().isVirtual()).get(), checksum, "virtual-thread-executor");
                }
            }


            private static void kemApi(Checksum checksum) throws Exception {
                check(KEM.class.getName().equals("javax.crypto.KEM"), checksum, "kem-api-class");
                check(SecureRandom.getInstanceStrong() != null, checksum, "secure-random-strong");
            }

            private static void serialization(Checksum checksum) throws Exception {
                SerializableRecord original = new SerializableRecord("ser", 21);
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
                    output.writeObject(original);
                }
                try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
                    check(original.equals(input.readObject()), checksum, "record-serialization");
                }
            }

            private static void hiddenClasses(Checksum checksum) throws Throwable {
                MethodHandles.Lookup hiddenLookup = MethodHandles.lookup().defineHiddenClass(hiddenClassBytes(), true);
                MethodHandle value = hiddenLookup.findStatic(hiddenLookup.lookupClass(), "value", MethodType.methodType(int.class));
                check((int) value.invoke() == 77, checksum, "hidden-class");
            }

            private static void resources(Checksum checksum) throws Exception {
                try (var input = Jdk21CompatMain.class.getResourceAsStream("data.txt")) {
                    check(input != null, checksum, "resource-present");
                    String text = new String(input.readAllBytes(), StandardCharsets.UTF_8);
                    check("resource-ok\\n".equals(text), checksum, "resource-read");
                }
            }

            private static void enumsAndNestmates(Checksum checksum) {
                Mode mode = Mode.SECOND;
                int value = switch (mode) {
                    case FIRST -> 1;
                    case SECOND -> 2;
                };
                check(value == 2, checksum, "enum-switch");
                check(new Outer().readInnerSecret() == 64, checksum, "nestmate-private-access");
            }

            private static byte[] hiddenClassBytes() throws Exception {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream(192);
                DataOutputStream out = new DataOutputStream(bytes);
                out.writeInt(0xCAFEBABE);
                out.writeShort(0);
                out.writeShort(65);
                out.writeShort(12);
                out.writeByte(1); out.writeUTF("compat/HiddenTemplate");
                out.writeByte(7); out.writeShort(1);
                out.writeByte(1); out.writeUTF("java/lang/Object");
                out.writeByte(7); out.writeShort(3);
                out.writeByte(1); out.writeUTF("<init>");
                out.writeByte(1); out.writeUTF("()V");
                out.writeByte(1); out.writeUTF("Code");
                out.writeByte(12); out.writeShort(5); out.writeShort(6);
                out.writeByte(10); out.writeShort(4); out.writeShort(8);
                out.writeByte(1); out.writeUTF("value");
                out.writeByte(1); out.writeUTF("()I");
                out.writeShort(0x0021);
                out.writeShort(2);
                out.writeShort(4);
                out.writeShort(0);
                out.writeShort(0);
                out.writeShort(2);
                out.writeShort(0x0001);
                out.writeShort(5);
                out.writeShort(6);
                out.writeShort(1);
                out.writeShort(7);
                out.writeInt(17);
                out.writeShort(1);
                out.writeShort(1);
                out.writeInt(5);
                out.writeByte(0x2A);
                out.writeByte(0xB7); out.writeShort(9);
                out.writeByte(0xB1);
                out.writeShort(0);
                out.writeShort(0);
                out.writeShort(0x0009);
                out.writeShort(10);
                out.writeShort(11);
                out.writeShort(1);
                out.writeShort(7);
                out.writeInt(15);
                out.writeShort(1);
                out.writeShort(0);
                out.writeInt(3);
                out.writeByte(0x10); out.writeByte(77);
                out.writeByte(0xAC);
                out.writeShort(0);
                out.writeShort(0);
                out.writeShort(0);
                return bytes.toByteArray();
            }

            private static void check(boolean condition, Checksum checksum, String label) {
                if (!condition) {
                    throw new AssertionError(label);
                }
                checksum.accept(label);
            }

            record Point(int x, int y) implements Serializable {}
            record Box(Point point) {}
            sealed interface Shape permits Rectangle, Circle {}
            record Rectangle(int width, int height) implements Shape {}
            record Circle(int radius) implements Shape {}
            record SerializableRecord(String name, int value) implements Serializable {}

            @Retention(RetentionPolicy.RUNTIME)
            @interface Marker {
                String value();
                int[] numbers();
            }

            @Marker(value = "reflect", numbers = {1, 2, 3})
            static final class ReflectTarget {
                private final String seed;
                private int counter;

                private ReflectTarget(String seed) {
                    this.seed = seed;
                }

                private String join(String suffix, int value) {
                    return seed + ':' + suffix + ':' + value;
                }
            }

            interface Greeter {
                String greet(String name);
            }

            @FunctionalInterface
            interface IntCombiner {
                int combine(int left, int right);
            }

            record LambdaOwner(String prefix) {
                String call() {
                    return prefix + "-call";
                }
            }

            enum Mode {
                FIRST,
                SECOND
            }

            static final class Outer {
                int readInnerSecret() {
                    return new Inner().secret;
                }

                private static final class Inner {
                    private final int secret = 64;
                }
            }

            private static final class Checksum {
                private int count;
                private long digest = 0x21L;

                private void accept(String label) {
                    count++;
                    digest = digest * 1315423911L + label.hashCode();
                }
            }
        }
        """;

    private record Fixture(Path workDir, Path inputJar) {}

    private record RunCheck(
        NativeObfuscationHelper.JarRunResult result,
        String combinedOutput,
        String successLine
    ) {}
}
