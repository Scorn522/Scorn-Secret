package com.himitsu.secret.bridge;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.invoke.MethodHandles;
import java.util.concurrent.locks.LockSupport;
import java.net.URLDecoder;
import org.lwjgl.system.MemoryUtil;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.Properties;
import org.lwjgl.system.JNI;
import org.lwjgl.system.Library;
import org.lwjgl.system.SharedLibrary;

public final class SecretNative {

    private static volatile boolean loaded;
    private static volatile boolean shuttingDown;
    private static volatile Thread shutdownThread;
    private static Runnable shutdownCleanup;
    private static volatile boolean nativeStarted;
    private static volatile boolean bridgeRequested;
    private static SharedLibrary nativeLibrary;
    private static Method invokeMethod;
    // Published by JNI only after registration and guard monitoring succeed.
    private static volatile Class<?> registeredBridge;
    private static volatile int bridgeFailure;

    private SecretNative() {
    }

    public static synchronized void load(
        Path gameDirectory,
        Duration readyTimeout
    ) throws IOException {
        if (shuttingDown) throw new IOException("Secret native bridge has been shut down");
        if (loaded) {
            return;
        }

        bootstrap(gameDirectory);
        resolveBridge(readyTimeout);
        loaded = true;
        registerShutdownHook();
    }

    public static synchronized void loadEarly(Path gameDirectory) throws IOException {
        if (shuttingDown) throw new IOException("Secret native bridge has been shut down");
        if (nativeStarted) {
            return;
        }

        Path libraryPath = prepareNativeLibrary(gameDirectory);

        try {
            nativeLibrary = Library.loadNative(
                SecretNative.class,
                "secret",
                libraryPath.toAbsolutePath().toString()
            );
        } catch (UnsatisfiedLinkError exception) {
            throw new IOException("LWJGL failed to load native library: " + libraryPath, exception);
        }

        invokeIntExport("HimitsuEarlyGuard", readJvmtiDisable(gameDirectory) ? 1 : 0);
        String location = URLDecoder.decode(SecretNative.class.getProtectionDomain()
            .getCodeSource().getLocation().getPath(), StandardCharsets.UTF_8);
        int archiveEnd = location.toLowerCase(java.util.Locale.ROOT).lastIndexOf(".jar");
        if (archiveEnd < 0) throw new IOException("Native source shield requires a packaged archive");
        location = location.substring(0, archiveEnd + 4);
        if (location.matches("^/[A-Za-z]:/.*")) location = location.substring(1);
        java.nio.ByteBuffer source = MemoryUtil.memUTF16(location);
        try {
            invokePointerExport("HimitsuLoadSources", MemoryUtil.memAddress(source), 0L);
        } finally { MemoryUtil.memFree(source); }
        nativeStarted = true;
    }

    // The service phase installs protection only. The actual mod loader claims
    // bridge ownership later; service/game copies must not publish to each other.
    public static synchronized void bootstrap(Path gameDirectory) throws IOException {
        loadEarly(gameDirectory);
        bridgeRequested = true;
        invokePointerExport("HimitsuBootstrap", 0L, 0L);
    }

    // Resolve the platform suffix at runtime: class transformers must not be able
    // to redirect native resources by replacing DLL string literals in bytecode.
    static Path prepareNativeLibrary(Path gameDirectory) throws IOException {
        String libraryName = System.mapLibraryName("himitsu");
        byte[] resourceBytes = readNativeResource(libraryName);
        Path nativeDirectory = gameDirectory.resolve("secret").resolve("native");
        Files.createDirectories(nativeDirectory);
        Path libraryPath = nativeDirectory.resolve(libraryName);
        if (Files.isRegularFile(libraryPath)
                && Arrays.equals(Files.readAllBytes(libraryPath), resourceBytes)) return libraryPath;
        Path temporary = Files.createTempFile(nativeDirectory, "himitsu-", ".pending");
        try {
            Files.write(temporary, resourceBytes);
            if (!Arrays.equals(Files.readAllBytes(temporary), resourceBytes)) {
                throw new IOException("Native library extraction verification failed");
            }
            try {
                Files.move(temporary, libraryPath, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, libraryPath, StandardCopyOption.REPLACE_EXISTING);
            }
            if (!Arrays.equals(Files.readAllBytes(libraryPath), resourceBytes)) {
                throw new IOException("Native library integrity verification failed");
            }
            return libraryPath;
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static byte[] readNativeResource(String libraryName) throws IOException {
        String resource = "/" + libraryName;
        byte[] bytes;
        try (InputStream input = SecretNative.class.getResourceAsStream(resource)) {
            if (input == null) throw new IOException("Missing native resource: " + resource);
            bytes = input.readAllBytes();
        }
        String digestResource = "/META-INF/secret-native.sha256";
        byte[] expected;
        try (InputStream input = SecretNative.class.getResourceAsStream(digestResource)) {
            if (input == null) throw new IOException("Missing native resource digest");
            // The generated descriptor is exactly 64 ASCII hex characters plus LF.
            byte[] text = input.readNBytes(66);
            String hex = new String(text, StandardCharsets.US_ASCII).trim();
            if (text.length > 65 || hex.length() != 64) {
                throw new IOException("Invalid native resource digest");
            }
            try {
                expected = HexFormat.of().parseHex(hex);
            } catch (IllegalArgumentException exception) {
                throw new IOException("Invalid native resource digest", exception);
            }
        }
        try {
            if (!MessageDigest.isEqual(expected, MessageDigest.getInstance("SHA-256").digest(bytes))) {
                throw new IOException("Packaged native resource integrity verification failed");
            }
        } catch (NoSuchAlgorithmException exception) {
            throw new IOException("SHA-256 unavailable for native resource verification", exception);
        }
        return bytes;
    }

    private static void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(
            SecretNative::shutdown,
            "Secret-Native-Shutdown"
        ));
    }

    public static void configure(Path gameDirectory, Path modPath) {
        requireLoaded();
        invokeChecked(
            "Configure",
            gameDirectory.toAbsolutePath().toString(),
            modPath.toAbsolutePath().toString()
        );
    }

    public static Object invokeChecked(String command, Object... arguments) {
        requireLoaded();
        Object result;
        try {
            result = invokeMethod.invoke(
                null,
                Objects.requireNonNull(command, "command"),
                arguments == null ? new Object[0] : arguments
            );
        } catch (IllegalAccessException exception) {
            throw new IllegalStateException("Cannot access native bridge", exception);
        } catch (InvocationTargetException exception) {
            throw new IllegalStateException("Native bridge invocation failed", exception.getCause());
        }
        if (result instanceof Throwable throwable) {
            throw new IllegalStateException("Native command failed: " + command, throwable);
        }
        return result;
    }

    public static boolean isLoaded() {
        return loaded;
    }

    public static synchronized void beforeShutdown(Runnable cleanup) {
        requireLoaded();
        if (shuttingDown || shutdownCleanup != null) throw new IllegalStateException("Secret shutdown cleanup already assigned");
        shutdownCleanup = Objects.requireNonNull(cleanup, "cleanup");
    }

    public static void shutdown() {
        Runnable cleanup;
        synchronized (SecretNative.class) {
            if (!loaded || shuttingDown) return;
            shutdownThread = Thread.currentThread();
            shuttingDown = true;
            cleanup = shutdownCleanup;
            shutdownCleanup = null;
        }
        try {
            if (cleanup != null) cleanup.run();
        } catch (Throwable ignored) {
        } finally {
            try {
                invokeChecked("Shutdown");
            } catch (Throwable failure) {
                System.err.println("[Secret/Shutdown] Native drain incomplete: "+failure);
            } finally {
                loaded = false;
                shutdownThread = null;
            }
        }
    }

    // Called once by the native bootstrap thread. Do not acquire this class's
    // monitor: load() holds it while waiting for the registered bridge.
    private static Class<?> defineNativeBridge(byte[] bytes) throws IllegalAccessException {
        return MethodHandles.lookup().defineHiddenClass(bytes, false).lookupClass();
    }

    private static int bridgeAttempts(Duration timeout) {
        if (timeout == null || timeout.isNegative() || timeout.isZero())
            throw new IllegalArgumentException("Native ready timeout must be positive");
        long millis;
        try { millis = timeout.toMillis(); }
        catch (ArithmeticException exception) { millis = Long.MAX_VALUE; }
        return (int) Math.max(1L, Math.min(2400L, millis / 25L + (millis % 25L == 0 ? 0 : 1)));
    }

    private static void resolveBridge(Duration timeout) {
        int maxAttempts = bridgeAttempts(timeout);
        Throwable lastFailure = null;
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int failure = bridgeFailure;
            if (failure != 0) {
                throw new IllegalStateException("Native bridge registration failed (status=" + failure
                    + "); see native log for the original exception");
            }
            try {
                Class<?> bridge = registeredBridge;
                if (bridge != null) {
                    Method candidateInvoke = bridge.getDeclaredMethod("invoke", String.class, Object[].class);
                    Method candidateReady = bridge.getDeclaredMethod("ready");
                    if (Boolean.TRUE.equals(candidateReady.invoke(null))) {
                        invokeMethod = candidateInvoke;
                        return;
                    }
                }
            } catch (Throwable exception) {
                lastFailure = exception;
            }

            if (Thread.currentThread().isInterrupted()) {
                throw new IllegalStateException("Interrupted while waiting for native bootstrap");
            }
            if (attempt + 1 < maxAttempts) LockSupport.parkNanos(25_000_000L);
        }
        throw new IllegalStateException("Native bootstrap did not become ready within " + timeout, lastFailure);
    }

    private static void invokeIntExport(String name, int argument) throws IOException {
        long address = exportAddress(name);
        int result = JNI.callI(argument, address);
        if (result != 0) {
            throw new IOException("Native export failed: " + name + " (result=" + result + ")");
        }
    }

    private static void invokePointerExport(String name, long first, long second) throws IOException {
        long address = exportAddress(name);
        int result = JNI.callPPI(first, second, address);
        if (result != 0) {
            throw new IOException("Native export failed: " + name + " (result=" + result + ")");
        }
    }

    private static long exportAddress(String name) throws IOException {
        long address = nativeLibrary.getFunctionAddress(name);
        if (address == 0L) throw new IOException("Missing native export: " + name);
        return address;
    }

    private static boolean readJvmtiDisable(Path gameDirectory) throws IOException {
        Path path = gameDirectory.resolve("config").resolve("secret.config");
        if (!Files.isRegularFile(path)) {
            return true;
        }
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        String value = properties.getProperty("JVMTI禁用", "true")
            .trim()
            .toLowerCase(java.util.Locale.ROOT);
        if (!value.equals("true") && !value.equals("false")) {
            throw new IOException("Invalid configuration JVMTI禁用: " + value);
        }
        return Boolean.parseBoolean(value);
    }

    private static void requireLoaded() {
        if (!loaded || shuttingDown && Thread.currentThread() != shutdownThread) {
            throw new IllegalStateException("Secret native bridge is not ready");
        }
    }
}
