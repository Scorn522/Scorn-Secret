package com.himitsu.secret.bridge;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

/** Real JNI binding under a narrowly scoped native-method-stripping test agent. */
public final class BridgeBindingCheck implements ClassFileTransformer {
    private static volatile int transformed;
    private static volatile boolean renameMethods;
    public static void premain(String arguments, Instrumentation instrumentation) {
        instrumentation.addTransformer(new BridgeBindingCheck());
    }
    @Override public byte[] transform(ClassLoader loader, String name, Class<?> redefined,
            ProtectionDomain domain, byte[] bytes) {
        if (!"com/himitsu/secret/bridge/NativeBridge".equals(name)) return null;
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        for (MethodNode method : node.methods) {
            if ((method.access & Opcodes.ACC_NATIVE) == 0) continue;
            if (renameMethods) { method.name = "rewritten_" + method.name; continue; }
            method.access &= ~Opcodes.ACC_NATIVE;
            method.instructions.clear();
            method.tryCatchBlocks.clear();
            method.localVariables = null;
            boolean ready = method.desc.equals("()Z");
            method.instructions.add(new InsnNode(ready ? Opcodes.ICONST_0 : Opcodes.ACONST_NULL));
            method.instructions.add(new InsnNode(ready ? Opcodes.IRETURN : Opcodes.ARETURN));
        }
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        transformed++;
        return writer.toByteArray();
    }
    private static native int bind(Class<?> bridge, Class<?> publicationOwner);
    private static void check(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }
    public static void main(String[] args) throws Exception {
        System.load(Path.of(args[0]).toAbsolutePath().toString());
        byte[] bytes = Files.readAllBytes(Path.of(args[1]));
        class OrdinaryLoader extends ClassLoader {
            Class<?> define() { return defineClass("com.himitsu.secret.bridge.NativeBridge", bytes, 0, bytes.length); }
        }
        Class<?> ordinary = new OrdinaryLoader().define();
        check(transformed == 1, "Native stripping agent did not run");
        check(!Modifier.isNative(ordinary.getDeclaredMethod("ready").getModifiers()), "Baseline not stripped");
        check(bind(ordinary, null) != 0, "Stripped native bridge unexpectedly bound");
        renameMethods = true;
        Class<?> renamed = new OrdinaryLoader().define();
        check(transformed == 2, "Method renaming agent did not run");
        check(bind(renamed, null) != 0, "Renamed native bridge unexpectedly bound");

        var define = SecretNative.class.getDeclaredMethod("defineNativeBridge", byte[].class);
        define.setAccessible(true);
        var resolve = SecretNative.class.getDeclaredMethod("resolveBridge", Duration.class);
        resolve.setAccessible(true);
        check(bind(ordinary, SecretNative.class) != 0, "Expected native failure publication");
        try {
            resolve.invoke(null, Duration.ofSeconds(3));
            throw new AssertionError("Failed native registration was accepted");
        } catch (java.lang.reflect.InvocationTargetException expected) {
            check(expected.getCause().getMessage().contains("status="), "Native failure became an ambiguous timeout");
        }
        var failureState = SecretNative.class.getDeclaredField("bridgeFailure");
        failureState.setAccessible(true);
        failureState.setInt(null, 0); // Isolate the next scenario in this check JVM.
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<Class<?>> actual = new AtomicReference<>();
        Thread publisher = new Thread(() -> {
            try {
                Class<?> hidden = (Class<?>) define.invoke(null, (Object) bytes);
                check(hidden.isHidden(), "Bridge was discoverable by name");
                check(Modifier.isNative(hidden.getDeclaredMethod("ready").getModifiers()), "Hidden method stripped");
                check(bind(hidden, SecretNative.class) == 0, "Hidden JNI registration failed");
                actual.set(hidden);
            } catch (Throwable error) { failure.set(error); }
        }, "bridge-binding-check");
        publisher.setDaemon(true);
        // Mirrors load(): the startup thread owns this monitor while JNI publishes.
        synchronized (SecretNative.class) {
            publisher.start();
            resolve.invoke(null, Duration.ofSeconds(3));
        }
        publisher.join(3000);
        check(!publisher.isAlive() && failure.get() == null, "Bridge publication failed: " + failure.get());
        check(transformed == 2, "Hidden bridge traversed the ordinary class transformer");
        try {
            Class.forName(actual.get().getName(), false, SecretNative.class.getClassLoader());
            throw new AssertionError("Hidden bridge was discoverable by name");
        } catch (ClassNotFoundException expected) { /* Direct reference must still resolve below. */ }
        var invoke = SecretNative.class.getDeclaredField("invokeMethod");
        invoke.setAccessible(true);
        var method = (java.lang.reflect.Method) invoke.get(null);
        check(method.getDeclaringClass() == actual.get(), "Resolver lost JNI-published class identity");
        check(method.invoke(null, "round-trip", new Object[0]).equals("round-trip"), "JNI invocation ABI changed");
        check(!SecretNative.isLoaded(), "Test must not initialize the production DLL");
        System.out.println("BRIDGE_BINDING_PASS ordinary_strip_and_rename_rejected hidden_native_registered name_lookup_unavailable failure_status volatile_publication held_monitor round_trip TEST_DLL_ONLY_NO_GAME");
    }
}
