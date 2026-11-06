package com.himitsu.secret.core;

import com.himitsu.secret.bridge.SecretNative;
import com.himitsu.secret.util.DynamicMethodLookup;
import com.himitsu.secret.hook.HookRegistry;
import com.himitsu.secret.hook.HookDefinition;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public final class PayloadTransformer {
    private static final AtomicBoolean LOADED_TARGETS_RETRANSFORMED = new AtomicBoolean();

    private PayloadTransformer() {
    }

    public static void install() throws Exception {
        try {
            EventBusBridge.defineAndBind();
        } catch (Exception exception) {
            throw exception;
        } catch (Throwable throwable) {
            throw new IllegalStateException("Cannot initialize EventBus bridge", throwable);
        }
        HookRegistry.register(HookDefinition.override(
            "net/minecraftforge/eventbus/EventBus", "post",
            "(Lnet/minecraftforge/eventbus/api/Event;)Z", true,
            EventBusBridge.INTERNAL_NAME, "post",
            "(Lnet/minecraftforge/eventbus/EventBus;Lnet/minecraftforge/eventbus/api/Event;)Z"
        ));
        HookRegistry.register(HookDefinition.override(
            "net/minecraftforge/eventbus/EventBus", "post",
            "(Lnet/minecraftforge/eventbus/api/Event;Lnet/minecraftforge/eventbus/api/IEventBusInvokeDispatcher;)Z", true,
            EventBusBridge.INTERNAL_NAME, "post",
            "(Lnet/minecraftforge/eventbus/EventBus;Lnet/minecraftforge/eventbus/api/Event;Lnet/minecraftforge/eventbus/api/IEventBusInvokeDispatcher;)Z"
        ));
        HookRegistry.register(SecretEntityHooks.class);
        HookRegistry.register(CivilizationSurvivalHooks.class);
        HookRegistry.register(OwnerSafetyHooks.class);
        HookRegistry.register(DeathExecutionHooks.class);
        HookRegistry.register(RuntimeCompatibilityHooks.class);
        SecretNative.invokeChecked(
            "ClassLoadHook",
            PayloadTransformer.class,
            DynamicMethodLookup.findStatic(
                PayloadTransformer.class,
                byte[].class,
                ClassLoader.class,
                String.class,
                Class.class,
                ProtectionDomain.class,
                byte[].class
            )
        );
    }

    public static void retransformLoadedTargets() {
        if (!LOADED_TARGETS_RETRANSFORMED.compareAndSet(false, true)) return;
        Class<?>[] loadedClasses = waitForMinecraft();
        retransformLoadedTargets(loadedClasses);
    }

    private static Class<?>[] waitForMinecraft() {
        while (true) {
            Object result = SecretNative.invokeChecked("GetLoadedClasses");
            if (result instanceof Class<?>[] loadedClasses) {
                for (Class<?> loadedClass : loadedClasses) {
                    if (loadedClass != null
                        && loadedClass.getName().equals("net.minecraft.client.Minecraft")) {
                        return loadedClasses;
                    }
                }
            }
            Thread.onSpinWait();
        }
    }

    private static void retransformLoadedTargets(Class<?>[] loadedClasses) {
        List<Class<?>> targets = new ArrayList<>();
        for (Class<?> loadedClass : loadedClasses) {
            if (loadedClass != null
                && (HookRegistry.hasTarget(loadedClass.getName()) || matchesSubclassTarget(loadedClass))
                && loadedClass.getClassLoader() != null
                && !loadedClass.isArray()
                && !loadedClass.isPrimitive()) {
                targets.add(loadedClass);
            }
        }
        if (!targets.isEmpty()) {
            SecretNative.invokeChecked("RetransformClass", (Object) targets.toArray(Class<?>[]::new));
        }
    }

    private static boolean matchesSubclassTarget(Class<?> type) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            if (current != type && HookRegistry.hooksFor(current.getName()).stream()
                .anyMatch(HookDefinition::includeSubclasses)) return true;
            for (Class<?> contract : current.getInterfaces()) {
                if (HookRegistry.hooksFor(contract.getName()).stream().anyMatch(HookDefinition::includeSubclasses)
                    || matchesSubclassTarget(contract)) return true;
            }
        }
        return false;
    }

    public static byte[] transform(
        ClassLoader loader,
        String className,
        Class<?> classBeingRedefined,
        ProtectionDomain protectionDomain,
        byte[] classFileBuffer
    ) {
        return ClassDefense.transformOrRestore(
            loader,
            className,
            classBeingRedefined,
            protectionDomain,
            classFileBuffer
        );
    }
}

