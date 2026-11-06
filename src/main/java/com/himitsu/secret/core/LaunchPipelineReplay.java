package com.himitsu.secret.core;

import com.himitsu.secret.transform.LoaderAwareClassWriter;
import cpw.mods.modlauncher.serviceapi.ILaunchPluginService;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import net.minecraftforge.accesstransformer.service.AccessTransformerService;
import net.minecraftforge.eventbus.service.ModLauncherService;
import net.minecraftforge.fml.common.asm.CapabilityTokenSubclass;
import net.minecraftforge.fml.common.asm.ObjectHolderDefinalize;
import net.minecraftforge.fml.common.asm.RuntimeEnumExtender;
import net.minecraftforge.fml.loading.RuntimeDistCleaner;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.spongepowered.asm.launch.IClassProcessor;
import org.spongepowered.asm.launch.MixinLaunchPluginLegacy;
import org.spongepowered.asm.service.IMixinService;
import org.spongepowered.asm.service.MixinService;
import org.spongepowered.asm.service.modlauncher.MixinServiceModLauncher;

final class LaunchPipelineReplay {
    private static final ILaunchPluginService[] COMMON = {
        new ModLauncherService(),
        new ObjectHolderDefinalize(),
        new CapabilityTokenSubclass(),
        new RuntimeDistCleaner(),
        new AccessTransformerService(),
        new RuntimeEnumExtender()
    };
    private static volatile ILaunchPluginService mixin;

    private LaunchPipelineReplay() {
    }

    static byte[] common(ClassLoader loader, byte[] source) {
        return process(loader, source, COMMON);
    }

    static byte[] mixin(ClassLoader loader, byte[] common) {
        ILaunchPluginService service = mixin;
        if (service == null) {
            synchronized (LaunchPipelineReplay.class) {
                service = mixin;
                if (service == null) mixin = service = createMixinReplay(loader);
            }
        }
        return service == null ? common : process(loader, common, service);
    }

    static byte[] modLauncher(ClassLoader loader, byte[] common) {
        try {
            Method method = findMethod(loader.getClass(), "maybeTransformClassBytes", byte[].class, String.class, String.class);
            method.setAccessible(true);
            String name = new ClassReader(common).getClassName().replace('/', '.');
            return (byte[]) method.invoke(loader, common, name, null);
        } catch (Throwable exception) {
            return common;
        }
    }

    private static byte[] process(ClassLoader loader, byte[] bytes, ILaunchPluginService... services) {
        try {
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES);
            Type type = Type.getObjectType(node.name);
            for (ILaunchPluginService service : services) {
                if (node.name.equals("net/minecraftforge/eventbus/api/Event") && service instanceof ModLauncherService) continue;
                for (ILaunchPluginService.Phase phase : service.handlesClass(type, false)) {
                    service.processClassWithFlags(phase, node, type, "classloading");
                }
            }
            ClassWriter writer = new LoaderAwareClassWriter(ClassWriter.COMPUTE_FRAMES, loader);
            node.accept(writer);
            return writer.toByteArray();
        } catch (Throwable exception) {
            return bytes;
        }
    }

    private static ILaunchPluginService createMixinReplay(ClassLoader loader) {
        try {
            MixinLaunchPluginLegacy replay = new MixinLaunchPluginLegacy();
            IMixinService service = MixinService.getService();
            if (!(service instanceof MixinServiceModLauncher modLauncher)) return replay;
            setField(replay, "service", service);
            setField(replay, "auditTrail", service.getAuditTrail());
            setField(replay, "commandLineMixins", new ArrayList<>());
            Object processors = getField(replay, "processors");
            if (processors instanceof List<?> values) {
                @SuppressWarnings("unchecked")
                List<IClassProcessor> target = (List<IClassProcessor>) values;
                synchronized (target) {
                    target.addAll(modLauncher.getProcessors());
                }
            }
            if (Boolean.FALSE.equals(getField(modLauncher, "initialised"))) modLauncher.onInit(replay);
            Method build = findMethod(loader.getClass(), "buildTransformedClassNodeFor", String.class, String.class);
            build.setAccessible(true);
            replay.initializeLaunch(name -> {
                try {
                    return (byte[]) build.invoke(loader, name, "mixin");
                } catch (Throwable ignored) {
                    return null;
                }
            }, new java.nio.file.Path[0]);
            return replay;
        } catch (Throwable exception) {
            return null;
        }
    }

    private static Method findMethod(Class<?> type, String name, Class<?>... parameters) throws NoSuchMethodException {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredMethod(name, parameters);
            } catch (NoSuchMethodException ignored) {
            }
        }
        throw new NoSuchMethodException(name);
    }

    private static Object getField(Object target, String name) throws ReflectiveOperationException {
        Field field = findField(target.getClass(), name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static void setField(Object target, String name, Object value) throws ReflectiveOperationException {
        Field field = findField(target.getClass(), name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static String message(Throwable exception) {
        Throwable cause = exception;
        while (cause.getCause() != null) cause = cause.getCause();
        return cause.getMessage() == null ? cause.getClass().getName() : cause.getMessage();
    }
}
