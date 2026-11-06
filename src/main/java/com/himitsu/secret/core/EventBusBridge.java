package com.himitsu.secret.core;

import com.himitsu.secret.bridge.SecretNative;
import com.himitsu.secret.util.DynamicMethodLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import net.minecraftforge.eventbus.EventBus;
import net.minecraftforge.eventbus.api.Event;
import net.minecraftforge.eventbus.api.IEventBusInvokeDispatcher;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class EventBusBridge {
    static final String INTERNAL_NAME = "net/minecraftforge/eventbus/SecretEventBusBridge";
    private static final String POST = "(Lnet/minecraftforge/eventbus/EventBus;Lnet/minecraftforge/eventbus/api/Event;)Z";
    private static final String POST_DISPATCHER = "(Lnet/minecraftforge/eventbus/EventBus;Lnet/minecraftforge/eventbus/api/Event;Lnet/minecraftforge/eventbus/api/IEventBusInvokeDispatcher;)Z";

    private EventBusBridge() {
    }

    static Class<?> defineAndBind() throws Throwable {
        ClassLoader loader = EventBus.class.getClassLoader();
        Class<?> bridge;
        try {
            bridge = Class.forName(INTERNAL_NAME.replace('/', '.'), false, loader);
        } catch (ClassNotFoundException ignored) {
            Object result = SecretNative.invokeChecked("DefineClass", INTERNAL_NAME, loader, bytes());
            if (!(result instanceof Class<?> type)) throw new IllegalStateException("Cannot define EventBus bridge");
            bridge = type;
        }
        MethodHandles.Lookup lookup = MethodHandles.lookup();
        MethodHandle simple = lookup.unreflect(DynamicMethodLookup.findStatic(
            EventBusTakeover.class, boolean.class, EventBus.class, Event.class
        ));
        MethodHandle dispatched = lookup.unreflect(DynamicMethodLookup.findStatic(
            EventBusTakeover.class,
            boolean.class,
            EventBus.class,
            Event.class,
            IEventBusInvokeDispatcher.class
        ));
        bridge.getMethod("bind", MethodHandle.class, MethodHandle.class).invoke(null, simple, dispatched);
        return bridge;
    }

    private static byte[] bytes() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, INTERNAL_NAME, null, "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_VOLATILE, "simple", "Ljava/lang/invoke/MethodHandle;", null, null).visitEnd();
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_VOLATILE, "dispatched", "Ljava/lang/invoke/MethodHandle;", null, null).visitEnd();

        MethodVisitor bind = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "bind", "(Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodHandle;)V", null, null);
        bind.visitCode();
        bind.visitVarInsn(Opcodes.ALOAD, 0);
        bind.visitFieldInsn(Opcodes.PUTSTATIC, INTERNAL_NAME, "simple", "Ljava/lang/invoke/MethodHandle;");
        bind.visitVarInsn(Opcodes.ALOAD, 1);
        bind.visitFieldInsn(Opcodes.PUTSTATIC, INTERNAL_NAME, "dispatched", "Ljava/lang/invoke/MethodHandle;");
        bind.visitInsn(Opcodes.RETURN);
        bind.visitMaxs(0, 0);
        bind.visitEnd();

        emitPost(writer, "post", POST, "simple", POST);
        emitPost(writer, "post", POST_DISPATCHER, "dispatched", POST_DISPATCHER);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitPost(ClassWriter writer, String name, String descriptor, String field, String invokeDescriptor) {
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, descriptor, null, new String[] {"java/lang/Throwable"});
        method.visitCode();
        method.visitFieldInsn(Opcodes.GETSTATIC, INTERNAL_NAME, field, "Ljava/lang/invoke/MethodHandle;");
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        if (descriptor.equals(POST_DISPATCHER)) method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandle", "invokeExact", invokeDescriptor, false);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
    }
}
