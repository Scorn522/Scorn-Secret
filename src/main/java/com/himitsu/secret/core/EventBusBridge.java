package com.himitsu.secret.core;

import com.himitsu.secret.bridge.SecretNative;
import com.himitsu.secret.util.DynamicMethodLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandleInfo;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import net.minecraftforge.eventbus.EventBus;
import net.minecraftforge.eventbus.api.Event;
import net.minecraftforge.eventbus.api.IEventBusInvokeDispatcher;
import org.objectweb.asm.*;

final class EventBusBridge {
    static final String INTERNAL_NAME = "net/minecraftforge/eventbus/SecretEventBusBridge";
    private static final String POST = "(Lnet/minecraftforge/eventbus/EventBus;Lnet/minecraftforge/eventbus/api/Event;)Z";
    private static final String POST_DISPATCHER = "(Lnet/minecraftforge/eventbus/EventBus;Lnet/minecraftforge/eventbus/api/Event;Lnet/minecraftforge/eventbus/api/IEventBusInvokeDispatcher;)Z";
    private static Class<?> installed;
    private EventBusBridge() {}

    static synchronized Class<?> defineAndBind() throws Throwable {
        if(installed!=null) {
            Object checked=SecretNative.invokeChecked("VerifyEventBusBridge");
            if(!(checked instanceof Class<?> bridge))throw new IllegalStateException("EventBus bridge unavailable");
            installed=bridge;return bridge;
        }
        MethodHandles.Lookup lookup=MethodHandles.lookup();
        MethodHandle[] handlers={
            lookup.unreflect(DynamicMethodLookup.findStatic(EventBusTakeover.class,boolean.class,EventBus.class,Event.class)),
            lookup.unreflect(DynamicMethodLookup.findStatic(EventBusTakeover.class,boolean.class,EventBus.class,Event.class,IEventBusInvokeDispatcher.class))};
        Object result=SecretNative.invokeChecked("DefineEventBusBridge",bytes(),EventBus.class,handlers);
        if(!(result instanceof Class<?> bridge) || bridge.getClassLoader()!=EventBus.class.getClassLoader()
            || !bridge.getName().equals(INTERNAL_NAME.replace('/','.')) || bridge.getSuperclass()!=Object.class)
            throw new IllegalStateException("Cannot define EventBus bridge");
        installed=bridge;return bridge;
    }
    // Called only during the Native installation transaction, on pinned local handle references.
    private static void validate(MethodHandle first,MethodHandle second) throws ReflectiveOperationException {
        if(first==null || second==null)throw new IllegalArgumentException("Incomplete EventBus binding");
        var lookup=MethodHandles.lookup();
        MethodHandle[] handlers={first,second};
        for(int i=0;i<2;i++) {
            MethodType expected=MethodType.fromMethodDescriptorString(i==0?POST:POST_DISPATCHER,EventBus.class.getClassLoader());
            var info=lookup.revealDirect(handlers[i]);
            if(!handlers[i].type().equals(expected) || info.getDeclaringClass()!=EventBusTakeover.class
                || info.getReferenceKind()!=MethodHandleInfo.REF_invokeStatic)
                throw new IllegalArgumentException("Unexpected EventBus handler");
        }
    }
    private static byte[] bytes() {
        ClassWriter writer=new ClassWriter(ClassWriter.COMPUTE_FRAMES|ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17,Opcodes.ACC_PUBLIC|Opcodes.ACC_FINAL,INTERNAL_NAME,null,"java/lang/Object",null);
        writer.visitField(Opcodes.ACC_PRIVATE|Opcodes.ACC_STATIC|Opcodes.ACC_VOLATILE,"handlers","[Ljava/lang/invoke/MethodHandle;",null,null).visitEnd();
        emitPost(writer,POST,0);emitPost(writer,POST_DISPATCHER,1);
        writer.visitEnd();return writer.toByteArray();
    }
    private static void emitPost(ClassWriter writer,String descriptor,int slot) {
        MethodVisitor method=writer.visitMethod(Opcodes.ACC_PUBLIC|Opcodes.ACC_STATIC,"post",descriptor,null,new String[]{"java/lang/Throwable"});
        method.visitCode();
        method.visitFieldInsn(Opcodes.GETSTATIC,INTERNAL_NAME,"handlers","[Ljava/lang/invoke/MethodHandle;");
        method.visitInsn(Opcodes.DUP);Label ready=new Label();method.visitJumpInsn(Opcodes.IFNONNULL,ready);
        method.visitInsn(Opcodes.POP);method.visitTypeInsn(Opcodes.NEW,"java/lang/IllegalStateException");method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("EventBus bridge not bound");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL,"java/lang/IllegalStateException","<init>","(Ljava/lang/String;)V",false);
        method.visitInsn(Opcodes.ATHROW);method.visitLabel(ready);
        method.visitInsn(slot==0?Opcodes.ICONST_0:Opcodes.ICONST_1);method.visitInsn(Opcodes.AALOAD);
        method.visitVarInsn(Opcodes.ALOAD,0);method.visitVarInsn(Opcodes.ALOAD,1);
        if(slot==1) method.visitVarInsn(Opcodes.ALOAD,2);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL,"java/lang/invoke/MethodHandle","invokeExact",descriptor,false);
        method.visitInsn(Opcodes.IRETURN);method.visitMaxs(0,0);method.visitEnd();
    }
}
