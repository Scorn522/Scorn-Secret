package com.himitsu.secret.tools;

import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Runs the actual Java coordinator with a fake JNI endpoint; never loads the DLL. */
public final class LocalShutdownCheck {
    private static final List<String> calls = new CopyOnWriteArrayList<>();
    private static final CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
    public static Object endpoint(String command,Object[] arguments) throws Exception {
        calls.add(command);
        if(command.equals("Shutdown")) { entered.countDown(); if(!release.await(5,TimeUnit.SECONDS))throw new AssertionError("release timeout"); }
        return Boolean.TRUE;
    }
    private static Object invoke(Method method,Object...args) {
        try { return method.invoke(null,args); }
        catch(InvocationTargetException failure) {
            if(failure.getCause() instanceof RuntimeException e)throw e;
            if(failure.getCause() instanceof Error e)throw e;
            throw new RuntimeException(failure.getCause());
        } catch(ReflectiveOperationException failure) { throw new RuntimeException(failure); }
    }
    public static void main(String[] args) throws Exception {
        Class<?> bridge=Class.forName("com.himitsu.secret.bridge.SecretNative");
        Field loaded=bridge.getDeclaredField("loaded"), endpoint=bridge.getDeclaredField("invokeMethod");
        loaded.setAccessible(true);endpoint.setAccessible(true);loaded.setBoolean(null,true);
        endpoint.set(null,LocalShutdownCheck.class.getMethod("endpoint",String.class,Object[].class));
        Method command=bridge.getMethod("invokeChecked",String.class,Object[].class), shutdown=bridge.getMethod("shutdown");
        invoke(bridge.getMethod("beforeShutdown",Runnable.class),(Runnable)()->invoke(command,"UnprotectThread",new Object[0]));
        AtomicReference<Throwable> failure=new AtomicReference<>();
        Thread closer=new Thread(()->{try{invoke(shutdown);}catch(Throwable e){failure.set(e);}});
        closer.start();
        if(!entered.await(5,TimeUnit.SECONDS))throw new AssertionError("shutdown did not reach native endpoint");
        try { invoke(command,"status",new Object[0]);throw new AssertionError("late command entered JNI"); }
        catch(IllegalStateException expected) {}
        invoke(shutdown);release.countDown();closer.join(5000);
        if(closer.isAlive()||failure.get()!=null||loaded.getBoolean(null)||!calls.equals(List.of("HostShutdown","UnprotectThread","Shutdown")))
            throw new AssertionError("shutdown order/count/state changed: "+calls,failure.get());
        invoke(shutdown);
        if(calls.size()!=3)throw new AssertionError("duplicate native shutdown");
        System.out.println("JAVA_SHUTDOWN_PASS cleanup_before_native late_call_refused duplicate_shutdown_noop MODEL_NO_DLL");
    }
}
