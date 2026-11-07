package com.himitsu.secret.bridge;

import java.net.URLClassLoader;
import java.nio.file.Path;
import java.time.Duration;

/** Explicit production-DLL startup check in a disposable JVM; never starts Forge or a world. */
public final class NativeStartupCheck {
    private static final java.util.Map<String,byte[]> authenticated=new java.util.LinkedHashMap<>();
    private static volatile boolean nestedDumpRequested;
    private static volatile byte[] nestedDump;
    private static volatile int heartbeatCallbacks;
    private static void check(boolean condition,String message) {
        if(!condition)throw new AssertionError(message);
    }
    private static Throwable rootCause(Throwable error) {
        while(error.getCause()!=null && error.getCause()!=error)error=error.getCause();return error;
    }
    private static void verifyEventBridge() throws Exception {
        try {SecretNative.invokeChecked("VerifyEventBusBridge");throw new AssertionError("untrusted bridge caller accepted");}
        catch(IllegalStateException expected){check(rootCause(expected) instanceof SecurityException,"Wrong unauthenticated caller failure");}
        for(String name:new String[]{"com/himitsu/secret/util/DynamicMethodLookup","com/himitsu/secret/core/EventBusTakeover$Handler","com/himitsu/secret/core/EventBusTakeover","com/himitsu/secret/core/EventBusBridge"}) {
            byte[] image=authenticated.get(name);check(image!=null,"Missing authenticated bridge dependency "+name);
            SecretNative.invokeChecked("DefineClass",name,SecretNative.class.getClassLoader(),image);
        }
        Class<?> installer=Class.forName("com.himitsu.secret.core.EventBusBridge");
        var bytes=installer.getDeclaredMethod("bytes");bytes.setAccessible(true);byte[] original=(byte[])bytes.invoke(null);
        var install=installer.getDeclaredMethod("defineAndBind");install.setAccessible(true);
        String name="net/minecraftforge/eventbus/SecretEventBusBridge";
        var busType=net.minecraftforge.eventbus.EventBus.class;
        if(Boolean.getBoolean("secret.check.bridgeConflict")) {
            SecretNative.invokeChecked("DefineClass",name,busType.getClassLoader(),original);
            try {install.invoke(null);throw new AssertionError("Foreign existing bridge adopted");}
            catch(java.lang.reflect.InvocationTargetException expected){check(rootCause(expected) instanceof LinkageError,"Conflict not preserved");}
            System.out.println("EVENT_BRIDGE_CONFLICT_PASS no_adoption generation_rollback NO_GAME");return;
        }
        Class<?> bridge=(Class<?>)install.invoke(null);check(install.invoke(null)==bridge,"Repeat bridge install changed Class");
        var slot=bridge.getDeclaredField("handlers");slot.setAccessible(true);
        var expected=((java.lang.invoke.MethodHandle[])slot.get(null)).clone();
        var replacement=expected.clone();replacement[0]=java.lang.invoke.MethodHandles.constant(boolean.class,true);
        slot.set(null,replacement);long deadline=System.nanoTime()+3_000_000_000L;
        while(System.nanoTime()<deadline && ((java.lang.invoke.MethodHandle[])slot.get(null))[0]!=expected[0])Thread.sleep(20);
        var restored=(java.lang.invoke.MethodHandle[])slot.get(null);check(restored[0]==expected[0]&&restored[1]==expected[1],"Native monitor did not restore handler elements");
        slot.set(null,null);check(install.invoke(null)==bridge,"Cold verification failed to repair whole array");
        var node=new org.objectweb.asm.tree.ClassNode();new org.objectweb.asm.ClassReader(original).accept(node,0);
        for(var method:node.methods)if(method.name.equals("post")) {
            method.instructions.clear();method.tryCatchBlocks.clear();if(method.localVariables!=null)method.localVariables.clear();
            method.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.ICONST_1));
            method.instructions.add(new org.objectweb.asm.tree.InsnNode(org.objectweb.asm.Opcodes.IRETURN));method.maxStack=1;
        }
        var writer=new org.objectweb.asm.ClassWriter(0);node.accept(writer);byte[] bad=writer.toByteArray();
        check(Boolean.TRUE.equals(SecretNative.invokeChecked("RedefineClass",bridge,bad)),"Bridge redefine request failed");
        var bus=(net.minecraftforge.eventbus.EventBus)net.minecraftforge.eventbus.api.BusBuilder.builder().build();bus.shutdown();
        var post=bridge.getMethod("post",busType,net.minecraftforge.eventbus.api.Event.class);
        check(!(boolean)post.invoke(null,bus,null),"Dynamic bridge bytecode was not restored");
        ClassLoader other=new java.net.URLClassLoader(new java.net.URL[0],busType.getClassLoader());
        Class<?> foreign=(Class<?>)SecretNative.invokeChecked("DefineClass",name,other,bad);
        check((boolean)foreign.getMethod("post",busType,net.minecraftforge.eventbus.api.Event.class).invoke(null,bus,null),"Different loader was rewritten");
        var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
        Thread writerThread=new Thread(()->{try {for(int i=0;i<80;i++)slot.set(null,expected.clone());}catch(Throwable error){failure.set(error);}},"Secret-check-bridge-writer");
        writerThread.start();for(int i=0;i<80;i++)check(install.invoke(null)==bridge,"Concurrent bridge verification failed");writerThread.join();
        check(failure.get()==null,"Bridge concurrent fixture failed");check(install.invoke(null)==bridge,"Final bridge state unavailable");
        System.out.println("EVENT_BRIDGE_PASS authenticated_installer exact_loader redefine_restore handlers_independent_baseline repeated_install concurrent_verify NO_GAME");
    }
    private static void verifySourceShield(Path archive) throws Exception {
        int decoded=0;
        try(var zip=new java.util.zip.ZipFile(archive.toFile())) {
            byte[] encrypted;
            try(var stream=zip.getInputStream(zip.getEntry("himitsu.jar"))) { encrypted=stream.readAllBytes(); }
            byte[] payload=(byte[])SecretNative.invokeChecked("DecryptPayloadJar",encrypted);
            try(var input=new java.util.jar.JarInputStream(new java.io.ByteArrayInputStream(payload))) {
                for(var entry=input.getNextJarEntry();entry!=null;entry=input.getNextJarEntry()) {
                    if(!entry.getName().endsWith(".bin"))continue;
                    byte[] bytes=(byte[])SecretNative.invokeChecked("DecryptPayloadClass",input.readAllBytes());
                    check(new org.objectweb.asm.ClassReader(bytes).getClassName().startsWith("com/himitsu/secret/"),"Unexpected authenticated class");
                    authenticated.put(new org.objectweb.asm.ClassReader(bytes).getClassName(),bytes);decoded++;
                }
            }
            byte[] original;
            try(var input=zip.getInputStream(zip.getEntry("com/himitsu/secret/bridge/EarlyBootstrapService.class"))) { original=input.readAllBytes(); }
            var node=new org.objectweb.asm.tree.ClassNode();new org.objectweb.asm.ClassReader(original).accept(node,0);
            boolean changed=false;
            for(var method:node.methods) for(var instruction:method.instructions) {
                if(instruction instanceof org.objectweb.asm.tree.LdcInsnNode ldc && "secret-bootstrap".equals(ldc.cst)) {
                    ldc.cst="changed-by-check";changed=true;
                }
            }
            check(changed,"Source mutation fixture did not change");
            var writer=new org.objectweb.asm.ClassWriter(0);node.accept(writer);
            check(Boolean.TRUE.equals(SecretNative.invokeChecked("RedefineClass",EarlyBootstrapService.class,writer.toByteArray())),"Own redefine failed");
            check(new EarlyBootstrapService().name().equals("secret-bootstrap"),"Own JAR source did not heal rewritten class");
            var callback=NativeStartupCheck.class.getMethod("ownedTransform",ClassLoader.class,String.class,Class.class,java.security.ProtectionDomain.class,byte[].class);
            SecretNative.invokeChecked("ClassLoadHook",NativeStartupCheck.class,callback);
            try {
                SecretNative.invokeChecked("RedefineClass",EarlyBootstrapService.class,writer.toByteArray());
                check(new EarlyBootstrapService().name().equals("authorized-hook"),"Legitimate internal hook was removed");
                nestedDumpRequested=true;
                byte[] observed=(byte[])SecretNative.invokeChecked("DumpClass",EarlyBootstrapService.class);
                check(new org.objectweb.asm.ClassReader(observed).getClassName().endsWith("EarlyBootstrapService"),"Outer dump capture was replaced");
                check(nestedDump!=null && new org.objectweb.asm.ClassReader(nestedDump).getClassName().endsWith("SecretNative"),"Nested dump capture failed");
                int before=heartbeatCallbacks;
                Thread.sleep(2500);
                check(heartbeatCallbacks==before,"Background monitor still retransforms SecretNative");
            } finally { SecretNative.invokeChecked("ClassLoadHook",null,null); }
            SecretNative.invokeChecked("RedefineClass",EarlyBootstrapService.class,writer.toByteArray());
            check(new EarlyBootstrapService().name().equals("secret-bootstrap"),"Disabling Java callback disabled native source shield");
        }
        check(decoded>0,"Authenticated payload was not checked");
        byte[] first=outsider(3),second=outsider(7);
        ClassLoader loader=new ClassLoader() {};
        Class<?> other=(Class<?>)SecretNative.invokeChecked("DefineClass","external/check/Ordinary",loader,first);
        check((Integer)other.getMethod("value").invoke(null)==3,"Ordinary class failed to load");
        check(Boolean.TRUE.equals(SecretNative.invokeChecked("RedefineClass",other,second)),"Ordinary redefine was blocked");
        check((Integer)other.getMethod("value").invoke(null)==7,"Source shield changed an unrelated class");
        System.out.println("SOURCE_SHIELD_PASS authenticated_classes="+decoded+" jar_self_heal internal_hook_preserved unregister_still_protected unrelated_class_preserved nested_dump no_background_retransform");
    }
    public static byte[] ownedTransform(ClassLoader loader,String name,Class<?> type,java.security.ProtectionDomain domain,byte[] input) {
        if(name.equals("com/himitsu/secret/bridge/SecretNative"))heartbeatCallbacks++;
        if(!name.equals("com/himitsu/secret/bridge/EarlyBootstrapService"))return null;
        if(nestedDumpRequested) {
            nestedDumpRequested=false;
            nestedDump=(byte[])SecretNative.invokeChecked("DumpClass",SecretNative.class);
        }
        var node=new org.objectweb.asm.tree.ClassNode();new org.objectweb.asm.ClassReader(input).accept(node,0);
        boolean clean=false;
        for(var method:node.methods)for(var instruction:method.instructions) {
            if(instruction instanceof org.objectweb.asm.tree.LdcInsnNode ldc && "secret-bootstrap".equals(ldc.cst)) {
                clean=true;ldc.cst="authorized-hook";
            }
        }
        check(clean,"Internal transformer received untrusted bytes");
        var writer=new org.objectweb.asm.ClassWriter(0);node.accept(writer);return writer.toByteArray();
    }
    private static byte[] outsider(int value) {
        var writer=new org.objectweb.asm.ClassWriter(0);
        writer.visit(61,org.objectweb.asm.Opcodes.ACC_PUBLIC,"external/check/Ordinary",null,"java/lang/Object",null);
        var method=writer.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC|org.objectweb.asm.Opcodes.ACC_STATIC,"value","()I",null,null);
        method.visitCode();method.visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH,value);method.visitInsn(org.objectweb.asm.Opcodes.IRETURN);
        method.visitMaxs(1,0);method.visitEnd();writer.visitEnd();return writer.toByteArray();
    }
    private static void verifyPackageBinding(Path archive,Path keys) throws Exception {
        String version;
        try(var jar=new java.util.jar.JarFile(archive.toFile())) {version=jar.getManifest().getMainAttributes().getValue("Implementation-Version");}
        String secret=com.google.gson.JsonParser.parseString(java.nio.file.Files.readString(keys)).getAsJsonObject().get("outer").getAsString();
        Class<?> tool=Class.forName("com.himitsu.secret.tools.SecureJarTool");
        var field=tool.getDeclaredField("packageVersion");field.setAccessible(true);
        var encrypt=tool.getDeclaredMethod("encrypt",byte[].class,String.class,String.class);encrypt.setAccessible(true);
        byte[] plain={7,19,31,43};field.set(null,version);
        byte[] valid=(byte[])encrypt.invoke(null,plain,secret,"outer");
        check(java.util.Arrays.equals(plain,(byte[])SecretNative.invokeChecked("DecryptPayloadJar",valid)),"Matching release failed native authentication");
        field.set(null,version+"-different");
        byte[] wrongVersion=(byte[])encrypt.invoke(null,plain,secret,"outer");
        field.set(null,version);
        byte[] wrongPurpose=(byte[])encrypt.invoke(null,plain,secret,"class");
        byte[] tampered=valid.clone();tampered[tampered.length-1]^=1;
        for(byte[] input:new byte[][]{wrongVersion,wrongPurpose,tampered}) {
            try {SecretNative.invokeChecked("DecryptPayloadJar",input);throw new AssertionError("Mismatched or modified payload accepted");}
            catch(IllegalStateException rejected) {check(rejected.getCause() instanceof SecurityException,"Unexpected authentication failure: "+rejected);}
        }
        System.out.println("PACKAGE_BINDING_PASS native_round_trip wrong_release wrong_purpose changed_tag_rejected");
    }
    private static native int createEnvironmentTail(int count);
    private static void verifyEnvironmentChain(Path directory) throws Exception {
        check(createEnvironmentTail(320)==320,"Could not construct a real long JVMTI chain");
        Thread.sleep(2500); // At least two production membership checks; no game is started.
        check(SecretNative.invokeChecked("DumpClass",EarlyBootstrapService.class) instanceof byte[],"Own JVMTI callback stopped after foreign tail growth");
        String log=java.nio.file.Files.readString(directory.resolve("secret/native/himitsu-native.log"));
        check(!log.contains("开始刷新 JVMTI 环境") && !log.contains("JVMTI health unavailable"),"Live own environment was invalidated by the long foreign tail");
        System.out.println("JVMTI_CHAIN_PASS 320_real_environments own_callbacks_live no_recreation");
    }
    private static native boolean probeCallerSuspend();
    private static native long currentHandle();
    private static native long copyHandle(long handle,int access);
    private static native long suspendHandle(long handle,boolean base);
    private static native long terminateHandle(long handle,boolean base);
    private static native int resumeHandle(long handle);
    private static native int threadId(long handle);
    private static native void closeHandle(long handle);
    private static native long ordinaryHandle();
    private static native boolean finishedHandle(long handle);
    private static void denied(long packed,long result,String message) {
        check((packed&0xffffffffL)==result && (packed>>>32)==5,message+": "+Long.toHexString(packed));
    }
    @SuppressWarnings({"deprecation", "removal"})
    private static void verifyThreadGuards() throws Exception {
        var running=new java.util.concurrent.atomic.AtomicBoolean(true);
        var ticks=new java.util.concurrent.atomic.AtomicLong();
        var handle=new java.util.concurrent.atomic.AtomicLong();
        var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
        var started=new java.util.concurrent.CountDownLatch(1);
        Thread worker=new Thread(() -> {
            try {
                handle.set(currentHandle());
                check(handle.get()!=0,"Cannot capture worker handle");
                check(Boolean.TRUE.equals(SecretNative.invokeChecked("ProtectThread",Thread.currentThread())),"Self registration failed");
                started.countDown();
                while(running.get()) {ticks.incrementAndGet();java.util.concurrent.locks.LockSupport.parkNanos(1_000_000L);}
            } catch(ThreadDeath stopped) {throw stopped;}
            catch(Throwable error) {failure.set(error);}
            finally {started.countDown();SecretNative.invokeChecked("UnprotectThread",Thread.currentThread());}
        },"Secret-check-protected-worker");
        worker.setDaemon(true);
        System.out.println("THREAD_GUARD_STAGE pre_registration");
        check(Boolean.TRUE.equals(SecretNative.invokeChecked("ProtectThread",worker)),"Pre-registration failed");
        System.out.println("THREAD_GUARD_STAGE caller_probe");
        check(probeCallerSuspend(),"Pre-registration wrongly protected the calling main OS thread");
        System.out.println("THREAD_GUARD_STAGE worker_start");
        worker.start();started.await();
        System.out.println("THREAD_GUARD_STAGE self_registered");
        long lowSuspend=0,lowTerminate=0,ordinary=0;
        try {
            check(failure.get()==null,"Self registration failed: "+failure.get());
            check(!Thread.getAllStackTraces().containsKey(worker),"Protected thread remained enumerable");
            System.out.println("THREAD_GUARD_STAGE low_rights");
            lowSuspend=copyHandle(handle.get(),2);lowTerminate=copyHandle(handle.get(),1);
            check(lowSuspend!=0 && lowTerminate!=0 && threadId(lowSuspend)==0 && threadId(lowTerminate)==0,"Low-rights handle fixture still has query access");
            for(boolean base:new boolean[]{false,true}) {
                denied(suspendHandle(lowSuspend,base),0xffffffffL,"Protected Win32 suspend succeeded");
                denied(terminateHandle(lowTerminate,base),0,"Protected Win32 terminate succeeded");
            }
            System.out.println("THREAD_GUARD_STAGE java_suspend");
            long before=ticks.get();worker.suspend();
            try {for(int n=0;n<100&&ticks.get()<=before;n++)Thread.sleep(10);check(ticks.get()>before,"Protected Java suspend succeeded");}
            finally {worker.resume();}
            worker.stop();Thread.sleep(30);check(worker.isAlive(),"Protected Java stop succeeded");
            System.out.println("THREAD_GUARD_STAGE ordinary_os");
            ordinary=ordinaryHandle();check(ordinary!=0,"Ordinary worker fixture missing");
            check((suspendHandle(ordinary,false)&0xffffffffL)==0,"Ordinary Win32 suspend blocked");
            check(resumeHandle(ordinary)==1,"Ordinary suspend count changed");
            check((terminateHandle(ordinary,true)&0xffffffffL)!=0 && finishedHandle(ordinary),"Ordinary Win32 terminate blocked");
            System.out.println("THREAD_GUARD_STAGE reference_churn");
            Thread reader=new Thread(() -> {
                try {for(int n=0;n<80;n++) Thread.getAllStackTraces();}
                catch(Throwable error) {failure.set(error);}
            },"Secret-check-reference-reader");
            reader.start();
            for(int n=0;n<80;n++) {SecretNative.invokeChecked("UnprotectThread",worker);SecretNative.invokeChecked("ProtectThread",worker);}
            reader.join(3000);check(!reader.isAlive() && failure.get()==null,"Concurrent reference retirement failed: "+failure.get());
            SecretNative.invokeChecked("UnprotectThread",worker);
            check(Thread.getAllStackTraces().containsKey(worker),"Unprotected thread stayed hidden");
            System.out.println("THREAD_GUARD_STAGE ordinary_java");
            worker.suspend();try {long parked=ticks.get();Thread.sleep(40);check(ticks.get()==parked,"Ordinary Java suspend blocked");}finally {worker.resume();}
            worker.stop();worker.join(2000);check(!worker.isAlive(),"Ordinary Java stop blocked");
        } finally {
            SecretNative.invokeChecked("UnprotectThread",worker);running.set(false);worker.resume();worker.join(2000);
            closeHandle(lowSuspend);closeHandle(lowTerminate);closeHandle(handle.get());
            if(ordinary!=0) {if(!finishedHandle(ordinary))terminateHandle(ordinary,false);closeHandle(ordinary);}
        }
        System.out.println("THREAD_GUARD_PASS pre_registration_not_caller self_os_registration low_rights_kernel32_kernelbase ordinary_operations_preserved concurrent_reference_retirement");
    }
    private static void verifyCallbackPublication() throws Exception {
        var method=NativeStartupCheck.class.getMethod("ownedTransform",ClassLoader.class,String.class,Class.class,java.security.ProtectionDomain.class,byte[].class);
        var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
        Thread writer=new Thread(() -> {
            try {for(int i=0;i<20;i++) {SecretNative.invokeChecked("ClassLoadHook",NativeStartupCheck.class,method);SecretNative.invokeChecked("ClassLoadHook",null,null);}}
            catch(Throwable error) {failure.set(error);}
        },"Secret-check-callback-publisher");
        writer.start();
        for(int i=0;i<20;i++) check(SecretNative.invokeChecked("DumpClass",EarlyBootstrapService.class) instanceof byte[],"Concurrent dump failed");
        writer.join(3000);check(!writer.isAlive()&&failure.get()==null,"Callback retirement failed: "+failure.get());
        SecretNative.invokeChecked("ClassLoadHook",null,null);
        System.out.println("CALLBACK_PUBLICATION_PASS concurrent_replace_capture JNI_OUTSIDE_NATIVE_LOCK");
    }
    private static void shutdownWhileEnumerating() throws Exception {
        var running=new java.util.concurrent.atomic.AtomicBoolean(true);
        var failure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
        var started=new java.util.concurrent.CountDownLatch(1);
        Thread reader=new Thread(() -> {
            started.countDown();
            try { while(running.get()) { Thread.getAllStackTraces(); Thread.yield(); } }
            catch(Throwable error) { failure.set(error); }
        },"Secret-check-exit-enumerator");
        reader.setDaemon(true);reader.start();started.await();
        try { SecretNative.shutdown(); }
        finally { running.set(false);reader.join(3000); }
        check(!reader.isAlive()&&failure.get()==null,"Concurrent shutdown/enumeration failed: "+failure.get());
        check(Thread.getAllStackTraces().containsKey(Thread.currentThread()),"Enumeration failed after shutdown");
        System.out.println("THREAD_GUARD_EXIT_PASS concurrent_enumeration late_calls_safe");
    }
    public static void main(String[] args) throws Exception {
        Path archive=Path.of(args[0]).toAbsolutePath(),directory=Path.of(args[1]).toAbsolutePath();
        System.load(Path.of(args[2]).toAbsolutePath().toString());
        try(URLClassLoader service=new URLClassLoader(new java.net.URL[]{archive.toUri().toURL()},NativeStartupCheck.class.getClassLoader()) {
            @Override protected Class<?> loadClass(String name,boolean resolve) throws ClassNotFoundException {
                if(!name.equals("com.himitsu.secret.bridge.SecretNative"))return super.loadClass(name,resolve);
                synchronized(getClassLoadingLock(name)) {
                    Class<?> value=findLoadedClass(name);
                    if(value==null)value=findClass(name);
                    if(resolve)resolveClass(value);return value;
                }
            }
        }) {
            Class<?> early=service.loadClass("com.himitsu.secret.bridge.SecretNative");
            early.getMethod("loadEarly",Path.class).invoke(null,directory);
            var published=early.getDeclaredField("registeredBridge");published.setAccessible(true);
            check(published.get(null)==null,"Service layer received game bridge");
            try {
                SecretNative.load(directory,Duration.ofSeconds(10));
                check(SecretNative.isLoaded(),"Production native runtime not ready");
                var field=SecretNative.class.getDeclaredField("registeredBridge");field.setAccessible(true);
                Class<?> bridge=(Class<?>)field.get(null);
                check(bridge!=null&&bridge!=Object.class,"Invalid bridge identity");
                check(bridge.getClassLoader()==SecretNative.class.getClassLoader(),"Wrong loader owns game bridge");
                check(published.get(null)==null,"Game bridge leaked into service copy");
                var count=BridgeBindingCheck.class.getDeclaredField("transformed");count.setAccessible(true);
                check(count.getInt(null)==0,"External class callback survived early isolation");
                verifyPackageBinding(archive,Path.of(args[3]));
                verifySourceShield(archive);
                verifyEventBridge();
                verifyCallbackPublication();
                verifyThreadGuards();
                verifyEnvironmentChain(directory);
                System.out.println("NATIVE_STARTUP_PASS two_loaders source_shield external_agent_isolated bridge="+bridge.getName());
            } finally { shutdownWhileEnumerating(); }
        }
        check(!SecretNative.isLoaded(),"Production native shutdown incomplete");
        System.out.println("NATIVE_STARTUP_EXIT_PASS NO_GAME");
    }
}
