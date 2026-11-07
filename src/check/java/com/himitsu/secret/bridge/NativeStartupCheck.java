package com.himitsu.secret.bridge;

import java.net.URLClassLoader;
import java.nio.file.Path;
import java.time.Duration;

/** Explicit production-DLL startup check in a disposable JVM; never starts Forge or a world. */
public final class NativeStartupCheck {
    private static final java.util.Map<String,byte[]> authenticated=new java.util.LinkedHashMap<>();
    private static volatile boolean nestedDumpRequested;
    private static volatile boolean allChecksPassed,exitReaderRun;
    private static Thread exitReader;
    private static volatile Throwable exitReaderFailure;
    private static native int ntThread(long handle,boolean terminate);
    private static native boolean selfEndDenied(boolean nt);
    private static native long nativeCreate(String program,String arguments,boolean ansi);
    private static native int directAttach();
    private static native long shellCreate(String program,String arguments);
    private static native void installFailureProbe();
    private static String sha(Path path) throws Exception {return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(path)));}
    private static void prepareHostPolicy(Path directory,Path probeDll) throws Exception {
        var config=new java.util.Properties();Path source=Path.of(NativeStartupCheck.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        Path command=Path.of(System.getenv("SystemRoot"),"System32/cmd.exe");
        for(String kind:new String[]{"java","native","shell"}) {
            String key="process.allow."+kind+".";Path origin=kind.equals("java")?source:probeDll;
            config.setProperty(key+"kind",kind);config.setProperty(key+"source",origin.toString());config.setProperty(key+"sourceSha256",sha(origin));
            config.setProperty(key+"program",command.toString());config.setProperty(key+"programSha256",sha(command));config.setProperty(key+"arguments","/d /c exit 0");
            config.setProperty(key+"directory",Path.of("").toAbsolutePath().toString());
            if(kind.equals("shell")) {config.setProperty(key+"verb","open");config.setProperty(key+"target",command.toString());config.setProperty(key+"childArguments","/d /c exit 0");}
        }
        java.nio.file.Files.createDirectories(directory.resolve("config"));
        try(var writer=java.nio.file.Files.newBufferedWriter(directory.resolve("config/secret.config"))) {config.store(writer,"Disposable host guard check only");}
    }
    private static void attachHelper(String[] args) throws Exception {
        Path ready=Path.of(args[2]),done=Path.of(args[3]);long until=System.nanoTime()+30_000_000_000L;
        while(!java.nio.file.Files.exists(ready)&&System.nanoTime()<until)Thread.sleep(20);
        if(!java.nio.file.Files.exists(ready))throw new AssertionError("Attach probe never received ready signal");
        try {
            var vm=com.sun.tools.attach.VirtualMachine.attach(args[1]);
            try {vm.getSystemProperties();throw new AssertionError("Runtime Attach operation was accepted");}
            finally {vm.detach();}
        } catch(java.io.IOException expected) {
            java.nio.file.Files.writeString(done,"PASS");System.out.println("EXTERNAL_ATTACH_DENIED_PASS");
        } catch(InternalError disabled) {
            // Windows libattach reports HotSpot ATTACH_ERROR_DISABLED (100) as InternalError.
            if(disabled.getMessage()==null || !disabled.getMessage().endsWith("(100)"))throw disabled;
            java.nio.file.Files.writeString(done,"PASS");System.out.println("EXTERNAL_ATTACH_DENIED_PASS status=100");
        }
    }
    private static void verifyHostPolicy() throws Exception {
        try {System.exit(73);throw new AssertionError("System.exit accepted");}catch(SecurityException expected) {}
        try {Runtime.getRuntime().halt(74);throw new AssertionError("Runtime.halt accepted");}catch(SecurityException expected) {}
        try {SecretNative.shutdown();throw new AssertionError("Direct shutdown accepted");}
        catch(IllegalStateException expected) {check(rootCause(expected) instanceof SecurityException,"Wrong shutdown refusal");}
        check(SecretNative.isLoaded(),"Unauthorized shutdown disarmed the runtime");
        for(String command:new String[]{"HostShutdown","Shutdown","HostLifecycle","HostInstall","HostPolicy"}) {
            try {SecretNative.invokeChecked(command);throw new AssertionError("Unauthenticated "+command+" accepted");}
            catch(IllegalStateException expected){check(rootCause(expected) instanceof SecurityException,"Wrong command refusal: "+command);}
        }
        check(selfEndDenied(false)&&selfEndDenied(true),"Self process termination accepted");check(directAttach()==100,"Attach status did not explicitly refuse");
        String executable=Path.of(System.getenv("SystemRoot"),"System32/cmd.exe").toString();
        var child=new ProcessBuilder(executable,"/d","/c","exit","0").start();check(child.waitFor()==0,"Exact Java allowlist operation failed");
        try {new ProcessBuilder(executable,"/d","/c","exit","1").start();throw new AssertionError("Mismatched process arguments accepted");}catch(java.io.IOException expected) {}
        check(nativeCreate(executable,"/d /c exit 0",false)==1,"Exact Unicode native process grant failed");
        check(nativeCreate(executable,"/d /c exit 0",true)==1,"Exact ANSI native process grant failed");
        check(nativeCreate(executable,"/d /c exit 1",false)==-5,"Native parameter mismatch accepted");
        var writer=new org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
        writer.visit(61,org.objectweb.asm.Opcodes.ACC_PUBLIC,"r24/check/ForgedOrigin",null,"java/lang/Object",null);
        var method=writer.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC|org.objectweb.asm.Opcodes.ACC_STATIC,"start","(Ljava/lang/String;)Ljava/lang/Process;",null,null);method.visitCode();
        method.visitTypeInsn(org.objectweb.asm.Opcodes.NEW,"java/lang/ProcessBuilder");method.visitInsn(org.objectweb.asm.Opcodes.DUP);
        method.visitInsn(org.objectweb.asm.Opcodes.ICONST_5);method.visitTypeInsn(org.objectweb.asm.Opcodes.ANEWARRAY,"java/lang/String");
        for(int i=0;i<5;i++){method.visitInsn(org.objectweb.asm.Opcodes.DUP);method.visitInsn(org.objectweb.asm.Opcodes.ICONST_0+i);if(i==0)method.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD,0);else method.visitLdcInsn(new String[]{"","/d","/c","exit","0"}[i]);method.visitInsn(org.objectweb.asm.Opcodes.AASTORE);}
        method.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL,"java/lang/ProcessBuilder","<init>","([Ljava/lang/String;)V",false);
        method.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL,"java/lang/ProcessBuilder","start","()Ljava/lang/Process;",false);method.visitInsn(org.objectweb.asm.Opcodes.ARETURN);method.visitMaxs(0,0);method.visitEnd();writer.visitEnd();
        var forged=new java.security.SecureClassLoader(NativeStartupCheck.class.getClassLoader()) {
            Class<?> define(byte[] bytes){return defineClass("r24.check.ForgedOrigin",bytes,0,bytes.length,NativeStartupCheck.class.getProtectionDomain().getCodeSource());}
        }.define(writer.toByteArray());
        try {var launched=(Process)forged.getMethod("start",String.class).invoke(null,executable);launched.waitFor();throw new AssertionError("Forged CodeSource loader acquired process permission");}
        catch(java.lang.reflect.InvocationTargetException refused){check(rootCause(refused) instanceof java.io.IOException,"Wrong forged-source refusal");}
        check(shellCreate(executable,"/d /c exit 0")==1,"Exact Shell grant failed");
        check(shellCreate(executable,"/d /c exit 1")==-5,"Shell argument mismatch was not denied");
        System.out.println("HOST_POLICY_PASS before_shutdown_hooks exit_halt_self_terminate_refused exact_java_native_shell_grants forged_loader_refused attach_disabled");
    }
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
    private static void verifyCleanupTasks() throws Exception {
        var direct=new java.util.concurrent.FutureTask<Void>(()->{},null);
        try {SecretNative.invokeChecked("ReadCleanupTask",direct);throw new AssertionError("unauthenticated task reader accepted");}
        catch(IllegalStateException expected){check(rootCause(expected) instanceof SecurityException,"wrong untrusted cleanup failure");}
        for(String name:new String[]{"com/himitsu/secret/network/sync/SyncValue","com/himitsu/secret/network/sync/StringSetSyncValue",
            "com/himitsu/secret/core/WeakTargetSet$Node","com/himitsu/secret/core/WeakTargetSet$Bucket",
            "com/himitsu/secret/core/WeakTargetSet","com/himitsu/secret/core/TargetCleanup$1","com/himitsu/secret/core/TargetCleanup",
            "com/himitsu/secret/core/TargetCleanup$Cleaner"}) {
            byte[] image=authenticated.get(name);check(image!=null,"missing cleanup dependency "+name);
            SecretNative.invokeChecked("DefineClass",name,SecretNative.class.getClassLoader(),image);
        }
        Class<?> type=Class.forName("com.himitsu.secret.core.TargetCleanup");
        var read=type.getDeclaredMethod("readTask",Object.class);read.setAccessible(true);
        check(!java.util.concurrent.FutureTask.class.getDeclaredField("callable").trySetAccessible(),"test unexpectedly opened JDK task fields");
        Runnable body=()->{};var task=new java.util.concurrent.FutureTask<Void>(body,null);
        Object[] snapshot=(Object[])read.invoke(null,task);check(snapshot.length==4&&snapshot[0]==body&&snapshot[2]==task,"trusted task unwrapping failed");
        try {read.invoke(null,new Object());throw new AssertionError("arbitrary object accepted as task");}
        catch(java.lang.reflect.InvocationTargetException expected){check(rootCause(expected) instanceof IllegalArgumentException,"wrong wrapper refusal");}
        net.minecraft.SharedConstants.tryDetectVersion();
        var bootstrap=net.minecraft.server.Bootstrap.class.getDeclaredField("isBootstrapped");bootstrap.setAccessible(true);bootstrap.set(null,true);
        net.minecraft.core.registries.BuiltInRegistries.bootStrap();net.minecraftforge.registries.GameData.vanillaSnapshot();
        var uf=sun.misc.Unsafe.class.getDeclaredField("theUnsafe");uf.setAccessible(true);var unsafe=(sun.misc.Unsafe)uf.get(null);
        var target=(com.himitsu.secret.core.TargetGuardCheck.EntityFixture)unsafe.allocateInstance(com.himitsu.secret.core.TargetGuardCheck.EntityFixture.class);
        target.uuid=java.util.UUID.randomUUID();
        Class<?> cleaner=Class.forName("com.himitsu.secret.core.TargetCleanup$Cleaner");
        // The released constructor reads SRG Entity fields; this disposable JVM uses official mappings.
        // Prepare its existing Java-only context, then exercise the unchanged production task path.
        Object context=unsafe.allocateInstance(cleaner);
        for(var field:cleaner.getDeclaredFields()) {
            if(java.lang.reflect.Modifier.isStatic(field.getModifiers()))continue;field.setAccessible(true);
            if(field.getName().equals("target"))field.set(context,target);
            else if(field.getName().equals("uuid"))field.set(context,target.uuid);
            else if(field.getType()==java.util.Set.class)field.set(context,java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>()));
            else if(field.getType()==java.util.Map.class)field.set(context,new java.util.IdentityHashMap<>());
        }
        var tasks=cleaner.getDeclaredMethod("tasks",Object.class);tasks.setAccessible(true);
        var own=new java.util.concurrent.FutureTask<Void>((Runnable)target,null);tasks.invoke(context,own);check(own.isCancelled(),"production cleaner failed through closed JDK Native path");
        var companion=new java.util.concurrent.FutureTask<Void>(()->target.run(),null);
        tasks.invoke(context,companion);check(companion.isCancelled(),"production Native path did not cancel companion");
        var timer=new java.util.concurrent.ScheduledThreadPoolExecutor(1);
        try {
            var timed=timer.scheduleAtFixedRate((Runnable)target,1,1,java.util.concurrent.TimeUnit.DAYS);
            var unrelated=timer.schedule(()->{},1,java.util.concurrent.TimeUnit.DAYS);
            tasks.invoke(context,timer);check(timed.isCancelled()&&!timer.getQueue().contains(timed)&&!unrelated.isCancelled(),"scheduled cleanup isolation failed");
            check(timer.submit(()->17).get(2,java.util.concurrent.TimeUnit.SECONDS)==17,"shared timer was stopped");
        } finally {timer.shutdownNow();check(timer.awaitTermination(2,java.util.concurrent.TimeUnit.SECONDS),"test timer failed to exit");}
        System.out.println("NATIVE_CLEANUP_PASS authenticated_reader closed_jdk_fields actual_cancel companion_cancel scheduler_isolation NO_GAME");
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
            check(ntThread(lowSuspend,false)==0xC0000022 && ntThread(lowTerminate,true)==0xC0000022,"Protected NT thread operation succeeded");
            System.out.println("THREAD_GUARD_STAGE java_suspend");
            long before=ticks.get();worker.suspend();
            try {for(int n=0;n<100&&ticks.get()<=before;n++)Thread.sleep(10);check(ticks.get()>before,"Protected Java suspend succeeded");}
            finally {worker.resume();}
            worker.stop();Thread.sleep(30);check(worker.isAlive(),"Protected Java stop succeeded");
            System.out.println("THREAD_GUARD_STAGE ordinary_os");
            ordinary=ordinaryHandle();check(ordinary!=0,"Ordinary worker fixture missing");
            check(ntThread(ordinary,false)==0,"Ordinary NT suspend blocked");check(resumeHandle(ordinary)==1,"NT suspend count changed");
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
        exitReaderRun=true;
        exitReader=new Thread(() -> {
            try {while(exitReaderRun){Thread.getAllStackTraces();Thread.yield();}}
            catch(Throwable error){exitReaderFailure=error;}
        },"Secret-check-exit-enumerator");
        exitReader.setDaemon(true);exitReader.start();
        try {SecretNative.shutdown();throw new AssertionError("Unauthorized shutdown accepted");}
        catch(IllegalStateException expected){check(rootCause(expected) instanceof SecurityException,"Wrong shutdown admission refusal");}
        check(SecretNative.isLoaded(),"Unauthorized shutdown disarmed runtime");
        System.out.println("HOST_SHUTDOWN_REFUSAL_PASS concurrent_enumeration_runtime_retained");
    }
    public static void main(String[] args) throws Exception {
        if(args.length>0&&args[0].equals("--attach-helper")){attachHelper(args);return;}
        Path archive=Path.of(args[0]).toAbsolutePath(),directory=Path.of(args[1]).toAbsolutePath();
        Path probeDll=Path.of(args[2]).toAbsolutePath();prepareHostPolicy(directory,probeDll);
        Path ready=directory.resolve("attach.ready"),done=directory.resolve("attach.done");java.nio.file.Files.deleteIfExists(ready);java.nio.file.Files.deleteIfExists(done);
        Process attach=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java.exe").toString(),"--add-modules=jdk.attach","-cp",System.getProperty("java.class.path"),NativeStartupCheck.class.getName(),"--attach-helper",Long.toString(ProcessHandle.current().pid()),ready.toString(),done.toString()).inheritIO().start();
        System.load(probeDll.toString());installFailureProbe();
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
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    try {
                        long limit=System.nanoTime()+8_000_000_000L;
                        while(SecretNative.isLoaded()&&System.nanoTime()<limit)Thread.sleep(10);
                        exitReaderRun=false;if(exitReader!=null)exitReader.join(3000);
                        boolean ok=allChecksPassed&&!SecretNative.isLoaded()&&exitReaderFailure==null&&(exitReader==null||!exitReader.isAlive());java.nio.file.Files.writeString(directory.resolve("exit.ok"),ok?"PASS":"FAIL");
                        if(ok)System.out.println("NATIVE_STARTUP_EXIT_PASS actual_JVM_shutdown_hook NO_GAME");
                    } catch(Throwable error){error.printStackTrace();}
                },"Secret-check-natural-exit"));
                java.nio.file.Files.writeString(ready,"ready");
                check(attach.waitFor(6,java.util.concurrent.TimeUnit.SECONDS)&&attach.exitValue()==0&&java.nio.file.Files.readString(done).equals("PASS"),"External Attach did not fail promptly");
                verifyHostPolicy();
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
                verifyCleanupTasks();
                verifyCallbackPublication();
                verifyThreadGuards();
                verifyEnvironmentChain(directory);
                System.out.println("NATIVE_STARTUP_PASS two_loaders source_shield external_agent_isolated bridge="+bridge.getName());
            } finally {
                if(attach.isAlive()&&!java.nio.file.Files.exists(ready)){attach.destroy();attach.waitFor(3,java.util.concurrent.TimeUnit.SECONDS);}
                shutdownWhileEnumerating();
            }
        }
        check(SecretNative.isLoaded(),"Production runtime stopped before actual JVM shutdown");
        allChecksPassed=true;
        System.out.println("NATIVE_STARTUP_AWAIT_NATURAL_EXIT NO_GAME");
    }
}
