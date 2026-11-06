package dev.nekoobfuscator.native_.stage;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.jar.ResourceEntry;
import dev.nekoobfuscator.native_.codegen.NativeBuildEngine;
import dev.nekoobfuscator.native_.resource.ResourceEncryptor;
import dev.nekoobfuscator.native_.translator.NativeTranslationSafetyChecker;
import dev.nekoobfuscator.native_.translator.NativeTranslator;
import dev.nekoobfuscator.native_.translator.NativeTranslator.MethodSelection;
import dev.nekoobfuscator.native_.translator.NativeTranslator.NativeMethodBinding;
import dev.nekoobfuscator.native_.translator.NativeTranslator.TranslationResult;
import org.objectweb.asm.Handle;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Compiles selected JVM methods into JNI libraries and rewrites classes to native stubs.
 */
public final class NativeCompilationStage {
    private static final Logger log = LoggerFactory.getLogger(NativeCompilationStage.class);
    private static final String NATIVE_TRANSLATE_DESC = "Ldev/nekoobfuscator/api/annotation/NativeTranslate;";
    private static final String NATIVE_LOADER_OWNER = "dev/nekoobfuscator/runtime/NekoNativeLoader";
    private static final String NATIVE_LOAD_NAME = "load";
    private static final String NATIVE_LOAD_DESC = "()V";
    private static final String LINKAGE_ERROR_INTERNAL = "java/lang/LinkageError";
    private static final String LINKAGE_ERROR_INIT_DESC = "(Ljava/lang/String;)V";
    private static final String LINKAGE_ERROR_MESSAGE = "please check your native library load correctly";

    private final ObfuscationConfig.NativeConfig cfg;
    private final long masterSeed;
    private final NativeTranslationSafetyChecker safetyChecker = new NativeTranslationSafetyChecker();
    private int lambdaClassCounter = 0;

    public NativeCompilationStage(ObfuscationConfig.NativeConfig cfg, long masterSeed) {
        this.cfg = cfg;
        this.masterSeed = masterSeed;
    }

    public NativeStageResult apply(Map<String, byte[]> allClasses, List<ResourceEntry> resources) {
        Map<String, byte[]> originalClasses = new LinkedHashMap<>(allClasses);
        List<ResourceEntry> originalResources = new ArrayList<>(resources);

        Map<String, ParsedClass> parsedClasses = parseClasses(allClasses);
        Set<String> generatedClasses = lowerSupportedInvokeDynamics(parsedClasses);
        Map<String, MethodSelection> manifestableMethods = manifestableMethods(parsedClasses);
        List<MethodSelection> candidateMethods = new ArrayList<>();
        List<MethodSelection> selectedMethods = new ArrayList<>();
        Map<String, List<String>> rejectionReasons = new LinkedHashMap<>();
        Set<String> queuedCandidates = new LinkedHashSet<>();

        for (ParsedClass parsedClass : parsedClasses.values()) {
            if (parsedClass.l1Class().isInterface()) {
                continue;
            }
            boolean classAnnotated = hasAnnotation(parsedClass.l1Class().asmNode().visibleAnnotations)
                || hasAnnotation(parsedClass.l1Class().asmNode().invisibleAnnotations);

            for (L1Method method : parsedClass.l1Class().methods()) {
                if (!shouldTranslate(method, parsedClass.l1Class().name(), classAnnotated)) {
                    continue;
                }
                if (method.isConstructor() || method.isClassInit() || method.isAbstract() || method.isNative() || method.isBridge()) {
                    continue;
                }
                MethodSelection selection = new MethodSelection(parsedClass.l1Class(), method);
                addCandidate(selection, candidateMethods, queuedCandidates);
            }
        }
        closeOverApplicationCallees(candidateMethods, queuedCandidates, manifestableMethods);

        Set<String> applicationMethodKeys = manifestableMethods.keySet();
        Set<String> selectedMethodKeys = methodKeys(candidateMethods);
        boolean changed;
        do {
            changed = false;
            selectedMethods.clear();
            rejectionReasons.clear();
            for (MethodSelection selection : candidateMethods) {
                List<String> reasons = new ArrayList<>();
                if (!safetyChecker.isSafe(selection.method(), reasons, applicationMethodKeys, selectedMethodKeys)) {
                    rejectionReasons.put(methodKey(selection), reasons);
                    continue;
                }
                selectedMethods.add(selection);
            }
            Set<String> nextKeys = methodKeys(selectedMethods);
            if (!nextKeys.equals(selectedMethodKeys)) {
                selectedMethodKeys = nextKeys;
                changed = true;
            }
        } while (changed);

        int rejectedMethodCount = rejectionReasons.size();
        if (!rejectionReasons.isEmpty()) {
            for (Map.Entry<String, List<String>> entry : rejectionReasons.entrySet()) {
                log.warn("Rejected native translation for {}: {}", entry.getKey(), String.join("; ", entry.getValue()));
            }
            if (!cfg.skipOnError()) {
                throw new IllegalStateException("Unsafe native translation target: " + rejectionReasons.keySet().iterator().next());
            }
        }

        if (selectedMethods.isEmpty()) {
            log.info("Native stage selected no methods");
            return new NativeStageResult(originalClasses, originalResources, 0, rejectedMethodCount);
        }

        TranslationResult translationResult;
        try {
            translationResult = new NativeTranslator(cfg.outputPrefix(), cfg.obfuscateJniSlotDispatch(), cfg.cacheJniIds(), masterSeed)
                .translate(selectedMethods, parsedClasses.values().stream().map(ParsedClass::l1Class).toList());
        } catch (RuntimeException ex) {
            if (cfg.skipOnError()) {
                log.error("Native translation failed; continuing without native stage", ex);
                return new NativeStageResult(originalClasses, originalResources, 0, rejectedMethodCount + selectedMethods.size());
            }
            throw ex;
        }

        Map<String, byte[]> builtLibraries;
        try {
            builtLibraries = new NativeBuildEngine(cfg.zigPath()).build(
                translationResult.sourceSet(),
                translationResult.header(),
                cfg.targets()
            );
        } catch (Exception ex) {
            if (cfg.skipOnError()) {
                log.error("Native compilation failed; continuing without native stage", ex);
                return new NativeStageResult(originalClasses, originalResources, 0, rejectedMethodCount + selectedMethods.size());
            }
            throw new RuntimeException("Native compilation failed", ex);
        }

        if (builtLibraries.isEmpty()) {
            String message = "Native compilation produced no libraries";
            if (cfg.skipOnError()) {
                log.error(message);
                return new NativeStageResult(originalClasses, originalResources, 0, rejectedMethodCount + selectedMethods.size());
            }
            throw new IllegalStateException(message);
        }

        List<String> modifiedClasses = rewriteClasses(parsedClasses, translationResult.bindings());

        Map<String, byte[]> mutatedClasses = new LinkedHashMap<>(originalClasses);
        for (String className : generatedClasses) {
            ParsedClass parsedClass = parsedClasses.get(className);
            mutatedClasses.put(className, writeClass(parsedClass.classNode()));
        }
        for (String className : modifiedClasses) {
            ParsedClass parsedClass = parsedClasses.get(className);
            mutatedClasses.put(className, writeClass(parsedClass.classNode()));
        }

        List<ResourceEntry> updatedResources = new ArrayList<>(resources);
        for (Map.Entry<String, byte[]> entry : builtLibraries.entrySet()) {
            updatedResources.add(new ResourceEntry(entry.getKey(), entry.getValue()));
        }
        if (cfg.resourceEncryption()) {
            updatedResources = new ResourceEncryptor(masterSeed).encryptResources(updatedResources);
        }

        if (!rejectionReasons.isEmpty()) {
            log.info("Native stage rejected {} method(s)", rejectionReasons.size());
        }
        return new NativeStageResult(mutatedClasses, updatedResources, translationResult.methodCount(), rejectedMethodCount);
    }

    private Map<String, ParsedClass> parseClasses(Map<String, byte[]> allClasses) {
        Map<String, ParsedClass> parsed = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : allClasses.entrySet()) {
            ClassReader reader = new ClassReader(entry.getValue());
            ClassNode classNode = new ClassNode();
            reader.accept(classNode, ClassReader.EXPAND_FRAMES);
            parsed.put(classNode.name, new ParsedClass(classNode, new L1Class(classNode)));
        }
        return parsed;
    }

    private Set<String> lowerSupportedInvokeDynamics(Map<String, ParsedClass> parsedClasses) {
        Set<String> generatedClasses = new LinkedHashSet<>();
        List<ParsedClass> initialClasses = new ArrayList<>(parsedClasses.values());
        for (ParsedClass parsedClass : initialClasses) {
            ClassNode owner = parsedClass.classNode();
            for (MethodNode method : owner.methods) {
                for (var insn = method.instructions.getFirst(); insn != null; ) {
                    var next = insn.getNext();
                    if (insn instanceof InvokeDynamicInsnNode indy) {
                        if (isLambdaMetafactory(indy)) {
                            String lambdaClass = lowerLambdaMetafactory(owner, method, indy, parsedClasses);
                            generatedClasses.add(lambdaClass);
                        } else if (isObjectMethodsBootstrap(indy)) {
                            lowerObjectMethods(method, indy);
                        }
                    }
                    insn = next;
                }
            }
        }
        return generatedClasses;
    }

    private boolean isLambdaMetafactory(InvokeDynamicInsnNode indy) {
        return "java/lang/invoke/LambdaMetafactory".equals(indy.bsm.getOwner())
            && "metafactory".equals(indy.bsm.getName())
            && indy.bsmArgs.length >= 3
            && indy.bsmArgs[0] instanceof Type
            && indy.bsmArgs[1] instanceof Handle
            && indy.bsmArgs[2] instanceof Type;
    }

    private boolean isObjectMethodsBootstrap(InvokeDynamicInsnNode indy) {
        return "java/lang/runtime/ObjectMethods".equals(indy.bsm.getOwner())
            && "bootstrap".equals(indy.bsm.getName())
            && indy.bsmArgs.length >= 2
            && indy.bsmArgs[0] instanceof Type
            && indy.bsmArgs[1] instanceof String;
    }

    private String lowerLambdaMetafactory(
        ClassNode owner,
        MethodNode method,
        InvokeDynamicInsnNode indy,
        Map<String, ParsedClass> parsedClasses
    ) {
        Type factoryType = Type.getReturnType(indy.desc);
        Type[] capturedTypes = Type.getArgumentTypes(indy.desc);
        Type samType = (Type) indy.bsmArgs[0];
        Handle impl = (Handle) indy.bsmArgs[1];
        Type instantiatedType = (Type) indy.bsmArgs[2];
        String lambdaName = owner.name + "$NekoLambda$" + (++lambdaClassCounter);
        ClassNode lambdaClass = createLambdaClass(owner, lambdaName, factoryType, capturedTypes, indy.name, samType, instantiatedType, impl);
        parsedClasses.put(lambdaName, new ParsedClass(lambdaClass, new L1Class(lambdaClass)));

        int nextLocal = method.maxLocals;
        int[] locals = new int[capturedTypes.length];
        InsnList replacement = new InsnList();
        for (int i = capturedTypes.length - 1; i >= 0; i--) {
            locals[i] = nextLocal;
            nextLocal += capturedTypes[i].getSize();
            replacement.add(new VarInsnNode(capturedTypes[i].getOpcode(Opcodes.ISTORE), locals[i]));
        }
        replacement.add(new TypeInsnNode(Opcodes.NEW, lambdaName));
        replacement.add(new InsnNode(Opcodes.DUP));
        for (int i = 0; i < capturedTypes.length; i++) {
            replacement.add(new VarInsnNode(capturedTypes[i].getOpcode(Opcodes.ILOAD), locals[i]));
        }
        replacement.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, lambdaName, "<init>", Type.getMethodDescriptor(Type.VOID_TYPE, capturedTypes), false));
        method.instructions.insert(indy, replacement);
        method.instructions.remove(indy);
        method.maxLocals = Math.max(method.maxLocals, nextLocal);
        method.maxStack = Math.max(method.maxStack, 8 + capturedTypes.length * 2);
        return lambdaName;
    }

    private ClassNode createLambdaClass(
        ClassNode owner,
        String lambdaName,
        Type factoryType,
        Type[] capturedTypes,
        String samName,
        Type samType,
        Type instantiatedType,
        Handle impl
    ) {
        ClassNode lambdaClass = new ClassNode();
        lambdaClass.version = owner.version;
        lambdaClass.access = Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        lambdaClass.name = lambdaName;
        lambdaClass.superName = "java/lang/Object";
        lambdaClass.outerClass = owner.name;
        lambdaClass.interfaces = new ArrayList<>();
        lambdaClass.interfaces.add(factoryType.getInternalName());
        lambdaClass.fields = new ArrayList<>();
        lambdaClass.methods = new ArrayList<>();

        for (int i = 0; i < capturedTypes.length; i++) {
            lambdaClass.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
                "arg$" + i, capturedTypes[i].getDescriptor(), null, null));
        }
        lambdaClass.methods.add(lambdaConstructor(lambdaName, capturedTypes));
        lambdaClass.methods.add(lambdaSamMethod(lambdaName, capturedTypes, samName, samType, instantiatedType, impl));
        return lambdaClass;
    }

    private MethodNode lambdaConstructor(String lambdaName, Type[] capturedTypes) {
        MethodNode ctor = new MethodNode(Opcodes.ACC_SYNTHETIC, "<init>",
            Type.getMethodDescriptor(Type.VOID_TYPE, capturedTypes), null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        int local = 1;
        for (int i = 0; i < capturedTypes.length; i++) {
            ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            ctor.instructions.add(new VarInsnNode(capturedTypes[i].getOpcode(Opcodes.ILOAD), local));
            ctor.instructions.add(new FieldInsnNode(Opcodes.PUTFIELD, lambdaName, "arg$" + i, capturedTypes[i].getDescriptor()));
            local += capturedTypes[i].getSize();
        }
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxLocals = local;
        ctor.maxStack = 4;
        return ctor;
    }

    private MethodNode lambdaSamMethod(
        String lambdaName,
        Type[] capturedTypes,
        String samName,
        Type samType,
        Type instantiatedType,
        Handle impl
    ) {
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
            samName, samType.getDescriptor(), null, null);
        Type[] samArgs = Type.getArgumentTypes(samType.getDescriptor());
        Type[] instantiatedArgs = Type.getArgumentTypes(instantiatedType.getDescriptor());
        Type[] invocationTypes = lambdaInvocationInputTypes(impl);
        int valueCount = capturedTypes.length + samArgs.length;
        if (invocationTypes.length != valueCount) {
            invocationTypes = new Type[valueCount];
            int p = 0;
            for (Type capturedType : capturedTypes) invocationTypes[p++] = capturedType;
            for (Type instantiatedArg : instantiatedArgs) invocationTypes[p++] = instantiatedArg;
        }

        if (impl.getTag() == Opcodes.H_NEWINVOKESPECIAL) {
            method.instructions.add(new TypeInsnNode(Opcodes.NEW, impl.getOwner()));
            method.instructions.add(new InsnNode(Opcodes.DUP));
        }

        int valueIndex = 0;
        for (int i = 0; i < capturedTypes.length; i++) {
            method.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            method.instructions.add(new FieldInsnNode(Opcodes.GETFIELD, lambdaName, "arg$" + i, capturedTypes[i].getDescriptor()));
            adaptStackValue(method.instructions, capturedTypes[i], invocationTypes[valueIndex++]);
        }
        int local = 1;
        for (int i = 0; i < samArgs.length; i++) {
            Type source = samArgs[i];
            Type target = valueIndex < invocationTypes.length ? invocationTypes[valueIndex++] : source;
            method.instructions.add(new VarInsnNode(source.getOpcode(Opcodes.ILOAD), local));
            adaptStackValue(method.instructions, source, target);
            local += source.getSize();
        }

        emitLambdaImplInvoke(method.instructions, impl);
        Type implReturn = impl.getTag() == Opcodes.H_NEWINVOKESPECIAL ? Type.getObjectType(impl.getOwner()) : Type.getReturnType(impl.getDesc());
        Type samReturn = Type.getReturnType(samType.getDescriptor());
        adaptReturnValue(method.instructions, implReturn, samReturn);
        method.maxLocals = local;
        method.maxStack = Math.max(8, 6 + valueCount * 2);
        return method;
    }

    private Type[] lambdaInvocationInputTypes(Handle impl) {
        Type[] methodArgs = Type.getArgumentTypes(impl.getDesc());
        if (impl.getTag() == Opcodes.H_INVOKESTATIC || impl.getTag() == Opcodes.H_NEWINVOKESPECIAL) {
            return methodArgs;
        }
        Type[] withReceiver = new Type[methodArgs.length + 1];
        withReceiver[0] = Type.getObjectType(impl.getOwner());
        System.arraycopy(methodArgs, 0, withReceiver, 1, methodArgs.length);
        return withReceiver;
    }

    private void emitLambdaImplInvoke(InsnList out, Handle impl) {
        switch (impl.getTag()) {
            case Opcodes.H_INVOKESTATIC -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, impl.getOwner(), impl.getName(), impl.getDesc(), impl.isInterface()));
            case Opcodes.H_INVOKEVIRTUAL -> out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, impl.getOwner(), impl.getName(), impl.getDesc(), false));
            case Opcodes.H_INVOKEINTERFACE -> out.add(new MethodInsnNode(Opcodes.INVOKEINTERFACE, impl.getOwner(), impl.getName(), impl.getDesc(), true));
            case Opcodes.H_INVOKESPECIAL -> out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, impl.getOwner(), impl.getName(), impl.getDesc(), impl.isInterface()));
            case Opcodes.H_NEWINVOKESPECIAL -> out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, impl.getOwner(), "<init>", impl.getDesc(), false));
            default -> throw new IllegalStateException("Unsupported LambdaMetafactory handle tag: " + impl.getTag());
        }
    }

    private void adaptStackValue(InsnList out, Type source, Type target) {
        if (source.equals(target)) {
            return;
        }
        if (source.getSort() == Type.OBJECT && target.getSort() == Type.OBJECT) {
            if ("java/lang/Object".equals(target.getInternalName())) {
                return;
            }
            out.add(new TypeInsnNode(Opcodes.CHECKCAST, target.getInternalName()));
        } else if (source.getSort() == Type.OBJECT && target.getSort() != Type.OBJECT && target.getSort() != Type.ARRAY) {
            emitUnbox(out, target);
        } else if (source.getSort() != Type.OBJECT && source.getSort() != Type.ARRAY && target.getSort() == Type.OBJECT) {
            emitBox(out, source);
        }
    }

    private void adaptReturnValue(InsnList out, Type source, Type target) {
        if (target.getSort() == Type.VOID) {
            if (source.getSort() == Type.LONG || source.getSort() == Type.DOUBLE) {
                out.add(new InsnNode(Opcodes.POP2));
            } else if (source.getSort() != Type.VOID) {
                out.add(new InsnNode(Opcodes.POP));
            }
            out.add(new InsnNode(Opcodes.RETURN));
            return;
        }
        adaptStackValue(out, source, target);
        out.add(new InsnNode(target.getOpcode(Opcodes.IRETURN)));
    }

    private void emitBox(InsnList out, Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false));
            case Type.CHAR -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false));
            case Type.BYTE -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false));
            case Type.SHORT -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false));
            case Type.INT -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
            case Type.FLOAT -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false));
            case Type.LONG -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false));
            case Type.DOUBLE -> out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false));
            default -> {
            }
        }
    }

    private void emitUnbox(InsnList out, Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Boolean"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean", "booleanValue", "()Z", false));
            }
            case Type.CHAR -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Character"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Character", "charValue", "()C", false));
            }
            case Type.BYTE -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Byte"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Byte", "byteValue", "()B", false));
            }
            case Type.SHORT -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Short"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Short", "shortValue", "()S", false));
            }
            case Type.INT -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false));
            }
            case Type.FLOAT -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Float"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Float", "floatValue", "()F", false));
            }
            case Type.LONG -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false));
            }
            case Type.DOUBLE -> {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Double"));
                out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Double", "doubleValue", "()D", false));
            }
            default -> {
            }
        }
    }

    private void lowerObjectMethods(MethodNode method, InvokeDynamicInsnNode indy) {
        Type recordType = (Type) indy.bsmArgs[0];
        String[] names = ((String) indy.bsmArgs[1]).isEmpty() ? new String[0] : ((String) indy.bsmArgs[1]).split(";");
        Object[] rawHandles = new Object[indy.bsmArgs.length - 2];
        System.arraycopy(indy.bsmArgs, 2, rawHandles, 0, rawHandles.length);
        Handle[] fields = new Handle[rawHandles.length];
        for (int i = 0; i < rawHandles.length; i++) {
            if (!(rawHandles[i] instanceof Handle handle)) {
                throw new IllegalStateException("Unsupported ObjectMethods field handle: " + rawHandles[i]);
            }
            fields[i] = handle;
        }

        Type[] args = Type.getArgumentTypes(indy.desc);
        int nextLocal = method.maxLocals;
        int[] locals = new int[args.length];
        InsnList replacement = new InsnList();
        for (int i = args.length - 1; i >= 0; i--) {
            locals[i] = nextLocal;
            nextLocal += args[i].getSize();
            replacement.add(new VarInsnNode(args[i].getOpcode(Opcodes.ISTORE), locals[i]));
        }
        switch (indy.name) {
            case "toString" -> emitObjectMethodsToString(replacement, recordType, names, fields, locals[0]);
            case "hashCode" -> emitObjectMethodsHashCode(replacement, fields, locals[0]);
            case "equals" -> emitObjectMethodsEquals(replacement, recordType, fields, locals[0], locals[1], nextLocal);
            default -> throw new IllegalStateException("Unsupported ObjectMethods operation: " + indy.name);
        }
        method.instructions.insert(indy, replacement);
        method.instructions.remove(indy);
        method.maxLocals = Math.max(method.maxLocals, nextLocal + 1);
        method.maxStack = Math.max(method.maxStack, 12 + fields.length * 3);
    }

    private void emitObjectMethodsToString(InsnList out, Type recordType, String[] names, Handle[] fields, int selfLocal) {
        String simpleName = recordType.getInternalName();
        int slash = simpleName.lastIndexOf('/');
        if (slash >= 0) {
            simpleName = simpleName.substring(slash + 1);
        }
        int dollar = simpleName.lastIndexOf('$');
        if (dollar >= 0) {
            simpleName = simpleName.substring(dollar + 1);
        }
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new LdcInsnNode(simpleName + "["));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false));
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                emitStringBuilderAppendString(out, ", ");
            }
            emitStringBuilderAppendString(out, i < names.length ? names[i] + "=" : "arg" + i + "=");
            emitLoadObjectMethodField(out, selfLocal, fields[i]);
            emitStringBuilderAppendValue(out, Type.getType(fields[i].getDesc()));
        }
        emitStringBuilderAppendString(out, "]");
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false));
    }

    private void emitStringBuilderAppendString(InsnList out, String value) {
        out.add(new LdcInsnNode(value));
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
    }

    private void emitStringBuilderAppendValue(InsnList out, Type type) {
        String desc = switch (type.getSort()) {
            case Type.BOOLEAN -> "(Z)Ljava/lang/StringBuilder;";
            case Type.CHAR -> "(C)Ljava/lang/StringBuilder;";
            case Type.BYTE, Type.SHORT, Type.INT -> "(I)Ljava/lang/StringBuilder;";
            case Type.FLOAT -> "(F)Ljava/lang/StringBuilder;";
            case Type.LONG -> "(J)Ljava/lang/StringBuilder;";
            case Type.DOUBLE -> "(D)Ljava/lang/StringBuilder;";
            default -> "(Ljava/lang/Object;)Ljava/lang/StringBuilder;";
        };
        out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", desc, false));
    }

    private void emitObjectMethodsHashCode(InsnList out, Handle[] fields, int selfLocal) {
        emitPushInt(out, fields.length);
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        for (int i = 0; i < fields.length; i++) {
            out.add(new InsnNode(Opcodes.DUP));
            emitPushInt(out, i);
            Type fieldType = Type.getType(fields[i].getDesc());
            emitLoadObjectMethodField(out, selfLocal, fields[i]);
            if (fieldType.getSort() != Type.OBJECT && fieldType.getSort() != Type.ARRAY) {
                emitBox(out, fieldType);
            }
            out.add(new InsnNode(Opcodes.AASTORE));
        }
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Objects", "hash", "([Ljava/lang/Object;)I", false));
    }

    private void emitObjectMethodsEquals(InsnList out, Type recordType, Handle[] fields, int selfLocal, int otherLocal, int castLocal) {
        LabelNode trueLabel = new LabelNode();
        LabelNode falseLabel = new LabelNode();
        LabelNode endLabel = new LabelNode();
        out.add(new VarInsnNode(Opcodes.ALOAD, otherLocal));
        out.add(new VarInsnNode(Opcodes.ALOAD, selfLocal));
        out.add(new JumpInsnNode(Opcodes.IF_ACMPEQ, trueLabel));
        out.add(new VarInsnNode(Opcodes.ALOAD, otherLocal));
        out.add(new TypeInsnNode(Opcodes.INSTANCEOF, recordType.getInternalName()));
        out.add(new JumpInsnNode(Opcodes.IFEQ, falseLabel));
        out.add(new VarInsnNode(Opcodes.ALOAD, otherLocal));
        out.add(new TypeInsnNode(Opcodes.CHECKCAST, recordType.getInternalName()));
        out.add(new VarInsnNode(Opcodes.ASTORE, castLocal));
        for (Handle field : fields) {
            Type fieldType = Type.getType(field.getDesc());
            emitLoadObjectMethodField(out, selfLocal, field);
            emitLoadObjectMethodField(out, castLocal, field);
            emitFieldEqualityJump(out, fieldType, falseLabel);
        }
        out.add(trueLabel);
        out.add(new InsnNode(Opcodes.ICONST_1));
        out.add(new JumpInsnNode(Opcodes.GOTO, endLabel));
        out.add(falseLabel);
        out.add(new InsnNode(Opcodes.ICONST_0));
        out.add(endLabel);
    }

    private void emitFieldEqualityJump(InsnList out, Type type, LabelNode falseLabel) {
        switch (type.getSort()) {
            case Type.LONG -> {
                out.add(new InsnNode(Opcodes.LCMP));
                out.add(new JumpInsnNode(Opcodes.IFNE, falseLabel));
            }
            case Type.FLOAT -> {
                out.add(new InsnNode(Opcodes.FCMPL));
                out.add(new JumpInsnNode(Opcodes.IFNE, falseLabel));
            }
            case Type.DOUBLE -> {
                out.add(new InsnNode(Opcodes.DCMPL));
                out.add(new JumpInsnNode(Opcodes.IFNE, falseLabel));
            }
            case Type.OBJECT, Type.ARRAY -> {
                out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/util/Objects", "equals",
                    "(Ljava/lang/Object;Ljava/lang/Object;)Z", false));
                out.add(new JumpInsnNode(Opcodes.IFEQ, falseLabel));
            }
            default -> out.add(new JumpInsnNode(Opcodes.IF_ICMPNE, falseLabel));
        }
    }

    private void emitLoadObjectMethodField(InsnList out, int ownerLocal, Handle field) {
        out.add(new VarInsnNode(Opcodes.ALOAD, ownerLocal));
        if (field.getTag() == Opcodes.H_GETFIELD) {
            out.add(new FieldInsnNode(Opcodes.GETFIELD, field.getOwner(), field.getName(), field.getDesc()));
            return;
        }
        if (field.getTag() == Opcodes.H_INVOKEVIRTUAL) {
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, field.getOwner(), field.getName(), field.getDesc(), false));
            return;
        }
        throw new IllegalStateException("Unsupported ObjectMethods field handle tag: " + field.getTag());
    }

    private void emitPushInt(InsnList out, int value) {
        if (value >= -1 && value <= 5) {
            out.add(new InsnNode(Opcodes.ICONST_0 + value));
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            out.add(new IntInsnNode(Opcodes.BIPUSH, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            out.add(new IntInsnNode(Opcodes.SIPUSH, value));
        } else {
            out.add(new LdcInsnNode(value));
        }
    }

    private boolean shouldTranslate(L1Method method, String classInternalName, boolean classAnnotated) {
        if (classInternalName.startsWith("dev/nekoobfuscator/runtime/")) {
            return false;
        }
        if (cfg.includeAnnotated()) {
            if (classAnnotated || hasAnnotation(method.asmNode().visibleAnnotations) || hasAnnotation(method.asmNode().invisibleAnnotations)) {
                return true;
            }
        }

        String methodTarget = classInternalName + '#' + method.name();
        for (String pattern : cfg.excludePatterns()) {
            Pattern regex = globToPattern(pattern);
            if (pattern.contains("#")) {
                if (regex.matcher(methodTarget).matches()) {
                    return false;
                }
            } else if (regex.matcher(classInternalName).matches()) {
                return false;
            }
        }
        for (String pattern : cfg.methods()) {
            Pattern regex = globToPattern(pattern);
            if (pattern.contains("#")) {
                if (regex.matcher(methodTarget).matches()) {
                    return true;
                }
            } else if (regex.matcher(classInternalName).matches()) {
                return true;
            }
        }
        return false;
    }

    private boolean hasAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (NATIVE_TRANSLATE_DESC.equals(annotation.desc)) {
                return true;
            }
        }
        return false;
    }

    private Pattern globToPattern(String glob) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < glob.length(); i++) {
            char ch = glob.charAt(i);
            if (ch == '*') {
                boolean doubleStar = i + 1 < glob.length() && glob.charAt(i + 1) == '*';
                if (doubleStar) {
                    boolean slashAfter = i + 2 < glob.length() && glob.charAt(i + 2) == '/';
                    regex.append(slashAfter ? "(?:.*/)?" : ".*");
                    i += slashAfter ? 2 : 1;
                } else {
                    regex.append("[^#]*");
                }
            } else if ("\\.^$|?+()[]{}".indexOf(ch) >= 0) {
                regex.append('\\').append(ch);
            } else {
                regex.append(ch);
            }
        }
        regex.append('$');
        return Pattern.compile(regex.toString());
    }

    private List<String> rewriteClasses(Map<String, ParsedClass> parsedClasses, List<NativeMethodBinding> bindings) {
        Map<String, List<NativeMethodBinding>> byOwner = new HashMap<>();
        List<String> modifiedClasses = new ArrayList<>();
        for (NativeMethodBinding binding : bindings) {
            byOwner.computeIfAbsent(binding.ownerInternalName(), ignored -> new ArrayList<>()).add(binding);
        }

        for (Map.Entry<String, List<NativeMethodBinding>> entry : byOwner.entrySet()) {
            ParsedClass parsedClass = parsedClasses.get(entry.getKey());
            if (parsedClass == null) {
                continue;
            }
            modifiedClasses.add(entry.getKey());

            for (NativeMethodBinding binding : entry.getValue()) {
                MethodNode methodNode = findMethod(parsedClass.classNode(), binding.methodName(), binding.descriptor());
                if (methodNode == null) {
                    continue;
                }
                rewriteTranslatedMethod(methodNode);
            }
        }

        List<String> loaderOwners = new ArrayList<>(modifiedClasses);
        for (String owner : loaderOwners) {
            ensureClinitLoadsNative(parsedClasses.get(owner).classNode());
        }
        return modifiedClasses;
    }

    private void rewriteTranslatedMethod(MethodNode methodNode) {
        methodNode.instructions.clear();
        if (methodNode.tryCatchBlocks != null) {
            methodNode.tryCatchBlocks.clear();
        }
        if (methodNode.localVariables != null) {
            methodNode.localVariables.clear();
        }
        methodNode.visibleLocalVariableAnnotations = null;
        methodNode.invisibleLocalVariableAnnotations = null;
        methodNode.access &= ~(Opcodes.ACC_NATIVE | Opcodes.ACC_STRICT);

        InsnList body = methodNode.instructions;
        // Inflate the body above HotSpot's three inline thresholds:
        //   MaxInlineSize     = 35   (C1 trivial inliner)
        //   MaxInlineLevel    irrelevant
        //   FreqInlineSize    = 325  (C2 frequency-based inliner)
        // Each ICONST_0 + IFEQ pair is 4 bytes; 90 pairs = 360 bytes, which
        // pushes the body over FreqInlineSize so neither C1 nor C2 will
        // inline us. Control always falls through (the comparison is a
        // constant zero) so semantics are preserved. 90 pairs encode their
        // branch targets within s2 reach (jump distance 360 < 32767).
        LabelNode exitLabel = new LabelNode();
        for (int i = 0; i < 90; i++) {
            body.add(new InsnNode(Opcodes.ICONST_0));
            body.add(new JumpInsnNode(Opcodes.IFEQ, exitLabel));
        }
        body.add(exitLabel);
        body.add(new TypeInsnNode(Opcodes.NEW, LINKAGE_ERROR_INTERNAL));
        body.add(new InsnNode(Opcodes.DUP));
        body.add(new LdcInsnNode(LINKAGE_ERROR_MESSAGE));
        body.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, LINKAGE_ERROR_INTERNAL, "<init>", LINKAGE_ERROR_INIT_DESC, false));
        body.add(new InsnNode(Opcodes.ATHROW));

        methodNode.maxStack = 3;
        methodNode.maxLocals = parameterSlotCount(methodNode.access, methodNode.desc);
    }

    private int parameterSlotCount(int access, String descriptor) {
        int slots = (access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type argumentType : Type.getArgumentTypes(descriptor)) {
            slots += argumentType.getSize();
        }
        return slots;
    }

    private MethodNode findMethod(ClassNode classNode, String name, String desc) {
        for (MethodNode method : classNode.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) {
                return method;
            }
        }
        return null;
    }

    private void ensureClinitLoadsNative(ClassNode classNode) {
        MethodNode clinit = findMethod(classNode, "<clinit>", "()V");
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            appendNativeBootstrap(clinit.instructions);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            clinit.maxStack = 1;
            clinit.maxLocals = 0;
            classNode.methods.add(clinit);
            return;
        }

        if (containsNativeLoad(clinit)) {
            return;
        }
        InsnList loadCall = new InsnList();
        appendNativeBootstrap(loadCall);
        clinit.instructions.insert(loadCall);
        clinit.maxStack = Math.max(clinit.maxStack, 1);
    }

    private void appendNativeBootstrap(InsnList instructions) {
        instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, NATIVE_LOADER_OWNER, NATIVE_LOAD_NAME, NATIVE_LOAD_DESC, false));
    }

    private boolean containsNativeLoad(MethodNode clinit) {
        for (var insn = clinit.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode methodInsn
                && methodInsn.getOpcode() == Opcodes.INVOKESTATIC
                && NATIVE_LOADER_OWNER.equals(methodInsn.owner)
                && NATIVE_LOAD_NAME.equals(methodInsn.name)
                && NATIVE_LOAD_DESC.equals(methodInsn.desc)) {
                return true;
            }
        }
        return false;
    }

    private byte[] writeClass(ClassNode classNode) {
        try {
            ClassWriter writer = new ClassWriter(0);
            classNode.accept(writer);
            return writer.toByteArray();
        } catch (Throwable plainWriteError) {
            log.warn("Plain class write failed for {}; falling back to COMPUTE_MAXS: {}", classNode.name, plainWriteError.getMessage());
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
            classNode.accept(writer);
            return writer.toByteArray();
        }
    }

    private String methodKey(String owner, L1Method method) {
        return owner + '#' + method.name() + method.descriptor();
    }

    private String methodKey(MethodSelection selection) {
        return methodKey(selection.owner().name(), selection.method());
    }

    private Set<String> methodKeys(List<MethodSelection> selections) {
        Set<String> keys = new LinkedHashSet<>();
        for (MethodSelection selection : selections) {
            keys.add(methodKey(selection));
        }
        return keys;
    }

    private Map<String, MethodSelection> manifestableMethods(Map<String, ParsedClass> parsedClasses) {
        Map<String, MethodSelection> methods = new LinkedHashMap<>();
        for (ParsedClass parsedClass : parsedClasses.values()) {
            if (parsedClass.l1Class().isInterface()) {
                continue;
            }
            for (L1Method method : parsedClass.l1Class().methods()) {
                if (method.isConstructor() || method.isClassInit() || method.isAbstract() || method.isNative() || method.isBridge()) {
                    continue;
                }
                MethodSelection selection = new MethodSelection(parsedClass.l1Class(), method);
                methods.put(methodKey(selection), selection);
            }
        }
        return methods;
    }

    private void closeOverApplicationCallees(
        List<MethodSelection> candidateMethods,
        Set<String> queuedCandidates,
        Map<String, MethodSelection> manifestableMethods
    ) {
        for (int i = 0; i < candidateMethods.size(); i++) {
            MethodSelection selection = candidateMethods.get(i);
            for (var insn = selection.method().instructions().getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode methodInsn) {
                    MethodSelection callee = manifestableMethods.get(methodInsn.owner + '#' + methodInsn.name + methodInsn.desc);
                    if (callee != null) {
                        addCandidate(callee, candidateMethods, queuedCandidates);
                    }
                }
            }
        }
    }

    private void addCandidate(MethodSelection selection, List<MethodSelection> candidateMethods, Set<String> queuedCandidates) {
        if (queuedCandidates.add(methodKey(selection))) {
            candidateMethods.add(selection);
        }
    }

    private record ParsedClass(ClassNode classNode, L1Class l1Class) {}

    public record NativeStageResult(
        Map<String, byte[]> allClasses,
        List<ResourceEntry> resources,
        int translatedMethodCount,
        int rejectedMethodCount
    ) {}
}
