package com.himitsu.secret.hook;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.objectweb.asm.Type;

public final class HookDefinition implements Comparable<HookDefinition> {
    private final String targetClass;
    private final String targetMethod;
    private final Set<String> targetMethods;
    private final String targetDescriptor;
    private final HookMode mode;
    private final boolean includeThis;
    private final boolean includeSubclasses;
    private final boolean includeResult;
    private final int order;
    private final String callbackOwner;
    private final String callbackName;
    private final String callbackDescriptor;

    private HookDefinition(AsmHook annotation, Method callback) {
        this.targetClass = normalizeClassName(annotation.targetClass());
        this.targetMethod = requireText(annotation.targetMethod(), "target method");
        this.targetMethods = Stream.concat(
                Stream.of(this.targetMethod),
                java.util.Arrays.stream(annotation.targetAliases())
                    .map(alias -> requireText(alias, "target alias"))
            )
            .collect(Collectors.toUnmodifiableSet());
        this.targetDescriptor = requireMethodDescriptor(annotation.targetDescriptor());
        this.mode = Objects.requireNonNull(annotation.mode(), "mode");
        this.includeThis = annotation.includeThis();
        this.includeSubclasses = annotation.includeSubclasses();
        this.order = annotation.order();
        this.callbackOwner = Type.getInternalName(callback.getDeclaringClass());
        this.callbackName = callback.getName();
        this.callbackDescriptor = Type.getMethodDescriptor(callback);
        this.includeResult = detectResultArgument();

        validateCallback(callback);
    }

    public static HookDefinition from(AsmHook annotation, Method callback) {
        Objects.requireNonNull(annotation, "annotation");
        Objects.requireNonNull(callback, "callback");
        return new HookDefinition(annotation, callback);
    }

    public static HookDefinition override(
        String targetClass,
        String targetMethod,
        String targetDescriptor,
        boolean includeThis,
        String callbackOwner,
        String callbackName,
        String callbackDescriptor
    ) {
        return new HookDefinition(
            targetClass,
            targetMethod,
            targetDescriptor,
            includeThis,
            callbackOwner,
            callbackName,
            callbackDescriptor
        );
    }

    private HookDefinition(
        String targetClass,
        String targetMethod,
        String targetDescriptor,
        boolean includeThis,
        String callbackOwner,
        String callbackName,
        String callbackDescriptor
    ) {
        this.targetClass = normalizeClassName(targetClass);
        this.targetMethod = requireText(targetMethod, "target method");
        this.targetMethods = Set.of(this.targetMethod);
        this.targetDescriptor = requireMethodDescriptor(targetDescriptor);
        this.mode = HookMode.OVERRIDE;
        this.includeThis = includeThis;
        this.includeSubclasses = false;
        this.includeResult = false;
        this.order = 0;
        this.callbackOwner = normalizeClassName(callbackOwner);
        this.callbackName = requireText(callbackName, "callback method");
        this.callbackDescriptor = requireMethodDescriptor(callbackDescriptor);

        Type targetType = Type.getMethodType(this.targetDescriptor);
        Type callbackType = Type.getMethodType(this.callbackDescriptor);
        Type[] targetArguments = targetType.getArgumentTypes();
        Type[] callbackArguments = callbackType.getArgumentTypes();
        int offset = includeThis ? 1 : 0;
        if (callbackArguments.length != targetArguments.length + offset
            || (includeThis && !callbackArguments[0].equals(Type.getObjectType(this.targetClass)))
            || !java.util.Arrays.equals(
                targetArguments,
                java.util.Arrays.copyOfRange(callbackArguments, offset, callbackArguments.length)
            )
            || !callbackType.getReturnType().equals(targetType.getReturnType())) {
            throw new IllegalArgumentException("Override callback must match target descriptor");
        }
    }

    private void validateCallback(Method callback) {
        if (!Modifier.isPublic(callback.getModifiers()) || !Modifier.isStatic(callback.getModifiers())) {
            throw new IllegalArgumentException("ASM hook callback must be public static: " + callback);
        }
        if (!Modifier.isPublic(callback.getDeclaringClass().getModifiers())) {
            throw new IllegalArgumentException("ASM hook callback class must be public: " + callback.getDeclaringClass());
        }
        if (targetMethod.equals("<init>") || targetMethod.equals("<clinit>")) {
            throw new IllegalArgumentException("Constructor hooks are not supported: " + targetClass + '.' + targetMethod);
        }

        Type targetType = Type.getMethodType(targetDescriptor);
        Type callbackType = Type.getMethodType(callbackDescriptor);
        Type[] targetArguments = targetType.getArgumentTypes();
        Type[] callbackArguments = callbackType.getArgumentTypes();
        if (mode == HookMode.CLEAR) {
            if (callbackArguments.length != 0 || callbackType.getReturnType().getSort() != Type.VOID) {
                throw new IllegalArgumentException("CLEAR marker callback must have signature ()V: " + callback);
            }
            return;
        }
        int offset = includeThis ? 1 : 0;
        int baseArguments = targetArguments.length + offset;
        boolean validScopeArgument = mode == HookMode.SCOPE
            && callbackArguments.length == baseArguments + 1
            && callbackArguments[baseArguments].equals(Type.BOOLEAN_TYPE)
            && callbackType.getReturnType().equals(Type.VOID_TYPE);
        boolean validResultArgument = isReturnMode()
            && targetType.getReturnType().getSort() != Type.VOID
            && callbackArguments.length == baseArguments + 1
            && callbackArguments[callbackArguments.length - 1].equals(targetType.getReturnType());
        if ((callbackArguments.length != baseArguments && !validResultArgument && !validScopeArgument)
            || (includeThis && !callbackArguments[0].equals(Type.getObjectType(targetClass)))
            || !java.util.Arrays.equals(
                targetArguments,
                java.util.Arrays.copyOfRange(callbackArguments, offset, offset + targetArguments.length)
            )) {
            throw new IllegalArgumentException("Hook arguments must match target arguments and optional return value: " + callback);
        }

        if (mode == HookMode.SCOPE && !validScopeArgument) throw new IllegalArgumentException("SCOPE requires trailing boolean and void return");
        Type callbackReturn = callbackType.getReturnType();
        Type targetReturn = targetType.getReturnType();
        if (mode == HookMode.OVERRIDE && !callbackReturn.equals(targetReturn)) {
            throw new IllegalArgumentException("OVERRIDE hook return type must match target: " + callback);
        }
        if ((isHeadMode() || isReturnMode())
            && callbackReturn.getSort() != Type.VOID
            && !callbackReturn.equals(Type.getType(HookResult.class))) {
            throw new IllegalArgumentException(mode + " hook must return void or HookResult: " + callback);
        }
        if (mode == HookMode.GUARD && callbackReturn.getSort() != Type.BOOLEAN) {
            throw new IllegalArgumentException("GUARD hook requires a boolean callback: " + callback);
        }
    }

    private static String normalizeClassName(String name) {
        return requireText(name, "target class").replace('.', '/');
    }

    private static String requireText(String value, String label) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(label + " cannot be empty");
        }
        return value.trim();
    }

    private static String requireMethodDescriptor(String descriptor) {
        String value = requireText(descriptor, "target descriptor");
        try {
            Type.getMethodType(value);
            return value;
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Invalid target method descriptor: " + value, exception);
        }
    }

    public String targetClass() {
        return targetClass;
    }

    public String targetMethod() {
        return targetMethod;
    }

    public Set<String> targetMethods() {
        return targetMethods;
    }

    public String targetDescriptor() {
        return targetDescriptor;
    }

    public HookMode mode() {
        return mode;
    }

    public boolean includeThis() {
        return includeThis;
    }

    public boolean includeSubclasses() {
        return includeSubclasses;
    }

    public boolean cancellable() {
        return Type.getReturnType(callbackDescriptor).equals(Type.getType(HookResult.class));
    }

    public boolean includeResult() {
        return includeResult;
    }

    private boolean detectResultArgument() {
        Type targetType = Type.getMethodType(targetDescriptor);
        Type callbackType = Type.getMethodType(callbackDescriptor);
        return isReturnMode()
            && targetType.getReturnType().getSort() != Type.VOID
            && callbackType.getArgumentTypes().length == targetType.getArgumentTypes().length + (includeThis ? 2 : 1);
    }

    public boolean isHeadMode() {
        return mode == HookMode.HEAD || mode == HookMode.INSERT;
    }

    public boolean isReturnMode() {
        return mode == HookMode.RETURN || mode == HookMode.APPEND;
    }

    public String callbackOwner() {
        return callbackOwner;
    }

    public String callbackName() {
        return callbackName;
    }

    public String callbackDescriptor() {
        return callbackDescriptor;
    }

    @Override
    public int compareTo(HookDefinition other) {
        int byOrder = Integer.compare(order, other.order);
        if (byOrder != 0) {
            return byOrder;
        }
        int byOwner = callbackOwner.compareTo(other.callbackOwner);
        return byOwner != 0 ? byOwner : callbackName.compareTo(other.callbackName);
    }
}
