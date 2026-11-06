package com.himitsu.secret.util;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;

public final class DynamicMethodLookup {
    private DynamicMethodLookup() {
    }

    public static Method findStatic(Class<?> owner, Class<?> returnType, Class<?>... parameterTypes) {
        return find(owner, true, returnType, parameterTypes);
    }

    public static Method findInstance(Class<?> owner, Class<?> returnType, Class<?>... parameterTypes) {
        return find(owner, false, returnType, parameterTypes);
    }

    private static Method find(
        Class<?> owner,
        boolean requireStatic,
        Class<?> returnType,
        Class<?>... parameterTypes
    ) {
        Method match = null;
        for (Method method : owner.getDeclaredMethods()) {
            if (Modifier.isStatic(method.getModifiers()) != requireStatic
                || method.getReturnType() != returnType
                || !Arrays.equals(method.getParameterTypes(), parameterTypes)) {
                continue;
            }
            if (match != null) {
                throw new IllegalStateException("Ambiguous callback descriptor in " + owner.getName());
            }
            match = method;
        }
        if (match == null) {
            throw new IllegalStateException("Callback descriptor not found in " + owner.getName());
        }
        return match;
    }
}
