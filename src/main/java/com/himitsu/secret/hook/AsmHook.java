package com.himitsu.secret.hook;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Repeatable(AsmHooks.class)
public @interface AsmHook {
    String targetClass();

    String targetMethod();

    String[] targetAliases() default {};

    String targetDescriptor();

    HookMode mode();

    boolean includeThis() default false;

    boolean includeSubclasses() default false;

    int order() default 0;
}
