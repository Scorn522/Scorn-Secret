package com.himitsu.secret.core;

import com.himitsu.secret.hook.AsmHook;
import com.himitsu.secret.hook.HookMode;

public final class RuntimeHooks {
    private RuntimeHooks() {
    }

    @AsmHook(
        targetClass = "com/himitsu/secret/core/BackgroundService",
        targetMethod = "commonLoop",
        targetDescriptor = "()V",
        mode = HookMode.INSERT
    )
    public static void backgroundCycle() {
        RuntimeMetrics.recordTransformedCycle();
    }
}
