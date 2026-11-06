package com.himitsu.secret.core;

import java.util.concurrent.atomic.AtomicLong;

public final class RuntimeMetrics {
    private static final AtomicLong TRANSFORMED_CYCLES = new AtomicLong();
    private static final AtomicLong NATIVE_RENDER_CALLBACKS = new AtomicLong();

    private RuntimeMetrics() {
    }

    public static void recordTransformedCycle() {
        TRANSFORMED_CYCLES.incrementAndGet();
    }

    public static void recordNativeRenderCallback() {
        NATIVE_RENDER_CALLBACKS.incrementAndGet();
    }

    public static long transformedCycles() {
        return TRANSFORMED_CYCLES.get();
    }

    public static long nativeRenderCallbacks() {
        return NATIVE_RENDER_CALLBACKS.get();
    }
}
