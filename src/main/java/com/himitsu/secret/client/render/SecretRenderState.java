package com.himitsu.secret.client.render;

import java.util.concurrent.atomic.AtomicBoolean;
import org.joml.Matrix4f;
import com.mojang.blaze3d.vertex.VertexSorting;

final class SecretRenderState {
    private static final AtomicBoolean NORMAL_RENDERED = new AtomicBoolean();
    private static final ThreadLocal<Boolean> FALLBACK_RENDER = ThreadLocal.withInitial(() -> false);
    private static volatile Matrix4f worldProjection;
    private static volatile VertexSorting worldSorting;

    private SecretRenderState() {
    }

    static void markNormalRender() {
        if (!FALLBACK_RENDER.get()) {
            NORMAL_RENDERED.set(true);
        }
    }

    static boolean consumeNormalRender() {
        return NORMAL_RENDERED.getAndSet(false);
    }

    static void captureWorldProjection(Matrix4f projection, VertexSorting sorting) {
        worldProjection = new Matrix4f(projection);
        worldSorting = sorting;
    }

    static Matrix4f worldProjection() {
        Matrix4f projection = worldProjection;
        return projection == null ? null : new Matrix4f(projection);
    }

    static VertexSorting worldSorting() {
        return worldSorting;
    }

    static void beginFallbackRender() {
        FALLBACK_RENDER.set(true);
    }

    static void endFallbackRender() {
        FALLBACK_RENDER.remove();
    }
}
