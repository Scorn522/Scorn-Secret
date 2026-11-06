package com.himitsu.secret.client.render;

import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public final class RenderCallbacks {
    private static final CopyOnWriteArrayList<Consumer<RenderContext>> CALLBACKS = new CopyOnWriteArrayList<>();

    private RenderCallbacks() {
    }

    public static void register(Consumer<RenderContext> callback) {
        CALLBACKS.addIfAbsent(Objects.requireNonNull(callback, "callback"));
    }

    public static void unregister(Consumer<RenderContext> callback) {
        CALLBACKS.remove(callback);
    }

    public static void callback(RenderContext context) {
        for (Consumer<RenderContext> callback : CALLBACKS) {
            try {
                callback.accept(context);
            } catch (Throwable ignored) {
            }
        }
    }
}
