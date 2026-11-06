package com.himitsu.secret.bridge;

public final class NativeBridge {
    private NativeBridge() {
    }

    public static synchronized native Object invoke(String command, Object[] arguments);

    public static synchronized native boolean ready();
}
