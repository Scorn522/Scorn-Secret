package com.himitsu.secret.core;

import com.himitsu.secret.bridge.SecretNative;

final class SecretThreadProtection {
    private SecretThreadProtection() {
    }

    static boolean protect(Thread thread) {
        try { return Boolean.TRUE.equals(SecretNative.invokeChecked("ProtectThread",thread)); }
        catch(Throwable failure) { System.err.println("[Secret/ThreadGuard] Protection failed: "+failure); return false; }
    }

    static void unprotect(Thread thread) {
        try {
            SecretNative.invokeChecked("UnprotectThread", thread);
        } catch (Throwable ignored) {
        }
    }
}
