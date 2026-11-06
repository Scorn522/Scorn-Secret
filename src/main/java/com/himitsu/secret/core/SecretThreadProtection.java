package com.himitsu.secret.core;

import com.himitsu.secret.bridge.SecretNative;

final class SecretThreadProtection {
    private SecretThreadProtection() {
    }

    static void protect(Thread thread) {
        try {
            SecretNative.invokeChecked("ProtectThread", thread);
        } catch (Throwable ignored) {
        }
    }

    static void unprotect(Thread thread) {
        try {
            SecretNative.invokeChecked("UnprotectThread", thread);
        } catch (Throwable ignored) {
        }
    }
}
