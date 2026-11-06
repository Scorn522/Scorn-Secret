package dev.nekoobfuscator.transforms.util;

import dev.nekoobfuscator.api.transform.TransformContext;

/**
 * Transform-side access point for JVM obfuscation coverage accounting.
 */
public final class JvmObfuscationCoverage {
    private JvmObfuscationCoverage() {}

    public static dev.nekoobfuscator.api.transform.JvmObfuscationCoverage get(TransformContext ctx) {
        return dev.nekoobfuscator.api.transform.JvmObfuscationCoverage.get(ctx);
    }
}