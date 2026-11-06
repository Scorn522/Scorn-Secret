package dev.nekoobfuscator.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.jar.ClassHierarchy;
import dev.nekoobfuscator.core.pipeline.GeneratedHelperTargetMap;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import java.util.LinkedHashMap;
import org.junit.jupiter.api.Test;

final class GeneratedHelperTargetMapTest {
    @Test
    void resolvesOriginalGeneratedHelperTargetThroughRenameAndRelocation() {
        PipelineContext ctx = context();

        GeneratedHelperTargetMap.recordMethodRemap(
            ctx,
            "pkg/Owner",
            "__neko_generated$0",
            "(IIJ)I",
            "pkg/Owner",
            "qa",
            "(IIJ)I"
        );
        GeneratedHelperTargetMap.recordMethodRemap(
            ctx,
            "pkg/Owner",
            "qa",
            "(IIJ)I",
            "pkg/Host",
            "qa",
            "(IIJ)I"
        );

        GeneratedHelperTargetMap.MethodTarget finalTarget =
            GeneratedHelperTargetMap.resolveMethod(ctx, "pkg/Owner", "__neko_generated$0", "(IIJ)I");

        assertEquals(new GeneratedHelperTargetMap.MethodTarget("pkg/Host", "qa", "(IIJ)I"), finalTarget);
        assertEquals(
            finalTarget,
            GeneratedHelperTargetMap.resolveMethod(ctx, "pkg/Owner", "qa", "(IIJ)I")
        );
        assertEquals(
            new GeneratedHelperTargetMap.MethodTarget("pkg/Other", "qa", "(IIJ)I"),
            GeneratedHelperTargetMap.resolveMethod(ctx, "pkg/Other", "qa", "(IIJ)I")
        );
    }

    private static PipelineContext context() {
        return new PipelineContext(
            new ObfuscationConfig(),
            new ClassHierarchy(),
            new LinkedHashMap<String, L1Class>()
        );
    }
}
