package dev.nekoobfuscator.core.pipeline;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tracks generated-helper method targets across late API renaming and helper
 * relocation so delayed metadata can resolve the same final ABI as bytecode
 * callsites.
 */
public final class GeneratedHelperTargetMap {
    private static final String PASS_DATA_KEY = "generatedHelper.finalMethodTargets";

    private GeneratedHelperTargetMap() {}

    public static MethodTarget resolveMethod(
        PipelineContext ctx,
        String owner,
        String name,
        String desc
    ) {
        MethodTarget target = new MethodTarget(owner, name, desc);
        return resolve(table(ctx), target);
    }

    public static void recordMethodRemap(
        PipelineContext ctx,
        String oldOwner,
        String oldName,
        String oldDesc,
        String newOwner,
        String newName,
        String newDesc
    ) {
        Map<MethodTarget, MethodTarget> map = table(ctx);
        MethodTarget source = new MethodTarget(oldOwner, oldName, oldDesc);
        MethodTarget target = resolve(map, new MethodTarget(newOwner, newName, newDesc));
        if (source.equals(target)) {
            return;
        }
        map.put(source, target);
        for (Map.Entry<MethodTarget, MethodTarget> entry : map.entrySet()) {
            if (entry.getValue().equals(source) || entry.getValue().equals(new MethodTarget(oldOwner, oldName, oldDesc))) {
                entry.setValue(target);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<MethodTarget, MethodTarget> table(PipelineContext ctx) {
        Map<MethodTarget, MethodTarget> map = ctx.getPassData(PASS_DATA_KEY);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(PASS_DATA_KEY, map);
        }
        return map;
    }

    private static MethodTarget resolve(
        Map<MethodTarget, MethodTarget> map,
        MethodTarget target
    ) {
        MethodTarget current = target;
        for (int i = 0; i < 64; i++) {
            MethodTarget next = map.get(current);
            if (next == null || next.equals(current)) {
                return current;
            }
            current = next;
        }
        throw new IllegalStateException("Generated helper target remap cycle at " + target);
    }

    public record MethodTarget(String owner, String name, String desc) {}
}
