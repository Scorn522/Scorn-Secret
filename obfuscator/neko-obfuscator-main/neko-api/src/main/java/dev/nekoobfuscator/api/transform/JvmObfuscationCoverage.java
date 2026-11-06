package dev.nekoobfuscator.api.transform;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Cross-pass accounting for JVM obfuscation coverage.
 *
 * <p>Transforms record either a full rewrite, a verifier-safe tier, a true
 * non-applicability boundary, or a fail-closed diagnostic for each method they
 * examine. The pipeline can then reject full JVM configurations that would
 * otherwise silently ship untouched application bytecode.</p>
 */
public final class JvmObfuscationCoverage {
    public static final String PASS_DATA_KEY = "jvmObfuscationCoverage";

    public enum Tier {
        FULL,
        SAFE,
        NOT_APPLICABLE,
        FAIL_CLOSED
    }

    private final Map<String, Map<String, Entry>> byMethod = new LinkedHashMap<>();
    private final Map<String, EnumMap<Tier, Integer>> summary = new LinkedHashMap<>();

    public static JvmObfuscationCoverage get(TransformContext ctx) {
        JvmObfuscationCoverage coverage = ctx.getPassData(PASS_DATA_KEY);
        if (coverage == null) {
            coverage = new JvmObfuscationCoverage();
            ctx.putPassData(PASS_DATA_KEY, coverage);
        }
        return coverage;
    }

    public void full(String passId, String owner, String name, String desc, String reason) {
        record(passId, owner, name, desc, Tier.FULL, reason);
    }

    public void safe(String passId, String owner, String name, String desc, String reason) {
        record(passId, owner, name, desc, Tier.SAFE, reason);
    }

    public void notApplicable(String passId, String owner, String name, String desc, String reason) {
        record(passId, owner, name, desc, Tier.NOT_APPLICABLE, reason);
    }

    public void failClosed(String passId, String owner, String name, String desc, String reason) {
        record(passId, owner, name, desc, Tier.FAIL_CLOSED, reason);
    }

    public void record(String passId, String owner, String name, String desc, Tier tier, String reason) {
        Objects.requireNonNull(passId, "passId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(desc, "desc");
        Objects.requireNonNull(tier, "tier");
        String methodKey = methodKey(owner, name, desc);
        byMethod.computeIfAbsent(methodKey, ignored -> new LinkedHashMap<>())
            .put(passId, new Entry(passId, tier, reason == null ? "" : reason));
        summary.computeIfAbsent(passId, ignored -> new EnumMap<>(Tier.class))
            .merge(tier, 1, Integer::sum);
    }

    public boolean hasApplied(String owner, String name, String desc, Set<String> passIds) {
        Map<String, Entry> entries = byMethod.get(methodKey(owner, name, desc));
        if (entries == null) return false;
        for (String passId : passIds) {
            Entry entry = entries.get(passId);
            if (entry != null && (entry.tier() == Tier.FULL || entry.tier() == Tier.SAFE)) {
                return true;
            }
        }
        return false;
    }

    public Entry entry(String owner, String name, String desc, String passId) {
        Map<String, Entry> entries = byMethod.get(methodKey(owner, name, desc));
        return entries == null ? null : entries.get(passId);
    }

    public Collection<String> methodKeys() {
        return Collections.unmodifiableSet(byMethod.keySet());
    }

    public List<String> summaryLines() {
        List<String> lines = new ArrayList<>();
        for (Map.Entry<String, EnumMap<Tier, Integer>> pass : summary.entrySet()) {
            EnumMap<Tier, Integer> tiers = pass.getValue();
            lines.add(pass.getKey()
                + " appliedFull=" + tiers.getOrDefault(Tier.FULL, 0)
                + " appliedSafe=" + tiers.getOrDefault(Tier.SAFE, 0)
                + " notApplicable=" + tiers.getOrDefault(Tier.NOT_APPLICABLE, 0)
                + " failClosed=" + tiers.getOrDefault(Tier.FAIL_CLOSED, 0));
        }
        return lines;
    }

    public Map<String, Map<String, Entry>> snapshot() {
        Map<String, Map<String, Entry>> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Map<String, Entry>> method : byMethod.entrySet()) {
            copy.put(method.getKey(), Map.copyOf(method.getValue()));
        }
        return Map.copyOf(copy);
    }

    public static String methodKey(String owner, String name, String desc) {
        return owner + "." + name + desc;
    }

    public record Entry(String passId, Tier tier, String reason) {}
}