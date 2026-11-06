package dev.nekoobfuscator.core.pipeline;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.api.config.TransformConfig;
import dev.nekoobfuscator.api.transform.TransformContext;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.ir.l2.ControlFlowGraph;
import dev.nekoobfuscator.core.ir.l2.SSAForm;
import dev.nekoobfuscator.core.ir.lift.L1ToL2Lifter;
import dev.nekoobfuscator.core.jar.ClassHierarchy;
import dev.nekoobfuscator.core.jar.ResourceEntry;
import dev.nekoobfuscator.core.util.RandomUtil;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Extended pipeline context providing IR access to transform passes.
 * Lazily lifts methods to L2 on demand, caches results.
 */
public final class PipelineContext extends TransformContext {
    private final ClassHierarchy hierarchy;
    private final Map<String, L1Class> classMap;
    private final List<ResourceEntry> resources;
    private final L1ToL2Lifter lifter = new L1ToL2Lifter();
    private final Map<String, ControlFlowGraph> cfgCache = new ConcurrentHashMap<>();
    private final Map<String, SSAForm> ssaCache = new ConcurrentHashMap<>();
    private final RandomUtil random;
    private final long masterSeed;

    // Current class/method being processed
    private L1Class currentL1Class;
    private L1Method currentL1Method;

    public PipelineContext(ObfuscationConfig config, ClassHierarchy hierarchy,
                           Map<String, L1Class> classMap) {
        this(config, hierarchy, classMap, List.of());
    }

    public PipelineContext(ObfuscationConfig config, ClassHierarchy hierarchy,
                           Map<String, L1Class> classMap, List<ResourceEntry> resources) {
        super(config);
        this.hierarchy = hierarchy;
        this.classMap = classMap;
        this.resources = List.copyOf(resources);
        long seed = config.keyConfig().masterSeed();
        this.masterSeed = seed != 0 ? seed : RandomUtil.secureLong();
        this.random = new RandomUtil(masterSeed);
    }

    public ClassHierarchy hierarchy() { return hierarchy; }
    public Map<String, L1Class> classMap() { return classMap; }
    public List<ResourceEntry> resources() { return resources; }
    public RandomUtil random() { return random; }
    public long masterSeed() { return masterSeed; }

    /**
     * Returns whether a transform is excluded for the supplied class or method.
     * Transform options accept exact internal names or simple '*'/'**' globs:
     * excludeClasses: [pkg/Bootstrap]
     * excludeMethods: [pkg/Runtime.boot, pkg/Runtime.boot(Descriptor)]
     */
    public boolean isTransformExcluded(String passId, String className, String methodName, String methodDesc) {
        TransformConfig transform = config().transforms().get(passId);
        if (transform == null) return false;
        String canonicalClassName = originalClassName(normalizeClassName(className));
        if (matchesOption(transform, "excludeClasses", canonicalClassName)) return true;
        if (methodName == null) return false;
        String owner = canonicalClassName;
        String shortKey = owner + "." + methodName;
        String fullKey = shortKey + (methodDesc == null ? "" : methodDesc);
        return matchesOption(transform, "excludeMethods", shortKey)
            || matchesOption(transform, "excludeMethods", fullKey);
    }

    @SuppressWarnings("unchecked")
    private String originalClassName(String className) {
        Map<String, String> renamed = getPassData("renamer.classMap");
        if (renamed == null || className == null) return className;
        for (Map.Entry<String, String> entry : renamed.entrySet()) {
            if (className.equals(entry.getValue())) return entry.getKey();
        }
        return className;
    }

    public boolean isTransformExcluded(String passId, L1Class clazz, L1Method method) {
        return clazz != null && isTransformExcluded(
            passId,
            clazz.name(),
            method == null ? null : method.name(),
            method == null ? null : method.descriptor()
        );
    }

    private boolean matchesOption(TransformConfig transform, String option, String value) {
        Object configured = transform.options().get(option);
        if (!(configured instanceof Collection<?> patterns) || value == null) return false;
        for (Object raw : patterns) {
            if (raw == null) continue;
            String pattern = normalizePattern(String.valueOf(raw));
            if (globMatches(pattern, value)) return true;
        }
        return false;
    }

    private String normalizeClassName(String value) {
        return value == null ? null : value.replace('.', '/');
    }

    private String normalizePattern(String value) {
        int methodSeparator = value.indexOf(".", value.indexOf('/') + 1);
        if (value.indexOf('/') < 0 || methodSeparator < 0) {
            return value;
        }
        return value;
    }

    private boolean globMatches(String pattern, String value) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < pattern.length(); i++) {
            char ch = pattern.charAt(i);
            if (ch == '*') {
                if (i + 1 < pattern.length() && pattern.charAt(i + 1) == '*') {
                    regex.append(".*");
                    i++;
                } else {
                    regex.append("[^/]*");
                }
            } else {
                if ("\\.^$|?+()[]{}".indexOf(ch) >= 0) regex.append('\\');
                regex.append(ch);
            }
        }
        regex.append('$');
        return value.matches(regex.toString());
    }

    public L1Class currentL1Class() { return currentL1Class; }
    public void setCurrentL1Class(L1Class clazz) {
        this.currentL1Class = clazz;
        setCurrentClass(clazz.name());
    }

    public L1Method currentL1Method() { return currentL1Method; }
    public void setCurrentL1Method(L1Method method) {
        this.currentL1Method = method;
        if (method == null) {
            setCurrentMethod(null, null);
            return;
        }
        setCurrentMethod(method.name(), method.descriptor());
    }

    /**
     * Get CFG for a method (lifts from L1 if not cached).
     */
    public ControlFlowGraph getCFG(L1Method method) {
        String key = method.owner().name() + "." + method.name() + method.descriptor();
        return cfgCache.computeIfAbsent(key, k -> lifter.buildCFG(method));
    }

    /**
     * Get SSA form for a method (lifts from L1 if not cached).
     */
    public SSAForm getSSA(L1Method method) {
        String key = method.owner().name() + "." + method.name() + method.descriptor();
        return ssaCache.computeIfAbsent(key, k -> lifter.lift(method));
    }

    /**
     * Invalidate cached IR for a method (call after mutation).
     */
    public void invalidate(L1Method method) {
        String key = method.owner().name() + "." + method.name() + method.descriptor();
        cfgCache.remove(key);
        ssaCache.remove(key);
    }

    /**
     * Invalidate all cached IR.
     */
    public void invalidateAll() {
        cfgCache.clear();
        ssaCache.clear();
    }
}
