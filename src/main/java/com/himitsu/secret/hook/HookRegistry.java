package com.himitsu.secret.hook;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public final class HookRegistry {
    private static final Map<String, CopyOnWriteArrayList<HookDefinition>> HOOKS = new ConcurrentHashMap<>();
    private static final Set<HookDefinition> MATCHED = ConcurrentHashMap.newKeySet();
    private static final Set<String> SEEN_CLASSES = ConcurrentHashMap.newKeySet();
    private static volatile boolean subclassTargets;

    private HookRegistry() {
    }

    public static List<HookDefinition> register(Class<?> callbackContainer) {
        Objects.requireNonNull(callbackContainer, "callbackContainer");
        List<HookDefinition> added = new ArrayList<>();
        for (Method method : callbackContainer.getDeclaredMethods()) {
            for (AsmHook annotation : method.getAnnotationsByType(AsmHook.class)) {
                HookDefinition definition = HookDefinition.from(annotation, method);
                HOOKS.computeIfAbsent(definition.targetClass(), ignored -> new CopyOnWriteArrayList<>()).add(definition);
                HOOKS.get(definition.targetClass()).sort(null);
                subclassTargets |= definition.includeSubclasses();
                added.add(definition);
            }
        }
        return Collections.unmodifiableList(added);
    }

    public static void register(HookDefinition definition) {
        Objects.requireNonNull(definition, "definition");
        HOOKS.computeIfAbsent(definition.targetClass(), ignored -> new CopyOnWriteArrayList<>()).add(definition);
        HOOKS.get(definition.targetClass()).sort(null);
        subclassTargets |= definition.includeSubclasses();
    }

    public static Collection<HookDefinition> hooksFor(String className) {
        if (className == null) {
            return Collections.emptyList();
        }
        List<HookDefinition> definitions = HOOKS.get(className.replace('.', '/'));
        return definitions == null ? Collections.emptyList() : definitions;
    }

    public static Collection<HookDefinition> hooksFor(String className, Collection<String> ancestors) {
        List<HookDefinition> result = new ArrayList<>(hooksFor(className));
        for (String ancestor : ancestors) {
            for (HookDefinition definition : hooksFor(ancestor)) {
                if (definition.includeSubclasses()) {
                    result.add(definition);
                }
            }
        }
        result.sort(null);
        return Collections.unmodifiableList(result);
    }

    public static boolean hasTarget(String className) {
        return className != null && HOOKS.containsKey(className.replace('.', '/'));
    }

    public static boolean hasSubclassTargets() {
        return subclassTargets;
    }

    static void recordClass(String className) {
        if (className != null) SEEN_CLASSES.add(className.replace('.', '/'));
    }

    static void recordMatch(HookDefinition definition) {
        MATCHED.add(definition);
    }

    public static HookAudit audit() {
        List<String> missingTargets = new ArrayList<>();
        for (Map.Entry<String, CopyOnWriteArrayList<HookDefinition>> entry : HOOKS.entrySet()) {
            for (HookDefinition definition : entry.getValue()) {
                if (!MATCHED.contains(definition)) {
                    missingTargets.add(definition.targetClass() + '.' + definition.targetMethod()
                        + definition.targetDescriptor() + " -> " + definition.callbackOwner().replace('/', '.')
                        + '.' + definition.callbackName() + definition.callbackDescriptor());
                }
            }
        }
        Collections.sort(missingTargets);
        List<String> unseenClasses = HOOKS.keySet().stream()
            .filter(target -> !SEEN_CLASSES.contains(target))
            .sorted()
            .toList();
        return new HookAudit(HOOKS.values().stream().mapToInt(Collection::size).sum(), MATCHED.size(), unseenClasses, missingTargets);
    }

    public record HookAudit(int registeredHooks, int matchedHooks, List<String> unseenClasses, List<String> missingTargets) {
        public boolean complete() {
            return missingTargets.isEmpty();
        }

        public String diagnostic() {
            if (complete()) return "All " + registeredHooks + " registered hooks matched";
            return "Matched " + matchedHooks + '/' + registeredHooks + " hooks; missing targets: "
                + String.join(", ", missingTargets);
        }
    }

    public static Set<String> targets() {
        return Set.copyOf(HOOKS.keySet());
    }

    public static void clear() {
        HOOKS.clear();
        MATCHED.clear();
        SEEN_CLASSES.clear();
        subclassTargets = false;
    }
}
