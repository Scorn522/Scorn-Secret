package com.himitsu.secret.network;

import com.himitsu.secret.network.sync.SyncValue;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public final class SyncRegistry {
    private static final Map<String, SyncValue> VALUES = new ConcurrentHashMap<>();

    private SyncRegistry() {
    }

    public static <T extends SyncValue> T register(T value) {
        Objects.requireNonNull(value, "value");
        SyncValue previous = VALUES.putIfAbsent(value.key(), value);
        if (previous != null && previous != value) {
            throw new IllegalStateException("Duplicate sync key: " + value.key());
        }
        return value;
    }

    public static SyncValue get(String key) {
        return VALUES.get(key);
    }

    public static Collection<SyncValue> values() {
        return Collections.unmodifiableCollection(VALUES.values());
    }
}
