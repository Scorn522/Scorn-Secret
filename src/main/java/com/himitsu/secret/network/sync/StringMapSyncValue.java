package com.himitsu.secret.network.sync;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import net.minecraft.network.FriendlyByteBuf;

public final class StringMapSyncValue implements SyncValue {
    public static final String TYPE = "string_map";
    private static final int MAX_ENTRIES = 4096;
    private static final int MAX_STRING_LENGTH = 32767;

    private final String key;
    private final Map<String, String> values = new LinkedHashMap<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public StringMapSyncValue(String key) {
        this.key = requireText(key, "Sync key cannot be empty");
    }

    public Map<String, String> snapshot() {
        lock.readLock().lock();
        try {
            return Collections.unmodifiableMap(new LinkedHashMap<>(values));
        } finally {
            lock.readLock().unlock();
        }
    }

    public void replace(Map<String, String> newValues) {
        Objects.requireNonNull(newValues, "newValues");
        if (newValues.size() > MAX_ENTRIES) {
            throw new IllegalArgumentException("Too many synchronized map entries");
        }
        lock.writeLock().lock();
        try {
            values.clear();
            for (Map.Entry<String, String> entry : newValues.entrySet()) {
                values.put(requireText(entry.getKey(), "Map key cannot be empty"), requireValue(entry.getValue()));
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public String key() {
        return key;
    }

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public void encode(FriendlyByteBuf buffer) {
        Map<String, String> snapshot = snapshot();
        buffer.writeVarInt(snapshot.size());
        for (Map.Entry<String, String> entry : snapshot.entrySet()) {
            buffer.writeUtf(entry.getKey(), MAX_STRING_LENGTH);
            buffer.writeUtf(entry.getValue(), MAX_STRING_LENGTH);
        }
    }

    @Override
    public void decode(FriendlyByteBuf buffer) {
        int size = buffer.readVarInt();
        if (size < 0 || size > MAX_ENTRIES) {
            throw new IllegalArgumentException("Invalid synchronized map size: " + size);
        }
        Map<String, String> decoded = new LinkedHashMap<>();
        for (int index = 0; index < size; index++) {
            decoded.put(buffer.readUtf(MAX_STRING_LENGTH), buffer.readUtf(MAX_STRING_LENGTH));
        }
        replace(decoded);
    }

    private static String requireText(String value, String message) {
        String result = Objects.requireNonNull(value, "value").trim();
        if (result.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
        if (result.length() > MAX_STRING_LENGTH) {
            throw new IllegalArgumentException("Synchronized string is too long");
        }
        return result;
    }

    private static String requireValue(String value) {
        String result = Objects.requireNonNull(value, "value");
        if (result.length() > MAX_STRING_LENGTH) {
            throw new IllegalArgumentException("Synchronized string is too long");
        }
        return result;
    }
}
