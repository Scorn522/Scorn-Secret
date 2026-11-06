package com.himitsu.secret.network.sync;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import net.minecraft.network.FriendlyByteBuf;

public final class StringSetSyncValue implements SyncValue {
    public static final String TYPE = "string_set";
    private static final int MAX_ENTRIES = 4096;
    private static final int MAX_STRING_LENGTH = 32767;

    private final String key;
    private volatile Set<String> values = Set.of();

    public StringSetSyncValue(String key) {
        this.key = requireKey(key);
    }

    public Set<String> snapshot() {
        return values;
    }

    public void replace(Collection<String> newValues) {
        Objects.requireNonNull(newValues, "newValues");
        if (newValues.size() > MAX_ENTRIES) {
            throw new IllegalArgumentException("Too many synchronized set entries");
        }
        Set<String> next = new LinkedHashSet<>();
        for (String value : newValues) next.add(requireValue(value));
        values = Collections.unmodifiableSet(next);
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
        Set<String> snapshot = snapshot();
        buffer.writeVarInt(snapshot.size());
        for (String value : snapshot) {
            buffer.writeUtf(value, MAX_STRING_LENGTH);
        }
    }

    @Override
    public void decode(FriendlyByteBuf buffer) {
        int size = buffer.readVarInt();
        if (size < 0 || size > MAX_ENTRIES) {
            throw new IllegalArgumentException("Invalid synchronized set size: " + size);
        }
        Set<String> decoded = new LinkedHashSet<>();
        for (int index = 0; index < size; index++) {
            decoded.add(buffer.readUtf(MAX_STRING_LENGTH));
        }
        replace(decoded);
    }

    private static String requireKey(String key) {
        String result = Objects.requireNonNull(key, "key").trim();
        if (result.isEmpty()) {
            throw new IllegalArgumentException("Sync key cannot be empty");
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
