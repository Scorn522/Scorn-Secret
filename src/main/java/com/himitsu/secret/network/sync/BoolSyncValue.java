package com.himitsu.secret.network.sync;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import net.minecraft.network.FriendlyByteBuf;

public final class BoolSyncValue implements SyncValue {
    public static final String TYPE = "bool";

    private final String key;
    private final AtomicBoolean value;

    public BoolSyncValue(String key, boolean initialValue) {
        this.key = requireKey(key);
        this.value = new AtomicBoolean(initialValue);
    }

    public boolean get() {
        return value.get();
    }

    public void set(boolean newValue) {
        value.set(newValue);
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
        buffer.writeBoolean(value.get());
    }

    @Override
    public void decode(FriendlyByteBuf buffer) {
        value.set(buffer.readBoolean());
    }

    private static String requireKey(String key) {
        String result = Objects.requireNonNull(key, "key").trim();
        if (result.isEmpty()) {
            throw new IllegalArgumentException("Sync key cannot be empty");
        }
        return result;
    }
}
