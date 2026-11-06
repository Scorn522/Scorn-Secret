package com.himitsu.secret.core;

import com.himitsu.secret.entity.SecretEntity;
import java.util.concurrent.atomic.AtomicReference;
import net.minecraft.world.level.Level;

public final class SecretEntityRegistry {
    private static final AtomicReference<SecretEntity> SERVER = new AtomicReference<>();
    private static final AtomicReference<SecretEntity> CLIENT = new AtomicReference<>();

    private SecretEntityRegistry() {
    }

    public static void register(SecretEntity entity) {
        if (entity == null || entity.level() == null) return;
        AtomicReference<SecretEntity> slot = entity.level().isClientSide() ? CLIENT : SERVER;
        slot.updateAndGet(current -> current == null ? entity : current);
    }

    public static SecretEntity instance(Level level) {
        if (level == null) return null;
        return level.isClientSide() ? CLIENT.get() : SERVER.get();
    }

    public static SecretEntity clientInstance() {
        return CLIENT.get();
    }

    public static void clearLevel(Level level) {
        if (level == null) return;
        AtomicReference<SecretEntity> slot = level.isClientSide() ? CLIENT : SERVER;
        SecretEntity entity = slot.get();
        if (entity != null && entity.level() == level) slot.compareAndSet(entity, null);
    }

}
