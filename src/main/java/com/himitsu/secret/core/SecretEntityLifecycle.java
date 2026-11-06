package com.himitsu.secret.core;

import net.minecraft.world.level.Level;
import net.minecraftforge.event.level.LevelEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;

public final class SecretEntityLifecycle {
    private SecretEntityLifecycle() {
    }

    public static void entityLeft(net.minecraftforge.event.entity.EntityLeaveLevelEvent event) {
        if(event.getEntity() instanceof com.himitsu.secret.entity.SecretEntity entity
            && entity.removalReason==net.minecraft.world.entity.Entity.RemovalReason.UNLOADED_TO_CHUNK
            && !AuthoritativeEntityTopology.expected(entity)) SecretEntityRegistry.leave(entity);
    }
    @SubscribeEvent
    public static void levelUnload(LevelEvent.Unload event) {
        if (event.getLevel() instanceof Level level) {
            AuthoritativeEntityTopology.clearLevel(level);
            SecretEntityRegistry.clearLevel(level);
            TargetCleanup.clearLevel(level);
            SecretEntityHooks.clearLevel(level);
            CivilizationSurvival.clearLevel(level);
            if(level.isClientSide()) {
                com.himitsu.secret.client.avatar.SecretAvatarManager.clear(level);
                com.himitsu.secret.client.render.NativeRenderBridge.clearLevel(level);
            }
        }
    }
}
