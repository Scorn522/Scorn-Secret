package com.himitsu.secret.core;

import net.minecraft.world.level.Level;
import net.minecraftforge.event.level.LevelEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;

public final class SecretEntityLifecycle {
    private SecretEntityLifecycle() {
    }

    @SubscribeEvent
    public static void levelUnload(LevelEvent.Unload event) {
        if (event.getLevel() instanceof Level level) {
            SecretEntityRegistry.clearLevel(level);
            SecretEntityHooks.clearLevel(level);
            CivilizationSurvival.clearLevel(level);
        }
    }
}
