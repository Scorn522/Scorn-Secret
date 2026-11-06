package com.himitsu.secret.client;

import com.himitsu.secret.client.screen.SecretDeathScreen;
import com.himitsu.secret.core.DeathExecution;
import net.minecraft.client.KeyMapping;
import net.minecraft.client.Minecraft;

public final class DeathClient {
    private static final SecretDeathScreen SCREEN = new SecretDeathScreen();

    private DeathClient() {
    }

    public static void activate() {
        maintain();
    }

    public static void maintain() {
        Minecraft minecraft = Minecraft.getInstance();
        if (!DeathExecution.isClientActive()) return;
        KeyMapping.releaseAll();
        if (minecraft.player != null && minecraft.player.input != null) {
            minecraft.player.input.leftImpulse = 0.0F;
            minecraft.player.input.forwardImpulse = 0.0F;
            minecraft.player.input.jumping = false;
            minecraft.player.input.shiftKeyDown = false;
        }
        if (minecraft.player != null) minecraft.player.setDeltaMovement(0.0D, 0.0D, 0.0D);
        if (minecraft.gameMode != null) minecraft.gameMode.stopDestroyBlock();
        if (minecraft.screen != SCREEN) minecraft.setScreen(SCREEN);
        minecraft.mouseHandler.releaseMouse();
    }

    public static boolean isDeathScreen(Object screen) {
        return screen == SCREEN;
    }
}
