package com.himitsu.secret.client;

import com.himitsu.secret.client.screen.SecretConfigScreen;
import net.minecraft.client.Minecraft;

public final class ConfigToolClient {
    private ConfigToolClient() {
    }

    public static void open() {
        Minecraft minecraft = Minecraft.getInstance();
        minecraft.execute(() -> {
            minecraft.setScreen(new SecretConfigScreen(minecraft.screen));
            minecraft.mouseHandler.releaseMouse();
        });
    }
}
