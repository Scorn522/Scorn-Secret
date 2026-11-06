package com.himitsu.secret.client.render;

import net.minecraftforge.client.event.RenderGuiOverlayEvent;
import net.minecraftforge.client.event.RenderLevelStageEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;

public final class ForgeRenderBridge {
    private ForgeRenderBridge() {
    }

    @SubscribeEvent
    public static void renderLevel(RenderLevelStageEvent event) {
        try {
            ForgeEntityLayer.render(event);
        } catch (Throwable ignored) {
        }
    }

    @SubscribeEvent
    public static void renderGui(RenderGuiOverlayEvent.Post event) {
        if (com.himitsu.secret.core.DeathExecution.isClientActive()) {
            SecretDeathRenderer.render(
                event.getGuiGraphics(),
                net.minecraft.client.Minecraft.getInstance().getWindow().getGuiScaledWidth(),
                net.minecraft.client.Minecraft.getInstance().getWindow().getGuiScaledHeight()
            );
        }
    }
}
