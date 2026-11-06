package com.himitsu.secret.client.render;

import com.himitsu.secret.SecretMod;
import com.mojang.blaze3d.systems.RenderSystem;
import net.minecraftforge.client.event.RenderGuiOverlayEvent;
import net.minecraftforge.client.event.RenderLevelStageEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;

public final class ForgeRenderBridge {
    private ForgeRenderBridge() {
    }

    @SubscribeEvent
    public static void renderLevel(RenderLevelStageEvent event) {
        SecretRenderState.captureWorldProjection(
            event.getProjectionMatrix(),
            RenderSystem.getVertexSorting()
        );
        RenderCallbacks.callback(RenderContext.level(event));
        try {
            ForgeEntityLayer.render(event);
        } catch (Throwable ignored) {
        }
    }

    @SubscribeEvent
    public static void renderGui(RenderGuiOverlayEvent.Post event) {
        RenderCallbacks.callback(RenderContext.gui(event));
        if (com.himitsu.secret.core.DeathExecution.isClientActive()) {
            SecretDeathRenderer.render(
                event.getGuiGraphics(),
                net.minecraft.client.Minecraft.getInstance().getWindow().getGuiScaledWidth(),
                net.minecraft.client.Minecraft.getInstance().getWindow().getGuiScaledHeight()
            );
        }
    }
}
