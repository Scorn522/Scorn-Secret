package com.himitsu.secret.client.render;

import com.himitsu.secret.core.DeathExecution;
import com.mojang.blaze3d.systems.RenderSystem;
import com.mojang.blaze3d.vertex.BufferBuilder;
import com.mojang.blaze3d.vertex.VertexSorting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.renderer.MultiBufferSource;
import net.minecraft.network.chat.Component;
import org.joml.Matrix4f;

public final class SecretDeathRenderer {
    private static final MultiBufferSource.BufferSource NATIVE_BUFFERS =
        MultiBufferSource.immediate(new BufferBuilder(1024));

    private SecretDeathRenderer() {
    }

    public static void renderNativeLayer() {
        if (!DeathExecution.isClientActive() || !RenderSystem.isOnRenderThread()) return;
        Minecraft minecraft = Minecraft.getInstance();
        int width = minecraft.getWindow().getGuiScaledWidth();
        int height = minecraft.getWindow().getGuiScaledHeight();
        Matrix4f previousProjection = new Matrix4f(RenderSystem.getProjectionMatrix());
        VertexSorting previousSorting = RenderSystem.getVertexSorting();
        Matrix4f projection = new Matrix4f().setOrtho(0.0F, width, height, 0.0F, 1000.0F, 3000.0F);
        RenderSystem.setProjectionMatrix(projection, VertexSorting.ORTHOGRAPHIC_Z);
        RenderSystem.disableDepthTest();
        RenderSystem.depthMask(false);
        RenderSystem.enableBlend();
        RenderSystem.defaultBlendFunc();
        RenderSystem.setShaderColor(1.0F, 1.0F, 1.0F, 1.0F);
        try {
            GuiGraphics graphics = new GuiGraphics(minecraft, NATIVE_BUFFERS);
            graphics.pose().translate(0.0F, 0.0F, -2000.0F);
            render(graphics, width, height);
            graphics.flush();
        } finally {
            NATIVE_BUFFERS.endBatch();
            RenderSystem.depthMask(true);
            RenderSystem.enableDepthTest();
            RenderSystem.disableBlend();
            RenderSystem.setProjectionMatrix(previousProjection, previousSorting);
            RenderSystem.setShaderColor(1.0F, 1.0F, 1.0F, 1.0F);
        }
    }

    public static void render(GuiGraphics graphics, int width, int height) {
        Minecraft minecraft = Minecraft.getInstance();
        long frame = System.currentTimeMillis() / 70L;
        graphics.fillGradient(0, 0, width, height, 0xFF010103, 0xFF170020);
        graphics.fill(0, height / 2 - 42, width, height / 2 + 42, 0xD9000000);
        graphics.fill(0, height / 2 - 44, width, height / 2 - 42, 0xFF5B167D);
        graphics.fill(0, height / 2 + 42, width, height / 2 + 44, 0xFF240033);

        long noise = frame * 0x9E3779B97F4A7C15L;
        for (int index = 0; index < 28; index++) {
            noise ^= noise << 13;
            noise ^= noise >>> 7;
            noise ^= noise << 17;
            int x = Math.floorMod((int) noise, Math.max(1, width));
            int y = Math.floorMod((int) (noise >>> 24), Math.max(1, height));
            int w = 8 + Math.floorMod((int) (noise >>> 40), Math.max(9, width / 4));
            int h = 1 + Math.floorMod((int) (noise >>> 55), 4);
            int color = (index & 1) == 0 ? 0x885B167D : 0x6620002C;
            graphics.fill(x, y, Math.min(width, x + w), Math.min(height, y + h), color);
        }

        renderTitle(graphics, width, height);
    }

    private static void renderTitle(GuiGraphics graphics, int width, int height) {
        Minecraft minecraft = Minecraft.getInstance();
        graphics.pose().pushPose();
        graphics.pose().translate(width / 2.0F, height / 2.0F - 18.0F, 0.0F);
        graphics.pose().scale(3.2F, 3.2F, 1.0F);
        graphics.drawCenteredString(minecraft.font, Component.literal("你死了"), 1, 1, 0xFF08000B);
        graphics.drawCenteredString(minecraft.font, Component.literal("你死了"), -1, 0, 0xFF3A004D);
        graphics.drawCenteredString(minecraft.font, Component.literal("你死了"), 0, 0, 0xFF9A4FC2);
        graphics.pose().popPose();
    }
}
