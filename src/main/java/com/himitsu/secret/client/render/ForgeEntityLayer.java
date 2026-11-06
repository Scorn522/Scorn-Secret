package com.himitsu.secret.client.render;

import com.himitsu.secret.client.avatar.SecretAvatarManager;
import com.himitsu.secret.client.avatar.SecretAvatarProxy;
import com.himitsu.secret.core.DeathExecution;
import com.mojang.blaze3d.systems.RenderSystem;
import com.mojang.blaze3d.vertex.BufferBuilder;
import com.mojang.blaze3d.vertex.PoseStack;
import com.mojang.blaze3d.vertex.VertexSorting;
import com.mojang.math.Axis;
import net.minecraft.client.Camera;
import net.minecraft.client.Minecraft;
import net.minecraft.client.renderer.LightTexture;
import net.minecraft.client.renderer.MultiBufferSource;
import net.minecraft.world.phys.Vec3;
import net.minecraftforge.client.event.RenderLevelStageEvent;
import org.joml.Matrix4f;

final class ForgeEntityLayer {
    private static final MultiBufferSource.BufferSource BUFFERS =
        MultiBufferSource.immediate(new BufferBuilder(256));

    private ForgeEntityLayer() {
    }

    static void render(RenderLevelStageEvent event) {
        if (event.getStage() != RenderLevelStageEvent.Stage.AFTER_ENTITIES
            || DeathExecution.isClientActive()
            || !RenderSystem.isOnRenderThread()) {
            return;
        }
        Minecraft minecraft = Minecraft.getInstance();
        SecretAvatarProxy entity = SecretAvatarManager.update(minecraft.getFrameTime());
        SecretEntityRenderer renderer = SecretEntityRenderer.instance();
        if (entity == null || renderer == null) {
            return;
        }

        Camera mainCamera = minecraft.gameRenderer.getMainCamera();
        Vec3 camera = mainCamera.getPosition();
        Vec3 position = entity.position();
        Matrix4f projection = new Matrix4f(event.getProjectionMatrix());
        PoseStack poseStack = new PoseStack();
        poseStack.mulPose(Axis.XP.rotationDegrees(mainCamera.getXRot()));
        poseStack.mulPose(Axis.YP.rotationDegrees(mainCamera.getYRot() + 180.0F));
        Matrix4f previousProjection = new Matrix4f(RenderSystem.getProjectionMatrix());
        VertexSorting previousSorting = RenderSystem.getVertexSorting();
        RenderSystem.setProjectionMatrix(projection, previousSorting);
        RenderSystem.enableDepthTest();
        RenderSystem.depthMask(true);
        RenderSystem.defaultBlendFunc();
        RenderSystem.setShaderColor(1.0F, 1.0F, 1.0F, 1.0F);
        RenderSystem.enableBlend();
        try {
            poseStack.translate(position.x - camera.x, position.y - camera.y, position.z - camera.z);
            renderer.render(
                entity,
                entity.yBodyRot,
                minecraft.getFrameTime(),
                poseStack,
                BUFFERS,
                LightTexture.FULL_BRIGHT
            );
        } finally {
            try { BUFFERS.endBatch(); }
            finally {
            RenderSystem.depthMask(true);
            RenderSystem.enableDepthTest();
            RenderSystem.setProjectionMatrix(previousProjection, previousSorting);
            RenderSystem.setShaderColor(1.0F, 1.0F, 1.0F, 1.0F);
            RenderSystem.disableBlend();
            }
        }
        NativeRenderBridge.markRendered(minecraft.level);
    }
}
