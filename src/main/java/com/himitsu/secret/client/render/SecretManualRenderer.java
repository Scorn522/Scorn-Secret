package com.himitsu.secret.client.render;

import com.himitsu.secret.client.avatar.SecretAvatarManager;
import com.himitsu.secret.client.avatar.SecretAvatarProxy;
import com.mojang.blaze3d.systems.RenderSystem;
import com.mojang.blaze3d.vertex.BufferBuilder;
import com.mojang.blaze3d.vertex.PoseStack;
import com.mojang.math.Axis;
import net.minecraft.client.Minecraft;
import net.minecraft.client.Camera;
import net.minecraft.client.renderer.LightTexture;
import net.minecraft.client.renderer.MultiBufferSource;
import net.minecraft.world.phys.Vec3;
import org.joml.Matrix4f;
import com.mojang.blaze3d.vertex.VertexSorting;
import java.lang.reflect.Method;
import net.minecraft.client.renderer.GameRenderer;
import net.minecraftforge.fml.util.ObfuscationReflectionHelper;

public final class SecretManualRenderer {
    private static final MultiBufferSource.BufferSource BUFFERS = MultiBufferSource.immediate(new BufferBuilder(256));
    private static final ThreadLocal<SecretAvatarProxy> FRAME_ENTITY = new ThreadLocal<>();
    private static final Method GET_FOV = ObfuscationReflectionHelper.findMethod(
        GameRenderer.class, "m_109141_", Camera.class, float.class, boolean.class
    );

    private SecretManualRenderer() {
    }

    public static void renderBeforeSwap(boolean advanceFrame) {
        Minecraft minecraft = Minecraft.getInstance();
        float partialTick = minecraft.getFrameTime();
        SecretAvatarProxy entity = FRAME_ENTITY.get();
        if (advanceFrame || entity == null) {
            entity = SecretAvatarManager.update(partialTick);
            if (entity != null) FRAME_ENTITY.set(entity);
        }
        SecretEntityRenderer renderer = SecretEntityRenderer.instance();
        if (entity == null || renderer == null) {
            return;
        }
        if (!RenderSystem.isOnRenderThread()) {
            return;
        }

        Vec3 position = entity.position();
        Camera mainCamera = minecraft.gameRenderer.getMainCamera();
        Vec3 camera = mainCamera.getPosition();
        Matrix4f worldProjection;
        try {
            double fov = (double) GET_FOV.invoke(
                minecraft.gameRenderer, mainCamera, minecraft.getFrameTime(), true
            );
            worldProjection = minecraft.gameRenderer.getProjectionMatrix(fov);
        } catch (ReflectiveOperationException exception) {
            return;
        }
        VertexSorting worldSorting = RenderSystem.getVertexSorting();
        PoseStack poseStack = new PoseStack();
        poseStack.mulPose(Axis.XP.rotationDegrees(mainCamera.getXRot()));
        poseStack.mulPose(Axis.YP.rotationDegrees(mainCamera.getYRot() + 180.0F));
        Matrix4f previousProjection = new Matrix4f(RenderSystem.getProjectionMatrix());
        VertexSorting previousSorting = RenderSystem.getVertexSorting();
        RenderSystem.setProjectionMatrix(worldProjection, worldSorting);
        RenderSystem.enableDepthTest();
        RenderSystem.depthMask(true);
        RenderSystem.clear(0x00000100, false);
        RenderSystem.defaultBlendFunc();
        RenderSystem.setShaderColor(1.0F, 1.0F, 1.0F, 1.0F);
        RenderSystem.enableBlend();
        try {
            poseStack.translate(position.x - camera.x, position.y - camera.y, position.z - camera.z);
            renderer.render(entity, entity.yBodyRot, partialTick, poseStack, BUFFERS, LightTexture.FULL_BRIGHT);
        } finally {
            BUFFERS.endBatch();
            RenderSystem.depthMask(true);
            RenderSystem.enableDepthTest();
            RenderSystem.setProjectionMatrix(previousProjection, previousSorting);
            RenderSystem.setShaderColor(1.0F, 1.0F, 1.0F, 1.0F);
            RenderSystem.disableBlend();
        }
    }

    public static void endFrame() {
        FRAME_ENTITY.remove();
    }

}
