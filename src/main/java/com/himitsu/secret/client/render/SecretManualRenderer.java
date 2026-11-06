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
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import net.minecraft.client.renderer.GameRenderer;
import net.minecraftforge.fml.util.ObfuscationReflectionHelper;

public final class SecretManualRenderer {
    private static final MultiBufferSource.BufferSource BUFFERS = MultiBufferSource.immediate(new BufferBuilder(256));
    private static final MethodHandle GET_FOV = fovHandle();
    private static MethodHandle fovHandle() {
        try { return MethodHandles.lookup().unreflect(ObfuscationReflectionHelper.findMethod(
            GameRenderer.class,"m_109141_",Camera.class,float.class,boolean.class)); }
        catch(IllegalAccessException failure) { throw new ExceptionInInitializerError(failure); }
    }

    private SecretManualRenderer() {
    }

    public static boolean renderBeforeSwap() {
        if (!RenderSystem.isOnRenderThread()) return false;
        Minecraft minecraft = Minecraft.getInstance();
        if(minecraft.level==null) return false;
        float partialTick = minecraft.getFrameTime();
        // AvatarManager already deduplicates updates within this game frame.
        SecretAvatarProxy entity = SecretAvatarManager.update(partialTick);
        SecretEntityRenderer renderer = SecretEntityRenderer.instance();
        if(entity==null || entity.level()!=minecraft.level || renderer==null) return false;

        Vec3 position = entity.position();
        Camera mainCamera = minecraft.gameRenderer.getMainCamera();
        Vec3 camera = mainCamera.getPosition();
        Matrix4f worldProjection;
        try {
            double fov = (double) GET_FOV.invokeExact(
                minecraft.gameRenderer, mainCamera, minecraft.getFrameTime(), true
            );
            worldProjection = minecraft.gameRenderer.getProjectionMatrix(fov);
        } catch (Throwable exception) {
            return false;
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
            try { BUFFERS.endBatch(); }
            finally {
            RenderSystem.depthMask(true);
            RenderSystem.enableDepthTest();
            RenderSystem.setProjectionMatrix(previousProjection, previousSorting);
            RenderSystem.setShaderColor(1.0F, 1.0F, 1.0F, 1.0F);
            RenderSystem.disableBlend();
            }
        }
        return true;
    }

}
