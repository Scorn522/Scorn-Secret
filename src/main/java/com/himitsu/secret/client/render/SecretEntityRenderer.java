package com.himitsu.secret.client.render;

import com.himitsu.secret.entity.SecretEntity;
import com.mojang.blaze3d.vertex.PoseStack;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.Font;
import net.minecraft.client.model.PlayerModel;
import net.minecraft.client.model.geom.ModelLayers;
import net.minecraft.client.renderer.culling.Frustum;
import net.minecraft.client.renderer.MultiBufferSource;
import net.minecraft.client.renderer.entity.EntityRendererProvider;
import net.minecraft.client.renderer.entity.HumanoidMobRenderer;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.network.chat.Component;
import net.minecraft.util.Mth;
import org.joml.Matrix4f;

public final class SecretEntityRenderer extends HumanoidMobRenderer<SecretEntity, PlayerModel<SecretEntity>> {
    private static volatile SecretEntityRenderer instance;
    private static final ResourceLocation TEXTURE = new ResourceLocation("secret", "himitsu.png");

    public SecretEntityRenderer(EntityRendererProvider.Context context) {
        super(context, new PlayerModel<>(context.bakeLayer(ModelLayers.PLAYER), false), 0.1F);
        instance = this;
    }

    public static SecretEntityRenderer instance() { return instance; }

    @Override
    public ResourceLocation getTextureLocation(SecretEntity entity) {
        return TEXTURE;
    }

    @Override
    public void render(
        SecretEntity entity,
        float entityYaw,
        float partialTick,
        PoseStack poseStack,
        MultiBufferSource buffers,
        int packedLight
    ) {
        if (!(entity instanceof com.himitsu.secret.client.avatar.SecretAvatarProxy)) return;
        super.render(entity, entityYaw, partialTick, poseStack, buffers, packedLight);
    }

    @Override
    protected void scale(SecretEntity entity, PoseStack poseStack, float partialTick) {
        poseStack.scale(0.9375F, 0.9375F, 0.9375F);
    }

    @Override
    public boolean shouldRender(SecretEntity entity, Frustum frustum, double x, double y, double z) {
        return true;
    }

    @Override
    protected boolean shouldShowName(SecretEntity entity) {
        return entity instanceof com.himitsu.secret.client.avatar.SecretAvatarProxy;
    }

    @Override
    protected void renderNameTag(SecretEntity entity, Component name, PoseStack poseStack,
                                 MultiBufferSource buffers, int packedLight) {
        float phase = (System.currentTimeMillis() % 4000L) / 4000.0F;
        poseStack.pushPose();
        poseStack.translate(
            0.0D,
            entity.getBbHeight() + 0.5F + Mth.sin(phase * Mth.TWO_PI) * 0.12F,
            0.0D
        );
        poseStack.mulPose(this.entityRenderDispatcher.cameraOrientation());
        poseStack.scale(-0.025F, -0.025F, 0.025F);
        Component title = SecretEntity.dynamicName();
        Font font = Minecraft.getInstance().font;
        Matrix4f matrix = poseStack.last().pose();
        float left = -font.width(title) * 0.5F;
        font.drawInBatch(
            title,
            left + 1.0F,
            1.0F,
            0xFF21002D,
            false,
            matrix,
            buffers,
            Font.DisplayMode.SEE_THROUGH,
            0,
            packedLight
        );
        font.drawInBatch(
            title,
            left,
            0.0F,
            0xFF9A4FC2,
            false,
            matrix,
            buffers,
            Font.DisplayMode.NORMAL,
            0,
            packedLight
        );
        poseStack.popPose();
    }
}
