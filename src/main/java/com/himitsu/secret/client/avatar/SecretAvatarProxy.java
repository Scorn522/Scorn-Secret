package com.himitsu.secret.client.avatar;

import com.himitsu.secret.content.SecretContent;
import com.himitsu.secret.entity.SecretEntity;
import net.minecraft.network.chat.Component;
import net.minecraft.world.level.Level;

public final class SecretAvatarProxy extends SecretEntity {
    private long lastWalkAnimationTick = Long.MIN_VALUE;

    public SecretAvatarProxy(Level level) {
        super(SecretContent.SECRET_ENTITY.get(), level, false);
    }

    void applyAvatarState(double x, double y, double z, float bodyYaw, float headYaw, float pitch,
                          float limbSwingAmount, long gameTick) {
        xo = avatarX();
        yo = avatarY();
        zo = avatarZ();
        setAvatarPosition(x, y, z);
        yBodyRotO = bodyYaw;
        yBodyRot = bodyYaw;
        yHeadRotO = headYaw;
        yHeadRot = headYaw;
        xRotO = pitch;
        setXRot(pitch);
        if (lastWalkAnimationTick != gameTick) {
            walkAnimation.update(limbSwingAmount, 1.0F);
            lastWalkAnimationTick = gameTick;
        }
    }

    @Override public void setPos(double x, double y, double z) { setAvatarPosition(x, y, z); }
    @Override public double getX() { return avatarX(); }
    @Override public double getY() { return avatarY(); }
    @Override public double getZ() { return avatarZ(); }
    @Override public float getXRot() { return avatarPitch(); }
    @Override public boolean isInvisible() { return false; }

    @Override
    public Component getName() {
        return SecretEntity.dynamicName();
    }

    @Override
    public Component getDisplayName() {
        return getName();
    }
}
