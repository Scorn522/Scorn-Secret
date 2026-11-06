package com.himitsu.secret.client.avatar;

import net.minecraft.client.Minecraft;
import net.minecraft.world.level.Level;

public final class SecretAvatarManager {
    private static volatile Level avatarLevel;
    private static volatile SecretAvatar avatar;
    private static volatile SecretAvatarProxy proxy;
    private static long lastFrameKey = Long.MIN_VALUE;

    private SecretAvatarManager() {
    }

    public static synchronized void spawn(Level level,double x, double y, double z) {
        if(avatarLevel!=level) { avatar=null; proxy=null; avatarLevel=level; lastFrameKey=Long.MIN_VALUE; }
        if(avatar==null) avatar=new SecretAvatar(x,y,z);
    }

    public static boolean present(Level level) { return level!=null && avatarLevel==level && avatar!=null; }

    public static synchronized void clear(Level level) {
        if(avatarLevel==level) { avatar=null; proxy=null; avatarLevel=null; lastFrameKey=Long.MIN_VALUE; }
    }
    public static synchronized SecretAvatarProxy update(float partialTick) {
        SecretAvatar current = avatar;
        Minecraft minecraft = Minecraft.getInstance();
        Level level = minecraft.level;
        if (current == null || level == null || level!=avatarLevel) return null;
        SecretAvatarProxy currentProxy = proxy;
        if (currentProxy == null || currentProxy.level() != level) {
            currentProxy = new SecretAvatarProxy(level);
            proxy = currentProxy;
            lastFrameKey = Long.MIN_VALUE;
        }
        long frameKey = (level.getGameTime() << 32)
            ^ Integer.toUnsignedLong(Float.floatToRawIntBits(partialTick));
        if (frameKey != lastFrameKey) {
            current.update();
            com.himitsu.secret.entity.SecretEntity.syncClientPosition(current.x(), current.y(), current.z());
            current.apply(currentProxy, partialTick, level.getGameTime());
            lastFrameKey = frameKey;
        }
        return currentProxy;
    }
}
