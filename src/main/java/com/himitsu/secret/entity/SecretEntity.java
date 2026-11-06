package com.himitsu.secret.entity;

import com.himitsu.secret.core.SecretEntityRegistry;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.network.chat.Style;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.damagesource.DamageSource;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.EntityType;
import net.minecraft.world.entity.Mob;
import net.minecraft.world.entity.PathfinderMob;
import net.minecraft.world.entity.Pose;
import net.minecraft.world.entity.ai.attributes.AttributeSupplier;
import net.minecraft.world.entity.ai.attributes.Attributes;
import net.minecraft.world.level.Level;
import net.minecraft.world.phys.AABB;
import net.minecraft.world.phys.Vec3;

public class SecretEntity extends PathfinderMob {
    private static final int[] NAME_GRADIENT = {
        0x100815,
        0x2A1038,
        0x54206F,
        0x8738B0,
        0xC36AF2,
        0x6D288F,
        0x1A0A24
    };
    private boolean positionLocked;
    private final boolean registerOnEntry;

    public SecretEntity(EntityType<? extends PathfinderMob> type, Level level) {
        this(type, level, true);
    }

    protected SecretEntity(EntityType<? extends PathfinderMob> type, Level level, boolean register) {
        super(type, level);
        setPersistenceRequired();
        registerOnEntry=register;
    }

    public static SecretEntity clientInstance() {
        return SecretEntityRegistry.clientInstance();
    }

    public static SecretEntity instance(Level level) {
        return SecretEntityRegistry.instance(level);
    }

    public static void syncClientPosition(double x, double y, double z) {
        SecretEntity entity = SecretEntityRegistry.clientInstance();
        if (entity != null) entity.setAvatarPosition(x, y, z);
    }

    public static AttributeSupplier.Builder createAttributes() {
        return Mob.createMobAttributes()
            .add(Attributes.MOVEMENT_SPEED, 0.5D)
            .add(Attributes.MAX_HEALTH, 20.0D)
            .add(Attributes.ARMOR, 32767.0D)
            .add(Attributes.ARMOR_TOUGHNESS, 32767.0D)
            .add(Attributes.FOLLOW_RANGE, 2048.0D)
            .add(Attributes.KNOCKBACK_RESISTANCE, 32767.0D)
            .add(Attributes.ATTACK_DAMAGE, 0.0D);
    }

    protected final void setAvatarPosition(double x, double y, double z) {
        super.setPos(x, y, z);
    }

    protected final double avatarX() { return super.getX(); }
    protected final double avatarY() { return super.getY(); }
    protected final double avatarZ() { return super.getZ(); }
    protected final float avatarPitch() { return super.getXRot(); }

    @Override
    public float getHealth() {
        lastDamageSource = null;
        return 20.0F;
    }

    @Override
    public float getMaxHealth() {
        return 20.0F;
    }

    @Override
    public boolean isDeadOrDying() {
        return false;
    }

    @Override
    public boolean isAlive() {
        return true;
    }

    @Override
    public boolean isInvulnerableTo(DamageSource source) {
        return true;
    }

    @Override
    public boolean hurt(DamageSource source, float amount) {
        return false;
    }

    @Override
    public boolean canChangeDimensions() {
        return false;
    }

    @Override
    public boolean removeWhenFarAway(double distanceToClosestPlayer) {
        return false;
    }

    @Override
    public boolean isPushable() {
        return false;
    }

    @Override
    public boolean canBeCollidedWith() {
        return false;
    }

    @Override
    public boolean isNoAi() {
        return false;
    }

    @Override
    public boolean isNoGravity() {
        return false;
    }

    @Override
    public boolean isInvisible() {
        return true;
    }

    @Override
    public float getXRot() {
        xRotO = 0.0F;
        return 0.0F;
    }

    @Override
    public float getYRot() {
        yRotO = 0.0F;
        return 0.0F;
    }

    @Override
    public float getYHeadRot() {
        yHeadRotO = 0.0F;
        return 0.0F;
    }

    @Override
    public float getViewXRot(float partialTick) {
        return 0.0F;
    }

    @Override
    public float getViewYRot(float partialTick) {
        return 0.0F;
    }

    @Override
    public boolean shouldRender(double x, double y, double z) {
        return true;
    }

    @Override
    public boolean shouldRenderAtSqrDistance(double distance) {
        return true;
    }

    @Override
    public boolean broadcastToPlayer(ServerPlayer player) {
        return true;
    }

    @Override
    public void setPos(double x, double y, double z) {
        if (!positionLocked) super.setPos(x, y, z);
    }

    @Override
    public void onAddedToWorld() {
        super.onAddedToWorld();
        if (getClass() != SecretEntity.class) { if(registerOnEntry) SecretEntityRegistry.register(this); return; }
        net.minecraft.world.entity.player.Player player;
        if (level().isClientSide()) {
            player = net.minecraft.client.Minecraft.getInstance().player;
        } else {
            player = level().getNearestPlayer(this, -1.0D);
        }
        if (player != null) {
            setAvatarPosition(player.getX(), player.getY(), player.getZ());
        }
        if (level().isClientSide()) {
            com.himitsu.secret.client.avatar.SecretAvatarManager.spawn(level(), super.getX(), super.getY(), super.getZ());
        }
        positionLocked = true;
        if(registerOnEntry) SecretEntityRegistry.register(this);
    }

    @Override
    public double getX() {
        return super.getX();
    }

    @Override
    public double getY() {
        return super.getY();
    }

    @Override
    public double getZ() {
        return super.getZ();
    }

    @Override
    public Vec3 position() {
        return super.position();
    }

    @Override
    public AABB getBoundingBox() {
        return super.getBoundingBox();
    }

    @Override
    public AABB makeBoundingBox() {
        return super.makeBoundingBox();
    }

    @Override
    public AABB getBoundingBoxForCulling() {
        return getBoundingBox();
    }

    @Override
    public float getStandingEyeHeight(Pose pose, net.minecraft.world.entity.EntityDimensions dimensions) {
        return 1.62F;
    }

    @Override
    public void actuallyHurt(DamageSource source, float amount) {
    }

    @Override
    public void tickDeath() {
    }

    @Override
    public void remove(Entity.RemovalReason reason) {
    }

    @Override
    public void kill() {
    }

    @Override
    public boolean isRemoved() {
        return false;
    }

    @Override
    public Entity.RemovalReason getRemovalReason() {
        return null;
    }

    @Override
    public EntityType<?> getType() {
        return com.himitsu.secret.content.SecretContent.SECRET_ENTITY.get();
    }

    @Override
    public Component getName() {
        return dynamicName();
    }

    @Override
    public Component getDisplayName() {
        return getName();
    }

    public static Component dynamicName() {
        float phase = (System.currentTimeMillis() % 5000L) / 5000.0F;
        MutableComponent result = Component.empty();
        int[] characters = "秘密".codePoints().toArray();
        for (int index = 0; index < characters.length; index++) {
            float position = phase + index * 0.23F;
            result.append(Component.literal(new String(Character.toChars(characters[index])))
                .withStyle(nameStyle(position)));
        }
        return result;
    }

    private static Style nameStyle(float position) {
        return Style.EMPTY
            .withColor(gradientColor(position))
            .withBold(true);
    }

    private static int gradientColor(float position) {
        float wrapped = position - (float)Math.floor(position);
        float scaled = wrapped * (NAME_GRADIENT.length - 1);
        int left = Math.min((int)scaled, NAME_GRADIENT.length - 2);
        return blend(NAME_GRADIENT[left], NAME_GRADIENT[left + 1], scaled - left);
    }

    private static int blend(int from, int to, float amount) {
        int red = Math.round(((from >> 16) & 0xFF) + (((to >> 16) & 0xFF) - ((from >> 16) & 0xFF)) * amount);
        int green = Math.round(((from >> 8) & 0xFF) + (((to >> 8) & 0xFF) - ((from >> 8) & 0xFF)) * amount);
        int blue = Math.round((from & 0xFF) + ((to & 0xFF) - (from & 0xFF)) * amount);
        return (red << 16) | (green << 8) | blue;
    }
}
