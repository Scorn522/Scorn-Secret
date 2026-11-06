package com.himitsu.secret.core;

import com.himitsu.secret.client.screen.SecretConfigScreen;
import com.himitsu.secret.client.screen.SecretDeathScreen;
import com.himitsu.secret.hook.AsmHook;
import com.himitsu.secret.hook.HookMode;
import net.minecraft.client.player.LocalPlayer;
import net.minecraft.client.renderer.entity.EntityRenderer;
import net.minecraft.client.MouseHandler;
import net.minecraft.network.syncher.EntityDataAccessor;
import net.minecraft.network.syncher.SynchedEntityData;
import net.minecraft.world.damagesource.DamageSource;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.LivingEntity;
import net.minecraft.world.entity.player.Player;
import net.minecraft.server.level.ServerPlayer;

public final class CivilizationSurvivalHooks {
    private CivilizationSurvivalHooks() {
    }

    public static void installWeaponHooks() {
        // Registration resolves these game types before the load callback is enabled.
        // Install only these two loaded targets once, after parallel mod construction.
        Object result = com.himitsu.secret.bridge.SecretNative.invokeChecked(
                "RetransformClass", (Object) new Class<?>[]{Player.class, LivingEntity.class});
        if (!Boolean.TRUE.equals(result)) throw new IllegalStateException("Weapon hook installation failed");
        for (String missing : com.himitsu.secret.hook.HookRegistry.audit().missingTargets()) {
            if (missing.contains("CivilizationSurvivalHooks.weaponAttack") || missing.contains("CivilizationSurvivalHooks.weaponSwing"))
                throw new IllegalStateException("Weapon hook was not applied: " + missing);
        }
        System.out.println("[Secret/Weapon] Attack and swing entry hooks installed");
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/player/Player",
        targetMethod = "attack",
        targetAliases = "m_5706_",
        targetDescriptor = "(Lnet/minecraft/world/entity/Entity;)V",
        mode = HookMode.HEAD,
        includeThis = true
    )
    public static void weaponAttack(Player player, Entity target) {
        if (!player.level().isClientSide()
            && player.getMainHandItem().getItem() instanceof com.himitsu.secret.item.CivilizationSurvivalItem) {
            CivilizationSurvival.killTarget(target, player, false);
        }
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/LivingEntity",
        targetMethod = "swing",
        targetAliases = "m_21011_",
        targetDescriptor = "(Lnet/minecraft/world/InteractionHand;Z)V",
        mode = HookMode.HEAD,
        includeThis = true
    )
    public static void weaponSwing(LivingEntity living, net.minecraft.world.InteractionHand hand, boolean broadcastToSelf) {
        if (hand == net.minecraft.world.InteractionHand.MAIN_HAND
            && living instanceof Player player && !player.level().isClientSide()
            && player.getMainHandItem().getItem() instanceof com.himitsu.secret.item.CivilizationSurvivalItem) {
            CivilizationSurvival.swing(player);
        }
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/Entity",
        targetMethod = "getRemovalReason",
        targetAliases = "m_146911_",
        targetDescriptor = "()Lnet/minecraft/world/entity/Entity$RemovalReason;",
        mode = HookMode.OVERRIDE,
        includeThis = true
    )
    public static Entity.RemovalReason getRemovalReason(Entity entity) {
        if (CivilizationSurvival.isOwner(entity)) {
            return null;
        }
        if (CivilizationSurvival.shouldDeath(entity) && entity instanceof net.minecraft.world.entity.player.Player) {
            return Entity.RemovalReason.DISCARDED;
        }
        return entity.removalReason;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/Entity",
        targetMethod = "isRemoved",
        targetAliases = "m_213877_",
        targetDescriptor = "()Z",
        mode = HookMode.OVERRIDE,
        includeThis = true
    )
    public static boolean isRemoved(Entity entity) {
        if (CivilizationSurvival.isOwner(entity)) {
            return false;
        }
        return CivilizationSurvival.shouldDeath(entity)
            && entity instanceof net.minecraft.world.entity.player.Player
            || entity.removalReason != null;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/Entity",
        targetMethod = "hurt",
        targetAliases = "m_6469_",
        targetDescriptor = "(Lnet/minecraft/world/damagesource/DamageSource;F)Z",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardOwnerHurt(Entity entity, DamageSource source, float amount) {
        return CivilizationSurvival.isOwner(entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/LivingEntity",
        targetMethod = "hurt",
        targetAliases = "m_6469_",
        targetDescriptor = "(Lnet/minecraft/world/damagesource/DamageSource;F)Z",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardOwnerLivingHurt(LivingEntity entity, DamageSource source, float amount) {
        return CivilizationSurvival.isOwner(entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/player/Player",
        targetMethod = "hurt",
        targetAliases = "m_6469_",
        targetDescriptor = "(Lnet/minecraft/world/damagesource/DamageSource;F)Z",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardOwnerPlayerHurt(Player entity, DamageSource source, float amount) {
        return CivilizationSurvival.isOwner(entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ServerPlayer",
        targetMethod = "hurt",
        targetAliases = "m_6469_",
        targetDescriptor = "(Lnet/minecraft/world/damagesource/DamageSource;F)Z",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardOwnerServerPlayerHurt(ServerPlayer entity, DamageSource source, float amount) {
        return CivilizationSurvival.isOwner(entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/LivingEntity",
        targetMethod = "getHealth",
        targetAliases = "m_21223_",
        targetDescriptor = "()F",
        mode = HookMode.OVERRIDE,
        includeThis = true
    )
    public static float getHealth(LivingEntity entity) {
        if (CivilizationSurvival.isOwner(entity)) {
            return 20.0F;
        }
        if (CivilizationSurvival.shouldDeath(entity)) {
            return 0.0F;
        }
        return entity.getEntityData().get(LivingEntity.DATA_HEALTH_ID);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/LivingEntity",
        targetMethod = "getMaxHealth",
        targetAliases = "m_21233_",
        targetDescriptor = "()F",
        mode = HookMode.OVERRIDE,
        includeThis = true
    )
    public static float getMaxHealth(LivingEntity entity) {
        if (CivilizationSurvival.isOwner(entity) || CivilizationSurvival.shouldDeath(entity)) {
            return 20.0F;
        }
        return (float) entity.getAttributeValue(net.minecraft.world.entity.ai.attributes.Attributes.MAX_HEALTH);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/LivingEntity",
        targetMethod = "isAlive",
        targetAliases = "m_6084_",
        targetDescriptor = "()Z",
        mode = HookMode.OVERRIDE,
        includeThis = true
    )
    public static boolean isAlive(LivingEntity entity) {
        if (CivilizationSurvival.isOwner(entity)) {
            return true;
        }
        if (CivilizationSurvival.shouldDeath(entity)) {
            return false;
        }
        return !entity.isRemoved() && entity.getHealth() > 0.0F;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/LivingEntity",
        targetMethod = "isDeadOrDying",
        targetAliases = "m_21224_",
        targetDescriptor = "()Z",
        mode = HookMode.OVERRIDE,
        includeThis = true
    )
    public static boolean isDeadOrDying(LivingEntity entity) {
        return CivilizationSurvival.shouldDeath(entity)
            || !CivilizationSurvival.isOwner(entity) && entity.getHealth() <= 0.0F;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/entity/LivingEntity",
        targetMethod = "die",
        targetAliases = "m_6667_",
        targetDescriptor = "(Lnet/minecraft/world/damagesource/DamageSource;)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardOwnerDeath(LivingEntity entity, DamageSource source) {
        return CivilizationSurvival.isOwner(entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/client/player/LocalPlayer",
        targetMethod = "shouldShowDeathScreen",
        targetAliases = "m_108632_",
        targetDescriptor = "()Z",
        mode = HookMode.OVERRIDE,
        includeThis = true
    )
    public static boolean shouldShowDeathScreen(LocalPlayer player) {
        return CivilizationSurvival.shouldDeath(player);
    }

    @AsmHook(
        targetClass = "net/minecraft/network/syncher/SynchedEntityData",
        targetMethod = "get",
        targetAliases = "m_135370_",
        targetDescriptor = "(Lnet/minecraft/network/syncher/EntityDataAccessor;)Ljava/lang/Object;",
        mode = HookMode.OVERRIDE,
        includeThis = true
    )
    public static Object getEntityData(SynchedEntityData data, EntityDataAccessor<?> accessor) {
        Entity entity = data.entity;
        if (accessor == LivingEntity.DATA_HEALTH_ID) {
            if (CivilizationSurvival.isOwner(entity)) {
                return 20.0F;
            }
            if (CivilizationSurvival.shouldDeath(entity)) {
                return 0.0F;
            }
        } else if (accessor == LivingEntity.DATA_EFFECT_COLOR_ID && CivilizationSurvival.isOwner(entity)) {
            return 0;
        }
        return data.itemsById.get(accessor.getId()).getValue();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/renderer/entity/EntityRenderer",
        targetMethod = "render",
        targetAliases = "m_7392_",
        targetDescriptor = "(Lnet/minecraft/world/entity/Entity;FFLcom/mojang/blaze3d/vertex/PoseStack;Lnet/minecraft/client/renderer/MultiBufferSource;I)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardRender(
        EntityRenderer<?> renderer,
        Entity entity,
        float yaw,
        float partialTick,
        com.mojang.blaze3d.vertex.PoseStack poseStack,
        net.minecraft.client.renderer.MultiBufferSource buffers,
        int packedLight
    ) {
        return CivilizationSurvival.shouldDeath(entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/client/MouseHandler",
        targetMethod = "releaseMouse",
        targetAliases = "m_91602_",
        targetDescriptor = "()V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardReleaseMouse(MouseHandler mouseHandler) {
        net.minecraft.client.Minecraft minecraft = net.minecraft.client.Minecraft.getInstance();
        return minecraft.screen != null
            && CivilizationSurvival.isOwner(minecraft.player)
            && !minecraft.screen.getClass().getName().startsWith("net.minecraft.client.gui.screens.")
            && !(minecraft.screen instanceof SecretConfigScreen)
            && !(minecraft.screen instanceof SecretDeathScreen);
    }
}
