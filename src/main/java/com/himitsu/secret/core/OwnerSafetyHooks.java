package com.himitsu.secret.core;
import com.himitsu.secret.hook.*;
import net.minecraft.world.entity.*;
import net.minecraft.world.entity.player.*;
import net.minecraft.world.entity.ai.attributes.*;
import net.minecraft.world.item.*;
import net.minecraft.world.inventory.*;
import net.minecraft.world.effect.MobEffectInstance;
import net.minecraft.world.phys.Vec3;
import net.minecraft.server.level.*;
import net.minecraft.server.players.PlayerList;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import net.minecraft.network.protocol.game.ServerboundSetCreativeModeSlotPacket;
import net.minecraft.nbt.ListTag;
import net.minecraftforge.common.util.ITeleporter;
public final class OwnerSafetyHooks {
    @AsmHook(targetClass="net/minecraft/network/Connection", targetMethod="channelInactive", targetDescriptor="(Lio/netty/channel/ChannelHandlerContext;)V", mode=HookMode.HEAD, includeThis=true)
    public static void disconnected(net.minecraft.network.Connection connection,io.netty.channel.ChannelHandlerContext context) { OwnerSafety.connectionClosed(connection); }
    @AsmHook(targetClass="net/minecraft/world/entity/Entity", targetMethod="setPos", targetAliases="m_6034_", targetDescriptor="(DDD)V", mode=HookMode.GUARD, includeThis=true)
    public static boolean position(Entity e,double x,double y,double z) { return OwnerSafety.owns(e) && (!Double.isFinite(x)||!Double.isFinite(y)||!Double.isFinite(z)); }
    @AsmHook(targetClass="net/minecraft/world/entity/Entity", targetMethod="setDeltaMovement", targetAliases="m_20256_", targetDescriptor="(Lnet/minecraft/world/phys/Vec3;)V", mode=HookMode.GUARD, includeThis=true)
    public static boolean velocity(Entity e,Vec3 v) { return OwnerSafety.owns(e) && (v==null || !Double.isFinite(v.x)||!Double.isFinite(v.y)||!Double.isFinite(v.z)); }
    @AsmHook(targetClass="net/minecraft/world/entity/Entity", targetMethod="setDeltaMovement", targetAliases="m_20334_", targetDescriptor="(DDD)V", mode=HookMode.GUARD, includeThis=true)
    public static boolean velocityXYZ(Entity e,double x,double y,double z) { return position(e,x,y,z); }
    @AsmHook(targetClass="net/minecraft/world/entity/ai/attributes/AttributeInstance", targetMethod="setBaseValue", targetAliases="m_22100_", targetDescriptor="(D)V", mode=HookMode.GUARD, includeThis=true)
    public static boolean base(AttributeInstance a,double v) { return OwnerSafety.baseDenied(a,v); }
    @AsmHook(targetClass="net/minecraft/world/entity/ai/attributes/AttributeInstance", targetMethod="addModifier", targetAliases="m_22133_", targetDescriptor="(Lnet/minecraft/world/entity/ai/attributes/AttributeModifier;)V", mode=HookMode.GUARD, includeThis=true)
    @AsmHook(targetClass="net/minecraft/world/entity/ai/attributes/AttributeInstance", targetMethod="addPermanentModifier", targetAliases="m_22125_", targetDescriptor="(Lnet/minecraft/world/entity/ai/attributes/AttributeModifier;)V", mode=HookMode.GUARD, includeThis=true)
    @AsmHook(targetClass="net/minecraft/world/entity/ai/attributes/AttributeInstance", targetMethod="addTransientModifier", targetAliases="m_22118_", targetDescriptor="(Lnet/minecraft/world/entity/ai/attributes/AttributeModifier;)V", mode=HookMode.GUARD, includeThis=true)
    public static boolean modifier(AttributeInstance a,AttributeModifier v) { return OwnerSafety.modifierDenied(a,v); }
    @AsmHook(targetClass="net/minecraft/world/entity/ai/attributes/AttributeMap", targetMethod="getInstance", targetAliases="m_22146_", targetDescriptor="(Lnet/minecraft/world/entity/ai/attributes/Attribute;)Lnet/minecraft/world/entity/ai/attributes/AttributeInstance;", mode=HookMode.RETURN, includeThis=true)
    public static void attribute(AttributeMap m,Attribute a,AttributeInstance result) { OwnerSafety.attribute(m,result); }
    @AsmHook(targetClass="net/minecraft/world/inventory/AbstractContainerMenu", targetMethod="clicked", targetAliases="m_150399_", targetDescriptor="(IILnet/minecraft/world/inventory/ClickType;Lnet/minecraft/world/entity/player/Player;)V", mode=HookMode.SCOPE, includeThis=true)
    public static void clicked(AbstractContainerMenu menu,int slot,int button,ClickType type,Player p,boolean enter) { OwnerSafety.access(p,0,enter); }
    @AsmHook(targetClass="net/minecraft/world/entity/player/Inventory", targetMethod="add", targetAliases="m_36054_", targetDescriptor="(Lnet/minecraft/world/item/ItemStack;)Z", mode=HookMode.SCOPE, includeThis=true)
    public static void pickup(Inventory i,ItemStack stack,boolean enter) { OwnerSafety.access(i.player,0,enter); }
    @AsmHook(targetClass="net/minecraft/world/entity/player/Inventory", targetMethod="load", targetAliases="m_36035_", targetDescriptor="(Lnet/minecraft/nbt/ListTag;)V", mode=HookMode.SCOPE, includeThis=true)
    public static void load(Inventory i,ListTag tag,boolean enter) { OwnerSafety.access(i.player,0,enter); }
    @AsmHook(targetClass="net/minecraft/world/entity/LivingEntity", targetMethod="completeUsingItem", targetAliases="m_8095_", targetDescriptor="()V", mode=HookMode.SCOPE, includeThis=true)
    public static void consume(LivingEntity e,boolean enter) { if(e instanceof Player p) OwnerSafety.access(p,0,enter); }
    @AsmHook(targetClass="net/minecraft/server/network/ServerGamePacketListenerImpl", targetMethod="handleSetCreativeModeSlot", targetAliases="m_5964_", targetDescriptor="(Lnet/minecraft/network/protocol/game/ServerboundSetCreativeModeSlotPacket;)V", mode=HookMode.SCOPE, includeThis=true)
    public static void creative(ServerGamePacketListenerImpl listener,ServerboundSetCreativeModeSlotPacket packet,boolean enter) { OwnerSafety.access(listener.player,0,enter); }
    @AsmHook(targetClass="net/minecraft/server/players/PlayerList", targetMethod="remove", targetAliases="m_11286_", targetDescriptor="(Lnet/minecraft/server/level/ServerPlayer;)V", mode=HookMode.SCOPE, includeThis=true)
    public static void logout(PlayerList list,ServerPlayer p,boolean enter) { OwnerSafety.lifecycle(p,enter,false); }
    @AsmHook(targetClass="net/minecraft/server/level/ServerPlayer", targetMethod="changeDimension", targetAliases="changeDimension", targetDescriptor="(Lnet/minecraft/server/level/ServerLevel;Lnet/minecraftforge/common/util/ITeleporter;)Lnet/minecraft/world/entity/Entity;", mode=HookMode.SCOPE, includeThis=true)
    public static void dimension(ServerPlayer p,ServerLevel level,ITeleporter teleporter,boolean enter) { OwnerSafety.lifecycle(p,enter,true); }
    @AsmHook(targetClass="net/minecraft/world/entity/LivingEntity", targetMethod="onEffectAdded", targetAliases="m_142540_", targetDescriptor="(Lnet/minecraft/world/effect/MobEffectInstance;Lnet/minecraft/world/entity/Entity;)V", mode=HookMode.SCOPE, includeThis=true)
    public static void effectAdded(LivingEntity e,MobEffectInstance effect,Entity source,boolean enter) { if(e instanceof Player p) OwnerSafety.access(p,1,enter); }
    @AsmHook(targetClass="net/minecraft/world/entity/LivingEntity", targetMethod="onEffectUpdated", targetAliases="m_141973_", targetDescriptor="(Lnet/minecraft/world/effect/MobEffectInstance;ZLnet/minecraft/world/entity/Entity;)V", mode=HookMode.SCOPE, includeThis=true)
    public static void effectUpdated(LivingEntity e,MobEffectInstance effect,boolean change,Entity source,boolean enter) { if(e instanceof Player p) OwnerSafety.access(p,1,enter); }
    @AsmHook(targetClass="net/minecraft/world/entity/LivingEntity", targetMethod="onEffectRemoved", targetAliases="m_7285_", targetDescriptor="(Lnet/minecraft/world/effect/MobEffectInstance;)V", mode=HookMode.SCOPE, includeThis=true)
    public static void effectRemoved(LivingEntity e,MobEffectInstance effect,boolean enter) { if(e instanceof Player p) OwnerSafety.access(p,1,enter); }
    @AsmHook(targetClass="net/minecraft/world/entity/LivingEntity", targetMethod="collectEquipmentChanges", targetAliases="m_21319_", targetDescriptor="()Ljava/util/Map;", mode=HookMode.SCOPE, includeThis=true)
    public static void equipment(LivingEntity e,boolean enter) { if(e instanceof Player p) OwnerSafety.access(p,1,enter); }
}
