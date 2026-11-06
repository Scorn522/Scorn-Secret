package com.himitsu.secret.core;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import net.minecraft.world.entity.*;
import net.minecraft.world.entity.ai.attributes.*;
import net.minecraft.world.entity.player.*;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.level.Level;

/** Identity snapshots are published only at registration/lifecycle boundaries. */
public final class OwnerSafety {
    private static volatile Map<Player,Binding> owners=new IdentityHashMap<>();
    private static final Map<AttributeInstance,Binding> ATTRIBUTES=new ConcurrentHashMap<>();
    private static final ThreadLocal<ArrayDeque<Access>> ACCESS=new ThreadLocal<>();
    private record Access(Player player,int kind,boolean owner,Binding previous) {}
    private static final class Binding {
        final Player player; final Level level; final Object session; final net.minecraft.network.Connection connection;
        final AttributeMap attributes;
        volatile boolean active=true, owner;
        ItemStack weapon=ItemStack.EMPTY; int weaponSlot=-1, nextCheck;
        Binding(Player player,Object session,Binding previous) {
            this.player=player; this.level=player.level(); this.session=session; attributes=player.getAttributes();
            connection=session instanceof net.minecraft.server.network.ServerGamePacketListenerImpl server
                ? server.connection : ((net.minecraft.client.multiplayer.ClientPacketListener)session).getConnection();
            if(previous!=null) { weapon=previous.weapon; weaponSlot=previous.weaponSlot; }
            nextCheck=player.tickCount+20;
        }
        void weapon(boolean legitimate) {
            nextCheck=player.tickCount+20;
            if(!(player instanceof net.minecraft.server.level.ServerPlayer)) return;
            Inventory inventory=player.getInventory();
            int slot=weaponSlot>=0 && weaponSlot<inventory.getContainerSize() && blade(inventory.getItem(weaponSlot)) ? weaponSlot : -1;
            if(slot<0) for(int i=0;i<inventory.getContainerSize();i++) if(blade(inventory.getItem(i))) { slot=i; break; }
            ItemStack present=slot>=0 ? inventory.getItem(slot) : player.containerMenu==null ? ItemStack.EMPTY : player.containerMenu.getCarried();
            if(blade(present)) {
                if(weapon.isEmpty() || !ItemStack.isSameItemSameTags(weapon,present)) { weapon=present.copy(); weapon.setCount(1); }
                weaponSlot=slot; return;
            }
            if(legitimate) { weapon=ItemStack.EMPTY; weaponSlot=-1; return; }
            if(weapon.isEmpty()) return;
            slot=weaponSlot>=0 && weaponSlot<inventory.items.size() && inventory.getItem(weaponSlot).isEmpty() ? weaponSlot : inventory.getFreeSlot();
            if(slot<0) return;
            inventory.setItem(slot,weapon.copy()); weaponSlot=slot; inventory.setChanged();
            if(player.containerMenu!=null) player.containerMenu.broadcastChanges();
        }
    }
    private OwnerSafety() {}
    private static boolean blade(ItemStack stack) { return stack!=null && !stack.isEmpty() && stack.getItem() instanceof com.himitsu.secret.item.CivilizationSurvivalItem; }
    private static Object session(Player player) {
        if(player==null || player instanceof net.minecraftforge.common.util.FakePlayer || player.level()==null) return null;
        if(player instanceof net.minecraft.server.level.ServerPlayer server)
            return server.connection!=null && server.connection.player==server && server.connection.connection!=null && server.connection.connection.isConnected()
                && server.server!=null && server.server.getPlayerList()!=null && server.server.getPlayerList().getPlayer(server.uuid)==server ? server.connection : null;
        if(player instanceof net.minecraft.client.player.AbstractClientPlayer) {
            var client=net.minecraft.client.Minecraft.getInstance(); var connection=client.getConnection();
            if(connection!=null && client.level!=null && player.level()==client.level && connection.getConnection().isConnected()
                && (client.player==player || connection.getPlayerInfo(player.uuid)!=null)
                && client.level.entityStorage.entityStorage.byId.get(player.getId())==player) return connection;
        }
        return null;
    }
    public static boolean owns(Object value) { if(!(value instanceof Player)) return false; Binding b=owners.get(value); return b!=null && b.active && b.owner; }
    static boolean authenticated(Player player) { Binding b=owners.get(player); return b!=null && b.active; }
    public static boolean registerSession(Player player) {
        Binding b=owners.get(player); return b!=null ? b.active && b.level==player.level() : registerSession(player,null);
    }
    public static void refreshDeaths() {
        for(Binding b:owners.values()) if(b.owner && TargetLedger.marked(b.player,true)) b.owner=false;
    }
    private static synchronized boolean registerSession(Player player,Binding previous) {
        Binding current=owners.get(player);
        if(current!=null) return current.active && current.level==player.level();
        if(player==null || inLifecycle(player)) return false;
        Object session=session(player); if(session==null) return false;
        var next=new IdentityHashMap<>(owners); next.put(player,new Binding(player,session,previous)); owners=next; return true;
    }
    static synchronized void bind(Player player) {
        if(player==null || DeathExecution.isMarked(player) || !registerSession(player)) return;
        Binding b=owners.get(player); if(b.owner) return;
        for(AttributeInstance attribute:b.attributes.attributes.values()) ATTRIBUTES.put(attribute,b);
        b.owner=true; b.weapon(false);
    }
    static void pruneClient(Level level) {
        if(level instanceof net.minecraft.client.multiplayer.ClientLevel client)
            for(Binding b:owners.values()) if(b.level==level && !b.owner && client.entityStorage.entityStorage.byId.get(b.player.getId())!=b.player) release(b.player);
    }
    public static void revoke(Player player) { Binding b=owners.get(player); if(b!=null) b.owner=false; }
    public static void connectionClosed(net.minecraft.network.Connection connection) {
        for(Binding b:owners.values()) if(b.connection==connection) b.active=false;
    }
    static synchronized void release(Player player) {
        Binding b=owners.get(player); if(b==null) return;
        b.active=false;
        var next=new IdentityHashMap<>(owners); next.remove(player); owners=next;
        ATTRIBUTES.entrySet().removeIf(e->e.getValue()==b);
    }
    static synchronized void clearLevel(Level level) {
        for(Binding b:owners.values()) if(b.level==level) release(b.player);
    }
    static void maintainWeapon(Player player) {
        Binding b=owners.get(player);
        if(b!=null && b.active && b.owner && player.tickCount-b.nextCheck>=0) b.weapon(false);
    }
    static void weaponChanged(Player player) { Binding b=owners.get(player); if(b!=null) b.nextCheck=player.tickCount; }
    public static void access(Player player,int kind,boolean enter) {
        if(player==null) return;
        ArrayDeque<Access> stack=ACCESS.get();
        if(enter) {
            if(stack==null) { stack=new ArrayDeque<>(); ACCESS.set(stack); }
            stack.push(new Access(player,kind,false,null));
        } else if(stack!=null && !stack.isEmpty()) {
            Access last=stack.peek(); if(last.player()!=player || last.kind()!=kind) return;
            stack.pop(); if(stack.isEmpty()) ACCESS.remove();
            Binding b=owners.get(player);
            if(kind==0 && b!=null && b.active && b.owner && !allowed(player,0)) b.weapon(true);
        }
    }
    public static void lifecycle(Player player,boolean enter,boolean restore) {
        ArrayDeque<Access> stack=ACCESS.get();
        if(enter) {
            Binding b=owners.get(player); boolean owned=b!=null && b.owner;
            if(stack==null) { stack=new ArrayDeque<>(); ACCESS.set(stack); }
            stack.push(new Access(player,2,owned,b));
            if(owned) CivilizationSurvival.detachOwner(player,!restore); else release(player);
        } else if(stack!=null && !stack.isEmpty()) {
            Access frame=stack.peek(); if(frame.player()!=player || frame.kind()!=2) return;
            stack.pop(); if(stack.isEmpty()) ACCESS.remove();
            if(restore && registerSession(player,frame.previous()) && frame.owner()) CivilizationSurvival.registerOwner(player);
        }
    }
    private static boolean allowed(Player player,int kind) {
        var stack=ACCESS.get(); if(stack!=null) for(Access a:stack) if(a.player()==player && (a.kind()==kind || a.kind()==2)) return true;
        return false;
    }
    static boolean inLifecycle(Player player) { return allowed(player,2); }
    static boolean returningOwner(Player player) {
        var stack=ACCESS.get();
        if(stack!=null) for(Access a:stack) if(a.player()==player && a.kind()==2 && a.owner()) return session(player)!=null;
        return false;
    }
    public static void attribute(AttributeMap map,AttributeInstance value) {
        if(value==null || ATTRIBUTES.containsKey(value)) return;
        for(Binding b:owners.values()) if(b.active && b.owner && b.attributes==map) { ATTRIBUTES.putIfAbsent(value,b); return; }
    }
    static boolean baseDenied(AttributeInstance instance,double value) {
        Binding b=ATTRIBUTES.get(instance); if(b==null || !owns(b.player) || allowed(b.player,1)) return false;
        if(!Double.isFinite(value)) return true;
        Attribute a=instance.getAttribute();
        return (a==Attributes.MAX_HEALTH || a==Attributes.MOVEMENT_SPEED || a==Attributes.ATTACK_SPEED) ? value<=0 : combat(a) && value<0;
    }
    static boolean modifierDenied(AttributeInstance instance,AttributeModifier modifier) {
        Binding b=ATTRIBUTES.get(instance);
        return b!=null && owns(b.player) && !allowed(b.player,1)
            && (!Double.isFinite(modifier.getAmount()) || combat(instance.getAttribute()) && modifier.getAmount()<0);
    }
    private static boolean combat(Attribute a) {
        return a==Attributes.MAX_HEALTH || a==Attributes.MOVEMENT_SPEED || a==Attributes.ATTACK_DAMAGE
            || a==Attributes.ATTACK_SPEED || a==Attributes.ARMOR || a==Attributes.ARMOR_TOUGHNESS
            || a==Attributes.KNOCKBACK_RESISTANCE || a==Attributes.LUCK;
    }
}
