package com.himitsu.secret.core;

import com.himitsu.secret.client.DeathClient;
import java.util.*;
import net.minecraft.client.Minecraft;
import net.minecraft.network.Connection;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.LivingEntity;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.level.Level;
import net.minecraft.world.level.entity.EntityInLevelCallback;

public final class DeathExecution {
    // Arrays hold the last maintenance tick and the ready flag; allocated only on registration.
    private static volatile Map<Player,int[]> MARKED_OBJECTS=new IdentityHashMap<>();
    private static volatile Map<Level,Player[]> WORLDS=new IdentityHashMap<>();
    private static volatile Map<Player,Level> LEVELS=new IdentityHashMap<>();
    private static final Map<Player,Connection> CONNECTIONS=new IdentityHashMap<>();
    private static volatile boolean clientActive;
    private static volatile Connection clientConnection;
    private DeathExecution() {}

    public static void activate(Player player) {
        if(player==null || !AuthoritativeEntityTopology.open(player.level())) return;
        if(player.level().isClientSide()) {
            var listener=Minecraft.getInstance().getConnection();
            clientConnection=listener==null ? null : listener.getConnection();
            clientActive=true; DeathClient.activate(); return;
        }
        remember(player,true);
        TargetLedger.mark(player,true);
        TargetCleanup.clean(player);
        enforce(player);
    }
    public static boolean isMarked(Object value) {
        if(!(value instanceof Player player)) return false;
        return MARKED_OBJECTS.containsKey(player) || TargetLedger.marked(player,true);
    }
    public static boolean isClientActive() { return clientActive; }
    static boolean sameSession(Player original,Player replacement) {
        return original instanceof ServerPlayer a && replacement instanceof ServerPlayer b
            && !(a instanceof net.minecraftforge.common.util.FakePlayer) && !(b instanceof net.minecraftforge.common.util.FakePlayer)
            && a.server==b.server && a.connection!=null && a.connection==b.connection
            && a.connection.connection!=null && a.connection.connection.isConnected() && a.uuid.equals(b.uuid);
    }
    public static synchronized void onPlayerClone(Player original,Player replacement) {
        if(!isMarked(original) || !sameSession(original,replacement)) return;
        remove(original); remember(replacement,false);
    }
    public static void onPlayerReady(Player player) {
        if(player==null || !AuthoritativeEntityTopology.open(player.level()) || !isMarked(player)) return;
        if(player instanceof ServerPlayer server && (server.connection==null || server.connection.player!=server
            || server.server.getPlayerList().getPlayer(server.uuid)!=server || !server.connection.connection.isConnected())) return;
        remember(player,true);
        if(!player.level().isClientSide() && !TargetLedger.marked(player,true)) TargetLedger.mark(player,true);
        enforce(player);
    }
    public static void clientTick() {
        Minecraft client=Minecraft.getInstance(); Player player=client.player;
        if(player!=null && isMarked(player)) {
            var connection=client.getConnection();
            if(connection!=null) clientConnection=connection.getConnection();
            clientActive=true;
            if(!MARKED_OBJECTS.containsKey(player)) remember(player,true);
            enforce(player);
        }
        if(clientActive) DeathClient.maintain();
    }
    public static void levelTick(Level level) {
        if(!AuthoritativeEntityTopology.open(level)) return;
        Player[] players=WORLDS.get(level); if(players==null) return;
        for(int i=0;i<players.length;i++) enforce(players[i]);
    }
    public static void enforce(Player player) {
        if(player==null || !AuthoritativeEntityTopology.open(player.level())) return;
        int[] state=MARKED_OBJECTS.get(player);
        if(state==null || state[1]==0 || LEVELS.get(player)!=player.level()) return;
        int tick=player instanceof ServerPlayer server ? server.server.getTickCount() : player.tickCount;
        if(state[0]==tick) return;
        state[0]=tick;
        if(player.isUsingItem()) player.stopUsingItem();
        player.setInvulnerable(false); player.getAbilities().invulnerable=false;
        var item=player.getEntityData().itemsById.get(LivingEntity.DATA_HEALTH_ID.getId());
        if(item!=null && ((Float)item.getValue()).floatValue()!=0.0F) player.getEntityData().set(LivingEntity.DATA_HEALTH_ID,0.0F);
        player.dead=true; player.deathTime=Math.max(player.deathTime,20);
        player.hurtTime=0; player.invulnerableTime=0;
        if(player.getDeltaMovement()!=net.minecraft.world.phys.Vec3.ZERO) player.setDeltaMovement(net.minecraft.world.phys.Vec3.ZERO);
        player.removalReason=Entity.RemovalReason.KILLED; player.isAddedToWorld=false;
        player.setLevelCallback(EntityInLevelCallback.NULL);
        if(AuthoritativeEntityTopology.present(player)) AuthoritativeEntityTopology.purge(player);
        AuthoritativeEntityTopology.release(player);
    }
    private static synchronized void remember(Player player,boolean ready) {
        OwnerSafety.revoke(player);
        int[] existing=MARKED_OBJECTS.get(player);
        if(existing!=null && LEVELS.get(player)==player.level()) { if(ready) existing[1]=1; return; }
        var next=new IdentityHashMap<>(MARKED_OBJECTS);
        next.put(player,new int[]{Integer.MIN_VALUE,ready?1:0});
        var levels=new IdentityHashMap<>(LEVELS); levels.put(player,player.level()); LEVELS=levels;
        if(player instanceof ServerPlayer server && server.connection!=null) CONNECTIONS.put(player,server.connection.connection);
        else if(player.level().isClientSide()) CONNECTIONS.put(player,clientConnection);
        publish(next);
    }
    private static void publish(Map<Player,int[]> next) {
        var grouped=new IdentityHashMap<Level,List<Player>>();
        for(Player player:next.keySet()) grouped.computeIfAbsent(LEVELS.get(player),k->new ArrayList<>()).add(player);
        var worlds=new IdentityHashMap<Level,Player[]>();
        for(var e:grouped.entrySet()) worlds.put(e.getKey(),e.getValue().toArray(Player[]::new));
        MARKED_OBJECTS=next; WORLDS=worlds;
    }
    private static void remove(Player player) {
        if(!MARKED_OBJECTS.containsKey(player)) return;
        var next=new IdentityHashMap<>(MARKED_OBJECTS); next.remove(player);
        var levels=new IdentityHashMap<>(LEVELS); levels.remove(player); LEVELS=levels; CONNECTIONS.remove(player); publish(next);
        AuthoritativeEntityTopology.release(player);
    }
    public static synchronized void connectionClosed(Connection connection) {
        if(connection==null) return;
        for(Player player:MARKED_OBJECTS.keySet()) if(CONNECTIONS.get(player)==connection) remove(player);
        if(clientConnection==connection) { clientActive=false; clientConnection=null; }
    }
    public static synchronized void clearLevel(Level level) {
        for(Player player:MARKED_OBJECTS.keySet()) if(LEVELS.get(player)==level) remove(player);
    }
}
