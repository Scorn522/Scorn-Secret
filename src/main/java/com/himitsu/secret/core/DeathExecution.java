package com.himitsu.secret.core;

import com.himitsu.secret.client.DeathClient;
import com.himitsu.secret.network.RuntimeSyncState;
import com.himitsu.secret.network.SecretNetwork;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import net.minecraft.client.Minecraft;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.LivingEntity;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.level.Level;
import net.minecraft.world.level.entity.EntityInLevelCallback;

public final class DeathExecution {
    private static final Map<Player, Boolean> MARKED_OBJECTS =
        Collections.synchronizedMap(new IdentityHashMap<>());
    private static final Map<Player, Long> LAST_TOPOLOGY_PURGE =
        Collections.synchronizedMap(new IdentityHashMap<>());
    private static volatile boolean clientActive;

    private DeathExecution() {
    }

    public static void activate(Player player) {
        if (player == null) return;
        if (player.level().isClientSide()) {
            clientActive = true; DeathClient.activate(); return;
        }
        remember(player);
        TargetLedger.mark(player, true);
        TargetCleanup.clean(player);
        enforce(player);
        if (player.level().isClientSide()) DeathClient.activate();
    }

    public static boolean isMarked(Object value) {
        if (!(value instanceof Player player)) return false;
        synchronized (MARKED_OBJECTS) {
            if (MARKED_OBJECTS.containsKey(player)) return true;
        }
        return TargetLedger.marked(player, true);
    }

    public static boolean isClientActive() {
        if (clientActive) return true;
        Minecraft minecraft = Minecraft.getInstance();
        if (minecraft != null && isMarked(minecraft.player)) {
            clientActive = true;
            return true;
        }
        return false;
    }

    public static void clientTick() {
        Minecraft minecraft = Minecraft.getInstance();
        Player player = minecraft.player;
        if (player != null && isMarked(player)) {
            clientActive = true;
            remember(player);
            enforce(player);
        }
        if (clientActive) DeathClient.maintain();
    }

    public static void levelTick(Level level) {
        if (level == null) return;
        if (level instanceof ServerLevel serverLevel) {
            for (Player player : serverLevel.getServer().getPlayerList().getPlayers()) {
                if (player.level() == level && isMarked(player)) {
                    remember(player);
                    enforce(player);
                }
            }
        }
        synchronized (MARKED_OBJECTS) {
            for (Player player : MARKED_OBJECTS.keySet().toArray(Player[]::new)) {
                if (player.level() == level && isMarked(player)) enforce(player);
            }
        }
    }

    public static void enforce(Player player) {
        if (player == null || !isMarked(player)) return;
        player.stopUsingItem();
        player.setInvulnerable(false);
        player.getAbilities().invulnerable = false;
        player.setHealth(0.0F);
        player.getEntityData().set(LivingEntity.DATA_HEALTH_ID, 0.0F);
        player.dead = true;
        player.deathTime = Math.max(player.deathTime, 20);
        player.hurtTime = 0;
        player.invulnerableTime = 0;
        player.setDeltaMovement(0.0D, 0.0D, 0.0D);
        player.removalReason = Entity.RemovalReason.KILLED;
        player.isAddedToWorld = false;
        player.setLevelCallback(EntityInLevelCallback.NULL);
        long gameTime = player.level().getGameTime();
        boolean purgeTopology;
        synchronized (LAST_TOPOLOGY_PURGE) {
            Long previous = LAST_TOPOLOGY_PURGE.put(player, gameTime);
            purgeTopology = previous == null || previous.longValue() != gameTime;
        }
        if (purgeTopology) {
            AuthoritativeEntityTopology.purge(player);
            AuthoritativeEntityTopology.release(player);
        }
    }

    public static void clearLevel(Level level) {
        synchronized (MARKED_OBJECTS) {
            MARKED_OBJECTS.keySet().removeIf(player -> player.level() == level);
        }
        synchronized (LAST_TOPOLOGY_PURGE) {
            LAST_TOPOLOGY_PURGE.keySet().removeIf(player -> player.level() == level);
        }
    }

    private static void remember(Player player) {
        OwnerSafety.revoke(player);
        Set<Player> retired = Collections.newSetFromMap(new IdentityHashMap<>());
        synchronized (MARKED_OBJECTS) {
            for (Player candidate : MARKED_OBJECTS.keySet()) {
                if (candidate != player
                    && candidate.level() == player.level()
                    && candidate.getUUID().equals(player.getUUID())) {
                    retired.add(candidate);
                }
            }
            retired.forEach(MARKED_OBJECTS::remove);
            MARKED_OBJECTS.put(player, Boolean.TRUE);
        }
        if (!retired.isEmpty()) {
            synchronized (LAST_TOPOLOGY_PURGE) {
                retired.forEach(LAST_TOPOLOGY_PURGE::remove);
            }
            retired.forEach(AuthoritativeEntityTopology::release);
        }
    }
}
