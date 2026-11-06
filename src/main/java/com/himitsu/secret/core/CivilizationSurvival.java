package com.himitsu.secret.core;

import com.himitsu.secret.content.SecretContent;
import com.himitsu.secret.entity.SecretEntity;
import com.himitsu.secret.network.RuntimeSyncState;
import com.himitsu.secret.network.SecretNetwork;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.List;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientLevel;
import net.minecraft.core.SectionPos;
import net.minecraft.core.registries.BuiltInRegistries;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.level.Level;
import net.minecraft.world.phys.AABB;
import net.minecraft.world.phys.Vec3;
import net.minecraft.world.level.entity.EntityInLevelCallback;
import net.minecraft.world.level.entity.EntitySection;
import net.minecraftforge.event.TickEvent;
import net.minecraftforge.entity.PartEntity;
import net.minecraftforge.event.entity.item.ItemTossEvent;
import net.minecraftforge.server.ServerLifecycleHooks;

public final class CivilizationSurvival {
    private static volatile Map<Level,Map<UUID,Player>> OWNER_OBJECTS=new IdentityHashMap<>();
    private static Set<String> clientOwners;
    private static Level clientLevel;
    private static int clientPlayers;
    private static volatile boolean clientOwnersDirty;
    private CivilizationSurvival() {
    }

    public static void release(Level level, Player player) {
        if (level.isClientSide()) return;

        registerOwner(player);
        if (level instanceof ServerLevel serverLevel) {
            for (ServerLevel loadedLevel : serverLevel.getServer().getAllLevels()) {
                sweep(loadedLevel);
            }
        }

        RuntimeSyncState.CIVILIZATION_ATTACKING.set(false);
        SecretNetwork.sendAll(RuntimeSyncState.CIVILIZATION_OWNERS);
        SecretNetwork.sendAll(RuntimeSyncState.CIVILIZATION_ATTACKING);
    }

    public static void levelTick(TickEvent.LevelTickEvent event) {
        if (event.phase != TickEvent.Phase.END) {
            return;
        }
        if(!AuthoritativeEntityTopology.open(event.level)) return;
        SecretEntityHooks.registerLevel(event.level);
        DeathExecution.levelTick(event.level);
        if (event.level instanceof ServerLevel serverLevel) {
            if(serverLevel.getGameTime()%20==0) registerOwners(serverLevel.players());
            maintainOwners(serverLevel);
            SecretEntityRegistry.maintain(serverLevel);
            TargetLedger.inspect(serverLevel);
            TargetCleanup.retryPending(serverLevel);
        }
    }

    public static boolean isAttacking() {
        return RuntimeSyncState.CIVILIZATION_ATTACKING.get();
    }

    public static boolean isOwner(Entity entity) {
        return OwnerSafety.owns(entity);
    }

    public static Collection<Player> owners(Level level) {
        Map<UUID,Player> current=OWNER_OBJECTS.get(level);
        return current==null ? List.of() : current.values();
    }

    public static Player owner(Level level, UUID uuid) {
        for (Player player : owners(level)) {
            if (AuthoritativeEntityTopology.capturedUuid(player).equals(uuid)) return player;
        }
        return null;
    }

    public static Player owner(Level level, int id) {
        for (Player player : owners(level)) {
            if (AuthoritativeEntityTopology.capturedId(player) == id) return player;
        }
        return null;
    }

    public static void clientTick() {
        Minecraft minecraft = Minecraft.getInstance();
        DeathExecution.clientTick();
        if (minecraft.level == null) return;
        Set<String> snapshot=RuntimeSyncState.CIVILIZATION_OWNERS.snapshot();
        int count=minecraft.level.players().size();
        if(clientOwnersDirty || clientLevel!=minecraft.level || clientOwners!=snapshot || clientPlayers!=count) {
            clientOwnersDirty=false; clientLevel=minecraft.level; clientOwners=snapshot; clientPlayers=count;
            refreshOwners(minecraft.level);
        }
        maintainOwner(minecraft.player);
        SecretEntityRegistry.maintain(minecraft.level);
    }

    public static void ownersChanged() { clientOwnersDirty=true; }

    public static synchronized void clearLevel(Level level) {
        AuthoritativeEntityTopology.clearLevel(level);
        TargetCleanup.clearLevel(level);
        var next=new IdentityHashMap<>(OWNER_OBJECTS); next.remove(level); OWNER_OBJECTS=next;
        if(clientLevel==level) { clientLevel=null; clientOwners=null; clientOwnersDirty=true; }
        DeathExecution.clearLevel(level);
        OwnerSafety.clearLevel(level);
        TargetLedger.clearLevel(level);
    }

    public static boolean shouldDeath(Object value) {
        if (!(value instanceof Entity entity) || entity instanceof SecretEntity) return false;
        if (DeathExecution.isMarked(entity)) return true;
        if (isOwner(entity)) return false;
        return TargetLedger.marked(entity);
    }

    public static boolean shouldRender(Entity entity) {
        return !shouldDeath(entity);
    }

    public static void maintainGlobal() {
        AuthoritativeEntityTopology.maintainAll();
    }

    public static void maintainLocalPlayer() {
        Minecraft minecraft = Minecraft.getInstance();
        maintainOwner(minecraft.player);
    }

    public static void maintainClientLevel() {
        Minecraft minecraft = Minecraft.getInstance();
        if (minecraft.level != null) {
            maintainLevel(minecraft.level);
        }
    }

    public static void maintainServerLevels() {
        if (ServerLifecycleHooks.getCurrentServer() == null) {
            return;
        }
        for (ServerLevel level : ServerLifecycleHooks.getCurrentServer().getAllLevels()) {
            maintainLevel(level);
        }
    }

    public static void maintainGui() {
        Minecraft minecraft = Minecraft.getInstance();
        if (isOwner(minecraft.player) && minecraft.player.containerMenu == null) {
            minecraft.player.containerMenu = minecraft.player.inventoryMenu;
        }
    }

    public static void registerOwner(Player player) {
        if(player==null || isOwner(player)) return;
        if(DeathExecution.isMarked(player) || !OwnerSafety.registerSession(player)) return;
        rememberOwner(player);
        if(!player.level().isClientSide() && isOwner(player)) {
            Set<String> owners=new HashSet<>(RuntimeSyncState.CIVILIZATION_OWNERS.snapshot());
            owners.removeIf(value->value.startsWith("name:")); owners.add(player.uuid.toString());
            replaceOwners(owners);
        }
    }

    public static void killTarget(Entity target, Player owner, boolean persistent) {
        if(target==null || target.level().isClientSide()) return;
        registerOwner(owner);
        executeTargets(relatedTargets(List.of(target)));
    }

    static List<Entity> relatedTargets(Collection<Entity> seeds) {
        Set<Entity> seen=Collections.newSetFromMap(new IdentityHashMap<>());
        Set<Entity> ancestry=Collections.newSetFromMap(new IdentityHashMap<>());
        java.util.ArrayDeque<Entity> pending=new java.util.ArrayDeque<>();
        List<Entity> targets=new ArrayList<>();
        for(Entity seed:seeds) {
            Entity root=seed; ancestry.clear();
            while(root instanceof PartEntity<?> part && part.getParent()!=null && ancestry.add(root)) root=part.getParent();
            if(root==null || root instanceof SecretEntity || isOwner(root)) continue;
            pending.add(root);
            while(!pending.isEmpty()) {
                Entity entity=pending.removeFirst();
                if(!seen.add(entity) || entity.level()!=root.level() || entity instanceof SecretEntity || isOwner(entity)) continue;
                targets.add(entity);
                if(entity instanceof PartEntity<?> part && part.getParent()!=null) pending.add(part.getParent());
                PartEntity<?>[] parts=entity.isMultipartEntity() ? entity.getParts() : null;
                if(parts!=null) for(PartEntity<?> part:parts) if(part!=null && part.getParent()==entity) pending.add(part);
            }
        }
        return targets;
    }

    private static void executeTargets(List<Entity> targets) {
        List<Entity> fresh=new ArrayList<>(), cleaning=new ArrayList<>();
        for(Entity target:targets) {
            if(!TargetLedger.marked(target)) { fresh.add(target); cleaning.add(target); }
            else if(TargetCleanup.isIncomplete(target)) cleaning.add(target);
        }
        TargetLedger.markAll(fresh,false);
        for(Entity target:cleaning) TargetCleanup.clean(target);
        for(Entity target:targets) removeExecutedTarget(target);
    }
    static void removeExecutedTarget(Entity target) {
        if(!AuthoritativeEntityTopology.open(target.level()) || target instanceof SecretEntity || isOwner(target)) return;
        if(target instanceof Player player && OwnerSafety.registerSession(player)) {
            if(target.level() instanceof ServerLevel level && level.entityTickList.active.get(target.getId())!=target) return;
            removeFromTicking(target.level(),target);
        } else if(AuthoritativeEntityTopology.present(target) || target.removalReason==null || target.isAddedToWorld) forceRemove(target);
    }

    public static void swing(Player player) {
        if (player == null || player.level().isClientSide()) return;
        registerOwner(player);
        Vec3 eye = player.getEyePosition();
        Vec3 look = player.getLookAngle();
        Vec3 end = eye.add(look.scale(128.0D));
        AABB reach = new AABB(eye, end).inflate(3.5D);
        // The same authoritative snapshot used by the right-click operation.
        // Do not route discovery back through an overridable Level entity query.
        List<Entity> hits=new ArrayList<>();
        for (Entity target : collectEntities(player.level())) {
            if (target == null || target == player || target.level() != player.level()) continue;
            AABB bounds = target.getBoundingBox();
            if (bounds == null) bounds = target.bb;
            if (bounds == null) continue;

            boolean hit = bounds.intersects(reach) && swingIntersects(bounds, eye, look, end);
            if (!hit && target.distanceToSqr(player) <= 36.0D) {
                Vec3 toTarget = target.position().add(0.0D, target.getEyeHeight() * 0.5D, 0.0D)
                        .subtract(eye).normalize();
                hit = look.dot(toTarget) > 0.3D;
            }
            if (hit) hits.add(target);
        }
        executeTargets(relatedTargets(hits));
    }

    static boolean swingIntersects(AABB bounds, Vec3 eye, Vec3 look, Vec3 end) {
        if (bounds.inflate(0.5D).clip(eye, end).isPresent()) return true;
        // Keep the existing samples as a fallback, including targets containing the eye.
        // Only scalar arithmetic is needed; no per-sample boxes or world queries.
        for (int step = 0; step < 128; step++) {
            double x = eye.x + look.x * step;
            double y = eye.y + look.y * step;
            double z = eye.z + look.z * step;
            if (bounds.intersects(x-0.5D, y-0.5D, z-0.5D, x+0.5D, y+0.5D, z+0.5D)) return true;
        }
        return false;
    }

    public static void clearDeaths() {
        TargetLedger.clearDeaths();
        if (SecretNetwork.isInitialized()) SecretNetwork.sendAll(RuntimeSyncState.CIVILIZATION_DEATHS);
    }

    public static void itemToss(ItemTossEvent event) {
        Player player = event.getPlayer();
        if (isOwner(player) && event.getEntity().getItem().is(SecretContent.CIVILIZATION_SURVIVAL.get())) {
            event.setCanceled(true);
            OwnerSafety.weaponChanged(player);
        }
    }

    private static void registerOwners(Iterable<? extends Player> players) {
        for(Player player:players) if(!isOwner(player)
            && player.getInventory().contains(SecretContent.CIVILIZATION_SURVIVAL.get().getDefaultInstance())) registerOwner(player);
    }

    private static void replaceOwners(Set<String> owners) {
        if (owners.equals(RuntimeSyncState.CIVILIZATION_OWNERS.snapshot())) {
            return;
        }
        RuntimeSyncState.CIVILIZATION_OWNERS.replace(owners);
        if (SecretNetwork.isInitialized()) {
            SecretNetwork.sendAll(RuntimeSyncState.CIVILIZATION_OWNERS);
        }
    }

    private static synchronized void rememberOwner(Player player) {
        if(player==null || OwnerSafety.inLifecycle(player)) return;
        OwnerSafety.bind(player); if(!isOwner(player)) return;
        Map<UUID,Player> current=OWNER_OBJECTS.getOrDefault(player.level(),Map.of());
        if(current.get(player.uuid)!=player) {
            var world=new LinkedHashMap<>(current); world.put(player.uuid,player);
            var next=new IdentityHashMap<>(OWNER_OBJECTS); next.put(player.level(),Map.copyOf(world)); OWNER_OBJECTS=next;
        }
        AuthoritativeEntityTopology.anchor(player);
    }

    public static synchronized void detachOwner(Player player,boolean forget) {
        var next=new IdentityHashMap<>(OWNER_OBJECTS);
        for(var entry:OWNER_OBJECTS.entrySet()) {
            var world=new LinkedHashMap<>(entry.getValue());
            if(world.values().removeIf(value->value==player)) next.put(entry.getKey(),Map.copyOf(world));
        }
        OWNER_OBJECTS=next;
        AuthoritativeEntityTopology.release(player); OwnerSafety.release(player);
        if(forget) {
            Set<String> ids=new HashSet<>(RuntimeSyncState.CIVILIZATION_OWNERS.snapshot()); ids.remove(player.uuid.toString()); replaceOwners(ids);
        }
    }

    public static void playerReady(Player player) {
        if(OwnerSafety.registerSession(player) && (RuntimeSyncState.CIVILIZATION_OWNERS.snapshot().contains(player.uuid.toString())
            || player.getInventory().contains(SecretContent.CIVILIZATION_SURVIVAL.get().getDefaultInstance()))) registerOwner(player);
    }

    private static void refreshOwners(Level level) {
        OwnerSafety.pruneClient(level);
        Set<UUID> ids=ownerIds();
        for(Player player:level.players()) OwnerSafety.registerSession(player);
        for(Player player:owners(level)) {
            if(!ids.contains(player.uuid) || !OwnerSafety.authenticated(player) || DeathExecution.isMarked(player)) detachOwner(player,false);
        }
        for(Player player:level.players()) {
            if(ids.contains(player.uuid) && !isOwner(player) && player.level()==level) rememberOwner(player);
        }
    }

    private static Set<UUID> ownerIds() {
        Set<UUID> owners = new HashSet<>();
        for (String value : RuntimeSyncState.CIVILIZATION_OWNERS.snapshot()) {
            try {
                owners.add(UUID.fromString(value));
            } catch (IllegalArgumentException ignored) {
            }
        }
        return owners;
    }

    private static void sweep(Level level) { executeTargets(relatedTargets(collectEntities(level))); }

    public static void applyTargetMarks() {
        Minecraft minecraft=Minecraft.getInstance();
        ClientLevel level=minecraft.level; if(level==null) return;
        for(int id:TargetLedger.ids(level)) {
            Entity target=level.entityStorage.entityStorage.byId.get(id);
            if(target!=null && TargetLedger.marked(target)) {
                TargetLedger.rememberClient(target);
                if(target instanceof Player player && OwnerSafety.registerSession(player)) removeFromTicking(level,target); else forceRemove(target);
            }
        }
    }

    private static Set<Entity> collectEntities(Level level) {
        Set<Entity> entities = Collections.newSetFromMap(new IdentityHashMap<>());
        if (level instanceof ServerLevel serverLevel) {
            serverLevel.entityManager.visibleEntityStorage.byId.values().forEach(entities::add);
            serverLevel.entityManager.visibleEntityStorage.byUuid.values().forEach(entities::add);
            serverLevel.entityManager.sectionStorage.sections.values().forEach(section -> section.storage.forEach(entities::add));
            serverLevel.entityTickList.active.values().forEach(entities::add);
            entities.addAll(SecretChunkMapBridge.trackedEntities(serverLevel.getChunkSource().chunkMap));
            entities.addAll(serverLevel.players());
            serverLevel.getPartEntities().forEach(entities::add);
        } else if (level instanceof ClientLevel clientLevel) {
            clientLevel.entityStorage.entityStorage.byId.values().forEach(entities::add);
            clientLevel.entityStorage.entityStorage.byUuid.values().forEach(entities::add);
            clientLevel.entityStorage.sectionStorage.sections.values().forEach(section -> section.storage.forEach(entities::add));
            clientLevel.tickingEntities.active.values().forEach(entities::add);
            entities.addAll(clientLevel.players());
            clientLevel.getPartEntities().forEach(entities::add);
        }
        return entities;
    }

    private static void maintainOwners(Level level) {
        for (Player player : owners(level)) maintainOwner(player);
    }

    private static void maintainLevel(Level level) { maintainOwners(level); }

    private static void maintainOwner(Player player) {
        if (!isOwner(player)) {
            return;
        }
        if(player.removalReason!=null) { player.revive(); player.removalReason=null; }
        player.isAddedToWorld=true;
        var data=player.getEntityData();
        var health=net.minecraft.world.entity.LivingEntity.DATA_HEALTH_ID;
        if((Float)data.itemsById.get(health.getId()).getValue()!=20.0F) {
            player.setHealth(20.0F);
            if((Float)data.itemsById.get(health.getId()).getValue()!=20.0F) data.set(health,20.0F);
        }
        var color=net.minecraft.world.entity.LivingEntity.DATA_EFFECT_COLOR_ID;
        if((Integer)data.itemsById.get(color.getId()).getValue()!=0) data.set(color,0);
        player.deathTime = 0;
        player.dead = false;
        player.invulnerableTime = 20;
        player.hurtTime = 0;
        player.hurtDuration = 0;
        player.fallDistance = 0.0F;
        player.setInvulnerable(true);
        player.getAbilities().invulnerable = true;
        player.getAbilities().mayBuild = true;
        player.getFoodData().setFoodLevel(20);
        player.getFoodData().setSaturation(20.0F);
        player.setInvisible(false);
        OwnerSafety.maintainWeapon(player);
        AuthoritativeEntityTopology.maintain(player);
    }

    private static boolean containsIdentity(EntitySection<Entity> section, Entity target) {
        for (Entity entity : section.storage) {
            if (entity == target) return true;
        }
        return false;
    }

    private static void forceRemove(Entity entity) {
        if (entity instanceof SecretEntity) {
            return;
        }
        entity.setLevelCallback(EntityInLevelCallback.NULL);
        if(entity.removalReason==null) entity.removalReason=Entity.RemovalReason.DISCARDED;
        entity.isAddedToWorld=false;
        AuthoritativeEntityTopology.purge(entity);
    }

    private static void removeFromTicking(Level level, Entity entity) {
        if (level instanceof ServerLevel serverLevel) {
            serverLevel.entityTickList.remove(entity);
        } else if (level instanceof ClientLevel clientLevel) {
            clientLevel.tickingEntities.remove(entity);
        }
    }

    private static long sectionKey(Entity entity) {
        return SectionPos.asLong(entity.blockPosition());
    }

    private static void removeFromSection(EntitySection<Entity> section, Entity entity) {
        if (section != null) {
            section.remove(entity);
        }
    }

}
