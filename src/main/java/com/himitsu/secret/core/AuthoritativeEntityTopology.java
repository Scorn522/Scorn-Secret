package com.himitsu.secret.core;

import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import net.minecraft.client.multiplayer.ClientLevel;
import net.minecraft.core.SectionPos;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.EntityType;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.level.Level;
import net.minecraft.world.level.entity.EntityInLevelCallback;
import net.minecraft.world.level.entity.EntityLookup;
import net.minecraft.world.level.entity.EntitySection;
import net.minecraft.world.level.entity.EntityTickList;
import net.minecraftforge.entity.PartEntity;

final class AuthoritativeEntityTopology {
    private static volatile Map<Entity, Anchor> ANCHORS = new IdentityHashMap<>();
    private static volatile Anchor[] maintained=new Anchor[0];
    private static final WeakTargetSet<Level> CLOSED=new WeakTargetSet<>();
    private static final ThreadLocal<Boolean> MUTATING = ThreadLocal.withInitial(() -> false);

    private AuthoritativeEntityTopology() {
    }

    static boolean open(Level level) { return level!=null && !CLOSED.contains(level); }
    static synchronized void anchor(Entity entity) {
        if(!(entity instanceof Player) && !(entity instanceof com.himitsu.secret.entity.SecretEntity)) return;
        if(!open(entity.level())) return;
        Anchor prior=ANCHORS.get(entity);
        if(prior==null || prior.level!=entity.level()) {
            var next=new IdentityHashMap<>(ANCHORS); next.put(entity,new Anchor(entity)); publish(next);
        }
    }
    static void release(Entity entity) { if(ANCHORS.containsKey(entity)) releaseBound(entity); }
    private static synchronized void releaseBound(Entity entity) {
        if(!ANCHORS.containsKey(entity)) return;
        var next=new IdentityHashMap<>(ANCHORS); next.remove(entity); publish(next);
    }
    static List<Entity> anchored(Level level) {
        List<Entity> result=new ArrayList<>();
        for(Anchor anchor:ANCHORS.values()) if(anchor.level==level) result.add(anchor.entity);
        return result;
    }

    static int capturedId(Entity entity) {
        Anchor anchor = anchorFor(entity);
        return anchor == null ? entity.getId() : anchor.id;
    }

    static UUID capturedUuid(Entity entity) {
        Anchor anchor = anchorFor(entity);
        return anchor == null ? entity.getUUID() : anchor.uuid;
    }

    static EntityType<?> capturedType(Entity entity) {
        Anchor anchor = anchorFor(entity);
        return anchor == null ? entity.getType() : anchor.type;
    }

    static void maintainAll() {
        Anchor[] current=maintained;
        for(int i=0;i<current.length;i++) maintain(current[i].entity);
    }

    static void maintain(Entity entity) {
        if (!(entity instanceof Player) && !(entity instanceof com.himitsu.secret.entity.SecretEntity)) return;
        if (!open(entity.level()) || Boolean.TRUE.equals(MUTATING.get())) return;
        if(entity instanceof Player && (!OwnerSafety.owns(entity) || OwnerSafety.inLifecycle((Player)entity))) return;
        if(!expected(entity)) return;
        Anchor anchor = anchorFor(entity);
        if (anchor == null || entity.level() != anchor.level) return;
        MUTATING.set(true);
        try {
            if(entity.removalReason!=null) entity.revive();
            entity.removalReason = null;
            entity.isAddedToWorld = true;
            if (anchor.level instanceof ServerLevel serverLevel) repairServer(serverLevel, anchor);
            else if (anchor.level instanceof ClientLevel clientLevel) repairClient(clientLevel, anchor);
        } finally {
            MUTATING.set(false);
        }
    }

    static void purge(Entity entity) {
        if (entity == null || !open(entity.level()) || Boolean.TRUE.equals(MUTATING.get())) return;
        Anchor anchor = anchorFor(entity);
        if (anchor == null) anchor = new Anchor(entity);
        MUTATING.set(true);
        try {
            entity.setLevelCallback(EntityInLevelCallback.NULL);
            if (anchor.level instanceof ServerLevel serverLevel) purgeServer(serverLevel, anchor);
            else if (anchor.level instanceof ClientLevel clientLevel) purgeClient(clientLevel, anchor);
        } finally {
            MUTATING.set(false);
        }
    }

    static synchronized void clearLevel(Level level) {
        CLOSED.add(level,level);
        var next=new IdentityHashMap<>(ANCHORS); next.entrySet().removeIf(entry->entry.getValue().level==level); publish(next);
    }

    static boolean expected(Entity entity) {
        if(!open(entity.level())) return false;
        if(entity instanceof Player) return true;
        long chunk=entity.chunkPosition().toLong();
        if(entity.level() instanceof ServerLevel level) return level.entityManager.chunkVisibility.get(chunk).isAccessible();
        if(entity.level() instanceof ClientLevel level) return level.getChunkSource().hasChunk(entity.chunkPosition().x,entity.chunkPosition().z);
        return false;
    }
    static boolean present(Entity entity) {
        if(!open(entity.level())) return false;
        if(entity.level() instanceof ServerLevel level)
            return level.entityManager.visibleEntityStorage.byId.get(entity.getId())==entity
                || level.entityManager.visibleEntityStorage.byUuid.get(entity.uuid)==entity
                || level.entityTickList.active.get(entity.getId())==entity || level.entityManager.knownUuids.contains(entity.uuid);
        if(entity.level() instanceof ClientLevel level)
            return level.entityStorage.entityStorage.byId.get(entity.getId())==entity
                || level.entityStorage.entityStorage.byUuid.get(entity.uuid)==entity || level.tickingEntities.active.get(entity.getId())==entity;
        return false;
    }
    private static void repairServer(ServerLevel level, Anchor anchor) {
        if (!lookupContains(level.entityManager.visibleEntityStorage, anchor)) {
            replaceLookup(level.entityManager.visibleEntityStorage, anchor, true);
        }
        if (!level.entityManager.knownUuids.contains(anchor.uuid)) {
            level.entityManager.knownUuids = copyUuidSet(level.entityManager.knownUuids, anchor, true);
        }
        if ((anchor.entity instanceof Player || level.entityManager.chunkVisibility.get(anchor.entity.chunkPosition().toLong()).isTicking())
            && level.entityTickList.active.get(anchor.id) != anchor.entity) {
            replaceTickList(level.entityTickList, anchor, true);
        }
        var section=level.entityManager.sectionStorage.getSection(anchor.sectionKey());
        if(section==null) section=level.entityManager.sectionStorage.getOrCreateSection(anchor.sectionKey());
        maintainSection(section,anchor);
        if (anchor.entity instanceof ServerPlayer player) {
            if(anchor.playerSlot<0 || anchor.playerSlot>=level.players.size() || level.players.get(anchor.playerSlot)!=player) {
                int index=0; while(index<level.players.size() && level.players.get(index)!=player) index++;
                if(index==level.players.size()) level.players.add(player);
                anchor.playerSlot=index;
            }
        }
        if (!anchor.parts.isEmpty() && !partsContain(level.dragonParts, anchor)) {
            level.dragonParts = copyParts(level.dragonParts, anchor, true);
        }
        if (!SecretChunkMapBridge.containsTrackedEntity(level.getChunkSource().chunkMap, anchor.entity, anchor.id)) {
            SecretChunkMapBridge.replaceTrackedEntity(
                level.getChunkSource().chunkMap, anchor.entity, anchor.id, anchor.type, true
            );
        }
    }

    private static void repairClient(ClientLevel level, Anchor anchor) {
        if (!lookupContains(level.entityStorage.entityStorage, anchor)) {
            replaceLookup(level.entityStorage.entityStorage, anchor, true);
        }
        if ((anchor.entity instanceof Player || level.entityStorage.tickingChunks.contains(anchor.entity.chunkPosition().toLong()))
            && level.tickingEntities.active.get(anchor.id) != anchor.entity) {
            replaceTickList(level.tickingEntities, anchor, true);
        }
        var section=level.entityStorage.sectionStorage.getSection(anchor.sectionKey());
        if(section==null) section=level.entityStorage.sectionStorage.getOrCreateSection(anchor.sectionKey());
        maintainSection(section,anchor);
        if (!anchor.parts.isEmpty() && !partsContain(level.partEntities, anchor)) {
            level.partEntities = copyParts(level.partEntities, anchor, true);
        }
    }

    private static boolean lookupContains(EntityLookup<Entity> lookup, Anchor anchor) {
        return lookup.byId.get(anchor.id) == anchor.entity && lookup.byUuid.get(anchor.uuid) == anchor.entity;
    }

    private static boolean partsContain(Map<Integer, PartEntity<?>> source, Anchor anchor) {
        for (Map.Entry<PartEntity<?>, Integer> part : anchor.parts.entrySet()) {
            if (source.get(part.getValue()) != part.getKey()) return false;
        }
        return true;
    }

    private static void purgeServer(ServerLevel level, Anchor anchor) {
        SecretChunkMapBridge.replaceTrackedEntity(
            level.getChunkSource().chunkMap, anchor.entity, anchor.id, anchor.type, false
        );
        replaceLookup(level.entityManager.visibleEntityStorage, anchor, false);
        level.entityManager.knownUuids = copyUuidSet(level.entityManager.knownUuids, anchor, false);
        replaceTickList(level.entityTickList, anchor, false);
        removeFromCurrentSection(level.entityManager.sectionStorage.getSection(anchor.sectionKey()), anchor.entity);
        if (anchor.entity instanceof Player) {
            ArrayList<ServerPlayer> players = new ArrayList<>(level.players);
            players.removeIf(candidate -> candidate == anchor.entity);
            level.players = players;
        }
        level.dragonParts = copyParts(level.dragonParts, anchor, false);
        int[] removed=new int[anchor.parts.size()+1]; removed[0]=anchor.id; int index=1;
        for(int id:anchor.parts.values()) removed[index++]=id;
        var packet=new net.minecraft.network.protocol.game.ClientboundRemoveEntitiesPacket(removed);
        for(ServerPlayer player:new ArrayList<>(level.players)) if(player.connection!=null) player.connection.send(packet);
    }

    private static void purgeClient(ClientLevel level, Anchor anchor) {
        replaceLookup(level.entityStorage.entityStorage, anchor, false);
        replaceTickList(level.tickingEntities, anchor, false);
        removeFromCurrentSection(level.entityStorage.sectionStorage.getSection(anchor.sectionKey()), anchor.entity);
        level.partEntities = copyParts(level.partEntities, anchor, false);
    }

    private static void replaceLookup(EntityLookup<Entity> lookup, Anchor anchor, boolean add) {
        Int2ObjectOpenHashMap<Entity> byId = new Int2ObjectOpenHashMap<>();
        for (Map.Entry<Integer, Entity> entry : lookup.byId.int2ObjectEntrySet()) {
            if (entry.getValue() != anchor.entity) byId.put(entry.getKey(), entry.getValue());
        }
        HashMap<UUID, Entity> byUuid = new HashMap<>();
        for (Map.Entry<UUID, Entity> entry : lookup.byUuid.entrySet()) {
            if (entry.getValue() != anchor.entity) byUuid.put(entry.getKey(), entry.getValue());
        }
        if (add) {
            byId.put(anchor.id, anchor.entity);
            byUuid.put(anchor.uuid, anchor.entity);
        }
        lookup.byId = byId;
        lookup.byUuid = byUuid;
    }

    private static Set<UUID> copyUuidSet(Set<UUID> source, Anchor anchor, boolean add) {
        HashSet<UUID> result = new HashSet<>(source);
        result.remove(anchor.uuid);
        if (add) result.add(anchor.uuid);
        return result;
    }

    private static void replaceTickList(EntityTickList ticks,Anchor anchor,boolean add) {
        ticks.ensureActiveIsNotIterated();
        ticks.active.values().removeIf(value->value==anchor.entity);
        if(add) ticks.active.put(anchor.id,anchor.entity);
    }
    private static void maintainSection(EntitySection<Entity> section,Anchor anchor) {
        if(section==null) { anchor.section=null; return; }
        if(anchor.entity.levelCallback==EntityInLevelCallback.NULL) anchor.entity.setLevelCallback(anchor.callback);
        if(anchor.entity.levelCallback instanceof net.minecraft.world.level.entity.PersistentEntitySectionManager<?>.Callback callback) {
            if(callback.currentSection!=section) { ((EntitySection)callback.currentSection).remove(anchor.entity); callback.currentSection=(EntitySection)section; callback.currentSectionKey=anchor.sectionKey(); }
        } else if(anchor.entity.levelCallback instanceof net.minecraft.world.level.entity.TransientEntitySectionManager<?>.Callback callback) {
            if(callback.currentSection!=section) { ((EntitySection)callback.currentSection).remove(anchor.entity); callback.currentSection=(EntitySection)section; callback.currentSectionKey=anchor.sectionKey(); }
        }
        List<Entity> members=section.storage.allInstances;
        if(anchor.section==section && anchor.member>=0 && anchor.member<members.size() && members.get(anchor.member)==anchor.entity) return;
        int index=0; while(index<members.size() && members.get(index)!=anchor.entity) index++;
        if(index==members.size()) section.add(anchor.entity);
        anchor.section=section; anchor.member=index;
    }

    private static void removeFromCurrentSection(EntitySection<Entity> section, Entity entity) {
        if (section != null) section.remove(entity);
    }

    private static Int2ObjectOpenHashMap<PartEntity<?>> copyParts(Map<Integer, PartEntity<?>> source, Anchor anchor, boolean add) {
        Int2ObjectOpenHashMap<PartEntity<?>> result = new Int2ObjectOpenHashMap<>();
        for (Map.Entry<Integer, PartEntity<?>> entry : source.entrySet()) {
            if (!anchor.parts.containsKey(entry.getValue())) result.put(entry.getKey(), entry.getValue());
        }
        if (add) {
            for (Map.Entry<PartEntity<?>, Integer> entry : anchor.parts.entrySet()) {
                result.put(entry.getValue(), entry.getKey());
            }
        }
        return result;
    }

    private static void publish(Map<Entity,Anchor> next) { ANCHORS=next; maintained=next.values().toArray(Anchor[]::new); }
    private static Anchor anchorFor(Entity entity) { return ANCHORS.get(entity); }
    private static final class Anchor {
        final Entity entity; final Level level; final int id; final UUID uuid; final EntityType<?> type;
        final Map<PartEntity<?>,Integer> parts; final EntityInLevelCallback callback;
        EntitySection<Entity> section; int member=-1,playerSlot=-1;
        Anchor(Entity entity) {
            this.entity=entity; level=entity.level(); id=entity.getId(); uuid=entity.getUUID(); type=entity.getType(); parts=captureParts(entity); callback=entity.levelCallback;
        }
        private long sectionKey() {
            return SectionPos.asLong(entity.blockPosition());
        }

        private static Map<PartEntity<?>, Integer> captureParts(Entity entity) {
            IdentityHashMap<PartEntity<?>, Integer> parts = new IdentityHashMap<>();
            if (entity.isMultipartEntity()) {
                PartEntity<?>[] values=entity.getParts();
                if(values!=null) for(PartEntity<?> part:values) if(part!=null && part.getParent()==entity) parts.put(part,part.getId());
            }
            return java.util.Collections.unmodifiableMap(parts);
        }
    }
}
