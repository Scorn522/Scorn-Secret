package com.himitsu.secret.core;

import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;
import java.util.ArrayList;
import java.util.List;
import net.minecraft.server.level.ChunkMap;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.EntityType;

final class SecretChunkMapBridge {
    private SecretChunkMapBridge() {
    }

    static void replaceTrackedEntity(
        ChunkMap chunkMap,
        Entity target,
        int capturedId,
        EntityType<?> capturedType,
        boolean add
    ) {
        Int2ObjectOpenHashMap<ChunkMap.TrackedEntity> replacement = new Int2ObjectOpenHashMap<>();
        ChunkMap.TrackedEntity targetTracking = null;
        for (ChunkMap.TrackedEntity tracked : new ArrayList<>(chunkMap.entityMap.values())) {
            if (tracked.entity == target) {
                if (targetTracking == null) targetTracking = tracked;
                if (!add) tracked.seenBy.clear();
            } else {
                replacement.put(tracked.entity.getId(), tracked);
            }
        }
        if (add) {
            if (targetTracking == null) targetTracking = createTrackedEntity(chunkMap, target, capturedType);
            if (targetTracking != null) replacement.put(capturedId, targetTracking);
        }
        chunkMap.entityMap = replacement;
    }

    static List<Entity> trackedEntities(ChunkMap chunkMap) {
        ArrayList<Entity> entities = new ArrayList<>();
        for (ChunkMap.TrackedEntity tracked : new ArrayList<>(chunkMap.entityMap.values())) {
            entities.add(tracked.entity);
        }
        return entities;
    }

    static boolean containsTrackedEntity(ChunkMap chunkMap, Entity target, int capturedId) {
        ChunkMap.TrackedEntity tracked = chunkMap.entityMap.get(capturedId);
        return tracked!=null && tracked.entity==target;
    }

    private static ChunkMap.TrackedEntity createTrackedEntity(
        ChunkMap chunkMap,
        Entity entity,
        EntityType<?> type
    ) {
        int range = type.clientTrackingRange() * 16;
        if (range == 0) return null;
        ChunkMap.TrackedEntity tracked = chunkMap.new TrackedEntity(
            entity,
            range,
            type.updateInterval(),
            type.trackDeltas()
        );
        tracked.updatePlayers(chunkMap.level.players());
        return tracked;
    }
}
