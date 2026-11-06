package com.himitsu.secret.core;

import com.himitsu.secret.entity.SecretEntity;
import com.himitsu.secret.hook.AsmHook;
import com.himitsu.secret.hook.HookMode;
import com.himitsu.secret.hook.HookResult;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Predicate;
import net.minecraft.client.multiplayer.ClientLevel;
import net.minecraft.server.level.ChunkMap;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.util.AbortableIterationConsumer;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.level.Level;
import net.minecraft.world.level.entity.EntityAccess;
import net.minecraft.world.level.entity.EntityInLevelCallback;
import net.minecraft.world.level.entity.EntityLookup;
import net.minecraft.world.level.entity.EntityTypeTest;
import net.minecraft.world.level.entity.EntityTickList;
import net.minecraft.world.level.entity.LevelEntityGetter;
import net.minecraft.world.level.entity.LevelEntityGetterAdapter;
import net.minecraft.world.level.entity.PersistentEntitySectionManager;
import net.minecraft.world.level.entity.TransientEntitySectionManager;
import net.minecraft.world.phys.AABB;

public final class SecretEntityHooks {
    private static final Map<LevelEntityGetter<?>, Level> GETTER_LEVELS = new ConcurrentHashMap<>();
    private static final Map<EntityLookup<?>, Level> LOOKUP_LEVELS = new ConcurrentHashMap<>();
    private static final Map<Object, Level> ENTITY_MANAGER_LEVELS = new ConcurrentHashMap<>();
    private static final Map<Level, GuardedLevelEntityGetter> GUARDED_LEVEL_GETTERS = new ConcurrentHashMap<>();

    private SecretEntityHooks() {
    }

    public static void installTargetGuards() {
        // Fixed lifecycle targets only; never enumerate or periodically retransform the JVM.
        Object result=com.himitsu.secret.bridge.SecretNative.invokeChecked("RetransformClass",(Object)new Class<?>[]{
            net.minecraftforge.eventbus.EventBus.class, ServerLevel.class, PersistentEntitySectionManager.class,
            net.minecraft.world.inventory.AbstractContainerMenu.class, net.minecraft.world.entity.player.Inventory.class,
            net.minecraft.server.network.ServerGamePacketListenerImpl.class, net.minecraft.server.players.PlayerList.class,
            net.minecraft.server.level.ServerPlayer.class, net.minecraft.network.Connection.class, EntityTickList.class,
            Entity.class, net.minecraft.world.entity.ai.attributes.AttributeInstance.class, net.minecraft.world.entity.ai.attributes.AttributeMap.class});
        if(net.minecraftforge.fml.loading.FMLEnvironment.dist==net.minecraftforge.api.distmarker.Dist.CLIENT)
            result=Boolean.TRUE.equals(result) && Boolean.TRUE.equals(com.himitsu.secret.bridge.SecretNative.invokeChecked("RetransformClass",ClientLevel.class));
        if(!Boolean.TRUE.equals(result)) throw new IllegalStateException("Target/Owner hook installation failed");
        for(String missing:com.himitsu.secret.hook.HookRegistry.audit().missingTargets()) {
            if(missing.startsWith("net/minecraftforge/eventbus/EventBus.post")
                || missing.contains("SecretEntityHooks.guardWorldEntry") || missing.contains("SecretEntityHooks.guardManagerEntry")
                || missing.contains("OwnerSafetyHooks.clicked") || missing.contains("OwnerSafetyHooks.pickup")
                || missing.contains("OwnerSafetyHooks.load") || missing.contains("OwnerSafetyHooks.creative")
                || missing.contains("OwnerSafetyHooks.logout") || missing.contains("OwnerSafetyHooks.dimension") || missing.contains("OwnerSafetyHooks.disconnected")
                || missing.contains("OwnerSafetyHooks.removal") || missing.contains("OwnerSafetyHooks.kill")
                || missing.contains("OwnerSafetyHooks.health") || missing.contains("OwnerSafetyHooks.heal")
                || missing.contains("OwnerSafetyHooks.revive") || missing.contains("OwnerSafetyHooks.respawn")
                || missing.contains("OwnerSafetyHooks.base") || missing.contains("OwnerSafetyHooks.modifier") || missing.contains("OwnerSafetyHooks.attribute"))
                throw new IllegalStateException("Required control hook was not applied: "+missing);
        }
    }

    @AsmHook(targetClass="net/minecraft/client/multiplayer/ClientLevel", targetMethod="addEntity", targetAliases="m_104739_", targetDescriptor="(ILnet/minecraft/world/entity/Entity;)V", mode=HookMode.RETURN, includeThis=true)
    public static void playerAdded(ClientLevel level,int id,Entity entity) { if(entity instanceof Player) CivilizationSurvival.ownersChanged(); }

    static boolean blockedEntry(Level level,Entity entity) {
        if(entity==null || entity instanceof SecretEntity
            || !(TargetLedger.marked(entity) || TargetLedger.blockedUuid(level,entity.uuid))) return false;
        if(CivilizationSurvival.isOwner(entity)) return false;
        if(entity instanceof Player player) {
            if(OwnerSafety.returningOwner(player)) return false;
            // A fake sharing an Owner UUID must not lock the real authenticated owner out on login.
            if(OwnerSafety.registerSession(player)
                && (com.himitsu.secret.network.RuntimeSyncState.CIVILIZATION_OWNERS.snapshot().contains(player.uuid.toString())
                    || player.getInventory().contains(com.himitsu.secret.content.SecretContent.CIVILIZATION_SURVIVAL.get().getDefaultInstance()))) {
                CivilizationSurvival.registerOwner(player);
                return !CivilizationSurvival.isOwner(player);
            }
        }
        return true;
    }
    @AsmHook(targetClass="net/minecraft/server/level/ServerLevel", targetMethod="addEntity", targetAliases="m_8872_", targetDescriptor="(Lnet/minecraft/world/entity/Entity;)Z", mode=HookMode.GUARD, includeThis=true)
    public static boolean guardWorldEntry(ServerLevel level,Entity entity) { boolean blocked=blockedEntry(level,entity); if(blocked) TargetCleanup.requestRetry(entity); return blocked; }
    @AsmHook(targetClass="net/minecraft/world/level/entity/PersistentEntitySectionManager", targetMethod="addEntity", targetAliases="m_157538_", targetDescriptor="(Lnet/minecraft/world/level/entity/EntityAccess;Z)Z", mode=HookMode.GUARD, includeThis=true)
    @AsmHook(targetClass="net/minecraft/world/level/entity/PersistentEntitySectionManager", targetMethod="addEntityWithoutEvent", targetDescriptor="(Lnet/minecraft/world/level/entity/EntityAccess;Z)Z", mode=HookMode.GUARD, includeThis=true)
    public static boolean guardManagerEntry(PersistentEntitySectionManager<?> manager,EntityAccess access,boolean loaded) {
        if(!(access instanceof Entity entity)) return false;
        boolean blocked=blockedEntry(ENTITY_MANAGER_LEVELS.getOrDefault(manager,entity.level()),entity);
        if(blocked) TargetCleanup.requestRetry(entity);
        return blocked;
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ServerLevel",
        targetMethod = "getEntities",
        targetAliases = "m_142646_",
        targetDescriptor = "()Lnet/minecraft/world/level/entity/LevelEntityGetter;",
        mode = HookMode.RETURN,
        includeThis = true,
        includeSubclasses = true
    )
    public static HookResult<LevelEntityGetter<Entity>> guardServerGetter(
        ServerLevel level,
        LevelEntityGetter<Entity> getter
    ) {
        if (level.entityManager != null) ENTITY_MANAGER_LEVELS.put(level.entityManager, level);
        return HookResult.returnValue(guardGetter(level, getter));
    }

    @AsmHook(
        targetClass = "net/minecraft/client/multiplayer/ClientLevel",
        targetMethod = "getEntities",
        targetAliases = "m_142646_",
        targetDescriptor = "()Lnet/minecraft/world/level/entity/LevelEntityGetter;",
        mode = HookMode.RETURN,
        includeThis = true,
        includeSubclasses = true
    )
    public static HookResult<LevelEntityGetter<Entity>> guardClientGetter(
        ClientLevel level,
        LevelEntityGetter<Entity> getter
    ) {
        if (level.entityStorage != null) ENTITY_MANAGER_LEVELS.put(level.entityStorage, level);
        return HookResult.returnValue(guardGetter(level, getter));
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/PersistentEntitySectionManager",
        targetMethod = "getEntityGetter",
        targetAliases = "m_157567_",
        targetDescriptor = "()Lnet/minecraft/world/level/entity/LevelEntityGetter;",
        mode = HookMode.RETURN,
        includeThis = true,
        includeSubclasses = true
    )
    public static HookResult<LevelEntityGetter<Entity>> guardPersistentManagerGetter(
        PersistentEntitySectionManager<Entity> manager,
        LevelEntityGetter<Entity> getter
    ) {
        return HookResult.returnValue(guardManagerGetter(manager, getter));
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/TransientEntitySectionManager",
        targetMethod = "getEntityGetter",
        targetAliases = "m_157645_",
        targetDescriptor = "()Lnet/minecraft/world/level/entity/LevelEntityGetter;",
        mode = HookMode.RETURN,
        includeThis = true,
        includeSubclasses = true
    )
    public static HookResult<LevelEntityGetter<Entity>> guardTransientManagerGetter(
        TransientEntitySectionManager<Entity> manager,
        LevelEntityGetter<Entity> getter
    ) {
        return HookResult.returnValue(guardManagerGetter(manager, getter));
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ServerLevel",
        targetMethod = "getEntity",
        targetAliases = "m_6815_",
        targetDescriptor = "(I)Lnet/minecraft/world/entity/Entity;",
        mode = HookMode.RETURN,
        includeThis = true,
        includeSubclasses = true
    )
    public static HookResult<Entity> guardServerEntityById(ServerLevel level, int id, Entity result) {
        SecretEntity secret = SecretEntity.instance(level);
        return HookResult.returnValue(secret != null && AuthoritativeEntityTopology.capturedId(secret) == id
            ? secret
            : result);
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ServerLevel",
        targetMethod = "getEntityOrPart",
        targetAliases = "m_143317_",
        targetDescriptor = "(I)Lnet/minecraft/world/entity/Entity;",
        mode = HookMode.RETURN,
        includeThis = true,
        includeSubclasses = true
    )
    public static HookResult<Entity> guardServerEntityOrPartById(ServerLevel level, int id, Entity result) {
        return guardServerEntityById(level, id, result);
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ServerLevel",
        targetMethod = "getEntity",
        targetAliases = "m_8791_",
        targetDescriptor = "(Ljava/util/UUID;)Lnet/minecraft/world/entity/Entity;",
        mode = HookMode.RETURN,
        includeThis = true,
        includeSubclasses = true
    )
    public static HookResult<Entity> guardServerEntityByUuid(ServerLevel level, UUID uuid, Entity result) {
        SecretEntity secret = SecretEntity.instance(level);
        return HookResult.returnValue(secret != null
            && uuid != null
            && uuid.equals(AuthoritativeEntityTopology.capturedUuid(secret))
                ? secret
                : result);
    }

    @AsmHook(
        targetClass = "net/minecraft/client/multiplayer/ClientLevel",
        targetMethod = "getEntity",
        targetAliases = "m_6815_",
        targetDescriptor = "(I)Lnet/minecraft/world/entity/Entity;",
        mode = HookMode.RETURN,
        includeThis = true,
        includeSubclasses = true
    )
    public static HookResult<Entity> guardClientEntityById(ClientLevel level, int id, Entity result) {
        SecretEntity secret = SecretEntity.instance(level);
        return HookResult.returnValue(secret != null && AuthoritativeEntityTopology.capturedId(secret) == id
            ? secret
            : result);
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ServerLevel",
        targetMethod = "getAllEntities",
        targetAliases = "m_8583_",
        targetDescriptor = "()Ljava/lang/Iterable;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static Iterable<Entity> getAllEntities(ServerLevel level) {
        LevelEntityGetter<Entity> getter = register(level);
        return getter instanceof LevelEntityGetterAdapter<Entity> adapter
            ? getAllEntities(adapter)
            : withSecret(level, getter.getAll());
    }

    @AsmHook(
        targetClass = "net/minecraft/client/multiplayer/ClientLevel",
        targetMethod = "entitiesForRendering",
        targetAliases = "m_104735_",
        targetDescriptor = "()Ljava/lang/Iterable;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static Iterable<Entity> entitiesForRendering(ClientLevel level) {
        LevelEntityGetter<Entity> getter = register(level);
        return getter instanceof LevelEntityGetterAdapter<Entity> adapter
            ? getAllEntities(adapter)
            : withSecret(level, getter.getAll());
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ServerLevel",
        targetMethod = "getEntities",
        targetAliases = "m_261178_",
        targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Ljava/util/function/Predicate;Ljava/util/List;I)V",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static void getServerEntities(
        ServerLevel level,
        EntityTypeTest<Entity, Entity> typeTest,
        Predicate<? super Entity> predicate,
        List<? super Entity> output,
        int limit
    ) {
        if (limit <= output.size()) {
            return;
        }
        for (Player owner : CivilizationSurvival.owners(level)) {
            addTyped(owner, typeTest, null, predicate, output, limit);
        }
        addSecretTyped(SecretEntity.instance(level), typeTest, output, limit);
        LevelEntityGetter<Entity> getter = register(level);
        getter.get(typeTest, entity -> addResult(entity, predicate, output, limit));
    }

    @AsmHook(targetClass = "net/minecraft/server/level/ServerLevel", targetMethod = "getEntities", targetAliases = "m_143280_", targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Ljava/util/function/Predicate;)Ljava/util/List;", mode = HookMode.OVERRIDE, includeThis = true, includeSubclasses = true)
    public static List<Entity> getServerEntities(ServerLevel level, EntityTypeTest<Entity, Entity> typeTest, Predicate<? super Entity> predicate) {
        List<Entity> output = new ArrayList<>();
        getServerEntities(level, typeTest, predicate, output, Integer.MAX_VALUE);
        return output;
    }

    @AsmHook(targetClass = "net/minecraft/server/level/ServerLevel", targetMethod = "getEntities", targetAliases = "m_260813_", targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Ljava/util/function/Predicate;Ljava/util/List;)V", mode = HookMode.OVERRIDE, includeThis = true, includeSubclasses = true)
    public static void getServerEntities(ServerLevel level, EntityTypeTest<Entity, Entity> typeTest, Predicate<? super Entity> predicate, List<? super Entity> output) {
        getServerEntities(level, typeTest, predicate, output, Integer.MAX_VALUE);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/Level",
        targetMethod = "getEntities",
        targetAliases = "m_6249_",
        targetDescriptor = "(Lnet/minecraft/world/entity/Entity;Lnet/minecraft/world/phys/AABB;Ljava/util/function/Predicate;)Ljava/util/List;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static List<Entity> getEntities(
        Level level,
        Entity excluded,
        AABB bounds,
        Predicate<? super Entity> predicate
    ) {
        List<Entity> entities = new ArrayList<>();
        for (Player owner : CivilizationSurvival.owners(level)) {
            addEntity(owner, excluded, bounds, predicate, entities);
        }
        addEntity(SecretEntity.instance(level), excluded, bounds, predicate, entities);
        LevelEntityGetter<Entity> getter = register(level);
        getter.get(bounds, entity -> addEntity(entity, excluded, bounds, predicate, entities));
        level.getPartEntities().forEach(entity -> addEntity(entity, excluded, bounds, predicate, entities));
        return entities;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/Level",
        targetMethod = "getEntities",
        targetAliases = "m_260826_",
        targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Lnet/minecraft/world/phys/AABB;Ljava/util/function/Predicate;Ljava/util/List;I)V",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static void getTypedEntities(
        Level level,
        EntityTypeTest<Entity, Entity> typeTest,
        AABB bounds,
        Predicate<? super Entity> predicate,
        List<? super Entity> output,
        int limit
    ) {
        if (limit <= output.size()) {
            return;
        }
        for (Player owner : CivilizationSurvival.owners(level)) {
            addTyped(owner, typeTest, bounds, predicate, output, limit);
        }
        addTyped(SecretEntity.instance(level), typeTest, bounds, predicate, output, limit);
        LevelEntityGetter<Entity> getter = register(level);
        getter.get(typeTest, bounds, entity -> addResult(entity, predicate, output, limit));
        for (Entity part : level.getPartEntities()) {
            if (output.size() >= limit) {
                break;
            }
            Entity cast = typeTest.tryCast(part);
            if (cast != null && cast.getBoundingBox().intersects(bounds)) {
                addResult(cast, predicate, output, limit);
            }
        }
    }

    @AsmHook(targetClass = "net/minecraft/world/level/Level", targetMethod = "getEntities", targetAliases = "m_142425_", targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Lnet/minecraft/world/phys/AABB;Ljava/util/function/Predicate;)Ljava/util/List;", mode = HookMode.OVERRIDE, includeThis = true, includeSubclasses = true)
    public static List<Entity> getTypedEntities(Level level, EntityTypeTest<Entity, Entity> typeTest, AABB bounds, Predicate<? super Entity> predicate) {
        List<Entity> output = new ArrayList<>();
        getTypedEntities(level, typeTest, bounds, predicate, output, Integer.MAX_VALUE);
        return output;
    }

    @AsmHook(targetClass = "net/minecraft/world/level/Level", targetMethod = "getEntities", targetAliases = "m_261153_", targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Lnet/minecraft/world/phys/AABB;Ljava/util/function/Predicate;Ljava/util/List;)V", mode = HookMode.OVERRIDE, includeThis = true, includeSubclasses = true)
    public static void getTypedEntities(Level level, EntityTypeTest<Entity, Entity> typeTest, AABB bounds, Predicate<? super Entity> predicate, List<? super Entity> output) {
        getTypedEntities(level, typeTest, bounds, predicate, output, Integer.MAX_VALUE);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/LevelEntityGetterAdapter",
        targetMethod = "getAll",
        targetAliases = "m_142273_",
        targetDescriptor = "()Ljava/lang/Iterable;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static Iterable<EntityAccess> getAll(LevelEntityGetterAdapter<EntityAccess> getter) {
        Set<EntityAccess> entities = Collections.newSetFromMap(new IdentityHashMap<>());
        getter.visibleEntities.getAllEntities().forEach(entity -> {
            if (!CivilizationSurvival.shouldDeath(entity)) {
                entities.add(entity);
            }
        });
        Level level = GETTER_LEVELS.get(getter);
        if (level != null) {
            entities.addAll(CivilizationSurvival.owners(level));
            entities.add(SecretEntity.instance(level));
        }
        entities.remove(null);
        return Collections.unmodifiableSet(entities);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/LevelEntityGetterAdapter",
        targetMethod = "get",
        targetAliases = "m_142597_",
        targetDescriptor = "(I)Lnet/minecraft/world/level/entity/EntityAccess;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static EntityAccess getById(LevelEntityGetterAdapter<EntityAccess> getter, int id) {
        Level level = GETTER_LEVELS.get(getter);
        SecretEntity secret = SecretEntity.instance(level);
        if (secret != null && AuthoritativeEntityTopology.capturedId(secret) == id) return secret;
        Player owner = CivilizationSurvival.owner(level, id);
        if (owner != null) return owner;
        EntityAccess entity = getter.visibleEntities.getEntity(id);
        return CivilizationSurvival.shouldDeath(entity) ? null : entity;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/LevelEntityGetterAdapter",
        targetMethod = "get",
        targetAliases = "m_142694_",
        targetDescriptor = "(Ljava/util/UUID;)Lnet/minecraft/world/level/entity/EntityAccess;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static EntityAccess getByUuid(LevelEntityGetterAdapter<EntityAccess> getter, UUID uuid) {
        Level level = GETTER_LEVELS.get(getter);
        SecretEntity secret = SecretEntity.instance(level);
        if (secret != null && AuthoritativeEntityTopology.capturedUuid(secret).equals(uuid)) return secret;
        Player owner = CivilizationSurvival.owner(level, uuid);
        if (owner != null) return owner;
        EntityAccess entity = getter.visibleEntities.getEntity(uuid);
        return CivilizationSurvival.shouldDeath(entity) ? null : entity;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/LevelEntityGetterAdapter",
        targetMethod = "get",
        targetAliases = "m_142690_",
        targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Lnet/minecraft/util/AbortableIterationConsumer;)V",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static void getTyped(
        LevelEntityGetterAdapter<EntityAccess> getter,
        EntityTypeTest<EntityAccess, EntityAccess> typeTest,
        AbortableIterationConsumer<EntityAccess> consumer
    ) {
        Level level = GETTER_LEVELS.get(getter);
        if (level != null) {
            for (Player owner : CivilizationSurvival.owners(level)) {
                EntityAccess cast = typeTest.tryCast(owner);
                if (cast != null && consumer.accept(cast).shouldAbort()) return;
            }
            SecretEntity secret = SecretEntity.instance(level);
            EntityAccess cast = secret == null ? null : typeTest.tryCast(secret);
            if (cast != null && consumer.accept(cast).shouldAbort()) return;
        }
        getter.visibleEntities.getEntities(typeTest, entity -> CivilizationSurvival.shouldDeath(entity) || isQueryInjected(entity)
            ? AbortableIterationConsumer.Continuation.CONTINUE
            : consumer.accept(entity));
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/LevelEntityGetterAdapter",
        targetMethod = "get",
        targetAliases = "m_142232_",
        targetDescriptor = "(Lnet/minecraft/world/phys/AABB;Ljava/util/function/Consumer;)V",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static void getInBounds(
        LevelEntityGetterAdapter<EntityAccess> getter,
        AABB bounds,
        Consumer<EntityAccess> consumer
    ) {
        Level level = GETTER_LEVELS.get(getter);
        if (level != null) {
            for (Player owner : CivilizationSurvival.owners(level)) {
                if (owner.getBoundingBox().intersects(bounds)) consumer.accept(owner);
            }
            SecretEntity secret = SecretEntity.instance(level);
            if (secret != null && secret.getBoundingBox().intersects(bounds)) consumer.accept(secret);
        }
        getter.sectionStorage.getEntities(bounds, entity -> {
            if (!CivilizationSurvival.shouldDeath(entity) && !isQueryInjected(entity)) {
                consumer.accept(entity);
            }
            return AbortableIterationConsumer.Continuation.CONTINUE;
        });
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/LevelEntityGetterAdapter",
        targetMethod = "get",
        targetAliases = "m_142137_",
        targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Lnet/minecraft/world/phys/AABB;Lnet/minecraft/util/AbortableIterationConsumer;)V",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static void getTypedInBounds(
        LevelEntityGetterAdapter<EntityAccess> getter,
        EntityTypeTest<EntityAccess, EntityAccess> typeTest,
        AABB bounds,
        AbortableIterationConsumer<EntityAccess> consumer
    ) {
        Level level = GETTER_LEVELS.get(getter);
        if (level != null) {
            for (Player owner : CivilizationSurvival.owners(level)) {
                EntityAccess cast = typeTest.tryCast(owner);
                if (cast != null && owner.getBoundingBox().intersects(bounds)
                    && consumer.accept(cast).shouldAbort()) return;
            }
            SecretEntity secret = SecretEntity.instance(level);
            EntityAccess cast = secret == null ? null : typeTest.tryCast(secret);
            if (cast != null && secret.getBoundingBox().intersects(bounds)
                && consumer.accept(cast).shouldAbort()) return;
        }
        getter.sectionStorage.getEntities(typeTest, bounds, entity -> CivilizationSurvival.shouldDeath(entity) || isQueryInjected(entity)
            ? AbortableIterationConsumer.Continuation.CONTINUE
            : consumer.accept(entity));
    }

    @AsmHook(targetClass="net/minecraft/world/level/entity/EntityTickList", targetMethod="remove", targetAliases="m_156912_", targetDescriptor="(Lnet/minecraft/world/entity/Entity;)V", mode=HookMode.GUARD, includeThis=true)
    public static boolean removeFromTickList(EntityTickList ticks,Entity entity) { return isRemovalProtected(entity); }
    @AsmHook(targetClass="net/minecraft/world/level/entity/EntityTickList", targetMethod="add", targetAliases="m_156908_", targetDescriptor="(Lnet/minecraft/world/entity/Entity;)V", mode=HookMode.GUARD, includeThis=true)
    public static boolean addToTickList(EntityTickList ticks,Entity entity) { return blockedEntry(entity.level(),entity); }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/EntityLookup",
        targetMethod = "remove",
        targetAliases = "m_156822_",
        targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityAccess;)V",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static void removeFromLookup(EntityLookup<EntityAccess> lookup, EntityAccess entity) {
        if (isRemovalProtected(entity)) {
            return;
        }
        lookup.byUuid.remove(entity.getUUID(), entity);
        if (lookup.byId.get(entity.getId()) == entity) {
            lookup.byId.remove(entity.getId());
        }
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/EntityLookup",
        targetMethod = "add",
        targetAliases = "m_156814_",
        targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityAccess;)V",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static void addToLookup(EntityLookup<EntityAccess> lookup, EntityAccess entity) {
        if (CivilizationSurvival.shouldDeath(entity)) {
            lookup.byUuid.remove(entity.getUUID(), entity);
            if (lookup.byId.get(entity.getId()) == entity) {
                lookup.byId.remove(entity.getId());
            }
            return;
        }
        if (entity instanceof SecretEntity secret) {
            LOOKUP_LEVELS.put(lookup, secret.level());
        }
        EntityAccess existing = lookup.byUuid.get(entity.getUUID());
        if (existing != null && existing != entity) {
            return;
        }
        lookup.byUuid.put(entity.getUUID(), entity);
        lookup.byId.put(entity.getId(), entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/EntityLookup",
        targetMethod = "getEntity",
        targetAliases = "m_156812_",
        targetDescriptor = "(I)Lnet/minecraft/world/level/entity/EntityAccess;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static EntityAccess getLookupById(EntityLookup<EntityAccess> lookup, int id) {
        Level level = LOOKUP_LEVELS.get(lookup);
        SecretEntity secret = SecretEntity.instance(level);
        if (secret != null && AuthoritativeEntityTopology.capturedId(secret) == id) return secret;
        Player owner = CivilizationSurvival.owner(level, id);
        if (owner != null) return owner;
        EntityAccess entity = lookup.byId.get(id);
        return CivilizationSurvival.shouldDeath(entity) ? null : entity;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/EntityLookup",
        targetMethod = "getEntity",
        targetAliases = "m_156819_",
        targetDescriptor = "(Ljava/util/UUID;)Lnet/minecraft/world/level/entity/EntityAccess;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static EntityAccess getLookupByUuid(EntityLookup<EntityAccess> lookup, UUID uuid) {
        Level level = LOOKUP_LEVELS.get(lookup);
        SecretEntity secret = SecretEntity.instance(level);
        if (secret != null && AuthoritativeEntityTopology.capturedUuid(secret).equals(uuid)) return secret;
        Player owner = CivilizationSurvival.owner(level, uuid);
        if (owner != null) return owner;
        EntityAccess entity = lookup.byUuid.get(uuid);
        return CivilizationSurvival.shouldDeath(entity) ? null : entity;
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/EntityLookup",
        targetMethod = "getAllEntities",
        targetAliases = "m_156811_",
        targetDescriptor = "()Ljava/lang/Iterable;",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static Iterable<EntityAccess> getAllLookupEntities(EntityLookup<EntityAccess> lookup) {
        Set<EntityAccess> entities = Collections.newSetFromMap(new IdentityHashMap<>());
        Level level = LOOKUP_LEVELS.get(lookup);
        if (level != null) {
            entities.addAll(CivilizationSurvival.owners(level));
            entities.add(SecretEntity.instance(level));
        }
        lookup.byId.values().forEach(entity -> {
            if (!CivilizationSurvival.shouldDeath(entity)) entities.add(entity);
        });
        entities.remove(null);
        return Collections.unmodifiableSet(entities);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/EntityLookup",
        targetMethod = "getEntities",
        targetAliases = "m_260822_",
        targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityTypeTest;Lnet/minecraft/util/AbortableIterationConsumer;)V",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static void getLookupEntities(
        EntityLookup<EntityAccess> lookup,
        EntityTypeTest<EntityAccess, EntityAccess> typeTest,
        AbortableIterationConsumer<EntityAccess> consumer
    ) {
        Level level = LOOKUP_LEVELS.get(lookup);
        if (level != null) {
            for (Player owner : CivilizationSurvival.owners(level)) {
                EntityAccess cast = typeTest.tryCast(owner);
                if (cast != null && consumer.accept(cast).shouldAbort()) return;
            }
            SecretEntity secret = SecretEntity.instance(level);
            EntityAccess cast = secret == null ? null : typeTest.tryCast(secret);
            if (cast != null && consumer.accept(cast).shouldAbort()) return;
        }
        for (EntityAccess entity : new ArrayList<>(lookup.byId.values())) {
            if (CivilizationSurvival.shouldDeath(entity) || isQueryInjected(entity)) continue;
            EntityAccess cast = typeTest.tryCast(entity);
            if (cast != null && consumer.accept(cast).shouldAbort()) {
                return;
            }
        }
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/EntityLookup",
        targetMethod = "count",
        targetAliases = "m_156821_",
        targetDescriptor = "()I",
        mode = HookMode.OVERRIDE,
        includeThis = true,
        includeSubclasses = true
    )
    public static int countLookupEntities(EntityLookup<EntityAccess> lookup) {
        Set<EntityAccess> entities = Collections.newSetFromMap(new IdentityHashMap<>());
        getAllLookupEntities(lookup).forEach(entities::add);
        return entities.size();
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ChunkMap",
        targetMethod = "removeEntity",
        targetAliases = "m_140331_",
        targetDescriptor = "(Lnet/minecraft/world/entity/Entity;)V",
        mode = HookMode.GUARD,
        includeThis = true,
        includeSubclasses = true
    )
    public static boolean guardChunkMapRemoval(ChunkMap chunkMap, Entity entity) {
        return isRemovalProtected(entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/server/level/ChunkMap",
        targetMethod = "addEntity",
        targetAliases = "m_140199_",
        targetDescriptor = "(Lnet/minecraft/world/entity/Entity;)V",
        mode = HookMode.GUARD,
        includeThis = true,
        includeSubclasses = true
    )
    public static boolean guardChunkMapAdd(ChunkMap chunkMap, Entity entity) {
        return CivilizationSurvival.shouldDeath(entity);
    }

    @AsmHook(
        targetClass = "net/minecraft/world/level/entity/PersistentEntitySectionManager",
        targetMethod = "unloadEntity",
        targetAliases = "m_157585_",
        targetDescriptor = "(Lnet/minecraft/world/level/entity/EntityAccess;)V",
        mode = HookMode.GUARD,
        includeThis = true,
        includeSubclasses = true
    )
    public static boolean guardPersistentUnload(
        PersistentEntitySectionManager<EntityAccess> manager,
        EntityAccess entity
    ) {
        return isRemovalProtected(entity);
    }

    public static void clearLevel(Level level) {
        GETTER_LEVELS.entrySet().removeIf(entry -> entry.getValue() == level);
        LOOKUP_LEVELS.entrySet().removeIf(entry -> entry.getValue() == level);
        ENTITY_MANAGER_LEVELS.entrySet().removeIf(entry -> entry.getValue() == level);
        GUARDED_LEVEL_GETTERS.remove(level);
    }

    public static void registerLevel(Level level) {
        register(level);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Iterable<Entity> getAllEntities(LevelEntityGetterAdapter<Entity> getter) {
        return (Iterable) getAll((LevelEntityGetterAdapter) getter);
    }

    @SuppressWarnings("unchecked")
    private static LevelEntityGetter<Entity> register(Level level) {
        LevelEntityGetter<Entity> getter = level.getEntities();
        associateGetter(level, getter);
        if (level instanceof ServerLevel serverLevel) {
            if (serverLevel.entityManager != null) ENTITY_MANAGER_LEVELS.put(serverLevel.entityManager, level);
        }
        if (level instanceof ClientLevel clientLevel) {
            if (clientLevel.entityStorage != null) ENTITY_MANAGER_LEVELS.put(clientLevel.entityStorage, level);
        }
        return getter;
    }

    private static LevelEntityGetter<Entity> guardGetter(Level level, LevelEntityGetter<Entity> getter) {
        if (level == null) return getter;
        if (getter == null) {
            return new GuardedLevelEntityGetter(level, EmptyLevelEntityGetter.INSTANCE);
        }
        associateGetter(level, getter);
        if (getter instanceof GuardedLevelEntityGetter guarded && guarded.level == level) {
            return getter;
        }
        return GUARDED_LEVEL_GETTERS.compute(level, (ignored, current) ->
            current != null && current.delegate == getter
                ? current
                : new GuardedLevelEntityGetter(level, getter)
        );
    }

    private static LevelEntityGetter<Entity> guardManagerGetter(
        Object manager,
        LevelEntityGetter<Entity> getter
    ) {
        Level level = ENTITY_MANAGER_LEVELS.get(manager);
        if (level == null && getter != null) level = GETTER_LEVELS.get(getter);
        return guardGetter(level, getter);
    }

    private static void associateGetter(Level level, LevelEntityGetter<?> getter) {
        if (level == null || getter == null) return;
        if (getter instanceof GuardedLevelEntityGetter guarded) {
            associateGetter(level, guarded.delegate);
        } else if (getter instanceof LevelEntityGetterAdapter<?> adapter) {
            GETTER_LEVELS.put(getter, level);
            LOOKUP_LEVELS.put(adapter.visibleEntities, level);
        }
    }

    private static Iterable<Entity> withSecret(Level level, Iterable<Entity> source) {
        Set<Entity> entities = Collections.newSetFromMap(new IdentityHashMap<>());
        entities.addAll(CivilizationSurvival.owners(level));
        if (source != null) {
            source.forEach(entity -> {
                if (!CivilizationSurvival.shouldDeath(entity)) {
                    entities.add(entity);
                }
            });
        }
        SecretEntity secret = SecretEntity.instance(level);
        if (secret != null) {
            entities.add(secret);
        }
        return Collections.unmodifiableSet(entities);
    }

    private static boolean isOwner(EntityAccess entity) {
        return CivilizationSurvival.isOwner(entity instanceof Entity value ? value : null);
    }

    private static boolean isQueryInjected(EntityAccess entity) {
        return entity instanceof SecretEntity || isOwner(entity);
    }

    private static boolean isRemovalProtected(EntityAccess entity) {
        return entity instanceof Player player && isOwner(player) && !OwnerSafety.inLifecycle(player);
    }

    private static void purgeLookupEntity(EntityLookup<EntityAccess> lookup, EntityAccess entity) {
        if (entity == null) {
            return;
        }
        lookup.byUuid.remove(entity.getUUID(), entity);
        if (lookup.byId.get(entity.getId()) == entity) {
            lookup.byId.remove(entity.getId());
        }
    }

    private static void addEntity(
        Entity entity,
        Entity excluded,
        AABB bounds,
        Predicate<? super Entity> predicate,
        List<Entity> output
    ) {
        if (entity != null && !CivilizationSurvival.shouldDeath(entity)
            && entity != excluded && entity.getBoundingBox().intersects(bounds)
            && predicate.test(entity) && !output.contains(entity)) {
            output.add(entity);
        }
    }

    private static void addTyped(
        Entity secret,
        EntityTypeTest<Entity, Entity> typeTest,
        AABB bounds,
        Predicate<? super Entity> predicate,
        List<? super Entity> output,
        int limit
    ) {
        if (secret == null || output.size() >= limit
            || bounds != null && !secret.getBoundingBox().intersects(bounds)) {
            return;
        }
        Entity entity = typeTest.tryCast(secret);
        if (entity != null && predicate.test(entity) && !output.contains(entity)) {
            output.add(entity);
        }
    }

    private static void addSecretTyped(
        SecretEntity secret,
        EntityTypeTest<Entity, Entity> typeTest,
        List<? super Entity> output,
        int limit
    ) {
        if (secret == null || output.size() >= limit) return;
        Entity entity = typeTest.tryCast(secret);
        if (entity != null && !output.contains(entity)) output.add(entity);
    }

    private static AbortableIterationConsumer.Continuation addResult(
        Entity entity,
        Predicate<? super Entity> predicate,
        List<? super Entity> output,
        int limit
    ) {
        if (!CivilizationSurvival.shouldDeath(entity) && predicate.test(entity) && !output.contains(entity)) {
            output.add(entity);
        }
        return output.size() >= limit
            ? AbortableIterationConsumer.Continuation.ABORT
            : AbortableIterationConsumer.Continuation.CONTINUE;
    }

    private static final class GuardedLevelEntityGetter implements LevelEntityGetter<Entity> {
        private final Level level;
        private final LevelEntityGetter<Entity> delegate;

        private GuardedLevelEntityGetter(Level level, LevelEntityGetter<Entity> delegate) {
            this.level = level;
            this.delegate = delegate;
        }

        @Override
        public Entity get(int id) {
            SecretEntity secret = SecretEntity.instance(level);
            if (secret != null && AuthoritativeEntityTopology.capturedId(secret) == id) return secret;
            Player owner = CivilizationSurvival.owner(level, id);
            if (owner != null) return owner;
            Entity entity = delegate.get(id);
            return CivilizationSurvival.shouldDeath(entity) ? null : entity;
        }

        @Override
        public Entity get(UUID uuid) {
            if (uuid == null) return null;
            SecretEntity secret = SecretEntity.instance(level);
            if (secret != null && uuid.equals(AuthoritativeEntityTopology.capturedUuid(secret))) return secret;
            Player owner = CivilizationSurvival.owner(level, uuid);
            if (owner != null) return owner;
            Entity entity = delegate.get(uuid);
            return CivilizationSurvival.shouldDeath(entity) ? null : entity;
        }

        @Override
        public Iterable<Entity> getAll() {
            return withSecret(level, delegate.getAll());
        }

        @Override
        public <U extends Entity> void get(
            EntityTypeTest<Entity, U> typeTest,
            AbortableIterationConsumer<U> consumer
        ) {
            Set<Entity> emitted = Collections.newSetFromMap(new IdentityHashMap<>());
            for (Player owner : CivilizationSurvival.owners(level)) {
                U cast = typeTest.tryCast(owner);
                if (cast != null && emitted.add(owner) && consumer.accept(cast).shouldAbort()) return;
            }
            SecretEntity secret = SecretEntity.instance(level);
            U cast = secret == null ? null : typeTest.tryCast(secret);
            if (cast != null && emitted.add(secret) && consumer.accept(cast).shouldAbort()) return;
            delegate.get(typeTest, entity -> {
                if (entity == null || CivilizationSurvival.shouldDeath(entity) || !emitted.add(entity)) {
                    return AbortableIterationConsumer.Continuation.CONTINUE;
                }
                return consumer.accept(entity);
            });
        }

        @Override
        public void get(AABB bounds, Consumer<Entity> consumer) {
            Set<Entity> emitted = Collections.newSetFromMap(new IdentityHashMap<>());
            for (Player owner : CivilizationSurvival.owners(level)) {
                if (owner.getBoundingBox().intersects(bounds) && emitted.add(owner)) consumer.accept(owner);
            }
            SecretEntity secret = SecretEntity.instance(level);
            if (secret != null && secret.getBoundingBox().intersects(bounds) && emitted.add(secret)) {
                consumer.accept(secret);
            }
            delegate.get(bounds, entity -> {
                if (entity != null && !CivilizationSurvival.shouldDeath(entity) && emitted.add(entity)) {
                    consumer.accept(entity);
                }
            });
        }

        @Override
        public <U extends Entity> void get(
            EntityTypeTest<Entity, U> typeTest,
            AABB bounds,
            AbortableIterationConsumer<U> consumer
        ) {
            Set<Entity> emitted = Collections.newSetFromMap(new IdentityHashMap<>());
            for (Player owner : CivilizationSurvival.owners(level)) {
                U cast = typeTest.tryCast(owner);
                if (cast != null && owner.getBoundingBox().intersects(bounds) && emitted.add(owner)
                    && consumer.accept(cast).shouldAbort()) return;
            }
            SecretEntity secret = SecretEntity.instance(level);
            U cast = secret == null ? null : typeTest.tryCast(secret);
            if (cast != null && secret.getBoundingBox().intersects(bounds) && emitted.add(secret)
                && consumer.accept(cast).shouldAbort()) return;
            delegate.get(typeTest, bounds, entity -> {
                if (entity == null || CivilizationSurvival.shouldDeath(entity) || !emitted.add(entity)) {
                    return AbortableIterationConsumer.Continuation.CONTINUE;
                }
                return consumer.accept(entity);
            });
        }
    }

    private enum EmptyLevelEntityGetter implements LevelEntityGetter<Entity> {
        INSTANCE;

        @Override public Entity get(int id) { return null; }
        @Override public Entity get(UUID uuid) { return null; }
        @Override public Iterable<Entity> getAll() { return List.of(); }
        @Override public <U extends Entity> void get(EntityTypeTest<Entity, U> typeTest, AbortableIterationConsumer<U> consumer) { }
        @Override public void get(AABB bounds, Consumer<Entity> consumer) { }
        @Override public <U extends Entity> void get(EntityTypeTest<Entity, U> typeTest, AABB bounds, AbortableIterationConsumer<U> consumer) { }
    }
}
