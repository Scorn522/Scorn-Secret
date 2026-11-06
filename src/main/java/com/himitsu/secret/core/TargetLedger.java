package com.himitsu.secret.core;

import com.himitsu.secret.network.*;
import com.himitsu.secret.network.sync.StringSetSyncValue;
import java.util.*;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.level.Level;

/** Execution identity, never a type, position, mod, player-name or factory blacklist. */
public final class TargetLedger {
    private record Token(net.minecraft.resources.ResourceLocation dimension,UUID uuid,int id) {}
    private record Index(Set<String> source,Map<UUID,List<Token>> rows,
        Map<net.minecraft.resources.ResourceLocation,Token[]> dimensions,
        Map<net.minecraft.resources.ResourceLocation,int[]> ids) {}
    private static final int[] NO_IDS=new int[0];
    private static volatile Index deaths=new Index(Set.of(),Map.of(),Map.of(),Map.of());
    private static volatile Index players=new Index(Set.of(),Map.of(),Map.of(),Map.of());
    private static volatile Index serverDeaths=new Index(Set.of(),Map.of(),Map.of(),Map.of());
    private static volatile Index serverPlayers=new Index(Set.of(),Map.of(),Map.of(),Map.of());
    private static final WeakTargetSet<Entity> exactDeaths=new WeakTargetSet<>();
    private static final WeakTargetSet<Entity> exactPlayers=new WeakTargetSet<>();
    private TargetLedger() {}
    static String token(Entity e) { return e.level().dimension().location()+"|"+e.uuid+"|"+e.getId(); }
    private static Index index(Set<String> source) {
        Map<UUID,List<Token>> rows=new HashMap<>();
        for(String text:source) {
            String[] bits=text.split("\\|",-1); if(bits.length!=3) continue;
            try { UUID uuid=UUID.fromString(bits[1]);
                rows.computeIfAbsent(uuid,k->new ArrayList<>()).add(new Token(new net.minecraft.resources.ResourceLocation(bits[0]),uuid,Integer.parseInt(bits[2])));
            } catch(IllegalArgumentException ignored) { /* Legacy type/name marks are intentionally not accepted. */ }
        }
        Map<net.minecraft.resources.ResourceLocation,List<Token>> grouped=new HashMap<>();
        for(List<Token> values:rows.values()) for(Token t:values) grouped.computeIfAbsent(t.dimension(),k->new ArrayList<>()).add(t);
        Map<net.minecraft.resources.ResourceLocation,Token[]> dimensions=new HashMap<>();
        Map<net.minecraft.resources.ResourceLocation,int[]> ids=new HashMap<>();
        for(var e:grouped.entrySet()) {
            Token[] values=e.getValue().toArray(Token[]::new); int[] keys=new int[values.length];
            for(int i=0;i<values.length;i++) keys[i]=values[i].id();
            dimensions.put(e.getKey(),values); ids.put(e.getKey(),keys);
        }
        return new Index(source,rows,Map.copyOf(dimensions),Map.copyOf(ids));
    }
    public static boolean marked(Entity e) { return marked(e,false); }
    static boolean marked(Entity e,boolean playerOnly) {
        if(e==null) return false;
        if((playerOnly ? exactPlayers : exactDeaths).contains(e)) return true;
        Index cached=current(e.level().isClientSide(),playerOnly);
        List<Token> rows=cached.rows().get(e.uuid); if(rows==null) return false;
        for(int i=0;i<rows.size();i++) { Token t=rows.get(i); if(t.id()==e.getId() && t.dimension().equals(e.level().dimension().location())) return true; }
        return false;
    }
    static boolean blockedUuid(Level level,UUID uuid) {
        Index cached=current(level.isClientSide(),false);
        List<Token> rows=cached.rows().get(uuid); if(rows==null) return false;
        for(int i=0;i<rows.size();i++) if(rows.get(i).dimension().equals(level.dimension().location())) return true;
        return false;
    }
    static void rememberClient(Entity e) { exactDeaths.add(e,e.level()); }
    static int[] ids(Level level) {
        return current(level.isClientSide(),false).ids().getOrDefault(level.dimension().location(),NO_IDS);
    }
    static void inspect(net.minecraft.server.level.ServerLevel level) {
        if(!AuthoritativeEntityTopology.open(level)) return;
        Token[] tokens=serverDeaths.dimensions().get(level.dimension().location());
        if(tokens==null) return;
        for(int i=0;i<tokens.length;i++) {
            Token t=tokens[i];
            Entity first=level.entityManager.visibleEntityStorage.byId.get(t.id());
            Entity second=level.entityManager.visibleEntityStorage.byUuid.get(t.uuid());
            Entity third=level.entityTickList.active.get(t.id());
            reconcile(level,t,first);
            if(second!=first) reconcile(level,t,second);
            if(third!=first && third!=second) reconcile(level,t,third);
        }
    }
    private static void reconcile(net.minecraft.server.level.ServerLevel level,Token token,Entity entity) {
        if(entity==null || entity.level()!=level || entity instanceof com.himitsu.secret.entity.SecretEntity
            || CivilizationSurvival.isOwner(entity) || !(entity.uuid.equals(token.uuid()) || marked(entity))) return;
        CivilizationSurvival.removeExecutedTarget(entity);
        TargetCleanup.requestRetry(entity);
    }
    private static Index current(boolean clientSide,boolean playerOnly) {
        if(!clientSide) return playerOnly ? serverPlayers : serverDeaths;
        Set<String> snapshot=(playerOnly ? RuntimeSyncState.DEATH_EXECUTED : RuntimeSyncState.CIVILIZATION_DEATHS).snapshot();
        Index cached=playerOnly ? players : deaths;
        if(cached.source()!=snapshot) { cached=index(snapshot); if(playerOnly) players=cached; else deaths=cached; }
        return cached;
    }
    static void mark(Entity e,boolean playerOnly) { markAll(List.of(e),playerOnly); }
    static synchronized void markAll(Collection<Entity> entities,boolean playerOnly) {
        if(entities.isEmpty()) return;
        StringSetSyncValue value=playerOnly ? RuntimeSyncState.DEATH_EXECUTED : RuntimeSyncState.CIVILIZATION_DEATHS;
        Index prior=playerOnly ? serverPlayers : serverDeaths;
        Set<String> next=new LinkedHashSet<>(prior.source());
        boolean changed=false;
        for(Entity e:entities) {
            if(e.level().isClientSide()) continue;
            (playerOnly ? exactPlayers : exactDeaths).add(e,e.level());
            changed|=next.add(token(e));
        }
        if(changed) {
            Index published=index(Set.copyOf(next));
            if(playerOnly) serverPlayers=published; else serverDeaths=published;
            value.replace(next);
            if(SecretNetwork.isInitialized()) SecretNetwork.sendAll(value);
        }
    }
    public static synchronized void publishServerSnapshot() {
        RuntimeSyncState.CIVILIZATION_DEATHS.replace(serverDeaths.source());
        RuntimeSyncState.DEATH_EXECUTED.replace(serverPlayers.source());
    }
    static synchronized void clearLevel(Level level) {
        exactDeaths.clearScope(level); exactPlayers.clearScope(level);
        if(level.isClientSide()) return;
        String prefix=level.dimension().location()+"|";
        Set<String> next=new LinkedHashSet<>(serverDeaths.source());
        next.removeIf(s->s.startsWith(prefix)); serverDeaths=index(Set.copyOf(next));
        next=new LinkedHashSet<>(serverPlayers.source());
        next.removeIf(s->s.startsWith(prefix)); serverPlayers=index(Set.copyOf(next));
        publishServerSnapshot();
    }
    static synchronized void clearDeaths() {
        exactDeaths.clear();
        serverDeaths=new Index(Set.of(),Map.of(),Map.of(),Map.of());
        RuntimeSyncState.CIVILIZATION_DEATHS.replace(Set.of());
    }
}
