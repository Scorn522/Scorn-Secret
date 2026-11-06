package com.himitsu.secret.core;

import com.himitsu.secret.network.*;
import com.himitsu.secret.network.sync.StringSetSyncValue;
import java.util.*;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.level.Level;

/** Execution identity, never a type, position, mod, player-name or factory blacklist. */
public final class TargetLedger {
    private record Token(String dimension,UUID uuid,int id) {}
    private record Index(Set<String> source,Map<UUID,List<Token>> rows) {}
    private static volatile Index deaths=new Index(Set.of(),Map.of());
    private static volatile Index players=new Index(Set.of(),Map.of());
    private static volatile Index serverDeaths=new Index(Set.of(),Map.of());
    private static volatile Index serverPlayers=new Index(Set.of(),Map.of());
    private static final WeakTargetSet<Entity> exactDeaths=new WeakTargetSet<>();
    private static final WeakTargetSet<Entity> exactPlayers=new WeakTargetSet<>();
    private TargetLedger() {}
    static String token(Entity e) { return e.level().dimension().location()+"|"+e.uuid+"|"+e.getId(); }
    private static Index index(Set<String> source) {
        Map<UUID,List<Token>> rows=new HashMap<>();
        for(String text:source) {
            String[] bits=text.split("\\|",-1); if(bits.length!=3) continue;
            try { UUID uuid=UUID.fromString(bits[1]);
                rows.computeIfAbsent(uuid,k->new ArrayList<>()).add(new Token(bits[0],uuid,Integer.parseInt(bits[2])));
            } catch(IllegalArgumentException ignored) { /* Legacy type/name marks are intentionally not accepted. */ }
        }
        return new Index(source,rows);
    }
    public static boolean marked(Entity e) { return marked(e,false); }
    static boolean marked(Entity e,boolean playerOnly) {
        if(e==null) return false;
        if((playerOnly ? exactPlayers : exactDeaths).contains(e)) return true;
        Index cached=current(e.level().isClientSide(),playerOnly);
        List<Token> rows=cached.rows().get(e.uuid); if(rows==null) return false;
        for(Token t:rows) if(t.id()==e.getId() && t.dimension().equals(e.level().dimension().location().toString())) return true;
        return false;
    }
    static boolean blockedUuid(Level level,UUID uuid) {
        Index cached=current(level.isClientSide(),false);
        List<Token> rows=cached.rows().get(uuid); if(rows==null) return false;
        for(Token t:rows) if(t.dimension().equals(level.dimension().location().toString())) return true;
        return false;
    }
    static void rememberClient(Entity e) { exactDeaths.add(e,e.level()); }
    static int[] ids(Level level) {
        Index cached=current(level.isClientSide(),false);
        it.unimi.dsi.fastutil.ints.IntArrayList ids=new it.unimi.dsi.fastutil.ints.IntArrayList();
        String dimension=level.dimension().location().toString();
        for(List<Token> rows:cached.rows().values()) for(Token t:rows) if(t.dimension().equals(dimension)) ids.add(t.id());
        return ids.toIntArray();
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
        serverDeaths=new Index(Set.of(),Map.of());
        RuntimeSyncState.CIVILIZATION_DEATHS.replace(Set.of());
    }
}
