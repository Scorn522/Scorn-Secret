package com.himitsu.secret.core;

import java.lang.reflect.*;
import java.util.*;
import com.himitsu.secret.network.*;
import net.minecraft.client.Minecraft;
import net.minecraft.nbt.*;
import net.minecraft.server.level.*;
import net.minecraft.server.bossevents.CustomBossEvent;
import net.minecraft.world.BossEvent;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.level.saveddata.SavedData;

/** One explicit execution, bounded reference depth. No background graph scan or type-wide purge. */
public final class TargetCleanup {
    private static final ClassValue<Field[]> FIELDS=new ClassValue<>() {
        @Override protected Field[] computeValue(Class<?> type) {
            List<Field> fields=new ArrayList<>();
            for(Class<?> c=type;c!=null && c!=Object.class && c!=Entity.class;c=c.getSuperclass()) {
                if(c.getName().startsWith("java.") || c.getName().startsWith("net.minecraft.world.entity.LivingEntity")) break;
                for(Field f:c.getDeclaredFields()) if(!f.getType().isPrimitive() && f.trySetAccessible()) fields.add(f);
            }
            return fields.toArray(Field[]::new);
        }
    };
    private static Set<String> appliedBossBars=Set.of();
    private TargetCleanup() {}
    static void clean(Entity target) {
        if(target.level() instanceof ServerLevel server && !server.getServer().isSameThread()) {
            server.getServer().execute(()->clean(target)); return;
        }
        if(!(target.level() instanceof ServerLevel server)) return;
        Cleaner cleaner=new Cleaner(target);
        // Only statics declared by the actual target hierarchy. Shared framework classes are excluded.
        for(Class<?> c=target.getClass();c!=null && c!=Entity.class;c=c.getSuperclass()) {
            if(c.getName().startsWith("net.minecraft.")) break;
            for(Field f:FIELDS.get(c)) if(Modifier.isStatic(f.getModifiers())) cleaner.field(null,f);
        }
        cleaner.bossFields(target,0);
        // Do not evict SavedData: edit only the matched record and mark its owning file dirty.
        for(SavedData data:new ArrayList<>(server.getDataStorage().cache.values())) {
            if(data==null) continue;
            boolean changed=false;
            cleaner.knownNbtRecords=data.getClass().getName().equals("plz.lizi.supersteve.level.SSSaveData");
            for(Field f:FIELDS.get(data.getClass())) if(!Modifier.isStatic(f.getModifiers())) changed|=cleaner.field(data,f);
            if(changed) data.setDirty();
        }
        if(!cleaner.bars.isEmpty()) {
            Set<String> ids=new LinkedHashSet<>(RuntimeSyncState.TARGET_BOSS_BARS.snapshot());
            ids.addAll(cleaner.bars); RuntimeSyncState.TARGET_BOSS_BARS.replace(ids);
            if(SecretNetwork.isInitialized()) SecretNetwork.sendAll(RuntimeSyncState.TARGET_BOSS_BARS);
        }
        if(cleaner.failures>0) System.err.println("[Secret/TargetCleanup] partial target="+target.uuid+" inaccessible-or-changing-fields="+cleaner.failures);
    }
    public static void applyBossRemovals() {
        Set<String> ids=RuntimeSyncState.TARGET_BOSS_BARS.snapshot();
        if(ids==appliedBossBars) return;
        Minecraft minecraft=Minecraft.getInstance();
        if(minecraft==null || minecraft.gui==null) return;
        for(String id:ids) try { minecraft.gui.getBossOverlay().events.remove(UUID.fromString(id)); }
            catch(IllegalArgumentException ignored) {}
        appliedBossBars=ids;
    }
    private static final class Cleaner {
        final Entity target; final UUID uuid;
        final Set<Object> seen=Collections.newSetFromMap(new IdentityHashMap<>());
        final Set<String> bars=new LinkedHashSet<>();
        final Set<Object> changedContainers=Collections.newSetFromMap(new IdentityHashMap<>());
        int failures;
        boolean knownNbtRecords;
        Cleaner(Entity target) { this.target=target; uuid=target.uuid; }
        boolean record(Object value) {
            if(value==target) return true;
            if(value==null || value instanceof Entity) return false;
            if(value instanceof CompoundTag tag) return knownNbtRecords && tag.hasUUID("UUID") && uuid.equals(tag.getUUID("UUID"));
            if(value instanceof Map || value instanceof Collection || value.getClass().isArray()) return false;
            boolean matched=false;
            for(Field f:FIELDS.get(value.getClass())) {
                if(Modifier.isStatic(f.getModifiers())) continue;
                Object v=get(f,value);
                if(v==target) matched=true;
                // Only explicit entity identity fields, never owner/player UUID collections or type names.
                String name=f.getName().replace("_", "").toLowerCase(Locale.ROOT);
                if(value.getClass().getName().equals("cn.blockforge.dyingsol.entity.BossIntegrityAgent$BossRecord")
                    && v instanceof UUID && name.equals("uuid") && uuid.equals(v)) matched=true;
                // A server/client pair must retain the unrelated member, not lose the whole wrapper.
                if(v instanceof Entity && v!=target) return false;
            }
            return matched;
        }
        Object get(Field f,Object owner) {
            try { return f.get(owner); } catch(ReflectiveOperationException | RuntimeException error) { failures++; return null; }
        }
        boolean field(Object owner,Field f) {
            Object value=get(f,owner); if(value==null) return false;
            if(value==target) {
                try { f.set(owner,null); return true; } catch(ReflectiveOperationException | RuntimeException error) { failures++; return false; }
            }
            return contents(value,0);
        }
        @SuppressWarnings({"rawtypes","unchecked"})
        boolean contents(Object value,int depth) {
            if(value==null || value instanceof Entity || value instanceof BossEvent) return false;
            if(!seen.add(value)) return changedContainers.contains(value);
            boolean changed=false;
            try {
                if(value instanceof Map map) {
                    for(Object raw:new ArrayList<>(map.entrySet())) {
                        Map.Entry entry=(Map.Entry)raw; Object old=entry.getValue();
                        if(record(old)) {
                            bossFields(old,0);
                            if(map.get(entry.getKey())==old) changed|=map.remove(entry.getKey(),old);
                        } else { changed|=directReferences(old); if(depth==0) changed|=contents(old,1); }
                    }
                } else if(value instanceof ListTag tags) {
                    for(int i=tags.size()-1;i>=0;i--) if(record(tags.get(i))) { tags.remove(i); changed=true; }
                } else if(value instanceof Collection collection) {
                    Iterator it=collection.iterator();
                    while(it.hasNext()) { Object old=it.next();
                        if(record(old)) { bossFields(old,0); it.remove(); changed=true; }
                        else { changed|=directReferences(old); if(depth==0) changed|=contents(old,1); }
                    }
                } else if(value.getClass().isArray() && !value.getClass().getComponentType().isPrimitive()) {
                    Object[] array=(Object[])value;
                    for(int i=0;i<array.length;i++) if(record(array[i])) { bossFields(array[i],0); array[i]=null; changed=true; }
                } else if(depth==0) {
                    // One wrapper such as EntityInstance: clear only its exact target reference.
                    for(Field f:FIELDS.get(value.getClass())) if(!Modifier.isStatic(f.getModifiers())) {
                        Object child=get(f,value);
                        if(child==target) { f.set(value,null); changed=true; }
                        else if(child instanceof Map || child instanceof Collection || child instanceof ListTag) changed|=contents(child,1);
                    }
                }
            } catch(ReflectiveOperationException | RuntimeException error) { failures++; }
            if(changed) {
                changedContainers.add(value);
                if(value instanceof SavedData data) data.setDirty();
            }
            return changed;
        }
        boolean directReferences(Object wrapper) {
            if(wrapper==null || wrapper instanceof Entity || wrapper instanceof BossEvent
                || wrapper instanceof Map || wrapper instanceof Collection || wrapper.getClass().isArray()) return false;
            boolean changed=false;
            for(Field f:FIELDS.get(wrapper.getClass())) if(!Modifier.isStatic(f.getModifiers()) && get(f,wrapper)==target) {
                try { f.set(wrapper,null); changed=true; }
                catch(ReflectiveOperationException | RuntimeException error) { failures++; }
            }
            return changed;
        }
        void bossFields(Object owner,int depth) {
            if(owner==null) return;
            if(owner instanceof ServerBossEvent event) {
                bars.add(event.getId().toString()); event.removeAllPlayers();
                if(event instanceof CustomBossEvent custom && target.level() instanceof ServerLevel level)
                    level.getServer().getCustomBossEvents().remove(custom);
                return;
            }
            if(owner instanceof Entity && owner!=target) return;
            if(depth>1) return;
            for(Field f:FIELDS.get(owner.getClass())) if(!Modifier.isStatic(f.getModifiers())) {
                Object child=get(f,owner);
                if(child instanceof BossEvent) bossFields(child,depth+1);
                else if(depth==0 && child!=null && !(child instanceof Entity) && !(child instanceof Collection) && !(child instanceof Map)) bossFields(child,1);
            }
        }
    }
}
