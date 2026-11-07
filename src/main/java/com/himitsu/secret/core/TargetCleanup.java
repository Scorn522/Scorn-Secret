package com.himitsu.secret.core;

import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
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
                for(Field f:c.getDeclaredFields()) if(!f.getType().isPrimitive()) {
                    // An inaccessible field is unknown, not proof that no other owner exists.
                    try { f.trySetAccessible(); } catch(RuntimeException ignored) {}
                    fields.add(f);
                }
            }
            return fields.toArray(Field[]::new);
        }
    };
    static final int RETRY=1, RETAINED=2;
    private static final Field CALLABLE=taskField("java.util.concurrent.FutureTask","callable"),
        RUNNABLE=taskField("java.util.concurrent.Executors$RunnableAdapter","task"),
        SCHEDULED_OWNER=taskField("java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask","this$0"),
        SCHEDULED_OUTER=taskField("java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask","outerTask");
    private static Field taskField(String type,String name) {
        try { return Class.forName(type,false,null).getDeclaredField(name); }
        catch(ReflectiveOperationException | RuntimeException unavailable) { return null; }
    }
    private static Set<String> appliedBossBars=Set.of();
    private static final WeakTargetSet<Entity> INCOMPLETE=new WeakTargetSet<>(), QUEUED=new WeakTargetSet<>(), EXHAUSTED=new WeakTargetSet<>(), DISPATCHED=new WeakTargetSet<>();
    private static volatile Map<net.minecraft.world.level.Level,ArrayDeque<Map.Entry<java.lang.ref.WeakReference<Entity>,int[]>>> queues=new IdentityHashMap<>();
    private TargetCleanup() {}
    static boolean isIncomplete(Entity target) { return INCOMPLETE.contains(target); }
    static boolean clean(Entity target) {
        if(!(target.level() instanceof ServerLevel level) || !AuthoritativeEntityTopology.open(level)) return true;
        if(!level.getServer().isSameThread()) {
            INCOMPLETE.add(target,level);
            if(DISPATCHED.add(target,level)) level.getServer().tell(new net.minecraft.server.TickTask(level.getServer().getTickCount(),()-> {
                DISPATCHED.remove(target);
                if(target.level()==level && AuthoritativeEntityTopology.open(level) && CivilizationSurvival.shouldDeath(target)) clean(target);
            }));
            return false;
        }
        EXHAUSTED.remove(target);
        int result=attempt(target);
        if(result==0) INCOMPLETE.remove(target);
        else {
            INCOMPLETE.add(target,level);
            if((result&RETRY)==0) EXHAUSTED.add(target,level);
            else requestRetry(target);
        }
        return result==0;
    }
    static void requestRetry(Entity target) {
        if(!INCOMPLETE.contains(target) || EXHAUSTED.contains(target) || QUEUED.contains(target)
            || !(target.level() instanceof ServerLevel level) || !AuthoritativeEntityTopology.open(level)) return;
        if(!level.getServer().isSameThread()) {
            if(DISPATCHED.add(target,level)) level.getServer().tell(new net.minecraft.server.TickTask(level.getServer().getTickCount(),()-> {
                DISPATCHED.remove(target); if(target.level()==level) requestRetry(target);
            }));
            return;
        }
        if(QUEUED.add(target,level)) queue(level).add(new AbstractMap.SimpleEntry<>(new java.lang.ref.WeakReference<>(target),new int[]{0,level.getServer().getTickCount()+20}));
    }
    private static synchronized ArrayDeque<Map.Entry<java.lang.ref.WeakReference<Entity>,int[]>> queue(ServerLevel level) {
        var q=queues.get(level); if(q!=null) return q;
        q=new ArrayDeque<>(); var next=new IdentityHashMap<>(queues); next.put(level,q); queues=next; return q;
    }
    static void retryPending(ServerLevel level) {
        if(!AuthoritativeEntityTopology.open(level)) return;
        var q=queues.get(level); if(q==null || q.isEmpty()) return;
        var entry=q.peek(); int[] state=entry.getValue(); int now=level.getServer().getTickCount();
        if(now-state[1]<0) return;
        q.remove(); Entity target=entry.getKey().get();
        if(target==null) return;
        if(target.level()!=level || !CivilizationSurvival.shouldDeath(target) || !INCOMPLETE.contains(target) || EXHAUSTED.contains(target)) { QUEUED.remove(target); return; }
        int result=attempt(target);
        if(result==0) { INCOMPLETE.remove(target); QUEUED.remove(target); return; }
        if((result&RETRY)==0 || ++state[0]>=3) { EXHAUSTED.add(target,level); QUEUED.remove(target); return; }
        state[1]=now+20; q.add(entry);
    }
    static synchronized void clearLevel(net.minecraft.world.level.Level level) {
        var next=new IdentityHashMap<>(queues); next.remove(level); queues=next;
        INCOMPLETE.clearScope(level); QUEUED.clearScope(level); EXHAUSTED.clearScope(level); DISPATCHED.clearScope(level);
    }
    private static int attempt(Entity target) {
        if(!(target.level() instanceof ServerLevel server) || !AuthoritativeEntityTopology.open(server)) return RETAINED;
        Cleaner cleaner=new Cleaner(target);
        try {
            // FIELDS already includes the hierarchy: visit each declared field once.
            for(Field f:FIELDS.get(target.getClass())) {
                if(f.getDeclaringClass().getName().startsWith("net.minecraft.") || !cleaner.source(f.getDeclaringClass())) continue;
                Object owner=Modifier.isStatic(f.getModifiers())?null:target;
                Object value=cleaner.get(f,owner);
                cleaner.tasks(value);
                if(owner==null) cleaner.field(owner,f,value);
            }
            cleaner.bossFields(target,0);
            cleaner.state(EventBusTakeover.detachTargetState((net.minecraftforge.eventbus.EventBus)net.minecraftforge.common.MinecraftForge.EVENT_BUS,cleaner));
            // Current-world cache only; never evict a SavedData file.
            for(SavedData data:new ArrayList<>(server.getDataStorage().cache.values())) cleaner.savedData(data);
            if(!cleaner.bars.isEmpty()) {
                Set<String> ids=new LinkedHashSet<>(RuntimeSyncState.TARGET_BOSS_BARS.snapshot());
                ids.addAll(cleaner.bars); RuntimeSyncState.TARGET_BOSS_BARS.replace(ids);
                if(SecretNetwork.isInitialized()) SecretNetwork.sendAll(RuntimeSyncState.TARGET_BOSS_BARS);
            }
        } catch(RuntimeException error) { cleaner.failed(error); }
        int result=cleaner.result();
        if(result!=0) System.err.println("[Secret/TargetCleanup] partial target="+target.uuid
            +" retryable="+cleaner.failures+" retained="+cleaner.retained);
        return result;
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
    static final class Cleaner {
        final Entity target; final UUID uuid;
        final Set<Object> seen=Collections.newSetFromMap(new IdentityHashMap<>()), knownSeen=Collections.newSetFromMap(new IdentityHashMap<>());
        final Set<String> bars=new LinkedHashSet<>();
        final Set<Object> changedContainers=Collections.newSetFromMap(new IdentityHashMap<>()), taskSeen=Collections.newSetFromMap(new IdentityHashMap<>()), ownedTasks=Collections.newSetFromMap(new IdentityHashMap<>());
        final Map<Class<?>,Boolean> sources=new IdentityHashMap<>();
        int failures,retained;
        boolean knownNbtRecords;
        Cleaner(Entity target) { this.target=target; uuid=target.uuid; }
        int result() { return (failures==0?0:RETRY)|(retained==0?0:RETAINED); }
        void state(int state) { if((state&RETRY)!=0) failures++; if((state&RETAINED)!=0) retained++; }
        void failed(Exception failure) {
            if(failure instanceof ConcurrentModificationException || failure instanceof IndexOutOfBoundsException) failures++;
            else retained++;
        }
        boolean source(Class<?> type) {
            Boolean known=sources.get(type); if(known!=null) return known;
            boolean same=false;
            try {
                var origin=target.getClass().getProtectionDomain().getCodeSource();
                var candidate=type.getProtectionDomain().getCodeSource();
                same=type.getClassLoader()==target.getClass().getClassLoader() && origin!=null && candidate!=null
                    && origin.getLocation()!=null && candidate.getLocation()!=null
                    && origin.getLocation().toExternalForm().equals(candidate.getLocation().toExternalForm());
            } catch(RuntimeException denied) { retained++; }
            sources.put(type,same); return same;
        }
        Object get(Field f,Object owner) {
            if(f==null) { retained++; return null; }
            try {
                if(!f.canAccess(owner) && !f.trySetAccessible()) { retained++; return null; }
                return f.get(owner);
            } catch(ReflectiveOperationException | RuntimeException error) { retained++; return null; }
        }
        boolean captured(Object value) {
            if(value==null || value instanceof Entity || !source(value.getClass())) return false;
            for(Field f:FIELDS.get(value.getClass())) if(!Modifier.isStatic(f.getModifiers()) && get(f,value)==target) return true;
            return false;
        }
        boolean callback(Object value) {
            Class<?> c=value.getClass();
            return value instanceof Runnable || value instanceof Callable<?> || value instanceof java.util.function.Consumer<?>
                || c.isSynthetic() || c.isAnonymousClass() || (c.isMemberClass() && !Modifier.isStatic(c.getModifiers()));
        }
        boolean record(Object value) {
            if(value==target) return true;
            if(value==null || value instanceof Entity) return false;
            if(value instanceof CompoundTag tag) return knownNbtRecords && tag.hasUUID("UUID") && uuid.equals(tag.getUUID("UUID"));
            // A reference alone does not authorize deleting a wrapper and its other duties.
            if(!value.getClass().getName().equals("cn.blockforge.dyingsol.entity.BossIntegrityAgent$BossRecord") || !source(value.getClass())) return false;
            boolean matched=false; int unreadable=retained;
            for(Field f:FIELDS.get(value.getClass())) if(!Modifier.isStatic(f.getModifiers())) {
                Object v=get(f,value);
                if(v instanceof Entity && v!=target) return false;
                if(v instanceof UUID && f.getName().replace("_", "").equalsIgnoreCase("uuid") && uuid.equals(v)) matched=true;
            }
            return retained==unreadable && matched;
        }
        boolean clear(Object owner,Field f) {
            if(Modifier.isFinal(f.getModifiers())) { retained++; return false; }
            try {
                if(get(f,owner)!=target) { failures++; return false; }
                f.set(owner,null); return true;
            } catch(ReflectiveOperationException | RuntimeException error) { retained++; return false; }
        }
        boolean field(Object owner,Field f,Object value) {
            if(value==null) return false;
            return value==target?clear(owner,f):contents(value,0);
        }
        boolean savedData(SavedData data) {
            if(data==null || !source(data.getClass())) return false;
            boolean previous=knownNbtRecords,changed=false;
            try {
                for(Field f:FIELDS.get(data.getClass())) if(!Modifier.isStatic(f.getModifiers())) {
                    knownNbtRecords=f.getDeclaringClass()==data.getClass() && f.getName().equals("ssList") && f.getType()==ListTag.class
                        && data.getClass().getName().equals("plz.lizi.supersteve.level.SSSaveData");
                    changed|=field(data,f,get(f,data));
                }
            } finally { knownNbtRecords=previous; if(changed) data.setDirty(); }
            return changed;
        }
        @SuppressWarnings({"rawtypes","unchecked"})
        boolean contents(Object value,int depth) {
            if(value==null || value instanceof Entity || value instanceof BossEvent || value instanceof Future<?> || value instanceof Executor) return false;
            if(!(knownNbtRecords?knownSeen:seen).add(value)) return changedContainers.contains(value);
            boolean changed=false;
            try {
                if(value instanceof Map map) {
                    Iterator<Map.Entry> iterator=map.entrySet().iterator();
                    while(iterator.hasNext()) {
                        Map.Entry entry=iterator.next(); Object key=entry.getKey(),old=entry.getValue();
                        if(key==target || record(old)) {
                            if(key==target && shared(old)) { retained++; continue; }
                            boolean ownRecord=record(old);
                            if(remove(map,iterator,entry,key,old)) { changed=true; if(ownRecord) bossFields(old,0); }
                        } else { changed|=directReferences(old); if(depth==0) changed|=contents(old,1); }
                    }
                } else if(value instanceof ListTag tags) {
                    for(int i=tags.size()-1;i>=0;i--) if(record(tags.get(i))) { tags.remove(i); changed=true; }
                } else if(value instanceof Collection collection) {
                    Iterator it=collection.iterator();
                    while(it.hasNext()) { Object old=it.next();
                        if(record(old)) {
                            if((value.getClass()==HashSet.class || value.getClass()==LinkedHashSet.class) && old instanceof Entity) {
                                if(!baseEntityKey(old)) { retained++; continue; }
                                boolean ambiguous=false;
                                for(Object other:collection) if(other!=old && other instanceof Entity e && e.id==((Entity)old).id) {ambiguous=true;break;}
                                if(ambiguous || !collection.contains(old)) {retained++;continue;}
                            }
                            it.remove(); changed=true; bossFields(old,0);
                        }
                        else { changed|=directReferences(old); if(depth==0) changed|=contents(old,1); }
                    }
                } else if(value.getClass().isArray() && !value.getClass().getComponentType().isPrimitive()) {
                    Object[] array=(Object[])value;
                    for(int i=0;i<array.length;i++) { Object old=array[i];
                        if(record(old)) {
                            if(array[i]!=old) { failures++; continue; }
                            array[i]=null; changed=true; bossFields(old,0);
                        } else changed|=directReferences(old);
                    }
                } else if(depth==0 && source(value.getClass())) {
                    if(callback(value)) { if(captured(value)) retained++; return false; }
                    for(Field f:FIELDS.get(value.getClass())) if(!Modifier.isStatic(f.getModifiers())) {
                        Object child=get(f,value);
                        if(child==target) changed|=clear(value,f);
                        else if(child instanceof Map || child instanceof Collection || child instanceof ListTag) changed|=contents(child,1);
                    }
                }
            } catch(RuntimeException error) { failed(error); }
            if(changed) changedContainers.add(value);
            return changed;
        }
        private boolean shared(Object value) {
            if(value instanceof Entity) return value!=target;
            if(value==null || value instanceof String || value instanceof UUID || value instanceof Integer || value instanceof Long
                || value instanceof Boolean || value instanceof Short || value instanceof Byte || value instanceof Character
                || value instanceof Float || value instanceof Double || value instanceof Enum<?>) return false;
            if(value instanceof Map || value instanceof Collection || value.getClass().isArray() || !source(value.getClass())) return true;
            int before=retained;
            for(Field f:FIELDS.get(value.getClass())) if(!Modifier.isStatic(f.getModifiers())) {
                Object member=get(f,value);
                if(member instanceof Entity && member!=target) return true;
            }
            return retained!=before;
        }
        private boolean stableKey(Object key) throws NoSuchMethodException {
            if(key==null || key instanceof String || key instanceof UUID || key instanceof Enum<?> || key instanceof Integer
                || key instanceof Long || key instanceof Short || key instanceof Byte || key instanceof Boolean || key instanceof Character
                || key instanceof Float || key instanceof Double) return true;
            return key.getClass().getMethod("hashCode").getDeclaringClass()==Object.class
                && key.getClass().getMethod("equals",Object.class).getDeclaringClass()==Object.class;
        }
        private boolean baseEntityKey(Object key) {
            try { return key instanceof Entity && key.getClass().getMethod("hashCode").getDeclaringClass()==Entity.class
                && key.getClass().getMethod("equals",Object.class).getDeclaringClass()==Entity.class; }
            catch(NoSuchMethodException unavailable) { return false; }
        }
        @SuppressWarnings({"rawtypes","unchecked"})
        private boolean remove(Map map,Iterator iterator,Map.Entry entry,Object key,Object old) {
            try {
                Class<?> type=map.getClass();
                if(entry.getKey()!=key || entry.getValue()!=old) { failures++; return false; }
                if(type==IdentityHashMap.class) { iterator.remove(); return true; }
                boolean stable=stableKey(key);
                if(type==ConcurrentHashMap.class && stable) {
                    boolean[] removed={false};
                    map.computeIfPresent(key,(k,v)-> { if(v==old) {removed[0]=true;return null;} return v; });
                    if(!removed[0]) failures++;
                    return removed[0];
                }
                if(type!=HashMap.class && type!=LinkedHashMap.class) { retained++; return false; }
                if(!stable) {
                    if(!baseEntityKey(key)) { retained++; return false; }
                    // Mutable Entity IDs can leave equal keys in separate old hash buckets.
                    for(Object raw:map.entrySet()) { Map.Entry other=(Map.Entry)raw;
                        if(other.getKey()!=key && other.getValue()==old) { retained++; return false; }
                    }
                }
                if(map.get(key)!=old) { if(stable) failures++; else retained++; return false; }
                iterator.remove(); return true;
            } catch(ReflectiveOperationException error) { retained++; return false; }
        }
        boolean directReferences(Object wrapper) {
            if(wrapper==null || wrapper instanceof Entity || wrapper instanceof BossEvent || wrapper instanceof Future<?> || wrapper instanceof Executor
                || wrapper instanceof Map || wrapper instanceof Collection || wrapper.getClass().isArray() || !source(wrapper.getClass())) return false;
            if(callback(wrapper)) { if(captured(wrapper)) retained++; return false; }
            boolean changed=false;
            for(Field f:FIELDS.get(wrapper.getClass())) if(!Modifier.isStatic(f.getModifiers()) && get(f,wrapper)==target) changed|=clear(wrapper,f);
            return changed;
        }
        void tasks(Object value) {
            try {
                if(value instanceof Future<?> future) { cancel(future,null); return; }
                if(!(value instanceof ThreadPoolExecutor pool) || !taskSeen.add(value)) return;
                if(pool.getClass()!=ThreadPoolExecutor.class && pool.getClass()!=ScheduledThreadPoolExecutor.class) { retained++; return; }
                var queue=pool.getQueue();
                if(!queue(queue)) { retained++; return; }
                var iterator=queue.iterator();
                while(iterator.hasNext()) { Object task=iterator.next();
                    if(task==target && pool.getClass()==ThreadPoolExecutor.class) { iterator.remove(); }
                    else if(task instanceof Future<?> future) cancel(future,pool);
                    else if(captured(task)) retained++;
                }
            } catch(RuntimeException error) { failed(error); }
        }
        private boolean queue(Object queue) {
            Class<?> c=queue.getClass();
            return c==LinkedBlockingQueue.class || c==ArrayBlockingQueue.class
                || (c.getClassLoader()==null && c.getName().equals("java.util.concurrent.ScheduledThreadPoolExecutor$DelayedWorkQueue"));
        }
        private void cancel(Future<?> future,ThreadPoolExecutor pool) {
            if(!taskSeen.add(future)) { unlink(future,pool); return; }
            Class<?> type=future.getClass();
            boolean scheduled=SCHEDULED_OWNER!=null && type==SCHEDULED_OWNER.getDeclaringClass();
            if(type!=FutureTask.class && !scheduled) { retained++; return; }
            if(future.isDone()) return;
            if(scheduled) {
                Object owner=get(SCHEDULED_OWNER,future);
                if(owner==null || owner.getClass()!=ScheduledThreadPoolExecutor.class || get(SCHEDULED_OUTER,future)!=future
                    || (pool!=null && pool!=owner)) { retained++; return; }
                pool=(ThreadPoolExecutor)owner;
            }
            Object callable=get(CALLABLE,future),body=callable;
            if(RUNNABLE!=null && callable!=null && callable.getClass()==RUNNABLE.getDeclaringClass()) body=get(RUNNABLE,callable);
            if(body!=target) { if(captured(body)) retained++; return; }
            if(get(CALLABLE,future)!=callable || (body!=callable && get(RUNNABLE,callable)!=target)) { failures++; return; }
            ownedTasks.add(future);
            // This prevents future execution/rescheduling; it never interrupts an in-flight call.
            if(!future.cancel(false) && !future.isDone()) failures++;
            unlink(future,pool);
        }
        private void unlink(Future<?> future,ThreadPoolExecutor pool) {
            if(pool==null || !ownedTasks.contains(future) || !future.isCancelled()) return;
            var queue=pool.getQueue();
            if(queue(queue)) queue.remove(future); else retained++;
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
