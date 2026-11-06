package com.himitsu.secret.core;

import com.himitsu.secret.entity.SecretEntity;
import java.util.IdentityHashMap;
import java.util.Map;
import net.minecraft.world.level.Level;

public final class SecretEntityRegistry {
    private static volatile Map<Level,SecretEntity> instances=new IdentityHashMap<>();
    private static volatile SecretEntity client;
    private SecretEntityRegistry() {}
    public static synchronized void register(SecretEntity entity) {
        if(entity==null || !AuthoritativeEntityTopology.open(entity.level()) || !entity.isAddedToWorld) return;
        SecretEntity prior=instances.get(entity.level());
        if(prior!=null && prior!=entity) return;
        if(prior==null) { var next=new IdentityHashMap<>(instances); next.put(entity.level(),entity); instances=next; }
        if(entity.level().isClientSide()) client=entity;
        AuthoritativeEntityTopology.anchor(entity);
    }
    public static SecretEntity instance(Level level) { return instances.get(level); }
    public static SecretEntity clientInstance() { return client; }
    static void maintain(Level level) {
        SecretEntity entity=instances.get(level);
        if(entity!=null) AuthoritativeEntityTopology.maintain(entity);
    }
    public static synchronized void leave(SecretEntity entity) {
        if(entity==null || instances.get(entity.level())!=entity) return;
        var next=new IdentityHashMap<>(instances); next.remove(entity.level()); instances=next;
        AuthoritativeEntityTopology.release(entity);
        if(client==entity) { client=null; com.himitsu.secret.client.avatar.SecretAvatarManager.clear(entity.level()); }
    }
    public static void clearLevel(Level level) {
        AuthoritativeEntityTopology.clearLevel(level);
        leave(instances.get(level));
    }
}
