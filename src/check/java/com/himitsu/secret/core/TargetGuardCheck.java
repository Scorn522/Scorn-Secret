package com.himitsu.secret.core;
import java.util.*;
import java.io.*;
import java.lang.reflect.*;
import com.himitsu.secret.hook.*;
import it.unimi.dsi.fastutil.ints.*;
import org.objectweb.asm.*;
public final class TargetGuardCheck {
    static void check(boolean value,String why) { if(!value) throw new AssertionError(why); }
    public static final class Fixture { public static int operation(int argument) { if(argument<0) throw new IllegalStateException("expected"); return argument+7; } }
    public static int depth,entered,exited;
    @AsmHook(targetClass="com/himitsu/secret/core/TargetGuardCheck$Fixture",targetMethod="operation",targetDescriptor="(I)I",mode=HookMode.SCOPE)
    public static void scope(int argument,boolean enter) { if(enter) {depth++;entered++;} else {depth--;exited++;} }
    private static void checkWeaponEntries() throws Exception {
        for (Method callback : CivilizationSurvivalHooks.class.getDeclaredMethods()) {
            if (!callback.getName().equals("weaponAttack") && !callback.getName().equals("weaponSwing")) continue;
            HookDefinition hook = HookDefinition.from(callback.getAnnotation(AsmHook.class), callback);
            HookRegistry.register(hook);
            for (String methodName : hook.targetMethods()) {
                var node = new org.objectweb.asm.tree.ClassNode();
                try (InputStream in = TargetGuardCheck.class.getClassLoader().getResourceAsStream(hook.targetClass()+".class")) {
                    new ClassReader(in).accept(node,0);
                }
                var method = node.methods.stream().filter(m -> m.name.equals(hook.targetMethod()) && m.desc.equals(hook.targetDescriptor())).findFirst().orElseThrow();
                // Simulate an upstream early return that suppresses the ordinary item callback.
                method.name = methodName;
                method.instructions.clear(); method.tryCatchBlocks.clear(); method.localVariables = null;
                method.visibleLocalVariableAnnotations = null; method.invisibleLocalVariableAnnotations = null;
                method.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
                ClassWriter writer = new ClassWriter(0); node.accept(writer);
                byte[] transformed = HookTransformer.transform(TargetGuardCheck.class.getClassLoader(),node.name,null,null,writer.toByteArray());
                // Reapplication must not duplicate the operation.
                transformed = HookTransformer.transform(TargetGuardCheck.class.getClassLoader(),node.name,null,null,transformed);
                var result = new org.objectweb.asm.tree.ClassNode(); new ClassReader(transformed).accept(result,0);
                var changed = result.methods.stream().filter(m -> m.name.equals(methodName) && m.desc.equals(hook.targetDescriptor())).findFirst().orElseThrow();
                int calls = 0;
                for (var instruction : changed.instructions) {
                    if (instruction instanceof org.objectweb.asm.tree.MethodInsnNode call
                        && call.owner.equals(hook.callbackOwner()) && call.name.equals(hook.callbackName())) calls++;
                    if (instruction.getOpcode() == Opcodes.RETURN) check(calls == 1,"entry lost before cancellation: "+methodName);
                }
                check(calls == 1,"entry duplicated or absent: "+methodName);
            }
        }
        for (Method method : com.himitsu.secret.item.CivilizationSurvivalItem.class.getDeclaredMethods())
            check(!method.getName().equals("onEntitySwing"),"legacy item swing duplicates execution");
    }
    public static final class EntityFixture extends net.minecraft.world.entity.Entity {
        net.minecraftforge.entity.PartEntity<?>[] parts;
        static Collection<Object> cleanupRefs;
        EntityFixture() { super(net.minecraft.world.entity.EntityType.PIG,null); }
        public void defineSynchedData() {}
        public void readAdditionalSaveData(net.minecraft.nbt.CompoundTag tag) {}
        public void addAdditionalSaveData(net.minecraft.nbt.CompoundTag tag) {}
        public boolean isMultipartEntity() { return parts!=null; }
        public net.minecraftforge.entity.PartEntity<?>[] getParts() { return parts; }
    }
    public static final class PartFixture extends net.minecraftforge.entity.PartEntity<net.minecraft.world.entity.Entity> {
        PartFixture(net.minecraft.world.entity.Entity parent) { super(parent); }
        public void defineSynchedData() {}
        public void readAdditionalSaveData(net.minecraft.nbt.CompoundTag tag) {}
        public void addAdditionalSaveData(net.minecraft.nbt.CompoundTag tag) {}
        public net.minecraft.network.protocol.Packet<net.minecraft.network.protocol.game.ClientGamePacketListener> getAddEntityPacket() { throw new UnsupportedOperationException(); }
    }
    public static final class SecretFixture extends com.himitsu.secret.entity.SecretEntity {
        SecretFixture() { super(null,null); }
        public net.minecraft.world.entity.EntityType<?> getType() { return net.minecraft.world.entity.EntityType.PIG; }
    }
    public static final class MenuFixture extends net.minecraft.world.inventory.AbstractContainerMenu {
        MenuFixture() { super(null,0); }
        public boolean stillValid(net.minecraft.world.entity.player.Player player) { return true; }
        public net.minecraft.world.item.ItemStack quickMoveStack(net.minecraft.world.entity.player.Player player,int slot) { return net.minecraft.world.item.ItemStack.EMPTY; }
        int broadcasts;
        public void broadcastChanges() { broadcasts++; }
    }
    private static void set(Object object,Class<?> type,String name,Object value) throws Exception {
        Field field=type.getDeclaredField(name); field.setAccessible(true); field.set(object,value);
    }
    private static void checkR14() throws Exception {
        // Registry fixtures only: a plain JVM has no Forge event-class transformer or game launcher.
        net.minecraft.SharedConstants.tryDetectVersion();
        set(null,net.minecraft.server.Bootstrap.class,"isBootstrapped",true);
        check(!net.minecraft.core.registries.BuiltInRegistries.REGISTRY.keySet().isEmpty(),"registry fixture did not initialize");
        var bladeItem=new com.himitsu.secret.item.CivilizationSurvivalItem();
        net.minecraftforge.registries.ForgeRegistries.ITEMS.register(new net.minecraft.resources.ResourceLocation("secret","r14_test_blade"),bladeItem);
        net.minecraft.core.registries.BuiltInRegistries.bootStrap();
        net.minecraftforge.registries.GameData.vanillaSnapshot();
        Field uf=sun.misc.Unsafe.class.getDeclaredField("theUnsafe"); uf.setAccessible(true);
        var unsafe=(sun.misc.Unsafe)uf.get(null);
        var level=(net.minecraft.server.level.ServerLevel)unsafe.allocateInstance(net.minecraft.server.level.ServerLevel.class);
        set(level,net.minecraft.world.level.Level.class,"dimension",net.minecraft.world.level.Level.OVERWORLD);
        Method parse=TargetLedger.class.getDeclaredMethod("index",Set.class); parse.setAccessible(true);
        Field deaths=TargetLedger.class.getDeclaredField("serverDeaths"); deaths.setAccessible(true);
        Object oldDeaths=deaths.get(null); UUID retired=UUID.randomUUID();
        try {
            deaths.set(null,parse.invoke(null,Set.of("minecraft:overworld|"+retired+"|12")));
            check(TargetLedger.blockedUuid(level,retired),"same-dimension retired UUID was admitted");
            check(!TargetLedger.blockedUuid(level,UUID.randomUUID()),"new UUID was blocked");
            set(level,net.minecraft.world.level.Level.class,"dimension",net.minecraft.world.level.Level.NETHER);
            check(!TargetLedger.blockedUuid(level,retired),"UUID exclusion leaked into another dimension");
        } finally { deaths.set(null,oldDeaths); set(level,net.minecraft.world.level.Level.class,"dimension",net.minecraft.world.level.Level.OVERWORLD); }
        EntityFixture root=(EntityFixture)unsafe.allocateInstance(EntityFixture.class);
        PartFixture first=(PartFixture)unsafe.allocateInstance(PartFixture.class), second=(PartFixture)unsafe.allocateInstance(PartFixture.class);
        set(first,net.minecraftforge.entity.PartEntity.class,"parent",root); set(second,net.minecraftforge.entity.PartEntity.class,"parent",root);
        root.parts=new net.minecraftforge.entity.PartEntity<?>[]{first,second,first};
        check(CivilizationSurvival.relatedTargets(List.of(first,root,second)).size()==3,"multipart identity dedup failed");
        EntityFixture vehicle=(EntityFixture)unsafe.allocateInstance(EntityFixture.class), passenger=(EntityFixture)unsafe.allocateInstance(EntityFixture.class);
        set(root,net.minecraft.world.entity.Entity.class,"vehicle",vehicle);
        set(root,net.minecraft.world.entity.Entity.class,"passengers",com.google.common.collect.ImmutableList.of(passenger));
        var related=CivilizationSurvival.relatedTargets(List.of(first));
        check(related.stream().noneMatch(e->e==vehicle||e==passenger),"ordinary riding graph was executed");
        set(first,net.minecraftforge.entity.PartEntity.class,"parent",second); set(second,net.minecraftforge.entity.PartEntity.class,"parent",first);
        check(CivilizationSurvival.relatedTargets(List.of(first)).size()==2,"cyclic part parents did not terminate");
        var player=(net.minecraft.server.level.ServerPlayer)unsafe.allocateInstance(net.minecraft.server.level.ServerPlayer.class);
        var fake=(net.minecraftforge.common.util.FakePlayer)unsafe.allocateInstance(net.minecraftforge.common.util.FakePlayer.class);
        UUID id=UUID.randomUUID(); player.uuid=id; fake.uuid=id;
        set(player,net.minecraft.world.entity.Entity.class,"level",level); set(fake,net.minecraft.world.entity.Entity.class,"level",level);
        check(!CivilizationSurvival.isOwner(fake)&&!OwnerSafety.authenticated(fake),"FakePlayer obtained session authority");
        var group=new io.netty.channel.DefaultEventLoopGroup(1);
        io.netty.channel.Channel listener=null,local=null;
        Field owners=OwnerSafety.class.getDeclaredField("owners"); owners.setAccessible(true); Object previous=owners.get(null);
        var priorOwners=com.himitsu.secret.network.RuntimeSyncState.CIVILIZATION_OWNERS.snapshot();
        try {
            listener=new io.netty.bootstrap.ServerBootstrap().group(group).channel(io.netty.channel.local.LocalServerChannel.class)
                .childHandler(new io.netty.channel.ChannelInboundHandlerAdapter()).bind(new io.netty.channel.local.LocalAddress("secret-check-"+id)).sync().channel();
            local=new io.netty.bootstrap.Bootstrap().group(group).channel(io.netty.channel.local.LocalChannel.class)
                .handler(new io.netty.channel.ChannelInboundHandlerAdapter()).connect(listener.localAddress()).sync().channel();
            var connection=new net.minecraft.network.Connection(net.minecraft.network.protocol.PacketFlow.SERVERBOUND);
            set(connection,net.minecraft.network.Connection.class,"channel",local);
            var handler=(net.minecraft.server.network.ServerGamePacketListenerImpl)unsafe.allocateInstance(net.minecraft.server.network.ServerGamePacketListenerImpl.class);
            set(handler,net.minecraft.server.network.ServerGamePacketListenerImpl.class,"connection",connection); handler.player=player; player.connection=handler;
            Class<?> bindingType=Arrays.stream(OwnerSafety.class.getDeclaredClasses()).filter(c->c.getSimpleName().equals("Binding")).findFirst().orElseThrow();
            Object binding=unsafe.allocateInstance(bindingType);
            set(binding,bindingType,"player",player); set(binding,bindingType,"level",level);
            set(binding,bindingType,"session",handler); set(binding,bindingType,"connection",connection);
            set(binding,bindingType,"active",true); set(binding,bindingType,"owner",true);
            var published=new IdentityHashMap<net.minecraft.world.entity.player.Player,Object>(); published.put(player,binding); owners.set(null,published);
            com.himitsu.secret.network.RuntimeSyncState.CIVILIZATION_OWNERS.replace(Set.of(id.toString(),"name:Scorn"));
            check(CivilizationSurvival.isOwner(player),"LocalChannel Owner was rejected");
            var server=(net.minecraft.server.dedicated.DedicatedServer)unsafe.allocateInstance(net.minecraft.server.dedicated.DedicatedServer.class);
            var playerList=(net.minecraft.server.dedicated.DedicatedPlayerList)unsafe.allocateInstance(net.minecraft.server.dedicated.DedicatedPlayerList.class);
            set(server,net.minecraft.server.MinecraftServer.class,"playerList",playerList);
            set(playerList,net.minecraft.server.players.PlayerList.class,"playersByUUID",new HashMap<>(Map.of(id,player)));
            set(player,net.minecraft.server.level.ServerPlayer.class,"server",server);
            Method session=OwnerSafety.class.getDeclaredMethod("session",net.minecraft.world.entity.player.Player.class); session.setAccessible(true);
            check(session.invoke(null,player)==handler && OwnerSafety.authenticated(player),"legitimate LocalChannel session registration failed");
            check(!OwnerSafety.registerSession(fake),"fake obtained a cached session");
            Object savedDeaths=deaths.get(null);
            try {
                deaths.set(null,parse.invoke(null,Set.of("minecraft:overworld|"+id+"|222")));
                check(SecretEntityHooks.blockedEntry(level,fake),"fake reused Owner UUID was admitted");
                check(!SecretEntityHooks.blockedEntry(level,player),"fake UUID execution blocked the bound Owner");
                OwnerSafety.lifecycle(player,true,true);
                try { check(!SecretEntityHooks.blockedEntry(level,player),"legitimate Owner dimension transition was blocked"); }
                finally { OwnerSafety.lifecycle(player,false,false); set(binding,bindingType,"active",true); owners.set(null,published); }
            } finally { deaths.set(null,savedDeaths); }
            check(!CivilizationSurvival.isOwner(fake),"UUID/name spoof inherited Owner protection");
            var impostor=(net.minecraft.server.level.ServerPlayer)unsafe.allocateInstance(net.minecraft.server.level.ServerPlayer.class);
            impostor.uuid=id; impostor.connection=handler;
            set(impostor,net.minecraft.world.entity.Entity.class,"level",level);
            check(!CivilizationSurvival.isOwner(impostor),"unbound player clone inherited the session");
            set(first,net.minecraftforge.entity.PartEntity.class,"parent",player);
            check(CivilizationSurvival.relatedTargets(List.of(first)).isEmpty(),"Owner's attached part was executed");
            var inventory=new net.minecraft.world.entity.player.Inventory(player);
            set(player,net.minecraft.world.entity.player.Player.class,"inventory",inventory);
            player.containerMenu=new MenuFixture();
            var blade=new net.minecraft.world.item.ItemStack(bladeItem);
            blade.getOrCreateTag().putString("r14-check","preserve-original-data");
            inventory.items.set(4,blade); inventory.selected=2;
            set(binding,bindingType,"weapon",net.minecraft.world.item.ItemStack.EMPTY); set(binding,bindingType,"weaponSlot",-1);
            Method weapon=bindingType.getDeclaredMethod("weapon",boolean.class); weapon.setAccessible(true); weapon.invoke(binding,false);
            inventory.items.set(4,net.minecraft.world.item.ItemStack.EMPTY);
            player.tickCount=1; OwnerSafety.maintainWeapon(player);
            check(inventory.getItem(4).isEmpty(),"weapon fallback scanned/restored before its deadline");
            player.tickCount=20; OwnerSafety.maintainWeapon(player);
            check(inventory.selected==2 && inventory.getItem(4).getCount()==1
                && "preserve-original-data".equals(inventory.getItem(4).getTag().getString("r14-check")),"lost weapon recovery changed selection/data");
            weapon.invoke(binding,false);
            check(inventory.items.stream().filter(stack->!stack.isEmpty()).count()==1,"repeated maintenance duplicated weapon");
            for(int i=0;i<inventory.items.size();i++) inventory.items.set(i,new net.minecraft.world.item.ItemStack(net.minecraft.world.item.Items.STONE));
            weapon.invoke(binding,false);
            check(inventory.items.stream().allMatch(stack->stack.is(net.minecraft.world.item.Items.STONE)),"full inventory was overwritten");
            inventory.items.set(8,net.minecraft.world.item.ItemStack.EMPTY); weapon.invoke(binding,false);
            check(inventory.getItem(8).getItem()==bladeItem && inventory.selected==2,"deferred recovery lost data or changed hotbar");
            inventory.items.clear(); player.containerMenu.setCarried(blade);
            weapon.invoke(binding,false); check(inventory.getFreeSlot()==0 && inventory.items.stream().allMatch(net.minecraft.world.item.ItemStack::isEmpty),"cursor weapon was duplicated");
            player.containerMenu.setCarried(net.minecraft.world.item.ItemStack.EMPTY);
            OwnerSafety.access(player,0,true); OwnerSafety.access(player,0,false); weapon.invoke(binding,false);
            check(inventory.items.stream().allMatch(net.minecraft.world.item.ItemStack::isEmpty),"intentional container transfer regenerated weapon");
            checkR16(unsafe,level,player,server,handler);
            OwnerSafety.revoke(player); check(!CivilizationSurvival.isOwner(player),"owner revocation was not published");
            set(binding,bindingType,"owner",true);
            local.close().sync(); OwnerSafetyHooks.disconnected(connection,null);
            check(!CivilizationSurvival.isOwner(player) && !OwnerSafety.authenticated(player),"disconnected session retained Owner protection");
        } finally {
            owners.set(null,previous); com.himitsu.secret.network.RuntimeSyncState.CIVILIZATION_OWNERS.replace(priorOwners);
            if(local!=null)local.close().sync(); if(listener!=null)listener.close().sync(); group.shutdownGracefully(0,1,java.util.concurrent.TimeUnit.SECONDS).sync();
        }
        for(Method method:SecretEntityHooks.class.getDeclaredMethods()) if(method.getName().equals("guardWorldEntry")||method.getName().equals("guardManagerEntry")||method.getName().equals("playerAdded")||method.getName().equals("addToTickList")||method.getName().equals("removeFromTickList")) {
            for(AsmHook hook:method.getAnnotationsByType(AsmHook.class)) {
                HookDefinition.from(hook,method);
                try(InputStream in=TargetGuardCheck.class.getClassLoader().getResourceAsStream(hook.targetClass()+".class")) {
                    var node=new org.objectweb.asm.tree.ClassNode(); new ClassReader(in).accept(node,ClassReader.SKIP_CODE);
                    check(node.methods.stream().anyMatch(m->m.name.equals(hook.targetMethod())&&m.desc.equals(hook.targetDescriptor())),"entry hook missing: "+hook.targetMethod());
                }
            }
        }
    }
    @SuppressWarnings({"unchecked","rawtypes"})
    private static void checkR16(sun.misc.Unsafe unsafe,net.minecraft.server.level.ServerLevel level,
        net.minecraft.server.level.ServerPlayer player,net.minecraft.server.MinecraftServer server,
        net.minecraft.server.network.ServerGamePacketListenerImpl handler) throws Exception {
        Method listenerList=net.minecraftforge.eventbus.api.EventListenerHelper.class.getDeclaredMethod("getListenerListInternal",Class.class,boolean.class);
        listenerList.setAccessible(true);
        listenerList.invoke(null,net.minecraftforge.network.NetworkEvent.class,true);
        listenerList.invoke(null,net.minecraftforge.network.NetworkEvent.GatherLoginPayloadsEvent.class,true);
        set(level,net.minecraft.server.level.ServerLevel.class,"server",server);
        set(server,net.minecraft.server.MinecraftServer.class,"serverThread",Thread.currentThread());
        var manager=(net.minecraft.world.level.entity.PersistentEntitySectionManager<net.minecraft.world.entity.Entity>)unsafe.allocateInstance(net.minecraft.world.level.entity.PersistentEntitySectionManager.class);
        manager.visibleEntityStorage=new net.minecraft.world.level.entity.EntityLookup<>();
        manager.knownUuids=new HashSet<>();
        var visibility=new it.unimi.dsi.fastutil.longs.Long2ObjectOpenHashMap<net.minecraft.world.level.entity.Visibility>();
        visibility.defaultReturnValue(net.minecraft.world.level.entity.Visibility.TICKING);
        set(manager,net.minecraft.world.level.entity.PersistentEntitySectionManager.class,"chunkVisibility",visibility);
        manager.sectionStorage=new net.minecraft.world.level.entity.EntitySectionStorage<>(net.minecraft.world.entity.Entity.class,visibility);
        level.entityManager=manager; level.entityTickList=new net.minecraft.world.level.entity.EntityTickList();
        level.dragonParts=new Int2ObjectOpenHashMap<>(); level.players=new ArrayList<>();
        var cache=(net.minecraft.server.level.ServerChunkCache)unsafe.allocateInstance(net.minecraft.server.level.ServerChunkCache.class);
        var chunks=(net.minecraft.server.level.ChunkMap)unsafe.allocateInstance(net.minecraft.server.level.ChunkMap.class);
        chunks.entityMap=new Int2ObjectOpenHashMap<>();
        set(cache,net.minecraft.server.level.ServerChunkCache.class,"chunkMap",chunks);
        var storage=(net.minecraft.world.level.storage.DimensionDataStorage)unsafe.allocateInstance(net.minecraft.world.level.storage.DimensionDataStorage.class);
        set(storage,net.minecraft.world.level.storage.DimensionDataStorage.class,"cache",new HashMap<>());
        set(cache,net.minecraft.server.level.ServerChunkCache.class,"dataStorage",storage);
        set(level,net.minecraft.server.level.ServerLevel.class,"chunkSource",cache);
        player.entityData=new net.minecraft.network.syncher.SynchedEntityData(player);
        player.entityData.define(net.minecraft.world.entity.LivingEntity.DATA_HEALTH_ID,20.0F);
        player.entityData.define(net.minecraft.world.entity.LivingEntity.DATA_LIVING_ENTITY_FLAGS,(byte)0);
        set(player,net.minecraft.world.entity.player.Player.class,"abilities",new net.minecraft.world.entity.player.Abilities());
        check(OwnerSafetyHooks.removal(player,net.minecraft.world.entity.Entity.RemovalReason.DISCARDED),"Owner remove not guarded");
        check(OwnerSafetyHooks.health(player,Float.NaN),"Owner NaN health not guarded");
        check(OwnerSafetyHooks.health(player,0),"Owner zero health not guarded");
        OwnerSafety.access(player,2,true);
        try { check(!OwnerSafetyHooks.kill(player)&&!OwnerSafetyHooks.health(player,0),"legitimate lifecycle was blocked"); }
        finally { OwnerSafety.access(player,2,false); }
        var oldOwners=OwnerSafety.class.getDeclaredField("owners"); oldOwners.setAccessible(true);
        Object binding=((Map<?,?>)oldOwners.get(null)).get(player);
        var replacement=(net.minecraft.server.level.ServerPlayer)unsafe.allocateInstance(net.minecraft.server.level.ServerPlayer.class);
        replacement.uuid=player.uuid; replacement.id=987; replacement.connection=handler;
        set(replacement,net.minecraft.server.level.ServerPlayer.class,"server",server);
        set(replacement,net.minecraft.world.entity.Entity.class,"level",level);
        Field marks=DeathExecution.class.getDeclaredField("MARKED_OBJECTS"); marks.setAccessible(true);
        Method remember=DeathExecution.class.getDeclaredMethod("remember",net.minecraft.world.entity.player.Player.class,boolean.class);remember.setAccessible(true);
        remember.invoke(null,player,true);
        check(!CivilizationSurvival.isOwner(player)&&OwnerSafetyHooks.heal(player,20)&&OwnerSafetyHooks.revive(player),"death did not override Owner");
        check(OwnerSafetyHooks.health(player,20)&&player.entityData.get(net.minecraft.world.entity.LivingEntity.DATA_HEALTH_ID)==0,"death health write escaped");
        DeathExecution.onPlayerClone(player,replacement);
        check(DeathExecution.isMarked(replacement),"clone did not inherit identity");
        int[] pending=(int[])((Map<?,?>)marks.get(null)).get(replacement);
        check(pending[1]==0,"clone was enforced before ready");
        DeathExecution.onPlayerReady(replacement);check(pending[1]==0,"unbound replacement became ready");
        replacement.id=988; replacement.entityData=new net.minecraft.network.syncher.SynchedEntityData(replacement);
        replacement.entityData.define(net.minecraft.world.entity.LivingEntity.DATA_HEALTH_ID,20.0F);
        replacement.entityData.define(net.minecraft.world.entity.LivingEntity.DATA_LIVING_ENTITY_FLAGS,(byte)0);
        set(replacement,net.minecraft.world.entity.player.Player.class,"abilities",new net.minecraft.world.entity.player.Abilities());
        handler.player=replacement;
        set(server.getPlayerList(),net.minecraft.server.players.PlayerList.class,"playersByUUID",new HashMap<>(Map.of(player.uuid,replacement)));
        DeathExecution.onPlayerReady(replacement);
        check(pending[1]==1 && replacement.dead && replacement.entityData.get(net.minecraft.world.entity.LivingEntity.DATA_HEALTH_ID)==0,"ready clone escaped enforcement");
        check(TargetLedger.marked(replacement,true),"final clone identity not published");
        var foreign=(net.minecraft.server.level.ServerPlayer)unsafe.allocateInstance(net.minecraft.server.level.ServerPlayer.class);
        foreign.uuid=player.uuid; foreign.id=989;
        set(foreign,net.minecraft.world.entity.Entity.class,"level",level);
        DeathExecution.onPlayerClone(replacement,foreign);
        check(!DeathExecution.isMarked(foreign),"unrelated same-UUID session inherited execution");
        handler.player=player;
        set(server.getPlayerList(),net.minecraft.server.players.PlayerList.class,"playersByUUID",new HashMap<>(Map.of(player.uuid,player)));
        DeathExecution.clearLevel(level);
        set(binding,binding.getClass(),"owner",true);
        var map=new net.minecraft.world.entity.ai.attributes.AttributeMap(net.minecraft.world.entity.ai.attributes.AttributeSupplier.builder().add(net.minecraft.world.entity.ai.attributes.Attributes.MAX_HEALTH).build());
        var attribute=map.getInstance(net.minecraft.world.entity.ai.attributes.Attributes.MAX_HEALTH);
        var motion=binding.getClass().getDeclaredMethod("motion");motion.setAccessible(true);
        var stablePosition=new net.minecraft.world.phys.Vec3(4,60,8);
        var stableVelocity=new net.minecraft.world.phys.Vec3(0.5,0.25,-0.5);
        set(player,net.minecraft.world.entity.Entity.class,"position",stablePosition);
        player.setDeltaMovement(stableVelocity);motion.invoke(binding);
        player.setDeltaMovement(new net.minecraft.world.phys.Vec3(Double.NaN,Double.POSITIVE_INFINITY,0));
        motion.invoke(binding);
        check(player.getDeltaMovement().equals(stableVelocity),"Owner raw velocity corruption was not repaired");
        var legitimateVelocity=new net.minecraft.world.phys.Vec3(-2,3,4);
        player.setDeltaMovement(legitimateVelocity);motion.invoke(binding);
        check(player.position()==stablePosition && player.getDeltaMovement()==legitimateVelocity,"normal motion was copied or changed");
        Field known=binding.getClass().getDeclaredField("positionKnown");known.setAccessible(true);
        check(known.getBoolean(binding),"finite position was not recorded");
        set(player,net.minecraft.world.entity.Entity.class,"dimensions",net.minecraft.world.entity.EntityDimensions.fixed(0.6F,1.8F));
        player.blockPosition=net.minecraft.core.BlockPos.containing(stablePosition);
        player.chunkPosition=new net.minecraft.world.level.ChunkPos(player.blockPosition);
        player.levelCallback=net.minecraft.world.level.entity.EntityInLevelCallback.NULL;
        boolean added=player.isAddedToWorld;player.isAddedToWorld=false;
        try {
            set(player,net.minecraft.world.entity.Entity.class,"position",new net.minecraft.world.phys.Vec3(Double.NaN,60,8));
            motion.invoke(binding);
            check(player.position().equals(stablePosition) && Double.isFinite(player.getBoundingBox().minX),"Owner raw position corruption was not repaired");
            set(player,net.minecraft.world.entity.Entity.class,"position",null);motion.invoke(binding);
            check(player.position().equals(stablePosition) && player.blockPosition.equals(net.minecraft.core.BlockPos.containing(stablePosition)),"null position lost the trusted position or block index");
        } finally {player.isAddedToWorld=added;}

        Field attributeIndex=OwnerSafety.class.getDeclaredField("attributeOwners"); attributeIndex.setAccessible(true);
        Field attributes=OwnerSafety.class.getDeclaredField("ATTRIBUTES"); attributes.setAccessible(true);
        Object beforeIndex=attributeIndex.get(null); Map savedAttributes=new HashMap((Map)attributes.get(null));
        try {
            int count=((Map)attributes.get(null)).size(); OwnerSafety.attribute(map,attribute);
            check(((Map)attributes.get(null)).size()==count,"ordinary mob touched Owner attribute table");
            var index=new IdentityHashMap<>();index.put(map,binding);attributeIndex.set(null,index);
            OwnerSafety.attribute(map,attribute);
            check(OwnerSafety.baseDenied(attribute,0),"late Owner attribute was not registered");
            OwnerSafety.access(player,1,true);
            try { check(!OwnerSafety.baseDenied(attribute,0),"legitimate effect scope was blocked"); }
            finally {OwnerSafety.access(player,1,false);}
        } finally {attributeIndex.set(null,beforeIndex);((Map)attributes.get(null)).clear();((Map)attributes.get(null)).putAll(savedAttributes);}
        EntityFixture target=(EntityFixture)unsafe.allocateInstance(EntityFixture.class); target.id=71;target.uuid=UUID.randomUUID();
        set(target,net.minecraft.world.entity.Entity.class,"level",level);
        set(target,net.minecraft.world.entity.Entity.class,"blockPosition",new net.minecraft.core.BlockPos(0,64,0));
        set(target,net.minecraft.world.entity.Entity.class,"chunkPosition",new net.minecraft.world.level.ChunkPos(0,0));
        target.levelCallback=net.minecraft.world.level.entity.EntityInLevelCallback.NULL;
        TargetLedger.mark(target,false);
        int[] ids=TargetLedger.ids(level);check(ids==TargetLedger.ids(level),"ledger recreates id snapshot on read");
        var other=(EntityFixture)unsafe.allocateInstance(EntityFixture.class);other.id=71;other.uuid=UUID.randomUUID();
        set(other,net.minecraft.world.entity.Entity.class,"level",level);
        manager.visibleEntityStorage.byId.put(71,other);level.entityTickList.active.put(71,other);
        TargetLedger.inspect(level);check(manager.visibleEntityStorage.byId.get(71)==other,"reused numeric id removed unrelated entity");
        target.id=72;manager.visibleEntityStorage.byUuid.put(target.uuid,target);level.entityTickList.active.put(72,target);
        TargetLedger.inspect(level);check(manager.visibleEntityStorage.byUuid.get(target.uuid)==null&&!level.entityTickList.active.containsKey(72),"UUID-only residual survived");
        EntityFixture.cleanupRefs=Collections.unmodifiableList(List.of(target));
        check(!TargetCleanup.clean(target)&&TargetCleanup.isIncomplete(target),"partial cleanup not retained");
        for(int tick:new int[]{20,40,60}) {set(server,net.minecraft.server.MinecraftServer.class,"tickCount",tick);TargetCleanup.retryPending(level);}
        Field exhausted=TargetCleanup.class.getDeclaredField("EXHAUSTED");exhausted.setAccessible(true);
        check(((WeakTargetSet<net.minecraft.world.entity.Entity>)exhausted.get(null)).contains(target),"retry limit not reached");
        EntityFixture.cleanupRefs=new ArrayList<>(List.of(target));
        check(TargetCleanup.clean(target)&&!TargetCleanup.isIncomplete(target)&&EntityFixture.cleanupRefs.isEmpty(),"explicit rehit did not complete cleanup");
        EntityFixture.cleanupRefs=null;
        SecretFixture secret=(SecretFixture)unsafe.allocateInstance(SecretFixture.class); secret.id=88; secret.uuid=UUID.randomUUID();
        set(secret,net.minecraft.world.entity.Entity.class,"level",level);
        set(secret,net.minecraft.world.entity.Entity.class,"blockPosition",new net.minecraft.core.BlockPos(0,64,0));
        set(secret,net.minecraft.world.entity.Entity.class,"chunkPosition",new net.minecraft.world.level.ChunkPos(0,0));
        var oldSection=new net.minecraft.world.level.entity.EntitySection<net.minecraft.world.entity.Entity>(net.minecraft.world.entity.Entity.class,net.minecraft.world.level.entity.Visibility.TICKING);
        oldSection.add(secret);
        var callback=(net.minecraft.world.level.entity.PersistentEntitySectionManager<?>.Callback)unsafe.allocateInstance(net.minecraft.world.level.entity.PersistentEntitySectionManager.Callback.class);
        set(callback,net.minecraft.world.level.entity.PersistentEntitySectionManager.Callback.class,"currentSection",oldSection);
        secret.levelCallback=callback;
        SecretEntityRegistry.register(secret);check(SecretEntityRegistry.instance(level)==null,"constructor-stage Secret was registered");
        secret.isAddedToWorld=true;SecretEntityRegistry.register(secret);
        var tracked=(net.minecraft.server.level.ChunkMap.TrackedEntity)unsafe.allocateInstance(net.minecraft.server.level.ChunkMap.TrackedEntity.class);
        set(tracked,net.minecraft.server.level.ChunkMap.TrackedEntity.class,"entity",secret);chunks.entityMap.put(88,tracked);
        AuthoritativeEntityTopology.maintain(secret);
        long section=net.minecraft.core.SectionPos.asLong(secret.blockPosition());
        check(manager.sectionStorage.getSection(section).storage.allInstances.stream().anyMatch(e->e==secret),"missing section not rebuilt");
        check(manager.visibleEntityStorage.byId.get(88)==secret&&level.entityTickList.active.get(88)==secret,"Secret topology not restored");
        check(callback.currentSection==manager.sectionStorage.getSection(section)&&oldSection.storage.allInstances.isEmpty(),"movement callback retained the deleted section");
        SecretFixture duplicate=(SecretFixture)unsafe.allocateInstance(SecretFixture.class);duplicate.uuid=UUID.randomUUID();duplicate.isAddedToWorld=true;
        set(duplicate,net.minecraft.world.entity.Entity.class,"level",level);
        SecretEntityRegistry.register(duplicate);check(SecretEntityRegistry.instance(level)==secret,"second same-world Secret replaced the first");
        var otherWorld=(net.minecraft.server.level.ServerLevel)unsafe.allocateInstance(net.minecraft.server.level.ServerLevel.class);
        check(SecretEntityRegistry.instance(otherWorld)==null,"Secret leaked across worlds");
        SecretFixture otherSecret=(SecretFixture)unsafe.allocateInstance(SecretFixture.class);otherSecret.uuid=UUID.randomUUID();otherSecret.isAddedToWorld=true;
        set(otherSecret,net.minecraft.world.entity.Entity.class,"level",otherWorld);SecretEntityRegistry.register(otherSecret);
        check(SecretEntityRegistry.instance(level)==secret&&SecretEntityRegistry.instance(otherWorld)==otherSecret,"independent dimensions were not retained");
        SecretEntityRegistry.clearLevel(otherWorld);
        check(SecretEntityRegistry.instance(level)==secret,"other dimension unload removed current Secret");
        AuthoritativeEntityTopology.clearLevel(level); SecretEntityRegistry.clearLevel(level);TargetCleanup.clearLevel(level);
        manager.sectionStorage.remove(section);manager.visibleEntityStorage.byId.remove(88);
        AuthoritativeEntityTopology.maintain(secret);SecretEntityRegistry.register(secret);
        check(manager.sectionStorage.getSection(section)==null&&SecretEntityRegistry.instance(level)==null,"unloaded world was resurrected");
        TargetLedger.clearLevel(level);
    }
    private static void checkLeanReads() throws Exception {
        for(Class<?> type:List.of(OwnerSafety.class,CivilizationSurvival.class)) {
            var node=new org.objectweb.asm.tree.ClassNode();
            try(InputStream in=type.getResourceAsStream(type.getSimpleName()+".class")) { new ClassReader(in).accept(node,0); }
            for(var method:node.methods) if(method.name.equals("owns")||method.name.equals("isOwner")||method.name.equals("authenticated")) {
                for(var insn:method.instructions) {
                    check(insn.getOpcode()!=Opcodes.MONITORENTER && insn.getOpcode()!=Opcodes.NEW,"owner hot read locks/allocates");
                    if(insn instanceof org.objectweb.asm.tree.MethodInsnNode call)
                        check(call.owner.equals("java/util/Map") || call.owner.equals("com/himitsu/secret/core/OwnerSafety") && call.name.equals("owns"),"dynamic owner query: "+call.owner+"."+call.name);
                }
            }
        }
        for(Method method:SecretEntityHooks.class.getDeclaredMethods())
            check(!method.getName().equals("forEachTickingEntity")&&!method.getName().equals("containsInTickList"),"obsolete tick read override retained");
        var ticks=new net.minecraft.world.level.entity.EntityTickList();
        check(ticks.active.getClass()==it.unimi.dsi.fastutil.ints.Int2ObjectLinkedOpenHashMap.class
            && ticks.passive.getClass()==it.unimi.dsi.fastutil.ints.Int2ObjectLinkedOpenHashMap.class,"tick maps are not vanilla native maps");
        Field uf=sun.misc.Unsafe.class.getDeclaredField("theUnsafe"); uf.setAccessible(true); var unsafe=(sun.misc.Unsafe)uf.get(null);
        var first=(EntityFixture)unsafe.allocateInstance(EntityFixture.class); first.id=41;
        var second=(EntityFixture)unsafe.allocateInstance(EntityFixture.class); second.id=42;
        var third=(EntityFixture)unsafe.allocateInstance(EntityFixture.class); third.id=43;
        ticks.add(first); ticks.add(second); var visited=new ArrayList<net.minecraft.world.entity.Entity>();
        ticks.forEach(e->{ visited.add(e); if(e==first) { ticks.remove(first); ticks.add(third); } });
        check(visited.size()==2 && visited.get(0)==first && visited.get(1)==second
            && !ticks.contains(first) && ticks.contains(second) && ticks.contains(third) && ticks.iterated==null,"vanilla iteration/swap semantics changed");
    }
    public static void main(String[] args) throws Exception {
        // Every production callback must match a real official-name Minecraft method.
        for(var method:OwnerSafetyHooks.class.getDeclaredMethods()) for(AsmHook hook:method.getAnnotationsByType(AsmHook.class)) {
            HookDefinition.from(hook,method);
            try(InputStream in=TargetGuardCheck.class.getClassLoader().getResourceAsStream(hook.targetClass()+".class")) {
                check(in!=null,"missing hook class "+hook.targetClass());
                org.objectweb.asm.tree.ClassNode node=new org.objectweb.asm.tree.ClassNode();
                new ClassReader(in).accept(node,ClassReader.SKIP_CODE);
                boolean found=false;
                for(var m:node.methods) if(m.name.equals(hook.targetMethod()) && m.desc.equals(hook.targetDescriptor())) found=true;
                check(found,"missing production hook "+hook.targetMethod()+hook.targetDescriptor());
            }
        }
        Method parse=TargetLedger.class.getDeclaredMethod("index",Set.class); parse.setAccessible(true);
        UUID uuid=UUID.randomUUID();
        Object parsed=parse.invoke(null,Set.of("minecraft:overworld|"+uuid+"|12", "type:example:boss", "name:someone"));
        Method rows=parsed.getClass().getDeclaredMethod("rows"); rows.setAccessible(true);
        Map<?,?> parsedRows=(Map<?,?>)rows.invoke(parsed);
        check(parsedRows.size()==1 && parsedRows.containsKey(uuid),"legacy broad death marks must not become targets");
        Method current=TargetLedger.class.getDeclaredMethod("current",boolean.class,boolean.class); current.setAccessible(true);
        Field server=TargetLedger.class.getDeclaredField("serverDeaths"); server.setAccessible(true);
        Object initial=server.get(null);
        try {
            server.set(null,parsed);
            com.himitsu.secret.network.RuntimeSyncState.CIVILIZATION_DEATHS.replace(Set.of());
            check(current.invoke(null,false,false)==parsed,"old client snapshot must not erase authoritative targets");
            Object client=current.invoke(null,true,false);
            check(((Map<?,?>)rows.invoke(client)).isEmpty(),"client has independent transport snapshot");
        } finally { server.set(null,initial); }
        WeakTargetSet<Object> identities=new WeakTargetSet<>();
        class MutableIdentity { int hash; public int hashCode() { return hash; } public boolean equals(Object other) { return other instanceof MutableIdentity; } }
        MutableIdentity target=new MutableIdentity(), neighbor=new MutableIdentity(); Object world=new Object();
        identities.add(target,world); target.hash=123;
        check(identities.contains(target) && !identities.contains(neighbor),"exact identity, not mutable equality");
        identities.clearScope(world); check(!identities.contains(target),"world lifecycle releases exact targets");
        // Preparing construction-time policy must work while no native library is loaded.
        check(!com.himitsu.secret.bridge.SecretNative.isLoaded(),"offline bridge unexpectedly loaded");
        ClassDefense.prepare(new com.himitsu.secret.config.SecretConfig("mixin",false));
        try {
            ClassDefense.initialize(new com.himitsu.secret.config.SecretConfig("mixin",false));
            throw new AssertionError("Startup accepted an unavailable native bridge");
        } catch (IllegalStateException expected) {}
        Field bridgeLoaded=com.himitsu.secret.bridge.SecretNative.class.getDeclaredField("loaded");
        bridgeLoaded.setAccessible(true);
        try {
            bridgeLoaded.setBoolean(null,true);
            // No native endpoint is installed: any hidden VM scan/call would fail this check.
            ClassDefense.initialize(new com.himitsu.secret.config.SecretConfig("mixin",false));
        } finally { bridgeLoaded.setBoolean(null,false); }
        check(!com.himitsu.secret.bridge.SecretNative.isLoaded(),"policy preparation must not load or invoke native code");
        HookRegistry.register(TargetGuardCheck.class);
        String name="com/himitsu/secret/core/TargetGuardCheck$Fixture";
        byte[] bytes; try(InputStream in=TargetGuardCheck.class.getClassLoader().getResourceAsStream(name+".class")) { bytes=in.readAllBytes(); }
        byte[] transformed=HookTransformer.transform(TargetGuardCheck.class.getClassLoader(),name,null,null,bytes);
        class Loader extends ClassLoader { Class<?> define(byte[] data) { return defineClass(name.replace('/','.'),data,0,data.length); } }
        Method operation=new Loader().define(transformed).getMethod("operation",int.class);
        check(operation.invoke(null,2).equals(9) && depth==0,"normal return cleanup");
        try { operation.invoke(null,-1); throw new AssertionError("missing exception"); } catch(InvocationTargetException e) { check(e.getCause() instanceof IllegalStateException,"original exception"); }
        check(depth==0 && entered==2 && exited==2,"exception finally cleanup");
        var eye = new net.minecraft.world.phys.Vec3(0.0D, 1.5D, 0.0D);
        var look = new net.minecraft.world.phys.Vec3(0.0D, 0.0D, 1.0D);
        var end = eye.add(look.scale(128.0D));
        check(CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(-0.25,1.25,5.25,0.25,1.75,5.75),eye,look,end),"left swing misses forward target");
        check(!CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(-0.25,1.25,-3,0.25,1.75,-2),eye,look,end),"left swing reaches behind owner");
        check(!CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(3,1.25,5,4,1.75,6),eye,look,end),"left swing widened into area attack");
        check(CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(-0.25,1.25,127.25,0.25,1.75,127.75),eye,look,end),"last original sample was lost");
        check(!CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(-0.25,1.25,129,0.25,1.75,130),eye,look,end),"left swing exceeded 128-block segment and its half-block tolerance");
        check(!CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(0.5001,1.25,5,1,1.75,6),eye,look,end),"outside ray tolerance became a hit");
        check(CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(-0.25,1.25,128,0.25,1.75,129),eye,look,end),"continuous ray lost its endpoint");
        check(CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(-1,0,-1,1,2,1),eye,look,end),"sample fallback lost target containing eye");
        var diagonal = new net.minecraft.world.phys.Vec3(1,0,1).normalize();
        check(CivilizationSurvival.swingIntersects(new net.minecraft.world.phys.AABB(0.6,1.4,-0.1,0.7,1.6,0),eye,diagonal,eye.add(diagonal.scale(128.0D))),"continuous ray misses a target between sample boxes");
        checkWeaponEntries();
        checkR14();
        checkLeanReads();
        System.out.println("TARGET_GUARDS_PASS owner_raw_motion_repair r16_ready_clone session_isolation attribute_index write_guards section_repair retry_budget indexed_residuals unload_barrier native_tick_swap identity_snapshot_no_auth bounded_weapon_scan new_instance scope_normal scope_throw production_hook_targets exact_identity_index startup_prepare_without_native left_swing_geometry attack_and_swing_before_cancel repeat_weave_once owner_session_localchannel fakeplayer multipart_cycle cursor_transfer_weapon_recovery entry_uuid MODEL_NO_GAME");
    }
}
