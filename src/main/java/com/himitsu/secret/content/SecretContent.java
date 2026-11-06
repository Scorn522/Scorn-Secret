package com.himitsu.secret.content;

import com.himitsu.secret.SecretMod;
import com.himitsu.secret.entity.SecretEntity;
import com.himitsu.secret.item.CivilizationSurvivalItem;
import com.himitsu.secret.item.ConfigToolItem;
import com.himitsu.secret.item.DeathItem;
import com.himitsu.secret.tab.SecretTab;
import net.minecraft.core.particles.ParticleType;
import net.minecraft.core.registries.Registries;
import net.minecraft.world.entity.EntityType;
import net.minecraft.world.entity.MobCategory;
import net.minecraft.world.item.CreativeModeTab;
import net.minecraft.world.item.Item;
import net.minecraft.world.level.block.Block;
import net.minecraftforge.eventbus.api.IEventBus;
import net.minecraftforge.common.ForgeSpawnEggItem;
import net.minecraftforge.event.entity.EntityAttributeCreationEvent;
import net.minecraftforge.registries.DeferredRegister;
import net.minecraftforge.registries.ForgeRegistries;
import net.minecraftforge.registries.RegistryObject;

public final class SecretContent {
    private static final DeferredRegister<Block> BLOCKS =
        DeferredRegister.create(ForgeRegistries.BLOCKS, SecretMod.MODID);
    private static final DeferredRegister<Item> ITEMS =
        DeferredRegister.create(ForgeRegistries.ITEMS, SecretMod.MODID);
    private static final DeferredRegister<EntityType<?>> ENTITIES =
        DeferredRegister.create(ForgeRegistries.ENTITY_TYPES, SecretMod.MODID);
    private static final DeferredRegister<ParticleType<?>> PARTICLES =
        DeferredRegister.create(ForgeRegistries.PARTICLE_TYPES, SecretMod.MODID);
    private static final DeferredRegister<CreativeModeTab> TABS =
        DeferredRegister.create(Registries.CREATIVE_MODE_TAB, SecretMod.MODID);

    public static final RegistryObject<Item> CIVILIZATION_SURVIVAL = ITEMS.register(
        "civilization_survival",
        CivilizationSurvivalItem::new
    );
    public static final RegistryObject<Item> CONFIG_TOOL = ITEMS.register(
        "config_tool",
        ConfigToolItem::new
    );
    public static final RegistryObject<Item> DEATH = ITEMS.register(
        "death",
        DeathItem::new
    );
    public static final RegistryObject<EntityType<SecretEntity>> SECRET_ENTITY = ENTITIES.register(
        "secret",
        () -> EntityType.Builder.of(SecretEntity::new, MobCategory.CREATURE)
            .sized(0.6F, 1.8F)
            .clientTrackingRange(256)
            .updateInterval(3)
            .build("secret")
    );
    public static final RegistryObject<Item> SECRET_SPAWN_EGG = ITEMS.register(
        "secret_spawn_egg",
        () -> new ForgeSpawnEggItem(SECRET_ENTITY, 0x00A4A7, 0x3F2A78, new Item.Properties())
    );
    public static final RegistryObject<CreativeModeTab> SECRET_TAB = TABS.register("secret", SecretTab::create);

    private SecretContent() {
    }

    public static void register(IEventBus modBus) {
        ITEMS.register(modBus);
        ENTITIES.register(modBus);
        BLOCKS.register(modBus);
        PARTICLES.register(modBus);
        TABS.register(modBus);
        modBus.addListener(SecretContent::registerAttributes);
    }

    private static void registerAttributes(EntityAttributeCreationEvent event) {
        event.put(SECRET_ENTITY.get(), SecretEntity.createAttributes().build());
    }
}
