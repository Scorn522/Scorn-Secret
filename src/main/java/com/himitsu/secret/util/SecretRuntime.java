package com.himitsu.secret.util;

import com.himitsu.secret.SecretMod;
import com.himitsu.secret.bridge.SecretNative;
import com.himitsu.secret.config.SecretConfig;
import com.himitsu.secret.content.SecretContent;
import com.himitsu.secret.core.BackgroundService;
import com.himitsu.secret.core.PayloadTransformer;
import com.himitsu.secret.core.RuntimeState;
import com.himitsu.secret.core.EventBusTakeover;
import com.himitsu.secret.network.RuntimeSyncState;
import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.fml.loading.FMLEnvironment;
import net.minecraftforge.fml.event.lifecycle.FMLClientSetupEvent;
import com.himitsu.secret.network.SecretNetwork;
import java.nio.file.Path;
import net.minecraftforge.eventbus.api.IEventBus;

public final class SecretRuntime {
    private static final RuntimeState STATE = new RuntimeState();
    private static BackgroundService backgroundService;

    private SecretRuntime() {
    }

    public static void boot(
        IEventBus modBus,
        Path gameDirectory,
        Path modPath
    ) {
        try {
            initialize(modBus, gameDirectory, modPath);
        } catch (Throwable throwable) {
            if (backgroundService != null) {
                backgroundService.close();
            }
            STATE.fail(throwable);
            SecretMod.throwUnchecked(throwable);
        }
    }

    private static void initialize(
        IEventBus modBus,
        Path gameDirectory,
        Path modPath
    ) throws Exception {
        STATE.enter(RuntimeState.Phase.CONFIGURATION);
        SecretConfig config = SecretConfig.load(gameDirectory);

        STATE.enter(RuntimeState.Phase.NATIVE_BRIDGE);
        SecretNative.configure(gameDirectory, modPath);

        STATE.initialize(config);

        STATE.enter(RuntimeState.Phase.PAYLOAD);
        STATE.enter(RuntimeState.Phase.TRANSFORMER);
        EventBusTakeover.registerRequiredHandlers();
        com.himitsu.secret.core.ClassDefense.initialize(config);
        PayloadTransformer.install();
        modBus.addListener((net.minecraftforge.fml.event.lifecycle.FMLCommonSetupEvent event) ->
            event.enqueueWork(() -> {
                com.himitsu.secret.core.CivilizationSurvivalHooks.installWeaponHooks();
                com.himitsu.secret.core.SecretEntityHooks.installTargetGuards();
            }));

        STATE.enter(RuntimeState.Phase.NETWORK);
        RuntimeSyncState.initialize();
        SecretNetwork.initialize();
        if (FMLEnvironment.dist == Dist.CLIENT) {
            registerClientInfrastructure(modBus);
        }

        STATE.enter(RuntimeState.Phase.BACKGROUND);
        backgroundService = new BackgroundService(STATE);
        backgroundService.start();
        SecretNative.beforeShutdown(backgroundService::close);

        STATE.enter(RuntimeState.Phase.CONTENT);
        registerContent(modBus);

        STATE.enter(RuntimeState.Phase.READY);
        EventBusTakeover.activate();
    }

    private static void registerContent(IEventBus modBus) {
        SecretContent.register(modBus);
    }

    private static void registerClientInfrastructure(IEventBus modBus) {
        modBus.addListener(com.himitsu.secret.client.SecretClientContent::registerRenderers);
        modBus.addListener((FMLClientSetupEvent event) -> event.enqueueWork(() -> {
            com.himitsu.secret.client.render.NativeRenderBridge.install();
        }));
    }

    public static RuntimeState state() {
        return STATE;
    }
}
