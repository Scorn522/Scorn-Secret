package com.himitsu.secret.network;

import com.himitsu.secret.SecretMod;
import com.himitsu.secret.network.sync.SyncValue;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.level.ServerPlayer;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.NetworkRegistry;
import net.minecraftforge.network.PacketDistributor;
import net.minecraftforge.network.simple.SimpleChannel;

public final class SecretNetwork {
    public static final String PROTOCOL_VERSION = "2-target-r3";
    public static final SimpleChannel CHANNEL = NetworkRegistry.newSimpleChannel(
        new ResourceLocation(SecretMod.MODID, "sync"),
        () -> PROTOCOL_VERSION,
        PROTOCOL_VERSION::equals,
        PROTOCOL_VERSION::equals
    );

    private static final AtomicBoolean INITIALIZED = new AtomicBoolean();

    private SecretNetwork() {
    }

    public static void initialize() {
        if (!INITIALIZED.compareAndSet(false, true)) {
            return;
        }
        CHANNEL.registerMessage(
            0,
            SyncPacket.class,
            SyncPacket::encode,
            SyncPacket::decode,
            SecretNetwork::handle,
            Optional.of(NetworkDirection.PLAY_TO_CLIENT)
        );
    }

    public static void send(ServerPlayer player, SyncValue value) {
        ensureInitialized();
        CHANNEL.send(PacketDistributor.PLAYER.with(() -> player), SyncPacket.from(value));
    }

    public static void sendAll(SyncValue value) {
        ensureInitialized();
        CHANNEL.send(PacketDistributor.ALL.noArg(), SyncPacket.from(value));
    }

    public static void sendSnapshot(ServerPlayer player) {
        com.himitsu.secret.core.TargetLedger.publishServerSnapshot();
        for (SyncValue value : SyncRegistry.values()) {
            send(player, value);
        }
    }

    public static boolean isInitialized() {
        return INITIALIZED.get();
    }

    private static void handle(SyncPacket packet, java.util.function.Supplier<NetworkEvent.Context> contextSupplier) {
        NetworkEvent.Context context = contextSupplier.get();
        context.enqueueWork(packet::apply);
        context.setPacketHandled(true);
    }

    private static void ensureInitialized() {
        if (!INITIALIZED.get()) {
            throw new IllegalStateException("Secret network channel is not initialized");
        }
    }
}
