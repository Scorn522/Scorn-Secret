package com.himitsu.secret.network;

import com.himitsu.secret.network.sync.SyncValue;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;

final class SyncPacket {
    private static final int MAX_PAYLOAD = 1024 * 1024;

    private final String key;
    private final String type;
    private final byte[] payload;

    private SyncPacket(String key, String type, byte[] payload) {
        this.key = key;
        this.type = type;
        this.payload = payload;
    }

    static SyncPacket from(SyncValue value) {
        ByteBuf byteBuf = Unpooled.buffer();
        try {
            FriendlyByteBuf buffer = new FriendlyByteBuf(byteBuf);
            value.encode(buffer);
            byte[] payload = new byte[buffer.readableBytes()];
            buffer.getBytes(buffer.readerIndex(), payload);
            if (payload.length > MAX_PAYLOAD) {
                throw new IllegalArgumentException("Synchronized payload is too large");
            }
            return new SyncPacket(value.key(), value.type(), payload);
        } finally {
            byteBuf.release();
        }
    }

    static void encode(SyncPacket packet, FriendlyByteBuf buffer) {
        buffer.writeUtf(packet.key, 256);
        buffer.writeUtf(packet.type, 64);
        buffer.writeByteArray(packet.payload);
    }

    static SyncPacket decode(FriendlyByteBuf buffer) {
        return new SyncPacket(buffer.readUtf(256), buffer.readUtf(64), buffer.readByteArray(MAX_PAYLOAD));
    }

    void apply() {
        SyncValue value = SyncRegistry.get(key);
        if (value == null || !value.type().equals(type)) {
            return;
        }
        FriendlyByteBuf buffer = new FriendlyByteBuf(Unpooled.wrappedBuffer(payload));
        try {
            value.decode(buffer);
            if(value==RuntimeSyncState.DEATH_EXECUTED) com.himitsu.secret.core.OwnerSafety.refreshDeaths();
            if(value==RuntimeSyncState.CIVILIZATION_OWNERS || value==RuntimeSyncState.DEATH_EXECUTED)
                com.himitsu.secret.core.CivilizationSurvival.ownersChanged();
            if (value == RuntimeSyncState.CIVILIZATION_DEATHS) com.himitsu.secret.core.CivilizationSurvival.applyTargetMarks();
            if (value == RuntimeSyncState.TARGET_BOSS_BARS) com.himitsu.secret.core.TargetCleanup.applyBossRemovals();
            if (buffer.isReadable()) {
                throw new IllegalArgumentException("Trailing bytes in synchronized value " + key);
            }
        } finally {
            buffer.release();
        }
    }
}
