package com.himitsu.secret.network.sync;

import net.minecraft.network.FriendlyByteBuf;

public interface SyncValue {
    String key();

    String type();

    void encode(FriendlyByteBuf buffer);

    void decode(FriendlyByteBuf buffer);
}
