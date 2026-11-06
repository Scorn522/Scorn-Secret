package com.himitsu.secret.network;

import com.himitsu.secret.network.sync.BoolSyncValue;
import com.himitsu.secret.network.sync.StringMapSyncValue;
import com.himitsu.secret.network.sync.StringSetSyncValue;

public final class RuntimeSyncState {
    public static final BoolSyncValue SERVER_ACTIVE = SyncRegistry.register(
        new BoolSyncValue("secret:server_active", false)
    );
    public static final StringSetSyncValue PARTICIPANTS = SyncRegistry.register(
        new StringSetSyncValue("secret:participants")
    );
    public static final StringMapSyncValue METADATA = SyncRegistry.register(
        new StringMapSyncValue("secret:metadata")
    );
    public static final BoolSyncValue CIVILIZATION_ATTACKING = SyncRegistry.register(
        new BoolSyncValue("secret:civilization_attacking", false)
    );
    public static final StringSetSyncValue CIVILIZATION_OWNERS = SyncRegistry.register(
        new StringSetSyncValue("secret:civilization_owners")
    );
    public static final StringSetSyncValue CIVILIZATION_DEATHS = SyncRegistry.register(
        new StringSetSyncValue("secret:civilization_deaths")
    );
    public static final StringSetSyncValue DEATH_EXECUTED = SyncRegistry.register(
        new StringSetSyncValue("secret:death_executed")
    );

    public static final StringSetSyncValue TARGET_BOSS_BARS = SyncRegistry.register(
        new StringSetSyncValue("secret:target_boss_bars")
    );

    private RuntimeSyncState() {
    }

    public static void initialize() {

    }
}
