package com.himitsu.secret.network;

import net.minecraftforge.event.entity.player.PlayerEvent;

public final class NetworkLifecycle {
    private NetworkLifecycle() {
    }

    public static final class PlayerSync {
        private PlayerSync() {
        }

        private static void ready(net.minecraft.world.entity.player.Player player) {
            if(player instanceof net.minecraft.server.level.ServerPlayer server && server.connection!=null && server.connection.player!=server) {
                server.server.tell(new net.minecraft.server.TickTask(server.server.getTickCount(),()-> {
                    if(server.connection.player==server && server.server.getPlayerList().getPlayer(server.uuid)==server) ready(server);
                }));
                return;
            }
            com.himitsu.secret.core.DeathExecution.onPlayerReady(player);
            com.himitsu.secret.core.CivilizationSurvival.playerReady(player);
            if(SecretNetwork.isInitialized() && player instanceof net.minecraft.server.level.ServerPlayer server) SecretNetwork.sendSnapshot(server);
        }

        public static void playerLoggedIn(PlayerEvent.PlayerLoggedInEvent event) { ready(event.getEntity()); }
        public static void playerChangedDimension(PlayerEvent.PlayerChangedDimensionEvent event) { ready(event.getEntity()); }
        public static void playerClone(PlayerEvent.Clone event) {
            if(event.getEntity() instanceof net.minecraft.server.level.ServerPlayer player) {
                com.himitsu.secret.core.OwnerSafety.onPlayerClone(event.getOriginal(),player);
                com.himitsu.secret.core.DeathExecution.onPlayerClone(event.getOriginal(),player);
                com.himitsu.secret.core.CivilizationSurvival.detachOwner(event.getOriginal(),false);
            }
        }
        public static void playerRespawn(PlayerEvent.PlayerRespawnEvent event) { ready(event.getEntity()); }
    }
}
