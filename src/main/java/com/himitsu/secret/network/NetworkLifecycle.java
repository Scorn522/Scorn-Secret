package com.himitsu.secret.network;

import net.minecraftforge.event.entity.player.PlayerEvent;

public final class NetworkLifecycle {
    private NetworkLifecycle() {
    }

    public static final class PlayerSync {
        private PlayerSync() {
        }

        public static void playerLoggedIn(PlayerEvent.PlayerLoggedInEvent event) {
            com.himitsu.secret.core.CivilizationSurvival.playerReady(event.getEntity());
            if (SecretNetwork.isInitialized()
                && event.getEntity() instanceof net.minecraft.server.level.ServerPlayer) {
                SecretNetwork.sendSnapshot((net.minecraft.server.level.ServerPlayer) event.getEntity());
            }
        }

        public static void playerChangedDimension(PlayerEvent.PlayerChangedDimensionEvent event) {
            com.himitsu.secret.core.CivilizationSurvival.playerReady(event.getEntity());
            if (SecretNetwork.isInitialized()
                && event.getEntity() instanceof net.minecraft.server.level.ServerPlayer) {
                SecretNetwork.sendSnapshot((net.minecraft.server.level.ServerPlayer) event.getEntity());
            }
        }

        public static void playerClone(PlayerEvent.Clone event) {
            if (event.getEntity() instanceof net.minecraft.server.level.ServerPlayer player) {
                if (com.himitsu.secret.core.CivilizationSurvival.isOwner(event.getOriginal())) {
                    com.himitsu.secret.core.CivilizationSurvival.registerOwner(player);
                }
                com.himitsu.secret.core.CivilizationSurvival.detachOwner(event.getOriginal(),false);
                if (SecretNetwork.isInitialized()) SecretNetwork.sendSnapshot(player);
            }
        }

        public static void playerRespawn(PlayerEvent.PlayerRespawnEvent event) {
            if (event.getEntity() instanceof net.minecraft.server.level.ServerPlayer player) {
                com.himitsu.secret.core.CivilizationSurvival.playerReady(player);
                if (SecretNetwork.isInitialized()) SecretNetwork.sendSnapshot(player);
            }
        }
    }
}
