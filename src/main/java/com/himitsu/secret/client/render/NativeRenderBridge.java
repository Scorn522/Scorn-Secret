package com.himitsu.secret.client.render;

import com.himitsu.secret.bridge.SecretNative;
import com.himitsu.secret.core.RuntimeMetrics;
import com.himitsu.secret.core.CivilizationSurvival;
import com.himitsu.secret.core.DeathExecution;
import com.himitsu.secret.util.DynamicMethodLookup;

public final class NativeRenderBridge {
    public static final int STAGE_GDI_SWAP = 1;
    public static final int STAGE_GLFW_SWAP = 2;
    public static final int STAGE_WGL_LAYER_SWAP = 3;
    public static final int STAGE_FRAMEBUFFER_BIND = 4;
    public static final int STAGE_FRAMEBUFFER_BLIT = 5;
    public static final int STAGE_NTGDI_SWAP = 6;
    public static final int STAGE_FRONT_OVERLAY = 7;
    public static final int STAGE_D3D9_PRESENT = 8;
    public static final int STAGE_DXGI_PRESENT = 9;

    private static volatile boolean installed;
    private static volatile boolean installing;
    private static net.minecraft.world.level.Level frameLevel;
    private static boolean frameRendered;
    private NativeRenderBridge() {
    }

    public static synchronized void install() {
        if (installed || installing) {
            return;
        }
        installing = true;
        if (bind()) {
            installed = true;
            installing = false;
            return;
        }

        Thread retry = new Thread(() -> {
            try {
                for (int attempt = 0; attempt < 60 && !installed; attempt++) {
                    Thread.sleep(1000L);
                    if (bind()) {
                        installed = true;
                    }
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            } finally {
                installing = false;
            }
        }, "Secret-SwapBuffers-Hook");
        retry.setDaemon(true);
        retry.start();
    }

    static void markRendered(net.minecraft.world.level.Level level) {
        frameLevel=level;frameRendered=level!=null;
    }
    public static void clearLevel(net.minecraft.world.level.Level level) {
        if(frameLevel==level) {frameLevel=null;frameRendered=false;}
    }
    private static void endFrame(net.minecraft.world.level.Level level) {frameRendered=false;frameLevel=level;}
    private static boolean needsAvatar(net.minecraft.world.level.Level level) {
        if(frameLevel!=level) {frameLevel=level;frameRendered=false;}
        return !frameRendered && com.himitsu.secret.client.avatar.SecretAvatarManager.present(level);
    }
    public static boolean callback(boolean before, int stage, long frameContext) {
        RuntimeMetrics.recordNativeRenderCallback();
        if (stage == STAGE_D3D9_PRESENT || stage == STAGE_DXGI_PRESENT)
            return !before || !DeathExecution.isClientActive();
        if(!com.mojang.blaze3d.systems.RenderSystem.isOnRenderThread()) return stage!=STAGE_FRONT_OVERLAY || before;
        var level=net.minecraft.client.Minecraft.getInstance().level;
        boolean needed=needsAvatar(level);
        // Native asks before querying/changing front-buffer GL state.
        if(!before && stage==STAGE_FRONT_OVERLAY)
            return DeathExecution.isClientActive() || needed;
        if(!before) {
            if(isSwapStage(stage)) endFrame(level);
            return true;
        }
        if(isSwapStage(stage)) {
            DeathExecution.clientTick();
            CivilizationSurvival.maintainGui();
        }
        if(stage<STAGE_GDI_SWAP || stage>STAGE_FRONT_OVERLAY) return true;
        try {
            if(DeathExecution.isClientActive()) SecretDeathRenderer.renderNativeLayer();
            else if(needed && (isSwapStage(stage) || stage==STAGE_FRONT_OVERLAY)
                    && SecretManualRenderer.renderBeforeSwap()) markRendered(level);
        } catch(Throwable ignored) {
            // A failed normal/swap draw does not consume the final front-buffer fallback.
        }
        return true;
    }
    private static boolean isSwapStage(int stage) {
        return stage==STAGE_GDI_SWAP || stage==STAGE_GLFW_SWAP
            || stage==STAGE_WGL_LAYER_SWAP || stage==STAGE_NTGDI_SWAP;
    }

    private static boolean bind() {
        try {
            return Boolean.TRUE.equals(SecretNative.invokeChecked(
                "BindRender",
                NativeRenderBridge.class,
                DynamicMethodLookup.findStatic(
                    NativeRenderBridge.class,
                    boolean.class,
                    boolean.class,
                    int.class,
                    long.class
                )
            ));
        } catch (Throwable ignored) {
            return false;
        }
    }
}
