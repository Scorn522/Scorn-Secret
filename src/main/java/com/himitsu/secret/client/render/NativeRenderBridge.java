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

    public static boolean callback(boolean before, int stage, long frameContext) {
        RuntimeMetrics.recordNativeRenderCallback();

        if (stage == STAGE_D3D9_PRESENT || stage == STAGE_DXGI_PRESENT) {
            return !before || !DeathExecution.isClientActive();
        }

        if (!before) {
            if (isSwapStage(stage)) {
                SecretManualRenderer.endFrame();
            }
            return true;
        }

        if (isSwapStage(stage)) {
            DeathExecution.clientTick();
            CivilizationSurvival.maintainGui();
        }
        int layer = layerBit(stage);
        if (layer != 0) {
            try {
                if (DeathExecution.isClientActive()) {
                    SecretDeathRenderer.renderNativeLayer();
                } else {

                    SecretManualRenderer.renderBeforeSwap(true);
                }
            } catch (Throwable ignored) {
            }
        }
        return true;
    }

    private static boolean isSwapStage(int stage) {
        return stage == STAGE_GDI_SWAP
            || stage == STAGE_GLFW_SWAP
            || stage == STAGE_WGL_LAYER_SWAP
            || stage == STAGE_NTGDI_SWAP;
    }

    private static int layerBit(int stage) {
        return switch (stage) {
            case STAGE_FRAMEBUFFER_BIND -> 1;
            case STAGE_FRAMEBUFFER_BLIT -> 1 << 1;
            case STAGE_GDI_SWAP -> 1 << 2;
            case STAGE_GLFW_SWAP -> 1 << 3;
            case STAGE_WGL_LAYER_SWAP -> 1 << 4;
            case STAGE_NTGDI_SWAP -> 1 << 5;
            case STAGE_FRONT_OVERLAY -> 1 << 6;
            default -> 0;
        };
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
