package com.himitsu.secret.core;

import com.himitsu.secret.client.DeathClient;
import com.himitsu.secret.hook.AsmHook;
import com.himitsu.secret.hook.HookMode;
import net.minecraft.client.Minecraft;
import net.minecraft.client.KeyboardHandler;
import net.minecraft.client.MouseHandler;
import net.minecraft.client.gui.screens.Overlay;
import net.minecraft.client.gui.screens.Screen;

public final class DeathExecutionHooks {
    private DeathExecutionHooks() {
    }

    @AsmHook(
        targetClass = "net/minecraft/client/Minecraft",
        targetMethod = "setScreen",
        targetAliases = "m_91152_",
        targetDescriptor = "(Lnet/minecraft/client/gui/screens/Screen;)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardSetScreen(Minecraft minecraft, Screen screen) {
        return DeathExecution.isClientActive() && !DeathClient.isDeathScreen(screen);
    }

    @AsmHook(
        targetClass = "net/minecraft/client/MouseHandler",
        targetMethod = "grabMouse",
        targetAliases = "m_91601_",
        targetDescriptor = "()V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardGrabMouse(MouseHandler mouseHandler) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/Minecraft",
        targetMethod = "forceSetScreen",
        targetAliases = "m_91346_",
        targetDescriptor = "(Lnet/minecraft/client/gui/screens/Screen;)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardForceSetScreen(Minecraft minecraft, Screen screen) {
        return DeathExecution.isClientActive() && !DeathClient.isDeathScreen(screen);
    }

    @AsmHook(
        targetClass = "net/minecraft/client/Minecraft",
        targetMethod = "setOverlay",
        targetAliases = "m_91150_",
        targetDescriptor = "(Lnet/minecraft/client/gui/screens/Overlay;)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardSetOverlay(Minecraft minecraft, Overlay overlay) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/Minecraft",
        targetMethod = "handleKeybinds",
        targetAliases = "m_91279_",
        targetDescriptor = "()V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardKeybinds(Minecraft minecraft) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/Minecraft",
        targetMethod = "pauseGame",
        targetAliases = "m_91358_",
        targetDescriptor = "(Z)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardPause(Minecraft minecraft, boolean pauseOnly) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/MouseHandler",
        targetMethod = "onPress",
        targetAliases = "m_91530_",
        targetDescriptor = "(JIII)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardMousePress(MouseHandler mouseHandler, long window, int button, int action, int modifiers) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/MouseHandler",
        targetMethod = "onScroll",
        targetAliases = "m_91526_",
        targetDescriptor = "(JDD)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardMouseScroll(MouseHandler mouseHandler, long window, double xOffset, double yOffset) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/MouseHandler",
        targetMethod = "onMove",
        targetAliases = "m_91561_",
        targetDescriptor = "(JDD)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardMouseMove(MouseHandler mouseHandler, long window, double x, double y) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/MouseHandler",
        targetMethod = "turnPlayer",
        targetAliases = "m_91523_",
        targetDescriptor = "()V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardTurnPlayer(MouseHandler mouseHandler) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/KeyboardHandler",
        targetMethod = "keyPress",
        targetAliases = "m_90893_",
        targetDescriptor = "(JIIII)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardKeyPress(
        KeyboardHandler keyboard,
        long window,
        int key,
        int scanCode,
        int action,
        int modifiers
    ) {
        return DeathExecution.isClientActive();
    }

    @AsmHook(
        targetClass = "net/minecraft/client/KeyboardHandler",
        targetMethod = "charTyped",
        targetAliases = "m_90889_",
        targetDescriptor = "(JII)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardCharTyped(KeyboardHandler keyboard, long window, int codePoint, int modifiers) {
        return DeathExecution.isClientActive();
    }
}
