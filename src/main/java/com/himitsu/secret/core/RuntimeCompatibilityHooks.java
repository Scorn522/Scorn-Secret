package com.himitsu.secret.core;

import com.himitsu.secret.client.screen.SecretConfigScreen;
import com.himitsu.secret.client.screen.SecretDeathScreen;
import com.himitsu.secret.hook.AsmHook;
import com.himitsu.secret.hook.HookMode;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.events.GuiEventListener;
import net.minecraft.client.gui.screens.Screen;

public final class RuntimeCompatibilityHooks {
    private RuntimeCompatibilityHooks() {
    }

    @AsmHook(
        targetClass = "net/minecraft/client/gui/screens/Screen",
        targetMethod = "render",
        targetAliases = "m_88315_",
        targetDescriptor = "(Lnet/minecraft/client/gui/GuiGraphics;IIF)V",
        mode = HookMode.GUARD,
        includeThis = true
    )
    public static boolean guardScreenRender(Screen screen, GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        return lockScreen(screen);
    }

    @AsmHook(targetClass = "net/minecraft/client/gui/components/events/GuiEventListener", targetMethod = "mouseClicked", targetAliases = "m_6375_", targetDescriptor = "(DDI)Z", mode = HookMode.GUARD, includeThis = true, includeSubclasses = true)
    @AsmHook(targetClass = "net/minecraft/client/gui/components/events/GuiEventListener", targetMethod = "mouseReleased", targetAliases = "m_6348_", targetDescriptor = "(DDI)Z", mode = HookMode.GUARD, includeThis = true, includeSubclasses = true)
    public static boolean guardScreenMouseButton(GuiEventListener listener, double mouseX, double mouseY, int button) {
        return lockScreen(listener);
    }

    @AsmHook(targetClass = "net/minecraft/client/gui/components/events/GuiEventListener", targetMethod = "mouseDragged", targetAliases = "m_7979_", targetDescriptor = "(DDIDD)Z", mode = HookMode.GUARD, includeThis = true, includeSubclasses = true)
    public static boolean guardScreenMouseDrag(GuiEventListener listener, double mouseX, double mouseY, int button, double dragX, double dragY) {
        return lockScreen(listener);
    }

    @AsmHook(targetClass = "net/minecraft/client/gui/components/events/GuiEventListener", targetMethod = "mouseScrolled", targetAliases = "m_6050_", targetDescriptor = "(DDD)Z", mode = HookMode.GUARD, includeThis = true, includeSubclasses = true)
    public static boolean guardScreenScroll(GuiEventListener listener, double mouseX, double mouseY, double delta) {
        return lockScreen(listener);
    }

    @AsmHook(targetClass = "net/minecraft/client/gui/screens/Screen", targetMethod = "keyPressed", targetAliases = "m_7933_", targetDescriptor = "(III)Z", mode = HookMode.GUARD, includeThis = true)
    public static boolean guardScreenKey(Screen screen, int keyCode, int scanCode, int modifiers) {
        return lockScreen(screen);
    }

    @AsmHook(targetClass = "net/minecraft/client/gui/components/events/GuiEventListener", targetMethod = "keyReleased", targetAliases = "m_7920_", targetDescriptor = "(III)Z", mode = HookMode.GUARD, includeThis = true, includeSubclasses = true)
    public static boolean guardScreenKeyRelease(GuiEventListener listener, int keyCode, int scanCode, int modifiers) {
        return lockScreen(listener);
    }

    @AsmHook(targetClass = "net/minecraft/client/gui/components/events/GuiEventListener", targetMethod = "charTyped", targetAliases = "m_5534_", targetDescriptor = "(CI)Z", mode = HookMode.GUARD, includeThis = true, includeSubclasses = true)
    public static boolean guardScreenCharacter(GuiEventListener listener, char codePoint, int modifiers) {
        return lockScreen(listener);
    }

    @AsmHook(
        targetClass = "net/minecraft/client/gui/screens/Screen",
        targetMethod = "wrapScreenError",
        targetAliases = "m_96579_",
        targetDescriptor = "(Ljava/lang/Runnable;Ljava/lang/String;Ljava/lang/String;)V",
        mode = HookMode.OVERRIDE
    )
    public static void wrapScreenError(Runnable runnable, String errorTitle, String screenName) {
        try {
            runnable.run();
        } catch (Throwable ignored) {
        }
    }

    @AsmHook(targetClass = "net/minecraft/util/ThreadingDetector", targetMethod = "checkAndLock", targetAliases = "m_199416_", targetDescriptor = "()V", mode = HookMode.CLEAR)
    @AsmHook(targetClass = "net/minecraft/util/ThreadingDetector", targetMethod = "checkAndUnlock", targetAliases = "m_199422_", targetDescriptor = "()V", mode = HookMode.CLEAR)
    public static void clearCrashPath() {
    }

    @AsmHook(
        targetClass = "org/spongepowered/asm/mixin/transformer/MixinProcessor",
        targetMethod = "handleMixinError",
        targetDescriptor = "(Ljava/lang/String;Lorg/spongepowered/asm/mixin/transformer/throwables/InvalidMixinException;Lorg/spongepowered/asm/mixin/MixinEnvironment;Lorg/spongepowered/asm/mixin/transformer/MixinProcessor$ErrorPhase;)V",
        mode = HookMode.CLEAR
    )
    public static void clearMixinError() {
    }

    private static boolean lockScreen(Screen screen) {
        Minecraft minecraft = screen.getMinecraft();
        return minecraft != null && CivilizationSurvival.isOwner(minecraft.player) && !isAllowedScreen(screen);
    }

    private static boolean lockScreen(GuiEventListener listener) {
        return listener instanceof Screen screen && lockScreen(screen);
    }

    private static boolean isAllowedScreen(Screen screen) {
        String name = screen.getClass().getName();
        return name.startsWith("net.minecraft.client.gui.screens.")
            && !name.contains("DeathScreen")
            || screen instanceof SecretConfigScreen
            || screen instanceof SecretDeathScreen;
    }
}

