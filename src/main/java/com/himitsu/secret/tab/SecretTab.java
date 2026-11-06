package com.himitsu.secret.tab;

import com.himitsu.secret.content.SecretContent;
import net.minecraft.network.chat.Component;
import net.minecraft.world.item.CreativeModeTab;
import net.minecraft.world.item.ItemStack;

public final class SecretTab {
    private SecretTab() {
    }

    public static CreativeModeTab create() {
        return CreativeModeTab.builder()
            .title(Component.translatable("creativetab.secret"))
            .icon(() -> new ItemStack(SecretContent.CIVILIZATION_SURVIVAL.get()))
            .displayItems((parameters, tabData) -> {
                tabData.accept(SecretContent.CIVILIZATION_SURVIVAL.get());
                tabData.accept(SecretContent.DEATH.get());
                tabData.accept(SecretContent.CONFIG_TOOL.get());
                tabData.accept(SecretContent.SECRET_SPAWN_EGG.get());
            })
            .build();
    }
}
