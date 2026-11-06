package com.himitsu.secret.client.screen;

import com.himitsu.secret.config.SecretConfig;
import java.io.IOException;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraftforge.fml.loading.FMLPaths;

public final class SecretConfigScreen extends Screen {
    private static final int PANEL_WIDTH = 456;
    private static final int PANEL_HEIGHT = 224;
    private static final int CARD_HEIGHT = 44;
    private static final int ACCENT = 0xFF72E4D1;
    private static final int ACCENT_BLUE = 0xFF6AA9FF;
    private static final int TEXT = 0xFFF4F8FA;
    private static final int MUTED = 0xFF8E9BA6;

    private final Screen parent;
    private String classDefense = "mixin";
    private boolean jvmtiDisable = false;
    private Component status = Component.empty();
    private int statusColor = MUTED;

    public SecretConfigScreen(Screen parent) {
        super(Component.translatable("screen.secret.config.title"));
        this.parent = parent;
        try {
            SecretConfig config = SecretConfig.load(FMLPaths.GAMEDIR.get());
            classDefense = config.classDefense();
            jvmtiDisable = config.jvmtiDisable();
        } catch (IOException exception) {
            status = Component.translatable("screen.secret.config.load_failed");
            statusColor = 0xFFFF7E8A;
        }
    }

    @Override
    protected void init() {
        if (minecraft != null) minecraft.mouseHandler.releaseMouse();
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        renderBackdrop(graphics);
        int panelWidth = Math.min(PANEL_WIDTH, width - 24);
        int panelHeight = Math.min(PANEL_HEIGHT, height - 24);
        int left = (width - panelWidth) / 2;
        int top = (height - panelHeight) / 2;

        shadow(graphics, left, top, panelWidth, panelHeight);
        rounded(graphics, left, top, panelWidth, panelHeight, 12, 0xFF0E171F);
        rounded(graphics, left + 1, top + 1, panelWidth - 2, panelHeight - 2, 11, 0xFF121D26);
        graphics.fillGradient(left + 12, top, left + panelWidth - 12, top + 3, ACCENT, ACCENT_BLUE);

        rounded(graphics, left + 18, top + 12, 30, 30, 8, 0xFF173B38);
        graphics.drawCenteredString(font, Component.literal("S"), left + 33, top + 23, ACCENT);
        graphics.drawString(font, title, left + 58, top + 13, TEXT, false);
        graphics.drawString(
            font, Component.translatable("screen.secret.config.subtitle"), left + 58, top + 30, MUTED, false
        );

        graphics.fill(left + 18, top + 50, left + panelWidth - 18, top + 51, 0xFF22313B);
        graphics.drawString(
            font, Component.translatable("screen.secret.config.section"), left + 20, top + 57, 0xFFB5C3CC, false
        );

        int cardLeft = left + 18;
        int cardWidth = panelWidth - 36;
        int firstCard = top + 69;
        optionCard(
            graphics, mouseX, mouseY, cardLeft, firstCard, cardWidth, "C",
            Component.translatable("screen.secret.config.class_defense"),
            Component.translatable("screen.secret.config.class_defense.description"),
            Component.translatable("screen.secret.config.class_defense." + classDefense),
            classDefense.equals("all")
        );
        optionCard(
            graphics, mouseX, mouseY, cardLeft, firstCard + 50, cardWidth, "J",
            Component.translatable("screen.secret.config.jvmti_disable"),
            Component.translatable("screen.secret.config.jvmti_disable.description"),
            Component.translatable(jvmtiDisable ? "options.on" : "options.off"),
            jvmtiDisable
        );

        int footerY = top + panelHeight - 45;
        graphics.fill(left + 18, footerY - 5, left + panelWidth - 18, footerY - 4, 0xFF22313B);
        int actionY = footerY + 5;
        drawAction(graphics, mouseX, mouseY, left + 18, actionY, 116, 26, true,
            Component.translatable("screen.secret.config.save"));
        drawAction(graphics, mouseX, mouseY, left + 142, actionY, 80, 26, false,
            Component.translatable("gui.done"));

        if (panelWidth >= 390) {
            Component statusText = status.getString().isEmpty()
                ? Component.translatable("screen.secret.config.restart_required")
                : status;
            int color = status.getString().isEmpty() ? MUTED : statusColor;
            int statusX = left + panelWidth - 18 - font.width(statusText);
            graphics.fill(statusX - 10, actionY + 12, statusX - 7, actionY + 15, color);
            graphics.drawString(font, statusText, statusX, actionY + 9, color, false);
        }
    }

    @Override
    public boolean mouseClicked(double mouseX, double mouseY, int button) {
        if (button != 0) return super.mouseClicked(mouseX, mouseY, button);
        int panelWidth = Math.min(PANEL_WIDTH, width - 24);
        int panelHeight = Math.min(PANEL_HEIGHT, height - 24);
        int left = (width - panelWidth) / 2;
        int top = (height - panelHeight) / 2;
        int cardLeft = left + 18;
        int cardWidth = panelWidth - 36;
        int firstCard = top + 69;

        if (inside(mouseX, mouseY, cardLeft, firstCard, cardWidth, CARD_HEIGHT)) {
            classDefense = classDefense.equals("mixin") ? "all" : "mixin";
            clearStatus();
            return true;
        }
        if (inside(mouseX, mouseY, cardLeft, firstCard + 50, cardWidth, CARD_HEIGHT)) {
            jvmtiDisable = !jvmtiDisable;
            clearStatus();
            return true;
        }

        int actionY = top + panelHeight - 40;
        if (inside(mouseX, mouseY, left + 18, actionY, 116, 26)) {
            save();
            return true;
        }
        if (inside(mouseX, mouseY, left + 142, actionY, 80, 26)) {
            onClose();
            return true;
        }
        return super.mouseClicked(mouseX, mouseY, button);
    }

    private void optionCard(
        GuiGraphics graphics,
        int mouseX,
        int mouseY,
        int x,
        int y,
        int cardWidth,
        String icon,
        Component label,
        Component description,
        Component value,
        boolean enabled
    ) {
        boolean hovered = inside(mouseX, mouseY, x, y, cardWidth, CARD_HEIGHT);
        rounded(graphics, x, y, cardWidth, CARD_HEIGHT, 8, hovered ? 0xFF29404C : 0xFF24343E);
        rounded(graphics, x + 1, y + 1, cardWidth - 2, CARD_HEIGHT - 2, 7, hovered ? 0xFF1A2B35 : 0xFF172630);
        if (hovered) graphics.fill(x, y + 9, x + 2, y + CARD_HEIGHT - 9, ACCENT);

        rounded(graphics, x + 9, y + 7, 30, 30, 8, enabled ? 0xFF173B38 : 0xFF25333D);
        graphics.drawCenteredString(font, Component.literal(icon), x + 24, y + 18, enabled ? ACCENT : 0xFFB2BEC7);
        graphics.drawString(font, label, x + 49, y + (cardWidth >= 340 ? 8 : 18), TEXT, false);
        if (cardWidth >= 340) {
            graphics.drawString(font, description, x + 49, y + 25, MUTED, false);
        }

        int valueWidth = Math.max(58, font.width(value) + 26);
        int valueX = x + cardWidth - valueWidth - 11;
        int valueColor = enabled ? 0xFF173B38 : 0xFF29363F;
        rounded(graphics, valueX, y + 11, valueWidth, 22, 11, valueColor);
        graphics.drawCenteredString(font, value, valueX + valueWidth / 2, y + 18, enabled ? ACCENT : 0xFFB2BEC7);
    }

    private void drawAction(
        GuiGraphics graphics, int mouseX, int mouseY, int x, int y, int actionWidth, int actionHeight,
        boolean primary, Component label
    ) {
        boolean hovered = inside(mouseX, mouseY, x, y, actionWidth, actionHeight);
        int color = primary
            ? hovered ? 0xFF8AF0DF : ACCENT
            : hovered ? 0xFF30414D : 0xFF24323C;
        rounded(graphics, x, y, actionWidth, actionHeight, 6, color);
        graphics.drawCenteredString(font, label, x + actionWidth / 2, y + 9, primary ? 0xFF09201E : TEXT);
    }

    private void save() {
        try {
            new SecretConfig(classDefense, jvmtiDisable).save(FMLPaths.GAMEDIR.get());
            status = Component.translatable("screen.secret.config.saved");
            statusColor = ACCENT;
        } catch (IOException exception) {
            status = Component.translatable("screen.secret.config.save_failed");
            statusColor = 0xFFFF7E8A;
        }
    }

    private void clearStatus() {
        status = Component.empty();
        statusColor = MUTED;
    }

    @Override
    public void onClose() {
        if (minecraft != null) minecraft.setScreen(parent);
    }

    private void renderBackdrop(GuiGraphics graphics) {
        graphics.fillGradient(0, 0, width, height, 0xFF071018, 0xFF122631);
        graphics.fillGradient(0, 0, width, Math.max(1, height / 2), 0x40225B66, 0x00121E27);
        for (int y = 12; y < height; y += 24) {
            for (int x = (y / 24 % 2) * 12; x < width; x += 24) {
                graphics.fill(x, y, x + 1, y + 1, 0x20B8FFF3);
            }
        }
    }

    private static boolean inside(double mouseX, double mouseY, int x, int y, int areaWidth, int areaHeight) {
        return mouseX >= x && mouseX < x + areaWidth && mouseY >= y && mouseY < y + areaHeight;
    }

    private static void shadow(GuiGraphics graphics, int x, int y, int panelWidth, int panelHeight) {
        rounded(graphics, x - 7, y + 9, panelWidth + 14, panelHeight + 8, 15, 0x30000000);
        rounded(graphics, x - 3, y + 5, panelWidth + 6, panelHeight + 4, 13, 0x60000000);
    }

    private static void rounded(
        GuiGraphics graphics, int x, int y, int areaWidth, int areaHeight, int radius, int color
    ) {
        int safeRadius = Math.min(radius, Math.min(areaWidth, areaHeight) / 2);
        graphics.fill(x + safeRadius, y, x + areaWidth - safeRadius, y + areaHeight, color);
        graphics.fill(x, y + safeRadius, x + areaWidth, y + areaHeight - safeRadius, color);
        for (int row = 0; row < safeRadius; row++) {
            double dy = safeRadius - row - 0.5D;
            int inset = (int)Math.ceil(safeRadius - Math.sqrt(safeRadius * safeRadius - dy * dy));
            graphics.fill(x + inset, y + row, x + areaWidth - inset, y + row + 1, color);
            graphics.fill(
                x + inset, y + areaHeight - row - 1, x + areaWidth - inset, y + areaHeight - row, color
            );
        }
    }
}
