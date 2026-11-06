package com.himitsu.secret.client.render;

import net.minecraftforge.client.event.RenderGuiOverlayEvent;
import net.minecraftforge.client.event.RenderLevelStageEvent;

public final class RenderContext {
    public enum Kind {
        LEVEL,
        GUI_OVERLAY
    }

    private final Kind kind;
    private final RenderLevelStageEvent levelEvent;
    private final RenderGuiOverlayEvent guiEvent;

    private RenderContext(Kind kind, RenderLevelStageEvent levelEvent, RenderGuiOverlayEvent guiEvent) {
        this.kind = kind;
        this.levelEvent = levelEvent;
        this.guiEvent = guiEvent;
    }

    public static RenderContext level(RenderLevelStageEvent event) {
        return new RenderContext(Kind.LEVEL, event, null);
    }

    public static RenderContext gui(RenderGuiOverlayEvent event) {
        return new RenderContext(Kind.GUI_OVERLAY, null, event);
    }

    public Kind kind() {
        return kind;
    }

    public RenderLevelStageEvent levelEvent() {
        return levelEvent;
    }

    public RenderGuiOverlayEvent guiEvent() {
        return guiEvent;
    }
}
