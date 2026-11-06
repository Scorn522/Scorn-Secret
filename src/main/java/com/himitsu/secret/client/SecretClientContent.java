package com.himitsu.secret.client;

import com.himitsu.secret.client.render.SecretEntityRenderer;
import com.himitsu.secret.content.SecretContent;
import net.minecraftforge.client.event.EntityRenderersEvent;

public final class SecretClientContent {
    private SecretClientContent() {
    }

    public static void registerRenderers(EntityRenderersEvent.RegisterRenderers event) {
        event.registerEntityRenderer(SecretContent.SECRET_ENTITY.get(), SecretEntityRenderer::new);
    }

}
