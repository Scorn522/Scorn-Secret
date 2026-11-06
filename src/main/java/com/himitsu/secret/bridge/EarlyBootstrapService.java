package com.himitsu.secret.bridge;

import cpw.mods.modlauncher.api.IEnvironment;
import cpw.mods.modlauncher.api.ITransformationService;
import cpw.mods.modlauncher.api.ITransformer;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** No transforms and no Forge/game class dependencies in the service layer. */
public final class EarlyBootstrapService implements ITransformationService {
    @Override public String name() { return "secret-bootstrap"; }
    @Override public void onLoad(IEnvironment environment, Set<String> services) {}
    @Override public List<ITransformer> transformers() { return List.of(); }
    @Override public void initialize(IEnvironment environment) {
        Path directory = environment.getProperty(IEnvironment.Keys.GAMEDIR.get()).orElse(Path.of("."));
        try {
            SecretNative.loadEarly(directory.toAbsolutePath());
            System.out.println("[Secret/Bootstrap] Service-stage native protection ready");
        } catch (LinkageError unavailableInServiceLayer) {
            System.err.println("[Secret/Bootstrap] Native dependencies unavailable in service layer; mod bootstrap will retry: "
                + unavailableInServiceLayer.getClass().getSimpleName());
        } catch (java.io.IOException failure) {
            throw new IllegalStateException("Secret early protection failed", failure);
        }
    }
}
