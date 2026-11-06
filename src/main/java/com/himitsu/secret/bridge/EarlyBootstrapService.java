package com.himitsu.secret.bridge;

import cpw.mods.modlauncher.api.IEnvironment;
import cpw.mods.modlauncher.api.ITransformationService;
import cpw.mods.modlauncher.api.ITransformer;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Service-layer native init and explicit Forge registration; no game class dependencies. */
public final class EarlyBootstrapService extends net.minecraftforge.fml.loading.moddiscovery.AbstractJarFileModLocator implements ITransformationService {
    @Override public String name() { return "secret-bootstrap"; }
    @Override public void initArguments(java.util.Map<String,?> arguments) {}
    @Override public java.util.stream.Stream<Path> scanCandidates() {
        // Forge excludes transformation-service jars from its ordinary mods-folder locator.
        String location=java.net.URLDecoder.decode(getClass().getProtectionDomain().getCodeSource()
            .getLocation().getPath(),java.nio.charset.StandardCharsets.UTF_8);
        int end=location.toLowerCase(java.util.Locale.ROOT).lastIndexOf(".jar");
        if(end<0) throw new IllegalStateException("Secret locator requires its packaged JAR");
        location=location.substring(0,end+4);
        if(location.matches("^/[A-Za-z]:/.*")) location=location.substring(1);
        Path archive=Path.of(location).toAbsolutePath().normalize();
        if(!java.nio.file.Files.isRegularFile(archive)) throw new IllegalStateException("Secret archive missing: "+archive);
        return java.util.stream.Stream.of(archive);
    }
    @Override public void onLoad(IEnvironment environment, Set<String> services) {}
    @Override public List<ITransformer> transformers() { return List.of(); }
    @Override public void initialize(IEnvironment environment) {
        Path directory = environment.getProperty(IEnvironment.Keys.GAMEDIR.get()).orElse(Path.of("."));
        try {
            // PCL may keep LWJGL on the class path instead of a named boot module.
            getClass().getModule().addReads(Class.forName("org.lwjgl.system.Library",false,getClass().getClassLoader()).getModule());
            SecretNative.loadEarly(directory.toAbsolutePath());
            System.out.println("[Secret/Bootstrap] Service-stage native protection ready");
        } catch (LinkageError | ClassNotFoundException unavailableInServiceLayer) {
            System.err.println("[Secret/Bootstrap] Native dependencies unavailable in service layer; mod bootstrap will retry: "
                + unavailableInServiceLayer.getClass().getSimpleName());
        } catch (java.io.IOException failure) {
            throw new IllegalStateException("Secret early protection failed", failure);
        }
    }
}
