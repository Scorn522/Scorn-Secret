package com.himitsu.secret;

import com.himitsu.secret.code.BootstrapPayload;
import java.io.File;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.jar.JarFile;
import com.himitsu.secret.bridge.SecretNative;
import net.minecraftforge.eventbus.api.IEventBus;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.fml.loading.FMLPaths;

@Mod(SecretMod.MODID)
public class SecretMod {
    public static final String MODID = "secret";

    public static AbstractMap.SimpleEntry<String, JarFile> MODFILE;

    static {
        try {
            SecretNative.bootstrap(FMLPaths.GAMEDIR.get().toAbsolutePath());
        } catch (Throwable throwable) {
            throwUnchecked(throwable);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T extends Throwable> void throwUnchecked(Throwable throwable) throws T {
        throw (T) throwable;
    }

    public SecretMod() {
        System.out.println("Secret start");

        IEventBus modBus = FMLJavaModLoadingContext.get().getModEventBus();

        try {
            File source = BootstrapPayload.locateSource(URLDecoder.decode(
                SecretMod.class.getProtectionDomain().getCodeSource().getLocation().getPath(),
                StandardCharsets.UTF_8
            ));

            JarFile jarFile = source.isFile() && source.getName().endsWith(".jar")
                ? new JarFile(source)
                : null;
            MODFILE = new AbstractMap.SimpleEntry<>(source.getAbsolutePath(), jarFile);

            BootstrapPayload.boot(
                modBus,
                FMLPaths.GAMEDIR.get().toAbsolutePath(),
                source.toPath().toAbsolutePath()
            );
        } catch (Throwable throwable) {
            throwUnchecked(throwable);
        }
    }

}
