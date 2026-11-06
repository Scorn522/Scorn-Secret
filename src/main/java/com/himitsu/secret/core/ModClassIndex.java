package com.himitsu.secret.core;

import com.himitsu.secret.SecretMod;
import java.util.HashSet;
import java.util.Set;
import net.minecraftforge.fml.ModList;
import net.minecraftforge.forgespi.language.IModInfo;
import net.minecraftforge.forgespi.locating.IModFile;

public final class ModClassIndex {
    private static final Set<String> BUILTIN_MODS = Set.of("minecraft", "forge");

    private ModClassIndex() {
    }

    public static Set<String> otherModClasses() {
        return modClasses(false);
    }

    public static Set<String> runtimeModClasses() {
        return modClasses(true);
    }

    private static Set<String> modClasses(boolean includeBuiltin) {
        Set<String> classes = new HashSet<>();
        ModList.get().forEachModFile(file -> {
            if (file.getType() != IModFile.Type.MOD || isSecretMod(file)
                || (!includeBuiltin && !isOtherMod(file))) {
                return;
            }
            file.getScanResult().getClasses().forEach(classData ->
                classes.add(classData.clazz().getClassName())
            );
        });
        return Set.copyOf(classes);
    }

    private static boolean isSecretMod(IModFile file) {
        return file.getModInfos().stream().anyMatch(mod -> SecretMod.MODID.equals(mod.getModId()));
    }

    private static boolean isOtherMod(IModFile file) {
        boolean userMod = false;
        for (IModInfo mod : file.getModInfos()) {
            String modId = mod.getModId();
            if (!BUILTIN_MODS.contains(modId)) {
                userMod = true;
            }
        }
        return userMod;
    }
}
