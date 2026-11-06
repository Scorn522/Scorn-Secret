package dev.nekoobfuscator.transforms.jvm.internal;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.jar.ResourceEntry;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ModuleProvideNode;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public final class JvmServiceAbi {
    private static final String SERVICE_PROVIDER_CLASSES = "jvm.serviceProviderClasses";

    private JvmServiceAbi() {
    }

    public static boolean isServiceProviderNoArgConstructor(PipelineContext pctx, L1Class clazz, L1Method method) {
        if (pctx == null || clazz == null || method == null) return false;
        if (!method.isConstructor() || !"()V".equals(method.descriptor())) return false;
        if ((method.access() & Opcodes.ACC_PUBLIC) == 0) return false;
        return serviceProviderClasses(pctx).contains(clazz.name());
    }

    @SuppressWarnings("unchecked")
    private static Set<String> serviceProviderClasses(PipelineContext pctx) {
        Set<String> cached = pctx.getPassData(SERVICE_PROVIDER_CLASSES);
        if (cached != null) return cached;
        Set<String> providers = new LinkedHashSet<>();
        collectServiceResourceProviders(pctx, providers);
        collectModuleProviders(pctx, providers);
        providers.removeIf(provider -> !pctx.classMap().containsKey(provider));
        Set<String> immutable = Set.copyOf(providers);
        pctx.putPassData(SERVICE_PROVIDER_CLASSES, immutable);
        return immutable;
    }

    private static void collectServiceResourceProviders(PipelineContext pctx, Set<String> providers) {
        for (ResourceEntry resource : pctx.resources()) {
            if (!resource.name().startsWith("META-INF/services/")) continue;
            String text = new String(resource.data(), StandardCharsets.UTF_8);
            for (String rawLine : text.split("\\R")) {
                String line = stripServiceComment(rawLine).trim();
                if (line.isEmpty()) continue;
                int whitespace = firstWhitespace(line);
                String providerName = whitespace < 0 ? line : line.substring(0, whitespace);
                if (!providerName.isEmpty()) {
                    addProvider(pctx, providers, providerName.replace('.', '/'));
                }
            }
        }
    }

    private static void collectModuleProviders(PipelineContext pctx, Set<String> providers) {
        for (L1Class clazz : pctx.classMap().values()) {
            if (clazz.asmNode().module == null || clazz.asmNode().module.provides == null) continue;
            for (ModuleProvideNode provide : clazz.asmNode().module.provides) {
                if (provide.providers == null) continue;
                for (String provider : provide.providers) {
                    addProvider(pctx, providers, provider);
                }
            }
        }
    }

    private static void addProvider(PipelineContext pctx, Set<String> providers, String internalName) {
        Map<String, String> renamerClassMap = pctx.getPassData("renamer.classMap");
        String currentName = renamerClassMap == null ? null : renamerClassMap.get(internalName);
        providers.add(currentName == null ? internalName : currentName);
    }

    private static String stripServiceComment(String line) {
        int comment = line.indexOf('#');
        return comment < 0 ? line : line.substring(0, comment);
    }

    private static int firstWhitespace(String line) {
        for (int i = 0; i < line.length(); i++) {
            if (Character.isWhitespace(line.charAt(i))) return i;
        }
        return -1;
    }
}
