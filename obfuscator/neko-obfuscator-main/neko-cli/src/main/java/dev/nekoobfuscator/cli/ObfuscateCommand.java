package dev.nekoobfuscator.cli;

import dev.nekoobfuscator.api.config.ObfuscationConfig;
import dev.nekoobfuscator.config.ConfigParser;
import dev.nekoobfuscator.config.ConfigValidator;
import dev.nekoobfuscator.core.pipeline.ObfuscationPipeline;
import dev.nekoobfuscator.core.pipeline.PassRegistry;
import dev.nekoobfuscator.transforms.jvm.StandardJvmPasses;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.List;

@CommandLine.Command(
    name = "obfuscate",
    description = "Obfuscate a JAR file"
)
public final class ObfuscateCommand implements Callable<Integer> {

    @CommandLine.Option(names = {"-c", "--config"}, description = "Config YAML file", required = true)
    private Path configFile;

    @CommandLine.Option(names = {"-i", "--input"}, description = "Input JAR (overrides config)")
    private Path inputJar;

    @CommandLine.Option(names = {"-o", "--output"}, description = "Output JAR (overrides config)")
    private Path outputJar;

    @CommandLine.Option(names = {"-v", "--verbose"}, description = "Verbose logging")
    private boolean verbose;

    @Override
    public Integer call() {
        try {
            System.out.println("[NekoObfuscator] Starting...");
            long startTime = System.currentTimeMillis();

            // Parse config
            ConfigParser parser = new ConfigParser();
            ObfuscationConfig config = parser.parse(configFile);

            // Override from CLI args
            if (inputJar != null) config.setInputJar(inputJar);
            if (outputJar != null) config.setOutputJar(outputJar);

            // Validate
            List<String> errors = ConfigValidator.validate(config);
            if (!errors.isEmpty()) {
                System.err.println("[NekoObfuscator] Configuration errors:");
                errors.forEach(e -> System.err.println("  - " + e));
                return 2;
            }

            PassRegistry registry = new PassRegistry();
            StandardJvmPasses.register(registry);

            System.out.println("[NekoObfuscator] Registered " + registry.size() + " transform passes");

            // Run pipeline
            ObfuscationPipeline pipeline = new ObfuscationPipeline(config, registry);
            clearPreviousOutput(config.inputJar(), config.outputJar());
            pipeline.execute(config.inputJar(), config.outputJar());

            long elapsed = System.currentTimeMillis() - startTime;
            System.out.println("[NekoObfuscator] Done in " + elapsed + "ms");
            return 0;

        } catch (Exception e) {
            System.err.println("[NekoObfuscator] Error: " + e.getMessage());
            if (verbose) {
                e.printStackTrace();
            }
            return 1;
        }
    }

    private void clearPreviousOutput(Path input, Path output) throws Exception {
        if (input == null || output == null) return;
        Path absInput = input.toAbsolutePath().normalize();
        Path absOutput = output.toAbsolutePath().normalize();
        if (absInput.equals(absOutput)) {
            throw new IllegalArgumentException("Input and output JAR must be different paths");
        }
        Files.deleteIfExists(absOutput);
        Files.deleteIfExists(absOutput.resolveSibling(absOutput.getFileName() + ".map"));
    }
}
