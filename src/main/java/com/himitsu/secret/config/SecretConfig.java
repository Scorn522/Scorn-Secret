package com.himitsu.secret.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

public record SecretConfig(
    String classDefense,
    boolean jvmtiDisable
) {
    private static final String FILE_NAME = "secret.config";
    private static final String CLASS_DEFENSE = "类防护";
    private static final String JVMTI_DISABLE = "JVMTI禁用";

    public static SecretConfig load(Path gameDirectory) throws IOException {
        Path path = configPath(gameDirectory);
        Files.createDirectories(path.getParent());

        Properties properties = new Properties();
        if (Files.isRegularFile(path)) {
            try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
                properties.load(reader);
            }
        }

        SecretConfig config = new SecretConfig(
            enumValue(properties, CLASS_DEFENSE, "mixin", Set.of("mixin", "all")),
            booleanValue(properties, JVMTI_DISABLE, true)
        );
        config.save(gameDirectory);
        return config;
    }

    public void save(Path gameDirectory) throws IOException {
        Path path = configPath(gameDirectory);
        Files.createDirectories(path.getParent());
        // Preserve startup-only process grants when saving unrelated UI options.
        Properties saved=new Properties();
        if(Files.isRegularFile(path)) try(var reader=Files.newBufferedReader(path,StandardCharsets.UTF_8)) { saved.load(reader); }
        saved.setProperty(CLASS_DEFENSE,classDefense);
        saved.setProperty(JVMTI_DISABLE,Boolean.toString(jvmtiDisable));
        Path temporary=Files.createTempFile(path.getParent(),"secret-", ".tmp");
        try {
            try(var writer=Files.newBufferedWriter(temporary,StandardCharsets.UTF_8)) { saved.store(writer,"Process grants are loaded only at startup; empty allowlist denies child processes."); }
            try(var channel=java.nio.channels.FileChannel.open(temporary,java.nio.file.StandardOpenOption.WRITE)) { channel.force(true); }
            try { Files.move(temporary,path,java.nio.file.StandardCopyOption.ATOMIC_MOVE,java.nio.file.StandardCopyOption.REPLACE_EXISTING); }
            catch(java.nio.file.AtomicMoveNotSupportedException unavailable) { Files.move(temporary,path,java.nio.file.StandardCopyOption.REPLACE_EXISTING); }
        } finally { Files.deleteIfExists(temporary); }
    }

    private static Path configPath(Path gameDirectory) {
        return gameDirectory.resolve("config").resolve(FILE_NAME);
    }

    private String template() {
        return "# 类防护=mixin | all\n"
            + CLASS_DEFENSE + "=" + classDefense + "\n"
            + "# JVMTI禁用=true | false\n"
            + JVMTI_DISABLE + "=" + jvmtiDisable + "\n";
    }

    private static String enumValue(Properties properties, String name, String defaultValue, Set<String> allowed) {
        String value = properties.getProperty(name, defaultValue).trim().toLowerCase(Locale.ROOT);
        if (!allowed.contains(value)) {
            throw new IllegalArgumentException("Invalid configuration " + name + ": " + value);
        }
        return value;
    }

    private static boolean booleanValue(Properties properties, String name, boolean defaultValue) {
        String value = properties.getProperty(name, Boolean.toString(defaultValue)).trim().toLowerCase(Locale.ROOT);
        if (!value.equals("true") && !value.equals("false")) {
            throw new IllegalArgumentException("Invalid configuration " + name + ": " + value);
        }
        return Boolean.parseBoolean(value);
    }

}
