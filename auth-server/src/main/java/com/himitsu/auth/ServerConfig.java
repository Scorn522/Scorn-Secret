package com.himitsu.auth;

import java.nio.file.Path;

record ServerConfig(
    String host,
    int port,
    Path database,
    Path keyStore,
    char[] keyStorePassword,
    String buildId,
    int ticketLifetimeSeconds,
    int refreshLifetimeDays,
    String adminUsername,
    String adminPassword,
    int adminSessionMinutes,
    String dataEncryptionKey,
    boolean adminLoopbackOnly,
    boolean trustProxyHeaders,
    Path payloadDirectory,
    Path releaseFile,
    String payloadMasterKey,
    long payloadLifetimeHours
) {
    static ServerConfig load() {
        return new ServerConfig(
            env("SECRET_AUTH_HOST", "127.0.0.1"),
            Integer.parseInt(env("SECRET_AUTH_PORT", "8443")),
            Path.of(env("SECRET_AUTH_DB", "data/auth.db")).toAbsolutePath(),
            Path.of(env("SECRET_AUTH_KEYSTORE", "config/dev-server.p12")).toAbsolutePath(),
            env("SECRET_AUTH_KEYSTORE_PASSWORD", "changeit").toCharArray(),
            env("SECRET_AUTH_BUILD_ID", "Secret-4.3"),
            Integer.parseInt(env("SECRET_AUTH_TICKET_SECONDS", "600")),
            Integer.parseInt(env("SECRET_AUTH_REFRESH_DAYS", "30")),
            env("SECRET_AUTH_ADMIN_USER", "admin"),
            env("SECRET_AUTH_ADMIN_PASSWORD", ""),
            Integer.parseInt(env("SECRET_AUTH_ADMIN_SESSION_MINUTES", "720")),
            required("SECRET_AUTH_DATA_KEY"),
            Boolean.parseBoolean(env("SECRET_AUTH_ADMIN_LOOPBACK_ONLY", "false")),
            Boolean.parseBoolean(env("SECRET_AUTH_TRUST_PROXY_HEADERS", "false")),
            Path.of(env("SECRET_AUTH_PAYLOAD_DIR", "/var/lib/secret-auth/data/payloads")).toAbsolutePath(),
            Path.of(env("SECRET_AUTH_RELEASE_FILE", "/etc/secret-auth/client-release.json")).toAbsolutePath(),
            payloadKey(env("SECRET_AUTH_PAYLOAD_MASTER_KEY", "")),
            payloadLifetime(env("SECRET_AUTH_PAYLOAD_LIFETIME_HOURS", "6"))
        );
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must be set");
        }
        return value.trim();
    }

    private static String payloadKey(String value) {
        try {
            if (java.util.Base64.getDecoder().decode(value).length != 32) {
                throw new IllegalArgumentException();
            }
            return value;
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(
                "SECRET_AUTH_PAYLOAD_MASTER_KEY must be Base64 for exactly 32 bytes"
            );
        }
    }

    private static long payloadLifetime(String value) {
        long hours = Long.parseLong(value);
        if (hours < 1 || hours > 24) {
            throw new IllegalStateException(
                "SECRET_AUTH_PAYLOAD_LIFETIME_HOURS must be between 1 and 24"
            );
        }
        return hours;
    }
}
