package com.himitsu.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

final class ReleaseCatalog {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern BUILD_ID = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final Pattern TIER = Pattern.compile("[a-z0-9_-]{1,32}");
    private static final int MAX_RELEASE_BYTES = 64 * 1024;
    private final ServerConfig config;

    ReleaseCatalog(ServerConfig config) {
        this.config = config;
    }

    ReleaseSnapshot current() {
        Path releaseFile = config.releaseFile();
        if (!Files.isRegularFile(releaseFile)) {
            return legacySnapshot();
        }
        try {
            byte[] encoded = Files.readAllBytes(releaseFile);
            if (encoded.length == 0 || encoded.length > MAX_RELEASE_BYTES) {
                throw new IllegalStateException("Client release descriptor has an invalid size");
            }
            JsonNode root = JSON.readTree(encoded);
            if (root.path("protocol").asInt(-1) != 1) {
                throw new IllegalStateException("Client release descriptor protocol is unsupported");
            }
            String buildId = root.path("build_id").asText("");
            if (!BUILD_ID.matcher(buildId).matches()) {
                throw new IllegalStateException("Client release descriptor has an invalid build ID");
            }
            long publishedAt = root.path("published_at").asLong(0L);
            JsonNode payloadsNode = root.path("payloads");
            if (!payloadsNode.isObject() || payloadsNode.isEmpty() || payloadsNode.size() > 32) {
                throw new IllegalStateException("Client release descriptor has invalid payloads");
            }
            Map<String, byte[]> payloads = new HashMap<>();
            Iterator<Map.Entry<String, JsonNode>> fields = payloadsNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String tier = field.getKey().toLowerCase(java.util.Locale.ROOT);
                if (!TIER.matcher(tier).matches() || !field.getValue().isTextual()) {
                    throw new IllegalStateException("Client release descriptor has an invalid tier");
                }
                byte[] payload = Base64.getDecoder().decode(field.getValue().textValue());
                if (payload.length < 28 || payload.length > 8 * 1024) {
                    throw new IllegalStateException("Client release payload has an invalid size");
                }
                payloads.put(tier, payload);
            }
            return new ReleaseSnapshot(buildId, publishedAt, Map.copyOf(payloads));
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Client release descriptor is invalid", exception);
        }
    }

    private ReleaseSnapshot legacySnapshot() {
        Map<String, byte[]> payloads = new HashMap<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(config.payloadDirectory(), "tier_*.dat")) {
            for (Path file : files) {
                String name = file.getFileName().toString();
                String tier = name.substring(5, name.length() - 4).toLowerCase(java.util.Locale.ROOT);
                if (!TIER.matcher(tier).matches()) continue;
                byte[] payload = Files.readAllBytes(file);
                if (payload.length >= 28 && payload.length <= 8 * 1024) payloads.put(tier, payload);
            }
        } catch (Exception exception) {
            throw new IllegalStateException("Legacy client release payload is unavailable", exception);
        }
        if (payloads.isEmpty()) {
            throw new IllegalStateException("Client release descriptor is unavailable");
        }
        return new ReleaseSnapshot(config.buildId(), 0L, Map.copyOf(payloads));
    }
}
