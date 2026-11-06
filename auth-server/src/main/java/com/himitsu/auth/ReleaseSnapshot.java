package com.himitsu.auth;

import java.util.Map;

record ReleaseSnapshot(String buildId, long publishedAt, Map<String, byte[]> payloads) {
    byte[] payload(String tier) {
        byte[] payload = payloads.get(tier);
        return payload == null ? null : payload.clone();
    }
}
