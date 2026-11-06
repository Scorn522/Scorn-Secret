package com.himitsu.auth;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

final class AttemptLimiter {
    private record Bucket(long windowStart, int attempts, long blockedUntil) {
    }

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final long windowMillis = Duration.ofMinutes(5).toMillis();
    private final int maxAttempts = 8;

    boolean allow(String key) {
        long now = System.currentTimeMillis();
        Bucket result = buckets.compute(key, (ignored, current) -> {
            if (current == null || now - current.windowStart() > windowMillis) {
                return new Bucket(now, 1, 0);
            }
            if (current.blockedUntil() > now) return current;
            int attempts = current.attempts() + 1;
            long blocked = attempts > maxAttempts
                ? now + Math.min(Duration.ofMinutes(15).toMillis(), (attempts - maxAttempts) * 30_000L)
                : 0;
            return new Bucket(current.windowStart(), attempts, blocked);
        });
        return result.blockedUntil() <= now;
    }

    void success(String key) {
        buckets.remove(key);
    }
}
