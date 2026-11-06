package com.himitsu.secret.core;

import com.himitsu.secret.config.SecretConfig;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public final class RuntimeState {
    public enum Phase {
        NEW,
        CONFIGURATION,
        NATIVE_BRIDGE,
        STATE,
        PAYLOAD,
        TRANSFORMER,
        NETWORK,
        BACKGROUND,
        CONTENT,
        READY,
        FAILED,
        STOPPED
    }

    private final AtomicReference<Phase> phase = new AtomicReference<>(Phase.NEW);
    private final AtomicLong backgroundRuns = new AtomicLong();
    private final Instant startedAt = Instant.now();
    private volatile SecretConfig config;
    private volatile Throwable failure;

    public void enter(Phase next) {
        phase.set(Objects.requireNonNull(next, "next"));
    }

    public void initialize(SecretConfig runtimeConfig) {
        config = Objects.requireNonNull(runtimeConfig, "runtimeConfig");
        enter(Phase.STATE);
    }

    public void recordBackgroundRun() {
        backgroundRuns.incrementAndGet();
    }

    public void fail(Throwable throwable) {
        failure = throwable;
        enter(Phase.FAILED);
    }

    public Phase phase() {
        return phase.get();
    }

    public SecretConfig config() {
        return config;
    }

    public long backgroundRuns() {
        return backgroundRuns.get();
    }

    public Instant startedAt() {
        return startedAt;
    }

    public Throwable failure() {
        return failure;
    }
}
