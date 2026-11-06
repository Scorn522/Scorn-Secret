package com.himitsu.secret.core;

import java.util.concurrent.atomic.AtomicBoolean;

public final class BackgroundService implements AutoCloseable {
    private final RuntimeState state;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean running = new AtomicBoolean();
    private Thread commonThread;

    public BackgroundService(RuntimeState state) {
        this.state = state;
    }

    public void start() {
        if (!started.compareAndSet(false, true)) {
            return;
        }
        running.set(true);
        commonThread = startProtected("Secret-Common-Maintenance", this::commonLoop);
    }

    private Thread startProtected(String name, Runnable loop) {
        Thread thread = new Thread(loop, name);
        thread.setDaemon(true);
        SecretThreadProtection.protect(thread);
        thread.start();
        return thread;
    }

    private void commonLoop() {
        while (running.get()) {
            try {
                RuntimeMetrics.recordTransformedCycle();
                state.recordBackgroundRun();
                Thread.sleep(10L);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                break;
            } catch (Throwable ignored) {
            }
        }
    }

    @Override
    public void close() {
        if (!running.getAndSet(false)) return;
        SecretThreadProtection.unprotect(commonThread);
        interrupt(commonThread);
        if (commonThread != null && commonThread != Thread.currentThread()) {
            try { commonThread.join(1000L); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
        }
        state.enter(RuntimeState.Phase.STOPPED);
    }

    private static void interrupt(Thread thread) {
        if (thread != null) {
            thread.interrupt();
        }
    }
}
