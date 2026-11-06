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
        if(!SecretThreadProtection.protect(thread)) {running.set(false);throw new IllegalStateException("Maintenance thread pre-registration failed");}
        thread.start();
        return thread;
    }

    private void commonLoop() {
        if(!SecretThreadProtection.protect(Thread.currentThread())) {running.set(false);return;}
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
        running.set(false);
        interrupt(commonThread);
        if (commonThread != null && commonThread != Thread.currentThread()) {
            try { commonThread.join(1000L); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
        }
        if(commonThread==null || !commonThread.isAlive()) {
            if(commonThread!=null) SecretThreadProtection.unprotect(commonThread);
            state.enter(RuntimeState.Phase.STOPPED);
        } else System.err.println("[Secret/ThreadGuard] Maintenance thread not drained; protection retained for native shutdown");
    }

    private static void interrupt(Thread thread) {
        if (thread != null) {
            thread.interrupt();
        }
    }
}
