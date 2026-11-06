package com.himitsu.secret.client.avatar;

import java.util.concurrent.ThreadLocalRandom;
import net.minecraft.util.Mth;

public final class SecretAvatar {
    private double x;
    private double y;
    private double z;
    private double previousX;
    private double previousY;
    private double previousZ;
    private double targetX;
    private double targetZ;
    private float bodyYaw;
    private float previousBodyYaw;
    private float headYaw;
    private float previousHeadYaw;
    private float headPitch;
    private float limbSwingAmount;
    private float age;
    private double decisionTime;
    private long lastUpdateNanos;

    SecretAvatar(double x, double y, double z) {
        this.x = this.previousX = this.targetX = x;
        this.y = this.previousY = y;
        this.z = this.previousZ = this.targetZ = z;
        chooseTarget();
    }

    void update() {
        long now = System.nanoTime();
        if (lastUpdateNanos == 0L) {
            lastUpdateNanos = now;
            return;
        }
        double delta = Math.min((now - lastUpdateNanos) / 1_000_000_000.0D, 0.05D);
        lastUpdateNanos = now;
        previousX = x;
        previousY = y;
        previousZ = z;
        previousBodyYaw = bodyYaw;
        previousHeadYaw = headYaw;
        decisionTime -= delta;

        double dx = targetX - x;
        double dz = targetZ - z;
        double distance = Math.sqrt(dx * dx + dz * dz);
        if (decisionTime <= 0.0D || distance < 0.25D) chooseTarget();
        if (distance > 0.001D) {
            double speed = Math.min(1.2D * delta, distance);
            x += dx / distance * speed;
            z += dz / distance * speed;
            float desiredYaw = (float) (Mth.atan2(-dx, dz) * 57.29577951308232D);
            bodyYaw = Mth.rotLerp((float) Math.min(1.0D, delta * 5.0D), bodyYaw, desiredYaw);
        }
        headYaw = bodyYaw + Mth.sin(age * 0.035F) * 18.0F;
        headPitch = Mth.sin(age * 0.027F) * 5.0F;
        float movement = (float) Math.sqrt((x - previousX) * (x - previousX) + (z - previousZ) * (z - previousZ));
        float targetSwing = Math.min(1.0F, movement * 26.0F);
        limbSwingAmount += (targetSwing - limbSwingAmount) * 0.58F;
        age += (float) (delta * 20.0D);
    }

    void apply(SecretAvatarProxy proxy, float partialTick, long gameTick) {
        double renderY = y + Mth.sin(age * 0.08F) * 0.025F;
        proxy.applyAvatarState(x, renderY, z, bodyYaw, headYaw, headPitch, limbSwingAmount, gameTick);
    }

    double x() { return x; }
    double y() { return y; }
    double z() { return z; }

    private void chooseTarget() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        double angle = random.nextDouble(Math.PI * 2.0D);
        double distance = random.nextDouble(2.0D, 9.0D);
        targetX = x + Math.cos(angle) * distance;
        targetZ = z + Math.sin(angle) * distance;
        decisionTime = random.nextDouble(2.0D, 6.0D);
    }
}
