package com.himitsu.auth;

import io.netty.util.AttributeKey;

record SessionState(
    String sessionId,
    String serverNonce,
    String clientNonce,
    String username,
    String buildId,
    String hwid,
    String publicKey,
    ReleaseSnapshot release,
    long issuedAt,
    long expiresAt
) {
    static final AttributeKey<SessionState> KEY = AttributeKey.valueOf("secret-auth-session");
}
