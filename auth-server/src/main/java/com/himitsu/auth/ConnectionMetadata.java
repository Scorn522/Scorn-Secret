package com.himitsu.auth;

import io.netty.util.AttributeKey;

record ConnectionMetadata(
    String userAgent,
    String forwardedFor,
    String host,
    String forwardedPort
) {
    static final AttributeKey<ConnectionMetadata> KEY =
        AttributeKey.valueOf("secret-connection-metadata");
}
