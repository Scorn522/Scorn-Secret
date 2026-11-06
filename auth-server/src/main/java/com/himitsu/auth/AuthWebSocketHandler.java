package com.himitsu.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.handler.ssl.SslHandler;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.net.ssl.SSLSession;

@ChannelHandler.Sharable
final class AuthWebSocketHandler extends SimpleChannelInboundHandler<WebSocketFrame> {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final AuthDatabase database;
    private final AttemptLimiter limiter;
    private final ServerConfig config;
    private final ReleaseCatalog releases;
    private final PrivateKey ticketKey;
    private final String certificateSha256;
    private final String certificateSubject;
    private final String certificateIssuer;
    private final String certificateSerial;

    AuthWebSocketHandler(
        AuthDatabase database,
        AttemptLimiter limiter,
        ServerConfig config,
        ReleaseCatalog releases,
        PrivateKey ticketKey,
        X509Certificate certificate
    ) throws Exception {
        this.database = database;
        this.limiter = limiter;
        this.config = config;
        this.releases = releases;
        this.ticketKey = ticketKey;
        this.certificateSha256 = CryptoSupport.sha256Hex(certificate.getEncoded());
        this.certificateSubject = certificate.getSubjectX500Principal().getName();
        this.certificateIssuer = certificate.getIssuerX500Principal().getName();
        this.certificateSerial = certificate.getSerialNumber().toString(16).toUpperCase(java.util.Locale.ROOT);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext context, WebSocketFrame frame) throws Exception {
        if (frame instanceof CloseWebSocketFrame close) {
            context.close();
            return;
        }
        if (!(frame instanceof TextWebSocketFrame text)) {
            sendError(context, "invalid_message", "Text frames are required");
            return;
        }
        if (text.text().length() > 32_768) {
            sendError(context, "message_too_large", "Message exceeds limit");
            return;
        }
        JsonNode message;
        try {
            message = JSON.readTree(text.text());
        } catch (Exception exception) {
            sendError(context, "invalid_json", "Malformed request");
            return;
        }
        String type = required(message, "type", 32);
        if ("hello".equals(type)) {
            handleHello(context, message);
        } else if ("authenticate".equals(type)) {
            handleAuthenticate(context, message);
        } else {
            sendError(context, "invalid_type", "Unsupported message type");
        }
    }

    private void handleHello(ChannelHandlerContext context, JsonNode message) throws Exception {
        if (context.channel().attr(SessionState.KEY).get() != null) {
            sendError(context, "invalid_state", "Challenge already issued");
            return;
        }
        int protocol = message.path("protocol").asInt(-1);
        String username = required(message, "username", 128);
        String buildId = required(message, "build_id", 64);
        String hwid = required(message, "hwid", 128);
        String publicKey = required(message, "device_public_key", 256);
        String clientNonce = required(message, "client_nonce", 128);
        if (protocol != 1) {
            auditLogin(context, provisional(username, buildId, hwid, publicKey),
                "hello", false, false, "unsupported_protocol", "Client protocol is not accepted", null);
            sendError(context, "unsupported_protocol", "Client protocol is not accepted");
            return;
        }
        ReleaseSnapshot release = releases.current();
        if (!CryptoSupport.constantEquals(buildId, release.buildId())) {
            auditLogin(context, provisional(username, buildId, hwid, publicKey),
                "hello", false, false, "unsupported_build", "请更新新版！", null);
            sendError(context, "unsupported_build", "请更新新版！");
            return;
        }
        if (!hwid.matches("[0-9a-f]{64}")) {
            auditLogin(context, provisional(username, buildId, hwid, publicKey),
                "hello", false, false, "invalid_hwid", "Invalid device fingerprint", null);
            sendError(context, "invalid_hwid", "Invalid device fingerprint");
            return;
        }
        try {
            CryptoSupport.importCngP256PublicKey(publicKey);
        } catch (Exception exception) {
            auditLogin(context, provisional(username, buildId, hwid, publicKey),
                "hello", false, false, "invalid_device_key", "Invalid device public key", null);
            sendError(context, "invalid_device_key", "Invalid device public key");
            return;
        }
        String sessionId = CryptoSupport.randomToken(24);
        String serverNonce = CryptoSupport.randomToken(32);
        long issuedAt = System.currentTimeMillis();
        SessionState session = new SessionState(
            sessionId,
            serverNonce,
            clientNonce,
            username,
            buildId,
            hwid,
            publicKey,
            release,
            issuedAt,
            issuedAt + 30_000L
        );
        context.channel().attr(SessionState.KEY).set(session);
        ObjectNode response = JSON.createObjectNode();
        response.put("type", "challenge");
        response.put("session_id", sessionId);
        response.put("server_nonce", serverNonce);
        response.put("expires_in_ms", 30_000);
        context.writeAndFlush(new TextWebSocketFrame(response.toString()));
    }

    private void handleAuthenticate(ChannelHandlerContext context, JsonNode message) throws Exception {
        SessionState session = context.channel().attr(SessionState.KEY).getAndSet(null);
        if (session == null || session.expiresAt() < System.currentTimeMillis()) {
            auditLogin(context, session, "unknown", false, false,
                "challenge_expired", "Challenge expired", null);
            sendError(context, "challenge_expired", "Challenge expired");
            return;
        }
        String sessionId = required(message, "session_id", 128);
        String mode = required(message, "mode", 16);
        String credential = required(message, "credential", 4096);
        String signature = required(message, "device_signature", 256);
        boolean remember = message.path("remember").asBoolean(false);
        if (!session.sessionId().equals(sessionId)) {
            auditLogin(context, session, mode, remember, false,
                "invalid_session", "Session mismatch", null);
            sendError(context, "invalid_session", "Session mismatch");
            return;
        }
        String signedMessage = session.sessionId() + "\n"
            + session.serverNonce() + "\n"
            + session.clientNonce() + "\n"
            + session.hwid() + "\n"
            + session.buildId();
        if (!CryptoSupport.verifyDeviceSignature(session.publicKey(), signedMessage, signature)) {
            auditLogin(context, session, mode, remember, false,
                "invalid_device_signature", "Device proof failed", null);
            sendError(context, "invalid_device_signature", "Device proof failed");
            return;
        }

        String remote = clientAddress(context);
        String limiterKey = remote + "|" + session.username().toLowerCase(java.util.Locale.ROOT);
        if (!limiter.allow(limiterKey)) {
            auditLogin(context, session, mode, remember, false,
                "rate_limited", "Too many attempts; retry later", null);
            sendError(context, "rate_limited", "Too many attempts; retry later");
            return;
        }

        AuthDatabase.LoginResult login;
        if ("password".equals(mode)) {
            char[] password = credential.toCharArray();
            try {
                login = database.passwordLogin(
                    session.username(),
                    password,
                    session.hwid(),
                    session.publicKey(),
                    remote
                );
            } finally {
                java.util.Arrays.fill(password, '\0');
            }
        } else if ("refresh".equals(mode)) {
            login = database.refreshLogin(
                session.username(),
                credential,
                session.hwid(),
                session.publicKey(),
                remote
            );
        } else {
            auditLogin(context, session, mode, remember, false,
                "invalid_mode", "Unsupported authentication mode", null);
            sendError(context, "invalid_mode", "Unsupported authentication mode");
            return;
        }

        if (!login.success()) {
            auditLogin(context, session, mode, remember, false,
                login.code(), login.message(), null);
            sendError(context, login.code(), login.message());
            return;
        }
        limiter.success(limiterKey);
        String refreshToken = remember
            ? database.issueRefreshToken(login.account(), session.hwid())
            : "";
        auditLogin(context, session, mode, remember, true,
            "ok", "Authentication approved", login.account().id());
        sendSuccess(context, session, login.account(), refreshToken);
    }

    private void sendSuccess(
        ChannelHandlerContext context,
        SessionState session,
        AuthDatabase.Account account,
        String refreshToken
    ) throws Exception {
        long issuedAt = Instant.now().getEpochSecond();
        Map<String, Object> ticket = new LinkedHashMap<>();
        ticket.put("protocol", 1);
        ticket.put("account_id", account.id());
        ticket.put("username", account.username());
        ticket.put("device_id", CryptoSupport.sha256Hex(account.devicePublicKey().getBytes(StandardCharsets.UTF_8)));
        ticket.put("hwid", session.hwid());
        ticket.put("issued_at", issuedAt);
        ticket.put("expires_at", issuedAt + config.ticketLifetimeSeconds());
        ticket.put("session_id", session.sessionId());
        ticket.put("client_nonce", session.clientNonce());
        ticket.put("server_nonce", session.serverNonce());
        ticket.put("build_id", session.buildId());
        byte[] payload = JSON.writeValueAsBytes(ticket);
        byte[] signature = CryptoSupport.sign(ticketKey, payload);

        ObjectNode response = JSON.createObjectNode();
        response.put("type", "auth_result");
        response.put("ok", true);
        response.put("ticket", Base64.getEncoder().encodeToString(payload));
        response.put("ticket_signature", Base64.getEncoder().encodeToString(signature));
        response.put("refresh_token", refreshToken);

        deliverCapabilityPayload(account, session, response);

        context.writeAndFlush(new TextWebSocketFrame(response.toString()));
    }

    private void deliverCapabilityPayload(
        AuthDatabase.Account account,
        SessionState session,
        ObjectNode response
    ) throws Exception {
        String tier = account.tier().toLowerCase(java.util.Locale.ROOT);
        if (!tier.matches("[a-z0-9_-]{1,32}")) {
            throw new IllegalStateException("Invalid account payload tier");
        }
        byte[] encryptedPayload = session.release().payload(tier);
        if (encryptedPayload == null) {
            throw new IllegalStateException("Account capability payload is unavailable");
        }

        long now = Instant.now().getEpochSecond();
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("protocol", 1);
        manifest.put("tier", tier);
        manifest.put("account_id", account.id());
        manifest.put("device_id", CryptoSupport.sha256Hex(
            account.devicePublicKey().getBytes(StandardCharsets.UTF_8)));
        manifest.put("hwid", session.hwid());
        manifest.put("session_id", session.sessionId());
        manifest.put("feature_mask", account.featureMask());
        manifest.put("payload_sha256", CryptoSupport.sha256Hex(encryptedPayload));
        manifest.put("payload_key", config.payloadMasterKey());
        manifest.put("issued_at", now);
        manifest.put("expires_at", now + config.payloadLifetimeHours() * 3600);

        byte[] manifestBytes = JSON.writeValueAsBytes(manifest);
        byte[] manifestSig = CryptoSupport.sign(ticketKey, manifestBytes);

        response.put("payload", Base64.getEncoder().encodeToString(encryptedPayload));
        response.put("manifest", Base64.getEncoder().encodeToString(manifestBytes));
        response.put("manifest_sig", Base64.getEncoder().encodeToString(manifestSig));
    }

    private static void sendError(ChannelHandlerContext context, String code, String message) {
        ObjectNode response = JSON.createObjectNode();
        response.put("type", "auth_result");
        response.put("ok", false);
        response.put("code", code);
        response.put("message", message);
        context.writeAndFlush(new TextWebSocketFrame(response.toString()));
    }

    private static String required(JsonNode node, String name, int maxLength) {
        JsonNode value = node.get(name);
        if (value == null || !value.isTextual() || value.textValue().isEmpty()
            || value.textValue().length() > maxLength) {
            throw new IllegalArgumentException("Invalid field: " + name);
        }
        return value.textValue();
    }

    private static String remoteAddress(ChannelHandlerContext context) {
        if (context.channel().remoteAddress() instanceof InetSocketAddress address) {
            return address.getAddress().getHostAddress();
        }
        return String.valueOf(context.channel().remoteAddress());
    }

    private static int remotePort(ChannelHandlerContext context) {
        return context.channel().remoteAddress() instanceof InetSocketAddress address
            ? address.getPort() : 0;
    }

    private String clientAddress(ChannelHandlerContext context) {
        String direct = remoteAddress(context);
        if (!config.trustProxyHeaders() || !isLoopback(context)) return direct;
        ConnectionMetadata metadata = context.channel().attr(ConnectionMetadata.KEY).get();
        if (metadata == null || metadata.forwardedFor() == null) return direct;
        String first = metadata.forwardedFor().split(",", 2)[0].trim();
        return first.isEmpty() || first.length() > 64 ? direct : first;
    }

    private int clientPort(ChannelHandlerContext context) {
        int direct = remotePort(context);
        if (!config.trustProxyHeaders() || !isLoopback(context)) return direct;
        ConnectionMetadata metadata = context.channel().attr(ConnectionMetadata.KEY).get();
        if (metadata == null || metadata.forwardedPort() == null) return direct;
        try {
            int value = Integer.parseInt(metadata.forwardedPort());
            return value >= 1 && value <= 65_535 ? value : direct;
        } catch (NumberFormatException ignored) {
            return direct;
        }
    }

    private static boolean isLoopback(ChannelHandlerContext context) {
        return context.channel().remoteAddress() instanceof InetSocketAddress address
            && address.getAddress() != null
            && address.getAddress().isLoopbackAddress();
    }

    private SessionState provisional(
        String username,
        String buildId,
        String hwid,
        String publicKey
    ) {
        long now = System.currentTimeMillis();
        return new SessionState("", "", "", username, buildId, hwid, publicKey, null, now, now);
    }

    private void auditLogin(
        ChannelHandlerContext context,
        SessionState session,
        String mode,
        boolean remember,
        boolean success,
        String code,
        String message,
        Long accountId
    ) {
        try {
            ConnectionMetadata metadata = context.channel().attr(ConnectionMetadata.KEY).get();
            if (metadata == null) metadata = new ConnectionMetadata("", "", "", "");
            SslHandler sslHandler = context.pipeline().get(SslHandler.class);
            SSLSession sslSession = sslHandler == null ? null : sslHandler.engine().getSession();
            String publicKey = session == null ? "" : session.publicKey();
            String deviceId = publicKey.isEmpty() ? "" : CryptoSupport.sha256Hex(
                publicKey.getBytes(StandardCharsets.UTF_8)
            );
            long issuedAt = session == null ? System.currentTimeMillis() : session.issuedAt();
            database.recordLoginAudit(new AuthDatabase.LoginAuditEvent(
                accountId,
                session == null ? "" : session.username(),
                success,
                code,
                message,
                mode,
                clientAddress(context),
                clientPort(context),
                metadata.forwardedFor(),
                metadata.userAgent(),
                metadata.host(),
                session == null ? "" : session.buildId(),
                session == null ? "" : session.hwid(),
                deviceId,
                publicKey,
                sslSession == null ? "" : sslSession.getProtocol(),
                sslSession == null ? "" : sslSession.getCipherSuite(),
                certificateSha256,
                certificateSubject,
                certificateIssuer,
                certificateSerial,
                session == null ? "" : session.sessionId(),
                remember,
                Math.max(0L, System.currentTimeMillis() - issuedAt)
            ));
        } catch (Exception ignored) {

        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext context) throws Exception {
        SessionState pending = context.channel().attr(SessionState.KEY).getAndSet(null);
        if (pending != null) {
            auditLogin(context, pending, "unknown", false, false,
                "connection_closed", "Connection closed before authentication", null);
        }
        super.channelInactive(context);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
        if (context.channel().isActive()) sendError(context, "server_error", "Request failed");
    }
}
