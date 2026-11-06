package com.himitsu.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import io.netty.util.CharsetUtil;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ChannelHandler.Sharable
final class PortalHttpHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    private record AdminSession(String csrfToken, long expiresAt) {
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_]{3,32}");
    private static final Pattern ACCOUNT_ACTION = Pattern.compile(
        "^/api/admin/accounts/(\\d+)/(ban|unban|reset-device|delete)$"
    );
    private static final Pattern CARD_ACTION = Pattern.compile(
        "^/api/admin/cards/(\\d+)/(revoke|delete)$"
    );
    private static final String SESSION_COOKIE = "secret_admin_session";

    private final AuthDatabase database;
    private final ServerConfig config;
    private final ReleaseCatalog releases;
    private final AttemptLimiter registrationLimiter = new AttemptLimiter();
    private final AttemptLimiter adminLoginLimiter = new AttemptLimiter();
    private final Map<String, AdminSession> sessions = new ConcurrentHashMap<>();
    private final byte[] registrationPage;
    private final byte[] adminPage;

    PortalHttpHandler(AuthDatabase database, ServerConfig config, ReleaseCatalog releases) throws Exception {
        this.database = database;
        this.config = config;
        this.releases = releases;
        this.registrationPage = resource("/web/register.html");
        this.adminPage = resource("/web/admin.html");
    }

    @Override
    protected void channelRead0(ChannelHandlerContext context, FullHttpRequest request) {
        String path = new QueryStringDecoder(request.uri()).path();
        if ("/auth".equals(path)) {
            context.channel().attr(ConnectionMetadata.KEY).set(new ConnectionMetadata(
                header(request, HttpHeaderNames.USER_AGENT.toString()),
                header(request, "X-Forwarded-For"),
                header(request, HttpHeaderNames.HOST.toString()),
                header(request, "X-Forwarded-Port")
            ));
            context.fireChannelRead(request.retain());
            return;
        }
        if (isAdminPath(path) && config.adminLoopbackOnly() && !isLoopback(context)) {
            sendJson(context, request, HttpResponseStatus.NOT_FOUND,
                error("not_found", "页面或接口不存在"));
            return;
        }

        try {
            route(context, request, path);
        } catch (IllegalArgumentException exception) {
            sendJson(context, request, HttpResponseStatus.BAD_REQUEST,
                error("invalid_request", exception.getMessage()));
        } catch (Exception exception) {
            sendJson(context, request, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                error("server_error", "请求处理失败，请稍后重试"));
        }
    }

    private void route(ChannelHandlerContext context, FullHttpRequest request, String path) throws Exception {
        if (request.method().equals(HttpMethod.GET) && ("/".equals(path) || "/register".equals(path))) {
            sendHtml(context, request, registrationPage);
            return;
        }
        if (request.method().equals(HttpMethod.GET) && "/admin".equals(path)) {
            sendHtml(context, request, adminPage);
            return;
        }
        if (request.method().equals(HttpMethod.GET) && "/favicon.ico".equals(path)) {
            sendEmpty(context, request, HttpResponseStatus.NO_CONTENT);
            return;
        }
        if (request.method().equals(HttpMethod.GET) && "/health".equals(path)) {
            ObjectNode value = JSON.createObjectNode();
            value.put("ok", true);
            ReleaseSnapshot release = releases.current();
            value.put("build", release.buildId());
            value.put("release_published_at", release.publishedAt());
            sendJson(context, request, HttpResponseStatus.OK, value);
            return;
        }
        if (request.method().equals(HttpMethod.POST) && "/api/register".equals(path)) {
            register(context, request);
            return;
        }
        if (request.method().equals(HttpMethod.POST) && "/api/admin/login".equals(path)) {
            adminLogin(context, request);
            return;
        }
        if (request.method().equals(HttpMethod.GET) && "/api/admin/session".equals(path)) {
            adminSession(context, request);
            return;
        }
        if (request.method().equals(HttpMethod.POST) && "/api/admin/logout".equals(path)) {
            adminLogout(context, request);
            return;
        }

        AdminSession session = requireAdmin(context, request);
        if (session == null) return;
        if (request.method().equals(HttpMethod.GET) && "/api/admin/accounts".equals(path)) {
            listAccounts(context, request);
            return;
        }
        if (request.method().equals(HttpMethod.GET) && "/api/admin/logins".equals(path)) {
            listLoginAudits(context, request);
            return;
        }
        if (request.method().equals(HttpMethod.POST) && "/api/admin/accounts".equals(path)) {
            if (!validCsrf(request, session)) {
                sendJson(context, request, HttpResponseStatus.FORBIDDEN, error("csrf", "请求验证已失效"));
                return;
            }
            createAccount(context, request);
            return;
        }
        if (request.method().equals(HttpMethod.GET) && "/api/admin/cards".equals(path)) {
            listCards(context, request);
            return;
        }
        if (request.method().equals(HttpMethod.POST) && "/api/admin/cards".equals(path)) {
            if (!validCsrf(request, session)) {
                sendJson(context, request, HttpResponseStatus.FORBIDDEN, error("csrf", "请求验证已失效"));
                return;
            }
            createCards(context, request);
            return;
        }

        Matcher accountAction = ACCOUNT_ACTION.matcher(path);
        if (request.method().equals(HttpMethod.POST) && accountAction.matches()) {
            if (!validCsrf(request, session)) {
                sendJson(context, request, HttpResponseStatus.FORBIDDEN, error("csrf", "请求验证已失效"));
                return;
            }
            updateAccount(context, request, Long.parseLong(accountAction.group(1)), accountAction.group(2));
            return;
        }
        Matcher cardAction = CARD_ACTION.matcher(path);
        if (request.method().equals(HttpMethod.POST) && cardAction.matches()) {
            if (!validCsrf(request, session)) {
                sendJson(context, request, HttpResponseStatus.FORBIDDEN, error("csrf", "请求验证已失效"));
                return;
            }
            long cardId = Long.parseLong(cardAction.group(1));
            if ("delete".equals(cardAction.group(2))) {
                database.deleteRegistrationKey(cardId);
                sendJson(context, request, HttpResponseStatus.OK, success("卡密已删除"));
            } else {
                database.revokeRegistrationKey(cardId);
                sendJson(context, request, HttpResponseStatus.OK, success("卡密已作废"));
            }
            return;
        }
        sendJson(context, request, HttpResponseStatus.NOT_FOUND, error("not_found", "页面或接口不存在"));
    }

    private void register(ChannelHandlerContext context, FullHttpRequest request) throws Exception {
        String remote = registrationAddress(context, request);
        if (!registrationLimiter.allow("register|" + remote)) {
            sendJson(context, request, HttpResponseStatus.TOO_MANY_REQUESTS,
                error("rate_limited", "注册请求过于频繁，请稍后重试"));
            return;
        }
        JsonNode body = jsonBody(request);
        String username = text(body, "username", 32).trim();
        String passwordValue = text(body, "password", 4096);
        String cardKey = text(body, "card_key", 64).trim();
        if (!USERNAME.matcher(username).matches()) {
            sendJson(context, request, HttpResponseStatus.BAD_REQUEST,
                error("invalid_username", "用户名需为 3-32 位字母、数字或下划线"));
            return;
        }
        char[] password = passwordValue.toCharArray();
        AuthDatabase.RegistrationResult result;
        try {
            result = database.registerWithCard(username, password, cardKey, remote);
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
        if (!result.success()) {
            HttpResponseStatus status = "username_taken".equals(result.code())
                ? HttpResponseStatus.CONFLICT
                : HttpResponseStatus.BAD_REQUEST;
            String message = "username_taken".equals(result.code())
                ? "该用户名已被注册"
                : "卡密错误、已使用或已失效";
            sendJson(context, request, status, error(result.code(), message));
            return;
        }
        ObjectNode response = success("注册成功，现在可以在客户端中登录");
        response.put("username", username);
        sendJson(context, request, HttpResponseStatus.CREATED, response);
    }

    private void adminLogin(ChannelHandlerContext context, FullHttpRequest request) throws Exception {
        String remote = registrationAddress(context, request);
        String limiterKey = "admin|" + remote;
        if (!adminLoginLimiter.allow(limiterKey)) {
            sendJson(context, request, HttpResponseStatus.TOO_MANY_REQUESTS,
                error("rate_limited", "登录尝试过多，请稍后重试"));
            return;
        }
        JsonNode body = jsonBody(request);
        String username = text(body, "username", 128);
        String password = text(body, "password", 512);
        if (config.adminPassword().isBlank()) {
            sendJson(context, request, HttpResponseStatus.SERVICE_UNAVAILABLE,
                error("admin_disabled", "管理后台未配置，请设置 SECRET_AUTH_ADMIN_PASSWORD"));
            return;
        }
        if (!CryptoSupport.constantEquals(username, config.adminUsername())
            || !CryptoSupport.constantEquals(password, config.adminPassword())) {
            sendJson(context, request, HttpResponseStatus.UNAUTHORIZED,
                error("invalid_credentials", "管理员账号或密码错误"));
            return;
        }
        adminLoginLimiter.success(limiterKey);
        String token = CryptoSupport.randomToken(32);
        String csrf = CryptoSupport.randomToken(24);
        long expiresAt = System.currentTimeMillis()
            + Duration.ofMinutes(config.adminSessionMinutes()).toMillis();
        sessions.put(token, new AdminSession(csrf, expiresAt));
        ObjectNode response = success("登录成功");
        response.put("csrf_token", csrf);
        response.put("username", config.adminUsername());
        sendJson(context, request, HttpResponseStatus.OK, response,
            SESSION_COOKIE + "=" + token + "; Path=/; Max-Age="
                + Duration.ofMinutes(config.adminSessionMinutes()).toSeconds()
                + "; HttpOnly; Secure; SameSite=Strict");
    }

    private void adminSession(ChannelHandlerContext context, FullHttpRequest request) {
        AdminSession session = session(request);
        if (session == null) {
            sendJson(context, request, HttpResponseStatus.UNAUTHORIZED,
                error("unauthorized", "请先登录管理后台"));
            return;
        }
        ObjectNode response = success("会话有效");
        response.put("csrf_token", session.csrfToken());
        response.put("username", config.adminUsername());
        sendJson(context, request, HttpResponseStatus.OK, response);
    }

    private void adminLogout(ChannelHandlerContext context, FullHttpRequest request) {
        String token = sessionToken(request);
        if (token != null) sessions.remove(token);
        sendJson(context, request, HttpResponseStatus.OK, success("已退出"),
            SESSION_COOKIE + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict");
    }

    private AdminSession requireAdmin(ChannelHandlerContext context, FullHttpRequest request) {
        AdminSession session = session(request);
        if (session == null) {
            sendJson(context, request, HttpResponseStatus.UNAUTHORIZED,
                error("unauthorized", "请先登录管理后台"));
        }
        return session;
    }

    private void listAccounts(ChannelHandlerContext context, FullHttpRequest request) throws Exception {
        List<AuthDatabase.AccountSummary> accounts = database.accountSummaries();
        ArrayNode values = JSON.createArrayNode();
        int banned = 0;
        int bound = 0;
        for (AuthDatabase.AccountSummary account : accounts) {
            ObjectNode value = values.addObject();
            value.put("id", account.id());
            value.put("username", account.username());
            value.put("password", account.password());
            if (account.hwid() == null) value.putNull("hwid"); else value.put("hwid", account.hwid());
            value.put("banned", account.banned());
            value.put("ban_reason", account.banReason());
            value.put("device_bound", account.deviceBound());
            value.put("created_at", account.createdAt());
            value.put("last_login_at", account.lastLoginAt());
            if (account.banned()) banned++;
            if (account.deviceBound()) bound++;
        }
        ObjectNode response = success("ok");
        response.set("accounts", values);
        response.put("total", accounts.size());
        response.put("banned", banned);
        response.put("bound", bound);
        sendJson(context, request, HttpResponseStatus.OK, response);
    }

    private void listCards(ChannelHandlerContext context, FullHttpRequest request) throws Exception {
        List<AuthDatabase.CardSummary> cards = database.registrationKeys();
        ArrayNode values = JSON.createArrayNode();
        int available = 0;
        for (AuthDatabase.CardSummary card : cards) {
            ObjectNode value = values.addObject();
            value.put("id", card.id());
            value.put("prefix", card.prefix());
            value.put("code", card.code().isEmpty() ? card.prefix() : card.code());
            value.put("used", card.used());
            value.put("revoked", card.revoked());
            value.put("created_at", card.createdAt());
            value.put("used_at", card.usedAt());
            if (card.usedBy() == null) value.putNull("used_by"); else value.put("used_by", card.usedBy());
            if (!card.used() && !card.revoked()) available++;
        }
        ObjectNode response = success("ok");
        response.set("cards", values);
        response.put("available", available);
        sendJson(context, request, HttpResponseStatus.OK, response);
    }

    private void listLoginAudits(ChannelHandlerContext context, FullHttpRequest request) throws Exception {
        List<AuthDatabase.LoginAuditEntry> entries = database.loginAudits(2000);
        ArrayNode values = JSON.createArrayNode();
        int successful = 0;
        int failed = 0;
        for (AuthDatabase.LoginAuditEntry entry : entries) {
            AuthDatabase.LoginAuditEvent event = entry.event();
            ObjectNode value = values.addObject();
            value.put("id", entry.id());
            value.put("created_at", entry.createdAt());
            if (event.accountId() == null) value.putNull("account_id"); else value.put("account_id", event.accountId());
            value.put("username", event.username());
            value.put("success", event.success());
            value.put("result_code", event.resultCode());
            value.put("result_message", event.resultMessage());
            value.put("auth_mode", event.authMode());
            value.put("remote_ip", event.remoteIp());
            value.put("remote_port", event.remotePort());
            value.put("forwarded_for", event.forwardedFor());
            value.put("user_agent", event.userAgent());
            value.put("host", event.host());
            value.put("build_id", event.buildId());
            value.put("hwid", event.hwid());
            value.put("device_id", event.deviceId());
            value.put("device_public_key", event.devicePublicKey());
            value.put("tls_protocol", event.tlsProtocol());
            value.put("tls_cipher", event.tlsCipher());
            value.put("certificate_sha256", event.certificateSha256());
            value.put("certificate_subject", event.certificateSubject());
            value.put("certificate_issuer", event.certificateIssuer());
            value.put("certificate_serial", event.certificateSerial());
            value.put("session_id", event.sessionId());
            value.put("remember", event.remember());
            value.put("duration_ms", event.durationMs());
            if (event.success()) successful++; else failed++;
        }
        ObjectNode response = success("ok");
        response.set("logs", values);
        response.put("total", entries.size());
        response.put("successful", successful);
        response.put("failed", failed);
        sendJson(context, request, HttpResponseStatus.OK, response);
    }

    private void createCards(ChannelHandlerContext context, FullHttpRequest request) throws Exception {
        JsonNode body = jsonBody(request);
        int quantity = body.path("quantity").asInt(1);
        List<String> keys = database.createRegistrationKeys(quantity);
        ObjectNode response = success("卡密创建成功");
        ArrayNode values = response.putArray("keys");
        keys.forEach(values::add);
        sendJson(context, request, HttpResponseStatus.CREATED, response);
    }

    private void updateAccount(
        ChannelHandlerContext context,
        FullHttpRequest request,
        long accountId,
        String action
    ) throws Exception {
        if ("delete".equals(action)) {
            database.deleteAccount(accountId);
            sendJson(context, request, HttpResponseStatus.OK, success("账号已删除"));
            return;
        }
        if ("reset-device".equals(action)) {
            database.resetDevice(accountId);
            sendJson(context, request, HttpResponseStatus.OK, success("设备绑定已清除"));
            return;
        }
        String reason = "";
        if ("ban".equals(action)) {
            JsonNode body = jsonBody(request);
            reason = optionalText(body, "reason", 256).trim();
            if (reason.isEmpty()) reason = "Account disabled by administrator";
        }
        database.setBan(accountId, "ban".equals(action), reason);
        sendJson(context, request, HttpResponseStatus.OK,
            success("ban".equals(action) ? "账号已封禁" : "账号已解除封禁"));
    }

    private void createAccount(ChannelHandlerContext context, FullHttpRequest request) throws Exception {
        JsonNode body = jsonBody(request);
        String username = text(body, "username", 32).trim();
        String passwordValue = text(body, "password", 4096);
        if (!USERNAME.matcher(username).matches()) {
            sendJson(context, request, HttpResponseStatus.BAD_REQUEST,
                error("invalid_username", "用户名需为 3-32 位字母、数字或下划线"));
            return;
        }
        char[] password = passwordValue.toCharArray();
        try {
            database.createUser(username, password);
        } catch (java.sql.SQLException exception) {
            if (exception.getMessage().toLowerCase(java.util.Locale.ROOT).contains("unique")) {
                sendJson(context, request, HttpResponseStatus.CONFLICT,
                    error("username_taken", "该用户名已存在"));
                return;
            }
            throw exception;
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
        sendJson(context, request, HttpResponseStatus.CREATED, success("账号创建成功"));
    }

    private AdminSession session(FullHttpRequest request) {
        String token = sessionToken(request);
        if (token == null) return null;
        AdminSession session = sessions.get(token);
        if (session == null) return null;
        if (session.expiresAt() <= System.currentTimeMillis()) {
            sessions.remove(token, session);
            return null;
        }
        return session;
    }

    private String sessionToken(FullHttpRequest request) {
        String header = request.headers().get(HttpHeaderNames.COOKIE);
        if (header == null) return null;
        Set<Cookie> cookies = ServerCookieDecoder.STRICT.decode(header);
        for (Cookie cookie : cookies) {
            if (SESSION_COOKIE.equals(cookie.name())) return cookie.value();
        }
        return null;
    }

    private static boolean validCsrf(FullHttpRequest request, AdminSession session) {
        return CryptoSupport.constantEquals(
            request.headers().get("X-CSRF-Token"),
            session.csrfToken()
        );
    }

    private static JsonNode jsonBody(FullHttpRequest request) throws Exception {
        if (request.content().readableBytes() == 0) return JSON.createObjectNode();
        return JSON.readTree(request.content().toString(CharsetUtil.UTF_8));
    }

    private static String text(JsonNode body, String name, int maxLength) {
        JsonNode value = body.get(name);
        if (value == null || !value.isTextual() || value.textValue().isEmpty()
            || value.textValue().length() > maxLength) {
            throw new IllegalArgumentException("字段格式错误：" + name);
        }
        return value.textValue();
    }

    private static String optionalText(JsonNode body, String name, int maxLength) {
        JsonNode value = body.get(name);
        if (value == null || value.isNull()) return "";
        if (!value.isTextual() || value.textValue().length() > maxLength) {
            throw new IllegalArgumentException("字段格式错误：" + name);
        }
        return value.textValue();
    }

    private static String header(FullHttpRequest request, String name) {
        String value = request.headers().get(name);
        if (value == null) return "";
        return value.length() > 512 ? value.substring(0, 512) : value;
    }

    private static ObjectNode success(String message) {
        ObjectNode value = JSON.createObjectNode();
        value.put("ok", true);
        value.put("message", message);
        return value;
    }

    private static ObjectNode error(String code, String message) {
        ObjectNode value = JSON.createObjectNode();
        value.put("ok", false);
        value.put("code", code);
        value.put("message", message == null ? "请求格式错误" : message);
        return value;
    }

    private static byte[] resource(String path) throws Exception {
        try (InputStream input = PortalHttpHandler.class.getResourceAsStream(path)) {
            if (input == null) throw new IllegalStateException("Missing web resource: " + path);
            return input.readAllBytes();
        }
    }

    private static void sendHtml(
        ChannelHandlerContext context,
        FullHttpRequest request,
        byte[] content
    ) {
        FullHttpResponse response = response(HttpResponseStatus.OK, content, "text/html; charset=utf-8");
        response.headers().set(HttpHeaderNames.CACHE_CONTROL, "no-store");
        response.headers().set("Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                + "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
        send(context, request, response);
    }

    private static void sendJson(
        ChannelHandlerContext context,
        FullHttpRequest request,
        HttpResponseStatus status,
        JsonNode value
    ) {
        sendJson(context, request, status, value, null);
    }

    private static void sendJson(
        ChannelHandlerContext context,
        FullHttpRequest request,
        HttpResponseStatus status,
        JsonNode value,
        String setCookie
    ) {
        byte[] bytes = value.toString().getBytes(StandardCharsets.UTF_8);
        FullHttpResponse response = response(status, bytes, "application/json; charset=utf-8");
        response.headers().set(HttpHeaderNames.CACHE_CONTROL, "no-store");
        if (setCookie != null) response.headers().set(HttpHeaderNames.SET_COOKIE, setCookie);
        send(context, request, response);
    }

    private static void sendEmpty(
        ChannelHandlerContext context,
        FullHttpRequest request,
        HttpResponseStatus status
    ) {
        send(context, request, response(status, new byte[0], "text/plain"));
    }

    private static FullHttpResponse response(HttpResponseStatus status, byte[] bytes, String type) {
        FullHttpResponse response = new DefaultFullHttpResponse(
            HttpVersion.HTTP_1_1,
            status,
            Unpooled.wrappedBuffer(bytes)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, type);
        response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, bytes.length);
        response.headers().set("X-Content-Type-Options", "nosniff");
        response.headers().set(HttpHeaderNames.X_FRAME_OPTIONS, "DENY");
        response.headers().set("Referrer-Policy", "no-referrer");
        return response;
    }

    private static void send(
        ChannelHandlerContext context,
        FullHttpRequest request,
        FullHttpResponse response
    ) {
        boolean keepAlive = HttpUtil.isKeepAlive(request);
        if (keepAlive) response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        var future = context.writeAndFlush(response);
        if (!keepAlive) future.addListener(io.netty.channel.ChannelFutureListener.CLOSE);
    }

    private static String remoteAddress(ChannelHandlerContext context) {
        if (context.channel().remoteAddress() instanceof InetSocketAddress address) {
            return address.getAddress().getHostAddress();
        }
        return String.valueOf(context.channel().remoteAddress());
    }

    private String registrationAddress(ChannelHandlerContext context, FullHttpRequest request) {
        String direct = remoteAddress(context);
        if (!config.trustProxyHeaders() || !isLoopback(context)) return direct;
        String forwarded = request.headers().get("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) return direct;
        String first = forwarded.split(",", 2)[0].trim();
        return first.isEmpty() || first.length() > 64 ? direct : first;
    }

    private static boolean isLoopback(ChannelHandlerContext context) {
        return context.channel().remoteAddress() instanceof InetSocketAddress address
            && address.getAddress() != null
            && address.getAddress().isLoopbackAddress();
    }

    private static boolean isAdminPath(String path) {
        return "/admin".equals(path) || path.startsWith("/api/admin/");
    }
}
