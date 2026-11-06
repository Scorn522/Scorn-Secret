package com.himitsu.auth;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class AuthDatabase {
    record Account(
        long id,
        String username,
        String passwordHash,
        boolean banned,
        long banUntil,
        String banReason,
        String hwid,
        String devicePublicKey,
        String tier,
        long featureMask
    ) {
        boolean banActive(long now) {
            return banned && (banUntil == 0 || banUntil > now);
        }
    }

    record LoginResult(boolean success, String code, String message, Account account) {
        static LoginResult failure(String code, String message) {
            return new LoginResult(false, code, message, null);
        }

        static LoginResult success(Account account) {
            return new LoginResult(true, "ok", "Authenticated", account);
        }
    }

    record RegistrationResult(boolean success, String code, String message) {
        static RegistrationResult failure(String code, String message) {
            return new RegistrationResult(false, code, message);
        }

        static RegistrationResult accepted() {
            return new RegistrationResult(true, "ok", "Account created");
        }
    }

    record AccountSummary(
        long id,
        String username,
        String password,
        String hwid,
        boolean banned,
        String banReason,
        boolean deviceBound,
        long createdAt,
        long lastLoginAt
    ) {
    }

    record CardSummary(
        long id,
        String prefix,
        String code,
        boolean used,
        boolean revoked,
        long createdAt,
        long usedAt,
        String usedBy
    ) {
    }

    record LoginAuditEvent(
        Long accountId,
        String username,
        boolean success,
        String resultCode,
        String resultMessage,
        String authMode,
        String remoteIp,
        int remotePort,
        String forwardedFor,
        String userAgent,
        String host,
        String buildId,
        String hwid,
        String deviceId,
        String devicePublicKey,
        String tlsProtocol,
        String tlsCipher,
        String certificateSha256,
        String certificateSubject,
        String certificateIssuer,
        String certificateSerial,
        String sessionId,
        boolean remember,
        long durationMs
    ) {
    }

    record LoginAuditEntry(long id, long createdAt, LoginAuditEvent event) {
    }

    private final String jdbcUrl;
    private final int refreshLifetimeDays;
    private final String dummyPasswordHash;
    private final String dataEncryptionKey;

    AuthDatabase(Path path, int refreshLifetimeDays, String dataEncryptionKey) throws Exception {
        Path parent = path.getParent();
        if (parent != null) Files.createDirectories(parent);
        this.jdbcUrl = "jdbc:sqlite:" + path;
        this.refreshLifetimeDays = refreshLifetimeDays;
        this.dataEncryptionKey = dataEncryptionKey;
        this.dummyPasswordHash = CryptoSupport.passwordHash("dummy-password-value".toCharArray());
        migrate();
    }

    private Connection connection() throws SQLException {
        Connection connection = DriverManager.getConnection(jdbcUrl);
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys=ON");
            statement.execute("PRAGMA busy_timeout=5000");
            statement.execute("PRAGMA journal_mode=WAL");
        }
        return connection;
    }

    private void migrate() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    banned INTEGER NOT NULL DEFAULT 0,
                    ban_until INTEGER NOT NULL DEFAULT 0,
                    ban_reason TEXT NOT NULL DEFAULT '',
                    hwid TEXT,
                    device_public_key TEXT,
                    created_at INTEGER NOT NULL,
                    last_login_at INTEGER NOT NULL DEFAULT 0
                )
                """);
            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    device_id TEXT NOT NULL,
                    hwid TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                )
                """);
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS refresh_account_idx ON refresh_tokens(account_id)");
            if (!hasColumn(connection, "accounts", "password_secret")) {
                statement.executeUpdate("ALTER TABLE accounts ADD COLUMN password_secret TEXT");
            }
            if (!hasColumn(connection, "accounts", "tier")) {
                statement.executeUpdate("ALTER TABLE accounts ADD COLUMN tier TEXT NOT NULL DEFAULT 'alpha'");
            }
            if (!hasColumn(connection, "accounts", "feature_mask")) {
                statement.executeUpdate("ALTER TABLE accounts ADD COLUMN feature_mask INTEGER NOT NULL DEFAULT -1");
            }
            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS registration_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code_hash TEXT NOT NULL UNIQUE,
                    code_prefix TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    used_at INTEGER NOT NULL DEFAULT 0,
                    used_by INTEGER REFERENCES accounts(id),
                    revoked INTEGER NOT NULL DEFAULT 0
                )
                """);
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS registration_key_state_idx "
                + "ON registration_keys(revoked,used_at)");
            if (!hasColumn(connection, "registration_keys", "code_secret")) {
                statement.executeUpdate("ALTER TABLE registration_keys ADD COLUMN code_secret TEXT");
            }
            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER,
                    event TEXT NOT NULL,
                    remote_address TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """);
            statement.executeUpdate("""
                CREATE TABLE IF NOT EXISTS login_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER,
                    username TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    result_code TEXT NOT NULL,
                    result_message TEXT NOT NULL,
                    auth_mode TEXT NOT NULL,
                    remote_ip TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    forwarded_for TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    host_header TEXT NOT NULL,
                    build_id TEXT NOT NULL,
                    hwid TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_public_key TEXT NOT NULL,
                    tls_protocol TEXT NOT NULL,
                    tls_cipher TEXT NOT NULL,
                    certificate_sha256 TEXT NOT NULL,
                    certificate_subject TEXT NOT NULL,
                    certificate_issuer TEXT NOT NULL,
                    certificate_serial TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    remember INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """);
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS login_audit_created_idx ON login_audit(created_at DESC)");
            statement.executeUpdate("CREATE INDEX IF NOT EXISTS login_audit_username_idx ON login_audit(username)");
        }
    }

    LoginResult passwordLogin(
        String username,
        char[] password,
        String hwid,
        String devicePublicKey,
        String remoteAddress
    ) throws SQLException {
        Account account = findAccount(username);
        boolean passwordValid = CryptoSupport.verifyPassword(
            password,
            account == null ? dummyPasswordHash : account.passwordHash()
        );
        if (account == null || !passwordValid) {
            audit(account == null ? null : account.id(), "login_failed", remoteAddress, "invalid_credentials");
            return LoginResult.failure("invalid_credentials", "Invalid username or password");
        }
        long now = Instant.now().getEpochSecond();
        if (account.banActive(now)) {
            audit(account.id(), "login_blocked", remoteAddress, "banned");
            return LoginResult.failure("banned", account.banReason().isBlank() ? "Account is banned" : account.banReason());
        }
        String passwordSecret = CryptoSupport.encryptForStorage(
            new String(password),
            dataEncryptionKey
        );

        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try {
                account = findAccount(connection, username);
                if (account.hwid() == null || account.devicePublicKey() == null) {
                    try (PreparedStatement update = connection.prepareStatement(
                        "UPDATE accounts SET hwid=?, device_public_key=?, last_login_at=?, "
                            + "password_secret=COALESCE(password_secret,?) "
                            + "WHERE id=? AND hwid IS NULL AND device_public_key IS NULL"
                    )) {
                        update.setString(1, hwid);
                        update.setString(2, devicePublicKey);
                        update.setLong(3, now);
                        update.setString(4, passwordSecret);
                        update.setLong(5, account.id());
                        if (update.executeUpdate() != 1) {
                            connection.rollback();
                            return LoginResult.failure("device_race", "Device binding changed; retry login");
                        }
                    }
                } else if (!constantEquals(account.hwid(), hwid)
                    || !constantEquals(account.devicePublicKey(), devicePublicKey)) {
                    connection.rollback();
                    audit(account.id(), "login_blocked", remoteAddress, "device_mismatch");
                    return LoginResult.failure("device_mismatch", "This account is bound to another device");
                } else {
                    try (PreparedStatement update = connection.prepareStatement(
                        "UPDATE accounts SET last_login_at=?,password_secret=COALESCE(password_secret,?) WHERE id=?"
                    )) {
                        update.setLong(1, now);
                        update.setString(2, passwordSecret);
                        update.setLong(3, account.id());
                        update.executeUpdate();
                    }
                }
                connection.commit();
            } catch (SQLException exception) {
                connection.rollback();
                throw exception;
            }
        }
        Account current = findAccount(username);
        audit(current.id(), "login_success", remoteAddress, "password");
        return LoginResult.success(current);
    }

    LoginResult refreshLogin(
        String username,
        String refreshToken,
        String hwid,
        String devicePublicKey,
        String remoteAddress
    ) throws SQLException {
        String tokenHash = CryptoSupport.sha256Hex(refreshToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        long now = Instant.now().getEpochSecond();
        String sql = """
            SELECT a.id,a.username,a.password_hash,a.banned,a.ban_until,a.ban_reason,a.hwid,a.device_public_key,a.tier,a.feature_mask,
                   t.id AS token_id,t.device_id,t.hwid AS token_hwid,t.expires_at,t.revoked
            FROM refresh_tokens t JOIN accounts a ON a.id=t.account_id
            WHERE t.token_hash=? AND a.username=?
            """;
        try (Connection connection = connection(); PreparedStatement query = connection.prepareStatement(sql)) {
            query.setString(1, tokenHash);
            query.setString(2, username);
            try (ResultSet result = query.executeQuery()) {
                if (!result.next()) {
                    return LoginResult.failure("invalid_refresh", "Saved login has expired");
                }
                Account account = account(result);
                boolean valid = result.getInt("revoked") == 0
                    && result.getLong("expires_at") > now
                    && constantEquals(result.getString("token_hwid"), hwid)
                    && constantEquals(account.hwid(), hwid)
                    && constantEquals(account.devicePublicKey(), devicePublicKey)
                    && constantEquals(result.getString("device_id"), deviceId(devicePublicKey));
                if (!valid) {
                    return LoginResult.failure("invalid_refresh", "Saved login has expired");
                }
                if (account.banActive(now)) {
                    return LoginResult.failure("banned", account.banReason().isBlank() ? "Account is banned" : account.banReason());
                }
                revokeToken(connection, result.getLong("token_id"));
                audit(account.id(), "login_success", remoteAddress, "refresh");
                return LoginResult.success(account);
            }
        }
    }

    String issueRefreshToken(Account account, String hwid) throws SQLException {
        String token = CryptoSupport.randomToken(48);
        String hash = CryptoSupport.sha256Hex(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        long now = Instant.now().getEpochSecond();
        long expiry = Instant.now().plus(refreshLifetimeDays, ChronoUnit.DAYS).getEpochSecond();
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement revoke = connection.prepareStatement(
                    "UPDATE refresh_tokens SET revoked=1 WHERE account_id=? AND device_id=? AND revoked=0");
                 PreparedStatement insert = connection.prepareStatement(
                    "INSERT INTO refresh_tokens(account_id,token_hash,device_id,hwid,expires_at,created_at) VALUES(?,?,?,?,?,?)"
                 )) {
                String deviceId = deviceId(account.devicePublicKey());
                revoke.setLong(1, account.id());
                revoke.setString(2, deviceId);
                revoke.executeUpdate();
                insert.setLong(1, account.id());
                insert.setString(2, hash);
                insert.setString(3, deviceId);
                insert.setString(4, hwid);
                insert.setLong(5, expiry);
                insert.setLong(6, now);
                insert.executeUpdate();
                connection.commit();
            } catch (SQLException exception) {
                connection.rollback();
                throw exception;
            }
        }
        return token;
    }

    private void revokeToken(Connection connection, long id) throws SQLException {
        try (PreparedStatement update = connection.prepareStatement("UPDATE refresh_tokens SET revoked=1 WHERE id=?")) {
            update.setLong(1, id);
            update.executeUpdate();
        }
    }

    private static String deviceId(String publicKey) {
        return CryptoSupport.sha256Hex(publicKey.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    Account findAccount(String username) throws SQLException {
        try (Connection connection = connection()) {
            return findAccount(connection, username);
        }
    }

    void setTier(long accountId, String tier, long featureMask) throws SQLException {
        try (Connection connection = connection(); PreparedStatement update = connection.prepareStatement(
            "UPDATE accounts SET tier=?,feature_mask=? WHERE id=?"
        )) {
            update.setString(1, tier);
            update.setLong(2, featureMask);
            update.setLong(3, accountId);
            if (update.executeUpdate() != 1) throw new IllegalArgumentException("Unknown account");
        }
    }

    private Account findAccount(Connection connection, String username) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement(
            "SELECT id,username,password_hash,banned,ban_until,ban_reason,hwid,device_public_key,tier,feature_mask FROM accounts WHERE username=?"
        )) {
            query.setString(1, username);
            try (ResultSet result = query.executeQuery()) {
                return result.next() ? account(result) : null;
            }
        }
    }

    private static Account account(ResultSet result) throws SQLException {
        return new Account(
            result.getLong("id"),
            result.getString("username"),
            result.getString("password_hash"),
            result.getInt("banned") != 0,
            result.getLong("ban_until"),
            result.getString("ban_reason"),
            result.getString("hwid"),
            result.getString("device_public_key"),
            result.getString("tier"),
            result.getLong("feature_mask")
        );
    }

    void createUser(String username, char[] password) throws SQLException {
        try (Connection connection = connection(); PreparedStatement insert = connection.prepareStatement(
            "INSERT INTO accounts(username,password_hash,password_secret,created_at) VALUES(?,?,?,?)"
        )) {
            insert.setString(1, username);
            insert.setString(2, CryptoSupport.passwordHash(password));
            insert.setString(3, CryptoSupport.encryptForStorage(new String(password), dataEncryptionKey));
            insert.setLong(4, Instant.now().getEpochSecond());
            insert.executeUpdate();
        }
    }

    RegistrationResult registerWithCard(
        String username,
        char[] password,
        String cardKey,
        String remoteAddress
    ) throws SQLException {
        String normalizedKey = normalizeCardKey(cardKey);
        String keyHash = CryptoSupport.sha256Hex(
            normalizedKey.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
        String passwordHash = CryptoSupport.passwordHash(password);
        long now = Instant.now().getEpochSecond();

        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try {
                long cardId;
                try (PreparedStatement card = connection.prepareStatement(
                    "SELECT id,used_at,revoked FROM registration_keys WHERE code_hash=?"
                )) {
                    card.setString(1, keyHash);
                    try (ResultSet result = card.executeQuery()) {
                        if (!result.next() || result.getInt("revoked") != 0 || result.getLong("used_at") != 0) {
                            connection.rollback();
                            audit(null, "registration_failed", remoteAddress, "invalid_card");
                            return RegistrationResult.failure("invalid_card", "Card key is invalid or already used");
                        }
                        cardId = result.getLong("id");
                    }
                }
                try (PreparedStatement existing = connection.prepareStatement(
                    "SELECT 1 FROM accounts WHERE username=?"
                )) {
                    existing.setString(1, username);
                    try (ResultSet result = existing.executeQuery()) {
                        if (result.next()) {
                            connection.rollback();
                            audit(null, "registration_failed", remoteAddress, "username_taken");
                            return RegistrationResult.failure("username_taken", "Username is already registered");
                        }
                    }
                }

                long accountId;
                try (PreparedStatement insert = connection.prepareStatement(
                    "INSERT INTO accounts(username,password_hash,password_secret,created_at) VALUES(?,?,?,?)",
                    Statement.RETURN_GENERATED_KEYS
                )) {
                    insert.setString(1, username);
                    insert.setString(2, passwordHash);
                    insert.setString(3, CryptoSupport.encryptForStorage(new String(password), dataEncryptionKey));
                    insert.setLong(4, now);
                    insert.executeUpdate();
                    try (ResultSet keys = insert.getGeneratedKeys()) {
                        if (!keys.next()) throw new SQLException("Account id was not generated");
                        accountId = keys.getLong(1);
                    }
                }
                try (PreparedStatement consume = connection.prepareStatement(
                    "UPDATE registration_keys SET used_at=?,used_by=? "
                        + "WHERE id=? AND used_at=0 AND revoked=0"
                )) {
                    consume.setLong(1, now);
                    consume.setLong(2, accountId);
                    consume.setLong(3, cardId);
                    if (consume.executeUpdate() != 1) {
                        connection.rollback();
                        return RegistrationResult.failure("invalid_card", "Card key is invalid or already used");
                    }
                }
                audit(connection, accountId, "registration_success", remoteAddress, "card");
                connection.commit();
                return RegistrationResult.accepted();
            } catch (SQLException exception) {
                connection.rollback();
                throw exception;
            }
        }
    }

    List<String> createRegistrationKeys(int quantity) throws SQLException {
        if (quantity < 1 || quantity > 100) throw new IllegalArgumentException("Quantity must be between 1 and 100");
        List<String> keys = new ArrayList<>(quantity);
        long now = Instant.now().getEpochSecond();
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement insert = connection.prepareStatement(
            "INSERT INTO registration_keys(code_hash,code_prefix,code_secret,created_at) VALUES(?,?,?,?)"
            )) {
                while (keys.size() < quantity) {
                    String key = CryptoSupport.randomCardKey();
                    String hash = CryptoSupport.sha256Hex(
                        key.getBytes(java.nio.charset.StandardCharsets.UTF_8)
                    );
                    try {
                        insert.setString(1, hash);
                        insert.setString(2, key.substring(0, 12));
                        insert.setString(3, CryptoSupport.encryptForStorage(key, dataEncryptionKey));
                        insert.setLong(4, now);
                        insert.executeUpdate();
                        keys.add(key);
                    } catch (SQLException duplicate) {
                        if (!duplicate.getMessage().toLowerCase(Locale.ROOT).contains("unique")) throw duplicate;
                    }
                }
                connection.commit();
            } catch (SQLException exception) {
                connection.rollback();
                throw exception;
            }
        }
        return keys;
    }

    List<CardSummary> registrationKeys() throws SQLException {
        List<CardSummary> values = new ArrayList<>();
        String sql = """
            SELECT k.id,k.code_prefix,k.code_secret,k.used_at,k.revoked,k.created_at,a.username
            FROM registration_keys k LEFT JOIN accounts a ON a.id=k.used_by
            ORDER BY k.id DESC
            """;
        try (Connection connection = connection();
             PreparedStatement query = connection.prepareStatement(sql);
             ResultSet result = query.executeQuery()) {
            while (result.next()) {
                long usedAt = result.getLong("used_at");
                values.add(new CardSummary(
                    result.getLong("id"),
                    result.getString("code_prefix") + "-•••••-•••••-•••••",
                    CryptoSupport.decryptFromStorage(result.getString("code_secret"), dataEncryptionKey),
                    usedAt != 0,
                    result.getInt("revoked") != 0,
                    result.getLong("created_at"),
                    usedAt,
                    result.getString("username")
                ));
            }
        }
        return values;
    }

    void revokeRegistrationKey(long id) throws SQLException {
        try (Connection connection = connection(); PreparedStatement update = connection.prepareStatement(
            "UPDATE registration_keys SET revoked=1 WHERE id=? AND used_at=0"
        )) {
            update.setLong(1, id);
            if (update.executeUpdate() != 1) throw new IllegalArgumentException("Card key is used or unknown");
        }
    }

    void deleteRegistrationKey(long id) throws SQLException {
        try (Connection connection = connection(); PreparedStatement delete = connection.prepareStatement(
            "DELETE FROM registration_keys WHERE id=? AND revoked=1"
        )) {
            delete.setLong(1, id);
            if (delete.executeUpdate() != 1) throw new IllegalArgumentException("Card key is not revoked or unknown");
        }
    }

    void setBan(String username, boolean banned, String reason) throws SQLException {
        try (Connection connection = connection(); PreparedStatement update = connection.prepareStatement(
            "UPDATE accounts SET banned=?,ban_until=0,ban_reason=? WHERE username=?"
        )) {
            update.setInt(1, banned ? 1 : 0);
            update.setString(2, banned ? reason : "");
            update.setString(3, username);
            if (update.executeUpdate() != 1) throw new IllegalArgumentException("Unknown account: " + username);
        }
    }

    void setBan(long accountId, boolean banned, String reason) throws SQLException {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement update = connection.prepareStatement(
                    "UPDATE accounts SET banned=?,ban_until=0,ban_reason=? WHERE id=?");
                 PreparedStatement tokens = connection.prepareStatement(
                    "UPDATE refresh_tokens SET revoked=1 WHERE account_id=?")) {
                update.setInt(1, banned ? 1 : 0);
                update.setString(2, banned ? reason : "");
                update.setLong(3, accountId);
                if (update.executeUpdate() != 1) throw new IllegalArgumentException("Unknown account");
                if (banned) {
                    tokens.setLong(1, accountId);
                    tokens.executeUpdate();
                }
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        }
    }

    void resetDevice(String username) throws SQLException {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement account = connection.prepareStatement(
                    "UPDATE accounts SET hwid=NULL,device_public_key=NULL WHERE username=?");
                 PreparedStatement tokens = connection.prepareStatement(
                    "UPDATE refresh_tokens SET revoked=1 WHERE account_id=(SELECT id FROM accounts WHERE username=?)")) {
                account.setString(1, username);
                if (account.executeUpdate() != 1) throw new IllegalArgumentException("Unknown account: " + username);
                tokens.setString(1, username);
                tokens.executeUpdate();
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        }
    }

    void resetDevice(long accountId) throws SQLException {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement account = connection.prepareStatement(
                    "UPDATE accounts SET hwid=NULL,device_public_key=NULL WHERE id=?");
                 PreparedStatement tokens = connection.prepareStatement(
                    "UPDATE refresh_tokens SET revoked=1 WHERE account_id=?")) {
                account.setLong(1, accountId);
                if (account.executeUpdate() != 1) throw new IllegalArgumentException("Unknown account");
                tokens.setLong(1, accountId);
                tokens.executeUpdate();
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        }
    }

    void deleteAccount(long accountId) throws SQLException {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement detachCards = connection.prepareStatement(
                    "UPDATE registration_keys SET used_by=NULL WHERE used_by=?");
                 PreparedStatement delete = connection.prepareStatement(
                    "DELETE FROM accounts WHERE id=?")) {
                detachCards.setLong(1, accountId);
                detachCards.executeUpdate();
                delete.setLong(1, accountId);
                if (delete.executeUpdate() != 1) throw new IllegalArgumentException("Unknown account");
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        }
    }

    List<Account> accounts() throws SQLException {
        List<Account> values = new ArrayList<>();
        try (Connection connection = connection(); PreparedStatement query = connection.prepareStatement(
            "SELECT id,username,password_hash,banned,ban_until,ban_reason,hwid,device_public_key,tier,feature_mask FROM accounts ORDER BY id"
        ); ResultSet result = query.executeQuery()) {
            while (result.next()) values.add(account(result));
        }
        return values;
    }

    List<AccountSummary> accountSummaries() throws SQLException {
        List<AccountSummary> values = new ArrayList<>();
        String sql = "SELECT id,username,password_secret,banned,ban_reason,hwid,device_public_key,created_at,last_login_at "
            + "FROM accounts ORDER BY id DESC";
        try (Connection connection = connection();
             PreparedStatement query = connection.prepareStatement(sql);
             ResultSet result = query.executeQuery()) {
            while (result.next()) {
                values.add(new AccountSummary(
                    result.getLong("id"),
                    result.getString("username"),
                    CryptoSupport.decryptFromStorage(result.getString("password_secret"), dataEncryptionKey),
                    result.getString("hwid"),
                    result.getInt("banned") != 0,
                    result.getString("ban_reason"),
                    result.getString("hwid") != null && result.getString("device_public_key") != null,
                    result.getLong("created_at"),
                    result.getLong("last_login_at")
                ));
            }
        }
        return values;
    }

    void audit(Long accountId, String event, String remoteAddress, String details) throws SQLException {
        try (Connection connection = connection(); PreparedStatement insert = connection.prepareStatement(
            "INSERT INTO audit_log(account_id,event,remote_address,details,created_at) VALUES(?,?,?,?,?)"
        )) {
            bindAudit(insert, accountId, event, remoteAddress, details);
        }
    }

    void recordLoginAudit(LoginAuditEvent value) throws SQLException {
        String sql = """
            INSERT INTO login_audit(
                account_id,username,success,result_code,result_message,auth_mode,
                remote_ip,remote_port,forwarded_for,user_agent,host_header,build_id,
                hwid,device_id,device_public_key,tls_protocol,tls_cipher,
                certificate_sha256,certificate_subject,certificate_issuer,certificate_serial,
                session_id,remember,duration_ms,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """;
        try (Connection connection = connection(); PreparedStatement insert = connection.prepareStatement(sql)) {
            if (value.accountId() == null) insert.setNull(1, java.sql.Types.BIGINT);
            else insert.setLong(1, value.accountId());
            insert.setString(2, value.username());
            insert.setInt(3, value.success() ? 1 : 0);
            insert.setString(4, value.resultCode());
            insert.setString(5, value.resultMessage());
            insert.setString(6, value.authMode());
            insert.setString(7, value.remoteIp());
            insert.setInt(8, value.remotePort());
            insert.setString(9, value.forwardedFor());
            insert.setString(10, value.userAgent());
            insert.setString(11, value.host());
            insert.setString(12, value.buildId());
            insert.setString(13, value.hwid());
            insert.setString(14, value.deviceId());
            insert.setString(15, value.devicePublicKey());
            insert.setString(16, value.tlsProtocol());
            insert.setString(17, value.tlsCipher());
            insert.setString(18, value.certificateSha256());
            insert.setString(19, value.certificateSubject());
            insert.setString(20, value.certificateIssuer());
            insert.setString(21, value.certificateSerial());
            insert.setString(22, value.sessionId());
            insert.setInt(23, value.remember() ? 1 : 0);
            insert.setLong(24, value.durationMs());
            insert.setLong(25, Instant.now().getEpochSecond());
            insert.executeUpdate();
        }
    }

    List<LoginAuditEntry> loginAudits(int limit) throws SQLException {
        int boundedLimit = Math.max(1, Math.min(limit, 5000));
        List<LoginAuditEntry> values = new ArrayList<>();
        String sql = "SELECT * FROM login_audit ORDER BY id DESC LIMIT ?";
        try (Connection connection = connection(); PreparedStatement query = connection.prepareStatement(sql)) {
            query.setInt(1, boundedLimit);
            try (ResultSet result = query.executeQuery()) {
                while (result.next()) {
                    Long accountId = result.getObject("account_id") == null
                        ? null : result.getLong("account_id");
                    LoginAuditEvent event = new LoginAuditEvent(
                        accountId,
                        result.getString("username"),
                        result.getInt("success") != 0,
                        result.getString("result_code"),
                        result.getString("result_message"),
                        result.getString("auth_mode"),
                        result.getString("remote_ip"),
                        result.getInt("remote_port"),
                        result.getString("forwarded_for"),
                        result.getString("user_agent"),
                        result.getString("host_header"),
                        result.getString("build_id"),
                        result.getString("hwid"),
                        result.getString("device_id"),
                        result.getString("device_public_key"),
                        result.getString("tls_protocol"),
                        result.getString("tls_cipher"),
                        result.getString("certificate_sha256"),
                        result.getString("certificate_subject"),
                        result.getString("certificate_issuer"),
                        result.getString("certificate_serial"),
                        result.getString("session_id"),
                        result.getInt("remember") != 0,
                        result.getLong("duration_ms")
                    );
                    values.add(new LoginAuditEntry(
                        result.getLong("id"),
                        result.getLong("created_at"),
                        event
                    ));
                }
            }
        }
        return values;
    }

    private void audit(
        Connection connection,
        Long accountId,
        String event,
        String remoteAddress,
        String details
    ) throws SQLException {
        try (PreparedStatement insert = connection.prepareStatement(
            "INSERT INTO audit_log(account_id,event,remote_address,details,created_at) VALUES(?,?,?,?,?)"
        )) {
            bindAudit(insert, accountId, event, remoteAddress, details);
        }
    }

    private static void bindAudit(
        PreparedStatement insert,
        Long accountId,
        String event,
        String remoteAddress,
        String details
    ) throws SQLException {
        if (accountId == null) insert.setNull(1, java.sql.Types.BIGINT); else insert.setLong(1, accountId);
        insert.setString(2, event);
        insert.setString(3, remoteAddress);
        insert.setString(4, details);
        insert.setLong(5, Instant.now().getEpochSecond());
        insert.executeUpdate();
    }

    private static String normalizeCardKey(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static boolean hasColumn(Connection connection, String table, String column) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement("PRAGMA table_info(" + table + ")");
             ResultSet result = query.executeQuery()) {
            while (result.next()) {
                if (column.equalsIgnoreCase(result.getString("name"))) return true;
            }
        }
        return false;
    }

    private static boolean constantEquals(String first, String second) {
        if (first == null || second == null) return first == null && second == null;
        return java.security.MessageDigest.isEqual(
            first.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            second.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }
}
