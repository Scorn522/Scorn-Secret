package com.himitsu.auth;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public final class AuthServerMain {
    private AuthServerMain() {
    }

    public static void main(String[] arguments) throws Exception {
        ServerConfig config = ServerConfig.load();
        AuthDatabase database = new AuthDatabase(
            config.database(),
            config.refreshLifetimeDays(),
            config.dataEncryptionKey()
        );
        if (arguments.length != 0) {
            runAdmin(database, arguments);
            return;
        }
        TlsIdentity identity = TlsIdentity.load(config);
        AttemptLimiter limiter = new AttemptLimiter();
        ReleaseCatalog releases = new ReleaseCatalog(config);
        ReleaseSnapshot activeRelease = releases.current();
        AuthWebSocketHandler authHandler = new AuthWebSocketHandler(
            database,
            limiter,
            config,
            releases,
            identity.privateKey(),
            identity.certificate()
        );
        PortalHttpHandler portalHandler = new PortalHttpHandler(database, config, releases);

        EventLoopGroup boss = new NioEventLoopGroup(1);
        EventLoopGroup workers = new NioEventLoopGroup();
        DefaultEventExecutorGroup requestWorkers = new DefaultEventExecutorGroup(2);
        try {
            ServerBootstrap bootstrap = new ServerBootstrap()
                .group(boss, workers)
                .channel(NioServerSocketChannel.class)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) {
                        channel.pipeline().addLast(identity.sslContext().newHandler(channel.alloc()));
                        channel.pipeline().addLast(new ReadTimeoutHandler(45, TimeUnit.SECONDS));
                        channel.pipeline().addLast(new HttpServerCodec());
                        channel.pipeline().addLast(new HttpObjectAggregator(32_768));
                        channel.pipeline().addLast(requestWorkers, portalHandler);
                        channel.pipeline().addLast(new WebSocketServerProtocolHandler(
                            "/auth",
                            null,
                            true,
                            32_768,
                            false,
                            true,
                            10_000L
                        ));
                        channel.pipeline().addLast(requestWorkers, authHandler);
                    }
                });
            Channel channel = bootstrap.bind(config.host(), config.port()).sync().channel();
            System.out.printf(
                "Secret Auth Server listening on wss://%s:%d/auth%nDatabase: %s%nBuild: %s%n",
                config.host(),
                config.port(),
                config.database(),
                activeRelease.buildId()
            );
            System.out.printf(
                "Registration: https://%s:%d/register%nAdmin: https://%s:%d/admin%n",
                config.host(), config.port(), config.host(), config.port()
            );
            if (config.adminPassword().isEmpty()) {
                System.out.println("WARNING: set SECRET_AUTH_ADMIN_PASSWORD before public deployment");
            }
            channel.closeFuture().sync();
        } finally {
            boss.shutdownGracefully();
            workers.shutdownGracefully();
            requestWorkers.shutdownGracefully();
        }
    }

    private static void runAdmin(AuthDatabase database, String[] arguments) throws Exception {
        switch (arguments[0]) {
            case "create-user" -> {
                require(arguments, 3);
                char[] password = arguments[2].toCharArray();
                try {
                    database.createUser(arguments[1], password);
                    System.out.println("Created account: " + arguments[1]);
                } finally {
                    Arrays.fill(password, '\0');
                }
            }
            case "ban" -> {
                require(arguments, 3);
                database.setBan(arguments[1], true, String.join(" ", Arrays.copyOfRange(arguments, 2, arguments.length)));
                System.out.println("Banned account: " + arguments[1]);
            }
            case "unban" -> {
                require(arguments, 2);
                database.setBan(arguments[1], false, "");
                System.out.println("Unbanned account: " + arguments[1]);
            }
            case "reset-device" -> {
                require(arguments, 2);
                database.resetDevice(arguments[1]);
                System.out.println("Reset device binding: " + arguments[1]);
            }
            case "list" -> database.accounts().forEach(account -> System.out.printf(
                "%d  %s  banned=%s  bound=%s  tier=%s  features=0x%016x%n",
                account.id(),
                account.username(),
                account.banned(),
                account.devicePublicKey() != null,
                account.tier(),
                account.featureMask()
            ));
            case "set-tier" -> {
                require(arguments, 4);
                long accountId = Long.parseLong(arguments[1]);
                String tier = arguments[2];
                long featureMask = Long.parseUnsignedLong(arguments[3].startsWith("0x")
                    ? arguments[3].substring(2) : arguments[3], 16);
                database.setTier(accountId, tier, featureMask);
                System.out.println("Updated tier for account " + accountId);
            }
            case "create-card" -> {
                int quantity = arguments.length > 1 ? Integer.parseInt(arguments[1]) : 1;
                database.createRegistrationKeys(quantity).forEach(System.out::println);
            }
            default -> throw new IllegalArgumentException("Unknown command: " + arguments[0]);
        }
    }

    private static void require(String[] arguments, int length) {
        if (arguments.length < length) throw new IllegalArgumentException("Missing command arguments");
    }
}
