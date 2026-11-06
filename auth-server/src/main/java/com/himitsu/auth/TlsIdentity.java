package com.himitsu.auth;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;

record TlsIdentity(SslContext sslContext, PrivateKey privateKey, X509Certificate certificate) {
    static TlsIdentity load(ServerConfig config) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(config.keyStore())) {
            keyStore.load(input, config.keyStorePassword());
        }
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, config.keyStorePassword());
        X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alias);
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore, config.keyStorePassword());
        SslContext context = SslContextBuilder.forServer(factory)
            .sslProvider(SslProvider.JDK)
            .protocols("TLSv1.3", "TLSv1.2")
            .build();
        return new TlsIdentity(context, privateKey, certificate);
    }
}
