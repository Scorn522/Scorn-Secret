package com.himitsu.auth;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

final class CryptoSupport {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] CARD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();

    private CryptoSupport() {
    }

    static String randomToken(int bytes) {
        byte[] value = new byte[bytes];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    static String randomCardKey() {
        StringBuilder value = new StringBuilder("SECRET-");
        for (int group = 0; group < 4; group++) {
            if (group != 0) value.append('-');
            for (int character = 0; character < 5; character++) {
                value.append(CARD_ALPHABET[RANDOM.nextInt(CARD_ALPHABET.length)]);
            }
        }
        return value.toString();
    }

    static boolean constantEquals(String first, String second) {
        if (first == null || second == null) return first == null && second == null;
        return MessageDigest.isEqual(
            first.getBytes(StandardCharsets.UTF_8),
            second.getBytes(StandardCharsets.UTF_8)
        );
    }

    static String encryptForStorage(String value, String masterKey) {
        try {
            byte[] nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, storageKey(masterKey), new GCMParameterSpec(128, nonce));
            byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return "v1." + Base64.getUrlEncoder().withoutPadding().encodeToString(nonce)
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted);
        } catch (Exception exception) {
            throw new IllegalStateException("Password storage encryption failed", exception);
        }
    }

    static String decryptFromStorage(String value, String masterKey) {
        if (value == null || value.isBlank()) return "";
        try {
            String[] parts = value.split("\\.", 3);
            if (parts.length != 3 || !"v1".equals(parts[0])) return "";
            byte[] nonce = Base64.getUrlDecoder().decode(parts[1]);
            byte[] encrypted = Base64.getUrlDecoder().decode(parts[2]);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, storageKey(masterKey), new GCMParameterSpec(128, nonce));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception exception) {
            return "";
        }
    }

    private static SecretKeySpec storageKey(String masterKey) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(
            masterKey.getBytes(StandardCharsets.UTF_8)
        );
        return new SecretKeySpec(digest, "AES");
    }

    static String sha256Hex(byte[] input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);
            StringBuilder output = new StringBuilder(digest.length * 2);
            for (byte value : digest) output.append(String.format("%02x", value & 0xff));
            return output.toString();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    static String passwordHash(char[] password) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        byte[] hash = argon2(password, salt, 65536, 3, 1);
        return "$argon2id$v=19$m=65536,t=3,p=1$"
            + Base64.getEncoder().withoutPadding().encodeToString(salt)
            + "$" + Base64.getEncoder().withoutPadding().encodeToString(hash);
    }

    static boolean verifyPassword(char[] password, String encoded) {
        try {
            String[] parts = encoded.split("\\$");
            String[] parameters = parts[3].split(",");
            int memory = Integer.parseInt(parameters[0].substring(2));
            int iterations = Integer.parseInt(parameters[1].substring(2));
            int parallelism = Integer.parseInt(parameters[2].substring(2));
            byte[] salt = Base64.getDecoder().decode(parts[4]);
            byte[] expected = Base64.getDecoder().decode(parts[5]);
            byte[] actual = argon2(password, salt, memory, iterations, parallelism);
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private static byte[] argon2(char[] password, byte[] salt, int memory, int iterations, int parallelism) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(memory)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .withSalt(salt)
            .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        byte[] result = new byte[32];
        generator.generateBytes(password, result);
        return result;
    }

    static PublicKey importCngP256PublicKey(String encoded) throws Exception {
        byte[] blob = Base64.getDecoder().decode(encoded);
        if (blob.length != 72) throw new IllegalArgumentException("Invalid device public key length");
        ByteBuffer header = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN);
        int magic = header.getInt();
        int keySize = header.getInt();
        if (magic != 0x31534345 || keySize != 32) {
            throw new IllegalArgumentException("Invalid ECDSA P-256 public key");
        }
        byte[] x = Arrays.copyOfRange(blob, 8, 40);
        byte[] y = Arrays.copyOfRange(blob, 40, 72);
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
        algorithmParameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec parameters = algorithmParameters.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(
            new ECPoint(new java.math.BigInteger(1, x), new java.math.BigInteger(1, y)),
            parameters
        );
        return KeyFactory.getInstance("EC").generatePublic(keySpec);
    }

    static boolean verifyDeviceSignature(String publicKey, String message, String rawSignature) {
        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(importCngP256PublicKey(publicKey));
            verifier.update(message.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(rawEcdsaToDer(Base64.getDecoder().decode(rawSignature)));
        } catch (Exception exception) {
            return false;
        }
    }

    static byte[] sign(PrivateKey key, byte[] payload) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key, RANDOM);
        signer.update(payload);
        return derEcdsaToRaw(signer.sign(), 32);
    }

    private static byte[] rawEcdsaToDer(byte[] raw) {
        if (raw.length != 64) throw new IllegalArgumentException("Invalid raw ECDSA signature");
        byte[] r = unsignedInteger(Arrays.copyOfRange(raw, 0, 32));
        byte[] s = unsignedInteger(Arrays.copyOfRange(raw, 32, 64));
        byte[] der = new byte[6 + r.length + s.length];
        int offset = 0;
        der[offset++] = 0x30;
        der[offset++] = (byte)(4 + r.length + s.length);
        der[offset++] = 0x02;
        der[offset++] = (byte)r.length;
        System.arraycopy(r, 0, der, offset, r.length);
        offset += r.length;
        der[offset++] = 0x02;
        der[offset++] = (byte)s.length;
        System.arraycopy(s, 0, der, offset, s.length);
        return der;
    }

    private static byte[] unsignedInteger(byte[] value) {
        int first = 0;
        while (first < value.length - 1 && value[first] == 0) first++;
        boolean prefix = (value[first] & 0x80) != 0;
        byte[] result = new byte[value.length - first + (prefix ? 1 : 0)];
        System.arraycopy(value, first, result, prefix ? 1 : 0, value.length - first);
        return result;
    }

    private static byte[] derEcdsaToRaw(byte[] der, int size) {
        int offset = 0;
        if ((der[offset++] & 0xff) != 0x30) throw new IllegalArgumentException("Invalid ECDSA DER sequence");
        int sequenceLength = der[offset++] & 0xff;
        if ((sequenceLength & 0x80) != 0) {
            int bytes = sequenceLength & 0x7f;
            sequenceLength = 0;
            for (int i = 0; i < bytes; i++) sequenceLength = (sequenceLength << 8) | (der[offset++] & 0xff);
        }
        if ((der[offset++] & 0xff) != 0x02) throw new IllegalArgumentException("Invalid ECDSA R");
        int rLength = der[offset++] & 0xff;
        byte[] r = Arrays.copyOfRange(der, offset, offset + rLength);
        offset += rLength;
        if ((der[offset++] & 0xff) != 0x02) throw new IllegalArgumentException("Invalid ECDSA S");
        int sLength = der[offset++] & 0xff;
        byte[] s = Arrays.copyOfRange(der, offset, offset + sLength);
        byte[] raw = new byte[size * 2];
        copyUnsigned(r, raw, 0, size);
        copyUnsigned(s, raw, size, size);
        return raw;
    }

    private static void copyUnsigned(byte[] source, byte[] target, int targetOffset, int size) {
        int sourceOffset = source.length > size ? source.length - size : 0;
        int length = Math.min(source.length, size);
        System.arraycopy(source, sourceOffset, target, targetOffset + size - length, length);
    }
}
