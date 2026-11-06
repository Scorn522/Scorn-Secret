package com.himitsu.secret.tools;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class SecureJarTool {
    private static final byte[] MAGIC = {'H', 'S', 'P', '2'};
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final String CLASS_ROOT = "com/himitsu/secret/";
    private static final String PAYLOAD_ENTRY = "himitsu.jar";
    private static final String NATIVE_BRIDGE = CLASS_ROOT + "bridge/NativeBridge.class";
    private static final Set<String> OUTER_CLASS_NAMES = Set.of(
        CLASS_ROOT + "SecretMod",
        CLASS_ROOT + "bridge/SecretNative",
        CLASS_ROOT + "bridge/EarlyBootstrapService",
        CLASS_ROOT + "code/BootstrapPayload"
    );

    private SecureJarTool() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException(
                "Usage: SecureJarTool <input.jar> <output.jar> <mapping.txt> <outer-key> <class-key>"
            );
        }
        secure(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]), args[3], args[4]);
    }

    private static void secure(
        Path input,
        Path output,
        Path mapping,
        String outerKey,
        String classKey
    ) throws Exception {
        Set<String> passthrough = resolvePassthrough(mapping);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Path temporary = output.resolveSibling(output.getFileName() + ".tmp");
        Files.deleteIfExists(temporary);
        try {
            writeSecuredJar(input, temporary, passthrough, outerKey, classKey);
            verify(temporary, passthrough, outerKey, classKey);
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void writeSecuredJar(
        Path input,
        Path output,
        Set<String> passthrough,
        String outerKey,
        String classKey
    ) throws Exception {
        Set<String> written = new java.util.HashSet<>();
        ByteArrayOutputStream payloadBytes = new ByteArrayOutputStream();
        int payloadClasses = 0;
        try (JarOutputStream payload = new JarOutputStream(payloadBytes, new Manifest())) {
        try (JarInputStream jar = new JarInputStream(Files.newInputStream(input));
             JarOutputStream secured = new JarOutputStream(Files.newOutputStream(output), jar.getManifest())) {
            JarEntry entry;
            while ((entry = jar.getNextJarEntry()) != null) {
                String name = entry.getName();
                if (entry.isDirectory() || name.equals("META-INF/MANIFEST.MF") || name.equals(NATIVE_BRIDGE)) {
                    continue;
                }

                byte[] bytes = readAll(jar);
                if (name.endsWith(".class") && !passthrough.contains(name)) {
                    String encryptedName = name.substring(0, name.length() - ".class".length()) + ".bin";
                    JarEntry payloadEntry = new JarEntry(encryptedName);
                    payloadEntry.setTime(0L);
                    payload.putNextEntry(payloadEntry);
                    payload.write(encrypt(bytes, classKey, "class"));
                    payload.closeEntry();
                    payloadClasses++;
                    continue;
                }
                String outputName = name;
                if (!written.add(outputName)) {
                    continue;
                }

                JarEntry securedEntry = new JarEntry(outputName);
                securedEntry.setTime(0L);
                secured.putNextEntry(securedEntry);
                secured.write(bytes);
                secured.closeEntry();
            }
            payload.finish();
            if (payloadClasses == 0) {
                throw new IOException("Input JAR contains no payload classes");
            }
            JarEntry sourceIndex = new JarEntry("META-INF/secret-bootstrap.list");
            sourceIndex.setTime(0L);
            secured.putNextEntry(sourceIndex);
            secured.write((String.join("\n", new java.util.TreeSet<>(passthrough)) + "\n")
                .getBytes(StandardCharsets.UTF_8));
            secured.closeEntry();
            JarEntry encryptedPayload = new JarEntry(PAYLOAD_ENTRY);
            encryptedPayload.setTime(0L);
            secured.putNextEntry(encryptedPayload);
            secured.write(encrypt(payloadBytes.toByteArray(), outerKey, "outer"));
            secured.closeEntry();
        }
        }
    }

    private static byte[] encrypt(byte[] data, String secret, String purpose) throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(salt);
        random.nextBytes(iv);
        byte[] header = header(salt, iv);
        byte[] key = deriveKey(secret, purpose, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        cipher.updateAAD(header);
        byte[] ciphertext = cipher.doFinal(data);
        ByteArrayOutputStream output = new ByteArrayOutputStream(header.length + ciphertext.length);
        output.write(header);
        output.write(ciphertext);
        return output.toByteArray();
    }

    private static byte[] decrypt(byte[] data, String secret, String purpose) throws Exception {
        if (data.length < MAGIC.length + SALT_LENGTH + IV_LENGTH + 16) {
            throw new IOException("Encrypted class payload is too short");
        }
        for (int index = 0; index < MAGIC.length; index++) {
            if (data[index] != MAGIC[index]) throw new IOException("Unsupported encrypted payload format");
        }
        int saltOffset = MAGIC.length;
        int ivOffset = saltOffset + SALT_LENGTH;
        int dataOffset = ivOffset + IV_LENGTH;
        byte[] salt = java.util.Arrays.copyOfRange(data, saltOffset, ivOffset);
        byte[] iv = java.util.Arrays.copyOfRange(data, ivOffset, dataOffset);
        byte[] ciphertext = java.util.Arrays.copyOfRange(data, dataOffset, data.length);
        byte[] key = deriveKey(secret, purpose, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        cipher.updateAAD(java.util.Arrays.copyOfRange(data, 0, dataOffset));
        return cipher.doFinal(ciphertext);
    }

    private static byte[] deriveKey(String secret, String purpose, byte[] salt) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(secret.getBytes(StandardCharsets.UTF_8));
        digest.update((byte)0);
        digest.update(purpose.getBytes(StandardCharsets.US_ASCII));
        digest.update((byte)0);
        digest.update(salt);
        return digest.digest();
    }

    private static byte[] header(byte[] salt, byte[] iv) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(MAGIC.length + salt.length + iv.length);
        output.write(MAGIC);
        output.write(salt);
        output.write(iv);
        return output.toByteArray();
    }

    private static void verify(
        Path output,
        Set<String> passthrough,
        String outerKey,
        String classKey
    ) throws Exception {
        boolean payloadFound = false;
        try (JarInputStream jar = new JarInputStream(Files.newInputStream(output))) {
            JarEntry entry;
            while ((entry = jar.getNextJarEntry()) != null) {
                String name = entry.getName();
                if (name.equals(NATIVE_BRIDGE)) {
                    throw new IOException("NativeBridge.class must not be packaged in the secured JAR");
                }
                if (entry.isDirectory()) {
                    throw new IOException("Secured JAR must not contain directory entries: " + name);
                }
                if (name.endsWith(".class") && !passthrough.contains(name)) {
                    throw new IOException("Payload class remained plaintext: " + name);
                }
                if (name.equals(PAYLOAD_ENTRY)) {
                    payloadFound = true;
                    byte[] encryptedPayload = readAll(jar);
                    if (isZip(encryptedPayload)) throw new IOException("Outer payload JAR remained plaintext");
                    verifyPayloadJar(decrypt(encryptedPayload, outerKey, "outer"), classKey);
                }
            }
        }
        if (!payloadFound) {
            throw new IOException("Secured JAR contains no encrypted payload JAR");
        }
    }

    private static Set<String> resolvePassthrough(Path mapping) throws IOException {
        java.util.Map<String, String> classNames = new java.util.HashMap<>();
        for (String line : Files.readAllLines(mapping, StandardCharsets.UTF_8)) {
            if (!line.startsWith("CLASS ")) continue;
            int separator = line.indexOf(" -> ", 6);
            if (separator < 0) continue;
            classNames.put(line.substring(6, separator), line.substring(separator + 4));
        }
        Set<String> resolved = new java.util.HashSet<>();
        for (String original : OUTER_CLASS_NAMES) {
            String renamed = classNames.get(original);
            if (renamed == null || renamed.isBlank()) {
                throw new IOException("Missing Neko mapping for outer class: " + original);
            }
            resolved.add(renamed + ".class");
        }
        return Set.copyOf(resolved);
    }

    private static void verifyPayloadJar(byte[] bytes, String classKey) throws Exception {
        if (!isZip(bytes)) throw new IOException("Decrypted payload is not a JAR");
        boolean classFound = false;
        try (JarInputStream payload = new JarInputStream(new java.io.ByteArrayInputStream(bytes))) {
            JarEntry entry;
            while ((entry = payload.getNextJarEntry()) != null) {
                if (!entry.isDirectory() && entry.getName().endsWith(".bin")) {
                    classFound = true;
                    byte[] encrypted = readAll(payload);
                    if (isClass(encrypted) || !isClass(decrypt(encrypted, classKey, "class"))) {
                        throw new IOException("Invalid encrypted class in payload JAR: " + entry.getName());
                    }
                }
            }
        }
        if (!classFound) throw new IOException("Payload JAR contains no encrypted classes");
    }

    private static boolean isZip(byte[] data) {
        return data.length >= 4 && data[0] == 'P' && data[1] == 'K'
            && data[2] == 3 && data[3] == 4;
    }

    private static boolean isClass(byte[] data) {
        return data.length >= 4
            && data[0] == (byte) 0xCA
            && data[1] == (byte) 0xFE
            && data[2] == (byte) 0xBA
            && data[3] == (byte) 0xBE;
    }

    private static byte[] readAll(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        input.transferTo(output);
        return output.toByteArray();
    }
}
