package dev.nekoobfuscator.test;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeGeneratedCHotPathAuditTest {
    private static final Pattern BUILD_MANIFEST_PATTERN = Pattern.compile("Native build manifest for ([^:]+): (\\S+)");
    private static final Pattern FUNCTION_NAME_PATTERN = Pattern.compile("([A-Za-z_][A-Za-z0-9_]*)\\s*\\([^{};]*\\)\\s*$");
    private static final List<AuditPattern> AUDIT_PATTERNS = List.of(
        new AuditPattern("neko_handle_save", Pattern.compile("\\bneko_handle_save\\b")),
        new AuditPattern("neko_handle_restore", Pattern.compile("\\bneko_handle_restore\\b")),
        new AuditPattern("neko_direct_oop_to_handle", Pattern.compile("\\bneko_direct_oop_to_handle\\b")),
        new AuditPattern("calloc", Pattern.compile("\\bcalloc\\s*\\(")),
        new AuditPattern("free", Pattern.compile("\\bfree\\s*\\(")),
        new AuditPattern("memset", Pattern.compile("\\bmemset\\s*\\(")),
        new AuditPattern("direct_g_hotspot_reads", Pattern.compile("\\bg_hotspot\\s*\\.")),
        new AuditPattern("volatile_primitive_field_accesses", Pattern.compile("\\bvolatile\\s+j(?:boolean|byte|char|short|int|long|float|double)\\s*\\*")),
        new AuditPattern("neko_exception_check", Pattern.compile("\\bneko_exception_check\\b")),
        new AuditPattern("neko_icache_dispatch", Pattern.compile("\\bneko_icache_dispatch\\b")),
        new AuditPattern("string_length_intrinsic", Pattern.compile("\\bneko_fast_string_length\\s*\\(")),
        new AuditPattern("njx_dispatcher_calls", Pattern.compile("\\bneko_njx_[A-Za-z0-9_]+\\s*\\(")),
        new AuditPattern("inline_fprintf", Pattern.compile("\\bfprintf\\s*\\(")),
        new AuditPattern("getenv", Pattern.compile("\\bgetenv\\s*\\(")),
        new AuditPattern("forbidden_jni_NEKO_JNI_FN_PTR", Pattern.compile("\\bNEKO_JNI_FN_PTR\\b")),
        new AuditPattern("forbidden_jni_c_env_arrow", Pattern.compile("\\(\\s*\\*\\s*env\\s*\\)\\s*->")),
        new AuditPattern("forbidden_jni_cpp_env_arrow", Pattern.compile("\\benv\\s*->")),
        new AuditPattern("forbidden_jni_CallMethod", Pattern.compile("\\bCall[A-Za-z0-9_]*Method\\b")),
        new AuditPattern("forbidden_jni_GetField", Pattern.compile("\\bGet[A-Za-z0-9_]*Field\\b")),
        new AuditPattern("forbidden_jni_FindClass", Pattern.compile("\\bFindClass\\b")),
        new AuditPattern("forbidden_jni_NewStringUTF", Pattern.compile("\\bNewStringUTF\\b")),
        new AuditPattern("forbidden_jni_NewObject", Pattern.compile("\\bNewObject[A-Za-z0-9_]*\\b")),
        new AuditPattern("forbidden_jni_Throw", Pattern.compile("\\bThrow[A-Za-z0-9_]*\\b")),
        new AuditPattern("forbidden_jni_monitor_calls", Pattern.compile("\\bMonitor(?:Enter|Exit)\\b")),
        new AuditPattern("forbidden_jni_array_calls", Pattern.compile("\\b(?:Get|Release|Set|New)(?:Boolean|Byte|Char|Short|Int|Long|Float|Double|Object)?Array(?:Elements|Region|Critical)?\\b|\\bGetArrayLength\\b"))
    );

    @Test
    @Timeout(value = 4, unit = TimeUnit.MINUTES)
    void generatedCHotPathAudit_reportsCountsByArtifactAndFunctionRegion() throws Exception {
        List<GeneratedArtifact> artifacts = List.of(
            regenerateArtifact("TEST", "audit-TEST-native.jar", "native-test.yml"),
            regenerateArtifact("obfusjack", "audit-obfusjack-native.jar", "native-obfusjack.yml")
        );

        List<ArtifactAudit> audits = new ArrayList<>();
        for (GeneratedArtifact artifact : artifacts) {
            StringBuilder source = new StringBuilder();
            for (Path generatedCPath : artifact.generatedCPaths()) {
                source.append("\n/* file: ").append(generatedCPath).append(" */\n");
                source.append(Files.readString(generatedCPath));
            }
            ArtifactAudit audit = auditArtifact(artifact, source.toString());
            assertTrue(!audit.regionAudits().isEmpty(), () -> "Missing function/region audit for " + artifact.generatedCPaths());
            assertTrue(audit.regionAudits().stream().anyMatch(region -> region.name().startsWith("neko_native_impl_")),
                () -> "Generated C function parser did not find translated impl regions in " + artifact.generatedCPaths());
            assertRegionTotalsMatchArtifactTotals(audit);
            assertTrue((" " + artifact.nativeCompilerCommandLine() + " ").contains(" -s "),
                () -> "Release native link command must strip debug/symtab data: " + artifact.nativeCompilerCommandLine());
            audits.add(audit);
        }

        Path report = NativeObfuscationHelper.nativeWorkDir().resolve("native-generated-c-hot-path-audit.json");
        Files.writeString(report, renderReport(audits), StandardCharsets.UTF_8);
        assertTrue(Files.exists(report), () -> "Missing generated-C hot-path audit report: " + report);
    }

    private static GeneratedArtifact regenerateArtifact(String fixture, String outputJarName, String configName) throws Exception {
        NativeObfuscationHelper.ObfuscationRunResult result = NativeObfuscationHelper.obfuscateJar(
            NativeObfuscationHelper.inputJarFor(fixture),
            NativeObfuscationHelper.nativeWorkDir().resolve(outputJarName),
            NativeObfuscationHelper.configsDir().resolve(configName),
            Duration.ofMinutes(3)
        );

        Path manifestPath = latestManifestPath(result.combinedOutput(), fixture);
        Properties properties = new Properties();
        try (var input = Files.newInputStream(manifestPath)) {
            properties.load(input);
        }

        List<GeneratedArtifact> artifacts = properties.stringPropertyNames().stream()
            .filter(name -> name.startsWith("target.") && name.endsWith(".command.line"))
            .map(name -> name.substring("target.".length(), name.length() - ".command.line".length()))
            .filter(target -> !target.contains("."))
            .sorted()
            .map(target -> generatedArtifact(fixture, target, manifestPath, properties))
            .toList();
        assertEquals(1, artifacts.size(), () -> "Expected one generated artifact for current platform in " + manifestPath);
        return artifacts.get(0);
    }

    private static Path latestManifestPath(String logs, String fixture) {
        Matcher matcher = BUILD_MANIFEST_PATTERN.matcher(logs);
        Path manifestPath = null;
        while (matcher.find()) {
            manifestPath = Path.of(matcher.group(2));
        }
        assertTrue(manifestPath != null && Files.exists(manifestPath),
            () -> "Missing native build manifest for " + fixture + "\n" + logs);
        return manifestPath;
    }

    private static GeneratedArtifact generatedArtifact(String fixture, String target, Path manifestPath, Properties properties) {
        String prefix = "target." + target + '.';
        List<Path> generatedCPaths = generatedCPaths(properties, manifestPath);
        Path generatedHeaderPath = Path.of(requiredProperty(properties, "generated.header.path", manifestPath));
        Path generatedLibraryPath = Path.of(requiredProperty(properties, prefix + "library.path", manifestPath));
        long generatedLibrarySize = Long.parseLong(requiredProperty(properties, prefix + "library.size.bytes", manifestPath));
        String compilerCommandLine = requiredProperty(properties, prefix + "command.line", manifestPath);
        for (Path generatedCPath : generatedCPaths) {
            assertTrue(Files.exists(generatedCPath), () -> "Missing generated C: " + generatedCPath);
        }
        assertTrue(generatedLibrarySize > 0, () -> "Missing generated library size in " + manifestPath);
        return new GeneratedArtifact(fixture, target, manifestPath, generatedCPaths, generatedHeaderPath, generatedLibraryPath, generatedLibrarySize, compilerCommandLine);
    }

    private static List<Path> generatedCPaths(Properties properties, Path manifestPath) {
        String countValue = properties.getProperty("generated.c.count");
        if (countValue == null || countValue.isBlank()) {
            return List.of(Path.of(requiredProperty(properties, "generated.c.path", manifestPath)));
        }
        int count = Integer.parseInt(countValue);
        List<Path> paths = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            paths.add(Path.of(requiredProperty(properties, "generated.c." + i + ".path", manifestPath)));
        }
        return paths;
    }

    private static String requiredProperty(Properties properties, String key, Path manifestPath) {
        String value = properties.getProperty(key);
        assertTrue(value != null && !value.isBlank(), () -> "Missing `" + key + "` in " + manifestPath);
        return value;
    }

    private static ArtifactAudit auditArtifact(GeneratedArtifact artifact, String source) {
        String code = stripCommentsAndStrings(source);
        List<Region> regions = regions(code);
        List<String> codeLines = code.lines().toList();
        boolean[] functionLine = new boolean[codeLines.size()];
        for (Region region : regions) {
            for (int i = region.startLine(); i <= region.endLine() && i <= functionLine.length; i++) {
                functionLine[i - 1] = true;
            }
        }

        List<RegionAudit> regionAudits = new ArrayList<>();
        StringBuilder global = new StringBuilder();
        for (int i = 0; i < codeLines.size(); i++) {
            if (!functionLine[i]) {
                global.append(codeLines.get(i)).append('\n');
            }
        }
        Map<String, Long> globalCounts = countPatterns(global.toString());
        if (hasNonZeroCount(globalCounts)) {
            regionAudits.add(new RegionAudit("global", 1, codeLines.size(), globalCounts));
        }

        for (Region region : regions) {
            StringBuilder body = new StringBuilder();
            for (int i = region.startLine(); i <= region.endLine() && i <= codeLines.size(); i++) {
                body.append(codeLines.get(i - 1)).append('\n');
            }
            Map<String, Long> counts = countPatterns(body.toString());
            if (hasNonZeroCount(counts)) {
                regionAudits.add(new RegionAudit(region.name(), region.startLine(), region.endLine(), counts));
            }
        }

        Map<String, Long> totals = countPatterns(code);
        return new ArtifactAudit(artifact, totals, regionAudits);
    }

    private static List<Region> regions(String code) {
        List<String> lines = code.lines().toList();
        List<Region> regions = new ArrayList<>();
        StringBuilder signature = new StringBuilder();
        int signatureStartLine = -1;
        int depth = 0;
        int functionStartLine = -1;
        String functionName = null;

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String trimmed = line.trim();
            if (depth == 0) {
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    signature.setLength(0);
                    signatureStartLine = -1;
                    continue;
                }
                if (signatureStartLine < 0) {
                    signatureStartLine = i + 1;
                }
                signature.append(' ').append(trimmed);

                int openIndex = trimmed.indexOf('{');
                int semicolonIndex = trimmed.indexOf(';');
                if (semicolonIndex >= 0 && (openIndex < 0 || semicolonIndex < openIndex)) {
                    signature.setLength(0);
                    signatureStartLine = -1;
                    continue;
                }
                if (openIndex >= 0) {
                    functionName = extractFunctionName(signature.substring(0, signature.indexOf("{") >= 0 ? signature.indexOf("{") : signature.length()));
                    depth = braceDelta(line);
                    if (functionName != null) {
                        functionStartLine = signatureStartLine;
                        if (depth == 0) {
                            regions.add(new Region(uniqueRegionName(functionName, functionStartLine), functionStartLine, i + 1));
                            functionName = null;
                            functionStartLine = -1;
                        }
                    } else {
                        functionStartLine = -1;
                    }
                    signature.setLength(0);
                    signatureStartLine = -1;
                }
            } else {
                depth += braceDelta(line);
                if (depth == 0 && functionName != null) {
                    regions.add(new Region(uniqueRegionName(functionName, functionStartLine), functionStartLine, i + 1));
                    functionName = null;
                    functionStartLine = -1;
                }
            }
        }
        return regions;
    }

    private static String extractFunctionName(String signature) {
        String normalized = signature.replace('\n', ' ').trim();
        if (normalized.startsWith("typedef ") || normalized.startsWith("struct ") || normalized.startsWith("union ")) {
            return null;
        }
        Matcher matcher = FUNCTION_NAME_PATTERN.matcher(normalized);
        if (!matcher.find()) {
            return null;
        }
        String name = matcher.group(1);
        return switch (name) {
            case "if", "for", "while", "switch", "return", "sizeof" -> null;
            default -> name;
        };
    }

    private static String uniqueRegionName(String functionName, int startLine) {
        return functionName + "@L" + startLine;
    }

    private static int braceDelta(String line) {
        int delta = 0;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '{') {
                delta++;
            } else if (c == '}') {
                delta--;
            }
        }
        return delta;
    }

    private static Map<String, Long> countPatterns(String text) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (AuditPattern auditPattern : AUDIT_PATTERNS) {
            Matcher matcher = auditPattern.pattern().matcher(text);
            long count = 0;
            while (matcher.find()) {
                count++;
            }
            counts.put(auditPattern.name(), count);
        }
        return counts;
    }

    private static boolean hasNonZeroCount(Map<String, Long> counts) {
        return counts.values().stream().anyMatch(count -> count > 0);
    }

    private static void assertRegionTotalsMatchArtifactTotals(ArtifactAudit audit) {
        for (AuditPattern pattern : AUDIT_PATTERNS) {
            long regionalTotal = audit.regionAudits().stream()
                .mapToLong(region -> region.counts().get(pattern.name()))
                .sum();
            assertEquals(audit.totals().get(pattern.name()), regionalTotal,
                () -> "Region counts do not add up for `" + pattern.name() + "` in " + audit.artifact().generatedCPaths());
        }
    }

    private static String stripCommentsAndStrings(String source) {
        StringBuilder out = new StringBuilder(source.length());
        boolean blockComment = false;
        boolean lineComment = false;
        boolean string = false;
        boolean character = false;
        boolean escape = false;

        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            char next = i + 1 < source.length() ? source.charAt(i + 1) : '\0';
            if (lineComment) {
                if (c == '\n') {
                    lineComment = false;
                    out.append('\n');
                } else {
                    out.append(' ');
                }
                continue;
            }
            if (blockComment) {
                if (c == '*' && next == '/') {
                    blockComment = false;
                    out.append("  ");
                    i++;
                } else {
                    out.append(c == '\n' ? '\n' : ' ');
                }
                continue;
            }
            if (string || character) {
                if (escape) {
                    escape = false;
                    out.append(' ');
                } else if (c == '\\') {
                    escape = true;
                    out.append(' ');
                } else if (string && c == '"') {
                    string = false;
                    out.append(' ');
                } else if (character && c == '\'') {
                    character = false;
                    out.append(' ');
                } else {
                    out.append(c == '\n' ? '\n' : ' ');
                }
                continue;
            }
            if (c == '/' && next == '/') {
                lineComment = true;
                out.append("  ");
                i++;
            } else if (c == '/' && next == '*') {
                blockComment = true;
                out.append("  ");
                i++;
            } else if (c == '"') {
                string = true;
                out.append(' ');
            } else if (c == '\'') {
                character = true;
                out.append(' ');
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static String renderReport(List<ArtifactAudit> audits) {
        StringBuilder sb = new StringBuilder(32 * 1024);
        sb.append("{\n");
        sb.append("  \"capturedAt\": ").append(json(Instant.now().toString())).append(",\n");
        sb.append("  \"patterns\": ");
        appendStringArray(sb, AUDIT_PATTERNS.stream().map(AuditPattern::name).toList(), "  ");
        sb.append(",\n");
        sb.append("  \"artifacts\": [\n");
        for (int i = 0; i < audits.size(); i++) {
            appendArtifactAudit(sb, audits.get(i), "    ");
            if (i + 1 < audits.size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static void appendArtifactAudit(StringBuilder sb, ArtifactAudit audit, String indent) {
        GeneratedArtifact artifact = audit.artifact();
        sb.append(indent).append("{\n");
        sb.append(indent).append("  \"fixture\": ").append(json(artifact.fixture())).append(",\n");
        sb.append(indent).append("  \"target\": ").append(json(artifact.target())).append(",\n");
        sb.append(indent).append("  \"manifestPath\": ").append(json(artifact.manifestPath().toString())).append(",\n");
        sb.append(indent).append("  \"generatedCPaths\": ");
        appendStringArray(sb, artifact.generatedCPaths().stream().map(Path::toString).toList(), indent + "  ");
        sb.append(",\n");
        sb.append(indent).append("  \"generatedHeaderPath\": ").append(json(artifact.generatedHeaderPath().toString())).append(",\n");
        sb.append(indent).append("  \"generatedLibraryPath\": ").append(json(artifact.generatedLibraryPath().toString())).append(",\n");
        sb.append(indent).append("  \"generatedLibrarySizeBytes\": ").append(artifact.generatedLibrarySizeBytes()).append(",\n");
        sb.append(indent).append("  \"nativeCompilerCommandLine\": ").append(json(artifact.nativeCompilerCommandLine())).append(",\n");
        sb.append(indent).append("  \"totals\": ");
        appendCounts(sb, audit.totals(), indent + "  ");
        sb.append(",\n");
        sb.append(indent).append("  \"regions\": [\n");
        for (int i = 0; i < audit.regionAudits().size(); i++) {
            RegionAudit region = audit.regionAudits().get(i);
            sb.append(indent).append("    {\n");
            sb.append(indent).append("      \"name\": ").append(json(region.name())).append(",\n");
            sb.append(indent).append("      \"startLine\": ").append(region.startLine()).append(",\n");
            sb.append(indent).append("      \"endLine\": ").append(region.endLine()).append(",\n");
            sb.append(indent).append("      \"counts\": ");
            appendCounts(sb, region.counts(), indent + "      ");
            sb.append('\n').append(indent).append("    }");
            if (i + 1 < audit.regionAudits().size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        sb.append(indent).append("  ]\n");
        sb.append(indent).append('}');
    }

    private static void appendCounts(StringBuilder sb, Map<String, Long> counts, String indent) {
        sb.append("{\n");
        int i = 0;
        for (Map.Entry<String, Long> entry : counts.entrySet()) {
            sb.append(indent).append("  ").append(json(entry.getKey())).append(": ").append(entry.getValue());
            if (++i < counts.size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        sb.append(indent).append('}');
    }

    private static void appendStringArray(StringBuilder sb, List<String> values, String indent) {
        sb.append("[\n");
        for (int i = 0; i < values.size(); i++) {
            sb.append(indent).append("  ").append(json(values.get(i)));
            if (i + 1 < values.size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        sb.append(indent).append(']');
    }

    private static String json(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private record AuditPattern(String name, Pattern pattern) {}

    private record GeneratedArtifact(
        String fixture,
        String target,
        Path manifestPath,
        List<Path> generatedCPaths,
        Path generatedHeaderPath,
        Path generatedLibraryPath,
        long generatedLibrarySizeBytes,
        String nativeCompilerCommandLine
    ) {}

    private record Region(String name, int startLine, int endLine) {}

    private record RegionAudit(String name, int startLine, int endLine, Map<String, Long> counts) {}

    private record ArtifactAudit(GeneratedArtifact artifact, Map<String, Long> totals, List<RegionAudit> regionAudits) {}
}
