package dev.nekoobfuscator.native_.codegen;

/**
 * Escapes Java text for insertion between the quotes of a generated C string literal.
 *
 * <p>The method is deliberately small and allocation-free for strings that do not
 * need escaping; generated native code emits many JVM owner names and descriptors
 * that are already valid C literal content.</p>
 */
public final class CStringLiteral {
    private CStringLiteral() {}

    public static String escape(String value) {
        StringBuilder escaped = null;
        int segmentStart = 0;
        for (int i = 0; i < value.length(); i++) {
            String replacement = replacementFor(value.charAt(i));
            if (replacement == null) {
                continue;
            }
            if (escaped == null) {
                escaped = new StringBuilder(value.length() + 8);
            }
            escaped.append(value, segmentStart, i).append(replacement);
            segmentStart = i + 1;
        }
        if (escaped == null) {
            return value;
        }
        return escaped.append(value, segmentStart, value.length()).toString();
    }

    private static String replacementFor(char c) {
        return switch (c) {
            case '\\' -> "\\\\";
            case '"' -> "\\\"";
            case '\n' -> "\\n";
            case '\r' -> "\\r";
            case '\t' -> "\\t";
            case '\b' -> "\\b";
            case '\f' -> "\\f";
            default -> null;
        };
    }
}
