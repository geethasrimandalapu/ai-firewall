package com.aifirewall.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds sensitive data in text and swaps it for placeholder tokens such as [EMAIL_1].
 * The mapping is kept so the real values can be put back into the model's answer
 * ("reversible tokenization") — the AI provider never sees the originals.
 *
 * Framework-free on purpose: easy to unit test and reuse.
 */
public class PiiRedactor {

    /** Order matters: more specific patterns run first. */
    private static final Map<String, Pattern> PATTERNS = new LinkedHashMap<>();

    static {
        PATTERNS.put("PRIVATE_KEY", Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----"));
        PATTERNS.put("API_KEY", Pattern.compile("\\b(?:sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\\b"));
        PATTERNS.put("JWT", Pattern.compile("\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"));
        PATTERNS.put("EMAIL", Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"));
        PATTERNS.put("CREDIT_CARD", Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b"));
        PATTERNS.put("SSN", Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"));
        PATTERNS.put("PHONE", Pattern.compile("(?<!\\w)(?:\\+?1[ .-]?)?\\(?\\d{3}\\)?[ .-]?\\d{3}[ .-]?\\d{4}\\b"));
        PATTERNS.put("IP_ADDRESS", Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b"));
    }

    public RedactionResult redact(String text) {
        return redact(text, new LinkedHashMap<>());
    }

    /**
     * Redacts using a shared vault so the same value gets the same token
     * across all messages of one request.
     */
    public RedactionResult redact(String text, Map<String, String> vault) {
        if (text == null || text.isEmpty()) {
            return new RedactionResult(text, List.of(), vault);
        }
        String current = text;
        List<Finding> findings = new ArrayList<>();

        for (Map.Entry<String, Pattern> entry : PATTERNS.entrySet()) {
            String type = entry.getKey();
            Matcher m = entry.getValue().matcher(current);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                String value = m.group();
                if (type.equals("CREDIT_CARD") && !passesLuhn(value)) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(value));
                    continue;
                }
                String token = tokenFor(type, value, vault);
                findings.add(new Finding(type, mask(value)));
                m.appendReplacement(sb, Matcher.quoteReplacement(token));
            }
            m.appendTail(sb);
            current = sb.toString();
        }
        return new RedactionResult(current, findings, vault);
    }

    /** Puts the original values back into text that contains tokens. */
    public String restore(String text, Map<String, String> vault) {
        if (text == null || vault.isEmpty()) {
            return text;
        }
        String result = text;
        for (Map.Entry<String, String> e : vault.entrySet()) {
            result = result.replace(e.getKey(), e.getValue());
        }
        return result;
    }

    private String tokenFor(String type, String value, Map<String, String> vault) {
        for (Map.Entry<String, String> e : vault.entrySet()) {
            if (e.getValue().equals(value)) {
                return e.getKey();
            }
        }
        long count = vault.keySet().stream().filter(k -> k.startsWith("[" + type + "_")).count();
        String token = "[" + type + "_" + (count + 1) + "]";
        vault.put(token, value);
        return token;
    }

    /** Keeps only a hint of the value so audit logs never store secrets. */
    static String mask(String value) {
        String v = value.strip();
        if (v.length() <= 4) {
            return "****";
        }
        return v.substring(0, 2) + "****" + v.substring(v.length() - 2);
    }

    static boolean passesLuhn(String raw) {
        String digits = raw.replaceAll("[^0-9]", "");
        if (digits.length() < 13 || digits.length() > 19) {
            return false;
        }
        int sum = 0;
        boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (dbl) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    public record Finding(String type, String maskedValue) {}

    public record RedactionResult(String text, List<Finding> findings, Map<String, String> vault) {
        public boolean hasFindings() {
            return !findings.isEmpty();
        }
    }
}
