package com.aifirewall.core;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scores text for prompt-injection and jailbreak attempts (0 = clean, 100 = attack).
 *
 * Layered approach used by real AI security tools:
 *  1. Normalise the text (unicode tricks, zero-width characters, leetspeak).
 *  2. Weighted signature rules for known attack families.
 *  3. Decode hidden Base64 payloads and scan them too.
 * An optional LLM-based classifier can be added on top (see README roadmap).
 */
public class InjectionDetector {

    private record Rule(String name, Pattern pattern, int weight) {}

    private static final List<Rule> RULES = List.of(
        rule("instruction_override", "(ignore|disregard|forget|override)\\s+(all\\s+|any\\s+|the\\s+)?(previous|prior|above|earlier|preceding|your)\\s+(instructions|rules|prompts?|directions|guidelines)", 60),
        rule("new_instructions", "(new|updated|real)\\s+(system\\s+)?instructions\\s*:", 35),
        rule("system_prompt_leak", "(reveal|show|print|repeat|output|tell me)\\s+(me\\s+)?(your|the)\\s+(system\\s+prompt|hidden\\s+instructions|initial\\s+prompt|instructions)", 50),
        rule("role_hijack", "you\\s+are\\s+(now|no longer)\\s+", 30),
        rule("jailbreak_persona", "\\b(DAN|do anything now|developer mode|jailbreak(ed)?|unfiltered mode|god mode)\\b", 45),
        rule("safety_bypass", "(bypass|disable|turn off|ignore)\\s+(your\\s+)?(safety|filters?|guardrails?|restrictions|content policy)", 50),
        rule("fake_system_tag", "(<\\s*/?\\s*system\\s*>|\\[\\s*system\\s*\\]|###\\s*system|<\\|im_start\\|>)", 40),
        rule("pretend", "(pretend|act as if|imagine)\\s+(you|that you)\\s+(have no|are not bound|don't have)", 35),
        rule("exfiltration", "(send|post|upload|forward|email)\\s+(all\\s+|the\\s+)?(data|conversation|history|credentials|secrets|passwords|api keys?)\\s+to", 55),
        rule("hidden_markdown_exfil", "!\\[[^\\]]*\\]\\(https?://[^)]*\\?[^)]*=", 40),
        rule("tool_abuse", "(call|invoke|run|execute)\\s+(the\\s+)?(tool|function|command)\\s+.*(delete|drop|rm -rf|transfer|refund)", 40)
    );

    private static final Pattern BASE64_CHUNK = Pattern.compile("[A-Za-z0-9+/]{24,}={0,2}");
    private static final Pattern ZERO_WIDTH = Pattern.compile("[\\u200B-\\u200F\\u2060\\uFEFF]");

    private static Rule rule(String name, String regex, int weight) {
        return new Rule(name, Pattern.compile(regex, Pattern.CASE_INSENSITIVE), weight);
    }

    public InjectionResult analyze(String text) {
        if (text == null || text.isBlank()) {
            return new InjectionResult(0, List.of());
        }
        List<String> signals = new ArrayList<>();
        int score = 0;

        if (ZERO_WIDTH.matcher(text).find()) {
            signals.add("hidden_characters");
            score += 15;
        }

        String normalized = normalize(text);
        score += scoreRules(normalized, signals, "");

        Matcher b64 = BASE64_CHUNK.matcher(text);
        while (b64.find()) {
            String decoded = tryDecode(b64.group());
            if (decoded != null) {
                int hidden = scoreRules(normalize(decoded), signals, "encoded:");
                if (hidden > 0) {
                    score += hidden + 10; // hiding an attack is itself suspicious
                }
            }
        }
        return new InjectionResult(Math.min(score, 100), signals);
    }

    private int scoreRules(String text, List<String> signals, String prefix) {
        int score = 0;
        for (Rule r : RULES) {
            if (r.pattern().matcher(text).find()) {
                signals.add(prefix + r.name());
                score += r.weight();
            }
        }
        return score;
    }

    static String normalize(String text) {
        String t = Normalizer.normalize(text, Normalizer.Form.NFKC);
        t = ZERO_WIDTH.matcher(t).replaceAll("");
        // undo common leetspeak used to dodge filters: 1gn0re -> ignore
        t = t.replace('0', 'o').replace('1', 'i').replace('3', 'e')
             .replace('4', 'a').replace('5', 's').replace('7', 't').replace('@', 'a');
        return t.replaceAll("\\s+", " ");
    }

    private static String tryDecode(String chunk) {
        try {
            String s = new String(Base64.getDecoder().decode(chunk), java.nio.charset.StandardCharsets.UTF_8);
            long printable = s.chars().filter(c -> c >= 32 && c < 127).count();
            return printable > s.length() * 0.9 ? s : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public record InjectionResult(int score, List<String> signals) {
        public boolean isSuspicious(int threshold) {
            return score >= threshold;
        }
    }
}
