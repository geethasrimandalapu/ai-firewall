package com.aifirewall.gateway;

import com.aifirewall.audit.AuditEvent;
import com.aifirewall.audit.AuditRepository;
import com.aifirewall.config.FirewallProperties;
import com.aifirewall.core.InjectionDetector;
import com.aifirewall.core.InjectionDetector.InjectionResult;
import com.aifirewall.core.PiiRedactor;
import com.aifirewall.core.PiiRedactor.Finding;
import com.aifirewall.llm.LlmClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Drop-in, OpenAI-compatible endpoint. An app only changes its base URL to
 * http://firewall:8080/v1 and every request is inspected:
 *
 *   1. scan user + tool messages for prompt injection (tool output = indirect injection)
 *   2. block if risk >= threshold
 *   3. replace PII/secrets with tokens before the request leaves the company
 *   4. call the model, then restore real values in the answer
 *   5. write an audit event with cost and latency
 */
@RestController
public class GatewayController {

    private final InjectionDetector detector;
    private final PiiRedactor redactor;
    private final LlmClient llm;
    private final AuditRepository audit;
    private final FirewallProperties props;
    private final ObjectMapper mapper;

    public GatewayController(InjectionDetector detector, PiiRedactor redactor, LlmClient llm,
                             AuditRepository audit, FirewallProperties props, ObjectMapper mapper) {
        this.detector = detector;
        this.redactor = redactor;
        this.llm = llm;
        this.audit = audit;
        this.props = props;
        this.mapper = mapper;
    }

    @PostMapping("/v1/chat/completions")
    public ResponseEntity<JsonNode> chat(@RequestBody ObjectNode request,
                                         @RequestHeader(value = "X-User-Id", defaultValue = "anonymous") String userId,
                                         @RequestHeader(value = "X-Agent-Id", required = false) String agentId) {
        long start = System.currentTimeMillis();
        JsonNode messagesNode = request.path("messages");
        if (!messagesNode.isArray() || messagesNode.isEmpty()) {
            return ResponseEntity.badRequest().body(error("invalid_request", "'messages' must be a non-empty array"));
        }
        ArrayNode messages = (ArrayNode) messagesNode;

        // 1-2. Prompt-injection check
        int maxScore = 0;
        Set<String> signals = new LinkedHashSet<>();
        for (JsonNode m : messages) {
            String role = m.path("role").asText();
            if (role.equals("user") || role.equals("tool")) {
                InjectionResult r = detector.analyze(textOf(m.path("content")));
                maxScore = Math.max(maxScore, r.score());
                signals.addAll(r.signals());
            }
        }
        if (maxScore >= props.injectionThreshold()) {
            audit.save(new AuditEvent(AuditEvent.Type.CHAT, AuditEvent.Outcome.BLOCKED, userId, agentId)
                    .risk(maxScore, String.join(",", signals))
                    .detail("Blocked prompt injection attempt")
                    .latency(System.currentTimeMillis() - start));
            ObjectNode body = error("prompt_injection_blocked",
                    "Request blocked by AI Firewall (risk " + maxScore + "/100)");
            ((ObjectNode) body.get("error")).putPOJO("signals", signals);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
        }

        // 3. Redact PII / secrets across all messages with one shared vault
        Map<String, String> vault = new LinkedHashMap<>();
        List<Finding> findings = new ArrayList<>();
        if (props.redactPii()) {
            for (JsonNode m : messages) {
                rewriteContent((ObjectNode) m, text -> {
                    PiiRedactor.RedactionResult rr = redactor.redact(text, vault);
                    findings.addAll(rr.findings());
                    return rr.text();
                });
            }
        }
        String redactedPreview = lastUserText(messages);

        // 4. Call the model and restore original values in the reply
        JsonNode response = llm.chat(request);
        if (response instanceof ObjectNode obj) {
            for (JsonNode choice : obj.path("choices")) {
                JsonNode msg = choice.path("message");
                if (msg instanceof ObjectNode msgObj) {
                    rewriteContent(msgObj, text -> redactor.restore(text, vault));
                }
            }
        }

        // 5. Audit with cost
        int promptTokens = response.path("usage").path("prompt_tokens").asInt();
        int completionTokens = response.path("usage").path("completion_tokens").asInt();
        double cost = promptTokens / 1_000_000.0 * props.inputCostPerMillion()
                + completionTokens / 1_000_000.0 * props.outputCostPerMillion();
        Set<String> piiTypes = new LinkedHashSet<>();
        findings.forEach(f -> piiTypes.add(f.type()));
        AuditEvent.Outcome outcome = findings.isEmpty() ? AuditEvent.Outcome.ALLOWED : AuditEvent.Outcome.REDACTED;
        audit.save(new AuditEvent(AuditEvent.Type.CHAT, outcome, userId, agentId)
                .risk(maxScore, String.join(",", signals))
                .pii(String.join(",", piiTypes))
                .detail("Model saw: " + redactedPreview)
                .usage(response.path("model").asText(), promptTokens, completionTokens, cost)
                .latency(System.currentTimeMillis() - start));

        if (response instanceof ObjectNode obj) {
            ObjectNode fw = obj.putObject("x_firewall");
            fw.put("risk_score", maxScore);
            fw.put("outcome", outcome.name());
            fw.putPOJO("redacted", findings);
            fw.put("model_saw", redactedPreview);
        }
        return ResponseEntity.ok(response);
    }

    /** Content can be a string or an array of parts ({type:text, text:...}). */
    static String textOf(JsonNode content) {
        if (content.isTextual()) {
            return content.asText();
        }
        StringBuilder sb = new StringBuilder();
        if (content.isArray()) {
            for (JsonNode part : content) {
                if (part.has("text")) {
                    sb.append(part.path("text").asText()).append('\n');
                }
            }
        }
        return sb.toString();
    }

    private static void rewriteContent(ObjectNode message, UnaryOperator<String> fn) {
        JsonNode content = message.path("content");
        if (content.isTextual()) {
            message.put("content", fn.apply(content.asText()));
        } else if (content.isArray()) {
            for (JsonNode part : content) {
                if (part instanceof ObjectNode p && p.path("text").isTextual()) {
                    p.put("text", fn.apply(p.path("text").asText()));
                }
            }
        }
    }

    private static String lastUserText(ArrayNode messages) {
        String last = "";
        for (JsonNode m : messages) {
            if ("user".equals(m.path("role").asText())) {
                last = textOf(m.path("content"));
            }
        }
        return last;
    }

    private ObjectNode error(String code, String message) {
        ObjectNode root = mapper.createObjectNode();
        ObjectNode err = root.putObject("error");
        err.put("type", code);
        err.put("message", message);
        return root;
    }
}
