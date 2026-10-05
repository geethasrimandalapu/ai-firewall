package com.aifirewall.gateway;

import com.aifirewall.audit.AuditEvent;
import com.aifirewall.audit.AuditRepository;
import com.aifirewall.config.FirewallProperties;
import com.aifirewall.core.InjectionDetector;
import com.aifirewall.policy.PolicyEngine;
import com.aifirewall.policy.PolicyEngine.Decision;
import com.aifirewall.policy.PolicyEngine.PolicyResult;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.Collection;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Agents ask here before running a tool: "may support-bot call issue_refund(amount=500)?"
 * Answer: ALLOW, DENY or REQUIRE_APPROVAL (human in the loop). Works with any agent
 * framework, including MCP servers, Spring AI and LangChain tool calls.
 */
@RestController
public class ToolAuthController {

    public record ToolCallRequest(@NotBlank String agentId, @NotBlank String tool, Map<String, Object> arguments) {}

    public record ToolCallResponse(Decision decision, String reason, int argumentRisk) {}

    private final PolicyEngine policyEngine;
    private final InjectionDetector detector;
    private final AuditRepository audit;
    private final FirewallProperties props;

    public ToolAuthController(PolicyEngine policyEngine, InjectionDetector detector,
                              AuditRepository audit, FirewallProperties props) {
        this.policyEngine = policyEngine;
        this.detector = detector;
        this.audit = audit;
        this.props = props;
    }

    @PostMapping("/v1/tools/authorize")
    public ResponseEntity<ToolCallResponse> authorize(@Valid @RequestBody ToolCallRequest req) {
        long start = System.currentTimeMillis();
        PolicyResult result = policyEngine.evaluate(req.agentId(), req.tool(), req.arguments());

        // Arguments written by an LLM can carry injected instructions too.
        int risk = detector.analyze(String.valueOf(req.arguments())).score();
        if (result.decision() == Decision.ALLOW && risk >= props.injectionThreshold()) {
            result = new PolicyResult(Decision.DENY, "Tool arguments look like a prompt-injection payload");
        }

        AuditEvent.Outcome outcome = switch (result.decision()) {
            case ALLOW -> AuditEvent.Outcome.ALLOWED;
            case DENY -> AuditEvent.Outcome.BLOCKED;
            case REQUIRE_APPROVAL -> AuditEvent.Outcome.REQUIRE_APPROVAL;
        };
        audit.save(new AuditEvent(AuditEvent.Type.TOOL_CALL, outcome, "agent", req.agentId())
                .risk(risk, null)
                .detail(req.tool() + " " + req.arguments() + " -> " + result.reason())
                .latency(System.currentTimeMillis() - start));

        HttpStatus status = result.decision() == Decision.DENY ? HttpStatus.FORBIDDEN : HttpStatus.OK;
        return ResponseEntity.status(status).body(new ToolCallResponse(result.decision(), result.reason(), risk));
    }

    @GetMapping("/api/policies")
    public Collection<PolicyEngine.AgentPolicy> policies() {
        return policyEngine.policies().values();
    }
}
