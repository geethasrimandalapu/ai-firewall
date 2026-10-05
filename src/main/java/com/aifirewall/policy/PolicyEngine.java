package com.aifirewall.policy;

import java.util.List;
import java.util.Map;

/**
 * Decides whether an AI agent may call a tool, with which arguments.
 *
 * Example: the "support-bot" may call get_order and issue_refund,
 * but refunds above $100 need a human, and delete_customer is never allowed.
 * Default is deny: anything not explicitly allowed is blocked (zero trust).
 */
public class PolicyEngine {

    public enum Decision { ALLOW, DENY, REQUIRE_APPROVAL }

    /** A numeric limit on one tool argument, e.g. amount <= 100. */
    public record ArgLimit(String argument, double max, Decision whenExceeded) {}

    public record ToolRule(String tool, List<ArgLimit> limits) {
        public ToolRule {
            limits = limits == null ? List.of() : limits;
        }
    }

    public record AgentPolicy(String agentId, List<ToolRule> allowedTools, List<String> deniedTools) {
        public AgentPolicy {
            allowedTools = allowedTools == null ? List.of() : allowedTools;
            deniedTools = deniedTools == null ? List.of() : deniedTools;
        }
    }

    public record PolicyResult(Decision decision, String reason) {}

    private final Map<String, AgentPolicy> policies;

    public PolicyEngine(Map<String, AgentPolicy> policies) {
        this.policies = Map.copyOf(policies);
    }

    public PolicyResult evaluate(String agentId, String tool, Map<String, Object> args) {
        AgentPolicy policy = policies.get(agentId);
        if (policy == null) {
            return new PolicyResult(Decision.DENY, "Unknown agent '" + agentId + "' (default deny)");
        }
        if (policy.deniedTools().contains(tool)) {
            return new PolicyResult(Decision.DENY, "Tool '" + tool + "' is explicitly forbidden for " + agentId);
        }
        ToolRule rule = policy.allowedTools().stream()
            .filter(r -> r.tool().equals(tool))
            .findFirst()
            .orElse(null);
        if (rule == null) {
            return new PolicyResult(Decision.DENY, "Tool '" + tool + "' is not in the allow-list for " + agentId);
        }
        Map<String, Object> safeArgs = args == null ? Map.of() : args;
        for (ArgLimit limit : rule.limits()) {
            Object raw = safeArgs.get(limit.argument());
            if (raw == null) {
                continue;
            }
            double value;
            try {
                value = Double.parseDouble(raw.toString());
            } catch (NumberFormatException e) {
                return new PolicyResult(Decision.DENY, "Argument '" + limit.argument() + "' must be numeric");
            }
            if (value > limit.max()) {
                Decision d = limit.whenExceeded() == null ? Decision.DENY : limit.whenExceeded();
                return new PolicyResult(d, limit.argument() + "=" + raw + " exceeds limit " + limit.max());
            }
        }
        return new PolicyResult(Decision.ALLOW, "Allowed by policy");
    }

    public Map<String, AgentPolicy> policies() {
        return policies;
    }
}
