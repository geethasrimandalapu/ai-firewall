package com.aifirewall.policy;

import static org.assertj.core.api.Assertions.assertThat;

import com.aifirewall.policy.PolicyEngine.AgentPolicy;
import com.aifirewall.policy.PolicyEngine.ArgLimit;
import com.aifirewall.policy.PolicyEngine.Decision;
import com.aifirewall.policy.PolicyEngine.ToolRule;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PolicyEngineTest {

    private final PolicyEngine engine = new PolicyEngine(Map.of("support-bot", new AgentPolicy(
            "support-bot",
            List.of(new ToolRule("get_order", null),
                    new ToolRule("issue_refund", List.of(new ArgLimit("amount", 100, Decision.REQUIRE_APPROVAL)))),
            List.of("delete_customer"))));

    @Test
    void allowsToolWithinLimits() {
        assertThat(engine.evaluate("support-bot", "issue_refund", Map.of("amount", 40)).decision())
                .isEqualTo(Decision.ALLOW);
    }

    @Test
    void requiresHumanApprovalAboveLimit() {
        assertThat(engine.evaluate("support-bot", "issue_refund", Map.of("amount", 900)).decision())
                .isEqualTo(Decision.REQUIRE_APPROVAL);
    }

    @Test
    void deniesForbiddenUnlistedAndUnknown() {
        assertThat(engine.evaluate("support-bot", "delete_customer", Map.of()).decision()).isEqualTo(Decision.DENY);
        assertThat(engine.evaluate("support-bot", "send_email", Map.of()).decision()).isEqualTo(Decision.DENY);
        assertThat(engine.evaluate("rogue-bot", "get_order", Map.of()).decision()).isEqualTo(Decision.DENY);
    }

    @Test
    void deniesNonNumericLimitArgument() {
        assertThat(engine.evaluate("support-bot", "issue_refund", Map.of("amount", "lots")).decision())
                .isEqualTo(Decision.DENY);
    }
}
