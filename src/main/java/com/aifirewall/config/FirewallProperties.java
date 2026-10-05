package com.aifirewall.config;

import com.aifirewall.policy.PolicyEngine;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** All settings live in application.yml under "firewall". */
@ConfigurationProperties(prefix = "firewall")
public record FirewallProperties(
        @DefaultValue("50") int injectionThreshold,
        @DefaultValue("true") boolean redactPii,
        @DefaultValue("0.15") double inputCostPerMillion,
        @DefaultValue("0.60") double outputCostPerMillion,
        Upstream upstream,
        List<PolicyEngine.AgentPolicy> agents) {

    public FirewallProperties {
        upstream = upstream == null ? new Upstream("https://api.openai.com/v1", "", "gpt-4o-mini") : upstream;
        agents = agents == null ? List.of() : agents;
    }

    /** Any OpenAI-compatible API: OpenAI, Azure OpenAI, Ollama, Groq, vLLM, etc. */
    public record Upstream(String baseUrl, String apiKey, String model) {
        /** With no API key the gateway runs a built-in mock model, so the demo works offline. */
        public boolean mock() {
            return apiKey == null || apiKey.isBlank();
        }
    }
}
