package com.aifirewall.config;

import com.aifirewall.core.InjectionDetector;
import com.aifirewall.core.PiiRedactor;
import com.aifirewall.policy.PolicyEngine;
import java.time.Duration;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
public class BeansConfig {

    @Bean
    PiiRedactor piiRedactor() {
        return new PiiRedactor();
    }

    @Bean
    InjectionDetector injectionDetector() {
        return new InjectionDetector();
    }

    @Bean
    PolicyEngine policyEngine(FirewallProperties props) {
        Map<String, PolicyEngine.AgentPolicy> byId = props.agents().stream()
                .collect(Collectors.toMap(PolicyEngine.AgentPolicy::agentId, Function.identity()));
        return new PolicyEngine(byId);
    }

    @Bean
    RestClient llmRestClient(FirewallProperties props) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(10));
        factory.setReadTimeout(Duration.ofSeconds(120));
        return RestClient.builder()
                .baseUrl(props.upstream().baseUrl())
                .requestFactory(factory)
                .build();
    }
}
