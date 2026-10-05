package com.aifirewall.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/** One row per decision the firewall makes. Secrets are never stored, only masked hints. */
@Entity
@Table(name = "audit_events")
public class AuditEvent {

    public enum Type { CHAT, TOOL_CALL, SCAN }

    public enum Outcome { ALLOWED, REDACTED, BLOCKED, REQUIRE_APPROVAL }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Instant createdAt = Instant.now();
    private String userId;
    private String agentId;

    @Enumerated(EnumType.STRING)
    private Type eventType;

    @Enumerated(EnumType.STRING)
    private Outcome outcome;

    private int riskScore;
    private String signals;
    private String piiTypes;

    @Column(length = 1000)
    private String detail;

    private String model;
    private int promptTokens;
    private int completionTokens;
    private double costUsd;
    private long latencyMs;

    protected AuditEvent() {
        // for JPA
    }

    public AuditEvent(Type type, Outcome outcome, String userId, String agentId) {
        this.eventType = type;
        this.outcome = outcome;
        this.userId = userId;
        this.agentId = agentId;
    }

    public AuditEvent risk(int score, String signals) {
        this.riskScore = score;
        this.signals = signals;
        return this;
    }

    public AuditEvent pii(String piiTypes) {
        this.piiTypes = piiTypes;
        return this;
    }

    public AuditEvent detail(String detail) {
        this.detail = detail == null ? null : detail.substring(0, Math.min(detail.length(), 1000));
        return this;
    }

    public AuditEvent usage(String model, int promptTokens, int completionTokens, double costUsd) {
        this.model = model;
        this.promptTokens = promptTokens;
        this.completionTokens = completionTokens;
        this.costUsd = costUsd;
        return this;
    }

    public AuditEvent latency(long ms) {
        this.latencyMs = ms;
        return this;
    }

    public Long getId() { return id; }
    public Instant getCreatedAt() { return createdAt; }
    public String getUserId() { return userId; }
    public String getAgentId() { return agentId; }
    public Type getEventType() { return eventType; }
    public Outcome getOutcome() { return outcome; }
    public int getRiskScore() { return riskScore; }
    public String getSignals() { return signals; }
    public String getPiiTypes() { return piiTypes; }
    public String getDetail() { return detail; }
    public String getModel() { return model; }
    public int getPromptTokens() { return promptTokens; }
    public int getCompletionTokens() { return completionTokens; }
    public double getCostUsd() { return costUsd; }
    public long getLatencyMs() { return latencyMs; }
}
