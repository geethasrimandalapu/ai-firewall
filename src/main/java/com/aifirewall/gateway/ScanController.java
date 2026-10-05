package com.aifirewall.gateway;

import com.aifirewall.audit.AuditEvent;
import com.aifirewall.audit.AuditRepository;
import com.aifirewall.config.FirewallProperties;
import com.aifirewall.core.InjectionDetector;
import com.aifirewall.core.PiiRedactor;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Inspect any text without calling a model: useful for DLP checks on emails, docs, tickets. */
@RestController
public class ScanController {

    public record ScanRequest(@NotNull String text) {}

    public record ScanResponse(boolean blocked, int riskScore, List<String> signals,
                               String redactedText, List<PiiRedactor.Finding> pii) {}

    private final InjectionDetector detector;
    private final PiiRedactor redactor;
    private final AuditRepository audit;
    private final FirewallProperties props;

    public ScanController(InjectionDetector detector, PiiRedactor redactor,
                          AuditRepository audit, FirewallProperties props) {
        this.detector = detector;
        this.redactor = redactor;
        this.audit = audit;
        this.props = props;
    }

    @PostMapping("/api/scan")
    public ScanResponse scan(@Valid @RequestBody ScanRequest req) {
        var injection = detector.analyze(req.text());
        var redaction = redactor.redact(req.text());
        boolean blocked = injection.isSuspicious(props.injectionThreshold());

        AuditEvent.Outcome outcome = blocked ? AuditEvent.Outcome.BLOCKED
                : redaction.hasFindings() ? AuditEvent.Outcome.REDACTED : AuditEvent.Outcome.ALLOWED;
        audit.save(new AuditEvent(AuditEvent.Type.SCAN, outcome, "playground", null)
                .risk(injection.score(), String.join(",", injection.signals()))
                .pii(redaction.findings().stream().map(PiiRedactor.Finding::type).distinct()
                        .collect(Collectors.joining(",")))
                .detail(redaction.text()));

        return new ScanResponse(blocked, injection.score(), injection.signals(),
                redaction.text(), redaction.findings());
    }
}
