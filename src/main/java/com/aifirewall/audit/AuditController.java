package com.aifirewall.audit;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditRepository repo;

    public AuditController(AuditRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/events")
    public List<AuditEvent> recent() {
        return repo.findTop100ByOrderByIdDesc();
    }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("total", repo.count());
        for (AuditEvent.Outcome o : AuditEvent.Outcome.values()) {
            s.put(o.name().toLowerCase(), repo.countByOutcome(o));
        }
        Long tokens = repo.totalTokens();
        Double cost = repo.totalCost();
        s.put("totalTokens", tokens == null ? 0 : tokens);
        s.put("totalCostUsd", cost == null ? 0.0 : cost);
        return s;
    }
}
