package com.aifirewall.audit;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface AuditRepository extends JpaRepository<AuditEvent, Long> {

    List<AuditEvent> findTop100ByOrderByIdDesc();

    long countByOutcome(AuditEvent.Outcome outcome);

    /** Null when the table is empty. */
    @Query("select sum(e.costUsd) from AuditEvent e")
    Double totalCost();

    /** Null when the table is empty. */
    @Query("select sum(e.promptTokens + e.completionTokens) from AuditEvent e")
    Long totalTokens();
}
