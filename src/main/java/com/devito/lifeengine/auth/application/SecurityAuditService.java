package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRow;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class SecurityAuditService {

    public static final String OUTCOME_SUCCESS = "SUCCESS";
    public static final String OUTCOME_FAILURE = "FAILURE";

    private final SecurityAuditRepository audit;
    private final SecurityStreamNotifier securityStreamNotifier;
    private final CriticalAuditMetrics criticalAuditMetrics;

    public SecurityAuditService(
            SecurityAuditRepository audit,
            SecurityStreamNotifier securityStreamNotifier,
            CriticalAuditMetrics criticalAuditMetrics) {
        this.audit = audit;
        this.securityStreamNotifier = securityStreamNotifier;
        this.criticalAuditMetrics = criticalAuditMetrics;
    }

    public Mono<Void> record(
            String eventType,
            String outcome,
            UUID userId,
            String email,
            AuditContext ctx,
            String detail) {
        SecurityAuditRow row = new SecurityAuditRow();
        row.setEventType(eventType);
        row.setOutcome(outcome);
        row.setUserId(userId);
        row.setEmail(email);
        if (ctx != null) {
            row.setIp(ctx.ip());
            row.setUserAgent(ctx.userAgent());
        }
        row.setDetail(detail);
        row.setCreatedAt(Instant.now());
        return audit
                .save(row)
                .doOnSuccess(
                        saved -> {
                            criticalAuditMetrics.maybeRecord(eventType);
                            securityStreamNotifier.notifyDomain(
                                        "audit_created",
                                        List.of("audit", "risk"),
                                        null,
                                        userId,
                                        Map.of(
                                                "auditId",
                                                saved.getId(),
                                                "eventType",
                                                eventType,
                                                "outcome",
                                                outcome));
                        })
                .doOnSuccess(
                        v ->
                                securityStreamNotifier.notifySurfaces(
                                        "push", List.of("audit", "risk")))
                .then();
    }
}
