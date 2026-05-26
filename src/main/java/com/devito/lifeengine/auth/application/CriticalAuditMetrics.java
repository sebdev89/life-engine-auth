package com.devito.lifeengine.auth.application;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * High-severity security audit events ({@code critical_audit_events_total}). Incremented when an audit row is
 * persisted with a classified event type.
 */
@Component
public class CriticalAuditMetrics {

    static final Set<String> CRITICAL_EVENT_TYPES =
            Set.of(
                    "ADMIN_USER_LOCKED",
                    "ADMIN_PASSWORD_RESET_FORCED",
                    "ADMIN_SESSION_KILLED",
                    "ADMIN_USER_DISABLED",
                    "LOGIN_TEMP_LOCKOUT");

    private final Counter critical;

    public CriticalAuditMetrics(MeterRegistry registry) {
        this.critical = Counter.builder("critical.audit.events").register(registry);
    }

    public void maybeRecord(String eventType) {
        if (eventType != null && CRITICAL_EVENT_TYPES.contains(eventType)) {
            critical.increment();
        }
    }

    public long criticalEventsTotal() {
        return (long) critical.count();
    }
}
