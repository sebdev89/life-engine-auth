package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.AuthDtos.AuthCounterTotalsDto;
import com.devito.lifeengine.auth.api.AuthDtos.AuthMetricsOverviewDto;
import com.devito.lifeengine.auth.api.AuthDtos.AuthTimelineEntryDto;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRow;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class AuthObservabilityAppService {

    private static final int TIMELINE_MAX = 500;

    private final SecurityAuditRepository audit;
    private final RefreshTokenRepository refreshTokens;
    private final BoUserRepository users;
    private final AuthMetricsRecorder metrics;

    public AuthObservabilityAppService(
            SecurityAuditRepository audit,
            RefreshTokenRepository refreshTokens,
            BoUserRepository users,
            AuthMetricsRecorder metrics) {
        this.audit = audit;
        this.refreshTokens = refreshTokens;
        this.users = users;
        this.metrics = metrics;
    }

    public Mono<AuthMetricsOverviewDto> overview() {
        Instant now = Instant.now();
        Instant since24h = now.minus(24, ChronoUnit.HOURS);
        Instant since1h = now.minus(1, ChronoUnit.HOURS);
        AuthMetricsRecorder.AuthCounterSnapshot snap = metrics.snapshot();
        AuthCounterTotalsDto lifetime =
                new AuthCounterTotalsDto(
                        snap.loginSuccessTotal(),
                        snap.loginFailureTotal(),
                        snap.refreshSuccessTotal(),
                        snap.refreshFailureTotal(),
                        snap.logoutTotal(),
                        snap.revokeTokenTotal(),
                        snap.revokeOthersTotal(),
                        snap.guestSessionsTotal(),
                        snap.refreshAttemptsTotal());
        return Mono.zip(
                        refreshTokens.countActiveDistinctSessions(),
                        refreshTokens.countActiveRefreshRows(),
                        users.countLockedAccounts(),
                        audit.countLoginSuccessSince(since24h),
                        audit.countLoginFailureSince(since24h),
                        audit.countAuthEventsSince(since1h))
                .map(
                        t -> {
                            long activeSess = nz(t.getT1());
                            long activeRows = nz(t.getT2());
                            long locked = nz(t.getT3());
                            long ok24 = nz(t.getT4());
                            long fail24 = nz(t.getT5());
                            long ev1h = nz(t.getT6());
                            double denom = (double) (ok24 + fail24);
                            double rate = denom > 0 ? fail24 / denom : 0d;
                            double perMin = ev1h / 60.0;
                            return new AuthMetricsOverviewDto(
                                    now,
                                    lifetime,
                                    activeSess,
                                    activeRows,
                                    locked,
                                    ok24,
                                    fail24,
                                    rate,
                                    ev1h,
                                    perMin);
                        });
    }

    public Flux<AuthTimelineEntryDto> timeline(int limit) {
        int cap = Math.min(Math.max(limit, 1), TIMELINE_MAX);
        return audit.findRecentAuthEvents(cap).map(this::toTimelineEntry);
    }

    private static long nz(Long v) {
        return v == null ? 0L : v;
    }

    private AuthTimelineEntryDto toTimelineEntry(SecurityAuditRow a) {
        String level = levelFor(a.getOutcome(), a.getEventType());
        String subtitle = buildSubtitle(a);
        UUID entityId = a.getUserId();
        return new AuthTimelineEntryDto(
                a.getEventType(),
                String.valueOf(a.getId()),
                a.getCreatedAt(),
                a.getEventType(),
                subtitle,
                level,
                "AUTH",
                entityId);
    }

    private static String levelFor(String outcome, String eventType) {
        if ("LOGIN_FAILURE".equals(eventType)
                || "GOOGLE_LOGIN_FAILURE".equals(eventType)
                || "GOOGLE_LINK_FAILURE".equals(eventType)
                || "REFRESH_FAILURE".equals(eventType)
                || (outcome != null && outcome.equalsIgnoreCase("FAILURE"))) {
            return "WARN";
        }
        if ("ADMIN_USER_LOCKED".equals(eventType)) {
            return "WARN";
        }
        return "INFO";
    }

    private static String buildSubtitle(SecurityAuditRow a) {
        String email = a.getEmail() != null ? a.getEmail().trim().toLowerCase(Locale.ROOT) : "";
        String detail = a.getDetail() != null ? a.getDetail().trim() : "";
        if (email.isEmpty()) {
            return truncate(detail, 240);
        }
        if (detail.isEmpty()) {
            return email;
        }
        return email + " · " + truncate(detail, 180);
    }

    private static String truncate(String s, int max) {
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "…";
    }
}
