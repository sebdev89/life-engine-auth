package com.devito.lifeengine.auth.application;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * Micrometer meters for auth flows (Prometheus: {@code auth_login_success_total}, {@code auth_refresh_total}, …).
 */
@Component
public class AuthMetricsRecorder {

    private final Counter loginSuccess;
    private final Counter loginFailure;
    /** Every {@code /api/auth/refresh} attempt (before success/failure split). */
    private final Counter refreshTotal;
    private final Counter refreshSuccess;
    private final Counter refreshFailure;
    private final Counter logoutTotal;
    private final Counter revokeToken;
    private final Counter revokeOthers;
    private final Counter guestSessions;
    private final AtomicLong activeSessions = new AtomicLong();

    public AuthMetricsRecorder(MeterRegistry registry) {
        this.loginSuccess = Counter.builder("auth.login.success").register(registry);
        this.loginFailure = Counter.builder("auth.login.failure").register(registry);
        this.refreshTotal = Counter.builder("auth.refresh").register(registry);
        this.refreshSuccess = Counter.builder("auth.refresh.success").register(registry);
        this.refreshFailure = Counter.builder("auth.refresh.failure").register(registry);
        this.logoutTotal = Counter.builder("auth.logout").register(registry);
        this.revokeToken = Counter.builder("auth.revoke").tag("kind", "token").register(registry);
        this.revokeOthers = Counter.builder("auth.revoke").tag("kind", "others").register(registry);
        this.guestSessions = Counter.builder("auth.guest.session").register(registry);
        Gauge.builder("auth.active.sessions", activeSessions, AtomicLong::get).register(registry);
    }

    public void recordLoginSuccess() {
        loginSuccess.increment();
    }

    public void recordLoginFailure() {
        loginFailure.increment();
    }

    public void recordRefreshAttempt() {
        refreshTotal.increment();
    }

    public void recordRefreshSuccess() {
        refreshSuccess.increment();
    }

    public void recordRefreshFailure() {
        refreshFailure.increment();
    }

    public void recordRevokeLogout() {
        logoutTotal.increment();
    }

    public void recordRevokeToken() {
        revokeToken.increment();
    }

    public void recordRevokeOthers() {
        revokeOthers.increment();
    }

    public void recordGuestSession() {
        guestSessions.increment();
    }

    /** Best-effort gauge for “current” BO sessions; updated by {@link AuthActiveSessionsGaugeUpdater}. */
    public void setActiveSessionsGauge(long value) {
        activeSessions.set(Math.max(0, value));
    }

    public AuthCounterSnapshot snapshot() {
        return new AuthCounterSnapshot(
                (long) loginSuccess.count(),
                (long) loginFailure.count(),
                (long) refreshTotal.count(),
                (long) refreshSuccess.count(),
                (long) refreshFailure.count(),
                (long) logoutTotal.count(),
                (long) revokeToken.count(),
                (long) revokeOthers.count(),
                (long) guestSessions.count());
    }

    public record AuthCounterSnapshot(
            long loginSuccessTotal,
            long loginFailureTotal,
            long refreshAttemptsTotal,
            long refreshSuccessTotal,
            long refreshFailureTotal,
            long logoutTotal,
            long revokeTokenTotal,
            long revokeOthersTotal,
            long guestSessionsTotal) {}
}
