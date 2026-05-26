package com.devito.lifeengine.auth.application;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/** Admin / security-operator actions (Micrometer: {@code admin_session_revoke_total}, …). */
@Component
public class AdminMetricsRecorder {

    private final Counter sessionRevoke;
    private final Counter passwordReset;
    private final Counter userLock;

    public AdminMetricsRecorder(MeterRegistry registry) {
        this.sessionRevoke = Counter.builder("admin.session.revoke").register(registry);
        this.passwordReset = Counter.builder("admin.password.reset").register(registry);
        this.userLock = Counter.builder("admin.user.lock").register(registry);
    }

    public void recordSessionRevoked() {
        sessionRevoke.increment();
    }

    public void recordPasswordResetForced() {
        passwordReset.increment();
    }

    public void recordUserLocked() {
        userLock.increment();
    }

    public AdminSnapshot snapshot() {
        return new AdminSnapshot(
                (long) sessionRevoke.count(), (long) passwordReset.count(), (long) userLock.count());
    }

    public record AdminSnapshot(long sessionRevokesTotal, long passwordResetsTotal, long userLocksTotal) {}
}
