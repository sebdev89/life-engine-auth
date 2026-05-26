package com.devito.lifeengine.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.UUID;

/** Aggregate row for {@link SecurityAuditRepository#findLastLoginSuccessAggregatedByUserIds}. */
public class UserLastLoginRow {

    private UUID userId;
    private Instant lastLogin;

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public Instant getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(Instant lastLogin) {
        this.lastLogin = lastLogin;
    }
}
