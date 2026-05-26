package com.devito.lifeengine.auth.application;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Result of evaluating risk for all active sessions and BO users. */
public record SecurityRiskComputation(
        Map<UUID, SessionRiskView> sessionRiskBySessionId,
        Map<UUID, UserRiskView> userRiskByUserId,
        Map<String, Integer> failedLoginsByEmailLowercase,
        /** Earliest {@code refresh_token.created_at} per {@code session_id} (login boundary). */
        Map<UUID, Instant> sessionStartedAtBySessionId,
        SecurityRiskSummary summary) {

    public record SessionRiskView(
            String riskLevel,
            List<String> signals,
            String riskSummary,
            String riskExplanation) {}

    public record UserRiskView(
            String riskLevel,
            List<String> signals,
            int activeSessionCount,
            int failedLoginAttempts24h,
            String riskSummary,
            String riskExplanation) {}

    /** Aggregate counts for control-plane status bar. */
    public record SecurityRiskSummary(int suspiciousSessions, int unusualSessions, int safeSessions) {}
}
