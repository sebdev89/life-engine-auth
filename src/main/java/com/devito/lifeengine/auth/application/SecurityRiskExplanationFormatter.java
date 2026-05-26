package com.devito.lifeengine.auth.application;

import java.util.ArrayList;
import java.util.List;

/**
 * Human-readable risk copy for the Security Control Plane — short headline ({@link RiskNarrative#summary()})
 * and operator-grade explanation ({@link RiskNarrative#explanation()}).
 */
public final class SecurityRiskExplanationFormatter {

    private SecurityRiskExplanationFormatter() {}

    public record RiskNarrative(String summary, String explanation) {}

    /** Guest refresh sessions: no BO user correlation. */
    public static RiskNarrative forGuestSession() {
        return new RiskNarrative(
                "Guest session",
                "Ephemeral guest refresh session. Risk scoring for IP, device, and failed logins applies to "
                        + "registered back-office users.");
    }

    /** Narrative for one active BO session row (risk computed on that session). */
    public static RiskNarrative forSession(
            String riskLevel, List<String> signals, long activeSessionsForUser, int failedLogins24h) {
        if (SecurityRiskLevel.SAFE.equals(riskLevel) && signals.isEmpty()) {
            return new RiskNarrative(
                    "All clear",
                    "No elevated indicators for this session: IP and device match prior activity, "
                            + "and account-wide signals are within normal bounds.");
        }
        return buildNarrative(riskLevel, signals, activeSessionsForUser, failedLogins24h, false);
    }

    /** Aggregated narrative for a BO user (may combine several sessions). */
    public static RiskNarrative forUser(
            String riskLevel, List<String> signals, int activeSessionCount, int failedLogins24h) {
        if (SecurityRiskLevel.SAFE.equals(riskLevel)
                && signals.isEmpty()
                && failedLogins24h == 0
                && activeSessionCount == 0) {
            return new RiskNarrative(
                    "All clear",
                    "No active sessions and no failed login attempts in the last 24 hours.");
        }
        if (SecurityRiskLevel.SAFE.equals(riskLevel) && signals.isEmpty() && failedLogins24h == 0) {
            return new RiskNarrative(
                    "All clear",
                    "Risk indicators are within normal range for this account.");
        }
        return buildNarrative(
                riskLevel, signals, activeSessionCount, failedLogins24h, true);
    }

    /**
     * User row when there are no active sessions but audit may still show failed password attempts (email-only
     * risk).
     */
    public static RiskNarrative forUserWithoutSessionContext(
            String riskLevel, int failedLogins24h) {
        if (failedLogins24h <= 0) {
            return new RiskNarrative(
                    "All clear",
                    "No active sessions. No failed login attempts recorded in the last 24 hours for this email.");
        }
        if (failedLogins24h < 3) {
            return new RiskNarrative(
                    "Watch",
                    failedLogins24h
                            + " failed password attempt(s) in the last 24 hours (below automated alert "
                            + "threshold). No active sessions to correlate.");
        }
        String sev =
                SecurityRiskLevel.SUSPICIOUS.equals(riskLevel)
                        ? "Elevated"
                        : "Unusual";
        return new RiskNarrative(
                sev + " · " + failedLogins24h + " failed logins (24h)",
                failedLogins24h
                        + " failed password attempts in the last 24 hours for this email. "
                        + "There are no active refresh sessions to correlate; consider password hygiene or "
                        + "credential-stuffing attempts.");
    }

    private static RiskNarrative buildNarrative(
            String riskLevel,
            List<String> signals,
            long activeSessionsForUser,
            int failedLogins24h,
            boolean userScope) {
        List<String> summaryBits = new ArrayList<>();
        List<String> explanationBits = new ArrayList<>();

        if (signals.contains(SecurityRiskLevel.SIGNAL_NEW_IP)) {
            summaryBits.add("New IP");
            explanationBits.add(
                    userScope
                            ? "At least one active session uses an IP address not seen on earlier sessions "
                                    + "for this account."
                            : "This session’s IP address was not seen on prior sessions for this account.");
        }
        if (signals.contains(SecurityRiskLevel.SIGNAL_NEW_USER_AGENT)) {
            summaryBits.add("New device signature");
            explanationBits.add(
                    userScope
                            ? "A session shows a browser or client signature not seen in earlier activity."
                            : "The browser or client signature for this session differs from prior sessions.");
        }
        if (signals.contains(SecurityRiskLevel.SIGNAL_MULTIPLE_SESSIONS) && activeSessionsForUser >= 2) {
            summaryBits.add(activeSessionsForUser + " active sessions");
            explanationBits.add(
                    activeSessionsForUser
                            + " concurrent active refresh sessions for this user — multiple devices or "
                            + "browsers may be signed in.");
        }
        if (failedLogins24h >= 3) {
            summaryBits.add(failedLogins24h + " failed logins (24h)");
            explanationBits.add(
                    failedLogins24h
                            + " failed password attempts recorded in the last 24 hours for this email "
                            + "(audit), which may indicate guessing or credential stuffing.");
        }

        String summary = String.join(" · ", summaryBits);
        if (summary.isEmpty()) {
            summary =
                    SecurityRiskLevel.SUSPICIOUS.equals(riskLevel)
                            ? "Elevated risk"
                            : SecurityRiskLevel.UNUSUAL.equals(riskLevel)
                                    ? "Review recommended"
                                    : "All clear";
        }
        String explanation = String.join(" ", explanationBits);
        if (explanation.isEmpty()) {
            explanation =
                    SecurityRiskLevel.SAFE.equals(riskLevel)
                            ? "No elevated indicators."
                            : "Heuristic risk rules flagged this row; review sessions and audit for context.";
        }
        return new RiskNarrative(summary, explanation);
    }
}
