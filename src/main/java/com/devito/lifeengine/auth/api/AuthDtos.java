package com.devito.lifeengine.auth.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class AuthDtos {

    private AuthDtos() {}

    public record LoginRequest(
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Size(min = 1, max = 1024) String password) {}

    public record LoginResponse(
            String accessToken,
            String tokenType,
            int expiresInSeconds,
            String refreshToken,
            int refreshExpiresInSeconds) {}

    public record GoogleLinkStartResponse(String authorizationUrl) {}

    public record GoogleAccountLinkedResponse(boolean linked, String provider) {}

    /**
     * Public BO diagnostics for Google login/linking — no secrets, no raw client identifiers.
     *
     * @param configured All required OAuth client fields are non-blank (same as {@code isConfigured()} on
     *     properties).
     * @param clientIdPresent Client id string is non-empty (not validated against Google).
     * @param clientSecretPresent Client secret string is non-empty.
     * @param redirectUriPresent Callback redirect URI string is non-empty.
     * @param linkSuccessRedirectConfigured SPA URL to receive the browser after successful account link.
     * @param loginSuccessRedirectConfigured SPA URL to receive the browser after Google login (tokens in fragment).
     */
    public record GoogleOAuthStatusResponse(
            boolean configured,
            boolean clientIdPresent,
            boolean clientSecretPresent,
            boolean redirectUriPresent,
            boolean linkSuccessRedirectConfigured,
            boolean loginSuccessRedirectConfigured) {}

    public record RefreshRequest(@NotBlank(message = "refreshToken required") String refreshToken) {}

    public record LogoutRequest(@NotBlank(message = "refreshToken required") String refreshToken) {}

    /** {@code primaryRole} is the application role code; {@code authorities} are effective RBAC permission codes. */
    public record MeResponse(String userId, String email, String primaryRole, List<String> authorities) {}

    /**
     * Current refresh-backed session for the access token (requires {@code sid} claim). No raw refresh
     * material is returned.
     */
    /**
     * Control-plane list row for operator sessions ({@code user_sessions}); device is a short label parsed from
     * {@code User-Agent}.
     */
    public record UserSessionDto(
            UUID id,
            String device,
            String ip,
            Instant createdAt,
            Instant expiresAt,
            /** ACTIVE or REVOKED (includes expired rows shown as REVOKED). */
            String status) {}

    public record SessionSnapshotDto(
            UUID sessionId,
            /** ACTIVE when a non-revoked refresh exists for this session. */
            String sessionStatus,
            Instant refreshExpiresAt,
            /**
             * Rolling access JWT expiry heuristic: {@code lastSeenAt + accessTokenValidity} from server config (same
             * rule as session rows in the security control plane).
             */
            Instant accessTokenExpiresAt,
            Instant lastSeenAt,
            String clientIp,
            String deviceLabel) {}

    /**
     * Aggregated auth observability: Micrometer process totals + bounded DB windows (24h / 1h). Compatible with
     * workflow-style dashboards.
     */
    public record AuthMetricsOverviewDto(
            Instant generatedAt,
            AuthCounterTotalsDto countersLifetime,
            long activeSessionsDistinct,
            long activeRefreshRows,
            long lockedAccounts,
            long loginSuccess24h,
            long loginFailure24h,
            /** {@code loginFailure24h / (loginFailure24h + loginSuccess24h)}, or {@code 0} if no logins in window. */
            double failedLoginRate24h,
            long authEventsLastHour,
            double authEventsPerMinuteLastHour) {}

    public record AuthCounterTotalsDto(
            long loginSuccess,
            long loginFailure,
            long refreshSuccess,
            long refreshFailure,
            long revokeLogout,
            long revokeToken,
            long revokeOthers,
            long guestSessions,
            /** Matches Micrometer {@code auth_refresh_total} ({@code auth.refresh}). */
            long refreshAttemptsTotal) {}

    /**
     * Auth security-audit feed (aligned with workflow {@code TimelineEntryDto} shape for merged platform
     * timelines).
     */
    public record AuthTimelineEntryDto(
            String kind,
            String id,
            Instant at,
            String title,
            String subtitle,
            String level,
            String entityType,
            UUID entityId) {}

    public record SelfSecurityOverviewDto(
            String userId,
            String email,
            String primaryRole,
            List<String> authorities,
            String authProvider,
            boolean googleLinked,
            /** Server-side Google OAuth client is configured (BO can offer login/link entrypoints). */
            boolean googleLoginServerConfigured,
            UUID currentSessionId,
            boolean loggedInNow,
            Instant accessTokenExpiresAt,
            Instant refreshTokenExpiresAt,
            Instant lastLoginAt,
            int failedLoginAttempts,
            int failedLoginAttempts24h,
            boolean accountAdminLocked,
            boolean accountTempLocked,
            Instant lockedUntil,
            boolean passwordPresent,
            Instant passwordChangedAt,
            String mfaStatus,
            int activeSessionCount,
            /** GREEN | YELLOW | RED */
            String securityHealthBand,
            /** From {@code lifeengine.security.jwt.require-active-user-session}. */
            boolean requireActiveUserSession,
            /**
             * From {@code lifeengine.security.jwt.max-active-bo-user-sessions}; {@code 0} means unlimited (BO users
             * only; informational for UI).
             */
            int maxActiveBoUserSessions) {}

    /** Tail of {@code auth_audit_log} for the authenticated principal (v1 self-service). */
    public record AuthAuditLogEntryDto(
            long id,
            String action,
            Instant createdAt,
            String ip,
            String userAgent,
            String metadata) {}

    public record SelfActivityEntryDto(
            long id, String eventType, String outcome, Instant createdAt, String detail) {}

    public record ChangePasswordRequest(
            @NotBlank @Size(min = 1, max = 1024) String currentPassword,
            @NotBlank @Size(min = 1, max = 1024) String newPassword,
            Boolean revokeOtherSessions,
            /** Required when {@code revokeOtherSessions} is true. */
            String refreshToken) {}

    public record ForgotPasswordRequest(@NotBlank @Email @Size(max = 320) String email) {}

    public record ForgotPasswordResponse(boolean accepted, String resetToken) {}

    public record ResetPasswordRequest(
            @NotBlank @Size(min = 20, max = 256) String token,
            @NotBlank @Size(min = 1, max = 1024) String newPassword) {}

    /** Local/test only — {@code POST /api/dev-auth/reset-password} (requires API key header). */
    public record DevPasswordResetRequest(
            @NotBlank @Email @Size(max = 320) String email,
            @NotBlank @Size(min = 1, max = 1024) String newPassword) {}

    public record DevPasswordResetResponse(boolean success, String message) {}
}
