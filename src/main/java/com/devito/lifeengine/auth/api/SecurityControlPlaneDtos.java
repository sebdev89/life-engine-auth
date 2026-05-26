package com.devito.lifeengine.auth.api;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Operator security cockpit — JSON DTOs (no password hashes). */
public final class SecurityControlPlaneDtos {

    private SecurityControlPlaneDtos() {}

    /** Linked external identity (no provider subject / token material). */
    public record IdpLinkViewDto(String provider, String linkedEmail) {}

    /**
     * @param accountStatus {@code ACTIVE} | {@code DISABLED} | {@code LOCKED} — {@code LOCKED} implies
     *     {@code locked=true}; {@code DISABLED} implies {@code enabled=false}.
     * @param role primary app role code from {@link com.devito.lifeengine.auth.application.EffectiveAuthorityService
     *     #resolvePrimaryRoleCode} ({@code bo_user_role} → {@code auth_role}; {@code null} when no role assignment).
     */
    public record SecurityUserDto(
            UUID id,
            String email,
            String role,
            boolean enabled,
            boolean locked,
            String accountStatus,
            Instant createdAt,
            /** {@code SAFE}, {@code UNUSUAL}, or {@code SUSPICIOUS}. */
            String riskLevel,
            List<String> riskSignals,
            /** Short headline for operators (e.g. chip subtitle). */
            String riskSummary,
            /** Full human-readable context. */
            String riskExplanation,
            int activeSessionCount,
            int failedLoginAttempts24h,
            /** {@code local}, {@code google}, {@code mixed}, or {@code none}. */
            String authProvider,
            Instant lastLoginAt,
            boolean loggedInNow,
            /** Current row counter (distinct from 24h audit window). */
            int failedLoginAttempts,
            Instant lockedUntil,
            /** Placeholder until MFA ships ({@code NOT_CONFIGURED}). */
            String mfaStatus,
            /** Reserved — {@code null} until persisted column exists. */
            Instant passwordChangedAt,
            boolean passwordPresent,
            List<IdpLinkViewDto> identityLinks) {}

    /**
     * Single round-trip read model for BO operator security detail: profile projection plus bounded sessions and
     * auth-scoped audit tail (same rows as {@code GET /api/security/users/{id}/sessions} and {@code .../audit}).
     */
    public record AdminOperatorSecurityBundleDto(
            SecurityUserDto user, List<SecuritySessionDto> sessions, List<SecurityAuditLogDto> securityEvents) {}

    /**
     * Role catalog row for control-plane UI — read from {@code auth_role} (same rows as {@code GET /api/auth/roles},
     * different authz). Not assignment ({@code bo_user_role}); not effective JWT permission list.
     */
    public record SecurityRoleDto(
            UUID id,
            String code,
            String displayName,
            String description,
            String effectiveSpringAuthority,
            boolean systemRole,
            Instant createdAt) {}

    /**
     * One operator session — {@code sessionId} is the stable login identity; {@code latestTokenId} is the
     * current refresh row (latest in the rotation chain). {@code createdAt} is that row’s issuance time;
     * {@code sessionStartedAt} is the first token in the chain (true login boundary).
     */
    public record SecuritySessionDto(
            UUID sessionId,
            UUID latestTokenId,
            String principalLabel,
            String ip,
            String device,
            Instant sessionStartedAt,
            Instant createdAt,
            Instant lastSeen,
            Instant expiresAt,
            boolean revoked,
            String kind,
            String riskLevel,
            List<String> riskSignals,
            String riskSummary,
            String riskExplanation,
            /**
             * Heuristic access JWT rolling expiry: {@code lastSeen + accessTokenValidity} from server config (not
             * parsed from JWT).
             */
            Instant accessTokenExpiresAt) {}

    /** Full refresh-token history; includes {@code sessionId} to correlate rotations. */
    public record SecurityTokenDto(
            UUID id,
            UUID sessionId,
            String principalLabel,
            Instant createdAt,
            Instant expiresAt,
            boolean revoked,
            String kind) {}

    public record SecurityAuditLogDto(
            long id,
            String eventType,
            String outcome,
            UUID userId,
            String email,
            String ip,
            String userAgent,
            String detail,
            Instant createdAt) {}

    /**
     * Body for {@code PATCH /api/security/users/{id}/role}. <strong>Canonical HTTP</strong> for "set single BO app
     * role" today; implementation uses {@code RbacAppService#syncUserToSingleRole} ({@code bo_user_role} only).
     */
    public record UpdateUserRoleRequest(String role) {}

    /**
     * Body for {@code POST /api/security/users} — admin provisioning. {@code initialRoleCodes} must reference existing
     * {@code auth_role.code} values. If {@code temporaryPassword} is non-blank it wins over {@code invite}. When only
     * {@code invite} is true (no password), the user is created without a password hash until a future invite/set-password
     * flow delivers credentials.
     */
    public record CreateAdminOperatorRequest(
            String email,
            List<String> initialRoleCodes,
            Boolean enabled,
            Boolean invite,
            String temporaryPassword) {}

    /** Response for {@code POST /api/security/users} (201). */
    public record CreatedOperatorResponse(
            UUID id,
            String email,
            boolean enabled,
            boolean invitePending,
            List<String> assignedRoleCodes) {}

    /** KPI strip for the BO security dashboard (ADMIN). */
    public record SecurityDashboardDto(
            Instant generatedAt,
            long activeSessions,
            long loggedInBoUsersDistinct,
            long guestSessions24h,
            long refreshSuccess24h,
            long failedLogins24h,
            long lockedAccounts,
            long activeRefreshRows,
            long guestSessionsLifetime,
            /** {@code GREEN}, {@code YELLOW}, or {@code RED}. */
            String healthBand) {}
}
