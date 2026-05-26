package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.AuthDtos;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.config.GuestAuthProperties;
import com.devito.lifeengine.auth.infrastructure.config.JwtSecurityProperties;
import com.devito.lifeengine.auth.infrastructure.config.LoginSecurityProperties;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRow;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class AuthAppService {

    private static final Logger SEC = LoggerFactory.getLogger("com.devito.lifeengine.security.http");

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final BoUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final R2dbcEntityTemplate entityTemplate;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtSecurityProperties jwtProps;
    private final SecurityAuditService securityAudit;
    private final SecurityStreamNotifier securityStreamNotifier;
    private final EffectiveAuthorityService effectiveAuthority;
    private final AuthMetricsRecorder metrics;
    private final LoginSecurityProperties loginProps;
    private final GuestAuthProperties guestAuthProperties;
    private final AuthSessionControlAppService sessionControl;
    private final AuthAuditLogAppService authAuditLog;

    public AuthAppService(
            BoUserRepository users,
            RefreshTokenRepository refreshTokens,
            R2dbcEntityTemplate entityTemplate,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            JwtSecurityProperties jwtProps,
            SecurityAuditService securityAudit,
            SecurityStreamNotifier securityStreamNotifier,
            EffectiveAuthorityService effectiveAuthority,
            AuthMetricsRecorder metrics,
            LoginSecurityProperties loginProps,
            GuestAuthProperties guestAuthProperties,
            AuthSessionControlAppService sessionControl,
            AuthAuditLogAppService authAuditLog) {
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.entityTemplate = entityTemplate;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.jwtProps = jwtProps;
        this.securityAudit = securityAudit;
        this.securityStreamNotifier = securityStreamNotifier;
        this.effectiveAuthority = effectiveAuthority;
        this.metrics = metrics;
        this.loginProps = loginProps;
        this.guestAuthProperties = guestAuthProperties;
        this.sessionControl = sessionControl;
        this.authAuditLog = authAuditLog;
    }

    /**
     * Issues the same access + refresh pair as password login (used after Google OAuth completes account
     * resolution / linking).
     */
    public Mono<AuthDtos.LoginResponse> issueSessionAfterOAuth(BoUserRow u, AuditContext ctx) {
        return issueSessionForBoUser(u, ctx, BoLoginChannel.OAUTH_GOOGLE);
    }

    public Mono<AuthDtos.LoginResponse> login(LoginCommand command, AuditContext ctx) {
        SEC.info("auth_http op=login_attempt");
        String email = command.email().trim().toLowerCase(Locale.ROOT);
        return users
                .findByEmailIgnoreCase(email)
                .flatMap(u -> loginExistingUser(u, email, command.password(), ctx))
                .switchIfEmpty(loginUnknownUser(email, ctx));
    }

    private Mono<AuthDtos.LoginResponse> loginUnknownUser(String email, AuditContext ctx) {
        return securityAudit
                .record(
                        SecurityAuditEventType.LOGIN_FAILURE,
                        SecurityAuditService.OUTCOME_FAILURE,
                        null,
                        email,
                        ctx,
                        "invalid_credentials")
                .then(trackLoginFailure(null, email, "invalid_credentials"))
                .then(
                        authAuditLog.record(
                                AuthAuditActions.FAILED_LOGIN,
                                null,
                                ctx,
                                Map.of("reason", "unknown_user", "email", email)))
                .then(loginUnauthorized());
    }

    private Mono<AuthDtos.LoginResponse> loginExistingUser(
            BoUserRow u, String emailNorm, String rawPassword, AuditContext ctx) {
        if (u.getLockedUntil() != null && !u.getLockedUntil().isAfter(Instant.now())) {
            u.setLockedUntil(null);
            u.setFailedLoginAttempts(0);
            return users.save(u).flatMap(fresh -> loginExistingUser(fresh, emailNorm, rawPassword, ctx));
        }
        if (!u.isEnabled()) {
            return securityAudit
                    .record(
                            SecurityAuditEventType.LOGIN_FAILURE,
                            SecurityAuditService.OUTCOME_FAILURE,
                            u.getId(),
                            emailNorm,
                            ctx,
                            "account_disabled")
                    .then(trackLoginFailure(u.getId(), emailNorm, "account_disabled"))
                    .then(
                            authAuditLog.record(
                                    AuthAuditActions.FAILED_LOGIN,
                                    u.getId(),
                                    ctx,
                                    Map.of("reason", "account_disabled", "email", emailNorm)))
                    .then(loginUnauthorized());
        }
        if (u.isLocked()) {
            return securityAudit
                    .record(
                            SecurityAuditEventType.LOGIN_FAILURE,
                            SecurityAuditService.OUTCOME_FAILURE,
                            u.getId(),
                            emailNorm,
                            ctx,
                            "account_locked")
                    .then(trackLoginFailure(u.getId(), emailNorm, "account_locked"))
                    .then(
                            authAuditLog.record(
                                    AuthAuditActions.FAILED_LOGIN,
                                    u.getId(),
                                    ctx,
                                    Map.of("reason", "account_locked", "email", emailNorm)))
                    .then(loginUnauthorized());
        }
        if (u.isTemporarilyLocked()) {
            return securityAudit
                    .record(
                            SecurityAuditEventType.LOGIN_FAILURE,
                            SecurityAuditService.OUTCOME_FAILURE,
                            u.getId(),
                            emailNorm,
                            ctx,
                            "rate_limited")
                    .then(trackLoginFailure(u.getId(), emailNorm, "rate_limited"))
                    .then(
                            authAuditLog.record(
                                    AuthAuditActions.FAILED_LOGIN,
                                    u.getId(),
                                    ctx,
                                    Map.of("reason", "rate_limited", "email", emailNorm)))
                    .then(loginUnauthorized());
        }
        if (!passwordEncoder.matches(rawPassword, u.getPasswordHash())) {
            return recordFailedPasswordAttempt(u, emailNorm, ctx);
        }
        return issueSessionForBoUser(u, ctx, BoLoginChannel.PASSWORD);
    }

    private Mono<AuthDtos.LoginResponse> recordFailedPasswordAttempt(BoUserRow u, String emailNorm, AuditContext ctx) {
        int prev = u.getFailedLoginAttempts() == null ? 0 : u.getFailedLoginAttempts();
        int next = prev + 1;
        u.setFailedLoginAttempts(next);
        int max = Math.max(1, loginProps.getMaxFailedAttempts());
        boolean lockout = next >= max;
        if (lockout) {
            u.setLockedUntil(Instant.now().plus(Math.max(1, loginProps.getLockoutMinutes()), ChronoUnit.MINUTES));
        }
        return users
                .save(u)
                .flatMap(
                        saved ->
                                (lockout
                                                ? securityAudit.record(
                                                        SecurityAuditEventType.LOGIN_TEMP_LOCKOUT,
                                                        SecurityAuditService.OUTCOME_FAILURE,
                                                        saved.getId(),
                                                        emailNorm,
                                                        ctx,
                                                        "attempts="
                                                                + next
                                                                + " lockoutMinutes="
                                                                + loginProps.getLockoutMinutes())
                                                : securityAudit.record(
                                                        SecurityAuditEventType.LOGIN_FAILURE,
                                                        SecurityAuditService.OUTCOME_FAILURE,
                                                        saved.getId(),
                                                        emailNorm,
                                                        ctx,
                                                        "invalid_credentials"))
                                        .then(trackLoginFailure(saved.getId(), emailNorm, lockout ? "lockout" : "invalid_credentials"))
                                        .then(
                                                authAuditLog.record(
                                                        AuthAuditActions.FAILED_LOGIN,
                                                        saved.getId(),
                                                        ctx,
                                                        Map.of(
                                                                "reason",
                                                                lockout ? "lockout" : "invalid_credentials",
                                                                "email",
                                                                emailNorm)))
                                        .then(loginUnauthorized()));
    }

    private static Mono<AuthDtos.LoginResponse> loginUnauthorized() {
        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    public Mono<AuthDtos.LoginResponse> guestSession(AuditContext ctx) {
        if (!guestAuthProperties.isEnabled()) {
            return Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND));
        }
        // TODO(rate-limit): plug shared rate limiting / abuse controls (e.g. Redis, API gateway) keyed by IP + UA.
        UUID guestJwtSubject = UUID.randomUUID();
        UUID refreshSessionId = UUID.randomUUID();
        String email = "guest@life-engine.local";
        String access = jwtService.createAccessToken(guestJwtSubject, email, "GUEST", refreshSessionId);
        String rawRefresh = newRawRefreshToken();
        RefreshTokenRow row = newRefreshTokenRow();
        row.setGuestSessionId(guestJwtSubject);
        row.setSessionId(refreshSessionId);
        row.setTokenHash(RefreshTokenHasher.sha256Hex(rawRefresh));
        row.setExpiresAt(refreshExpiryInstant());
        row.setRevoked(false);
        row.setCreatedAt(Instant.now());
        return insertRefreshToken(row, ctx)
                .doOnSuccess(this::emitSessionCreated)
                .flatMap(
                        saved ->
                                securityAudit
                                        .record(
                                                SecurityAuditEventType.GUEST_SESSION_CREATED,
                                                SecurityAuditService.OUTCOME_SUCCESS,
                                                guestJwtSubject,
                                                email,
                                                ctx,
                                                null)
                                        .then(
                                                Mono.fromRunnable(
                                                        () -> {
                                                            metrics.recordGuestSession();
                                                            AuthObservabilityLogger.info(
                                                                    SecurityAuditEventType.GUEST_SESSION_CREATED,
                                                                    guestJwtSubject,
                                                                    email,
                                                                    null);
                                                        }))
                                        .then(
                                                authAuditLog.record(
                                                        AuthAuditActions.LOGIN,
                                                        guestJwtSubject,
                                                        ctx,
                                                        Map.of("channel", "guest")))
                                        .thenReturn(
                                                new AuthDtos.LoginResponse(
                                                        access,
                                                        "Bearer",
                                                        accessSeconds(),
                                                        rawRefresh,
                                                        refreshExpiresSeconds())));
    }

    public Mono<AuthDtos.LoginResponse> refresh(String rawRefresh, AuditContext ctx) {
        SEC.info("auth_http op=refresh_attempt");
        metrics.recordRefreshAttempt();
        if (rawRefresh == null || rawRefresh.isBlank()) {
            return securityAudit
                    .record(
                            SecurityAuditEventType.REFRESH_FAILURE,
                            SecurityAuditService.OUTCOME_FAILURE,
                            null,
                            null,
                            ctx,
                            "missing_token")
                    .then(trackRefreshFailure(null, null, "missing_token"))
                    .then(refreshUnauthorized());
        }
        String hash = RefreshTokenHasher.sha256Hex(rawRefresh.trim());
        return refreshTokens
                .findValidByHash(hash)
                .flatMap(old -> dispatchValidRefresh(old, ctx))
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        securityAudit
                                                .record(
                                                        SecurityAuditEventType.REFRESH_FAILURE,
                                                        SecurityAuditService.OUTCOME_FAILURE,
                                                        null,
                                                        null,
                                                        ctx,
                                                        "unknown_or_expired")
                                                .then(trackRefreshFailure(null, null, "unknown_or_expired"))
                                                .then(refreshUnauthorized())));
    }

    /**
     * Validates account policy before rotation; burns the presented refresh row when policy forbids rotation
     * so the secret cannot be replayed.
     */
    private Mono<AuthDtos.LoginResponse> dispatchValidRefresh(RefreshTokenRow old, AuditContext ctx) {
        if (old.getBoUserId() != null) {
            return users
                    .findById(old.getBoUserId())
                    .flatMap(
                            u -> {
                                if (!u.isEnabled()) {
                                    return burnRefreshAndFail(
                                            old, ctx, u.getId(), u.getEmail(), "account_disabled");
                                }
                                if (u.isLocked()) {
                                    return burnRefreshAndFail(
                                            old, ctx, u.getId(), u.getEmail(), "account_locked");
                                }
                                return rotateUserRefreshChain(old, u, ctx);
                            })
                    .switchIfEmpty(
                            Mono.defer(
                                    () ->
                                            burnRefreshAndFail(
                                                    old,
                                                    ctx,
                                                    old.getBoUserId(),
                                                    null,
                                                    "user_missing")));
        }
        if (old.getGuestSessionId() != null) {
            return rotateGuestRefreshChain(old, ctx);
        }
        return securityAudit
                .record(
                        SecurityAuditEventType.REFRESH_FAILURE,
                        SecurityAuditService.OUTCOME_FAILURE,
                        null,
                        null,
                        ctx,
                        "invalid_subject")
                .then(trackRefreshFailure(null, null, "invalid_subject"))
                .then(refreshUnauthorized());
    }

    private Mono<AuthDtos.LoginResponse> burnRefreshAndFail(
            RefreshTokenRow old,
            AuditContext ctx,
            UUID auditUserId,
            String auditEmail,
            String detail) {
        old.setRevoked(true);
        return refreshTokens
                .save(old)
                .then(sessionControl.markUserSessionRevokedBySessionId(old.getSessionId()))
                .then(
                        securityAudit.record(
                                SecurityAuditEventType.REFRESH_FAILURE,
                                SecurityAuditService.OUTCOME_FAILURE,
                                auditUserId,
                                auditEmail,
                                ctx,
                                detail))
                .then(trackRefreshFailure(auditUserId, auditEmail, detail))
                .then(refreshUnauthorized());
    }

    private static Mono<AuthDtos.LoginResponse> refreshUnauthorized() {
        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    private Mono<AuthDtos.LoginResponse> rotateUserRefreshChain(RefreshTokenRow old, BoUserRow u, AuditContext ctx) {
        UUID auditUserId = u.getId();
        String auditEmail = u.getEmail();
        old.setRevoked(true);
        UUID chainSessionId = old.getSessionId() != null ? old.getSessionId() : old.getId();
        return refreshTokens
                .save(old)
                .then(Mono.defer(() -> rotateForUser(u, ctx, chainSessionId)))
                .flatMap(
                        resp ->
                                securityAudit
                                        .record(
                                                SecurityAuditEventType.REFRESH_SUCCESS,
                                                SecurityAuditService.OUTCOME_SUCCESS,
                                                auditUserId,
                                                auditEmail,
                                                ctx,
                                                null)
                                        .then(trackRefreshSuccess(auditUserId, auditEmail, false))
                                        .then(
                                                authAuditLog.record(
                                                        AuthAuditActions.REFRESH,
                                                        auditUserId,
                                                        ctx,
                                                        Map.of("guest", "false")))
                                        .thenReturn(resp));
    }

    private Mono<AuthDtos.LoginResponse> rotateGuestRefreshChain(RefreshTokenRow old, AuditContext ctx) {
        UUID auditId = old.getGuestSessionId();
        old.setRevoked(true);
        UUID chainSessionId = old.getSessionId() != null ? old.getSessionId() : old.getId();
        return refreshTokens
                .save(old)
                .then(Mono.defer(() -> rotateForGuest(auditId, ctx, chainSessionId)))
                .flatMap(
                        resp ->
                                securityAudit
                                        .record(
                                                SecurityAuditEventType.REFRESH_SUCCESS,
                                                SecurityAuditService.OUTCOME_SUCCESS,
                                                auditId,
                                                "guest@life-engine.local",
                                                ctx,
                                                null)
                                        .then(trackRefreshSuccess(auditId, "guest@life-engine.local", true))
                                        .then(
                                                authAuditLog.record(
                                                        AuthAuditActions.REFRESH,
                                                        auditId,
                                                        ctx,
                                                        Map.of("guest", "true")))
                                        .thenReturn(resp));
    }

    private Mono<AuthDtos.LoginResponse> rotateForUser(BoUserRow u, AuditContext ctx, UUID sessionId) {
        if (!u.isEnabled()) {
            return securityAudit
                    .record(
                            SecurityAuditEventType.REFRESH_FAILURE,
                            SecurityAuditService.OUTCOME_FAILURE,
                            u.getId(),
                            u.getEmail(),
                            ctx,
                            "account_disabled")
                    .then(trackRefreshFailure(u.getId(), u.getEmail(), "account_disabled"))
                    .then(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
        }
        if (u.isLocked()) {
            return securityAudit
                    .record(
                            SecurityAuditEventType.REFRESH_FAILURE,
                            SecurityAuditService.OUTCOME_FAILURE,
                            u.getId(),
                            u.getEmail(),
                            ctx,
                            "account_locked")
                    .then(trackRefreshFailure(u.getId(), u.getEmail(), "account_locked"))
                    .then(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
        }
        return effectiveAuthority
                .resolvePrimaryRoleCode(u.getId())
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        securityAudit
                                                .record(
                                                        SecurityAuditEventType.REFRESH_FAILURE,
                                                        SecurityAuditService.OUTCOME_FAILURE,
                                                        u.getId(),
                                                        u.getEmail(),
                                                        ctx,
                                                        "rbac_incomplete_no_bo_user_role")
                                                .then(trackRefreshFailure(u.getId(), u.getEmail(), "rbac_incomplete_no_bo_user_role"))
                                                .then(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "rbac_incomplete")))))
                .flatMap(
                        primaryRole ->
                                effectiveAuthority
                                        .resolvePermissionCodesForBoUser(u.getId())
                                        .flatMap(
                                                perms -> {
                                                    String access =
                                                            jwtService.createAccessToken(
                                                                    u.getId(),
                                                                    u.getEmail(),
                                                                    primaryRole,
                                                                    perms,
                                                                    sessionId);
                                                    String rawRefresh = newRawRefreshToken();
                                                    RefreshTokenRow n = newRefreshTokenRow();
                                                    n.setSessionId(sessionId);
                                                    n.setBoUserId(u.getId());
                                                    n.setTokenHash(RefreshTokenHasher.sha256Hex(rawRefresh));
                                                    n.setExpiresAt(refreshExpiryInstant());
                                                    n.setRevoked(false);
                                                    n.setCreatedAt(Instant.now());
                                                    return insertRefreshToken(n, ctx)
                                                            .map(
                                                                    saved ->
                                                                            new AuthDtos.LoginResponse(
                                                                                    access,
                                                                                    "Bearer",
                                                                                    accessSeconds(),
                                                                                    rawRefresh,
                                                                                    refreshExpiresSeconds()));
                                                }));
    }

    private Mono<AuthDtos.LoginResponse> rotateForGuest(
            UUID guestJwtSubject, AuditContext ctx, UUID refreshSessionId) {
        String access =
                jwtService.createAccessToken(
                        guestJwtSubject,
                        "guest@life-engine.local",
                        "GUEST",
                        List.of("ROLE_GUEST"),
                        refreshSessionId);
        String rawRefresh = newRawRefreshToken();
        RefreshTokenRow n = newRefreshTokenRow();
        n.setSessionId(refreshSessionId);
        n.setGuestSessionId(guestJwtSubject);
        n.setTokenHash(RefreshTokenHasher.sha256Hex(rawRefresh));
        n.setExpiresAt(refreshExpiryInstant());
        n.setRevoked(false);
        n.setCreatedAt(Instant.now());
        return insertRefreshToken(n, ctx)
                .map(
                        saved ->
                                new AuthDtos.LoginResponse(
                                        access, "Bearer", accessSeconds(), rawRefresh, refreshExpiresSeconds()));
    }

    public Mono<Void> logout(String rawRefresh, AuditContext ctx) {
        return revokeRefreshInternal(rawRefresh, ctx, SecurityAuditEventType.LOGOUT);
    }

    /** Self-service revoke — same persistence as logout; audit distinguishes intent for operators. */
    public Mono<Void> revoke(String rawRefresh, AuditContext ctx) {
        return revokeRefreshInternal(rawRefresh, ctx, SecurityAuditEventType.TOKEN_REVOKED);
    }

    private Mono<Void> revokeRefreshInternal(String rawRefresh, AuditContext ctx, String auditType) {
        SEC.info("auth_http op=revoke_attempt auditType={}", auditType);
        if (rawRefresh == null || rawRefresh.isBlank()) {
            return Mono.empty();
        }
        String hash = RefreshTokenHasher.sha256Hex(rawRefresh.trim());
        return refreshTokens
                .findValidByHash(hash)
                .flatMap(
                        row -> {
                            row.setRevoked(true);
                            UUID uid = row.getBoUserId() != null ? row.getBoUserId() : row.getGuestSessionId();
                            String email =
                                    row.getBoUserId() != null ? null : "guest@life-engine.local";
                            return refreshTokens
                                    .save(row)
                                    .then(sessionControl.markUserSessionRevokedBySessionId(row.getSessionId()))
                                    .then(
                                            securityAudit
                                                    .record(
                                                            auditType,
                                                            SecurityAuditService.OUTCOME_SUCCESS,
                                                            uid,
                                                            email,
                                                            ctx,
                                                            null)
                                                    .then(
                                                            Mono.fromRunnable(
                                                                    () -> {
                                                                        if (SecurityAuditEventType.LOGOUT.equals(
                                                                                auditType)) {
                                                                            metrics.recordRevokeLogout();
                                                                            AuthObservabilityLogger.info(
                                                                                    SecurityAuditEventType.LOGOUT,
                                                                                    uid,
                                                                                    email,
                                                                                    null);
                                                                        } else {
                                                                            metrics.recordRevokeToken();
                                                                            AuthObservabilityLogger.info(
                                                                                    SecurityAuditEventType
                                                                                            .TOKEN_REVOKED,
                                                                                    uid,
                                                                                    email,
                                                                                    null);
                                                                        }
                                                                    })))
                                    .then(
                                            SecurityAuditEventType.LOGOUT.equals(auditType)
                                                    ? authAuditLog.record(
                                                            AuthAuditActions.LOGOUT,
                                                            uid,
                                                            ctx,
                                                            Map.of(
                                                                    "sessionId",
                                                                    row.getSessionId() == null
                                                                            ? ""
                                                                            : row.getSessionId().toString()))
                                                    : authAuditLog.record(
                                                            AuthAuditActions.SESSION_REVOKED,
                                                            uid,
                                                            ctx,
                                                            Map.of(
                                                                    "sessionId",
                                                                    row.getSessionId() == null
                                                                            ? ""
                                                                            : row.getSessionId().toString())));
                        })
                .then();
    }

    public AuthDtos.MeResponse me(BoUserPrincipal principal) {
        return new AuthDtos.MeResponse(
                principal.userId().toString(),
                principal.email(),
                principal.primaryRole(),
                principal.authorities());
    }

    public Flux<AuthDtos.UserSessionDto> listOperatorSessions(BoUserPrincipal principal) {
        return sessionControl.listSessions(principal);
    }

    public Mono<Void> revokeOperatorSession(BoUserPrincipal principal, UUID sessionId, AuditContext ctx) {
        return sessionControl.revokeSessionForPrincipal(principal, sessionId, ctx);
    }

    public Mono<Void> logoutAllSessions(BoUserPrincipal principal, AuditContext ctx) {
        return sessionControl.logoutAll(principal, ctx);
    }

    /**
     * Snapshot of the refresh-backed session matching the access token’s {@code sid} claim (no secrets).
     */
    public Mono<AuthDtos.SessionSnapshotDto> currentSession(BoUserPrincipal principal) {
        if (principal.sessionId() == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "session not bound"));
        }
        return refreshTokens
                .findLatestActiveBySessionId(principal.sessionId())
                .flatMap(
                        r -> {
                            if (r.getBoUserId() != null) {
                                if (!r.getBoUserId().equals(principal.userId())) {
                                    return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN));
                                }
                            } else if (r.getGuestSessionId() != null) {
                                if (!r.getGuestSessionId().equals(principal.userId())) {
                                    return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN));
                                }
                            } else {
                                return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN));
                            }
                            String ip = r.getClientIp() != null ? r.getClientIp() : "";
                            String ua = r.getClientUserAgent();
                            String device = ua == null || ua.isBlank() ? "" : abbreviateUserAgent(ua);
                            Instant last =
                                    r.getLastSeenAt() != null ? r.getLastSeenAt() : r.getCreatedAt();
                            Instant accessExp =
                                    last.plus(jwtProps.getAccessTokenValidityMinutes(), ChronoUnit.MINUTES);
                            return Mono.just(
                                    new AuthDtos.SessionSnapshotDto(
                                            r.getSessionId(),
                                            "ACTIVE",
                                            r.getExpiresAt(),
                                            accessExp,
                                            last,
                                            ip,
                                            device));
                        })
                .switchIfEmpty(
                        Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "session not found")));
    }

    /**
     * Revokes every other active refresh row for the same BO user as {@code rawRefresh}; keeps the presented
     * session. Guest sessions are not supported.
     */
    public Mono<Void> changePassword(
            BoUserPrincipal principal,
            String currentPassword,
            String newPassword,
            boolean revokeOtherSessions,
            String refreshTokenForRevokeOthers,
            AuditContext ctx) {
        return users
                .findById(principal.userId())
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .flatMap(
                        u -> {
                            if (u.getPasswordHash() == null || u.getPasswordHash().isBlank()) {
                                return Mono.error(
                                        new ResponseStatusException(
                                                HttpStatus.BAD_REQUEST, "password_not_configured"));
                            }
                            if (!passwordEncoder.matches(currentPassword, u.getPasswordHash())) {
                                return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bad_credentials"));
                            }
                            PasswordPolicy.validate(newPassword, u.getEmail());
                            if (passwordEncoder.matches(newPassword, u.getPasswordHash())) {
                                return Mono.error(
                                        new ResponseStatusException(HttpStatus.BAD_REQUEST, "password_unchanged"));
                            }
                            u.setPasswordHash(passwordEncoder.encode(newPassword));
                            u.setPasswordChangedAt(Instant.now());
                            u.setFailedLoginAttempts(0);
                            u.setLockedUntil(null);
                            /*
                             * Product contract: password change ends every server-side session for this principal
                             * (refresh rows + user_sessions), including the caller — client must re-authenticate.
                             * {@code revokeOtherSessions} / {@code refreshToken} on the request are ignored.
                             */
                            Mono<Void> afterSave =
                                    securityAudit
                                            .record(
                                                    SecurityAuditEventType.USER_PASSWORD_CHANGED,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    u.getId(),
                                                    u.getEmail(),
                                                    ctx,
                                                    "self_all_sessions_revoked")
                                            .then(sessionControl.logoutAll(principal, ctx));
                            return users.save(u).then(afterSave);
                        });
    }

    public Mono<Void> revokeOtherSessions(String rawRefresh, AuditContext ctx) {
        SEC.info("auth_http op=revoke_other_sessions_attempt");
        if (rawRefresh == null || rawRefresh.isBlank()) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "refreshToken required"));
        }
        String hash = RefreshTokenHasher.sha256Hex(rawRefresh.trim());
        return refreshTokens
                .findValidByHash(hash)
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        securityAudit
                                                .record(
                                                        SecurityAuditEventType.REFRESH_FAILURE,
                                                        SecurityAuditService.OUTCOME_FAILURE,
                                                        null,
                                                        null,
                                                        ctx,
                                                        "unknown_or_expired")
                                                .then(trackRefreshFailure(null, null, "unknown_or_expired"))
                                                .then(
                                                        Mono.error(
                                                                new ResponseStatusException(
                                                                        HttpStatus.UNAUTHORIZED)))))
                .flatMap(
                        keep -> {
                            if (keep.getBoUserId() == null) {
                                return securityAudit
                                        .record(
                                                SecurityAuditEventType.REFRESH_FAILURE,
                                                SecurityAuditService.OUTCOME_FAILURE,
                                                null,
                                                null,
                                                ctx,
                                                "revoke_others_guest_not_supported")
                                        .then(
                                                trackRefreshFailure(
                                                        null, null, "revoke_others_guest_not_supported"))
                                        .then(
                                                Mono.error(
                                                        new ResponseStatusException(
                                                                HttpStatus.BAD_REQUEST, "unsupported")));
                            }
                            UUID keepSid = keep.getSessionId();
                            if (keepSid == null) {
                                return securityAudit
                                        .record(
                                                SecurityAuditEventType.REFRESH_FAILURE,
                                                SecurityAuditService.OUTCOME_FAILURE,
                                                keep.getBoUserId(),
                                                null,
                                                ctx,
                                                "revoke_others_missing_session")
                                        .then(
                                                trackRefreshFailure(
                                                        keep.getBoUserId(),
                                                        null,
                                                        "revoke_others_missing_session"))
                                        .then(
                                                Mono.error(
                                                        new ResponseStatusException(
                                                                HttpStatus.BAD_REQUEST, "unsupported")));
                            }
                            UUID uid = keep.getBoUserId();
                            return refreshTokens
                                    .findActiveByBoUserExcludingSession(uid, keepSid)
                                    .concatMap(
                                            row -> {
                                                row.setRevoked(true);
                                                return refreshTokens
                                                        .save(row)
                                                        .then(
                                                                sessionControl.markUserSessionRevokedBySessionId(
                                                                        row.getSessionId()));
                                            })
                                    .then(
                                            securityAudit
                                                    .record(
                                                            SecurityAuditEventType.OTHER_SESSIONS_REVOKED,
                                                            SecurityAuditService.OUTCOME_SUCCESS,
                                                            uid,
                                                            null,
                                                            ctx,
                                                            "keptSessionId=" + keepSid)
                                                    .then(
                                                            Mono.fromRunnable(
                                                                    () -> {
                                                                        metrics.recordRevokeOthers();
                                                                        AuthObservabilityLogger.info(
                                                                                SecurityAuditEventType
                                                                                        .OTHER_SESSIONS_REVOKED,
                                                                                uid,
                                                                                null,
                                                                                "keptSessionId=" + keepSid);
                                                                    })))
                                    .then();
                        });
    }

    private static String abbreviateUserAgent(String ua) {
        int max = 120;
        return ua.length() <= max ? ua : ua.substring(0, max) + "…";
    }

    private Mono<AuthDtos.LoginResponse> issueSessionForBoUser(BoUserRow u, AuditContext ctx, BoLoginChannel channel) {
        if (!u.isEnabled()) {
            return securityAudit
                    .record(
                            SecurityAuditEventType.LOGIN_FAILURE,
                            SecurityAuditService.OUTCOME_FAILURE,
                            u.getId(),
                            u.getEmail(),
                            ctx,
                            "account_disabled")
                    .then(trackLoginFailure(u.getId(), u.getEmail(), "account_disabled"))
                    .then(loginUnauthorized());
        }
        if (u.isLocked()) {
            return securityAudit
                    .record(
                            SecurityAuditEventType.LOGIN_FAILURE,
                            SecurityAuditService.OUTCOME_FAILURE,
                            u.getId(),
                            u.getEmail(),
                            ctx,
                            "account_locked")
                    .then(trackLoginFailure(u.getId(), u.getEmail(), "account_locked"))
                    .then(loginUnauthorized());
        }
        u.setFailedLoginAttempts(0);
        u.setLockedUntil(null);
        UUID sessionId = UUID.randomUUID();
        return users
                .save(u)
                .flatMap(
                        fresh ->
                                sessionControl
                                        .enforceMaxSessionsBeforeNewBoLogin(fresh.getId(), ctx)
                                        .then(
                                                effectiveAuthority
                                                        .resolvePrimaryRoleCode(fresh.getId())
                                                        .switchIfEmpty(
                                                                Mono.defer(
                                                                        () ->
                                                                                securityAudit
                                                                                        .record(
                                                                                                SecurityAuditEventType
                                                                                                        .LOGIN_FAILURE,
                                                                                                SecurityAuditService
                                                                                                        .OUTCOME_FAILURE,
                                                                                                fresh.getId(),
                                                                                                fresh.getEmail(),
                                                                                                ctx,
                                                                                                "rbac_incomplete_no_bo_user_role")
                                                                                        .then(
                                                                                                trackLoginFailure(
                                                                                                        fresh.getId(),
                                                                                                        fresh.getEmail(),
                                                                                                        "rbac_incomplete_no_bo_user_role"))
                                                                                        .then(
                                                                                                Mono.error(
                                                                                                        new ResponseStatusException(
                                                                                                                HttpStatus.UNAUTHORIZED,
                                                                                                                "rbac_incomplete")))))
                                                        .flatMap(
                                                                primaryRole ->
                                                                        effectiveAuthority
                                                                                .resolvePermissionCodesForBoUser(
                                                                                        fresh.getId())
                                                                                .flatMap(
                                                                                        perms -> {
                                                                                            String access =
                                                                                                    jwtService
                                                                                                            .createAccessToken(
                                                                                                                    fresh.getId(),
                                                                                                                    fresh.getEmail(),
                                                                                                                    primaryRole,
                                                                                                                    perms,
                                                                                                                    sessionId);
                                                                                            String rawRefresh =
                                                                                                    newRawRefreshToken();
                                                                                            RefreshTokenRow row =
                                                                                                    newRefreshTokenRow();
                                                                                            row.setSessionId(sessionId);
                                                                                            row.setBoUserId(fresh.getId());
                                                                                            row.setTokenHash(
                                                                                                    RefreshTokenHasher
                                                                                                            .sha256Hex(
                                                                                                                    rawRefresh));
                                                                                            row.setExpiresAt(
                                                                                                    refreshExpiryInstant());
                                                                                            row.setRevoked(false);
                                                                                            row.setCreatedAt(
                                                                                                    Instant.now());
                                                                                            return insertRefreshToken(
                                                                                                            row, ctx)
                                                                                                    .doOnSuccess(
                                                                                                            this::
                                                                                                                    emitSessionCreated)
                                                                                                    .flatMap(
                                                                                                            saved ->
                                                                                                                    securityAudit
                                                                                                                            .record(
                                                                                                                                    channel
                                                                                                                                                    == BoLoginChannel
                                                                                                                                                            .OAUTH_GOOGLE
                                                                                                                                            ? SecurityAuditEventType
                                                                                                                                                    .GOOGLE_LOGIN_SUCCESS
                                                                                                                                            : SecurityAuditEventType
                                                                                                                                                    .LOGIN_SUCCESS,
                                                                                                                                    SecurityAuditService
                                                                                                                                            .OUTCOME_SUCCESS,
                                                                                                                                    fresh.getId(),
                                                                                                                                    fresh.getEmail(),
                                                                                                                                    ctx,
                                                                                                                                    channel
                                                                                                                                                    == BoLoginChannel
                                                                                                                                                            .OAUTH_GOOGLE
                                                                                                                                            ? "provider=google"
                                                                                                                                            : null)
                                                                                                                            .then(
                                                                                                                                    Mono.fromRunnable(
                                                                                                                                            () -> {
                                                                                                                                                metrics.recordLoginSuccess();
                                                                                                                                                AuthObservabilityLogger
                                                                                                                                                        .info(
                                                                                                                                                                channel
                                                                                                                                                                                == BoLoginChannel
                                                                                                                                                                                        .OAUTH_GOOGLE
                                                                                                                                                                        ? SecurityAuditEventType
                                                                                                                                                                                .GOOGLE_LOGIN_SUCCESS
                                                                                                                                                                        : SecurityAuditEventType
                                                                                                                                                                                .LOGIN_SUCCESS,
                                                                                                                                                                fresh.getId(),
                                                                                                                                                                fresh.getEmail(),
                                                                                                                                                                channel
                                                                                                                                                                                == BoLoginChannel
                                                                                                                                                                                        .OAUTH_GOOGLE
                                                                                                                                                                        ? "provider=google"
                                                                                                                                                                        : null);
                                                                                                                                            }))
                                                                                                                            .then(
                                                                                                                                    authAuditLog
                                                                                                                                            .record(
                                                                                                                                                    AuthAuditActions
                                                                                                                                                            .LOGIN,
                                                                                                                                                    fresh.getId(),
                                                                                                                                                    ctx,
                                                                                                                                                    Map.of(
                                                                                                                                                            "channel",
                                                                                                                                                            channel
                                                                                                                                                                            == BoLoginChannel
                                                                                                                                                                                    .OAUTH_GOOGLE
                                                                                                                                                                    ? "oauth_google"
                                                                                                                                                                    : "password")))
                                                                                                                            .thenReturn(
                                                                                                                                    new AuthDtos.LoginResponse(
                                                                                                                                            access,
                                                                                                                                            "Bearer",
                                                                                                                                            accessSeconds(),
                                                                                                                                            rawRefresh,
                                                                                                                                            refreshExpiresSeconds())));
                                                                                        }))
                                                                        ));
    }

    private Mono<Void> trackLoginFailure(UUID userId, String email, String detail) {
        return Mono.fromRunnable(
                () -> {
                    metrics.recordLoginFailure();
                    AuthObservabilityLogger.warn(SecurityAuditEventType.LOGIN_FAILURE, userId, email, detail);
                });
    }

    private Mono<Void> trackRefreshFailure(UUID userId, String email, String detail) {
        return Mono.fromRunnable(
                () -> {
                    metrics.recordRefreshFailure();
                    AuthObservabilityLogger.warn(SecurityAuditEventType.REFRESH_FAILURE, userId, email, detail);
                });
    }

    private Mono<Void> trackRefreshSuccess(UUID userId, String email, boolean guest) {
        return Mono.fromRunnable(
                () -> {
                    metrics.recordRefreshSuccess();
                    AuthObservabilityLogger.info(
                            SecurityAuditEventType.REFRESH_SUCCESS,
                            userId,
                            email,
                            guest ? "subject=guest" : "subject=user");
                });
    }

    private void emitSessionCreated(RefreshTokenRow saved) {
        UUID principalId =
                saved.getBoUserId() != null
                        ? saved.getBoUserId()
                        : saved.getGuestSessionId();
        Map<String, Object> payload = new HashMap<>();
        payload.put("tokenRowId", saved.getId().toString());
        securityStreamNotifier.notifyDomain(
                "session_created",
                List.of("sessions", "tokens", "users", "risk"),
                saved.getSessionId(),
                principalId,
                payload);
    }

    private static RefreshTokenRow newRefreshTokenRow() {
        RefreshTokenRow row = new RefreshTokenRow();
        row.setId(UUID.randomUUID());
        return row;
    }

    /**
     * Spring Data R2DBC {@code save()} issues UPDATE when {@code @Id} is set; new rows must use INSERT.
     */
    private Mono<RefreshTokenRow> insertRefreshToken(RefreshTokenRow row, AuditContext ctx) {
        if (ctx != null) {
            row.setClientIp(ctx.ip());
            row.setClientUserAgent(ctx.userAgent());
        }
        row.setLastSeenAt(Instant.now());
        return entityTemplate
                .insert(row)
                .flatMap(
                        saved ->
                                sessionControl
                                        .syncUserSessionAfterRefreshInsert(saved, ctx)
                                        .thenReturn(saved));
    }

    private static String newRawRefreshToken() {
        byte[] b = new byte[48];
        SECURE_RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private Instant refreshExpiryInstant() {
        return Instant.now().plus(jwtProps.getRefreshTokenValidityDays(), ChronoUnit.DAYS);
    }

    private int refreshExpiresSeconds() {
        return Math.toIntExact(jwtProps.getRefreshTokenValidityDays() * 24L * 3600L);
    }

    private int accessSeconds() {
        return jwtProps.getAccessTokenValidityMinutes() * 60;
    }
}
