package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.RbacDtos.RoleSummaryDto;
import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos;
import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos.SecurityAuditLogDto;
import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos.SecuritySessionDto;
import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos.SecurityTokenDto;
import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos.IdpLinkViewDto;
import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos.SecurityUserDto;
import com.devito.lifeengine.platform.PlatformRoles;
import com.devito.lifeengine.auth.application.SecurityRiskComputation.SessionRiskView;
import com.devito.lifeengine.auth.application.SecurityRiskComputation.UserRiskView;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.config.JwtSecurityProperties;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserIdentityProviderRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserIdentityProviderRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRow;
import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.SecurityAuditRow;
import com.devito.lifeengine.auth.infrastructure.persistence.UserLastLoginRow;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class SecurityControlPlaneAppService {

    private static final int DEFAULT_AUDIT_LIMIT = 500;
    private static final int DEFAULT_TOKEN_LIMIT = 500;

    /**
     * Allowed single-role codes for control-plane PATCH (must exist in {@code auth_role}). {@code RbacAppService}
     * persists {@code bo_user_role} only (RBAC is the sole assignment store).
     */
    private static final Set<String> ASSIGNABLE_BO_ROLES =
            Set.of("ADMIN", "USER", "GUEST", "BO_ADMIN", "OPERATOR", "VIEWER");

    private static final Pattern ROLE_TOKEN = Pattern.compile("^[A-Z][A-Z0-9_]{0,31}$");

    private final BoUserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final SecurityAuditRepository audit;
    private final SecurityRiskSignalsService riskSignals;
    private final SecurityStreamNotifier streamNotifier;
    private final SecurityAuditService securityAudit;
    private final RbacAppService rbac;
    private final BoUserIdentityProviderRepository identityProviders;
    private final JwtSecurityProperties jwtSecurityProperties;
    private final AuthObservabilityAppService authObservability;
    private final AdminMetricsRecorder adminMetrics;
    private final EffectiveAuthorityService effectiveAuthority;

    public SecurityControlPlaneAppService(
            BoUserRepository users,
            RefreshTokenRepository refreshTokens,
            SecurityAuditRepository audit,
            SecurityRiskSignalsService riskSignals,
            SecurityStreamNotifier streamNotifier,
            SecurityAuditService securityAudit,
            RbacAppService rbac,
            BoUserIdentityProviderRepository identityProviders,
            JwtSecurityProperties jwtSecurityProperties,
            AuthObservabilityAppService authObservability,
            AdminMetricsRecorder adminMetrics,
            EffectiveAuthorityService effectiveAuthority) {
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.audit = audit;
        this.riskSignals = riskSignals;
        this.streamNotifier = streamNotifier;
        this.securityAudit = securityAudit;
        this.rbac = rbac;
        this.identityProviders = identityProviders;
        this.jwtSecurityProperties = jwtSecurityProperties;
        this.authObservability = authObservability;
        this.adminMetrics = adminMetrics;
        this.effectiveAuthority = effectiveAuthority;
    }

    public Mono<SecurityControlPlaneDtos.SecurityDashboardDto> dashboardSnapshot() {
        Instant since24h = Instant.now().minus(24, ChronoUnit.HOURS);
        return Mono.zip(
                        authObservability.overview(),
                        refreshTokens.countDistinctBoUsersWithActiveSession(),
                        audit.countGuestSessionsSince(since24h),
                        audit.countRefreshSuccessSince(since24h))
                .map(
                        t -> {
                            var overview = t.getT1();
                            long distinctUsers = nz(t.getT2());
                            long guest24 = nz(t.getT3());
                            long refresh24 = nz(t.getT4());
                            String band =
                                    dashboardHealthBand(
                                            overview.loginFailure24h(),
                                            overview.lockedAccounts(),
                                            guest24);
                            return new SecurityControlPlaneDtos.SecurityDashboardDto(
                                    overview.generatedAt(),
                                    overview.activeSessionsDistinct(),
                                    distinctUsers,
                                    guest24,
                                    refresh24,
                                    overview.loginFailure24h(),
                                    overview.lockedAccounts(),
                                    overview.activeRefreshRows(),
                                    overview.countersLifetime().guestSessions(),
                                    band);
                        });
    }

    public Flux<SecurityUserDto> listUsers() {
        return users
                .findAllOrderByCreatedAtDesc()
                .collectList()
                .flatMapMany(
                        list -> {
                            if (list.isEmpty()) {
                                return Flux.empty();
                            }
                            List<UUID> ids = list.stream().map(BoUserRow::getId).toList();
                            Mono<Map<UUID, Instant>> lastLoginsMono =
                                    audit.findLastLoginSuccessAggregatedByUserIds(ids)
                                            .collectMap(UserLastLoginRow::getUserId, UserLastLoginRow::getLastLogin);
                            Mono<Map<UUID, List<IdpLinkViewDto>>> idpViewsMono =
                                    identityProviders
                                            .findByBoUserIdIn(ids)
                                            .collectMultimap(
                                                    BoUserIdentityProviderRow::getBoUserId,
                                                    Function.identity())
                                            .map(
                                                    m -> {
                                                        Map<UUID, List<IdpLinkViewDto>> out = new HashMap<>();
                                                        m.forEach((k, v) -> out.put(k, toIdpViews(v)));
                                                        return out;
                                                    });
                            Mono<Map<UUID, String>> primaryRoleByUserMono =
                                    Flux.fromIterable(ids)
                                            .flatMap(
                                                    uid ->
                                                            effectiveAuthority
                                                                    .resolvePrimaryRoleCode(uid)
                                                                    .map(code -> Map.entry(uid, code))
                                                                    .switchIfEmpty(
                                                                            Mono.just(
                                                                                    new AbstractMap.SimpleEntry<>(
                                                                                            uid, null))))
                                            .collectMap(Map.Entry::getKey, Map.Entry::getValue);
                            return Mono.zip(riskSignals.compute(), lastLoginsMono, idpViewsMono, primaryRoleByUserMono)
                                    .flatMapMany(
                                            t -> {
                                                SecurityRiskComputation comp = t.getT1();
                                                Map<UUID, Instant> lastByUser = t.getT2();
                                                Map<UUID, List<IdpLinkViewDto>> idps = t.getT3();
                                                Map<UUID, String> primaryRoleByUser = t.getT4();
                                                return Flux.fromIterable(list)
                                                        .map(
                                                                u ->
                                                                        toUserDto(
                                                                                u,
                                                                                comp,
                                                                                lastByUser.get(u.getId()),
                                                                                idps.getOrDefault(
                                                                                        u.getId(), List.of()),
                                                                                primaryRoleByUser.get(u.getId())));
                                            });
                        });
    }

    public Mono<SecurityUserDto> getUser(UUID id) {
        return users
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u -> {
                            List<UUID> ids = List.of(id);
                            Mono<Map<UUID, Instant>> lastLoginsMono =
                                    audit.findLastLoginSuccessAggregatedByUserIds(ids)
                                            .collectMap(UserLastLoginRow::getUserId, UserLastLoginRow::getLastLogin);
                            Mono<Map<UUID, List<IdpLinkViewDto>>> idpViewsMono =
                                    identityProviders
                                            .findByBoUserIdIn(ids)
                                            .collectMultimap(
                                                    BoUserIdentityProviderRow::getBoUserId,
                                                    Function.identity())
                                            .map(
                                                    m -> {
                                                        Map<UUID, List<IdpLinkViewDto>> out = new HashMap<>();
                                                        m.forEach((k, v) -> out.put(k, toIdpViews(v)));
                                                        return out;
                                                    });
                            return Mono.zip(
                                            riskSignals.compute(),
                                            lastLoginsMono,
                                            idpViewsMono,
                                            effectiveAuthority
                                                    .resolvePrimaryRoleCode(id)
                                                    .map(Optional::of)
                                                    .switchIfEmpty(Mono.just(Optional.<String>empty())))
                                    .map(
                                            t ->
                                                    toUserDto(
                                                            u,
                                                            t.getT1(),
                                                            t.getT2().get(id),
                                                            t.getT3().getOrDefault(id, List.of()),
                                                            t.getT4().orElse(null)));
                        });
    }

    /**
     * Revokes all refresh rows, clears password material, resets brute-force counters — user may sign in again
     * via linked IdP (e.g. Google) or after an operator sets a password through supported flows.
     */
    public Mono<Void> forcePasswordReset(UUID id, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u ->
                                killAllSessionsForUser(id, actor, ctx)
                                        .then(
                                                users
                                                        .findById(id)
                                                        .switchIfEmpty(
                                                                Mono.error(
                                                                        new ResponseStatusException(
                                                                                HttpStatus.NOT_FOUND,
                                                                                "user not found")))
                                                        .flatMap(
                                                                fresh -> {
                                                                    fresh.setPasswordHash(null);
                                                                    fresh.setFailedLoginAttempts(0);
                                                                    fresh.setLockedUntil(null);
                                                                    return users.save(fresh);
                                                                }))
                                        .flatMap(
                                                saved ->
                                                        securityAudit.record(
                                                                SecurityAuditEventType.ADMIN_PASSWORD_RESET_FORCED,
                                                                SecurityAuditService.OUTCOME_SUCCESS,
                                                                id,
                                                                saved.getEmail(),
                                                                ctx,
                                                                actorDetail(actor)))
                                        .then(
                                                Mono.fromRunnable(
                                                        () ->
                                                                streamNotifier.notifyDomain(
                                                                        "password_reset_forced",
                                                                        List.of(
                                                                                "users",
                                                                                "sessions",
                                                                                "tokens",
                                                                                "risk",
                                                                                "audit"),
                                                                        id,
                                                                        id,
                                                                        Map.of())))
                                        .then(Mono.fromRunnable(adminMetrics::recordPasswordResetForced)));
    }

    /**
     * Operator-facing catalog — persisted {@code auth_role} rows (same source as {@code GET /api/auth/roles} via
     * {@link RbacAppService#listRoles()}). {@code /api/security/roles} stays ADMIN-only; RBAC CRUD remains under
     * {@code /api/auth/roles} with {@code AUTH:RBAC:MANAGE}.
     */
    public Flux<SecurityControlPlaneDtos.SecurityRoleDto> listRoles() {
        return rbac.listRoles().map(SecurityControlPlaneAppService::toSecurityRoleCatalogDto);
    }

    private static SecurityControlPlaneDtos.SecurityRoleDto toSecurityRoleCatalogDto(RoleSummaryDto r) {
        String description =
                r.systemRole()
                        ? "Predefined system role (auth_role)."
                        : "Custom role (auth_role).";
        return new SecurityControlPlaneDtos.SecurityRoleDto(
                r.id(),
                r.code(),
                r.name(),
                description,
                PlatformRoles.toAuthority(r.code()),
                r.systemRole(),
                r.createdAt());
    }

    /** Latest active refresh row for a {@code session_id} (same projection as session list). */
    public Mono<SecuritySessionDto> getSession(UUID sessionId) {
        return refreshTokens
                .findLatestActiveBySessionId(sessionId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "session not found")))
                .flatMap(
                        r ->
                                riskSignals
                                        .computeForActiveSessions(List.of(r))
                                        .flatMap(comp -> toSessionDto(r, comp)));
    }

    public Mono<Void> updateUserRole(UUID id, String requestedRole, BoUserPrincipal actor, AuditContext ctx) {
        String normalized = normalizeBoAssignableRole(requestedRole);
        if (normalized == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid role"));
        }
        return users
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u ->
                                effectiveAuthority
                                        .resolvePrimaryRoleCode(id)
                                        .map(s -> s.trim().toUpperCase(Locale.ROOT))
                                        .defaultIfEmpty("")
                                        .flatMap(
                                                current -> {
                                                    if (current.equals(normalized)) {
                                                        return Mono.<Void>empty();
                                                    }
                                                    return rbac
                                                            .syncUserToSingleRole(id, normalized)
                                                            .then(
                                                                    securityAudit.record(
                                                                            SecurityAuditEventType
                                                                                    .ADMIN_USER_ROLE_CHANGED,
                                                                            SecurityAuditService.OUTCOME_SUCCESS,
                                                                            id,
                                                                            u.getEmail(),
                                                                            ctx,
                                                                            actorDetail(actor)
                                                                                    + " oldRole="
                                                                                    + current
                                                                                    + " newRole="
                                                                                    + normalized))
                                                            .then(
                                                                    Mono.fromRunnable(
                                                                            () ->
                                                                                    streamNotifier.notifyDomain(
                                                                                            "user_role_changed",
                                                                                            List.of(
                                                                                                    "users",
                                                                                                    "sessions",
                                                                                                    "tokens",
                                                                                                    "risk",
                                                                                                    "audit"),
                                                                                            id,
                                                                                            id,
                                                                                            Map.of(
                                                                                                    "newRole",
                                                                                                    normalized))));
                                                }));
    }

    /**
     * Accepts persisted app-role tokens ({@code ADMIN}, …) or Spring-style {@code ROLE_ADMIN} (stripped to
     * {@code ADMIN} when unambiguous).
     */
    private static String normalizeBoAssignableRole(String raw) {
        if (raw == null) {
            return null;
        }
        String t = raw.trim();
        if (t.isEmpty()) {
            return null;
        }
        if (t.regionMatches(true, 0, "ROLE_", 0, 5)) {
            t = t.substring(5);
        }
        t = t.toUpperCase(Locale.ROOT);
        if (!ROLE_TOKEN.matcher(t).matches()) {
            return null;
        }
        if (!ASSIGNABLE_BO_ROLES.contains(t)) {
            return null;
        }
        return t;
    }

    public Flux<SecuritySessionDto> listSessions() {
        return refreshTokens
                .findActiveSessionsLatestPerSession()
                .collectList()
                .flatMapMany(
                        active ->
                                riskSignals
                                        .computeForActiveSessions(active)
                                        .flatMapMany(
                                                comp ->
                                                        Flux.fromIterable(active)
                                                                .concatMap(r -> toSessionDto(r, comp))));
    }

    /** Active operator sessions for one BO user (same projection as {@link #listSessions()}). */
    public Flux<SecuritySessionDto> listSessionsForUser(UUID userId) {
        return users
                .findById(userId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMapMany(
                        u ->
                                refreshTokens
                                        .findActiveSessionsLatestPerSessionForBoUser(u.getId())
                                        .collectList()
                                        .flatMapMany(
                                                active ->
                                                        riskSignals
                                                                .computeForActiveSessions(active)
                                                                .flatMapMany(
                                                                        comp ->
                                                                                Flux.fromIterable(active)
                                                                                        .concatMap(
                                                                                                r ->
                                                                                                        toSessionDto(
                                                                                                                r,
                                                                                                                comp)))));
    }

    public Flux<SecurityTokenDto> listTokens() {
        return refreshTokens.findRecentTokens(DEFAULT_TOKEN_LIMIT).concatMap(this::toTokenDto);
    }

    public Flux<SecurityAuditLogDto> listAudit(Integer limit) {
        int lim = limit == null || limit < 1 ? DEFAULT_AUDIT_LIMIT : Math.min(limit, 2000);
        return audit.findRecent(lim).map(this::toAuditDto);
    }

    public static final int DEFAULT_USER_AUDIT_LIMIT = 120;

    /**
     * Auth-scoped audit tail for a single BO user (same event universe as {@link
     * AuthObservabilityAppService#timeline(int)} / {@code findRecentAuthEvents}).
     */
    public Flux<SecurityAuditLogDto> listAuditForUser(UUID userId, Integer limit) {
        int lim =
                limit == null || limit < 1
                        ? DEFAULT_USER_AUDIT_LIMIT
                        : Math.min(limit, 500);
        return users
                .findById(userId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMapMany(
                        u -> {
                            String emailNorm =
                                    u.getEmail() == null
                                            ? ""
                                            : u.getEmail().trim().toLowerCase(Locale.ROOT);
                            return audit.findAuthEventsForUser(userId, emailNorm, lim).map(this::toAuditDto);
                        });
    }

    /**
     * Auth-scoped security audit tail across all operators (same event universe as {@link
     * com.devito.lifeengine.auth.application.AuthObservabilityAppService#timeline(int)}).
     */
    public Flux<SecurityAuditLogDto> listAuthSecurityEvents(Integer limit) {
        int lim = limit == null || limit < 1 ? DEFAULT_AUDIT_LIMIT : Math.min(limit, 2000);
        return audit.findRecentAuthEvents(lim).map(this::toAuditDto);
    }

    /**
     * BO read model: {@link SecurityControlPlaneDtos.AdminOperatorSecurityBundleDto} for one user (bounded lists).
     */
    public Mono<SecurityControlPlaneDtos.AdminOperatorSecurityBundleDto> adminOperatorSecurityBundle(
            UUID userId, Integer sessionsLimit, Integer eventsLimit) {
        int sLim = sessionsLimit == null || sessionsLimit < 1 ? 80 : Math.min(sessionsLimit, 200);
        int eLim =
                eventsLimit == null || eventsLimit < 1 ? DEFAULT_USER_AUDIT_LIMIT : Math.min(eventsLimit, 500);
        return getUser(userId)
                .flatMap(
                        profile ->
                                Mono.zip(
                                                listSessionsForUser(userId).take(sLim).collectList(),
                                                listAuditForUser(userId, eLim).collectList())
                                        .map(
                                                t ->
                                                        new SecurityControlPlaneDtos.AdminOperatorSecurityBundleDto(
                                                                profile, t.getT1(), t.getT2())));
    }

    public Mono<Void> disableUser(UUID id, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u -> {
                            u.setEnabled(false);
                            return users
                                    .save(u)
                                    .then(revokeAllActiveRefreshForBoUserId(id))
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.ADMIN_USER_DISABLED,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    id,
                                                    u.getEmail(),
                                                    ctx,
                                                    actorDetail(actor)))
                                    .then(
                                            Mono.fromRunnable(
                                                    () ->
                                                            streamNotifier.notifyDomain(
                                                                    "user_disabled",
                                                                    List.of(
                                                                            "users",
                                                                            "sessions",
                                                                            "tokens",
                                                                            "risk",
                                                                            "audit"),
                                                                    id,
                                                                    id,
                                                                    Map.of())));
                        });
    }

    public Mono<Void> lockUser(UUID id, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u -> {
                            if (u.isLocked()) {
                                return Mono.<Void>empty();
                            }
                            u.setLocked(true);
                            return users
                                    .save(u)
                                    .then(revokeAllActiveRefreshForBoUserId(id))
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.ADMIN_USER_LOCKED,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    id,
                                                    u.getEmail(),
                                                    ctx,
                                                    actorDetail(actor)))
                                    .then(
                                            Mono.fromRunnable(
                                                    () ->
                                                            streamNotifier.notifyDomain(
                                                                    "user_locked",
                                                                    List.of(
                                                                            "users",
                                                                            "sessions",
                                                                            "tokens",
                                                                            "risk",
                                                                            "audit"),
                                                                    id,
                                                                    id,
                                                                    Map.of())))
                                    .then(Mono.fromRunnable(adminMetrics::recordUserLocked));
                        });
    }

    public Mono<Void> unlockUser(UUID id, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u -> {
                            if (!u.isLocked()) {
                                return Mono.<Void>empty();
                            }
                            u.setLocked(false);
                            u.setLockedUntil(null);
                            u.setFailedLoginAttempts(0);
                            return users
                                    .save(u)
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.ADMIN_USER_UNLOCKED,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    id,
                                                    u.getEmail(),
                                                    ctx,
                                                    actorDetail(actor)))
                                    .then(
                                            Mono.fromRunnable(
                                                    () ->
                                                            streamNotifier.notifyDomain(
                                                                    "user_unlocked",
                                                                    List.of(
                                                                            "users",
                                                                            "sessions",
                                                                            "tokens",
                                                                            "risk",
                                                                            "audit"),
                                                                    id,
                                                                    id,
                                                                    Map.of())));
                        });
    }

    /**
     * Clears elevated role to {@code VIEWER} via {@link RbacAppService#syncUserToSingleRole}. Idempotent when the
     * effective primary is already {@code VIEWER}. Users with no {@code bo_user_role} rows are assigned {@code VIEWER}.
     */
    public Mono<Void> clearUserRole(UUID id, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u ->
                                effectiveAuthority
                                        .resolvePrimaryRoleCode(id)
                                        .map(cr -> cr.trim().toUpperCase(Locale.ROOT))
                                        .flatMap(
                                                current -> {
                                                    if ("VIEWER".equals(current)) {
                                                        return Mono.<Void>empty();
                                                    }
                                                    return syncUserToViewerWithAudit(id, u.getEmail(), actor, ctx, current);
                                                })
                                        .switchIfEmpty(
                                                syncUserToViewerWithAudit(id, u.getEmail(), actor, ctx, "(none)")));
    }

    private Mono<Void> syncUserToViewerWithAudit(
            UUID id, String email, BoUserPrincipal actor, AuditContext ctx, String oldRoleLabel) {
        return rbac
                .syncUserToSingleRole(id, "VIEWER")
                .then(
                        securityAudit.record(
                                SecurityAuditEventType.ADMIN_USER_ROLE_CHANGED,
                                SecurityAuditService.OUTCOME_SUCCESS,
                                id,
                                email,
                                ctx,
                                actorDetail(actor)
                                        + " action=cleared_to_viewer oldRole="
                                        + oldRoleLabel
                                        + " newRole=VIEWER"))
                .then(
                        Mono.fromRunnable(
                                () ->
                                        streamNotifier.notifyDomain(
                                                "user_role_changed",
                                                List.of("users", "sessions", "tokens", "risk", "audit"),
                                                id,
                                                id,
                                                Map.of("newRole", "VIEWER"))));
    }

    public Mono<Void> enableUser(UUID id, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u -> {
                            u.setEnabled(true);
                            u.setLockedUntil(null);
                            u.setFailedLoginAttempts(0);
                            return users
                                    .save(u)
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.ADMIN_USER_ENABLED,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    id,
                                                    u.getEmail(),
                                                    ctx,
                                                    actorDetail(actor)))
                                    .then(
                                            Mono.fromRunnable(
                                                    () ->
                                                            streamNotifier.notifyDomain(
                                                                    "user_enabled",
                                                                    List.of(
                                                                            "users",
                                                                            "sessions",
                                                                            "tokens",
                                                                            "risk",
                                                                            "audit"),
                                                                    id,
                                                                    id,
                                                                    Map.of())));
                        });
    }

    public Mono<Void> revokeToken(UUID id, BoUserPrincipal actor, AuditContext ctx) {
        return refreshTokens
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "token not found")))
                .flatMap(
                        row -> {
                            row.setRevoked(true);
                            UUID subject =
                                    row.getBoUserId() != null
                                            ? row.getBoUserId()
                                            : row.getGuestSessionId();
                            return refreshTokens
                                    .save(row)
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.ADMIN_TOKEN_REVOKED,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    subject,
                                                    null,
                                                    ctx,
                                                    actorDetail(actor)
                                                            + " refreshTokenRow="
                                                            + row.getId()
                                                            + (row.getSessionId() != null
                                                                    ? " sessionId=" + row.getSessionId()
                                                                    : "")))
                                    .then(
                                            Mono.fromRunnable(
                                                    () -> {
                                                        UUID uid =
                                                                row.getBoUserId() != null
                                                                        ? row.getBoUserId()
                                                                        : row.getGuestSessionId();
                                                        Map<String, Object> payload =
                                                                row.getSessionId() != null
                                                                        ? Map.of(
                                                                                "sessionId",
                                                                                row.getSessionId().toString())
                                                                        : Map.of();
                                                        streamNotifier.notifyDomain(
                                                                "token_revoked",
                                                                List.of(
                                                                        "tokens",
                                                                        "sessions",
                                                                        "users",
                                                                        "risk",
                                                                        "audit"),
                                                                row.getId(),
                                                                uid,
                                                                payload);
                                                    }));
                        });
    }

    /**
     * Ends an operator session: revokes every non-revoked refresh row with this {@code session_id}
     * (path param is session id, not token row id).
     */
    public Mono<Void> killSession(UUID sessionId, BoUserPrincipal actor, AuditContext ctx) {
        return refreshTokens
                .findBySessionId(sessionId)
                .filter(r -> !r.isRevoked())
                .collectList()
                .flatMap(
                        rows -> {
                            if (rows.isEmpty()) {
                                return Mono.empty();
                            }
                            UUID userId =
                                    rows.stream()
                                            .map(RefreshTokenRow::getBoUserId)
                                            .filter(Objects::nonNull)
                                            .findFirst()
                                            .orElseGet(
                                                    () ->
                                                            rows.stream()
                                                                    .map(RefreshTokenRow::getGuestSessionId)
                                                                    .filter(Objects::nonNull)
                                                                    .findFirst()
                                                                    .orElse(null));
                            return Flux.fromIterable(rows)
                                    .concatMap(
                                            r -> {
                                                r.setRevoked(true);
                                                return refreshTokens.save(r);
                                            })
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.ADMIN_SESSION_KILLED,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    userId,
                                                    null,
                                                    ctx,
                                                    actorDetail(actor)
                                                            + " sessionId="
                                                            + sessionId
                                                            + " revokedRefreshRows="
                                                            + rows.size()))
                                    .then(
                                            Mono.fromRunnable(
                                                    () ->
                                                            streamNotifier.notifyDomain(
                                                                    "session_killed",
                                                                    List.of(
                                                                            "sessions",
                                                                            "tokens",
                                                                            "users",
                                                                            "risk",
                                                                            "audit"),
                                                                    sessionId,
                                                                    userId,
                                                                    Map.of(
                                                                            "revokedRefreshRows",
                                                                            rows.size()))))
                                    .then(Mono.fromRunnable(adminMetrics::recordSessionRevoked));
                        });
    }

    /**
     * Revokes a session only if refresh rows tie it to {@code userId} (admin path contract under
     * {@code DELETE /api/.../users/{userId}/sessions/{sessionId}}).
     */
    public Mono<Void> killSessionForBoUser(UUID userId, UUID sessionId, BoUserPrincipal actor, AuditContext ctx) {
        return refreshTokens
                .findBySessionId(sessionId)
                .filter(r -> !r.isRevoked())
                .take(1)
                .next()
                .flatMap(
                        row -> {
                            if (row.getBoUserId() == null || !userId.equals(row.getBoUserId())) {
                                return Mono.error(
                                        new ResponseStatusException(
                                                HttpStatus.NOT_FOUND, "session not found for user"));
                            }
                            return killSession(sessionId, actor, ctx);
                        })
                .switchIfEmpty(
                        Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "session not found")));
    }

    public Mono<Void> killAllSessionsForUser(UUID userId, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(userId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u ->
                                refreshTokens
                                        .findByBoUserId(userId)
                                        .filter(r -> !r.isRevoked())
                                        .collectList()
                                        .flatMap(
                                                rows -> {
                                                    if (rows.isEmpty()) {
                                                        return Mono.empty();
                                                    }
                                                    Set<UUID> sessionIds =
                                                            rows.stream()
                                                                    .map(RefreshTokenRow::getSessionId)
                                                                    .filter(Objects::nonNull)
                                                                    .collect(
                                                                            Collectors.toCollection(
                                                                                    LinkedHashSet::new));
                                                    return persistRevokedRows(rows)
                                                            .then(
                                                                    securityAudit.record(
                                                                            SecurityAuditEventType
                                                                                    .ADMIN_USER_SESSIONS_REVOKED,
                                                                            SecurityAuditService
                                                                                    .OUTCOME_SUCCESS,
                                                                            userId,
                                                                            u.getEmail(),
                                                                            ctx,
                                                                            actorDetail(actor)
                                                                                    + " sessions="
                                                                                    + sessionIds.size()
                                                                                    + " rows="
                                                                                    + rows.size()))
                                                            .then(
                                                                    Mono.fromRunnable(
                                                                            () -> {
                                                                                for (UUID sid : sessionIds) {
                                                                                    streamNotifier.notifyDomain(
                                                                                            "session_killed",
                                                                                            List.of(
                                                                                                    "sessions",
                                                                                                    "tokens",
                                                                                                    "users",
                                                                                                    "risk",
                                                                                                    "audit"),
                                                                                            sid,
                                                                                            userId,
                                                                                            Map.of(
                                                                                                    "bulkKillForUser",
                                                                                                    true));
                                                                                }
                                                                            }));
                                                }));
    }

    private Mono<Void> revokeAllActiveRefreshForBoUserId(UUID userId) {
        return refreshTokens
                .findByBoUserId(userId)
                .filter(r -> !r.isRevoked())
                .collectList()
                .flatMap(this::persistRevokedRows);
    }

    private Mono<Void> persistRevokedRows(List<RefreshTokenRow> rows) {
        if (rows.isEmpty()) {
            return Mono.empty();
        }
        return Flux.fromIterable(rows)
                .concatMap(
                        r -> {
                            r.setRevoked(true);
                            return refreshTokens.save(r);
                        })
                .then();
    }

    private static String actorDetail(BoUserPrincipal actor) {
        return "actorId="
                + actor.userId()
                + " actorEmail="
                + actor.email().trim().toLowerCase(Locale.ROOT);
    }

    private static List<IdpLinkViewDto> toIdpViews(Collection<BoUserIdentityProviderRow> rows) {
        if (rows == null || rows.isEmpty()) {
            return List.of();
        }
        return rows.stream()
                .filter(Objects::nonNull)
                .map(r -> new IdpLinkViewDto(r.getProvider(), r.getLinkedEmail()))
                .sorted(Comparator.comparing(IdpLinkViewDto::provider, String.CASE_INSENSITIVE_ORDER))
                .toList();
    }

    private SecurityUserDto toUserDto(
            BoUserRow u,
            SecurityRiskComputation comp,
            Instant lastLoginAt,
            List<IdpLinkViewDto> identityLinks,
            String primaryRoleCode) {
        String emailLower = u.getEmail().trim().toLowerCase(Locale.ROOT);
        int fails = comp.failedLoginsByEmailLowercase().getOrDefault(emailLower, 0);
        boolean passwordPresent = u.getPasswordHash() != null && !u.getPasswordHash().isBlank();
        Set<String> idpProvidersLower =
                identityLinks.stream()
                        .map(l -> l.provider().trim().toLowerCase(Locale.ROOT))
                        .collect(Collectors.toCollection(LinkedHashSet::new));
        String authProvider = authProviderLabel(passwordPresent, idpProvidersLower);
        int failedRow = u.getFailedLoginAttempts() == null ? 0 : u.getFailedLoginAttempts();
        UserRiskView v = comp.userRiskByUserId().get(u.getId());
        if (v == null) {
            String level =
                    fails >= 5
                            ? SecurityRiskLevel.SUSPICIOUS
                            : fails >= 3 ? SecurityRiskLevel.UNUSUAL : SecurityRiskLevel.SAFE;
            List<String> sigs =
                    fails >= 3 ? List.of(SecurityRiskLevel.SIGNAL_FAILED_LOGINS) : List.of();
            var offline = SecurityRiskExplanationFormatter.forUserWithoutSessionContext(level, fails);
            return new SecurityUserDto(
                    u.getId(),
                    u.getEmail(),
                    primaryRoleCode,
                    u.isEnabled(),
                    u.isLocked(),
                    accountStatus(u),
                    u.getCreatedAt(),
                    level,
                    sigs,
                    offline.summary(),
                    offline.explanation(),
                    0,
                    fails,
                    authProvider,
                    lastLoginAt,
                    false,
                    failedRow,
                    u.getLockedUntil(),
                    "NOT_CONFIGURED",
                    u.getPasswordChangedAt(),
                    passwordPresent,
                    identityLinks);
        }
        return new SecurityUserDto(
                u.getId(),
                u.getEmail(),
                primaryRoleCode,
                u.isEnabled(),
                u.isLocked(),
                accountStatus(u),
                u.getCreatedAt(),
                v.riskLevel(),
                v.signals(),
                v.riskSummary(),
                v.riskExplanation(),
                v.activeSessionCount(),
                v.failedLoginAttempts24h(),
                authProvider,
                lastLoginAt,
                v.activeSessionCount() > 0,
                failedRow,
                u.getLockedUntil(),
                "NOT_CONFIGURED",
                u.getPasswordChangedAt(),
                passwordPresent,
                identityLinks);
    }

    private static String authProviderLabel(boolean passwordPresent, Set<String> idpProvidersLower) {
        boolean google = idpProvidersLower.stream().anyMatch(s -> "google".equals(s));
        if (passwordPresent && google) {
            return "mixed";
        }
        if (google) {
            return "google";
        }
        if (passwordPresent) {
            return "local";
        }
        return idpProvidersLower.isEmpty() ? "none" : String.join(",", idpProvidersLower.stream().sorted().toList());
    }

    private static String dashboardHealthBand(long failed24h, long lockedAccounts, long guest24h) {
        if (failed24h >= 25 || lockedAccounts >= 8) {
            return "RED";
        }
        if (failed24h >= 8 || lockedAccounts >= 3 || guest24h >= 50) {
            return "YELLOW";
        }
        return "GREEN";
    }

    private static long nz(Long v) {
        return v == null ? 0L : v;
    }

    private static String accountStatus(BoUserRow u) {
        if (!u.isEnabled()) {
            return "DISABLED";
        }
        if (u.isLocked()) {
            return "LOCKED";
        }
        if (u.isTemporarilyLocked()) {
            return "TEMP_LOCK";
        }
        return "ACTIVE";
    }

    private Mono<SecuritySessionDto> toSessionDto(RefreshTokenRow r, SecurityRiskComputation comp) {
        SessionRiskView risk =
                r.getSessionId() != null
                        ? comp.sessionRiskBySessionId().getOrDefault(r.getSessionId(), safeSessionRisk())
                        : safeSessionRisk();
        Instant sessionStarted =
                r.getSessionId() != null
                        ? comp.sessionStartedAtBySessionId()
                                .getOrDefault(r.getSessionId(), r.getCreatedAt())
                        : r.getCreatedAt();
        int accessMin = Math.max(1, jwtSecurityProperties.getAccessTokenValidityMinutes());
        Instant accessExpiry =
                lastSeen(r).plus(accessMin, ChronoUnit.MINUTES);
        return principalLabel(r)
                .map(
                        label ->
                                new SecuritySessionDto(
                                        r.getSessionId(),
                                        r.getId(),
                                        label,
                                        ipOrDash(r),
                                        deviceOrDash(r),
                                        sessionStarted,
                                        r.getCreatedAt(),
                                        lastSeen(r),
                                        r.getExpiresAt(),
                                        r.isRevoked(),
                                        r.getBoUserId() != null ? "user" : "guest",
                                        risk.riskLevel(),
                                        risk.signals(),
                                        risk.riskSummary(),
                                        risk.riskExplanation(),
                                        accessExpiry));
    }

    private static SessionRiskView safeSessionRisk() {
        var n =
                SecurityRiskExplanationFormatter.forSession(
                        SecurityRiskLevel.SAFE, List.of(), 0, 0);
        return new SessionRiskView(
                SecurityRiskLevel.SAFE, List.of(), n.summary(), n.explanation());
    }

    private Mono<SecurityTokenDto> toTokenDto(RefreshTokenRow r) {
        return principalLabel(r)
                .map(
                        label ->
                                new SecurityTokenDto(
                                        r.getId(),
                                        r.getSessionId(),
                                        label,
                                        r.getCreatedAt(),
                                        r.getExpiresAt(),
                                        r.isRevoked(),
                                        r.getBoUserId() != null ? "user" : "guest"));
    }

    private Instant lastSeen(RefreshTokenRow r) {
        return r.getLastSeenAt() != null ? r.getLastSeenAt() : r.getCreatedAt();
    }

    private String ipOrDash(RefreshTokenRow r) {
        return r.getClientIp() != null && !r.getClientIp().isBlank() ? r.getClientIp() : "—";
    }

    private String deviceOrDash(RefreshTokenRow r) {
        return r.getClientUserAgent() != null && !r.getClientUserAgent().isBlank()
                ? abbreviateUa(r.getClientUserAgent())
                : "—";
    }

    private static String abbreviateUa(String ua) {
        int max = 120;
        return ua.length() <= max ? ua : ua.substring(0, max) + "…";
    }

    private Mono<String> principalLabel(RefreshTokenRow r) {
        if (r.getBoUserId() != null) {
            return users
                    .findById(r.getBoUserId())
                    .map(BoUserRow::getEmail)
                    .defaultIfEmpty("(unknown user)");
        }
        if (r.getGuestSessionId() != null) {
            return Mono.just("guest:" + r.getGuestSessionId());
        }
        return Mono.just("(anonymous)");
    }

    private SecurityAuditLogDto toAuditDto(SecurityAuditRow a) {
        return new SecurityAuditLogDto(
                a.getId(),
                a.getEventType(),
                a.getOutcome(),
                a.getUserId(),
                a.getEmail(),
                a.getIp(),
                a.getUserAgent(),
                a.getDetail(),
                a.getCreatedAt());
    }
}
