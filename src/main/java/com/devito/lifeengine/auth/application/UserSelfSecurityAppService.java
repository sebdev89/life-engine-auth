package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.AuthDtos;
import com.devito.lifeengine.auth.api.AuthDtos.SelfActivityEntryDto;
import com.devito.lifeengine.auth.api.AuthDtos.SelfSecurityOverviewDto;
import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos.SecuritySessionDto;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.config.GoogleLoginOAuthProperties;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import reactor.util.function.Tuple5;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class UserSelfSecurityAppService {

    private static final int DEFAULT_ACTIVITY = 80;

    private final BoUserRepository users;
    private final BoUserIdentityProviderRepository identityProviders;
    private final SecurityAuditRepository audit;
    private final SecurityControlPlaneAppService security;
    private final RefreshTokenRepository refreshTokens;
    private final SecurityAuditService securityAudit;
    private final SecurityStreamNotifier streamNotifier;
    private final JwtService jwtService;
    private final JwtSecurityProperties jwtProps;
    private final GoogleLoginOAuthProperties googleLoginProps;

    public UserSelfSecurityAppService(
            BoUserRepository users,
            BoUserIdentityProviderRepository identityProviders,
            SecurityAuditRepository audit,
            SecurityControlPlaneAppService security,
            RefreshTokenRepository refreshTokens,
            SecurityAuditService securityAudit,
            SecurityStreamNotifier streamNotifier,
            JwtService jwtService,
            JwtSecurityProperties jwtProps,
            GoogleLoginOAuthProperties googleLoginProps) {
        this.users = users;
        this.identityProviders = identityProviders;
        this.audit = audit;
        this.security = security;
        this.refreshTokens = refreshTokens;
        this.securityAudit = securityAudit;
        this.streamNotifier = streamNotifier;
        this.jwtService = jwtService;
        this.jwtProps = jwtProps;
        this.googleLoginProps = googleLoginProps;
    }

    public Mono<SelfSecurityOverviewDto> overview(BoUserPrincipal principal, String authorizationHeader) {
        Instant since24h = Instant.now().minus(24, ChronoUnit.HOURS);
        String emailNorm = principal.email().trim().toLowerCase(Locale.ROOT);
        Instant accessExp =
                jwtService.readAccessTokenExpiration(authorizationHeader).orElse(null);
        Mono<BoUserRow> userMono =
                users.findById(principal.userId())
                        .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND)));
        Mono<Long> googleMono =
                identityProviders.countByBoUserIdAndProvider(principal.userId(), BoUserIdentityProviderRow.PROVIDER_GOOGLE);
        Mono<Map<UUID, Instant>> lastLoginMono =
                audit.findLastLoginSuccessAggregatedByUserIds(List.of(principal.userId()))
                        .collectMap(UserLastLoginRow::getUserId, UserLastLoginRow::getLastLogin);
        Mono<Long> fail24Mono = audit.countLoginFailuresForUserSince(principal.userId(), emailNorm, since24h);
        Mono<Long> activeSessionsMono = security.listSessionsForUser(principal.userId()).count();

        return Mono.zip(userMono, googleMono, lastLoginMono, fail24Mono, activeSessionsMono)
                .flatMap(
                        t ->
                                currentSessionSnapshot(principal)
                                        .map(s -> buildOverview(principal, t, s, accessExp))
                                        .switchIfEmpty(
                                                Mono.fromCallable(() -> buildOverview(principal, t, null, accessExp))));
    }

    private SelfSecurityOverviewDto buildOverview(
            BoUserPrincipal principal,
            Tuple5<BoUserRow, Long, Map<UUID, Instant>, Long, Long> t,
            AuthDtos.SessionSnapshotDto snap,
            Instant accessExp) {
        BoUserRow u = t.getT1();
        long googleN = nz(t.getT2());
        Map<UUID, Instant> ll = t.getT3();
        long f24 = nz(t.getT4());
        long activeSess = nz(t.getT5());
        boolean passwordPresent = u.getPasswordHash() != null && !u.getPasswordHash().isBlank();
        Set<String> idp = new LinkedHashSet<>();
        if (googleN > 0) {
            idp.add("google");
        }
        String authProvider = authProviderLabel(passwordPresent, idp);
        boolean googleLinked = googleN > 0;
        Instant lastLogin = ll.get(u.getId());
        boolean loggedIn =
                snap != null
                        && snap.sessionId() != null
                        && "ACTIVE".equalsIgnoreCase(snap.sessionStatus());
        String health = computeHealth(u, f24, activeSess, googleLinked, passwordPresent);
        return new SelfSecurityOverviewDto(
                u.getId().toString(),
                u.getEmail(),
                principal.primaryRole(),
                List.copyOf(principal.authorities()),
                authProvider,
                googleLinked,
                googleLoginProps.isConfigured(),
                snap != null ? snap.sessionId() : principal.sessionId(),
                loggedIn,
                accessExp,
                snap != null ? snap.refreshExpiresAt() : null,
                lastLogin,
                u.getFailedLoginAttempts() == null ? 0 : u.getFailedLoginAttempts(),
                Math.toIntExact(Math.min(f24, Integer.MAX_VALUE)),
                u.isLocked(),
                u.isTemporarilyLocked(),
                u.getLockedUntil(),
                passwordPresent,
                u.getPasswordChangedAt(),
                "NOT_CONFIGURED",
                Math.toIntExact(Math.min(activeSess, Integer.MAX_VALUE)),
                health,
                jwtProps.isRequireActiveUserSession(),
                jwtProps.getMaxActiveBoUserSessions());
    }

    public Flux<SecuritySessionDto> mySessions(BoUserPrincipal principal) {
        return security.listSessionsForUser(principal.userId());
    }

    public Flux<SelfActivityEntryDto> myActivity(BoUserPrincipal principal, Integer limit) {
        int lim = limit == null || limit < 1 ? DEFAULT_ACTIVITY : Math.min(limit, 200);
        String emailNorm = principal.email().trim().toLowerCase(Locale.ROOT);
        return audit.findAuthEventsForUser(principal.userId(), emailNorm, lim).map(this::toActivity);
    }

    public Mono<Void> revokeMySession(BoUserPrincipal principal, UUID sessionId, AuditContext ctx) {
        return refreshTokens
                .findBySessionId(sessionId)
                .collectList()
                .flatMap(
                        rows -> {
                            if (rows.isEmpty()) {
                                return Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND));
                            }
                            UUID owner =
                                    rows.stream()
                                            .map(RefreshTokenRow::getBoUserId)
                                            .filter(Objects::nonNull)
                                            .findFirst()
                                            .orElse(null);
                            if (owner == null || !owner.equals(principal.userId())) {
                                return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN));
                            }
                            return Flux.fromIterable(rows)
                                    .filter(r -> !r.isRevoked())
                                    .concatMap(
                                            r -> {
                                                r.setRevoked(true);
                                                return refreshTokens.save(r);
                                            })
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.USER_SESSION_REVOKED_SELF,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    principal.userId(),
                                                    principal.email(),
                                                    ctx,
                                                    "sessionId=" + sessionId))
                                    .then(
                                            Mono.fromRunnable(
                                                    () ->
                                                            streamNotifier.notifyDomain(
                                                                    "user_session_revoked_self",
                                                                    List.of("sessions", "tokens", "audit"),
                                                                    sessionId,
                                                                    principal.userId(),
                                                                    Map.of())));
                        });
    }

    public Mono<Void> revokeAllMySessions(BoUserPrincipal principal, AuditContext ctx) {
        return refreshTokens
                .findByBoUserId(principal.userId())
                .filter(r -> !r.isRevoked())
                .collectList()
                .flatMap(
                        rows -> {
                            if (rows.isEmpty()) {
                                return Mono.empty();
                            }
                            return Flux.fromIterable(rows)
                                    .concatMap(
                                            r -> {
                                                r.setRevoked(true);
                                                return refreshTokens.save(r);
                                            })
                                    .then(
                                            securityAudit.record(
                                                    SecurityAuditEventType.USER_SESSIONS_REVOKED_ALL_SELF,
                                                    SecurityAuditService.OUTCOME_SUCCESS,
                                                    principal.userId(),
                                                    principal.email(),
                                                    ctx,
                                                    "rows=" + rows.size()))
                                    .then(
                                            Mono.fromRunnable(
                                                    () ->
                                                            streamNotifier.notifyDomain(
                                                                    "user_sessions_revoked_all_self",
                                                                    List.of("sessions", "tokens", "audit"),
                                                                    principal.userId(),
                                                                    principal.userId(),
                                                                    Map.of("rows", rows.size()))));
                        });
    }

    private Mono<AuthDtos.SessionSnapshotDto> currentSessionSnapshot(BoUserPrincipal principal) {
        if (principal.sessionId() == null) {
            return Mono.empty();
        }
        return refreshTokens
                .findLatestActiveBySessionId(principal.sessionId())
                .flatMap(
                        r -> {
                            if (r.getBoUserId() == null || !r.getBoUserId().equals(principal.userId())) {
                                return Mono.empty();
                            }
                            String ip = r.getClientIp() != null ? r.getClientIp() : "";
                            String ua = r.getClientUserAgent();
                            String device = ua == null || ua.isBlank() ? "" : abbreviateUa(ua);
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
                .switchIfEmpty(Mono.empty());
    }

    private SelfActivityEntryDto toActivity(SecurityAuditRow a) {
        return new SelfActivityEntryDto(
                a.getId(),
                a.getEventType(),
                a.getOutcome(),
                a.getCreatedAt(),
                a.getDetail());
    }

    private static String abbreviateUa(String ua) {
        int max = 120;
        return ua.length() <= max ? ua : ua.substring(0, max) + "…";
    }

    private static long nz(Long v) {
        return v == null ? 0L : v;
    }

    private static String authProviderLabel(boolean passwordPresent, Set<String> idpLower) {
        boolean google = idpLower.contains("google");
        if (passwordPresent && google) {
            return "mixed";
        }
        if (google) {
            return "google";
        }
        if (passwordPresent) {
            return "local";
        }
        return idpLower.isEmpty() ? "none" : idpLower.stream().sorted().collect(Collectors.joining(","));
    }

    private static String computeHealth(
            BoUserRow u, long fail24, long activeSessions, boolean googleLinked, boolean passwordPresent) {
        if (!u.isEnabled() || u.isLocked()) {
            return "RED";
        }
        if (u.isTemporarilyLocked() || fail24 >= 8) {
            return "YELLOW";
        }
        if (activeSessions >= 4 || (!googleLinked && passwordPresent && fail24 >= 3)) {
            return "YELLOW";
        }
        return "GREEN";
    }
}
