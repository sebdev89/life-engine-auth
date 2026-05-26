package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.AuthDtos;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.config.JwtSecurityProperties;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRow;
import com.devito.lifeengine.auth.infrastructure.persistence.UserSessionRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.UserSessionRow;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class AuthSessionControlAppService implements ReactiveUserSessionGate {

    private static final Logger log = LoggerFactory.getLogger(AuthSessionControlAppService.class);

    private final UserSessionRepository userSessions;
    private final RefreshTokenRepository refreshTokens;
    private final JwtSecurityProperties jwtProps;
    private final AuthAuditLogAppService authAudit;
    private final R2dbcEntityTemplate entityTemplate;

    public AuthSessionControlAppService(
            UserSessionRepository userSessions,
            RefreshTokenRepository refreshTokens,
            JwtSecurityProperties jwtProps,
            AuthAuditLogAppService authAudit,
            R2dbcEntityTemplate entityTemplate) {
        this.userSessions = userSessions;
        this.refreshTokens = refreshTokens;
        this.jwtProps = jwtProps;
        this.authAudit = authAudit;
        this.entityTemplate = entityTemplate;
    }

    @Override
    public Mono<Void> assertAccessAllowed(ServerWebExchange exchange, BoUserPrincipal principal) {
        String path = exchange.getRequest().getPath().value();
        if (!jwtProps.isRequireActiveUserSession()) {
            sessionGateDiag(path, "gate_disabled_requireActiveUserSession_false", principal, null, null);
            return Mono.empty();
        }
        UUID sid = principal.sessionId();
        if (sid == null) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "session gate: skipped requireActiveUserSession (no sessionId on JWT) userId={}",
                        principal.userId());
            }
            sessionGateDiag(path, "skipped_no_sid_on_jwt", principal, null, null);
            return Mono.empty();
        }
        AuditContext ctx = AuditContext.from(exchange);
        sessionGateDiag(path, "enter_active_session_lookup", principal, sid, null);
        /*
         * Never chain switchIfEmpty after Mono<T>.then() -> Mono<Void>: a completed Void sequence has no onNext and
         * is treated as empty, so switchIfEmpty(legacy) would always run even when user_sessions had a row.
         */
        return userSessions
                .findById(sid)
                .hasElement()
                .flatMap(
                        hasRow -> {
                            sessionGateDiag(
                                    path,
                                    "user_sessions_findById_hasElement",
                                    principal,
                                    sid,
                                    Boolean.TRUE.equals(hasRow));
                            if (Boolean.TRUE.equals(hasRow)) {
                                return userSessions
                                        .findById(sid)
                                        .delayUntil(us -> validatePersistedSession(path, us, principal, ctx))
                                        .then();
                            }
                            return legacyActiveRefreshGate(path, sid, principal, ctx);
                        });
    }

    private Mono<Void> validatePersistedSession(String path, UserSessionRow us, BoUserPrincipal p, AuditContext ctx) {
        if (us.getRevokedAt() != null) {
            sessionGateDiag(path, "row_present_but_revoked", p, us.getId(), us.getRevokedAt());
            return sessionUnauthorized("session_revoked", us.getId());
        }
        /*
         * Do not reject here with Instant.now(): the row's expires_at was written for PostgreSQL and the refresh
         * chain uses SQL "expires_at > NOW()". A JVM clock skew vs the DB (or driver Instant mapping edge) can mark
         * the session "expired" in Java while refresh_token is still active — and this path runs before the legacy
         * refresh fallback, producing immediate session_inactive after LOGIN_SUCCESS.
         */
        if (!ownsSessionRow(us, p)) {
            sessionGateDiag(path, "session_owner_mismatch", p, us.getId(), null);
            return sessionForbidden("session_owner_mismatch", us.getId());
        }
        sessionGateDiag(path, "session_row_validated_ok", p, us.getId(), us.getExpiresAt());
        return softClientHintAudit(us, ctx).then();
    }

    private Mono<Void> legacyActiveRefreshGate(String path, UUID sid, BoUserPrincipal p, AuditContext ctx) {
        return refreshTokens
                .findLatestActiveBySessionId(sid)
                .hasElement()
                .flatMap(
                        hasRt -> {
                            sessionGateDiag(path, "legacy_refresh_lookup_hasElement", p, sid, Boolean.TRUE.equals(hasRt));
                            return Boolean.TRUE.equals(hasRt)
                                    ? refreshTokens
                                            .findLatestActiveBySessionId(sid)
                                            .delayUntil(
                                                    rt ->
                                                            verifyRefreshRowSubject(rt, p)
                                                                    .then(softClientHintFromRefresh(rt, ctx)))
                                            .doOnSuccess(
                                                    rt ->
                                                            sessionGateDiag(
                                                                    path,
                                                                    "legacy_refresh_row_ok",
                                                                    p,
                                                                    sid,
                                                                    rt != null ? rt.getId() : null))
                                            .then()
                                    : sessionUnauthorized(
                                            "no_user_session_and_no_active_refresh", sid);
                        });
    }

    /** Temporary: set {@code logging.level.com.devito.lifeengine.auth.application.AuthSessionControlAppService=DEBUG}. */
    private static void sessionGateDiag(
            String path,
            String phase,
            BoUserPrincipal principal,
            Object idOrSidOrFlag,
            Object extra) {
        if (!log.isDebugEnabled()) {
            return;
        }
        log.debug(
                "session_gate_diag path={} phase={} userId={} jwtSid={} detail={} extra={}",
                path,
                phase,
                principal != null ? principal.userId() : null,
                principal != null ? principal.sessionId() : null,
                idOrSidOrFlag,
                extra);
    }

    private Mono<Void> sessionUnauthorized(String reason, UUID sessionId) {
        log.warn("session gate: UNAUTHORIZED reason={} sessionId={}", reason, sessionId);
        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "session_inactive"));
    }

    private Mono<Void> sessionForbidden(String reason, UUID sessionId) {
        if (log.isDebugEnabled()) {
            log.debug("session gate: FORBIDDEN reason={} sessionId={}", reason, sessionId);
        }
        return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN));
    }

    private static boolean ownsSessionRow(UserSessionRow us, BoUserPrincipal p) {
        if (us.getBoUserId() != null) {
            return us.getBoUserId().equals(p.userId());
        }
        if (us.getGuestSessionId() != null) {
            return us.getGuestSessionId().equals(p.userId());
        }
        return false;
    }

    private Mono<Void> verifyRefreshRowSubject(RefreshTokenRow rt, BoUserPrincipal p) {
        if (rt.getBoUserId() != null) {
            if (!rt.getBoUserId().equals(p.userId())) {
                return sessionForbidden("refresh_row_bo_user_mismatch", rt.getSessionId());
            }
            return Mono.empty();
        }
        if (rt.getGuestSessionId() != null) {
            if (!rt.getGuestSessionId().equals(p.userId())) {
                return sessionForbidden("refresh_row_guest_mismatch", rt.getSessionId());
            }
            return Mono.empty();
        }
        return sessionForbidden("refresh_row_missing_subject", rt.getSessionId());
    }

    private Mono<Void> softClientHintAudit(UserSessionRow us, AuditContext ctx) {
        if (!jwtProps.isSessionClientHintAuditEnabled() || ctx == null) {
            return Mono.empty();
        }
        String curIp = emptyToNull(ctx.ip());
        String stoIp = emptyToNull(us.getIpAddress());
        String curUa = emptyToNull(ctx.userAgent());
        String stoUa = emptyToNull(us.getUserAgent());
        boolean mismatch =
                (curIp != null && stoIp != null && !curIp.equals(stoIp))
                        || (curUa != null && stoUa != null && !curUa.equals(stoUa));
        if (!mismatch) {
            return Mono.empty();
        }
        UUID uid = us.getBoUserId() != null ? us.getBoUserId() : us.getGuestSessionId();
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("sessionId", us.getId().toString());
        meta.put("storedIp", stoIp);
        meta.put("currentIp", curIp);
        meta.put("hint", "ip_or_ua_changed");
        return authAudit.record(AuthAuditActions.SESSION_CLIENT_HINT, uid, ctx, meta);
    }

    private Mono<Void> softClientHintFromRefresh(RefreshTokenRow rt, AuditContext ctx) {
        if (!jwtProps.isSessionClientHintAuditEnabled() || ctx == null) {
            return Mono.empty();
        }
        String curIp = emptyToNull(ctx.ip());
        String stoIp = emptyToNull(rt.getClientIp());
        String curUa = emptyToNull(ctx.userAgent());
        String stoUa = emptyToNull(rt.getClientUserAgent());
        boolean mismatch =
                (curIp != null && stoIp != null && !curIp.equals(stoIp))
                        || (curUa != null && stoUa != null && !curUa.equals(stoUa));
        if (!mismatch) {
            return Mono.empty();
        }
        UUID uid = rt.getBoUserId() != null ? rt.getBoUserId() : rt.getGuestSessionId();
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("sessionId", rt.getSessionId() != null ? rt.getSessionId().toString() : null);
        meta.put("legacyRefreshRow", true);
        return authAudit.record(AuthAuditActions.SESSION_CLIENT_HINT, uid, ctx, meta);
    }

    private static String emptyToNull(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return s.trim();
    }

    /** Upserts {@code user_sessions} for the latest refresh row in a rotation chain. */
    public Mono<Void> syncUserSessionAfterRefreshInsert(RefreshTokenRow saved, AuditContext ctx) {
        if (saved.getSessionId() == null) {
            return Mono.empty();
        }
        return userSessions
                .findById(saved.getSessionId())
                .flatMap(existing -> patchUserSessionFromRefresh(existing, saved, ctx))
                .switchIfEmpty(Mono.defer(() -> insertUserSessionFromRefresh(saved, ctx)))
                .then()
                .doOnError(
                        e ->
                                log.warn(
                                        "user_sessions sync failed sessionId={}: {}",
                                        saved.getSessionId(),
                                        e.toString()));
    }

    private Mono<UserSessionRow> patchUserSessionFromRefresh(
            UserSessionRow existing, RefreshTokenRow saved, AuditContext ctx) {
        existing.setRefreshTokenHash(saved.getTokenHash());
        existing.setExpiresAt(saved.getExpiresAt());
        if (ctx != null && ctx.ip() != null) {
            existing.setIpAddress(ctx.ip());
        } else if (saved.getClientIp() != null) {
            existing.setIpAddress(saved.getClientIp());
        }
        if (ctx != null && ctx.userAgent() != null) {
            existing.setUserAgent(ctx.userAgent());
        } else if (saved.getClientUserAgent() != null) {
            existing.setUserAgent(saved.getClientUserAgent());
        }
        return userSessions.save(existing);
    }

    private Mono<UserSessionRow> insertUserSessionFromRefresh(RefreshTokenRow saved, AuditContext ctx) {
        UserSessionRow u = new UserSessionRow();
        u.setId(saved.getSessionId());
        u.setBoUserId(saved.getBoUserId());
        u.setGuestSessionId(saved.getGuestSessionId());
        u.setRefreshTokenHash(saved.getTokenHash());
        u.setCreatedAt(saved.getCreatedAt() != null ? saved.getCreatedAt() : Instant.now());
        u.setExpiresAt(saved.getExpiresAt());
        if (ctx != null && ctx.ip() != null) {
            u.setIpAddress(ctx.ip());
        } else {
            u.setIpAddress(saved.getClientIp());
        }
        if (ctx != null && ctx.userAgent() != null) {
            u.setUserAgent(ctx.userAgent());
        } else {
            u.setUserAgent(saved.getClientUserAgent());
        }
        // Spring Data R2DBC save() issues UPDATE when @Id is set; new rows must use INSERT (same as refresh_token).
        return entityTemplate.insert(u);
    }

    public Mono<Void> markUserSessionRevokedBySessionId(UUID sessionId) {
        if (sessionId == null) {
            return Mono.empty();
        }
        return userSessions
                .markRevokedById(sessionId)
                .then()
                .onErrorResume(
                        e -> {
                            log.warn(
                                    "user_sessions revoke mark failed sessionId={}: {}",
                                    sessionId,
                                    e.toString());
                            return Mono.empty();
                        });
    }

    /**
     * When {@code maxActiveBoUserSessions} &gt; 0, evicts oldest active BO sessions until under the cap (before
     * issuing a new login session).
     */
    public Mono<Void> enforceMaxSessionsBeforeNewBoLogin(UUID boUserId, AuditContext ctx) {
        int max = jwtProps.getMaxActiveBoUserSessions();
        if (max <= 0 || boUserId == null) {
            return Mono.empty();
        }
        return userSessions
                .countActiveForBoUser(boUserId)
                .defaultIfEmpty(0L)
                .flatMap(
                        c -> {
                            if (c < max) {
                                return Mono.empty();
                            }
                            return userSessions
                                    .findOldestActiveForBoUser(boUserId)
                                    .flatMap(
                                            oldest ->
                                                    refreshTokens
                                                            .revokeAllActiveForSession(oldest.getId())
                                                            .then(userSessions.markRevokedById(oldest.getId()))
                                                            .then(
                                                                    authAudit.record(
                                                                            AuthAuditActions.SESSION_REVOKED,
                                                                            boUserId,
                                                                            ctx,
                                                                            Map.of(
                                                                                    "reason",
                                                                                    "session_cap_eviction",
                                                                                    "sessionId",
                                                                                    oldest.getId().toString()))))
                                    .then(enforceMaxSessionsBeforeNewBoLogin(boUserId, ctx));
                        })
                .onErrorResume(
                        e -> {
                            log.warn(
                                    "session cap enforcement skipped for user {}: {}",
                                    boUserId,
                                    e.toString());
                            return Mono.empty();
                        });
    }

    public Mono<Void> logoutAll(BoUserPrincipal principal, AuditContext ctx) {
        if (isGuest(principal)) {
            return refreshTokens
                    .revokeAllActiveForGuest(principal.userId())
                    .then(userSessions.markAllRevokedForGuest(principal.userId()))
                    .then(
                            authAudit.record(
                                    AuthAuditActions.LOGOUT_ALL,
                                    principal.userId(),
                                    ctx,
                                    Map.of("subject", "guest")));
        }
        return refreshTokens
                .revokeAllActiveForBoUser(principal.userId())
                .then(userSessions.markAllRevokedForBoUser(principal.userId()))
                .then(authAudit.record(AuthAuditActions.LOGOUT_ALL, principal.userId(), ctx, Map.of()));
    }

    public Mono<Void> revokeSessionForPrincipal(BoUserPrincipal principal, UUID targetSessionId, AuditContext ctx) {
        return userSessions
                .findById(targetSessionId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND)))
                .flatMap(
                        us -> {
                            if (!ownsSessionRow(us, principal)) {
                                return sessionForbidden("revoke_target_not_owned", targetSessionId);
                            }
                            return refreshTokens
                                    .revokeAllActiveForSession(targetSessionId)
                                    .then(userSessions.markRevokedById(targetSessionId))
                                    .then(
                                            authAudit.record(
                                                    AuthAuditActions.SESSION_REVOKED,
                                                    principal.userId(),
                                                    ctx,
                                                    Map.of("sessionId", targetSessionId.toString())));
                        });
    }

    public Flux<AuthDtos.UserSessionDto> listSessions(BoUserPrincipal principal) {
        if (isGuest(principal)) {
            return userSessions
                    .findByGuestSessionIdOrderByCreatedAtDesc(principal.userId())
                    .map(this::toSessionDto);
        }
        return userSessions.findByBoUserIdOrderByCreatedAtDesc(principal.userId()).map(this::toSessionDto);
    }

    private AuthDtos.UserSessionDto toSessionDto(UserSessionRow us) {
        boolean active = us.getRevokedAt() == null && (us.getExpiresAt() == null || !us.getExpiresAt().isBefore(Instant.now()));
        String status = active ? "ACTIVE" : "REVOKED";
        String ip = us.getIpAddress() != null ? us.getIpAddress() : "";
        return new AuthDtos.UserSessionDto(
                us.getId(),
                deviceLabel(us.getUserAgent()),
                ip,
                us.getCreatedAt(),
                us.getExpiresAt(),
                status);
    }

    private static String deviceLabel(String ua) {
        if (ua == null || ua.isBlank()) {
            return "";
        }
        String u = ua.trim();
        String lower = u.toLowerCase(Locale.ROOT);
        if (lower.contains("edg/")) {
            return "Edge";
        }
        if (lower.contains("chrome/") && !lower.contains("chromium")) {
            return "Chrome";
        }
        if (lower.contains("firefox/")) {
            return "Firefox";
        }
        if (lower.contains("safari/") && !lower.contains("chrome")) {
            return "Safari";
        }
        int max = 96;
        return u.length() <= max ? u : u.substring(0, max) + "…";
    }

    private static boolean isGuest(BoUserPrincipal p) {
        return p.primaryRole() != null && "GUEST".equalsIgnoreCase(p.primaryRole().trim());
    }
}
