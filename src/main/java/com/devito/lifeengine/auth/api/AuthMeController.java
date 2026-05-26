package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.api.AuthDtos;
import com.devito.lifeengine.auth.api.AuthDtos.ChangePasswordRequest;
import com.devito.lifeengine.auth.api.AuthDtos.SelfActivityEntryDto;
import com.devito.lifeengine.auth.api.AuthDtos.SelfSecurityOverviewDto;
import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos.SecuritySessionDto;
import com.devito.lifeengine.auth.application.AuditContext;
import com.devito.lifeengine.auth.application.AuthAppService;
import com.devito.lifeengine.auth.application.AuthAuditLogAppService;
import com.devito.lifeengine.auth.application.GoogleIdentityLinkAppService;
import com.devito.lifeengine.auth.application.UserSelfSecurityAppService;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import jakarta.validation.Valid;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth/me")
public class AuthMeController {

    private final UserSelfSecurityAppService selfSecurity;
    private final AuthAppService authAppService;
    private final GoogleIdentityLinkAppService googleIdentityLink;
    private final AuthAuditLogAppService authAuditLog;

    public AuthMeController(
            UserSelfSecurityAppService selfSecurity,
            AuthAppService authAppService,
            GoogleIdentityLinkAppService googleIdentityLink,
            AuthAuditLogAppService authAuditLog) {
        this.selfSecurity = selfSecurity;
        this.authAppService = authAppService;
        this.googleIdentityLink = googleIdentityLink;
        this.authAuditLog = authAuditLog;
    }

    @GetMapping("/security")
    public Mono<SelfSecurityOverviewDto> securityOverview(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono, ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(
                        p ->
                                selfSecurity.overview(
                                        p, exchange.getRequest().getHeaders().getFirst("Authorization")))
                .switchIfEmpty(unauthorized());
    }

    @GetMapping("/sessions")
    public Flux<SecuritySessionDto> mySessions(@AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMapMany(selfSecurity::mySessions)
                .switchIfEmpty(Flux.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
    }

    @GetMapping("/activity")
    public Flux<SelfActivityEntryDto> myActivity(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            @RequestParam(name = "limit", required = false) Integer limit) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMapMany(p -> selfSecurity.myActivity(p, limit))
                .switchIfEmpty(Flux.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
    }

    /** Structured auth audit tail ({@code auth_audit_log}) for the signed-in principal. */
    @GetMapping("/auth-audit")
    public Flux<AuthDtos.AuthAuditLogEntryDto> myAuthAudit(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            @RequestParam(name = "limit", required = false) Integer limit) {
        int lim = limit == null ? 50 : Math.min(200, Math.max(1, limit));
        return principalMono
                .filter(Objects::nonNull)
                .flatMapMany(p -> authAuditLog.recentForUser(p.userId(), lim))
                .switchIfEmpty(Flux.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
    }

    @PostMapping("/sessions/{sessionId}/revoke")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> revokeMySession(
            @PathVariable("sessionId") UUID sessionId,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(p -> selfSecurity.revokeMySession(p, sessionId, AuditContext.from(exchange)))
                .switchIfEmpty(unauthorizedVoid());
    }

    @PostMapping("/sessions/revoke-all")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> revokeAllMySessions(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono, ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(p -> selfSecurity.revokeAllMySessions(p, AuditContext.from(exchange)))
                .switchIfEmpty(unauthorizedVoid());
    }

    @PostMapping("/identity/google/link/start")
    public Mono<AuthDtos.GoogleLinkStartResponse> startGoogleLink(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(googleIdentityLink::startGoogleLink)
                .switchIfEmpty(unauthorized());
    }

    @PostMapping("/identity/google/unlink")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> unlinkGoogle(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono, ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(p -> googleIdentityLink.unlinkGoogle(p, AuditContext.from(exchange)))
                .switchIfEmpty(unauthorizedVoid());
    }

    @PostMapping("/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> changePassword(
            @Valid @RequestBody ChangePasswordRequest body,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        boolean revoke =
                body.revokeOtherSessions() != null && Boolean.TRUE.equals(body.revokeOtherSessions());
        return principalMono
                .filter(Objects::nonNull)
                .switchIfEmpty(unauthorized())
                .flatMap(
                        p ->
                                authAppService.changePassword(
                                        p,
                                        body.currentPassword(),
                                        body.newPassword(),
                                        revoke,
                                        body.refreshToken(),
                                        AuditContext.from(exchange)));
    }

    private static <T> Mono<T> unauthorized() {
        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    private static Mono<Void> unauthorizedVoid() {
        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }
}
