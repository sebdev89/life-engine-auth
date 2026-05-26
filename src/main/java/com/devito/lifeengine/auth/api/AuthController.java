package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.application.AuditContext;
import com.devito.lifeengine.auth.application.AuthAppService;
import com.devito.lifeengine.auth.application.LoginCommand;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import jakarta.validation.Valid;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthAppService authAppService;

    public AuthController(AuthAppService authAppService) {
        this.authAppService = authAppService;
    }

    @PostMapping("/login")
    public Mono<AuthDtos.LoginResponse> login(
            @Valid @RequestBody AuthDtos.LoginRequest request, ServerWebExchange exchange) {
        return authAppService.login(
                new LoginCommand(request.email(), request.password()), AuditContext.from(exchange));
    }

    @PostMapping("/guest")
    public Mono<AuthDtos.LoginResponse> guest(ServerWebExchange exchange) {
        return authAppService.guestSession(AuditContext.from(exchange));
    }

    @PostMapping("/refresh")
    public Mono<AuthDtos.LoginResponse> refresh(
            @Valid @RequestBody AuthDtos.RefreshRequest request, ServerWebExchange exchange) {
        return authAppService.refresh(request.refreshToken(), AuditContext.from(exchange));
    }

    @PostMapping("/logout")
    public Mono<Void> logout(
            @Valid @RequestBody AuthDtos.LogoutRequest request, ServerWebExchange exchange) {
        return authAppService.logout(request.refreshToken(), AuditContext.from(exchange));
    }

    /** Revokes every refresh session for the authenticated principal (Bearer access token). */
    @PostMapping("/logout-all")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> logoutAll(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono, ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(p -> authAppService.logoutAllSessions(p, AuditContext.from(exchange)))
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        Mono.error(
                                                new ResponseStatusException(HttpStatus.UNAUTHORIZED))));
    }

    /** Invalidates the presented refresh token (same effect as logout; audit type {@code TOKEN_REVOKED}). */
    @PostMapping("/revoke")
    public Mono<Void> revoke(
            @Valid @RequestBody AuthDtos.RefreshRequest request, ServerWebExchange exchange) {
        return authAppService.revoke(request.refreshToken(), AuditContext.from(exchange));
    }

    /**
     * Revokes all other BO-user refresh sessions; the presented refresh (and its session) stays valid. Not
     * available for guest.
     */
    @PostMapping("/sessions/revoke-others")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> revokeOtherSessions(
            @Valid @RequestBody AuthDtos.RefreshRequest request, ServerWebExchange exchange) {
        return authAppService.revokeOtherSessions(request.refreshToken(), AuditContext.from(exchange));
    }

    @GetMapping("/me")
    public Mono<AuthDtos.MeResponse> me(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return principalMono
                .filter(Objects::nonNull)
                .map(authAppService::me)
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        Mono.error(
                                                new ResponseStatusException(HttpStatus.UNAUTHORIZED))));
    }

    /** Alias for {@code POST /api/auth/me/password} — same body as {@code AuthDtos.ChangePasswordRequest}. */
    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> changePassword(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            @Valid @RequestBody AuthDtos.ChangePasswordRequest request,
            ServerWebExchange exchange) {
        boolean revoke = Boolean.TRUE.equals(request.revokeOtherSessions());
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(
                        p ->
                                authAppService.changePassword(
                                        p,
                                        request.currentPassword(),
                                        request.newPassword(),
                                        revoke,
                                        request.refreshToken(),
                                        AuditContext.from(exchange)))
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        Mono.error(
                                                new ResponseStatusException(HttpStatus.UNAUTHORIZED))));
    }

    /** Current session bound to the access token (requires {@code sid} claim). */
    @GetMapping("/session")
    public Mono<AuthDtos.SessionSnapshotDto> session(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(authAppService::currentSession)
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        Mono.error(
                                                new ResponseStatusException(HttpStatus.UNAUTHORIZED))));
    }

    /** Lists {@code user_sessions} rows for the authenticated principal (newest first). */
    @GetMapping("/sessions")
    public Flux<AuthDtos.UserSessionDto> sessions(
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return principalMono
                .filter(Objects::nonNull)
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        Mono.error(
                                                new ResponseStatusException(HttpStatus.UNAUTHORIZED))))
                .flatMapMany(authAppService::listOperatorSessions);
    }

    @DeleteMapping("/sessions/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> deleteSession(
            @PathVariable("id") UUID sessionId,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(p -> authAppService.revokeOperatorSession(p, sessionId, AuditContext.from(exchange)))
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        Mono.error(
                                                new ResponseStatusException(HttpStatus.UNAUTHORIZED))));
    }
}
