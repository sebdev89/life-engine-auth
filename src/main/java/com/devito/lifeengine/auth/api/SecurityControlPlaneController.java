package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.application.AdminOperatorProvisioningAppService;
import com.devito.lifeengine.auth.application.AuditContext;
import com.devito.lifeengine.auth.application.SecurityControlPlaneAppService;
import com.devito.lifeengine.auth.application.SecuritySseService;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
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

/** Security control plane — <strong>canonical admin prefix: {@code /api/security/**}</strong>. */
@RestController
@RequestMapping("/api/security")
public class SecurityControlPlaneController {

    private final SecurityControlPlaneAppService security;
    private final SecuritySseService sse;
    private final AdminOperatorProvisioningAppService operatorProvisioning;

    public SecurityControlPlaneController(
            SecurityControlPlaneAppService security,
            SecuritySseService sse,
            AdminOperatorProvisioningAppService operatorProvisioning) {
        this.security = security;
        this.sse = sse;
        this.operatorProvisioning = operatorProvisioning;
    }

    /**
     * Live control plane: push on new audit rows plus periodic snapshot when sessions/tokens drift. Clients
     * should refresh affected tabs and control-plane status when {@code surfaces} mentions them.
     */
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> stream() {
        return sse.securityEvents();
    }

    @GetMapping("/dashboard")
    public Mono<SecurityControlPlaneDtos.SecurityDashboardDto> dashboard() {
        return security.dashboardSnapshot();
    }

    @GetMapping("/users")
    public Flux<SecurityControlPlaneDtos.SecurityUserDto> users() {
        return security.listUsers();
    }

    /**
     * Creates a BO operator (production provisioning). Requires {@code ROLE_ADMIN}. Audited as {@code ADMIN_USER_CREATED}.
     */
    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<SecurityControlPlaneDtos.CreatedOperatorResponse> createUser(
            @RequestBody SecurityControlPlaneDtos.CreateAdminOperatorRequest body,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> operatorProvisioning.createOperator(body, actor, AuditContext.from(exchange)));
    }

    @GetMapping("/users/{id}")
    public Mono<SecurityControlPlaneDtos.SecurityUserDto> user(@PathVariable("id") UUID id) {
        return security.getUser(id);
    }

    /** Aggregated profile + sessions + auth-audit for one operator (single round-trip for detail pages). */
    @GetMapping("/users/{id}/security")
    public Mono<SecurityControlPlaneDtos.AdminOperatorSecurityBundleDto> operatorSecurityDetail(
            @PathVariable("id") UUID id,
            @RequestParam(name = "sessionsLimit", required = false) Integer sessionsLimit,
            @RequestParam(name = "eventsLimit", required = false) Integer eventsLimit,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.adminOperatorSecurityBundle(id, sessionsLimit, eventsLimit));
    }

    @GetMapping("/users/{id}/sessions")
    public Flux<SecurityControlPlaneDtos.SecuritySessionDto> listUserSessions(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return requireAdmin(principalMono).flatMapMany(actor -> security.listSessionsForUser(id));
    }

    @GetMapping("/users/{id}/audit")
    public Flux<SecurityControlPlaneDtos.SecurityAuditLogDto> listUserAudit(
            @PathVariable("id") UUID id,
            @RequestParam(name = "limit", required = false) Integer limit,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return requireAdmin(principalMono).flatMapMany(actor -> security.listAuditForUser(id, limit));
    }

    /** Alias name for UI readability; same rows as {@code /audit}. */
    @GetMapping("/users/{id}/auth-audit")
    public Flux<SecurityControlPlaneDtos.SecurityAuditLogDto> listUserAuthAudit(
            @PathVariable("id") UUID id,
            @RequestParam(name = "limit", required = false) Integer limit,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return listUserAudit(id, limit, principalMono);
    }

    /** Catalog rows from {@code auth_role} (ADMIN); RBAC CRUD remains on {@code /api/auth/roles}. */
    @GetMapping("/roles")
    public Flux<SecurityControlPlaneDtos.SecurityRoleDto> roles() {
        return security.listRoles();
    }

    /**
     * Sets a <strong>single</strong> BO operator role: updates {@code bo_user_role} via {@code
     * RbacAppService#syncUserToSingleRole} (RBAC only). Convergence: clients
     * should prefer RBAC assign/remove endpoints when multi-role is required; this PATCH duplicates “one primary role”
     * semantics until the legacy column is removed.
     */
    @PatchMapping("/users/{id}/role")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> updateUserRole(
            @PathVariable("id") UUID id,
            @RequestBody SecurityControlPlaneDtos.UpdateUserRoleRequest body,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.updateUserRole(id, body.role(), actor, AuditContext.from(exchange)));
    }

    /**
     * Clears to {@code VIEWER} via {@code RbacAppService#syncUserToSingleRole}.
     */
    @DeleteMapping("/users/{id}/role")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> clearUserRole(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.clearUserRole(id, actor, AuditContext.from(exchange)));
    }

    @GetMapping("/sessions")
    public Flux<SecurityControlPlaneDtos.SecuritySessionDto> sessions() {
        return security.listSessions();
    }

    /** @param id {@code session_id} (stable session), same id as in session list. */
    @GetMapping("/sessions/{id}")
    public Mono<SecurityControlPlaneDtos.SecuritySessionDto> session(@PathVariable("id") UUID id) {
        return security.getSession(id);
    }

    @GetMapping("/tokens")
    public Flux<SecurityControlPlaneDtos.SecurityTokenDto> tokens() {
        return security.listTokens();
    }

    @GetMapping("/audit")
    public Flux<SecurityControlPlaneDtos.SecurityAuditLogDto> audit(
            @RequestParam(name = "limit", required = false) Integer limit) {
        return security.listAudit(limit);
    }

    @PostMapping("/users/{id}/disable")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> disableUser(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.disableUser(id, actor, AuditContext.from(exchange)));
    }

    @PostMapping("/users/{id}/enable")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> enableUser(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.enableUser(id, actor, AuditContext.from(exchange)));
    }

    @PostMapping("/users/{id}/lock")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> lockUser(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.lockUser(id, actor, AuditContext.from(exchange)));
    }

    @PostMapping("/users/{id}/unlock")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> unlockUser(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.unlockUser(id, actor, AuditContext.from(exchange)));
    }

    /** @param id {@code session_id} (stable session), not refresh row id. */
    @PostMapping("/sessions/{id}/kill")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> killSession(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.killSession(id, actor, AuditContext.from(exchange)));
    }

    @PostMapping("/tokens/{id}/revoke")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> revokeToken(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.revokeToken(id, actor, AuditContext.from(exchange)));
    }

    @PostMapping("/users/{id}/sessions/kill-all")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> killAllSessionsForUser(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.killAllSessionsForUser(id, actor, AuditContext.from(exchange)));
    }

    @PostMapping("/users/{id}/force-password-reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> forcePasswordReset(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.forcePasswordReset(id, actor, AuditContext.from(exchange)));
    }

    /**
     * Revokes one session belonging to a given user. Returns 404 when unknown or not owned by that user.
     *
     * @param sessionId stable {@code session_id}
     */
    @DeleteMapping("/users/{id}/sessions/{sessionId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> deleteUserSession(
            @PathVariable("id") UUID id,
            @PathVariable("sessionId") UUID sessionId,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return requireAdmin(principalMono)
                .flatMap(actor -> security.killSessionForBoUser(id, sessionId, actor, AuditContext.from(exchange)));
    }

    private static Mono<BoUserPrincipal> requireAdmin(Mono<BoUserPrincipal> principalMono) {
        return principalMono
                .filter(Objects::nonNull)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
    }
}
