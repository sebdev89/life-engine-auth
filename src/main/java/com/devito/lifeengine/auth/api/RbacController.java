package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.application.AuditContext;
import com.devito.lifeengine.auth.application.RbacAppService;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import jakarta.validation.Valid;
import java.util.Objects;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * RBAC API — <strong>canonical data model</strong> for roles and user↔role assignments ({@code auth_role},
 * {@code bo_user_role}, permissions). Prefix {@code /api/auth} is historical and is reserved for RBAC management
 * operations (not admin user-security endpoints).
 */
@RestController
@RequestMapping("/api/auth")
public class RbacController {

    private final RbacAppService rbac;

    public RbacController(RbacAppService rbac) {
        this.rbac = rbac;
    }

    @GetMapping("/roles")
    public Flux<RbacDtos.RoleSummaryDto> listRoles() {
        return rbac.listRoles();
    }

    @GetMapping("/roles/{id}")
    public Mono<RbacDtos.RoleDetailDto> getRole(@PathVariable("id") UUID id) {
        return rbac.getRole(id);
    }

    @PostMapping("/roles")
    public Mono<RbacDtos.RoleDetailDto> createRole(
            @Valid @RequestBody RbacDtos.CreateRoleRequest body,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(actor -> rbac.createRole(body, actor, AuditContext.from(exchange)));
    }

    @PatchMapping("/roles/{id}")
    public Mono<RbacDtos.RoleDetailDto> updateRole(
            @PathVariable("id") UUID id,
            @Valid @RequestBody RbacDtos.UpdateRoleRequest body,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(actor -> rbac.updateRole(id, body, actor, AuditContext.from(exchange)));
    }

    @PostMapping("/users/{userId}/roles")
    public Mono<Void> assignRole(
            @PathVariable("userId") UUID userId,
            @Valid @RequestBody RbacDtos.AssignRoleRequest body,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(actor -> rbac.assignUserRole(userId, body, actor, AuditContext.from(exchange)));
    }

    @DeleteMapping("/users/{userId}/roles/{roleId}")
    public Mono<Void> removeRole(
            @PathVariable("userId") UUID userId,
            @PathVariable("roleId") UUID roleId,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono,
            ServerWebExchange exchange) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMap(actor -> rbac.removeUserRole(userId, roleId, actor, AuditContext.from(exchange)));
    }
}
