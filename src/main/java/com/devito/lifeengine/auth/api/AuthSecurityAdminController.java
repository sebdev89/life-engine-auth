package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.api.SecurityControlPlaneDtos.SecurityAuditLogDto;
import com.devito.lifeengine.auth.application.SecurityControlPlaneAppService;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Admin-only auth/security read APIs under {@code /api/auth/security/...} (distinct from self-service {@code
 * /api/auth/me/...}). Access is enforced by {@code ROLE_ADMIN} on {@code /api/auth/security/**} in {@code
 * SecurityConfig}.
 */
@RestController
@RequestMapping("/api/auth/security")
public class AuthSecurityAdminController {

    private final SecurityControlPlaneAppService security;

    public AuthSecurityAdminController(SecurityControlPlaneAppService security) {
        this.security = security;
    }

    @GetMapping("/events")
    public Flux<SecurityAuditLogDto> recentSecurityEvents(
            @RequestParam(name = "limit", required = false) Integer limit,
            @AuthenticationPrincipal Mono<BoUserPrincipal> principalMono) {
        return principalMono
                .filter(Objects::nonNull)
                .flatMapMany(p -> security.listAuthSecurityEvents(limit))
                .switchIfEmpty(Flux.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
    }
}
