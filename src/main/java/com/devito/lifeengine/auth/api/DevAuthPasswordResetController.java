package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.application.AuditContext;
import com.devito.lifeengine.auth.application.LocalDevPasswordResetAppService;
import com.devito.lifeengine.auth.infrastructure.conditions.LocalTestOnlyAuthToolingCondition;
import jakarta.validation.Valid;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Conditional;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Dev-only password reset (no email). {@code POST /api/dev-auth/reset-password} — enabled only when {@code
 * lifeengine.security.dev-password-reset.enabled=true}, deployment is local|test, and API key header is configured.
 */
@RestController
@RequestMapping("/api/dev-auth")
@ConditionalOnProperty(prefix = "lifeengine.security.dev-password-reset", name = "enabled", havingValue = "true")
@Conditional(LocalTestOnlyAuthToolingCondition.class)
public class DevAuthPasswordResetController {

    private final LocalDevPasswordResetAppService resetAppService;

    public DevAuthPasswordResetController(LocalDevPasswordResetAppService resetAppService) {
        this.resetAppService = resetAppService;
    }

    @PostMapping(value = "/reset-password", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Mono<AuthDtos.DevPasswordResetResponse> resetPassword(
            @RequestHeader(value = LocalDevPasswordResetAppService.HEADER_DEV_RESET_KEY, required = false)
                    String apiKey,
            @Valid @RequestBody Mono<AuthDtos.DevPasswordResetRequest> body,
            ServerWebExchange exchange) {
        AuditContext ctx = AuditContext.from(exchange);
        return body.flatMap(req -> resetAppService.resetIfAuthorized(apiKey, req.email(), req.newPassword(), ctx));
    }
}
