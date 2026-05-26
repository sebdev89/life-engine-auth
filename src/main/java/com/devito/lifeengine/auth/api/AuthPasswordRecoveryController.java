package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.application.AuditContext;
import com.devito.lifeengine.auth.application.PasswordRecoveryAppService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth/password")
public class AuthPasswordRecoveryController {

    private final PasswordRecoveryAppService recovery;

    public AuthPasswordRecoveryController(PasswordRecoveryAppService recovery) {
        this.recovery = recovery;
    }

    @PostMapping("/forgot")
    public Mono<ResponseEntity<AuthDtos.ForgotPasswordResponse>> forgot(
            @Valid @RequestBody AuthDtos.ForgotPasswordRequest body, ServerWebExchange exchange) {
        return recovery
                .requestReset(body.email(), AuditContext.from(exchange))
                .map(t -> ResponseEntity.ok(new AuthDtos.ForgotPasswordResponse(true, t)))
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.ACCEPTED).body(new AuthDtos.ForgotPasswordResponse(true, null)));
    }

    @PostMapping("/reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> reset(
            @Valid @RequestBody AuthDtos.ResetPasswordRequest body, ServerWebExchange exchange) {
        return recovery.completeReset(body.token(), body.newPassword(), AuditContext.from(exchange));
    }
}
