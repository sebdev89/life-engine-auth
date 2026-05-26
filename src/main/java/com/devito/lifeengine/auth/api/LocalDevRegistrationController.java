package com.devito.lifeengine.auth.api;

import com.devito.lifeengine.auth.application.LocalDevRegistrationService;
import com.devito.lifeengine.auth.infrastructure.conditions.NotProductionEnvironmentCondition;
import jakarta.validation.Valid;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Conditional;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Non-production self-registration for BO operators. Disabled unless {@code
 * lifeengine.security.local-dev-registration.enabled=true} and not running in production.
 */
@RestController
@RequestMapping("/api/auth/dev")
@ConditionalOnProperty(prefix = "lifeengine.security.local-dev-registration", name = "enabled", havingValue = "true")
@Conditional(NotProductionEnvironmentCondition.class)
public class LocalDevRegistrationController {

    private final LocalDevRegistrationService registrationService;

    public LocalDevRegistrationController(LocalDevRegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<Void>> register(@Valid @RequestBody Mono<LocalDevRegisterRequest> body) {
        return body.flatMap(registrationService::register).thenReturn(ResponseEntity.status(HttpStatus.CREATED).build());
    }
}
