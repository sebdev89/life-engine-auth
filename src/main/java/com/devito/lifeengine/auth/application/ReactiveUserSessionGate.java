package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** Validates that the JWT-bound refresh session is still acceptable for API access. */
public interface ReactiveUserSessionGate {

    /**
     * @param exchange current request (IP / UA soft checks).
     */
    Mono<Void> assertAccessAllowed(ServerWebExchange exchange, BoUserPrincipal principal);
}
