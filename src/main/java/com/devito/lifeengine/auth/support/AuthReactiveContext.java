package com.devito.lifeengine.auth.support;

import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import reactor.core.publisher.Mono;

public final class AuthReactiveContext {

    private AuthReactiveContext() {}

    /** Prefers servlet {@link SecurityContextHolder} (Tomcat + JWT filter), then reactive context. */
    public static Mono<BoUserPrincipal> currentUser() {
        var servletAuth = SecurityContextHolder.getContext().getAuthentication();
        if (servletAuth != null && servletAuth.getPrincipal() instanceof BoUserPrincipal p) {
            return Mono.just(p);
        }
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getPrincipal())
                .cast(BoUserPrincipal.class);
    }
}
