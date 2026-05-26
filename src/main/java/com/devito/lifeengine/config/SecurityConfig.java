package com.devito.lifeengine.config;

import com.devito.lifeengine.auth.application.JwtService;
import com.devito.lifeengine.auth.application.ReactiveUserSessionGate;
import com.devito.lifeengine.auth.infrastructure.config.GuestAuthProperties;
import com.devito.lifeengine.platform.PlatformRoles;
import com.devito.lifeengine.security.JwtReactiveAuthenticationWebFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * WebFlux authorization for {@code core-app}. Role model for BO JWT authorities:
 *
 * <ul>
 *   <li>{@link com.devito.lifeengine.platform.PlatformRoles#ROLE_GUEST} — read-only {@code GET /api/auth/me/*}
 *       slices + operator session endpoints in {@code /api/auth/session|sessions}; no mutations under {@code
 *       /api/auth/me/**} except as listed in matchers below.
 *   <li>{@link com.devito.lifeengine.platform.PlatformRoles#ROLE_USER} — full self-service under {@code
 *       /api/auth/me/**}; most {@code /api/bo/**} APIs.
 *   <li>{@link com.devito.lifeengine.platform.PlatformRoles#ROLE_ADMIN} — control plane {@code /api/security/**},
 *       admin security observability, and other privileged APIs.
 * </ul>
 *
 * <p><b>Normalization:</b> canonical admin API for identity/sessions/tokens/global audit is {@code /api/security/**}.
 * Legacy mirrors under {@code /api/admin/**} and {@code /api/auth/users/**} were removed.
 *
 * <p>Human-readable tables: {@code docs/auth-v1/auth-role-map.md} in the workspace repo.
 *
 * <p><b>Matcher order:</b> first match wins — keep {@code /api/auth/me} GET-specific reads for guest before {@code
 * /api/auth/me/**}, and both before the {@code /api/**} catch-all (which excludes {@code ROLE_GUEST}).
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    JwtReactiveAuthenticationWebFilter jwtReactiveAuthenticationWebFilter(
            JwtService jwtService,
            Environment environment,
            GuestAuthProperties guestAuthProperties,
            ReactiveUserSessionGate reactiveUserSessionGate,
            ObjectMapper objectMapper) {
        return new JwtReactiveAuthenticationWebFilter(
                jwtService, environment, guestAuthProperties, reactiveUserSessionGate, objectMapper);
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            JwtReactiveAuthenticationWebFilter jwtFilter,
            Environment environment,
            GuestAuthProperties guestAuthProperties,
            ObjectMapper objectMapper) {
        return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .addFilterBefore(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .authorizeExchange(
                        auth -> {
                            configurePublicEndpoints(auth, environment, guestAuthProperties);
                            configureAdminEndpoints(auth);
                            configureAgentEndpoints(auth);
                            configureAuthEndpoints(auth);
                        })
                .exceptionHandling(spec ->
                        spec.authenticationEntryPoint(
                                        (exchange, e) -> {
                                            if (LOG.isDebugEnabled()) {
                                                LOG.debug(
                                                        "authentication_entry_point status=401 path={} method={} authHeaderPresent={} type={}",
                                                        exchange.getRequest().getPath(),
                                                        exchange.getRequest().getMethod(),
                                                        exchange.getRequest().getHeaders().getFirst("Authorization")
                                                                != null,
                                                        e != null ? e.getClass().getName() : "null");
                                            }
                                            return jsonApiError(
                                                    exchange,
                                                    HttpStatus.UNAUTHORIZED,
                                                    objectMapper,
                                                    ApiErrorHttpSupport.defaultMessageForHttpStatus(401));
                                        })
                                .accessDeniedHandler(
                                        (exchange, e) -> {
                                            if (LOG.isDebugEnabled()) {
                                                LOG.debug(
                                                        "access_denied status=403 path={} method={} type={}",
                                                        exchange.getRequest().getPath(),
                                                        exchange.getRequest().getMethod(),
                                                        e != null ? e.getClass().getName() : "null");
                                            }
                                            return jsonApiError(
                                                    exchange,
                                                    HttpStatus.FORBIDDEN,
                                                    objectMapper,
                                                    ApiErrorHttpSupport.defaultMessageForHttpStatus(403));
                                        }))
                .build();
    }

    /** OPTIONS, OpenAPI rules, guest/login surface, actuator, OAuth callbacks — anonymous permitted where noted. */
    private static void configurePublicEndpoints(
            ServerHttpSecurity.AuthorizeExchangeSpec auth,
            Environment environment,
            GuestAuthProperties guestAuthProperties) {
        auth.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll();
        applyOpenApiAccessRules(auth, environment);
        if (guestAuthProperties.isEnabled()) {
            auth.pathMatchers(HttpMethod.POST, "/api/auth/guest").permitAll();
        } else {
            auth.pathMatchers(HttpMethod.POST, "/api/auth/guest").denyAll();
        }
        auth.pathMatchers(
                        HttpMethod.POST,
                        "/api/auth/login",
                        "/api/auth/refresh",
                        "/api/auth/logout",
                        "/api/auth/revoke",
                        "/api/auth/sessions/revoke-others")
                .permitAll()
                .pathMatchers(HttpMethod.POST, "/api/auth/password/forgot", "/api/auth/password/reset")
                .permitAll()
                .pathMatchers(HttpMethod.POST, "/api/auth/dev/register")
                .permitAll()
                .pathMatchers(HttpMethod.POST, "/api/dev-auth/reset-password")
                .permitAll()
                .pathMatchers("/actuator/health")
                .permitAll()
                .pathMatchers(HttpMethod.GET, "/actuator/prometheus", "/actuator/metrics", "/actuator/metrics/**")
                .permitAll()
                .pathMatchers("/error")
                .permitAll()
                .pathMatchers("/api/email/oauth/google/callback")
                .permitAll()
                .pathMatchers(HttpMethod.GET, "/api/email/oauth/google/authorize")
                .permitAll()
                .pathMatchers(HttpMethod.GET, "/api/auth/google/callback")
                .permitAll()
                .pathMatchers(HttpMethod.GET, "/api/auth/google/status")
                .permitAll()
                .pathMatchers(HttpMethod.GET, "/api/auth/google/authorize")
                .permitAll();
    }

    /** RBAC catalogue + auth observability + {@code /api/security/**}. */
    private static void configureAdminEndpoints(ServerHttpSecurity.AuthorizeExchangeSpec auth) {
        auth.pathMatchers(HttpMethod.GET, "/api/auth/roles", "/api/auth/roles/*")
                .hasAuthority("AUTH:RBAC:MANAGE")
                .pathMatchers(HttpMethod.POST, "/api/auth/roles")
                .hasAuthority("AUTH:RBAC:MANAGE")
                .pathMatchers(HttpMethod.PATCH, "/api/auth/roles/*")
                .hasAuthority("AUTH:RBAC:MANAGE")
                .pathMatchers(HttpMethod.POST, "/api/auth/users/*/roles")
                .hasAuthority("AUTH:RBAC:MANAGE")
                .pathMatchers(HttpMethod.DELETE, "/api/auth/users/*/roles/*")
                .hasAuthority("AUTH:RBAC:MANAGE")
                /*
                 * Cross-operator auth observability. There is no separate ROLE_AUTH_SUPPORT (or
                 * equivalent) in {@link com.devito.lifeengine.platform.PlatformRoles} yet — keep
                 * these endpoints admin-only until a scoped read authority is introduced.
                 */
                .pathMatchers(HttpMethod.GET, "/api/auth/timeline")
                .hasAuthority(PlatformRoles.ROLE_ADMIN)
                .pathMatchers(HttpMethod.GET, "/api/auth/metrics/overview")
                .hasAuthority(PlatformRoles.ROLE_ADMIN)
                .pathMatchers(HttpMethod.GET, "/api/auth/security/**")
                .hasAuthority(PlatformRoles.ROLE_ADMIN)
                .pathMatchers("/api/security/**")
                .hasAuthority(PlatformRoles.ROLE_ADMIN);
    }

    /** Vertical APIs, platform bootstrap, Dev Agent, Control Plane, Agent Runtime, integrations. */
    private static void configureAgentEndpoints(ServerHttpSecurity.AuthorizeExchangeSpec auth) {
        auth.pathMatchers("/api/ocr/v1/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/media-studio/v1/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/workflow/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/boss/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER);
        configurePlatformEndpoints(auth);
        auth.pathMatchers(HttpMethod.PUT, "/api/dev-agent/runtime/settings")
                .hasAuthority(PlatformRoles.ROLE_ADMIN)
                .pathMatchers(HttpMethod.POST, "/api/dev-agent/runtime/settings/reset")
                .hasAuthority(PlatformRoles.ROLE_ADMIN)
                .pathMatchers("/api/dev-agent/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                /*
                 * BO shell + dashboard: control-plane status/overview/logs/toggles/SSE events.
                 * Same authority envelope as the {@code /api/**} catch-all, listed explicitly for audits.
                 */
                .pathMatchers("/api/control-plane/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                /*
                 * interaction-platform: ingest/list/detail + modes catalog. BO JWT only
                 * (ADMIN|USER) — matches pipeline auth (no anonymous writes; GUEST excluded).
                 */
                .pathMatchers("/api/interactions/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/crypto-bot/runtime", "/api/crypto-bot/runtime/**")
                .hasAuthority(PlatformRoles.ROLE_ADMIN)
                .pathMatchers("/api/bo/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/crypto", "/api/crypto/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/crypto-bot/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/memory/**", "/api/rag/**", "/api/benchmark/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/email/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/social/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/finance/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/bogabot/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/land-radar/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/expenses/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers("/api/agents/settings/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .pathMatchers(
                        HttpMethod.GET,
                        "/api/agents/overview",
                        "/api/agents/health",
                        "/api/agents/readiness",
                        "/api/agents/models",
                        "/api/agents/debug/config")
                .hasAnyAuthority(
                        PlatformRoles.ROLE_ADMIN,
                        PlatformRoles.ROLE_USER,
                        PlatformRoles.ROLE_GUEST)
                .pathMatchers("/api/agents/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER);
    }

    /**
     * AI Control Plane shell bootstrap + load balancer probes.
     *
     * <p>Anonymous permitted: BO and Playwright smoke tests load these before JWT exists;
     * payload is non-secret (portfolio flags + shallow health). Authenticated callers
     * still receive the same JSON. Tighter routes (e.g. /api/platform/timeline) stay
     * behind /api/** below.
     */
    private static void configurePlatformEndpoints(ServerHttpSecurity.AuthorizeExchangeSpec auth) {
        auth.pathMatchers(HttpMethod.GET, "/api/platform/config", "/api/platform/health").permitAll();
    }

    /** Session list, {@code /api/auth/me/**}, catch-all {@code /api/**}. */
    private static void configureAuthEndpoints(ServerHttpSecurity.AuthorizeExchangeSpec auth) {
        auth.pathMatchers(HttpMethod.GET, "/api/auth/session")
                .hasAnyAuthority(
                        PlatformRoles.ROLE_ADMIN,
                        PlatformRoles.ROLE_USER,
                        PlatformRoles.ROLE_GUEST)
                .pathMatchers(HttpMethod.GET, "/api/auth/sessions")
                .hasAnyAuthority(
                        PlatformRoles.ROLE_ADMIN,
                        PlatformRoles.ROLE_USER,
                        PlatformRoles.ROLE_GUEST)
                .pathMatchers(HttpMethod.DELETE, "/api/auth/sessions/**")
                .hasAnyAuthority(
                        PlatformRoles.ROLE_ADMIN,
                        PlatformRoles.ROLE_USER,
                        PlatformRoles.ROLE_GUEST)
                .pathMatchers(HttpMethod.POST, "/api/auth/logout-all")
                .hasAnyAuthority(
                        PlatformRoles.ROLE_ADMIN,
                        PlatformRoles.ROLE_USER,
                        PlatformRoles.ROLE_GUEST)
                /*
                 * /api/auth/me — self-service (AuthMeController + GET /api/auth/me on AuthController).
                 * Order matters: more specific matchers first.
                 * - GUEST: read-only GETs (security overview, my sessions, activity, auth-audit).
                 * - USER + ADMIN: full self-service (password, Google link/unlink, revoke sessions).
                 */
                .pathMatchers(
                        HttpMethod.GET,
                        "/api/auth/me/security",
                        "/api/auth/me/sessions",
                        "/api/auth/me/activity",
                        "/api/auth/me/auth-audit")
                .hasAnyAuthority(
                        PlatformRoles.ROLE_GUEST,
                        PlatformRoles.ROLE_USER,
                        PlatformRoles.ROLE_ADMIN)
                .pathMatchers("/api/auth/me/**")
                .hasAnyAuthority(
                        PlatformRoles.ROLE_USER, PlatformRoles.ROLE_ADMIN)
                .pathMatchers(HttpMethod.GET, "/api/auth/me")
                .authenticated()
                .pathMatchers("/api/**")
                .hasAnyAuthority(PlatformRoles.ROLE_ADMIN, PlatformRoles.ROLE_USER)
                .anyExchange()
                .denyAll();
    }

    private static String appEnv(Environment environment) {
        return environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase();
    }

    private static void applyOpenApiAccessRules(
            ServerHttpSecurity.AuthorizeExchangeSpec auth, Environment environment) {
        String env = appEnv(environment);
        if ("prod".equals(env) || environment.acceptsProfiles(Profiles.of("prod"))) {
            auth.pathMatchers("/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**")
                    .denyAll();
        } else if ("dev".equals(env) || environment.acceptsProfiles(Profiles.of("dev"))) {
            auth.pathMatchers("/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**")
                    .hasAuthority(PlatformRoles.ROLE_ADMIN);
        } else {
            auth.pathMatchers("/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**")
                    .permitAll();
        }
    }

    private static Mono<Void> jsonApiError(
            ServerWebExchange exchange, HttpStatus status, ObjectMapper objectMapper, String message) {
        byte[] bytes =
                ApiErrorHttpSupport.envelopeUtf8(
                        objectMapper, status.value(), message, ApiErrorHttpSupport.requestId(exchange));
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        DataBuffer buf = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buf));
    }
}
