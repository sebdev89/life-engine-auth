package com.devito.lifeengine.security;

import com.devito.lifeengine.auth.application.JwtService;
import com.devito.lifeengine.auth.application.ReactiveUserSessionGate;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.config.GuestAuthProperties;
import com.devito.lifeengine.config.ApiErrorHttpSupport;
import com.devito.lifeengine.platform.observability.RequestCorrelationKeys;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Parses {@code Authorization: Bearer} JWT and attaches {@link BoUserPrincipal} to the reactive security
 * context (WebFlux / Netty). Path skips cover the public auth surface ({@code login}, {@code refresh},
 * {@code logout}, {@code revoke}, password recovery, OAuth callbacks, non-prod gated dev endpoints) so the
 * downstream {@link org.springframework.security.config.web.server.ServerHttpSecurity} chain handles
 * authorisation for those routes.
 *
 * <p>This filter is intentionally vertical-agnostic: it does not know about dev-agent, control-plane,
 * crypto, workflow, agents, memory/RAG, finance, social, OCR, media-studio, BO, or any other route owned
 * by a different service. SSE-aware handling (returning {@code AUTH_EXPIRED} on token expiry instead of
 * forcing browsers to reconnect indefinitely) is triggered generically by {@code Accept: text/event-stream}.
 */
public class JwtReactiveAuthenticationWebFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtReactiveAuthenticationWebFilter.class);

    private final JwtService jwtService;
    private final Environment environment;
    private final GuestAuthProperties guestAuthProperties;
    private final ReactiveUserSessionGate reactiveUserSessionGate;
    private final ObjectMapper objectMapper;

    public JwtReactiveAuthenticationWebFilter(
            JwtService jwtService,
            Environment environment,
            GuestAuthProperties guestAuthProperties,
            ReactiveUserSessionGate reactiveUserSessionGate,
            ObjectMapper objectMapper) {
        this.jwtService = jwtService;
        this.environment = environment;
        this.guestAuthProperties = guestAuthProperties;
        this.reactiveUserSessionGate = reactiveUserSessionGate;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (shouldSkip(exchange)) {
            return chain.filter(exchange);
        }
        String path = exchange.getRequest().getPath().value();
        String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        boolean authHeaderPresent = auth != null && !auth.isBlank();
        boolean bearerShape =
                authHeaderPresent && auth.regionMatches(true, 0, "Bearer ", 0, 7) && auth.length() > 7;
        var outcome = jwtService.parseAuthorizationHeaderOutcome(auth);

        if (outcome.principal().isEmpty()) {
            String reason = outcome.failureReason().orElse("unknown");
            boolean expired = "expired".equals(reason);
            if (expired && acceptsEventStream(exchange)) {
                log.debug(
                        "sse_closed reason=auth_expired path={} traceId={}",
                        path,
                        traceIdForLog(exchange));
                return writeJson(
                        exchange,
                        HttpStatus.UNAUTHORIZED,
                        "Token expired",
                        "AUTH_EXPIRED");
            }
            log.warn(
                    "jwt_web_filter rejected path={} method={} parseOutcome={} authHeaderPresent={} bearerShape={}",
                    path,
                    exchange.getRequest().getMethod(),
                    reason,
                    authHeaderPresent,
                    bearerShape);
            return writeJson(exchange, HttpStatus.UNAUTHORIZED, null);
        }
        BoUserPrincipal p = outcome.principal().get();
        return reactiveUserSessionGate
                .assertAccessAllowed(exchange, p)
                .then(
                        Mono.defer(
                                () -> {
                                    List<SimpleGrantedAuthority> granted =
                                            p.authorities().stream()
                                                    .map(SimpleGrantedAuthority::new)
                                                    .collect(Collectors.toList());
                                    var authentication =
                                            new UsernamePasswordAuthenticationToken(p, null, granted);
                                    return chain.filter(exchange)
                                            .contextWrite(
                                                    ReactiveSecurityContextHolder.withAuthentication(
                                                            authentication));
                                }))
                .onErrorResume(
                        ResponseStatusException.class,
                        ex -> {
                            log.warn(
                                    "jwt filter: rejected path={} method={} status={} reason={}",
                                    path,
                                    exchange.getRequest().getMethod(),
                                    ex.getStatusCode(),
                                    ex.getReason());
                            return writeJson(exchange, ex.getStatusCode(), ex.getReason());
                        });
    }

    /**
     * Generic SSE detection. Returns true when the client advertises {@code text/event-stream} via the
     * {@code Accept} header — used to convert {@code 401 expired} into a stream-friendly close with the
     * {@code AUTH_EXPIRED} hint instead of an opaque reconnect loop. Intentionally route-agnostic.
     */
    private static boolean acceptsEventStream(ServerWebExchange exchange) {
        if (exchange.getRequest().getMethod() != HttpMethod.GET) {
            return false;
        }
        List<MediaType> accept = exchange.getRequest().getHeaders().getAccept();
        if (accept == null || accept.isEmpty()) {
            return false;
        }
        for (MediaType mt : accept) {
            if (MediaType.TEXT_EVENT_STREAM.isCompatibleWith(mt)) {
                return true;
            }
        }
        return false;
    }

    private static String traceIdForLog(ServerWebExchange exchange) {
        Object v = exchange.getAttributes().get(RequestCorrelationKeys.TRACE_ID);
        if (v == null) {
            return "-";
        }
        String s = String.valueOf(v).trim();
        return s.isEmpty() ? "-" : s;
    }

    private Mono<Void> writeJson(ServerWebExchange exchange, HttpStatusCode statusCode, String optionalReason) {
        return writeJson(exchange, statusCode, optionalReason, null);
    }

    private Mono<Void> writeJson(
            ServerWebExchange exchange,
            HttpStatusCode statusCode,
            String optionalReason,
            String optionalErrorCode) {
        HttpStatus status = ApiErrorHttpSupport.resolveOrUnauthorized(statusCode);
        String message =
                optionalReason != null && !optionalReason.isBlank()
                        ? optionalReason.trim()
                        : ApiErrorHttpSupport.defaultMessageForHttpStatus(status.value());
        byte[] bytes =
                ApiErrorHttpSupport.envelopeUtf8(
                        objectMapper,
                        status.value(),
                        message,
                        ApiErrorHttpSupport.requestId(exchange),
                        optionalErrorCode);
        exchange.getResponse().setStatusCode(status);
        ApiErrorHttpSupport.writeJsonContentType(exchange.getResponse().getHeaders());
        DataBuffer buf = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buf));
    }

    private boolean shouldSkip(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        HttpMethod m = exchange.getRequest().getMethod();
        if (m == HttpMethod.OPTIONS) {
            return true;
        }
        if (path.startsWith("/actuator/health")) {
            return true;
        }
        if (path.startsWith("/actuator/prometheus") || path.startsWith("/actuator/metrics")) {
            return true;
        }
        if ("/api/auth/login".equals(path) && m == HttpMethod.POST) {
            return true;
        }
        if ("/api/auth/refresh".equals(path) && m == HttpMethod.POST) {
            return true;
        }
        if ("/api/auth/logout".equals(path) && m == HttpMethod.POST) {
            return true;
        }
        if ("/api/auth/revoke".equals(path) && m == HttpMethod.POST) {
            return true;
        }
        if ("/api/auth/sessions/revoke-others".equals(path) && m == HttpMethod.POST) {
            return true;
        }
        if ((("/api/auth/password/forgot".equals(path) || "/api/auth/password/reset".equals(path)))
                && m == HttpMethod.POST) {
            return true;
        }
        if ("/api/auth/dev/register".equals(path) && m == HttpMethod.POST) {
            return true;
        }
        if ("/api/dev-auth/reset-password".equals(path) && m == HttpMethod.POST) {
            return true;
        }
        if (guestAuthProperties.isEnabled() && "/api/auth/guest".equals(path) && m == HttpMethod.POST) {
            return true;
        }
        if (skipJwtForOpenApiDocumentation()) {
            if (path.startsWith("/v3/api-docs")
                    || path.startsWith("/swagger-ui")
                    || "/swagger-ui.html".equals(path)) {
                return true;
            }
        }
        if ("/api/auth/google/callback".equals(path) && m == HttpMethod.GET) {
            return true;
        }
        if ("/api/auth/google/status".equals(path) && m == HttpMethod.GET) {
            return true;
        }
        if ("/api/auth/google/authorize".equals(path) && m == HttpMethod.GET) {
            return true;
        }
        return false;
    }

    private boolean skipJwtForOpenApiDocumentation() {
        String env = environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase();
        if ("local".equals(env)) {
            return true;
        }
        return environment.acceptsProfiles(Profiles.of("test"));
    }
}
