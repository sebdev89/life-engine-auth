package com.devito.lifeengine.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebInputException;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

/**
 * JSON API errors for {@code /api/**}: unified {@link ApiErrorEnvelope} for all routes (HTTP status preserved).
 */
@Component
@Order(-2)
public class SafeApiErrorWebExceptionHandler implements WebExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(SafeApiErrorWebExceptionHandler.class);

    private final ObjectMapper objectMapper;

    public SafeApiErrorWebExceptionHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        String path = exchange.getRequest().getPath().value();
        if (!path.startsWith("/api/")) {
            return Mono.error(ex);
        }
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }
        HttpStatusCode statusCode = resolveHttpStatus(ex);
        HttpStatus status = HttpStatus.resolve(statusCode.value());
        if (status == null) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        if (status.is5xxServerError()) {
            // Phase-1 extraction note (life-engine-auth): gRPC StatusRuntimeException-aware logging
            // belongs in life-engine-runtime; auth has no gRPC clients.
            LOG.warn(
                    "api_error status={} path={} type={}",
                    status.value(),
                    path,
                    ex.getClass().getName());
        }
        String codeOverride = errorCodeOverride(ex);
        String body =
                ApiErrorHttpSupport.toEnvelopeJson(
                        objectMapper,
                        status.value(),
                        messageForClient(ex, status),
                        ApiErrorHttpSupport.requestId(exchange),
                        codeOverride);
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        var buf = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buf));
    }

    private static String messageForClient(Throwable ex, HttpStatus status) {
        if (ex instanceof ResponseStatusException rse) {
            String reason = rse.getReason();
            if (reason != null && !reason.isBlank()) {
                return reason.trim();
            }
        }
        if (ex instanceof ServerWebInputException) {
            return "invalid_request";
        }
        if (ex instanceof org.springframework.web.bind.support.WebExchangeBindException) {
            return "validation_failed";
        }
        if (status.is4xxClientError()) {
            return "request_failed";
        }
        return "internal_error";
    }

    private static HttpStatusCode resolveHttpStatus(Throwable ex) {
        if (ex instanceof ResponseStatusException rse) {
            return rse.getStatusCode();
        }
        if (ex instanceof ServerWebInputException swi) {
            return swi.getStatusCode();
        }
        if (ex instanceof org.springframework.web.bind.support.WebExchangeBindException webEx) {
            return webEx.getStatusCode();
        }
        // Phase-1 extraction note (life-engine-auth): gRPC StatusRuntimeException → HTTP mapping
        // (mapGrpcToHttp) belongs in life-engine-runtime; auth has no gRPC clients.
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    /**
     * Prefer stable domain codes in JSON {@code code} when present, including {@link ResponseStatusException}
     * reasons shaped as {@code CODE: message} from controllers. Dev Agent's {@code DevAgentBusinessException}
     * branch was intentionally dropped during the auth extraction; controllers that need stable codes can
     * shape their {@code ResponseStatusException.reason} as {@code STABLE_CODE: human message}.
     */
    private static String errorCodeOverride(Throwable ex) {
        if (ex instanceof ResponseStatusException rse) {
            String r = rse.getReason();
            if (r == null || r.isBlank()) {
                return null;
            }
            int c = r.indexOf(':');
            if (c <= 0) {
                return null;
            }
            String head = r.substring(0, c).trim();
            if (head.length() < 64 && head.chars().allMatch(ch -> ch == '_' || Character.isUpperCase(ch) || Character.isDigit(ch))) {
                return head;
            }
        }
        return null;
    }

    // Phase-1 extraction note (life-engine-auth): mapGrpcToHttp removed — see comments above.
}
