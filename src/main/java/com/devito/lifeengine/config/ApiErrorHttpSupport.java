package com.devito.lifeengine.config;

import com.devito.lifeengine.platform.api.ApiErrorEnvelope;
import com.devito.lifeengine.platform.observability.RequestCorrelationKeys;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.web.server.ServerWebExchange;

/**
 * Single serialization path for {@link ApiErrorEnvelope} on HTTP API errors — keeps {@link
 * SafeApiErrorWebExceptionHandler}, security entry points, and JWT filter aligned without duplicating JSON shape.
 */
public final class ApiErrorHttpSupport {

    private ApiErrorHttpSupport() {}

    public static String requestId(ServerWebExchange exchange) {
        Object v = exchange.getAttributes().get(RequestCorrelationKeys.REQUEST_ID);
        if (v == null) {
            return null;
        }
        String s = String.valueOf(v).trim();
        return s.isEmpty() ? null : s;
    }

    public static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }

    /** Stable machine-oriented code (matches former legacy {@code error} string values where applicable). */
    public static String errorCodeForHttpStatus(int status) {
        return switch (status) {
            case 400 -> "bad_request";
            case 401 -> "unauthorized";
            case 403 -> "forbidden";
            case 404 -> "not_found";
            case 409 -> "conflict";
            case 422 -> "unprocessable_entity";
            case 429 -> "too_many_requests";
            case 502 -> "bad_gateway";
            case 503 -> "service_unavailable";
            default -> status >= 500 ? "internal_error" : "client_error";
        };
    }

    public static String defaultMessageForHttpStatus(int status) {
        return switch (status) {
            case 401 -> "unauthorized";
            case 403 -> "forbidden";
            default -> errorCodeForHttpStatus(status);
        };
    }

    public static String toEnvelopeJson(
            ObjectMapper objectMapper, int httpStatusValue, String message, String requestId) {
        return toEnvelopeJson(objectMapper, httpStatusValue, message, requestId, null);
    }

    /**
     * @param codeOverride when non-null/non-blank, used as {@link ApiErrorEnvelope#code()} instead of the default from
     *     HTTP status (e.g. {@code AUTH_EXPIRED} for expired JWT on SSE).
     */
    public static String toEnvelopeJson(
            ObjectMapper objectMapper,
            int httpStatusValue,
            String message,
            String requestId,
            @Nullable String codeOverride) {
        String code =
                codeOverride != null && !codeOverride.isBlank()
                        ? codeOverride.trim()
                        : errorCodeForHttpStatus(httpStatusValue);
        try {
            return objectMapper.writeValueAsString(
                    new ApiErrorEnvelope(code, message, blankToNull(requestId), Instant.now()));
        } catch (JsonProcessingException e) {
            return fallbackEnvelopeJson(code, message, requestId);
        }
    }

    private static String fallbackEnvelopeJson(String code, String message, String requestId) {
        String rid =
                requestId == null || requestId.isBlank()
                        ? "null"
                        : "\"" + escapeJson(requestId) + "\"";
        return "{\"code\":\""
                + escapeJson(code)
                + "\",\"message\":\""
                + escapeJson(message)
                + "\",\"requestId\":"
                + rid
                + ",\"timestamp\":\""
                + Instant.now().toString()
                + "\"}";
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public static byte[] envelopeUtf8(
            ObjectMapper objectMapper, int httpStatusValue, String message, String requestId) {
        return envelopeUtf8(objectMapper, httpStatusValue, message, requestId, null);
    }

    public static byte[] envelopeUtf8(
            ObjectMapper objectMapper,
            int httpStatusValue,
            String message,
            String requestId,
            @Nullable String codeOverride) {
        return toEnvelopeJson(objectMapper, httpStatusValue, message, requestId, codeOverride)
                .getBytes(StandardCharsets.UTF_8);
    }

    public static void writeJsonContentType(org.springframework.http.HttpHeaders headers) {
        headers.setContentType(MediaType.APPLICATION_JSON);
    }

    /** Resolve {@link HttpStatus} or fall back to {@link HttpStatus#UNAUTHORIZED} for unknown codes. */
    public static HttpStatus resolveOrUnauthorized(org.springframework.http.HttpStatusCode statusCode) {
        HttpStatus status = HttpStatus.resolve(statusCode.value());
        return status != null ? status : HttpStatus.UNAUTHORIZED;
    }
}
