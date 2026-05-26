package com.devito.lifeengine.auth.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Security control-plane SSE payload. {@code type} is either a domain event ({@code audit_created}, …) or a
 * coarse signal ({@code push}, {@code snapshot}) with {@link #surfaces()} for tab-level invalidation.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SecurityStreamEventDto(
        int v,
        String type,
        List<String> surfaces,
        UUID entityId,
        UUID userId,
        Map<String, Object> payload,
        Instant ts,
        String traceId,
        String requestId) {}
