package com.devito.lifeengine.platform.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;

/** Shared JSON error body for selected V1 APIs (Dev Agent, Agent Runtime). */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiErrorEnvelope(String code, String message, String requestId, Instant timestamp) {}
