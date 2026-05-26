package com.devito.lifeengine.platform.observability;

import java.util.Optional;

/**
 * Bridges inbound HTTP correlation (Reactor {@code Context} via web filters) to blocking gRPC client threads so a
 * {@link io.grpc.ClientInterceptor} can attach metadata without changing business APIs.
 */
public final class GrpcCorrelationThreadLocals {

    private static final ThreadLocal<String> REQUEST_ID = new ThreadLocal<>();
    private static final ThreadLocal<String> TRACE_ID = new ThreadLocal<>();
    private static final ThreadLocal<String> TRACEPARENT = new ThreadLocal<>();

    private GrpcCorrelationThreadLocals() {}

    public static void set(String requestId, String traceId, String traceparent) {
        REQUEST_ID.set(requestId == null ? "" : requestId);
        TRACE_ID.set(traceId == null ? "" : traceId);
        TRACEPARENT.set(traceparent == null ? "" : traceparent);
    }

    public static void clear() {
        REQUEST_ID.remove();
        TRACE_ID.remove();
        TRACEPARENT.remove();
    }

    public static Optional<String> requestId() {
        String v = REQUEST_ID.get();
        return v == null || v.isBlank() ? Optional.empty() : Optional.of(v);
    }

    public static Optional<String> traceId() {
        String v = TRACE_ID.get();
        return v == null || v.isBlank() ? Optional.empty() : Optional.of(v);
    }

    public static Optional<String> traceparent() {
        String v = TRACEPARENT.get();
        return v == null || v.isBlank() ? Optional.empty() : Optional.of(v);
    }
}
