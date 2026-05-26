package com.devito.lifeengine.platform.observability;

/**
 * HTTP request correlation for WebFlux: {@link reactor.util.context.Context} key and {@link
 * org.springframework.web.server.ServerWebExchange#getAttributes()} key share the same string so filters, controllers,
 * and handlers agree without coupling to Spring HTTP header constants.
 */
public final class RequestCorrelationKeys {

    private RequestCorrelationKeys() {}

    /** Reactor {@code Context} and {@code ServerWebExchange} attribute key for the resolved request id. */
    public static final String REQUEST_ID = "le.requestId";

    /**
     * Optional W3C / {@code X-Trace-Id} correlation (same dual storage as {@link #REQUEST_ID}). Empty when the client
     * did not send {@code traceparent} or {@code X-Trace-Id}.
     */
    public static final String TRACE_ID = "le.traceId";

    /**
     * Raw {@code traceparent} header when present (for outbound propagation); empty string when absent.
     */
    public static final String TRACEPARENT = "le.traceparent";
}
