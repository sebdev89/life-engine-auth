package com.devito.lifeengine.platform.web;

import com.devito.lifeengine.platform.observability.GrpcCorrelationThreadLocals;
import com.devito.lifeengine.platform.observability.RequestCorrelationKeys;
import com.devito.lifeengine.platform.observability.TracePropagationUtil;
import java.util.List;
import java.util.UUID;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

/**
 * Accepts {@code X-Request-Id}, generates one if absent, echoes on the response, and stores it on the Reactor context
 * and exchange attributes under {@link RequestCorrelationKeys#REQUEST_ID}. Also stores {@code traceparent} (raw) and
 * mirrors correlation into {@link GrpcCorrelationThreadLocals} for blocking gRPC clients on the same request.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class RequestCorrelationWebFilter implements WebFilter {

    private static final String HEADER_X_REQUEST_ID = "X-Request-Id";
    private static final String HEADER_TRACEPARENT = "traceparent";
    private static final String HEADER_X_TRACE_ID = "X-Trace-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        List<String> incoming = exchange.getRequest().getHeaders().get(HEADER_X_REQUEST_ID);
        String rid =
                incoming != null && !incoming.isEmpty() && incoming.getFirst() != null && !incoming.getFirst().isBlank()
                        ? incoming.getFirst().trim()
                        : "le-" + UUID.randomUUID();
        exchange.getResponse().getHeaders().set(HEADER_X_REQUEST_ID, rid);
        exchange.getAttributes().put(RequestCorrelationKeys.REQUEST_ID, rid);
        String tid =
                TracePropagationUtil.resolveTraceId(
                        exchange.getRequest().getHeaders().get(HEADER_TRACEPARENT),
                        exchange.getRequest().getHeaders().get(HEADER_X_TRACE_ID));
        String traceAttr = tid == null ? "" : tid;
        exchange.getAttributes().put(RequestCorrelationKeys.TRACE_ID, traceAttr);
        List<String> tpIncoming = exchange.getRequest().getHeaders().get(HEADER_TRACEPARENT);
        String tpRaw =
                tpIncoming != null
                                && !tpIncoming.isEmpty()
                                && tpIncoming.getFirst() != null
                                && !tpIncoming.getFirst().isBlank()
                        ? tpIncoming.getFirst().trim()
                        : "";
        exchange.getAttributes().put(RequestCorrelationKeys.TRACEPARENT, tpRaw);

        Context ctx =
                Context.of(
                        RequestCorrelationKeys.REQUEST_ID,
                        rid,
                        RequestCorrelationKeys.TRACE_ID,
                        traceAttr,
                        RequestCorrelationKeys.TRACEPARENT,
                        tpRaw);
        return Mono.deferContextual(
                        cv -> {
                            GrpcCorrelationThreadLocals.set(
                                    String.valueOf(cv.getOrDefault(RequestCorrelationKeys.REQUEST_ID, "")),
                                    String.valueOf(cv.getOrDefault(RequestCorrelationKeys.TRACE_ID, "")),
                                    String.valueOf(cv.getOrDefault(RequestCorrelationKeys.TRACEPARENT, "")));
                            return chain.filter(exchange).doFinally(sig -> GrpcCorrelationThreadLocals.clear());
                        })
                .contextWrite(ctx);
    }
}
