package com.devito.lifeengine.auth.application;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Component;

/** Live SSE subscribers on {@code /api/security/stream} ({@code sse_clients_connected_current}). */
@Component
public class SecuritySseConnectionRegistry {

    private final AtomicInteger connections = new AtomicInteger();

    public SecuritySseConnectionRegistry(MeterRegistry registry) {
        Gauge.builder("sse.clients", connections, AtomicInteger::get).tag("channel", "security").register(registry);
    }

    public void acquire() {
        connections.incrementAndGet();
    }

    public void release() {
        connections.updateAndGet(v -> Math.max(0, v - 1));
    }

    public int connected() {
        return connections.get();
    }
}
