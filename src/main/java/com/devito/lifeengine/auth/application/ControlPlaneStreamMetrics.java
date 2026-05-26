package com.devito.lifeengine.auth.application;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Control-plane SSE fan-out ({@code control_plane_events_emitted_total}) — increments when the security stream
 * notifier emits.
 */
@Component
public class ControlPlaneStreamMetrics {

    private final Counter eventsEmitted;

    public ControlPlaneStreamMetrics(MeterRegistry registry) {
        this.eventsEmitted = Counter.builder("control.plane.events").register(registry);
    }

    public void recordEventEmitted() {
        eventsEmitted.increment();
    }

    public long emittedEventsTotal() {
        return (long) eventsEmitted.count();
    }
}
