package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.SecurityStreamEventDto;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

/**
 * Multicast stream of security control-plane notifications (audit writes, etc.). Snapshot drift is handled
 * separately by {@link SecurityStreamFingerprintService}.
 */
@Component
public class SecurityStreamNotifier {

    private final SecurityStreamActivityTracker activity;
    private final ControlPlaneStreamMetrics streamMetrics;
    private final Sinks.Many<SecurityStreamEventDto> sink =
            Sinks.many().multicast().onBackpressureBuffer(256);

    public SecurityStreamNotifier(SecurityStreamActivityTracker activity, ControlPlaneStreamMetrics streamMetrics) {
        this.activity = activity;
        this.streamMetrics = streamMetrics;
    }

    /** Coarse invalidation (legacy / fallback): {@code type} is typically {@code push} or {@code snapshot}. */
    public void notifySurfaces(String type, List<String> surfaces) {
        activity.touch();
        streamMetrics.recordEventEmitted();
        sink.tryEmitNext(
                new SecurityStreamEventDto(
                        1, type, List.copyOf(surfaces), null, null, null, Instant.now(), null, null));
    }

    /**
     * Domain event plus optional {@code surfaces} so clients that only understand surface lists still refresh the
     * right tabs.
     */
    public void notifyDomain(
            String type,
            List<String> surfaces,
            UUID entityId,
            UUID userId,
            Map<String, Object> payload) {
        activity.touch();
        streamMetrics.recordEventEmitted();
        sink.tryEmitNext(
                new SecurityStreamEventDto(
                        1,
                        type,
                        surfaces == null ? List.of() : List.copyOf(surfaces),
                        entityId,
                        userId,
                        payload,
                        Instant.now(),
                        null,
                        null));
    }

    public Flux<SecurityStreamEventDto> events() {
        return sink.asFlux();
    }
}
