package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.SecurityStreamEventDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

/** Merges push notifications, fingerprint polling, and keepalive into one SSE flux. */
@Service
public class SecuritySseService {

    private final ObjectMapper objectMapper;
    private final SecurityStreamNotifier notifier;
    private final SecurityStreamFingerprintService fingerprint;
    private final SecuritySseConnectionRegistry sseConnections;

    public SecuritySseService(
            ObjectMapper objectMapper,
            SecurityStreamNotifier notifier,
            SecurityStreamFingerprintService fingerprint,
            SecuritySseConnectionRegistry sseConnections) {
        this.objectMapper = objectMapper;
        this.notifier = notifier;
        this.fingerprint = fingerprint;
        this.sseConnections = sseConnections;
    }

    public Flux<ServerSentEvent<String>> securityEvents() {
        Flux<ServerSentEvent<String>> push = notifier.events().map(this::toSse);
        Flux<ServerSentEvent<String>> snapshot = fingerprint.watchChanges().map(this::toSse);
        Flux<ServerSentEvent<String>> keepalive =
                Flux.interval(Duration.ofSeconds(25))
                        .map(i -> ServerSentEvent.<String>builder().comment("ping").build());
        return Flux.merge(push, snapshot, keepalive)
                .doOnSubscribe(s -> sseConnections.acquire())
                .doFinally(s -> sseConnections.release());
    }

    private ServerSentEvent<String> toSse(SecurityStreamEventDto e) {
        try {
            return ServerSentEvent.<String>builder()
                    .event("security")
                    .data(objectMapper.writeValueAsString(e))
                    .build();
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("SSE encode failed", ex);
        }
    }
}
