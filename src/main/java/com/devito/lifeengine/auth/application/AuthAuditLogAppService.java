package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.AuthDtos;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthAuditLogRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthAuditLogRow;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class AuthAuditLogAppService {

    private static final Logger log = LoggerFactory.getLogger(AuthAuditLogAppService.class);

    private final AuthAuditLogRepository repository;
    private final ObjectMapper objectMapper;

    public AuthAuditLogAppService(AuthAuditLogRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    public Mono<Void> record(String action, UUID userId, AuditContext ctx, Map<String, Object> metadata) {
        AuthAuditLogRow row = new AuthAuditLogRow();
        row.setAction(action);
        row.setUserId(userId);
        if (ctx != null) {
            row.setIp(ctx.ip());
            row.setUserAgent(ctx.userAgent());
        }
        row.setCreatedAt(Instant.now());
        if (metadata != null && !metadata.isEmpty()) {
            try {
                row.setMetadata(objectMapper.writeValueAsString(metadata));
            } catch (JsonProcessingException e) {
                row.setMetadata("{\"error\":\"metadata_serialization\"}");
            }
        }
        return repository
                .save(row)
                .then()
                .onErrorResume(
                        e -> {
                            log.warn(
                                    "auth_audit_log write failed (run Flyway through V53+ if table missing): action={} userId={} — {}",
                                    action,
                                    userId,
                                    e.toString());
                            return Mono.empty();
                        });
    }

    public Mono<Void> recordSimple(String action, UUID userId, AuditContext ctx, String key, String value) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (key != null) {
            m.put(key, value);
        }
        return record(action, userId, ctx, m);
    }

    /** Recent rows from {@code auth_audit_log} for the authenticated principal (self-service). */
    public Flux<AuthDtos.AuthAuditLogEntryDto> recentForUser(UUID userId, int limit) {
        int lim = Math.min(200, Math.max(1, limit));
        return repository
                .findRecentForUser(userId, lim)
                .map(this::toEntryDto)
                .onErrorResume(
                        e -> {
                            log.warn(
                                    "auth_audit_log read failed for userId={} (run Flyway through V53+ if table missing): {}",
                                    userId,
                                    e.toString());
                            return Flux.empty();
                        });
    }

    private AuthDtos.AuthAuditLogEntryDto toEntryDto(AuthAuditLogRow r) {
        return new AuthDtos.AuthAuditLogEntryDto(
                r.getId(),
                r.getAction(),
                r.getCreatedAt(),
                r.getIp(),
                r.getUserAgent(),
                r.getMetadata());
    }
}
