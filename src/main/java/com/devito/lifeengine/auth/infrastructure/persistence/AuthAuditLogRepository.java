package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

public interface AuthAuditLogRepository extends ReactiveCrudRepository<AuthAuditLogRow, Long> {

    @Query(
            """
            SELECT * FROM auth_audit_log
            WHERE user_id = :userId
            ORDER BY created_at DESC
            LIMIT :limit
            """)
    Flux<AuthAuditLogRow> findRecentForUser(@Param("userId") UUID userId, @Param("limit") int limit);
}
