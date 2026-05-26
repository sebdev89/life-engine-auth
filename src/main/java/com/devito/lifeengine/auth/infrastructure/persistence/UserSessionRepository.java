package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface UserSessionRepository extends ReactiveCrudRepository<UserSessionRow, UUID> {

    Flux<UserSessionRow> findByBoUserIdOrderByCreatedAtDesc(UUID boUserId);

    Flux<UserSessionRow> findByGuestSessionIdOrderByCreatedAtDesc(UUID guestSessionId);

    @Query(
            """
            SELECT COUNT(*) FROM user_sessions
            WHERE bo_user_id = :uid AND revoked_at IS NULL AND expires_at > NOW()
            """)
    Mono<Long> countActiveForBoUser(@Param("uid") UUID uid);

    @Query(
            """
            SELECT * FROM user_sessions
            WHERE bo_user_id = :uid AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at ASC
            LIMIT 1
            """)
    Mono<UserSessionRow> findOldestActiveForBoUser(@Param("uid") UUID uid);

    @Modifying
    @Query("UPDATE user_sessions SET revoked_at = NOW() WHERE id = :id AND revoked_at IS NULL")
    Mono<Long> markRevokedById(@Param("id") UUID id);

    @Modifying
    @Query(
            """
            UPDATE user_sessions SET revoked_at = NOW()
            WHERE bo_user_id = :uid AND revoked_at IS NULL
            """)
    Mono<Long> markAllRevokedForBoUser(@Param("uid") UUID uid);

    @Modifying
    @Query(
            """
            UPDATE user_sessions SET revoked_at = NOW()
            WHERE guest_session_id = :gid AND revoked_at IS NULL
            """)
    Mono<Long> markAllRevokedForGuest(@Param("gid") UUID gid);
}
