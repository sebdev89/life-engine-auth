package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface RefreshTokenRepository extends ReactiveCrudRepository<RefreshTokenRow, UUID> {

    @Query(
            """
            SELECT COUNT(DISTINCT session_id) FROM refresh_token
            WHERE revoked = FALSE AND expires_at > NOW()
            """)
    Mono<Long> countActiveDistinctSessions();

    @Query(
            """
            SELECT COUNT(*) FROM refresh_token
            WHERE revoked = FALSE AND expires_at > NOW()
            """)
    Mono<Long> countActiveRefreshRows();

    @Query(
            """
            SELECT COUNT(DISTINCT bo_user_id) FROM refresh_token
            WHERE revoked = FALSE
              AND expires_at > NOW()
              AND bo_user_id IS NOT NULL
            """)
    Mono<Long> countDistinctBoUsersWithActiveSession();

    @Query(
            """
            SELECT * FROM refresh_token
            WHERE token_hash = :hash
              AND revoked = FALSE
              AND expires_at > NOW()
            LIMIT 1
            """)
    Mono<RefreshTokenRow> findValidByHash(@Param("hash") String hash);

    Flux<RefreshTokenRow> findByBoUserId(UUID boUserId);

    @Query(
            """
            SELECT * FROM refresh_token
            WHERE bo_user_id = :uid
              AND revoked = FALSE
              AND expires_at > NOW()
              AND session_id IS DISTINCT FROM :exceptSid
            """)
    Flux<RefreshTokenRow> findActiveByBoUserExcludingSession(
            @Param("uid") UUID uid, @Param("exceptSid") UUID exceptSid);

    @Query("SELECT * FROM refresh_token WHERE bo_user_id IN (:ids)")
    Flux<RefreshTokenRow> findByBoUserIdIn(@Param("ids") List<UUID> ids);

    Flux<RefreshTokenRow> findBySessionId(UUID sessionId);

    @Query(
            """
            SELECT * FROM refresh_token
            WHERE session_id = :sessionId
              AND revoked = FALSE
              AND expires_at > NOW()
            ORDER BY created_at DESC
            FETCH FIRST 1 ROW ONLY
            """)
    Mono<RefreshTokenRow> findLatestActiveBySessionId(@Param("sessionId") UUID sessionId);

    /**
     * One row per {@code session_id}: the latest active refresh row for that operator session (rotation
     * chain collapses here).
     */
    @Query(
            """
            SELECT * FROM (
                SELECT DISTINCT ON (session_id) *
                FROM refresh_token
                WHERE revoked = false AND expires_at > NOW()
                ORDER BY session_id, created_at DESC
            ) sub
            ORDER BY created_at DESC
            """)
    Flux<RefreshTokenRow> findActiveSessionsLatestPerSession();

    /**
     * Latest active refresh row per {@code session_id} for a single BO user (operator session list scoped to
     * {@code bo_user_id}).
     */
    @Query(
            """
            SELECT * FROM (
                SELECT DISTINCT ON (session_id) *
                FROM refresh_token
                WHERE revoked = false
                  AND expires_at > NOW()
                  AND bo_user_id = :uid
                ORDER BY session_id, created_at DESC
            ) sub
            ORDER BY created_at DESC
            """)
    Flux<RefreshTokenRow> findActiveSessionsLatestPerSessionForBoUser(@Param("uid") UUID uid);

    @Query(
            """
            SELECT * FROM refresh_token
            ORDER BY created_at DESC
            FETCH FIRST :limit ROWS ONLY
            """)
    Flux<RefreshTokenRow> findRecentTokens(@Param("limit") int limit);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE session_id = :sid AND revoked = false")
    Mono<Long> revokeAllActiveForSession(@Param("sid") UUID sid);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE bo_user_id = :uid AND revoked = false")
    Mono<Long> revokeAllActiveForBoUser(@Param("uid") UUID uid);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE guest_session_id = :gid AND revoked = false")
    Mono<Long> revokeAllActiveForGuest(@Param("gid") UUID gid);
}
