package com.devito.lifeengine.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface SecurityAuditRepository extends ReactiveCrudRepository<SecurityAuditRow, Long> {

    @Query("SELECT COALESCE(MAX(id), 0) FROM security_audit_event")
    Mono<Long> findMaxId();

    @Query(
            """
            SELECT * FROM security_audit_event
            ORDER BY created_at DESC
            FETCH FIRST :limit ROWS ONLY
            """)
    Flux<SecurityAuditRow> findRecent(@Param("limit") int limit);

    @Query(
            """
            SELECT * FROM security_audit_event
            WHERE user_id IN (:userIds)
              AND created_at >= :since
            ORDER BY created_at DESC
            FETCH FIRST 20000 ROWS ONLY
            """)
    Flux<SecurityAuditRow> findByUserIdInAndCreatedAtAfter(
            @Param("userIds") List<UUID> userIds, @Param("since") Instant since);

    @Query(
            """
            SELECT * FROM security_audit_event
            WHERE event_type = 'LOGIN_FAILURE'
              AND created_at >= :since
            ORDER BY created_at DESC
            FETCH FIRST 10000 ROWS ONLY
            """)
    Flux<SecurityAuditRow> findLoginFailuresSince(@Param("since") Instant since);

    /**
     * Auth-relevant events for one BO user: {@code user_id} match, or email match (e.g. login failures
     * before user_id was bound). {@code emailNorm} must be lowercased + trimmed; if empty, only
     * {@code user_id} is used.
     */
    @Query(
            """
            SELECT * FROM security_audit_event
            WHERE event_type IN (
              'LOGIN_SUCCESS', 'GOOGLE_LOGIN_SUCCESS', 'LOGIN_FAILURE', 'GOOGLE_LOGIN_FAILURE',
              'LOGIN_TEMP_LOCKOUT', 'REFRESH_SUCCESS', 'REFRESH_FAILURE',
              'LOGOUT', 'TOKEN_REVOKED', 'OTHER_SESSIONS_REVOKED', 'GUEST_SESSION_CREATED',
              'ADMIN_USER_DISABLED', 'ADMIN_USER_ENABLED', 'ADMIN_SESSION_KILLED', 'ADMIN_TOKEN_REVOKED',
              'ADMIN_USER_SESSIONS_REVOKED', 'ADMIN_USER_ROLE_CHANGED', 'ADMIN_USER_LOCKED', 'ADMIN_USER_UNLOCKED',
              'ADMIN_PASSWORD_RESET_FORCED',
              'USER_PASSWORD_CHANGED', 'PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_COMPLETED',
              'USER_SESSION_REVOKED_SELF', 'USER_SESSIONS_REVOKED_ALL_SELF',
              'GOOGLE_ACCOUNT_LINKED', 'GOOGLE_ACCOUNT_UNLINKED', 'GOOGLE_LINK_FAILURE',
              'RBAC_ROLE_CREATED', 'RBAC_ROLE_UPDATED', 'RBAC_USER_ROLE_ASSIGNED', 'RBAC_USER_ROLE_REMOVED'
            )
              AND (
                user_id = :userId
                OR (
                  :emailNorm <> ''
                  AND LOWER(TRIM(COALESCE(email, ''))) = :emailNorm
                )
              )
            ORDER BY created_at DESC
            FETCH FIRST :limit ROWS ONLY
            """)
    Flux<SecurityAuditRow> findAuthEventsForUser(
            @Param("userId") UUID userId, @Param("emailNorm") String emailNorm, @Param("limit") int limit);

    @Query(
            """
            SELECT * FROM security_audit_event
            WHERE event_type IN (
              'LOGIN_SUCCESS', 'GOOGLE_LOGIN_SUCCESS', 'LOGIN_FAILURE', 'GOOGLE_LOGIN_FAILURE',
              'LOGIN_TEMP_LOCKOUT', 'REFRESH_SUCCESS', 'REFRESH_FAILURE',
              'LOGOUT', 'TOKEN_REVOKED', 'OTHER_SESSIONS_REVOKED', 'GUEST_SESSION_CREATED',
              'ADMIN_USER_DISABLED', 'ADMIN_USER_ENABLED', 'ADMIN_SESSION_KILLED', 'ADMIN_TOKEN_REVOKED',
              'ADMIN_USER_SESSIONS_REVOKED', 'ADMIN_USER_ROLE_CHANGED', 'ADMIN_USER_LOCKED', 'ADMIN_USER_UNLOCKED',
              'ADMIN_PASSWORD_RESET_FORCED',
              'USER_PASSWORD_CHANGED', 'PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_COMPLETED',
              'USER_SESSION_REVOKED_SELF', 'USER_SESSIONS_REVOKED_ALL_SELF',
              'GOOGLE_ACCOUNT_LINKED', 'GOOGLE_ACCOUNT_UNLINKED', 'GOOGLE_LINK_FAILURE',
              'RBAC_ROLE_CREATED', 'RBAC_ROLE_UPDATED', 'RBAC_USER_ROLE_ASSIGNED', 'RBAC_USER_ROLE_REMOVED'
            )
            ORDER BY created_at DESC
            FETCH FIRST :limit ROWS ONLY
            """)
    Flux<SecurityAuditRow> findRecentAuthEvents(@Param("limit") int limit);

    @Query(
            """
            SELECT COUNT(*) FROM security_audit_event
            WHERE created_at >= :since
              AND event_type IN (
                'LOGIN_SUCCESS', 'GOOGLE_LOGIN_SUCCESS', 'LOGIN_FAILURE', 'GOOGLE_LOGIN_FAILURE',
                'LOGIN_TEMP_LOCKOUT', 'REFRESH_SUCCESS', 'REFRESH_FAILURE',
                'LOGOUT', 'TOKEN_REVOKED', 'OTHER_SESSIONS_REVOKED', 'GUEST_SESSION_CREATED',
                'ADMIN_USER_DISABLED', 'ADMIN_USER_ENABLED', 'ADMIN_SESSION_KILLED', 'ADMIN_TOKEN_REVOKED',
                'ADMIN_USER_SESSIONS_REVOKED', 'ADMIN_USER_ROLE_CHANGED', 'ADMIN_USER_LOCKED', 'ADMIN_USER_UNLOCKED',
                'ADMIN_PASSWORD_RESET_FORCED',
                'USER_PASSWORD_CHANGED', 'PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_COMPLETED',
                'USER_SESSION_REVOKED_SELF', 'USER_SESSIONS_REVOKED_ALL_SELF',
                'GOOGLE_ACCOUNT_LINKED', 'GOOGLE_ACCOUNT_UNLINKED', 'GOOGLE_LINK_FAILURE',
                'RBAC_ROLE_CREATED', 'RBAC_ROLE_UPDATED', 'RBAC_USER_ROLE_ASSIGNED', 'RBAC_USER_ROLE_REMOVED'
              )
            """)
    Mono<Long> countAuthEventsSince(@Param("since") Instant since);

    @Query(
            """
            SELECT COUNT(*) FROM security_audit_event
            WHERE created_at >= :since AND event_type IN ('LOGIN_SUCCESS', 'GOOGLE_LOGIN_SUCCESS')
            """)
    Mono<Long> countLoginSuccessSince(@Param("since") Instant since);

    @Query(
            """
            SELECT COUNT(*) FROM security_audit_event
            WHERE created_at >= :since AND event_type = 'LOGIN_FAILURE'
            """)
    Mono<Long> countLoginFailureSince(@Param("since") Instant since);

    @Query(
            """
            SELECT COUNT(*) FROM security_audit_event
            WHERE created_at >= :since AND event_type = 'GUEST_SESSION_CREATED'
            """)
    Mono<Long> countGuestSessionsSince(@Param("since") Instant since);

    @Query(
            """
            SELECT COUNT(*) FROM security_audit_event
            WHERE created_at >= :since AND event_type = 'REFRESH_SUCCESS'
            """)
    Mono<Long> countRefreshSuccessSince(@Param("since") Instant since);

    @Query(
            """
            SELECT user_id AS userId, MAX(created_at) AS lastLogin
            FROM security_audit_event
            WHERE event_type IN ('LOGIN_SUCCESS', 'GOOGLE_LOGIN_SUCCESS')
              AND user_id IN (:ids)
            GROUP BY user_id
            """)
    Flux<UserLastLoginRow> findLastLoginSuccessAggregatedByUserIds(@Param("ids") List<UUID> ids);

    @Query(
            """
            SELECT COUNT(*) FROM security_audit_event
            WHERE event_type = 'LOGIN_FAILURE'
              AND created_at >= :since
              AND (
                user_id = :userId
                OR (
                  :emailNorm <> ''
                  AND LOWER(TRIM(COALESCE(email, ''))) = :emailNorm
                )
              )
            """)
    Mono<Long> countLoginFailuresForUserSince(
            @Param("userId") UUID userId, @Param("emailNorm") String emailNorm, @Param("since") Instant since);
}
