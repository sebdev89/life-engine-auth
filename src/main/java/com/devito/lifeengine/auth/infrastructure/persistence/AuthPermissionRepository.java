package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AuthPermissionRepository extends ReactiveCrudRepository<AuthPermissionRow, UUID> {

    Mono<AuthPermissionRow> findByCode(String code);

    Flux<AuthPermissionRow> findAllByOrderByCodeAsc();

    @Query(
            """
            SELECT DISTINCT p.id, p.code, p.description, p.created_at
            FROM auth_permission p
            JOIN auth_role_permission rp ON rp.permission_id = p.id
            JOIN bo_user_role ur ON ur.role_id = rp.role_id
            WHERE ur.bo_user_id = :uid
            ORDER BY p.code
            """)
    Flux<AuthPermissionRow> findDistinctPermissionsForBoUser(@Param("uid") UUID uid);

    @Query(
            """
            SELECT p.id, p.code, p.description, p.created_at
            FROM auth_permission p
            JOIN auth_role_permission rp ON rp.permission_id = p.id
            WHERE rp.role_id = :rid
            ORDER BY p.code
            """)
    Flux<AuthPermissionRow> findPermissionsForRole(@Param("rid") UUID rid);
}
