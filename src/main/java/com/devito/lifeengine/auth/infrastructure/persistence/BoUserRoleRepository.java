package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BoUserRoleRepository extends ReactiveCrudRepository<BoUserRoleRow, UUID> {

    Flux<BoUserRoleRow> findByBoUserId(UUID boUserId);

    Mono<Boolean> existsByBoUserIdAndRoleId(UUID boUserId, UUID roleId);

    @Modifying
    @Query("DELETE FROM bo_user_role WHERE bo_user_id = :uid")
    Mono<Long> deleteByBoUserId(@Param("uid") UUID uid);

    @Modifying
    @Query("DELETE FROM bo_user_role WHERE bo_user_id = :uid AND role_id = :rid")
    Mono<Long> deleteByBoUserIdAndRoleId(@Param("uid") UUID uid, @Param("rid") UUID rid);

    @Query("SELECT COUNT(*) FROM bo_user_role WHERE role_id = :rid")
    Mono<Long> countByRoleId(@Param("rid") UUID rid);

    @Query("SELECT COUNT(*) FROM bo_user_role WHERE bo_user_id = :uid")
    Mono<Long> countByBoUserId(@Param("uid") UUID uid);
}
