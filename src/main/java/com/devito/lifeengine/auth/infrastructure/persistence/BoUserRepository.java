package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BoUserRepository extends ReactiveCrudRepository<BoUserRow, UUID> {

    @Query("SELECT * FROM bo_user WHERE LOWER(email) = LOWER(:email) LIMIT 1")
    Mono<BoUserRow> findByEmailIgnoreCase(@Param("email") String email);

    @Query("SELECT * FROM bo_user ORDER BY created_at DESC")
    Flux<BoUserRow> findAllOrderByCreatedAtDesc();

    @Query("SELECT COUNT(*) FROM bo_user WHERE locked = TRUE")
    Mono<Long> countLockedAccounts();
}
