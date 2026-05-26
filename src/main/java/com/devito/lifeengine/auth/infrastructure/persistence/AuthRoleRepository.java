package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AuthRoleRepository extends ReactiveCrudRepository<AuthRoleRow, UUID> {

    Mono<AuthRoleRow> findByCode(String code);

    Flux<AuthRoleRow> findAllByOrderByCodeAsc();
}
