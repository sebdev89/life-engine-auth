package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BoUserIdentityProviderRepository extends ReactiveCrudRepository<BoUserIdentityProviderRow, UUID> {

    @Query(
            """
            SELECT * FROM bo_user_identity_provider
            WHERE provider = :provider AND provider_subject = :providerSubject
            LIMIT 1
            """)
    Mono<BoUserIdentityProviderRow> findByProviderAndProviderSubject(
            @Param("provider") String provider, @Param("providerSubject") String providerSubject);

    @Query(
            """
            SELECT * FROM bo_user_identity_provider
            WHERE bo_user_id = :boUserId AND provider = :provider
            LIMIT 1
            """)
    Mono<BoUserIdentityProviderRow> findByBoUserIdAndProvider(
            @Param("boUserId") UUID boUserId, @Param("provider") String provider);

    @Query("SELECT * FROM bo_user_identity_provider WHERE bo_user_id IN (:ids)")
    Flux<BoUserIdentityProviderRow> findByBoUserIdIn(@Param("ids") List<UUID> ids);

    @Query(
            """
            SELECT COUNT(*) FROM bo_user_identity_provider
            WHERE bo_user_id = :uid AND lower(provider) = lower(:provider)
            """)
    Mono<Long> countByBoUserIdAndProvider(@Param("uid") UUID uid, @Param("provider") String provider);

    @Modifying
    @Query(
            """
            DELETE FROM bo_user_identity_provider
            WHERE bo_user_id = :boUserId AND LOWER(provider) = LOWER(:provider)
            """)
    Mono<Long> deleteByBoUserIdAndProvider(@Param("boUserId") UUID boUserId, @Param("provider") String provider);
}
