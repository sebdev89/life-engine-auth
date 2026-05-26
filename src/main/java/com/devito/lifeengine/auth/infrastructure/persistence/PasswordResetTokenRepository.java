package com.devito.lifeengine.auth.infrastructure.persistence;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface PasswordResetTokenRepository extends ReactiveCrudRepository<PasswordResetTokenRow, UUID> {

    @Query(
            """
            SELECT * FROM password_reset_token
            WHERE token_hash = :hash
              AND used_at IS NULL
              AND expires_at > NOW()
            LIMIT 1
            """)
    Mono<PasswordResetTokenRow> findActiveByTokenHash(@Param("hash") String hash);
}
