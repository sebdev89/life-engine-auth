package com.devito.lifeengine.auth.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.RefreshTokenRow;
import com.devito.lifeengine.auth.infrastructure.persistence.UserSessionRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.UserSessionRow;
import com.devito.lifeengine.support.persistence.AbstractPostgresPersistenceIT;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * R2DBC persistence for {@code user_sessions} and {@code refresh_token}: round-trip CRUD, CHECK constraints, unique
 * indexes, and reactive transaction boundaries.
 */
@Tag("auth")
class AuthSessionRefreshTokenPersistenceIT extends AbstractPostgresPersistenceIT {

    @Autowired private UserSessionRepository userSessions;
    @Autowired private RefreshTokenRepository refreshTokens;
    @Autowired private R2dbcEntityTemplate entityTemplate;

    @Autowired private TransactionalOperator transactionalOperator;

    @Test
    @DisplayName("Guest user_session insert + read (nullable IP/UA, bo_user_id null)")
    void guestUserSessionRoundTrip() {
        UUID sid = UUID.randomUUID();
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        UserSessionRow row = new UserSessionRow();
        row.setId(UUID.randomUUID());
        row.setBoUserId(null);
        row.setGuestSessionId(sid);
        row.setRefreshTokenHash("hash-" + sid);
        row.setCreatedAt(now);
        row.setExpiresAt(now.plus(1, ChronoUnit.HOURS));
        row.setRevokedAt(null);
        row.setIpAddress(null);
        row.setUserAgent(null);

        StepVerifier.create(
                        entityTemplate
                                .insert(UserSessionRow.class)
                                .using(row)
                                .thenMany(userSessions.findByGuestSessionIdOrderByCreatedAtDesc(sid)))
                .assertNext(read -> {
                    assertThat(read.getId()).isEqualTo(row.getId());
                    assertThat(read.getBoUserId()).isNull();
                    assertThat(read.getGuestSessionId()).isEqualTo(sid);
                    assertThat(read.getRefreshTokenHash()).isEqualTo(row.getRefreshTokenHash());
                    assertThat(read.getIpAddress()).isNull();
                    assertThat(read.getUserAgent()).isNull();
                    assertThat(read.getRevokedAt()).isNull();
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("user_sessions CHECK rejects both principals null")
    void userSessionRejectsBothPrincipalsNull() {
        UserSessionRow row = new UserSessionRow();
        row.setId(UUID.randomUUID());
        row.setBoUserId(null);
        row.setGuestSessionId(null);
        row.setRefreshTokenHash("orphan");
        row.setCreatedAt(Instant.now());
        row.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

        StepVerifier.create(entityTemplate.insert(UserSessionRow.class).using(row))
                .expectError(DataIntegrityViolationException.class)
                .verify();
    }

    @Test
    @DisplayName("markRevokedById sets revoked_at (update flow)")
    void markRevokedById() {
        UUID guest = UUID.randomUUID();
        UserSessionRow row = new UserSessionRow();
        row.setId(UUID.randomUUID());
        row.setGuestSessionId(guest);
        row.setRefreshTokenHash("revoke-hash-" + guest);
        row.setCreatedAt(Instant.now());
        row.setExpiresAt(Instant.now().plus(2, ChronoUnit.HOURS));

        StepVerifier.create(
                        entityTemplate
                                .insert(UserSessionRow.class)
                                .using(row)
                                .then(userSessions.markRevokedById(row.getId()))
                                .thenMany(userSessions.findByGuestSessionIdOrderByCreatedAtDesc(guest)))
                .assertNext(read -> assertThat(read.getRevokedAt()).isNotNull())
                .verifyComplete();
    }

    @Test
    @DisplayName("refresh_token UNIQUE(token_hash) rejects duplicate")
    void refreshTokenUniqueHash() {
        UUID guest = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        String hash = "uniq-" + guest;
        Instant exp = Instant.now().plus(6, ChronoUnit.HOURS);

        RefreshTokenRow a = new RefreshTokenRow();
        a.setId(UUID.randomUUID());
        a.setGuestSessionId(guest);
        a.setBoUserId(null);
        a.setSessionId(sessionId);
        a.setTokenHash(hash);
        a.setExpiresAt(exp);
        a.setRevoked(false);
        a.setCreatedAt(Instant.now());

        RefreshTokenRow b = new RefreshTokenRow();
        b.setId(UUID.randomUUID());
        b.setGuestSessionId(guest);
        b.setBoUserId(null);
        b.setSessionId(UUID.randomUUID());
        b.setTokenHash(hash);
        b.setExpiresAt(exp);
        b.setRevoked(false);
        b.setCreatedAt(Instant.now());

        StepVerifier.create(
                        entityTemplate
                                .insert(RefreshTokenRow.class)
                                .using(a)
                                .then(entityTemplate.insert(RefreshTokenRow.class).using(b)))
                .expectErrorSatisfies(
                        ex -> {
                            assertThat(ex).isInstanceOf(DataAccessException.class);
                            assertThat(ex.getMessage().toLowerCase()).matches(".*(duplicate|unique|violates).*");
                        })
                .verify();
    }

    @Test
    @DisplayName("TransactionalOperator: guest session + refresh commit together")
    void transactionalCommitGuestSessionAndRefresh() {
        UUID guest = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        UUID usId = UUID.randomUUID();
        UUID rtId = UUID.randomUUID();
        String hash = "tx-hash-" + guest;
        Instant now = Instant.now();

        UserSessionRow us = new UserSessionRow();
        us.setId(usId);
        us.setGuestSessionId(guest);
        us.setRefreshTokenHash("us-" + hash);
        us.setCreatedAt(now);
        us.setExpiresAt(now.plus(3, ChronoUnit.HOURS));

        RefreshTokenRow rt = new RefreshTokenRow();
        rt.setId(rtId);
        rt.setGuestSessionId(guest);
        rt.setBoUserId(null);
        rt.setSessionId(sessionId);
        rt.setTokenHash(hash);
        rt.setExpiresAt(now.plus(3, ChronoUnit.HOURS));
        rt.setRevoked(false);
        rt.setCreatedAt(now);

        StepVerifier.create(
                        transactionalOperator.transactional(
                                entityTemplate
                                        .insert(UserSessionRow.class)
                                        .using(us)
                                        .flatMap(
                                                ignored ->
                                                        entityTemplate.insert(RefreshTokenRow.class).using(rt))
                                        .then()))
                .verifyComplete();

        StepVerifier.create(refreshTokens.findValidByHash(hash))
                .assertNext(found -> {
                    assertThat(found.getSessionId()).isEqualTo(sessionId);
                    assertThat(found.getGuestSessionId()).isEqualTo(guest);
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("TransactionalOperator: failure rolls back companion insert")
    void transactionalRollback() {
        UUID guest = UUID.randomUUID();
        UUID usId = UUID.randomUUID();
        UserSessionRow us = new UserSessionRow();
        us.setId(usId);
        us.setGuestSessionId(guest);
        us.setRefreshTokenHash("rollback-us-" + guest);
        us.setCreatedAt(Instant.now());
        us.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

        StepVerifier.create(
                        transactionalOperator.transactional(
                                entityTemplate
                                        .insert(UserSessionRow.class)
                                        .using(us)
                                        .then(Mono.error(new IllegalStateException("abort")))))
                .expectError(IllegalStateException.class)
                .verify();

        StepVerifier.create(userSessions.findById(usId)).verifyComplete();
    }

    @Test
    @DisplayName("refreshTokens.revokeAllActiveForSession marks rows revoked (bulk update)")
    void revokeAllActiveForSession() {
        UUID guest = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant exp = Instant.now().plus(4, ChronoUnit.HOURS);
        RefreshTokenRow rt = new RefreshTokenRow();
        rt.setId(UUID.randomUUID());
        rt.setGuestSessionId(guest);
        rt.setBoUserId(null);
        rt.setSessionId(sessionId);
        rt.setTokenHash("revoke-session-" + guest);
        rt.setExpiresAt(exp);
        rt.setRevoked(false);
        rt.setCreatedAt(Instant.now());

        StepVerifier.create(
                        entityTemplate
                                .insert(RefreshTokenRow.class)
                                .using(rt)
                                .then(refreshTokens.revokeAllActiveForSession(sessionId))
                                .thenMany(refreshTokens.findBySessionId(sessionId)))
                .assertNext(r -> assertThat(r.isRevoked()).isTrue())
                .verifyComplete();
    }
}
