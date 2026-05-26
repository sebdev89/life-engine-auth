package com.devito.lifeengine.auth.infrastructure.bootstrap;

import com.devito.lifeengine.auth.application.PasswordPolicy;
import com.devito.lifeengine.auth.infrastructure.config.LocalDevOperatorSeedProperties;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Deterministic BO operator for local/dev and Playwright — runs after empty-table bootstrap may have skipped.
 *
 * <p>Idempotent: upserts by email; optionally re-hashes password each boot via {@link
 * LocalDevOperatorSeedProperties#isSyncPassword()}. RBAC roles from {@link LocalDevOperatorSeedProperties#getRoles()}.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
@ConditionalOnProperty(prefix = "lifeengine.security.local-dev-operator-seed", name = "enabled", havingValue = "true")
public class LocalDevOperatorSeedRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(LocalDevOperatorSeedRunner.class);

    /** Stable id for FK references and idempotent inserts (distinct from CI SQL seed UUID). */
    public static final UUID LOCAL_DEV_E2E_USER_ID = UUID.fromString("e0000000-0000-4000-8000-00000000e2e0");

    private final BoUserRepository users;
    private final R2dbcEntityTemplate entityTemplate;
    private final PasswordEncoder passwordEncoder;
    private final LocalDevOperatorSeedProperties props;
    private final Environment environment;
    private final SecurityDevSeedSupport seedSupport;

    public LocalDevOperatorSeedRunner(
            BoUserRepository users,
            R2dbcEntityTemplate entityTemplate,
            PasswordEncoder passwordEncoder,
            LocalDevOperatorSeedProperties props,
            Environment environment,
            SecurityDevSeedSupport seedSupport) {
        this.users = users;
        this.entityTemplate = entityTemplate;
        this.passwordEncoder = passwordEncoder;
        this.props = props;
        this.environment = environment;
        this.seedSupport = seedSupport;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (LifeEngineDeploymentGuard.isProduction(environment)) {
            log.error(
                    "LocalDevOperatorSeedRunner: refusing to run in production — disable lifeengine.security.local-dev-operator-seed.enabled");
            return;
        }
        String email = props.getEmail() == null ? "" : props.getEmail().trim().toLowerCase(Locale.ROOT);
        String rawPassword = props.getPassword() == null ? "" : props.getPassword();
        if (email.isEmpty()) {
            log.warn("LocalDevOperatorSeedRunner: skip — email blank");
            return;
        }
        if (rawPassword.isBlank()) {
            log.warn(
                    "LocalDevOperatorSeedRunner: skip — password blank (set lifeengine.security.local-dev-operator-seed.password or LOCAL_DEV_E2E_PASSWORD)");
            return;
        }
        try {
            PasswordPolicy.validate(rawPassword, email);
        } catch (Exception e) {
            log.warn("LocalDevOperatorSeedRunner: skip — password does not meet policy: {}", e.toString());
            return;
        }

        users.findByEmailIgnoreCase(email)
                .flatMap(this::seedExistingUser)
                .switchIfEmpty(Mono.defer(() -> insertNewUser(email, rawPassword)))
                .flatMap(u -> ensureOperatorRbac(u, email))
                .doOnError(e -> log.error("LocalDevOperatorSeedRunner: failed for email={}", email, e))
                .onErrorResume(e -> Mono.empty())
                .block();
    }

    private List<String> effectiveRoleCodes() {
        List<String> n = SecurityDevSeedSupport.normalizeRoleCodes(props.getRoles());
        return n.isEmpty() ? List.of("USER") : n;
    }

    private Mono<BoUserRow> seedExistingUser(BoUserRow existing) {
        if (!props.isSyncPassword()) {
            log.info(
                    "LocalDevOperatorSeedRunner: user already exists email={} id={} (syncPassword=false, leaving hash unchanged)",
                    existing.getEmail(),
                    existing.getId());
            return Mono.just(existing);
        }
        String raw = props.getPassword();
        existing.setPasswordHash(passwordEncoder.encode(raw));
        existing.setFailedLoginAttempts(0);
        existing.setLockedUntil(null);
        existing.setLocked(false);
        existing.setEnabled(true);
        existing.setPasswordChangedAt(Instant.now());
        return entityTemplate
                .update(existing)
                .doOnSuccess(
                        u ->
                                log.warn(
                                        "LocalDevOperatorSeedRunner: refreshed password hash for email={} id={}",
                                        u.getEmail(),
                                        u.getId()));
    }

    private Mono<BoUserRow> insertNewUser(String email, String rawPassword) {
        List<String> roleCodes = effectiveRoleCodes();
        BoUserRow row = new BoUserRow();
        row.setId(LOCAL_DEV_E2E_USER_ID);
        row.setEmail(email);
        row.setPasswordHash(passwordEncoder.encode(rawPassword));
        row.setEnabled(true);
        row.setLocked(false);
        row.setFailedLoginAttempts(0);
        row.setLockedUntil(null);
        row.setCreatedAt(Instant.now());
        row.setPasswordChangedAt(Instant.now());
        return entityTemplate
                .insert(row)
                .doOnSuccess(
                        u ->
                                log.warn(
                                        "LocalDevOperatorSeedRunner: inserted local dev operator id={} email={}",
                                        u.getId(),
                                        u.getEmail()))
                .onErrorResume(
                        DuplicateKeyException.class,
                        e ->
                                users.findByEmailIgnoreCase(email)
                                        .switchIfEmpty(
                                                Mono.error(
                                                        new IllegalStateException(
                                                                "Duplicate key but email not found: " + email, e)))
                                        .flatMap(this::seedExistingUser));
    }

    private Mono<BoUserRow> ensureOperatorRbac(BoUserRow user, String email) {
        List<String> roleCodes = effectiveRoleCodes();
        UUID id = user.getId();
        return seedSupport
                .ensureRoleLinks(id, roleCodes)
                .doOnSuccess(
                        v ->
                                log.info(
                                        "Local dev operator ensured with roles {} email={} id={}",
                                        roleCodes,
                                        email,
                                        id))
                .thenReturn(user);
    }
}
