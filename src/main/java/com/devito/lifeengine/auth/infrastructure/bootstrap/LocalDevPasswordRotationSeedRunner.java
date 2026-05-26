package com.devito.lifeengine.auth.infrastructure.bootstrap;

import com.devito.lifeengine.auth.application.PasswordPolicy;
import com.devito.lifeengine.auth.infrastructure.config.LocalDevPasswordRotationSeedProperties;
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
 * Dedicated BO user for destructive change-password E2E — idempotent; never enable in production YAML.
 *
 * <p>Stable UUID distinct from {@link LocalDevOperatorSeedRunner#LOCAL_DEV_E2E_USER_ID}.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
@ConditionalOnProperty(
        prefix = "lifeengine.security.local-dev-password-rotation-seed",
        name = "enabled",
        havingValue = "true")
public class LocalDevPasswordRotationSeedRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(LocalDevPasswordRotationSeedRunner.class);

    /** Distinct from CI primary operator ({@code …e2e1}) and SCP RBAC target ({@code …e2e2}). */
    public static final UUID LOCAL_DEV_PASSWORD_ROTATION_USER_ID =
            UUID.fromString("e0000000-0000-4000-8000-00000000e2e3");

    private final BoUserRepository users;
    private final R2dbcEntityTemplate entityTemplate;
    private final PasswordEncoder passwordEncoder;
    private final LocalDevPasswordRotationSeedProperties props;
    private final Environment environment;
    private final SecurityDevSeedSupport seedSupport;

    public LocalDevPasswordRotationSeedRunner(
            BoUserRepository users,
            R2dbcEntityTemplate entityTemplate,
            PasswordEncoder passwordEncoder,
            LocalDevPasswordRotationSeedProperties props,
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
                    "LocalDevPasswordRotationSeedRunner: refusing to run in production — disable lifeengine.security.local-dev-password-rotation-seed.enabled");
            return;
        }
        String email = props.getEmail() == null ? "" : props.getEmail().trim().toLowerCase(Locale.ROOT);
        String rawPassword = props.getPassword() == null ? "" : props.getPassword();
        if (email.isEmpty()) {
            log.warn("LocalDevPasswordRotationSeedRunner: skip — email blank");
            return;
        }
        if (rawPassword.isBlank()) {
            log.warn(
                    "LocalDevPasswordRotationSeedRunner: skip — password blank (set lifeengine.security.local-dev-password-rotation-seed.password or LOCAL_DEV_PASSWORD_ROTATION_PASSWORD)");
            return;
        }
        try {
            PasswordPolicy.validate(rawPassword, email);
        } catch (Exception e) {
            log.warn("LocalDevPasswordRotationSeedRunner: skip — password does not meet policy: {}", e.toString());
            return;
        }

        users.findByEmailIgnoreCase(email)
                .flatMap(this::seedExistingUser)
                .switchIfEmpty(Mono.defer(() -> insertNewUser(email, rawPassword)))
                .flatMap(u -> ensureRbac(u, email))
                .doOnError(e -> log.error("LocalDevPasswordRotationSeedRunner: failed for email={}", email, e))
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
                    "LocalDevPasswordRotationSeedRunner: user already exists email={} id={} (syncPassword=false, leaving hash unchanged)",
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
                                        "LocalDevPasswordRotationSeedRunner: refreshed password hash for email={} id={}",
                                        u.getEmail(),
                                        u.getId()));
    }

    private Mono<BoUserRow> insertNewUser(String email, String rawPassword) {
        List<String> roleCodes = effectiveRoleCodes();
        BoUserRow row = new BoUserRow();
        row.setId(LOCAL_DEV_PASSWORD_ROTATION_USER_ID);
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
                                        "LocalDevPasswordRotationSeedRunner: inserted user id={} email={}",
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

    private Mono<BoUserRow> ensureRbac(BoUserRow user, String email) {
        List<String> roleCodes = effectiveRoleCodes();
        UUID id = user.getId();
        return seedSupport
                .ensureRoleLinks(id, roleCodes)
                .doOnSuccess(
                        v ->
                                log.info(
                                        "Local dev password-rotation user ensured with roles {} email={} id={}",
                                        roleCodes,
                                        email,
                                        id))
                .thenReturn(user);
    }
}
