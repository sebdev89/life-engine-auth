package com.devito.lifeengine.auth.infrastructure.bootstrap;

import com.devito.lifeengine.auth.application.PasswordPolicy;
import com.devito.lifeengine.auth.infrastructure.config.AdminSeedProperties;
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
 * Deterministic admin BO user for local/dev — separate from {@link LocalDevOperatorSeedRunner}. Never enable in
 * production YAML.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
@ConditionalOnProperty(prefix = "lifeengine.security.admin-seed", name = "enabled", havingValue = "true")
public class AdminSeedRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminSeedRunner.class);

    /** Stable id for idempotent inserts (distinct from e2e and CI seeds). */
    public static final UUID ADMIN_SEED_USER_ID = UUID.fromString("a0000000-0000-4000-8000-000000000001");

    private final BoUserRepository users;
    private final R2dbcEntityTemplate entityTemplate;
    private final PasswordEncoder passwordEncoder;
    private final AdminSeedProperties props;
    private final Environment environment;
    private final SecurityDevSeedSupport seedSupport;

    public AdminSeedRunner(
            BoUserRepository users,
            R2dbcEntityTemplate entityTemplate,
            PasswordEncoder passwordEncoder,
            AdminSeedProperties props,
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
                    "AdminSeedRunner: refusing to run in production — disable lifeengine.security.admin-seed.enabled");
            return;
        }
        String email = props.getEmail() == null ? "" : props.getEmail().trim().toLowerCase(Locale.ROOT);
        String rawPassword = props.getPassword() == null ? "" : props.getPassword();
        if (email.isEmpty()) {
            log.warn("AdminSeedRunner: skip — email blank");
            return;
        }
        if (rawPassword.isBlank()) {
            log.warn("AdminSeedRunner: skip — password blank (set lifeengine.security.admin-seed.password or LOCAL_DEV_ADMIN_PASSWORD)");
            return;
        }
        if (!validatePasswordForSeed(rawPassword, email)) {
            return;
        }

        users.findByEmailIgnoreCase(email)
                .switchIfEmpty(Mono.defer(() -> insertAdmin(email, rawPassword)))
                .flatMap(u -> ensureAdminRbac(u, email))
                .doOnError(e -> log.error("AdminSeedRunner: failed for email={}", email, e))
                .onErrorResume(e -> Mono.empty())
                .block();
    }

    /** @return {@code false} when seed should abort (already logged). */
    private boolean validatePasswordForSeed(String rawPassword, String email) {
        if (props.isRelaxPasswordPolicy()) {
            if (rawPassword.length() > PasswordPolicy.MAX_LENGTH) {
                log.warn(
                        "AdminSeedRunner: skip — password longer than {} chars",
                        PasswordPolicy.MAX_LENGTH);
                return false;
            }
            return true;
        }
        try {
            PasswordPolicy.validate(rawPassword, email);
        } catch (Exception e) {
            log.warn("AdminSeedRunner: skip — password does not meet policy: {}", e.toString());
            return false;
        }
        return true;
    }

    private List<String> effectiveRoleCodes() {
        List<String> n = SecurityDevSeedSupport.normalizeRoleCodes(props.getRoles());
        return n.isEmpty() ? List.of("ADMIN") : n;
    }

    private Mono<BoUserRow> insertAdmin(String email, String rawPassword) {
        List<String> roleCodes = effectiveRoleCodes();
        BoUserRow row = new BoUserRow();
        row.setId(ADMIN_SEED_USER_ID);
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
                        u -> log.warn("AdminSeedRunner: inserted admin seed user id={} email={}", u.getId(), u.getEmail()))
                .onErrorResume(
                        DuplicateKeyException.class,
                        e ->
                                users.findByEmailIgnoreCase(email)
                                        .switchIfEmpty(
                                                Mono.error(
                                                        new IllegalStateException(
                                                                "Duplicate key but email not found: " + email, e))));
    }

    private Mono<BoUserRow> ensureAdminRbac(BoUserRow user, String email) {
        List<String> roleCodes = effectiveRoleCodes();
        UUID id = user.getId();
        return seedSupport
                .ensureRoleLinks(id, roleCodes)
                .doOnSuccess(
                        v ->
                                log.info(
                                        "Local admin seed ensured with roles {} email={} id={}",
                                        roleCodes,
                                        email,
                                        id))
                .thenReturn(user);
    }
}
