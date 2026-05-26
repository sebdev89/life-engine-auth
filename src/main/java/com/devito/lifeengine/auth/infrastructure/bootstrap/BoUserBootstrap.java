package com.devito.lifeengine.auth.infrastructure.bootstrap;

import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Seeds a default admin when {@code bo_user} is empty. Credentials from {@code AUTH_BOOTSTRAP_USER} /
 * {@code AUTH_BOOTSTRAP_PASSWORD} (bound as {@code lifeengine.security.bootstrap-admin-*}).
 */
@Component
public class BoUserBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BoUserBootstrap.class);

    private final BoUserRepository users;
    private final R2dbcEntityTemplate entityTemplate;
    private final PasswordEncoder passwordEncoder;
    private final Environment environment;
    private final SecurityDevSeedSupport seedSupport;

    @Value("${lifeengine.security.bootstrap-admin-password:}")
    private String bootstrapPassword;

    @Value("${lifeengine.security.bootstrap-admin-email:}")
    private String bootstrapEmail;

    public BoUserBootstrap(
            BoUserRepository users,
            R2dbcEntityTemplate entityTemplate,
            PasswordEncoder passwordEncoder,
            Environment environment,
            SecurityDevSeedSupport seedSupport) {
        this.users = users;
        this.entityTemplate = entityTemplate;
        this.passwordEncoder = passwordEncoder;
        this.environment = environment;
        this.seedSupport = seedSupport;
    }

    @Override
    public void run(ApplicationArguments args) {
        String email = bootstrapEmail == null ? "" : bootstrapEmail.trim().toLowerCase();
        int passwordLen = bootstrapPassword == null ? 0 : bootstrapPassword.length();
        log.info("BoUserBootstrap: start (email={}, password length={})", email, passwordLen);

        users.count()
                .flatMap(
                        n -> {
                            log.info("BoUserBootstrap: bo_user count before seed={}", n);
                            if (n > 0) {
                                log.info("BoUserBootstrap: skip seed — table not empty");
                                return Mono.empty();
                            }
                            String appEnv =
                                    environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase();
                            if ("prod".equals(appEnv)) {
                                if (email.isEmpty() || bootstrapPassword == null || bootstrapPassword.isBlank()) {
                                    return Mono.error(
                                            new IllegalStateException(
                                                    "APP_ENV=prod: AUTH_BOOTSTRAP_USER and AUTH_BOOTSTRAP_PASSWORD are required when bo_user is empty."));
                                }
                            } else if (email.isEmpty() || bootstrapPassword == null || bootstrapPassword.isBlank()) {
                                log.warn(
                                        "BoUserBootstrap: skip seed — bootstrap admin email/password not configured");
                                return Mono.empty();
                            }
                            log.info("BoUserBootstrap: inserting default ADMIN row");
                            BoUserRow u = new BoUserRow();
                            u.setId(UUID.randomUUID());
                            u.setEmail(email);
                            u.setPasswordHash(passwordEncoder.encode(bootstrapPassword));
                            u.setEnabled(true);
                            u.setCreatedAt(Instant.now());
                            return entityTemplate
                                    .insert(u)
                                    .flatMap(
                                            saved ->
                                                    seedSupport
                                                            .ensureRoleLinks(saved.getId(), List.of("ADMIN"))
                                                            .doOnSuccess(
                                                                    v ->
                                                                            log.warn(
                                                                                    "BoUserBootstrap: seeded default admin id={} email={} — rotate AUTH_BOOTSTRAP_PASSWORD after first login",
                                                                                    saved.getId(),
                                                                                    email))
                                                            .thenReturn(saved));
                        })
                .onErrorResume(
                        e -> {
                            if (e instanceof IllegalStateException) {
                                return Mono.error(e);
                            }
                            log.error(
                                    "BoUserBootstrap: failed (count or insert). Fix DB/R2DBC mapping and retry.",
                                    e);
                            return Mono.empty();
                        })
                .block();
    }
}
