package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.LocalDevRegisterRequest;
import com.devito.lifeengine.auth.infrastructure.bootstrap.LifeEngineDeploymentGuard;
import com.devito.lifeengine.auth.infrastructure.config.LocalDevRegistrationProperties;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRoleRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.springframework.context.annotation.Conditional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import com.devito.lifeengine.auth.infrastructure.conditions.NotProductionEnvironmentCondition;

@Service
@ConditionalOnProperty(prefix = "lifeengine.security.local-dev-registration", name = "enabled", havingValue = "true")
@Conditional(NotProductionEnvironmentCondition.class)
public class LocalDevRegistrationService {

    private final BoUserRepository users;
    private final AuthRoleRepository roles;
    private final R2dbcEntityTemplate entityTemplate;
    private final PasswordEncoder passwordEncoder;
    private final LocalDevRegistrationProperties props;
    private final Environment environment;

    public LocalDevRegistrationService(
            BoUserRepository users,
            AuthRoleRepository roles,
            R2dbcEntityTemplate entityTemplate,
            PasswordEncoder passwordEncoder,
            LocalDevRegistrationProperties props,
            Environment environment) {
        this.users = users;
        this.roles = roles;
        this.entityTemplate = entityTemplate;
        this.passwordEncoder = passwordEncoder;
        this.props = props;
        this.environment = environment;
    }

    public Mono<Void> register(LocalDevRegisterRequest req) {
        if (LifeEngineDeploymentGuard.isProduction(environment)) {
            return Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND));
        }
        String email = req.email().trim().toLowerCase(Locale.ROOT);
        if (!emailAllowed(email)) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "email_domain_not_allowed"));
        }
        try {
            PasswordPolicy.validate(req.password(), email);
        } catch (ResponseStatusException e) {
            return Mono.error(e);
        }
        return users.findByEmailIgnoreCase(email)
                .flatMap(
                        u ->
                                Mono.<Void>error(
                                        new ResponseStatusException(HttpStatus.CONFLICT, "email_already_registered")))
                .switchIfEmpty(insertUserAndRole(email, req.password()))
                .then();
    }

    private boolean emailAllowed(String email) {
        String lower = email.toLowerCase(Locale.ROOT);
        for (String suffix : props.getAllowedEmailDomainSuffixes()) {
            if (suffix == null || suffix.isBlank()) {
                continue;
            }
            if (lower.endsWith(suffix.trim().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private Mono<Void> insertUserAndRole(String email, String rawPassword) {
        BoUserRow row = new BoUserRow();
        row.setId(UUID.randomUUID());
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
                .flatMap(
                        saved ->
                                roles.findByCode("USER")
                                        .switchIfEmpty(
                                                Mono.error(
                                                        new ResponseStatusException(
                                                                HttpStatus.INTERNAL_SERVER_ERROR,
                                                                "role_user_missing")))
                                        .flatMap(
                                                role -> {
                                                    BoUserRoleRow ur = new BoUserRoleRow();
                                                    ur.setId(UUID.randomUUID());
                                                    ur.setBoUserId(saved.getId());
                                                    ur.setRoleId(role.getId());
                                                    ur.setAssignedAt(Instant.now());
                                                    return entityTemplate.insert(ur).then();
                                                }));
    }
}
