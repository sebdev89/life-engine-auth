package com.devito.lifeengine.auth.infrastructure.bootstrap;

import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRow;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRoleRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRoleRow;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Shared RBAC helpers for local/dev-only seeds ({@code bo_user_role} → {@code auth_role}; optional bootstrap for
 * missing {@code ADMIN} catalog row).
 */
@Component
public class SecurityDevSeedSupport {

    private static final Logger log = LoggerFactory.getLogger(SecurityDevSeedSupport.class);

    /** Same UUID as {@code V49__auth_rbac.sql} for {@code auth_role} row {@code ADMIN}. */
    private static final UUID ADMIN_ROLE_ID = UUID.fromString("b1111111-1111-4111-8111-111111111101");

    private final BoUserRoleRepository userRoles;
    private final AuthRoleRepository roles;
    private final R2dbcEntityTemplate entityTemplate;
    private final DatabaseClient databaseClient;

    public SecurityDevSeedSupport(
            BoUserRoleRepository userRoles,
            AuthRoleRepository roles,
            R2dbcEntityTemplate entityTemplate,
            DatabaseClient databaseClient) {
        this.userRoles = userRoles;
        this.roles = roles;
        this.entityTemplate = entityTemplate;
        this.databaseClient = databaseClient;
    }

    /** Uppercase, trim, drop blanks, stable order preserved. */
    public static List<String> normalizeRoleCodes(List<String> raw) {
        if (raw == null || raw.isEmpty()) {
            return List.of();
        }
        return raw.stream()
                .map(s -> s == null ? "" : s.trim().toUpperCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .distinct()
                .toList();
    }

    public Mono<Void> ensureRoleLinks(UUID userId, List<String> roleCodesUpper) {
        return Flux.fromIterable(roleCodesUpper).concatMap(code -> ensureRoleLink(userId, code)).then();
    }

    private Mono<Void> ensureRoleLink(UUID userId, String roleCode) {
        return roles.findByCode(roleCode)
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        "ADMIN".equals(roleCode)
                                                ? insertAdminRoleAndPermissions()
                                                : Mono.error(
                                                        new IllegalStateException(
                                                                "ROLE " + roleCode + " missing in DB"))))
                .flatMap(role -> linkUserToRoleIfMissing(userId, role))
                .then();
    }

    private Mono<AuthRoleRow> insertAdminRoleAndPermissions() {
        log.warn(
                "SecurityDevSeedSupport: auth_role ADMIN missing — creating role {} (matches V49 seed)",
                ADMIN_ROLE_ID);
        AuthRoleRow row = new AuthRoleRow();
        row.setId(ADMIN_ROLE_ID);
        row.setCode("ADMIN");
        row.setName("Administrator");
        row.setSystemRole(true);
        row.setCreatedAt(Instant.now());
        return entityTemplate
                .insert(row)
                .flatMap(this::linkAdminRolePermissions)
                .onErrorResume(
                        DuplicateKeyException.class,
                        e -> roles.findByCode("ADMIN").switchIfEmpty(Mono.error(e)));
    }

    private Mono<AuthRoleRow> linkAdminRolePermissions(AuthRoleRow admin) {
        return databaseClient
                .sql(
                        """
                        INSERT INTO auth_role_permission (role_id, permission_id)
                        SELECT :rid, id FROM auth_permission WHERE code IN ('ROLE_ADMIN','ROLE_USER','AUTH:RBAC:MANAGE')
                        ON CONFLICT DO NOTHING
                        """)
                .bind("rid", admin.getId())
                .fetch()
                .rowsUpdated()
                .thenReturn(admin);
    }

    private Mono<Void> linkUserToRoleIfMissing(UUID userId, AuthRoleRow role) {
        return userRoles.existsByBoUserIdAndRoleId(userId, role.getId())
                .flatMap(
                        exists -> {
                            if (Boolean.TRUE.equals(exists)) {
                                return Mono.<Void>empty();
                            }
                            BoUserRoleRow ur = new BoUserRoleRow();
                            ur.setId(UUID.randomUUID());
                            ur.setBoUserId(userId);
                            ur.setRoleId(role.getId());
                            ur.setAssignedAt(Instant.now());
                            return entityTemplate.insert(ur).then();
                        });
    }
}
