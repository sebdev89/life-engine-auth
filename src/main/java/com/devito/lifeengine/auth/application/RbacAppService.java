package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.api.RbacDtos;
import com.devito.lifeengine.auth.api.RbacDtos.AssignRoleRequest;
import com.devito.lifeengine.auth.api.RbacDtos.CreateRoleRequest;
import com.devito.lifeengine.auth.api.RbacDtos.PermissionDto;
import com.devito.lifeengine.auth.api.RbacDtos.RoleDetailDto;
import com.devito.lifeengine.auth.api.RbacDtos.RoleSummaryDto;
import com.devito.lifeengine.auth.api.RbacDtos.UpdateRoleRequest;
import com.devito.lifeengine.auth.domain.BoUserPrincipal;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthPermissionRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthPermissionRow;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRoleRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRoleRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRow;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class RbacAppService {

    private static final Pattern ROLE_CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,31}$");

    private final AuthRoleRepository roles;
    private final AuthPermissionRepository permissions;
    private final BoUserRoleRepository userRoles;
    private final BoUserRepository users;
    private final SecurityAuditService securityAudit;
    private final DatabaseClient databaseClient;

    public RbacAppService(
            AuthRoleRepository roles,
            AuthPermissionRepository permissions,
            BoUserRoleRepository userRoles,
            BoUserRepository users,
            SecurityAuditService securityAudit,
            DatabaseClient databaseClient) {
        this.roles = roles;
        this.permissions = permissions;
        this.userRoles = userRoles;
        this.users = users;
        this.securityAudit = securityAudit;
        this.databaseClient = databaseClient;
    }

    /**
     * Control-plane: replace all {@code bo_user_role} rows with a single role (canonical RBAC). JWT issuance uses
     * {@link EffectiveAuthorityService#resolvePrimaryRoleCode} / permissions from RBAC tables only.
     */
    public Mono<Void> syncUserToSingleRole(UUID userId, String roleCode) {
        String code = roleCode.trim().toUpperCase(Locale.ROOT);
        return roles
                .findByCode(code)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "unknown role")))
                .flatMap(
                        role ->
                                users
                                        .findById(userId)
                                        .switchIfEmpty(
                                                Mono.error(
                                                        new ResponseStatusException(
                                                                HttpStatus.NOT_FOUND, "user not found")))
                                        .flatMap(
                                                u ->
                                                        userRoles
                                                                .deleteByBoUserId(userId)
                                                                .then(insertUserRole(userId, role.getId()))));
    }

    public Flux<RoleSummaryDto> listRoles() {
        return roles.findAllByOrderByCodeAsc()
                .map(
                        r ->
                                new RoleSummaryDto(
                                        r.getId(), r.getCode(), r.getName(), r.isSystemRole(), r.getCreatedAt()));
    }

    public Mono<RoleDetailDto> getRole(UUID id) {
        return roles
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "role not found")))
                .flatMap(
                        r ->
                                permissions
                                        .findPermissionsForRole(r.getId())
                                        .map(p -> new PermissionDto(p.getId(), p.getCode(), p.getDescription()))
                                        .sort(Comparator.comparing(PermissionDto::code))
                                        .collectList()
                                        .map(
                                                perms ->
                                                        new RoleDetailDto(
                                                                r.getId(),
                                                                r.getCode(),
                                                                r.getName(),
                                                                r.isSystemRole(),
                                                                perms,
                                                                r.getCreatedAt())));
    }

    public Mono<RoleDetailDto> createRole(
            CreateRoleRequest req, BoUserPrincipal actor, AuditContext ctx) {
        String code = req.code().trim().toUpperCase(Locale.ROOT);
        if (!ROLE_CODE.matcher(code).matches()) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid role code"));
        }
        return roles
                .findByCode(code)
                .flatMap(
                        existing ->
                                Mono.<RoleDetailDto>error(
                                        new ResponseStatusException(HttpStatus.CONFLICT, "role code already exists")))
                .switchIfEmpty(
                        Mono.defer(
                                () ->
                                        validatePermissionIds(req.permissionIds())
                                                .flatMap(
                                                        validIds -> {
                                                            AuthRoleRow row = new AuthRoleRow();
                                                            row.setId(UUID.randomUUID());
                                                            row.setCode(code);
                                                            row.setName(req.name().trim());
                                                            row.setSystemRole(false);
                                                            row.setCreatedAt(Instant.now());
                                                            return roles
                                                                    .save(row)
                                                                    .flatMap(
                                                                            saved ->
                                                                                    replacePermissionsForRole(
                                                                                                    saved.getId(),
                                                                                                    validIds)
                                                                                            .then(
                                                                                                    securityAudit
                                                                                                            .record(
                                                                                                                    SecurityAuditEventType
                                                                                                                            .RBAC_ROLE_CREATED,
                                                                                                                    SecurityAuditService
                                                                                                                            .OUTCOME_SUCCESS,
                                                                                                                    saved.getId(),
                                                                                                                    null,
                                                                                                                    ctx,
                                                                                                                    rbacDetail(actor)
                                                                                                                            + " code="
                                                                                                                            + saved.getCode()
                                                                                                                            + " name="
                                                                                                                            + saved.getName()))
                                                                                            .then(getRole(saved.getId())));
                                                        })));
    }

    public Mono<RoleDetailDto> updateRole(
            UUID id, UpdateRoleRequest req, BoUserPrincipal actor, AuditContext ctx) {
        if (req.name() == null && req.permissionIds() == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "no changes"));
        }
        return roles
                .findById(id)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "role not found")))
                .flatMap(
                        r -> {
                            if (r.isSystemRole()) {
                                if (req.permissionIds() != null) {
                                    return permissions
                                            .findPermissionsForRole(r.getId())
                                            .map(AuthPermissionRow::getId)
                                            .collectList()
                                            .flatMap(
                                                    current -> {
                                                        if (!samePermissionSet(current, req.permissionIds())) {
                                                            return Mono.error(
                                                                    new ResponseStatusException(
                                                                            HttpStatus.BAD_REQUEST,
                                                                            "system role permissions are immutable"));
                                                        }
                                                        return applyRoleUpdate(r, req, actor, ctx);
                                                    });
                                }
                                return applyRoleUpdate(r, req, actor, ctx);
                            }
                            return applyRoleUpdate(r, req, actor, ctx);
                        });
    }

    private Mono<RoleDetailDto> applyRoleUpdate(
            AuthRoleRow r, UpdateRoleRequest req, BoUserPrincipal actor, AuditContext ctx) {
        if (req.name() != null && !req.name().isBlank()) {
            r.setName(req.name().trim());
        }
        Mono<Void> permMono =
                req.permissionIds() != null
                        ? validatePermissionIds(req.permissionIds())
                                .flatMap(ids -> replacePermissionsForRole(r.getId(), ids))
                        : Mono.empty();
        return permMono.then(
                roles.save(r)
                        .then(
                                securityAudit.record(
                                        SecurityAuditEventType.RBAC_ROLE_UPDATED,
                                        SecurityAuditService.OUTCOME_SUCCESS,
                                        r.getId(),
                                        null,
                                        ctx,
                                        rbacDetail(actor)
                                                + " code="
                                                + r.getCode()
                                                + (req.permissionIds() != null ? " permissionsReplaced=true" : "")))
                        .then(getRole(r.getId())));
    }

    private static boolean samePermissionSet(List<UUID> a, List<UUID> b) {
        Set<UUID> sa = new HashSet<>(a);
        Set<UUID> sb = new HashSet<>(b);
        return sa.equals(sb);
    }

    public Mono<Void> assignUserRole(
            UUID userId, AssignRoleRequest req, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(userId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u ->
                                roles
                                        .findById(req.roleId())
                                        .switchIfEmpty(
                                                Mono.error(
                                                        new ResponseStatusException(
                                                                HttpStatus.BAD_REQUEST, "role not found")))
                                        .flatMap(
                                                role ->
                                                        userRoles
                                                                .existsByBoUserIdAndRoleId(userId, role.getId())
                                                                .flatMap(
                                                                        exists -> {
                                                                            if (Boolean.TRUE.equals(exists)) {
                                                                                return Mono.error(
                                                                                        new ResponseStatusException(
                                                                                                HttpStatus.CONFLICT,
                                                                                                "role already assigned"));
                                                                            }
                                                                            BoUserRoleRow row = new BoUserRoleRow();
                                                                            // id left null so Spring Data R2DBC performs INSERT (DB default gen_random_uuid());
                                                                            // a pre-assigned UUID makes the entity "not new" and triggers UPDATE of a missing row.
                                                                            row.setBoUserId(userId);
                                                                            row.setRoleId(role.getId());
                                                                            row.setAssignedAt(Instant.now());
                                                                            return userRoles
                                                                                    .save(row)
                                                                                    .then(
                                                                                            securityAudit.record(
                                                                                                    SecurityAuditEventType
                                                                                                            .RBAC_USER_ROLE_ASSIGNED,
                                                                                                    SecurityAuditService
                                                                                                            .OUTCOME_SUCCESS,
                                                                                                    userId,
                                                                                                    u.getEmail(),
                                                                                                    ctx,
                                                                                                    rbacDetail(actor)
                                                                                                            + " roleId="
                                                                                                            + role.getId()
                                                                                                            + " roleCode="
                                                                                                            + role.getCode()))
                                                                                    .then();
                                                                        })));
    }

    public Mono<Void> removeUserRole(
            UUID userId, UUID roleId, BoUserPrincipal actor, AuditContext ctx) {
        return users
                .findById(userId)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")))
                .flatMap(
                        u ->
                                userRoles
                                        .countByBoUserId(userId)
                                        .flatMap(
                                                cnt -> {
                                                    if (cnt != null && cnt <= 1) {
                                                        return Mono.error(
                                                                new ResponseStatusException(
                                                                        HttpStatus.BAD_REQUEST,
                                                                        "cannot remove last role"));
                                                    }
                                                    return userRoles
                                                            .existsByBoUserIdAndRoleId(userId, roleId)
                                                            .flatMap(
                                                                    ok -> {
                                                                        if (!Boolean.TRUE.equals(ok)) {
                                                                            return Mono.error(
                                                                                    new ResponseStatusException(
                                                                                            HttpStatus.NOT_FOUND,
                                                                                            "assignment not found"));
                                                                        }
                                                                        return roles
                                                                                .findById(roleId)
                                                                                .flatMap(
                                                                                        role ->
                                                                                                userRoles
                                                                                                        .deleteByBoUserIdAndRoleId(
                                                                                                                userId, roleId)
                                                                                                        .then(
                                                                                                                securityAudit
                                                                                                                        .record(
                                                                                                                                SecurityAuditEventType
                                                                                                                                        .RBAC_USER_ROLE_REMOVED,
                                                                                                                                SecurityAuditService
                                                                                                                                        .OUTCOME_SUCCESS,
                                                                                                                                userId,
                                                                                                                                u.getEmail(),
                                                                                                                                ctx,
                                                                                                                                rbacDetail(
                                                                                                                                                actor)
                                                                                                                                        + " roleId="
                                                                                                                                        + roleId
                                                                                                                                        + " roleCode="
                                                                                                                                        + role.getCode()))
                                                                                                        .then());
                                                                    });
                                                }));
    }

    private Mono<List<UUID>> validatePermissionIds(List<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "permissionIds required"));
        }
        List<UUID> distinct = ids.stream().distinct().collect(Collectors.toCollection(ArrayList::new));
        return permissions
                .findAllById(distinct)
                .collectList()
                .flatMap(
                        found -> {
                            if (found.size() != distinct.size()) {
                                return Mono.error(
                                        new ResponseStatusException(HttpStatus.BAD_REQUEST, "unknown permission id"));
                            }
                            return Mono.just(distinct);
                        });
    }

    private Mono<Void> replacePermissionsForRole(UUID roleId, List<UUID> permissionIds) {
        return databaseClient
                .sql("DELETE FROM auth_role_permission WHERE role_id = :rid")
                .bind("rid", roleId)
                .fetch()
                .rowsUpdated()
                .then(
                        Flux.fromIterable(permissionIds)
                                .concatMap(
                                        pid ->
                                                databaseClient
                                                        .sql(
                                                                "INSERT INTO auth_role_permission (role_id, permission_id) VALUES (:rid, :pid)")
                                                        .bind("rid", roleId)
                                                        .bind("pid", pid)
                                                        .fetch()
                                                        .rowsUpdated())
                                .then());
    }

    private Mono<Void> insertUserRole(UUID userId, UUID roleId) {
        BoUserRoleRow row = new BoUserRoleRow();
        row.setBoUserId(userId);
        row.setRoleId(roleId);
        row.setAssignedAt(Instant.now());
        return userRoles.save(row).then();
    }

    private static String rbacDetail(BoUserPrincipal actor) {
        return "actorId="
                + actor.userId()
                + " actorEmail="
                + actor.email().trim().toLowerCase(Locale.ROOT);
    }
}
