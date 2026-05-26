package com.devito.lifeengine.auth.application;

import com.devito.lifeengine.auth.infrastructure.persistence.AuthPermissionRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthPermissionRow;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRepository;
import com.devito.lifeengine.auth.infrastructure.persistence.AuthRoleRow;
import com.devito.lifeengine.auth.infrastructure.persistence.BoUserRoleRepository;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Resolves effective permission codes (Spring {@link org.springframework.security.core.GrantedAuthority}
 * names) from {@code bo_user_role} → {@code auth_role} → {@code auth_role_permission}.
 *
 * <p><strong>Canonical source of truth:</strong> {@code bo_user_role}, {@code auth_role},
 * {@code auth_role_permission}, {@code auth_permission}. Users
 * without {@code bo_user_role} rows cannot obtain a primary role or session JWT (see {@link AuthAppService}).
 */
@Service
public class EffectiveAuthorityService {

    private final AuthPermissionRepository permissions;
    private final AuthRoleRepository roles;
    private final BoUserRoleRepository userRoles;

    public EffectiveAuthorityService(
            AuthPermissionRepository permissions,
            AuthRoleRepository roles,
            BoUserRoleRepository userRoles) {
        this.permissions = permissions;
        this.roles = roles;
        this.userRoles = userRoles;
    }

    /** Distinct permission codes (e.g. {@code ROLE_USER}, {@code AUTH:RBAC:MANAGE}). */
    public Mono<List<String>> resolvePermissionCodesForBoUser(UUID boUserId) {
        return permissions
                .findDistinctPermissionsForBoUser(boUserId)
                .map(AuthPermissionRow::getCode)
                .distinct()
                .sort()
                .collectList();
    }

    /**
     * Primary application role code for JWT {@code role} claim and admin directory UI — deterministic when
     * multiple {@code bo_user_role} rows exist ({@code auth_role} codes).
     *
     * @return empty when the user has no {@code bo_user_role} rows (login/refresh must reject)
     */
    public Mono<String> resolvePrimaryRoleCode(UUID boUserId) {
        return userRoles
                .findByBoUserId(boUserId)
                .flatMap(ur -> roles.findById(ur.getRoleId()))
                .collectList()
                .flatMap(
                        roleRows -> {
                            if (roleRows.isEmpty()) {
                                return Mono.empty();
                            }
                            return Mono.just(
                                    roleRows.stream()
                                            .min(Comparator.comparingInt(r -> primaryRank(r.getCode())))
                                            .map(AuthRoleRow::getCode)
                                            .orElse("USER"));
                        });
    }

    private static int primaryRank(String code) {
        if (code == null) {
            return 99;
        }
        return switch (code) {
            case "ADMIN" -> 0;
            case "BO_ADMIN" -> 1;
            case "OPERATOR" -> 2;
            case "USER" -> 3;
            case "VIEWER" -> 4;
            case "GUEST" -> 5;
            default -> 50;
        };
    }
}
