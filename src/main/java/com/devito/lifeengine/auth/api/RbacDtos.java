package com.devito.lifeengine.auth.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** RBAC REST payloads — permission codes are Spring authority strings (e.g. {@code ROLE_USER}, {@code AUTH:RBAC:MANAGE}). */
public final class RbacDtos {

    private RbacDtos() {}

    public record PermissionDto(UUID id, String code, String description) {}

    public record RoleSummaryDto(UUID id, String code, String name, boolean systemRole, Instant createdAt) {}

    public record RoleDetailDto(
            UUID id,
            String code,
            String name,
            boolean systemRole,
            List<PermissionDto> permissions,
            Instant createdAt) {}

    public record CreateRoleRequest(
            @NotBlank String code,
            @NotBlank String name,
            @NotNull List<UUID> permissionIds) {}

    public record UpdateRoleRequest(String name, List<UUID> permissionIds) {}

    public record AssignRoleRequest(@NotNull UUID roleId) {}
}
