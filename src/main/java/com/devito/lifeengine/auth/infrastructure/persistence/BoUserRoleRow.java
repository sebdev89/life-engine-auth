package com.devito.lifeengine.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Table("bo_user_role")
public class BoUserRoleRow {

    @Id
    private UUID id;

    @Column("bo_user_id")
    private UUID boUserId;

    @Column("role_id")
    private UUID roleId;

    private Instant assignedAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getBoUserId() {
        return boUserId;
    }

    public void setBoUserId(UUID boUserId) {
        this.boUserId = boUserId;
    }

    public UUID getRoleId() {
        return roleId;
    }

    public void setRoleId(UUID roleId) {
        this.roleId = roleId;
    }

    public Instant getAssignedAt() {
        return assignedAt;
    }

    public void setAssignedAt(Instant assignedAt) {
        this.assignedAt = assignedAt;
    }
}
