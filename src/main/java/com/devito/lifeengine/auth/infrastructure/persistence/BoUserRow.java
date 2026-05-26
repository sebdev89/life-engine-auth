package com.devito.lifeengine.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Table("bo_user")
public class BoUserRow {

    @Id
    private UUID id;

    private String email;

    @Column("password_hash")
    private String passwordHash;

    private Boolean enabled;

    /** Admin security lock — cannot log in or refresh while true (see {@link #isLocked()}). */
    private Boolean locked;

    @Column("failed_login_attempts")
    private Integer failedLoginAttempts;

    /** Auto lockout after failed attempts; cleared on success or admin unlock. */
    @Column("locked_until")
    private Instant lockedUntil;

    @Column("created_at")
    private Instant createdAt;

    @Column("password_changed_at")
    private Instant passwordChangedAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled != null && enabled;
    }

    public Boolean getLocked() {
        return locked;
    }

    public void setLocked(Boolean locked) {
        this.locked = locked;
    }

    public boolean isLocked() {
        return locked != null && locked;
    }

    public Integer getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(Integer failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    /** True when {@link #lockedUntil} is in the future (brute-force lockout). */
    public boolean isTemporarilyLocked() {
        return lockedUntil != null && lockedUntil.isAfter(Instant.now());
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getPasswordChangedAt() {
        return passwordChangedAt;
    }

    public void setPasswordChangedAt(Instant passwordChangedAt) {
        this.passwordChangedAt = passwordChangedAt;
    }
}
