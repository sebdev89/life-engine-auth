package com.devito.lifeengine.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Table("refresh_token")
public class RefreshTokenRow {

    @Id
    private UUID id;

    @Column("bo_user_id")
    private UUID boUserId;

    @Column("guest_session_id")
    private UUID guestSessionId;

    /** Stable id for operator “session” — same across refresh rotations for one login/device. */
    @Column("session_id")
    private UUID sessionId;

    @Column("token_hash")
    private String tokenHash;

    @Column("expires_at")
    private Instant expiresAt;

    private Boolean revoked;

    @Column("created_at")
    private Instant createdAt;

    @Column("client_ip")
    private String clientIp;

    @Column("client_user_agent")
    private String clientUserAgent;

    @Column("last_seen_at")
    private Instant lastSeenAt;

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

    public UUID getGuestSessionId() {
        return guestSessionId;
    }

    public void setGuestSessionId(UUID guestSessionId) {
        this.guestSessionId = guestSessionId;
    }

    public UUID getSessionId() {
        return sessionId;
    }

    public void setSessionId(UUID sessionId) {
        this.sessionId = sessionId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Boolean getRevoked() {
        return revoked;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
    }

    public boolean isRevoked() {
        return revoked != null && revoked;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getClientIp() {
        return clientIp;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    public String getClientUserAgent() {
        return clientUserAgent;
    }

    public void setClientUserAgent(String clientUserAgent) {
        this.clientUserAgent = clientUserAgent;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }
}
