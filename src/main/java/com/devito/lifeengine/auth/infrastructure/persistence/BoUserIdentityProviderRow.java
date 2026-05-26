package com.devito.lifeengine.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Table("bo_user_identity_provider")
public class BoUserIdentityProviderRow {

    public static final String PROVIDER_GOOGLE = "google";

    @Id
    private UUID id;

    @Column("bo_user_id")
    private UUID boUserId;

    private String provider;

    @Column("provider_subject")
    private String providerSubject;

    @Column("linked_email")
    private String linkedEmail;

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

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getProviderSubject() {
        return providerSubject;
    }

    public void setProviderSubject(String providerSubject) {
        this.providerSubject = providerSubject;
    }

    public String getLinkedEmail() {
        return linkedEmail;
    }

    public void setLinkedEmail(String linkedEmail) {
        this.linkedEmail = linkedEmail;
    }

    @Column("created_at")
    private Instant createdAt;

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
