-- OAuth-only BO users may exist without a password (Google-only accounts).
ALTER TABLE bo_user
  ALTER COLUMN password_hash DROP NOT NULL;

-- Links external IdP subjects (e.g. Google "sub") to bo_user for sign-in and account recovery.
CREATE TABLE IF NOT EXISTS bo_user_identity_provider (
    id UUID PRIMARY KEY,
    bo_user_id UUID NOT NULL REFERENCES bo_user (id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    provider_subject VARCHAR(255) NOT NULL,
    linked_email VARCHAR(320),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_bo_user_identity_provider UNIQUE (provider, provider_subject),
    CONSTRAINT uq_bo_user_identity_provider_user_provider UNIQUE (bo_user_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_bo_user_identity_provider_bo_user
  ON bo_user_identity_provider (bo_user_id);
