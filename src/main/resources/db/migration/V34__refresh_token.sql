CREATE TABLE IF NOT EXISTS refresh_token (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bo_user_id UUID REFERENCES bo_user (id) ON DELETE CASCADE,
    guest_session_id UUID,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT chk_refresh_token_owner CHECK (
        (bo_user_id IS NOT NULL AND guest_session_id IS NULL)
        OR (bo_user_id IS NULL AND guest_session_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_refresh_token_bo_user_active
    ON refresh_token (bo_user_id)
    WHERE revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_refresh_token_guest_active
    ON refresh_token (guest_session_id)
    WHERE revoked = FALSE AND guest_session_id IS NOT NULL;
