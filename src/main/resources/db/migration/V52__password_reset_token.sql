CREATE TABLE IF NOT EXISTS password_reset_token (
    id UUID PRIMARY KEY,
    bo_user_id UUID NOT NULL REFERENCES bo_user (id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_ip VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_password_reset_token_hash ON password_reset_token (token_hash);
CREATE INDEX IF NOT EXISTS idx_password_reset_token_user_created
  ON password_reset_token (bo_user_id, created_at DESC);
