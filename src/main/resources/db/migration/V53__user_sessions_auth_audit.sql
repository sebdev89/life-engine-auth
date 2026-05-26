CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY,
    bo_user_id UUID REFERENCES bo_user (id) ON DELETE CASCADE,
    guest_session_id UUID,
    refresh_token_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    ip_address VARCHAR(128),
    user_agent TEXT,
    CONSTRAINT user_sessions_principal_chk CHECK (
        (bo_user_id IS NOT NULL AND guest_session_id IS NULL)
        OR (bo_user_id IS NULL AND guest_session_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_bo_user ON user_sessions (bo_user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_guest ON user_sessions (guest_session_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions (expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_revoked ON user_sessions (revoked_at);

CREATE TABLE IF NOT EXISTS auth_audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    action VARCHAR(48) NOT NULL,
    ip VARCHAR(128),
    user_agent TEXT,
    metadata TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_created ON auth_audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_audit_user ON auth_audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_action ON auth_audit_log (action);
