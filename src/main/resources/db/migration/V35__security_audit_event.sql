CREATE TABLE IF NOT EXISTS security_audit_event (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    user_id UUID,
    email VARCHAR(320),
    ip VARCHAR(128),
    user_agent TEXT,
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_audit_created ON security_audit_event (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_audit_type ON security_audit_event (event_type);
