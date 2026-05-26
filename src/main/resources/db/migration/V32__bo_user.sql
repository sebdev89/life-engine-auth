CREATE TABLE IF NOT EXISTS bo_user (
    id UUID PRIMARY KEY,
    email VARCHAR(320) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('ADMIN', 'USER')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_bo_user_email UNIQUE (email)
);

CREATE INDEX IF NOT EXISTS idx_bo_user_email_lower ON bo_user (LOWER(email));
