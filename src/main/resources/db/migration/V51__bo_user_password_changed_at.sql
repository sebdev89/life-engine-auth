ALTER TABLE bo_user ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN bo_user.password_changed_at IS 'Last time the user password hash was changed (self-service or admin).';
