-- Optional operator-cockpit metadata (populated on new tokens when AuditContext is available).
ALTER TABLE refresh_token ADD COLUMN IF NOT EXISTS client_ip VARCHAR(128);
ALTER TABLE refresh_token ADD COLUMN IF NOT EXISTS client_user_agent TEXT;
ALTER TABLE refresh_token ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
