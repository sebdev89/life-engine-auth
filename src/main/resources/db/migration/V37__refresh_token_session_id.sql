-- Stable operator session identity: one session_id per login/device chain; refresh rotation reuses it.
ALTER TABLE refresh_token ADD COLUMN IF NOT EXISTS session_id UUID;

UPDATE refresh_token SET session_id = id WHERE session_id IS NULL;

ALTER TABLE refresh_token ALTER COLUMN session_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_token_session_id ON refresh_token (session_id);
