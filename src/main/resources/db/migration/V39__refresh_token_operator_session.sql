-- Operator session identity is refresh_token.session_id (V37): one UUID per login/device chain;
-- refresh rotation only adds new rows with the same session_id. Document + support lookups by user + session.
COMMENT ON COLUMN refresh_token.session_id IS
  'Stable operator session identity: new UUID on login/OAuth; preserved across refresh-token rotation rows.';

CREATE INDEX IF NOT EXISTS idx_refresh_token_bo_user_session
  ON refresh_token (bo_user_id, session_id)
  WHERE bo_user_id IS NOT NULL;
