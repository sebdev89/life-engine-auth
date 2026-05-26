-- Brute-force mitigation: count failed password checks and temporary lockout (distinct from admin `locked`).

ALTER TABLE bo_user ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bo_user ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ NULL;

COMMENT ON COLUMN bo_user.failed_login_attempts IS 'Resets on successful login; used with locked_until for auto lockout.';
COMMENT ON COLUMN bo_user.locked_until IS 'When set and in the future, password login is rejected (generic error).';
