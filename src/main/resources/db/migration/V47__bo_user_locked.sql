-- Admin lockout (distinct from enabled=false / deactivated).
ALTER TABLE bo_user ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT FALSE;
