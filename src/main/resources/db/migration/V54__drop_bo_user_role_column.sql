-- RBAC-only: primary app role comes from bo_user_role → auth_role (EffectiveAuthorityService).
ALTER TABLE bo_user DROP CONSTRAINT IF EXISTS bo_user_role_check;
ALTER TABLE bo_user DROP COLUMN IF EXISTS role;
