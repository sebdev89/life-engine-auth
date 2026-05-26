-- Align CHECK constraint with SecurityControlPlaneAppService.ASSIGNABLE_BO_ROLES (control-plane PATCH role).
ALTER TABLE bo_user DROP CONSTRAINT IF EXISTS bo_user_role_check;
ALTER TABLE bo_user
  ADD CONSTRAINT bo_user_role_check
  CHECK (role IN ('ADMIN', 'USER', 'GUEST', 'BO_ADMIN', 'OPERATOR', 'VIEWER'));
