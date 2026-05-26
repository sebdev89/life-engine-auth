-- Extend bo_user.role to allow GUEST (for seeded accounts; guest JWT may not use a row).
ALTER TABLE bo_user DROP CONSTRAINT IF EXISTS bo_user_role_check;
ALTER TABLE bo_user
  ADD CONSTRAINT bo_user_role_check CHECK (role IN ('ADMIN', 'USER', 'GUEST'));
