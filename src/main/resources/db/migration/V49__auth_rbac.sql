-- RBAC: permissions, roles, role↔permission, user↔role (JWT carries permission codes as Spring authorities).

CREATE TABLE IF NOT EXISTS auth_permission (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(96) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_auth_permission_code UNIQUE (code),
    CONSTRAINT chk_auth_permission_code_upper CHECK (code = upper(code))
);

CREATE TABLE IF NOT EXISTS auth_role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(32) NOT NULL,
    name VARCHAR(160) NOT NULL,
    system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_auth_role_code UNIQUE (code),
    CONSTRAINT chk_auth_role_code_upper CHECK (code = upper(code))
);

CREATE TABLE IF NOT EXISTS auth_role_permission (
    role_id UUID NOT NULL REFERENCES auth_role (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES auth_permission (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS bo_user_role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bo_user_id UUID NOT NULL REFERENCES bo_user (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES auth_role (id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_bo_user_role_pair UNIQUE (bo_user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_bo_user_role_user ON bo_user_role (bo_user_id);
CREATE INDEX IF NOT EXISTS idx_bo_user_role_role ON bo_user_role (role_id);

INSERT INTO auth_permission (id, code, description)
SELECT 'a1111111-1111-4111-8111-111111111101', 'ROLE_ADMIN', 'Security plane and admin API access (Spring authority).'
WHERE NOT EXISTS (SELECT 1 FROM auth_permission WHERE code = 'ROLE_ADMIN');

INSERT INTO auth_permission (id, code, description)
SELECT 'a1111111-1111-4111-8111-111111111102', 'ROLE_USER', 'Standard authenticated API access.'
WHERE NOT EXISTS (SELECT 1 FROM auth_permission WHERE code = 'ROLE_USER');

INSERT INTO auth_permission (id, code, description)
SELECT 'a1111111-1111-4111-8111-111111111103', 'ROLE_GUEST', 'Guest / limited exploration.'
WHERE NOT EXISTS (SELECT 1 FROM auth_permission WHERE code = 'ROLE_GUEST');

INSERT INTO auth_permission (id, code, description)
SELECT 'a1111111-1111-4111-8111-111111111104', 'AUTH:RBAC:MANAGE', 'Create/update roles and assign roles to users.'
WHERE NOT EXISTS (SELECT 1 FROM auth_permission WHERE code = 'AUTH:RBAC:MANAGE');

INSERT INTO auth_role (id, code, name, system_role)
SELECT 'b1111111-1111-4111-8111-111111111101', 'ADMIN', 'Administrator', TRUE
WHERE NOT EXISTS (SELECT 1 FROM auth_role WHERE code = 'ADMIN');

INSERT INTO auth_role (id, code, name, system_role)
SELECT 'b1111111-1111-4111-8111-111111111102', 'USER', 'Standard user', TRUE
WHERE NOT EXISTS (SELECT 1 FROM auth_role WHERE code = 'USER');

INSERT INTO auth_role (id, code, name, system_role)
SELECT 'b1111111-1111-4111-8111-111111111103', 'GUEST', 'Guest', TRUE
WHERE NOT EXISTS (SELECT 1 FROM auth_role WHERE code = 'GUEST');

INSERT INTO auth_role (id, code, name, system_role)
SELECT 'b1111111-1111-4111-8111-111111111104', 'BO_ADMIN', 'BO administrator', TRUE
WHERE NOT EXISTS (SELECT 1 FROM auth_role WHERE code = 'BO_ADMIN');

INSERT INTO auth_role (id, code, name, system_role)
SELECT 'b1111111-1111-4111-8111-111111111105', 'OPERATOR', 'Operator', TRUE
WHERE NOT EXISTS (SELECT 1 FROM auth_role WHERE code = 'OPERATOR');

INSERT INTO auth_role (id, code, name, system_role)
SELECT 'b1111111-1111-4111-8111-111111111106', 'VIEWER', 'Viewer', TRUE
WHERE NOT EXISTS (SELECT 1 FROM auth_role WHERE code = 'VIEWER');

INSERT INTO auth_role_permission (role_id, permission_id)
SELECT 'b1111111-1111-4111-8111-111111111101', id FROM auth_permission WHERE code IN ('ROLE_ADMIN', 'ROLE_USER', 'AUTH:RBAC:MANAGE')
ON CONFLICT DO NOTHING;

INSERT INTO auth_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM auth_role r
CROSS JOIN auth_permission p
WHERE r.code IN ('USER', 'BO_ADMIN', 'OPERATOR', 'VIEWER')
  AND p.code = 'ROLE_USER'
ON CONFLICT DO NOTHING;

INSERT INTO auth_role_permission (role_id, permission_id)
SELECT 'b1111111-1111-4111-8111-111111111103', id FROM auth_permission WHERE code = 'ROLE_GUEST'
ON CONFLICT DO NOTHING;

INSERT INTO bo_user_role (bo_user_id, role_id, assigned_at)
SELECT u.id, r.id, NOW()
FROM bo_user u
JOIN auth_role r ON r.code = trim(upper(u.role))
WHERE NOT EXISTS (
    SELECT 1 FROM bo_user_role ur WHERE ur.bo_user_id = u.id AND ur.role_id = r.id
);
