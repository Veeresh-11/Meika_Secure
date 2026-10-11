-- ============================================================
-- Meika Secure ID
-- 013_create_tenant_foundation.sql
--
-- Establish tenant ownership for existing identity records.
--
-- Scope:
--   organizations
--   users
--   devices
--   webauthn_credentials
--
-- Existing records are assigned to one bootstrap organization.
--
-- Sessions, grants, evidence, JWT, and application authorization
-- are intentionally handled in later phases.
-- ============================================================

-- ------------------------------------------------------------
-- Organizations
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT organizations_status_check
        CHECK (status IN ('ACTIVE', 'DISABLED'))
);

-- ------------------------------------------------------------
-- Bootstrap organization for existing identity data
-- ------------------------------------------------------------

INSERT INTO identity.organizations (
    id,
    name,
    status
)
VALUES (
    '00000000-0000-4000-8000-000000000001',
    'Meika Legacy',
    'ACTIVE'
)
ON CONFLICT (id) DO NOTHING;

-- ------------------------------------------------------------
-- Users
-- ------------------------------------------------------------

ALTER TABLE identity.users
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE identity.users
SET tenant_id = '00000000-0000-4000-8000-000000000001'
WHERE tenant_id IS NULL;

ALTER TABLE identity.users
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE identity.users
    ADD CONSTRAINT fk_users_tenant
    FOREIGN KEY (tenant_id)
    REFERENCES identity.organizations(id);

ALTER TABLE identity.users
    DROP CONSTRAINT IF EXISTS users_email_key;

ALTER TABLE identity.users
    ADD CONSTRAINT users_tenant_email_key
    UNIQUE (tenant_id, email);

CREATE INDEX IF NOT EXISTS ix_users_tenant_id
ON identity.users(tenant_id);

-- ------------------------------------------------------------
-- Devices
-- ------------------------------------------------------------

ALTER TABLE identity.devices
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE identity.devices
SET tenant_id = '00000000-0000-4000-8000-000000000001'
WHERE tenant_id IS NULL;

ALTER TABLE identity.devices
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE identity.devices
    ADD CONSTRAINT fk_devices_tenant
    FOREIGN KEY (tenant_id)
    REFERENCES identity.organizations(id);

CREATE INDEX IF NOT EXISTS ix_devices_tenant_id
ON identity.devices(tenant_id);

-- ------------------------------------------------------------
-- WebAuthn credentials
-- ------------------------------------------------------------

ALTER TABLE identity.webauthn_credentials
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE identity.webauthn_credentials
SET tenant_id = '00000000-0000-4000-8000-000000000001'
WHERE tenant_id IS NULL;

ALTER TABLE identity.webauthn_credentials
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE identity.webauthn_credentials
    ADD CONSTRAINT fk_webauthn_credentials_tenant
    FOREIGN KEY (tenant_id)
    REFERENCES identity.organizations(id);

CREATE INDEX IF NOT EXISTS ix_webauthn_credentials_tenant_id
ON identity.webauthn_credentials(tenant_id);