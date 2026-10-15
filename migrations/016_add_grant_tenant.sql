-- 016_add_grant_tenant.sql
-- Add authoritative tenant identity to authorization grants.

ALTER TABLE identity.grants
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Existing grants inherit tenant ownership from their authoritative user.
UPDATE identity.grants g
SET tenant_id = u.tenant_id
FROM identity.users u
WHERE g.user_id = u.id
  AND g.tenant_id IS NULL;

-- Do not permit grants that cannot be attributed to a tenant.
ALTER TABLE identity.grants
    ALTER COLUMN tenant_id SET NOT NULL;

-- Enforce tenant ownership at the database layer.
ALTER TABLE identity.grants
    ADD CONSTRAINT fk_grants_tenant
    FOREIGN KEY (tenant_id)
    REFERENCES identity.organizations(id);

-- Support tenant-scoped grant lookups.
CREATE INDEX IF NOT EXISTS ix_grants_tenant_id
ON identity.grants(tenant_id);
