-- 016_add_grant_tenant.sql
-- Add authoritative tenant identity to authorization grants.

ALTER TABLE identity.grants
    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL;

-- Enforce tenant ownership at the database layer.
ALTER TABLE identity.grants
    ADD CONSTRAINT fk_grants_tenant
    FOREIGN KEY (tenant_id)
    REFERENCES identity.organizations(id);

-- Support tenant-scoped grant lookups.
CREATE INDEX IF NOT EXISTS ix_grants_tenant_id
ON identity.grants(tenant_id);
