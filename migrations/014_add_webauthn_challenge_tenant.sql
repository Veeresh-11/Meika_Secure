-- ============================================================
-- Meika Secure ID
-- 014_add_webauthn_challenge_tenant.sql
--
-- Establish tenant ownership for WebAuthn challenges.
--
-- Existing challenges inherit tenant ownership from their
-- authoritative identity.users record.
-- ============================================================

ALTER TABLE identity.webauthn_challenges
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE identity.webauthn_challenges wc
SET tenant_id = u.tenant_id
FROM identity.users u
WHERE wc.user_id = u.id
  AND wc.tenant_id IS NULL;

ALTER TABLE identity.webauthn_challenges
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE identity.webauthn_challenges
    ADD CONSTRAINT fk_webauthn_challenges_tenant
    FOREIGN KEY (tenant_id)
    REFERENCES identity.organizations(id);

CREATE INDEX IF NOT EXISTS ix_webauthn_challenges_tenant_id
ON identity.webauthn_challenges(tenant_id);