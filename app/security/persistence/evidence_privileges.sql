-- ============================================================
-- MEIKA — Evidence Ledger Role Hardening
-- ============================================================

-- Create dedicated application role (if not exists)
DO $$
BEGIN
   IF NOT EXISTS (
       SELECT FROM pg_catalog.pg_roles
       WHERE rolname = 'meika_app'
   ) THEN
       CREATE ROLE meika_app LOGIN PASSWORD 'CHANGE_ME';
   END IF;
END
$$;

-- Remove dangerous privileges
REVOKE ALL ON TABLE evidence_ledger FROM PUBLIC;
REVOKE ALL ON TABLE evidence_ledger FROM meika_app;

-- Allow ONLY INSERT and SELECT
GRANT INSERT ON evidence_ledger TO meika_app;
GRANT SELECT ON evidence_ledger TO meika_app;

-- Prevent schema modification
REVOKE CREATE ON SCHEMA public FROM meika_app;
REVOKE USAGE ON SCHEMA public FROM meika_app;

-- Metadata table protection
REVOKE ALL ON TABLE schema_metadata FROM PUBLIC;
REVOKE ALL ON TABLE schema_metadata FROM meika_app;
GRANT SELECT ON schema_metadata TO meika_app;
