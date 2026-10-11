-- ============================================================
-- Meika Secure ID
-- 010_reconcile_evidence_ledger_schema.sql
--
-- Reconcile the legacy public evidence ledger with the
-- canonical identity-scoped evidence ledger.
--
-- Migration 002 created public.evidence_ledger because the
-- table name was unqualified. The security architecture now
-- treats identity.evidence_ledger as the canonical ledger.
--
-- IMPORTANT:
-- - Do not modify or drop public.evidence_ledger here.
-- - Existing migration history remains unchanged.
-- - The canonical ledger is established under identity.
-- ============================================================


-- ------------------------------------------------------------
-- Canonical evidence ledger
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity.evidence_ledger (

    sequence_number BIGINT PRIMARY KEY
        CHECK (sequence_number >= 0),

    -- NULL is permitted only for the genesis record.
    previous_hash TEXT,

    payload_hash TEXT NOT NULL,

    record_hash TEXT NOT NULL UNIQUE,

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT evidence_ledger_record_hash_format
        CHECK (record_hash ~ '^[a-f0-9]{64}$'),

    CONSTRAINT evidence_ledger_payload_hash_format
        CHECK (payload_hash ~ '^[a-f0-9]{64}$')
);


-- ------------------------------------------------------------
-- Sequence lookup
-- ------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_identity_evidence_sequence
ON identity.evidence_ledger(sequence_number);


-- ------------------------------------------------------------
-- Chain integrity
-- ------------------------------------------------------------

DO
$$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_previous_hash'
          AND conrelid = 'identity.evidence_ledger'::regclass
    ) THEN

        ALTER TABLE identity.evidence_ledger
        ADD CONSTRAINT fk_previous_hash
        FOREIGN KEY (previous_hash)
        REFERENCES identity.evidence_ledger(record_hash)
        DEFERRABLE INITIALLY DEFERRED;

    END IF;
END
$$;


-- ------------------------------------------------------------
-- Append-only enforcement
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION identity.forbid_mutation()
RETURNS trigger
AS
$$
BEGIN
    RAISE EXCEPTION 'Evidence ledger is append-only';
END;
$$
LANGUAGE plpgsql;


DROP TRIGGER IF EXISTS no_update
ON identity.evidence_ledger;

CREATE TRIGGER no_update
BEFORE UPDATE
ON identity.evidence_ledger
FOR EACH ROW
EXECUTE FUNCTION identity.forbid_mutation();


DROP TRIGGER IF EXISTS no_delete
ON identity.evidence_ledger;

CREATE TRIGGER no_delete
BEFORE DELETE
ON identity.evidence_ledger
FOR EACH ROW
EXECUTE FUNCTION identity.forbid_mutation();


-- ------------------------------------------------------------
-- Schema governance metadata
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS identity.schema_metadata (

    id INTEGER PRIMARY KEY DEFAULT 1,

    schema_version TEXT NOT NULL,

    schema_checksum TEXT NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);


INSERT INTO identity.schema_metadata (
    id,
    schema_version,
    schema_checksum
)
VALUES (
    1,
    '1.0.0',
    ''
)
ON CONFLICT (id)
DO NOTHING;


-- ------------------------------------------------------------
-- Immutable schema metadata
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION identity.forbid_schema_version_change()
RETURNS trigger
AS
$$
BEGIN
    RAISE EXCEPTION
        'Schema version metadata is immutable';
END;
$$
LANGUAGE plpgsql;


DROP TRIGGER IF EXISTS no_schema_update
ON identity.schema_metadata;

CREATE TRIGGER no_schema_update
BEFORE UPDATE OR DELETE
ON identity.schema_metadata
FOR EACH ROW
EXECUTE FUNCTION identity.forbid_schema_version_change();


-- ------------------------------------------------------------
-- Documentation
-- ------------------------------------------------------------

COMMENT ON TABLE identity.evidence_ledger IS
'Append-only cryptographic evidence ledger used by the Meika Security Kernel.';

COMMENT ON TABLE identity.schema_metadata IS
'Schema governance metadata used to validate integrity and version compatibility.';
