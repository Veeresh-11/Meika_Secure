-- ============================================================
-- MEIKA — Evidence Ledger (Append-Only)
-- Hardened Governance Edition
-- ============================================================

-- ------------------------------------------------------------
-- Core Ledger Table
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS evidence_ledger (
    sequence_number BIGINT PRIMARY KEY CHECK (sequence_number >= 0),

    -- NULL allowed only for genesis record
    previous_hash TEXT,

    payload_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- --------------------------------------------------------
    -- Hash Format Enforcement
    -- --------------------------------------------------------

    CONSTRAINT record_hash_format
        CHECK (record_hash ~ '^[a-f0-9]{64}$'),

    CONSTRAINT payload_hash_format
        CHECK (payload_hash ~ '^[a-f0-9]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_evidence_sequence
ON evidence_ledger(sequence_number);

-- ------------------------------------------------------------
-- Strict Chain Integrity (Database-Level)
-- ------------------------------------------------------------

-- Foreign key ensures previous_hash references real record
-- DEFERRABLE allows insertion order safety within transaction

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_previous_hash'
    ) THEN
        ALTER TABLE evidence_ledger
        ADD CONSTRAINT fk_previous_hash
        FOREIGN KEY (previous_hash)
        REFERENCES evidence_ledger(record_hash)
        DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$$;

-- ------------------------------------------------------------
-- Append-Only Enforcement
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION forbid_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Evidence ledger is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS no_update ON evidence_ledger;
CREATE TRIGGER no_update
BEFORE UPDATE ON evidence_ledger
FOR EACH ROW
EXECUTE FUNCTION forbid_mutation();

DROP TRIGGER IF EXISTS no_delete ON evidence_ledger;
CREATE TRIGGER no_delete
BEFORE DELETE ON evidence_ledger
FOR EACH ROW
EXECUTE FUNCTION forbid_mutation();

-- ------------------------------------------------------------
-- Schema Metadata (Governance)
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS schema_metadata (
    id INTEGER PRIMARY KEY DEFAULT 1,
    schema_version TEXT NOT NULL,
    schema_checksum TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Insert initial row if not exists
INSERT INTO schema_metadata (id, schema_version, schema_checksum)
VALUES (1, '1.0.0', '')
ON CONFLICT (id) DO NOTHING;

-- Prevent modification of schema metadata

CREATE OR REPLACE FUNCTION forbid_schema_version_change()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Schema version metadata is immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS no_schema_update ON schema_metadata;

CREATE TRIGGER no_schema_update
BEFORE UPDATE OR DELETE ON schema_metadata
FOR EACH ROW
EXECUTE FUNCTION forbid_schema_version_change();
