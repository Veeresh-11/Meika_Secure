CREATE TABLE IF NOT EXISTS evidence_ledger (
    sequence_number BIGINT PRIMARY KEY,
    previous_hash TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION forbid_update()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Evidence ledger is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS no_update ON evidence_ledger;
CREATE TRIGGER no_update
BEFORE UPDATE ON evidence_ledger
FOR EACH ROW
EXECUTE FUNCTION forbid_update();

DROP TRIGGER IF EXISTS no_delete ON evidence_ledger;
CREATE TRIGGER no_delete
BEFORE DELETE ON evidence_ledger
FOR EACH ROW
EXECUTE FUNCTION forbid_update();
