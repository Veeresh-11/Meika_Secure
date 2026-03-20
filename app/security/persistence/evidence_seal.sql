-- Governance Sealing Layer

CREATE OR REPLACE FUNCTION forbid_schema_version_change()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Schema version metadata is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER no_schema_update
BEFORE UPDATE OR DELETE ON schema_metadata
FOR EACH ROW
EXECUTE FUNCTION forbid_schema_version_change();
