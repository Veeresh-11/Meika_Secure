import pathlib

def test_evidence_migration_exists():
    path = pathlib.Path("migrations/001_create_evidence_log.sql")
    assert path.exists()
