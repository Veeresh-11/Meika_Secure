import pathlib

def test_append_only_migration_exists():
    path = pathlib.Path("migrations/003_enforce_append_only.sql")
    assert path.exists()
