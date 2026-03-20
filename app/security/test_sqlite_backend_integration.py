import time
import os

from app.security.track_d.storage.sqlite_backend import (
    SQLiteBackend,
    Signer,
    Table,
)


def test_sqlite_append_with_quorum(tmp_path):
    db_path = tmp_path / "test.db"

    # ✅ isolate anchor file per test
    anchor_file = tmp_path / "ledger.anchor"
    os.environ["ANCHOR_FILE"] = str(anchor_file)

    db = SQLiteBackend(str(db_path))

    s1 = Signer("a" * 64)
    s2 = Signer("b" * 64)

    db.register_signer(s1.get_public_key())
    db.register_signer(s2.get_public_key())

    entry = {
        "test": True,
        "timestamp": time.time(),
    }

    db.append(Table.VERIFICATION, entry, [s1, s2])

    # ✅ verify anchor created in isolated path
    assert anchor_file.exists()

    db.close()