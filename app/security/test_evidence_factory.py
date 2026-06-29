import pytest
from unittest.mock import patch

from app.security.evidence.factory import get_evidence_store


def test_default_returns_inmemory():
    with patch.dict("os.environ", {}, clear=True):
        store = get_evidence_store()

    assert store.__class__.__name__ == "InMemoryEvidenceStore"


def test_explicit_inmemory_returns_inmemory():
    with patch.dict(
        "os.environ",
        {"EVIDENCE_BACKEND": "inmemory"},
        clear=True,
    ):
        store = get_evidence_store()

    assert store.__class__.__name__ == "InMemoryEvidenceStore"


def test_postgres_requires_dsn():
    with patch.dict(
        "os.environ",
        {"EVIDENCE_BACKEND": "postgres"},
        clear=True,
    ):
        with pytest.raises(RuntimeError):
            get_evidence_store()


def test_postgres_backend_created():
    fake_store = object()

    with patch.dict(
        "os.environ",
        {
            "EVIDENCE_BACKEND": "postgres",
            "EVIDENCE_DSN": "postgresql://test",
        },
        clear=True,
    ):
        with patch(
            "app.security.evidence.postgres_store.PostgresEvidenceStore",
            return_value=fake_store,
        ):
            result = get_evidence_store()

    assert result is fake_store