import pytest

import sys
def test_allow_context_fixture(request):
    ctx = request.getfixturevalue("allow_context")
    assert ctx is not None


def test_deny_context_fixture(request):
    ctx = request.getfixturevalue("deny_context")
    assert ctx is not None


def test_evidence_store_fixture(request):
    store = request.getfixturevalue("evidence_store")
    assert store is not None


def test_postgres_kernel_skips_without_dsn(monkeypatch, request):
    monkeypatch.delenv("POSTGRES_DSN", raising=False)

    with pytest.raises(pytest.skip.Exception):
        request.getfixturevalue("postgres_kernel")
        
def test_postgres_kernel_with_mock(monkeypatch, request):
    from app.security import conftest

    class DummyStore:
        def __init__(self, dsn):
            self.dsn = dsn

    class DummyKernel:
        def __init__(self, evidence_store):
            self.evidence_store = evidence_store

    monkeypatch.setattr(conftest, "POSTGRES_DSN", "postgres://dummy")
    monkeypatch.setattr(conftest, "PostgresEvidenceStore", DummyStore)
    monkeypatch.setattr(conftest, "SecureIDKernel", DummyKernel)

    kernel = request.getfixturevalue("postgres_kernel")

    assert isinstance(kernel.evidence_store, DummyStore)
    

import types


def test_postgres_kernel_with_mock(monkeypatch):
    from app.security import conftest

    # Pretend DSN exists
    monkeypatch.setattr(
        conftest,
        "POSTGRES_DSN",
        "postgres://dummy",
    )

    # Fake psycopg2 import
    monkeypatch.setitem(
        sys.modules,
        "psycopg2",
        types.ModuleType("psycopg2"),
    )

    class DummyStore:
        def __init__(self, dsn):
            self.dsn = dsn

    class DummyKernel:
        def __init__(self, evidence_store):
            self.evidence_store = evidence_store

    monkeypatch.setattr(
        conftest,
        "PostgresEvidenceStore",
        DummyStore,
    )

    monkeypatch.setattr(
        conftest,
        "SecureIDKernel",
        DummyKernel,
    )

    # Call the underlying fixture function directly
    kernel = conftest.postgres_kernel.__wrapped__()

    assert isinstance(kernel, DummyKernel)
    assert isinstance(kernel.evidence_store, DummyStore)
    assert kernel.evidence_store.dsn == "postgres://dummy"