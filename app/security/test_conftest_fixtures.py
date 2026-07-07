import pytest
import app.security.evidence.postgres_store as postgres_store
import app.security.pipeline as pipeline

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
    monkeypatch.delenv("POSTGRES_TEST_DSN", raising=False)

    with pytest.raises(pytest.skip.Exception):
        request.getfixturevalue("postgres_kernel")
        
def test_postgres_kernel_with_mock(monkeypatch, request):
    

    monkeypatch.setenv(
        "POSTGRES_DSN",
        "postgresql://dummy",
    )
    monkeypatch.delenv("POSTGRES_TEST_DSN", raising=False)

    class DummyCursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, *args, **kwargs):
            pass

    class DummyConn:
        def cursor(self):
            return DummyCursor()

        def commit(self):
            pass

    class DummyStore:
        def __init__(self, dsn):
            self.dsn = dsn
            self._conn = DummyConn()

    class DummyKernel:
        def __init__(self, evidence_store):
            self.evidence_store = evidence_store

    monkeypatch.setattr(
        postgres_store,
        "PostgresEvidenceStore",
        DummyStore,
    )

    monkeypatch.setattr(
        pipeline,
        "SecureIDKernel",
        DummyKernel,
    )

    kernel = request.getfixturevalue("postgres_kernel")

    assert kernel is not None
    assert isinstance(kernel.evidence_store, DummyStore)
    assert kernel.evidence_store.dsn == "postgresql://dummy"