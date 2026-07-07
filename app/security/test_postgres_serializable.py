import threading
import app.security.pipeline as pipeline
import app.security.evidence.postgres_store as postgres_store


def test_postgres_kernel_with_mock(monkeypatch, request):
    from app.security import conftest

    monkeypatch.setenv(
        "POSTGRES_DSN",
        "postgresql://dummy",
    )
    monkeypatch.delenv(
        "POSTGRES_TEST_DSN",
        raising=False,
    )

    class DummyStore:
        def __init__(self, dsn):
            self.dsn = dsn

        def close(self):
            pass

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
    
def test_postgres_concurrent_append_safe(postgres_kernel):
    
    before =  postgres_kernel.health_snapshot()["last_sequence_number"]

    def worker():
        ctx = postgres_kernel._default_context()
        postgres_kernel.evaluate(ctx)

    threads = []

    for _ in range(5):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    after = postgres_kernel.health_snapshot()["last_sequence_number"]
    
    assert after - before == 5, f"Expected 5 new entries, got {after - before}"