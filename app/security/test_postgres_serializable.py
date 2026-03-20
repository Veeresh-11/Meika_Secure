import threading
from app.security.pipeline import SecureIDKernel


def test_postgres_concurrent_append_safe(postgres_kernel):

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

    snapshot = postgres_kernel.health_snapshot()

    assert snapshot["last_sequence_number"] == 4
