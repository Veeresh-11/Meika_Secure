import threading
from app.security.pipeline import SecureIDKernel


def test_concurrent_allows_produce_sequential_chain():

    kernel = SecureIDKernel()

    def worker():
        ctx = kernel._default_context()
        kernel.evaluate(ctx)

    threads = []

    for _ in range(10):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    snapshot = kernel.health_snapshot()

    # 10 ALLOW decisions → sequence 0..9
    assert snapshot["last_sequence_number"] == 9
    assert snapshot["last_record_hash"] is not None
