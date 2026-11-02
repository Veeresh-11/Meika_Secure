import ssl

from app.security.observability import exporter


class FakeServer:
    def __init__(self, address, handler):
        self.address = address
        self.handler = handler
        self.socket = object()

    def serve_forever(self):
        pass


class FakeTLSContext:
    def __init__(self):
        self.minimum_version = None
        self.cert_chain = None
        self.wrapped_socket = None

    def load_cert_chain(self, certfile, keyfile):
        self.cert_chain = (certfile, keyfile)

    def wrap_socket(self, sock, server_side):
        self.wrapped_socket = (sock, server_side)
        return "wrapped-tls-socket"


class FakeThread:
    def __init__(self, target, daemon):
        self.target = target
        self.daemon = daemon
        self.started = False

    def start(self):
        self.started = True


def test_tls_server_requires_tls_12_or_newer(monkeypatch):
    fake_context = FakeTLSContext()
    fake_server = FakeServer(("127.0.0.1", 0), exporter.MetricsHandler)
    fake_threads = []

    def make_thread(target, daemon):
        thread = FakeThread(target, daemon)
        fake_threads.append(thread)
        return thread

    monkeypatch.setattr(exporter, "HTTPServer", lambda address, handler: fake_server)
    monkeypatch.setattr(
        exporter.ssl,
        "create_default_context",
        lambda purpose: fake_context,
    )
    monkeypatch.setattr(
        exporter,
        "Thread",
        make_thread,
    )

    server = exporter.start_metrics_server(
        host="127.0.0.1",
        port=0,
        use_tls=True,
        certfile="test-cert.pem",
        keyfile="test-key.pem",
    )

    assert server is fake_server
    assert fake_context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert fake_context.cert_chain == ("test-cert.pem", "test-key.pem")
    assert fake_context.wrapped_socket is not None
    assert fake_context.wrapped_socket[1] is True
    assert fake_server.socket == "wrapped-tls-socket"
    assert server.socket == "wrapped-tls-socket"
    assert len(fake_threads) == 1
    assert fake_threads[0].started is True
    assert fake_threads[0].target == server.serve_forever
    assert fake_threads[0].daemon is True
