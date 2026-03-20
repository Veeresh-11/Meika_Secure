# app/security/observability/exporter.py

from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from app.security.observability.metrics import metrics


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        data = metrics.render_prometheus().encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()

        self.wfile.write(data)


def start_metrics_server(port: int = 9100):
    server = HTTPServer(("0.0.0.0", port), MetricsHandler)

    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    return server
