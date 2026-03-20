# app/security/observability/exporter.py

from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread, Lock
import time
import ssl
import os
import json
import hashlib
from pathlib import Path
from typing import Optional

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from app.security.observability.metrics import metrics


# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9100

METRICS_TOKEN = os.getenv("METRICS_TOKEN", "change-this-secret")
SIGNING_KEY_HEX = os.getenv("METRICS_SIGNING_KEY")

RATE_LIMIT = int(os.getenv("METRICS_RATE_LIMIT", "60"))

CHAIN_FILE = "metrics.chain"


# ---------------------------------------------------------
# RATE LIMITER
# ---------------------------------------------------------

class RateLimiter:
    def __init__(self, limit):
        self.limit = limit
        self.calls = {}
        self.lock = Lock()

    def allow(self, ip):
        now = int(time.time() // 60)

        with self.lock:
            count, ts = self.calls.get(ip, (0, now))

            if ts != now:
                count = 0
                ts = now

            count += 1
            self.calls[ip] = (count, ts)

            return count <= self.limit


rate_limiter = RateLimiter(RATE_LIMIT)


# ---------------------------------------------------------
# SIGNER
# ---------------------------------------------------------

signer = None
if SIGNING_KEY_HEX:
    signer = SigningKey(SIGNING_KEY_HEX, encoder=HexEncoder)


# ---------------------------------------------------------
# CHAIN STATE
# ---------------------------------------------------------

def _load_prev_hash():
    if not Path(CHAIN_FILE).exists():
        return None

    data = json.loads(Path(CHAIN_FILE).read_text())
    return data.get("chain_hash")


def _write_chain(chain_hash):
    Path(CHAIN_FILE).write_text(json.dumps({
        "chain_hash": chain_hash,
        "timestamp": time.time(),
    }))


def _compute_chain(payload_hash, prev_hash):
    return hashlib.sha256(((prev_hash or "") + payload_hash).encode()).hexdigest()


# ---------------------------------------------------------
# HANDLER
# ---------------------------------------------------------

class MetricsHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        # 🔐 Auth
        if self.headers.get("Authorization") != f"Bearer {METRICS_TOKEN}":
            self.send_response(401)
            self.end_headers()
            return

        # 🚦 Rate limit
        ip = self.client_address[0]
        if not rate_limiter.allow(ip):
            self.send_response(429)
            self.end_headers()
            return

        # 📊 Generate metrics
        payload = metrics.render_prometheus().encode()

        # 🔐 Hash
        payload_hash = hashlib.sha256(payload).hexdigest()

        # 🔗 Chain
        prev_hash = _load_prev_hash()
        chain_hash = _compute_chain(payload_hash, prev_hash)

        _write_chain(chain_hash)

        # 🔏 Sign
        signature = ""
        if signer:
            signature = signer.sign(chain_hash.encode()).signature.hex()

        # 📤 Response
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(payload)))

        # 🔥 Verifiability headers
        self.send_header("X-Metrics-Hash", payload_hash)
        self.send_header("X-Metrics-Chain-Hash", chain_hash)

        if signature:
            self.send_header("X-Metrics-Signature", signature)

        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


# ---------------------------------------------------------
# SERVER
# ---------------------------------------------------------

def start_metrics_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    use_tls: bool = False,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    ca_file: Optional[str] = None,
    require_client_cert: bool = False,
):

    # nosec B104
    server = HTTPServer((host, port), MetricsHandler)

    if use_tls:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile, keyfile)

        if require_client_cert:
            context.load_verify_locations(cafile=ca_file)
            context.verify_mode = ssl.CERT_REQUIRED

        server.socket = context.wrap_socket(server.socket, server_side=True)

    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    return server