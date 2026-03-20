# app/security/observability/metrics.py

import threading
from collections import defaultdict


class MetricsRegistry:
    """
    Thread-safe in-memory metrics registry.

    Prometheus-compatible text format.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._counters = defaultdict(int)
        self._gauges = defaultdict(int)

    # -----------------------------
    # Counters
    # -----------------------------

    def inc(self, name: str, labels: dict | None = None, value: int = 1):
        key = self._build_key(name, labels)

        with self._lock:
            self._counters[key] += value

    # -----------------------------
    # Gauges
    # -----------------------------

    def set_gauge(self, name: str, value: int, labels: dict | None = None):
        key = self._build_key(name, labels)

        with self._lock:
            self._gauges[key] = value

    # -----------------------------
    # Rendering
    # -----------------------------

    def render_prometheus(self) -> str:
        lines = []

        with self._lock:
            for key, value in self._counters.items():
                lines.append(f"{key} {value}")

            for key, value in self._gauges.items():
                lines.append(f"{key} {value}")

        return "\n".join(lines)

    # -----------------------------

    @staticmethod
    def _build_key(name: str, labels: dict | None):
        if not labels:
            return name

        label_str = ",".join(
            f'{k}="{v}"' for k, v in sorted(labels.items())
        )

        return f"{name}{{{label_str}}}"


# Global registry instance
metrics = MetricsRegistry()
