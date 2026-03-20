# app/security/test_observability_metrics.py

from app.security.pipeline import SecureIDKernel
from app.security.observability.metrics import metrics
from app.security.observability.events import event_stream


def reset_metrics():
    # Hard reset registry (test-only helper)
    metrics._counters.clear()
    metrics._gauges.clear()


def test_decision_counter_increments():
    reset_metrics()

    kernel = SecureIDKernel()

    ctx = kernel._default_context()
    kernel.evaluate(ctx)

    output = metrics.render_prometheus()

    assert "meika_kernel_decisions_total{result=\"allow\"}" in output
    assert "meika_evidence_appends_total" in output


def test_safe_mode_metrics_and_event_stream():
    reset_metrics()

    kernel = SecureIDKernel()

    kernel._enter_safe_mode("TEST_TAMPER")

    output = metrics.render_prometheus()

    assert "meika_tamper_events_total" in output
    assert "meika_safe_mode_state 1" in output

    events = event_stream.snapshot()

    assert any(e["type"] == "safe_mode_entered" for e in events)


def test_multiple_decisions_increment_counter():
    reset_metrics()

    kernel = SecureIDKernel()

    for _ in range(3):
        kernel.evaluate(kernel._default_context())

    output = metrics.render_prometheus()

    assert "meika_evidence_appends_total 3" in output


def test_metrics_do_not_break_kernel_execution():
    reset_metrics()

    kernel = SecureIDKernel()

    # Corrupt metrics intentionally
    metrics._counters = None

    # Kernel must still operate
    decision = kernel.evaluate(kernel._default_context())

    assert decision is not None
    assert decision.outcome.name == "ALLOW"
