from unittest.mock import patch

from app.security.pipeline import SecureIDKernel


def test_safe_mode_metrics_failure():

    kernel = SecureIDKernel()

    with patch(
        "app.security.pipeline.metrics.inc",
        side_effect=Exception("boom"),
    ):
        kernel._enter_safe_mode("test")

    assert kernel._state.name == "SAFE_MODE"


def test_safe_mode_emitter_failure():

    class BadEmitter:
        def emit(self, event):
            raise Exception("boom")

    kernel = SecureIDKernel(
        event_emitter=BadEmitter()
    )

    kernel._enter_safe_mode("tamper")

    assert kernel._state.name == "SAFE_MODE"