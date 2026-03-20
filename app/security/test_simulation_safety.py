import pytest

pytestmark = [
    pytest.mark.simulation,
]

from app.security.pipeline import SecureIDKernel
from app.security.simulation.engine import SimulationEngine


class ExplodingSimulation(SimulationEngine):
    def evaluate(self, context, decision):
        raise RuntimeError("boom")


def test_simulation_failure_is_ignored():
    kernel = SecureIDKernel(simulation_engine=ExplodingSimulation())

    ctx = kernel._default_context()
    decision = kernel.evaluate(ctx)

    assert decision.outcome is not None
