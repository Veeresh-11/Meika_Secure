from typing import List
from app.security.simulation.models import SimulationResult


class SimulationEmitter:
    """
    Emits simulation results.
    Failures MUST be ignored by callers.
    """

    def emit(self, results: List[SimulationResult]) -> None:
        pass
