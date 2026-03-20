from typing import List
from app.security.simulation.models import SimulationResult


class SimulationEngine:
    """
    Parallel, non-authoritative evaluator.
    """

    def evaluate(self, context, decision) -> List[SimulationResult]:
        """
        MUST:
        - NOT mutate context
        - NOT raise
        - NOT block
        """
        return []
