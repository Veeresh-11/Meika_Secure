from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class SimulationResult:
    """
    NON-AUTHORITATIVE observation.

    MUST NOT influence decisions, evidence, or execution.
    """
    rule_id: str
    severity: str  # INFO | WARN | CRITICAL
    message: str
    metadata: Dict
