"""
TRACK D — Simulation / Shadow Evaluation Interface
=================================================

This module provides NON-AUTHORITATIVE simulation of security
decisions for:

- policy testing
- rollout safety
- behavioral analysis

SECURITY LAW:
- Simulation MUST NOT deny
- Simulation MUST NOT write evidence
- Simulation MUST NOT affect Track A/B/C
- Simulation output is WARN-only
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any

from app.security.context import SecurityContext
from app.security.pipeline import SecurityPipeline
from app.security.decision import DecisionOutcome
from app.security.track_d.error_codes import classify_decision


# ---------------------------------------------------------------------
# Simulation Result Model
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class SimulationResult:
    """
    Result of a shadow / simulation evaluation.

    NOTE:
    - This result is NOT authoritative
    - This result MUST NOT be enforced
    """

    simulated_outcome: DecisionOutcome
    simulated_reason: str
    error_class: Optional[str]
    warnings: Dict[str, Any]
    authoritative: bool = False


# ---------------------------------------------------------------------
# Simulation Engine
# ---------------------------------------------------------------------

def simulate_decision(
    ctx: SecurityContext,
    *,
    policy_version: Optional[str] = None,
) -> SimulationResult:
    """
    Simulate a security decision WITHOUT enforcement.

    INPUT:
        ctx:
            Fully constructed SecurityContext.

        policy_version:
            Optional alternate policy identifier.

    OUTPUT:
        SimulationResult (NON-AUTHORITATIVE)

    SECURITY:
        - No evidence written
        - No denial enforced
        - No side effects allowed
    """

    # -------------------------------------------------------------
    # Step 1: Evaluate using standard pipeline
    # -------------------------------------------------------------
    pipeline = SecurityPipeline(
        policy_version_override=policy_version
    )

    decision = pipeline.evaluate(ctx)

    # -------------------------------------------------------------
    # Step 2: Force WARN-only semantics
    # -------------------------------------------------------------
    if decision.outcome == DecisionOutcome.DENY:
        simulated_outcome = DecisionOutcome.WARN
    else:
        simulated_outcome = decision.outcome

    # -------------------------------------------------------------
    # Step 3: Classify error (for diagnostics only)
    # -------------------------------------------------------------
    error_class = classify_decision(decision)

    # -------------------------------------------------------------
    # Step 4: Return non-authoritative result
    # -------------------------------------------------------------
    return SimulationResult(
        simulated_outcome=simulated_outcome,
        simulated_reason=decision.reason,
        error_class=error_class,
        warnings={
            "non_authoritative": True,
            "simulation_only": True,
            "policy_version": policy_version,
        },
    )
