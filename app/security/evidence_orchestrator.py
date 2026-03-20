from datetime import datetime

from app.security.pipeline import SecurityPipeline
from app.security.context import SecurityContext
from app.security.decision import (
    SecurityDecision,
    SecurityDecisionFactory,
    DecisionOutcome,
)
from app.security.version import KERNEL_VERSION
from app.security.errors import SecurityInvariantViolation

from app.security.evidence.store import InMemoryEvidenceStore
import app.security.evidence.engine as evidence_engine


class EvidenceEnforcedPipeline:
    """
    TRACK B — Evidence-Enforced Wrapper

    Wraps the pure SecurityPipeline.
    Commits evidence.
    Emits merkle root into decision.
    """

    def __init__(
        self,
        event_emitter=None,
        evidence_store=None,
        simulation_engine=None,
        simulation_emitter=None,
        revocation_registry=None,
        policy_evaluator=None,
    ):
        self.kernel = SecurityPipeline(
            policy_evaluator=policy_evaluator,
            revocation_registry=revocation_registry,
        )

        self.event_emitter = event_emitter
        self.evidence_store = evidence_store or InMemoryEvidenceStore()
        self.simulation_engine = simulation_engine
        self.simulation_emitter = simulation_emitter

    # -------------------------------------------------
    # Test helper compatibility
    # -------------------------------------------------
    def _default_context(self) -> SecurityContext:
        return SecurityContext(
            request_id="kernel-test",
            principal_id="kernel",
            intent="authentication.attempt",
            authenticated=True,
            device_id=None,
            device=None,
            risk_signals={},
            request_time=datetime.utcnow(),
            metadata={},
            grant=None,
        )

    # -------------------------------------------------
    # Evidence-Enforced Evaluation
    # -------------------------------------------------
    def evaluate(self, context: SecurityContext) -> SecurityDecision:

        decision = self.kernel.evaluate(context)

        if decision.outcome != DecisionOutcome.ALLOW:
            return decision

        record = evidence_engine.build_evidence_record(
            context=context,
            policy=None,
            risk=None,
            authority=[],
            decision=decision,
            extra_metadata={},
            store=self.evidence_store,
        )

        receipt = evidence_engine.append_evidence_record(
            record,
            store=self.evidence_store,
        )

        if receipt is None:
            raise SecurityInvariantViolation(
                "ALLOW without evidence commit forbidden"
            )

        decision = SecurityDecisionFactory._kernel_create(
            outcome=decision.outcome,
            reason=decision.reason,
            policy_version=KERNEL_VERSION,
            evaluated_at=decision.evaluated_at,
            obligations=decision.obligations,
            evidence_hash=receipt.merkle_root,
        )

        if self.event_emitter:
            try:
                self.event_emitter.emit(record)
            except Exception:
                pass

        if self.simulation_engine:
            try:
                results = self.simulation_engine.evaluate(context, decision)
                if self.simulation_emitter:
                    self.simulation_emitter.emit(results)
            except Exception:
                pass

        return decision
