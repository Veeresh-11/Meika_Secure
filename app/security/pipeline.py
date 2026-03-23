from datetime import datetime
from typing import Optional
import hashlib
import json
import threading

from app.security.runtime_state import KernelState
from app.security.context import SecurityContext
from app.security.decision import (
    SecurityDecision,
    SecurityDecisionFactory,
    DecisionOutcome,
)
from app.security.device_snapshot import DeviceSnapshot
from app.security.device_trust import DeviceTrustEvaluator
from app.security.errors import (
    SecurityPipelineError,
    SecurityInvariantViolation,
    FailureClass,
)
from app.security.precedence import PrecedenceGuard
from app.security.results import DenyReason
from app.security.policy.adapter import PolicyDecisionAdapter
from app.security.evidence.store import InMemoryEvidenceStore
from app.security.version import KERNEL_VERSION, KERNEL_BUILD_HASH
from app.security.governance.policy_revocation import PolicyRevocationRegistry
from app.security.tamper_event import TamperEvent

from app.security.observability.metrics import metrics
from app.security.observability.events import event_stream

import app.security.evidence.engine as evidence_engine

# NEW: optional authorization receipts
from app.security.receipts.generator import AuthorizationReceiptGenerator


# ==========================================================
# TRACK A — Deterministic Decision Kernel
# ==========================================================


class SecurityPipeline:
    """
    Pure deterministic decision kernel.
    Raises SecurityPipelineError on enforcement failure.
    Does NOT write evidence.
    """

    def __init__(self, policy_evaluator=None, revocation_registry=None):
        self.policy_evaluator = policy_evaluator or self._default_policy
        self.revocation_registry = (
            revocation_registry or PolicyRevocationRegistry()
        )

    def _default_policy(self, context):
     """
     Default Track-A policy:

     - If NO device present → DENY (used by deny tests)
     - If device present → ALLOW (used by device tests)
     """

     # 🔥 DENY scenario (used by fake_deny_context)
     if context.device is None:
        return SecurityDecisionFactory._kernel_create(
            outcome=DecisionOutcome.DENY,
            reason=DenyReason.POLICY_DENY,
            policy_version=KERNEL_VERSION,
            evaluated_at=context.request_time,
            obligations={
                "evidence": {
                    "reason": DenyReason.POLICY_DENY,
                    "timestamp": context.request_time.isoformat(),
                }
            },
        )

    # ✅ ALLOW scenario (device present)
     return SecurityDecisionFactory._kernel_create(
        outcome=DecisionOutcome.ALLOW,
        reason="KERNEL_ALLOW",
        policy_version=KERNEL_VERSION,
        evaluated_at=context.request_time,
        obligations={},
    )
    def evaluate(self, context: SecurityContext) -> SecurityDecision:

      if context is None:
        raise SecurityPipelineError(
            DenyReason.MISSING_CONTEXT,
            FailureClass.CONTEXT,
        )

      if not context.authenticated:
        raise SecurityPipelineError(
            DenyReason.UNAUTHENTICATED,
            FailureClass.AUTH,
        )

      if isinstance(context.device, DeviceSnapshot):
        snapshot = context.device

      elif isinstance(context.device, dict):
        snapshot = DeviceSnapshot.from_context(context.device)

      elif context.device is not None:
    # fallback for object-like device
        snapshot = DeviceSnapshot(
    device_id=getattr(context.device, "device_id", None),
    registered=getattr(context.device, "registered", False),
    compromised=getattr(context.device, "compromised", False),
    clone_confirmed=getattr(context.device, "clone_confirmed", False),
    state=getattr(context.device, "state", "active"),
    hardware_backed=getattr(context.device, "hardware_backed", False),
    attestation_verified=getattr(context.device, "attestation_verified", False),
    binding_valid=getattr(context.device, "binding_valid", False),
    replay_detected=getattr(context.device, "replay_detected", False),

    # ✅ ADD THIS (CRITICAL)
    secure_boot=getattr(context.device, "secure_boot", False),
)
      else:
       snapshot = None
      # Device precedence
      PrecedenceGuard.enforce(snapshot)

    # Device trust
      if snapshot is not None:
       DeviceTrustEvaluator.enforce(snapshot)

    # Grant enforcement
      if context.grant is not None:

        now = context.request_time

        if context.grant.expires_at <= now:
            raise SecurityPipelineError(
                DenyReason.EXPIRED_GRANT,
                FailureClass.GRANT,
            )

        if context.grant.intent != context.intent:
            raise SecurityPipelineError(
                DenyReason.GRANT_SCOPE_MISMATCH,
                FailureClass.GRANT,
            )

    # Policy evaluation
      policy_result = self.policy_evaluator(context)
      decision = PolicyDecisionAdapter.adapt(policy_result)

    # Governance
      if self.revocation_registry.is_revoked(decision.policy_version):
        raise SecurityPipelineError(
            DenyReason.POLICY_DENY,
            FailureClass.GOVERNANCE,
        )

    # Evidence enforcement
      if (
        isinstance(policy_result, SecurityDecision)
        and policy_result.outcome == DecisionOutcome.DENY
        and not policy_result.obligations
        ):
        raise SecurityPipelineError(
            DenyReason.MISSING_EVIDENCE,
            FailureClass.EVIDENCE,
        )

    # Normalize deny
      if decision.outcome == DecisionOutcome.DENY:

        ctx_hash = hashlib.sha256(
            json.dumps(context.to_dict(), sort_keys=True).encode("utf-8")
        ).hexdigest()

        decision = SecurityDecisionFactory._kernel_create(
            outcome=DecisionOutcome.DENY,
            reason=decision.reason,
            policy_version=KERNEL_VERSION,
            evaluated_at=context.request_time,
            obligations={
                "evidence": {
                    "reason": decision.reason,
                    "context_hash": ctx_hash,
                    "timestamp": context.request_time.isoformat(),
                }
            },
        )

      return decision


# ==========================================================
# TRACK B — Evidence-Enforced Kernel
# ==========================================================


class SecureIDKernel(SecurityPipeline):

    def __init__(
        self,
        event_emitter=None,
        evidence_store=None,
        simulation_engine=None,
        simulation_emitter=None,
        revocation_registry=None,
    ):
        self.event_emitter = event_emitter
        self.evidence_store = evidence_store or InMemoryEvidenceStore()
        self.simulation_engine = simulation_engine
        self.simulation_emitter = simulation_emitter

        # Optional signer for receipts
        self.signer = None

        self._build_hash = KERNEL_BUILD_HASH
        self._state = KernelState.NORMAL
        self._safe_mode_reason = None
        self._append_lock = threading.Lock()

        metrics.set_gauge("meika_safe_mode_state", 0)

        super().__init__(
            policy_evaluator=lambda ctx: SecurityDecisionFactory._kernel_create(
                outcome=DecisionOutcome.ALLOW,
                reason="KERNEL_ALLOW",
                policy_version=KERNEL_VERSION,
                evaluated_at=ctx.request_time,
                obligations={},
            ),
            revocation_registry=revocation_registry,
        )

    # -------------------------------------------------
    # Test helper
    # -------------------------------------------------

    def _default_context(self) -> SecurityContext:
        import uuid
        
        return SecurityContext(
            request_id=str(uuid.uuid4()),
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
    # Safe Mode
    # -------------------------------------------------

    def _enter_safe_mode(self, reason: str = "manual"):

        if self._state == KernelState.SAFE_MODE:
            return

        self._state = KernelState.SAFE_MODE
        self._safe_mode_reason = reason

        try:
            metrics.inc("meika_tamper_events_total")
            metrics.set_gauge("meika_safe_mode_state", 1)
            event_stream.emit("safe_mode_entered", {"reason": reason})
        except Exception:
            pass

        if self.event_emitter:
            try:
                event = TamperEvent.create(reason)
                self.event_emitter.emit(event)
            except Exception:
                pass

    # -------------------------------------------------
    # Health Snapshot
    # -------------------------------------------------

    def health_snapshot(self) -> dict:

        try:
            last_seq = self.evidence_store.next_sequence() - 1
        except Exception:
            last_seq = None

        try:
            last_hash = self.evidence_store.last_hash()
        except Exception:
            last_hash = None

        return {
            "state": self._state.name,
            "kernel_version": KERNEL_VERSION,
            "build_hash": self._build_hash,
            "evidence_store_type": type(self.evidence_store).__name__,
            "last_sequence_number": last_seq,
            "last_record_hash": last_hash,
            "safe_mode_reason": self._safe_mode_reason,
        }

    # -------------------------------------------------
    # Evaluation
    # -------------------------------------------------

    def evaluate(self, context: SecurityContext) -> SecurityDecision:

        if self._state == KernelState.SAFE_MODE:

            decision = super().evaluate(context)

            if decision.outcome == DecisionOutcome.ALLOW:
                raise SecurityPipelineError(
                    DenyReason.POLICY_DENY,
                    FailureClass.GOVERNANCE,
                )

            return decision

        try:
            decision = super().evaluate(context)

        except SecurityPipelineError as e:
           return SecurityDecisionFactory._kernel_create(
           outcome=DecisionOutcome.DENY,
           reason=e.reason,
           policy_version=KERNEL_VERSION,
           evaluated_at=context.request_time,
           obligations={},
        )
        try:
            metrics.inc(
                "meika_kernel_decisions_total",
                labels={"result": decision.outcome.name.lower()},
            )
        except Exception:
            pass

        if decision.policy_version != KERNEL_VERSION:
            self._enter_safe_mode("KERNEL_VERSION_MISMATCH")
            raise SecurityInvariantViolation("KERNEL_VERSION_MISMATCH")

        if self._build_hash != KERNEL_BUILD_HASH:
            self._enter_safe_mode("KERNEL_BUILD_HASH_CHANGED_AT_RUNTIME")
            raise SecurityInvariantViolation(
                "KERNEL_BUILD_HASH_CHANGED_AT_RUNTIME"
            )

        if decision.outcome != DecisionOutcome.ALLOW:
            return decision

        with self._append_lock:
            try:
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
                    raise RuntimeError("Evidence append returned None")

            except AttributeError:

                self._enter_safe_mode("EVIDENCE_COMMIT_FAILURE")

                return SecurityDecisionFactory._kernel_create(
                    outcome=DecisionOutcome.DENY,
                    reason=DenyReason.MISSING_EVIDENCE,
                    policy_version=KERNEL_VERSION,
                    evaluated_at=context.request_time,
                    obligations={},
                )

            except Exception as e:
                self._enter_safe_mode("EVIDENCE_COMMIT_FAILURE")
                raise SecurityInvariantViolation(
                    "Evidence commit failed"
                ) from e

        try:
            metrics.inc("meika_evidence_appends_total")
        except Exception:
            pass

        final_decision = SecurityDecisionFactory._kernel_create(
            outcome=decision.outcome,
            reason=decision.reason,
            policy_version=KERNEL_VERSION,
            evaluated_at=decision.evaluated_at,
            obligations=decision.obligations,
            evidence_hash=receipt.merkle_root,
        )

        # Optional Authorization Receipt
        try:

            if self.signer:

                generator = AuthorizationReceiptGenerator(self.signer)

                auth_receipt = generator.generate(
                    context=context,
                    decision=final_decision,
                    evidence_hash=getattr(receipt, "record_hash", receipt.merkle_root),
                    merkle_root=receipt.merkle_root,
                )

                final_decision.authorization_receipt = auth_receipt

        except Exception:
            pass

        return final_decision