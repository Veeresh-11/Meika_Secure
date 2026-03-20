from __future__ import annotations

from typing import Iterable

from app.security.track_d.anchoring.anchor_policy_engine import (
    AnchorPolicy,
)
from app.security.track_d.anchoring.anchor_policy_registry import (
    AnchorPolicyRegistry,
)
from app.security.track_d.anchoring.root_anchor_ledger import (
    RootAnchorLedger,
)
from app.security.track_d.consensus.threshold_signature import (
    ThresholdSignature,
    ThresholdSigner,
)


class PolicyUpgradeError(ValueError):
    pass


class PolicyUpgradeEngine:
    """
    Constitutional Policy Upgrade Engine

    Guarantees:
    - Existing policy must exist
    - Previous policy hash must match
    - Version increments strictly by +1
    - Threshold signature must verify
    - Governance signer continuity enforced (global authority)
    - Upgrade must be anchored
    """

    def __init__(
        self,
        *,
        registry: AnchorPolicyRegistry,
        ledger: RootAnchorLedger,
    ):
        self._registry = registry
        self._ledger = ledger

    # -----------------------------------------------------

    def upgrade(
        self,
        *,
        new_policy: AnchorPolicy,
        previous_policy_hash: str,
        threshold_signature: ThresholdSignature,
        anchor_receipts: Iterable,
        anchored_at: str,
    ) -> None:

        # 1️⃣ Verify existing policy
        current_policy = self._registry.latest()

        if current_policy is None:
            raise PolicyUpgradeError("No existing policy to upgrade")

        if current_policy.policy_hash != previous_policy_hash:
            raise PolicyUpgradeError("Previous policy hash mismatch")

        # 2️⃣ Version must increment exactly by +1
        if new_policy.version != current_policy.version + 1:
            raise PolicyUpgradeError("Policy version must increment by 1")

        # 3️⃣ Verify threshold signature integrity
        if not threshold_signature.verify(new_policy.policy_hash):
            raise PolicyUpgradeError("Invalid threshold signature")

        # 4️⃣ Enforce governance signer authority
        governance_id = ThresholdSigner.governance_signer_id()

        if governance_id is None:
            raise PolicyUpgradeError("Governance signer not established")

        if threshold_signature.signer_id != governance_id:
            raise PolicyUpgradeError("Unauthorized governance signer")

        # 5️⃣ Anchor new policy in ledger
        self._ledger.append(
            certificate_hash=new_policy.policy_hash,
            anchored_at=anchored_at,
            receipts=list(anchor_receipts),
        )

        # 6️⃣ Register new policy
        self._registry.register(new_policy)
