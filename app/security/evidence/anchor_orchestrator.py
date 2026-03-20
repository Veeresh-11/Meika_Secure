from typing import List

from app.security.evidence.models import EvidenceRecord
from app.security.evidence.anchor_bridge import EvidenceAnchorBridge
from app.security.evidence.anchor_policy import AnchorPolicy, TimeAnchorPolicy


class EvidenceAnchorOrchestrator:
    """
    Controls automatic anchoring policies.

    This is infrastructure orchestration.
    Not part of kernel.
    """

    def __init__(
        self,
        bridge: EvidenceAnchorBridge,
        record_policy: AnchorPolicy | None = None,
        time_policy: TimeAnchorPolicy | None = None,
    ):
        self.bridge = bridge
        self.record_policy = record_policy
        self.time_policy = time_policy

    def evaluate(
        self,
        records: List[EvidenceRecord],
        store,
        context,
    ):
        record_count = len(records)

        record_trigger = (
            self.record_policy.should_anchor(record_count)
            if self.record_policy
            else False
        )

        time_trigger = (
            self.time_policy.should_anchor()
            if self.time_policy
            else False
        )

        if record_trigger or time_trigger:
            result = self.bridge.seal_anchor_and_record(
                records, store, context
            )

            if self.time_policy:
                self.time_policy.mark_anchored()

            return result

        return None
