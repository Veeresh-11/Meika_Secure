# app/security/track_d/anchoring/multi_anchor_client.py

from __future__ import annotations
from typing import List

from .anchor_receipt import AnchorReceipt
from .anchor_providers.base_provider import BaseAnchorProvider


class MultiAnchorClient:
    """
    Anchors a root hash across multiple providers and enforces
    N-of-M anchoring guarantees.

    Guarantees:
    - Fail-closed if insufficient confirmations
    - Per-provider isolation (one provider failure does not break others)
    - Deterministic verification logic
    """

    def __init__(self, providers: List[BaseAnchorProvider], minimum_success: int):

        if not providers:
            raise ValueError("At least one provider required")

        if minimum_success <= 0:
            raise ValueError("minimum_success must be > 0")

        if minimum_success > len(providers):
            raise ValueError("minimum_success cannot exceed provider count")

        self.providers = providers
        self.minimum_success = minimum_success

    # ---------------------------------------------------------
    # Anchor
    # ---------------------------------------------------------

    def anchor(self, root_hash: str) -> List[AnchorReceipt]:
        """
        Submit root hash to all providers.

        Returns:
            List[AnchorReceipt]

        Raises:
            ValueError if minimum_success confirmations not achieved.
        """

        receipts: List[AnchorReceipt] = []

        for provider in self.providers:
            try:
                receipt = provider.submit_root(root_hash)

                if not isinstance(receipt, AnchorReceipt):
                    raise TypeError(
                        f"Provider {provider.network_id()} returned invalid receipt type"
                    )

                receipts.append(receipt)

            except Exception:
                # Fail per-provider only
                continue

        if len(receipts) < self.minimum_success:
            raise ValueError(
                f"Insufficient anchor confirmations: "
                f"{len(receipts)}/{self.minimum_success}"
            )

        return receipts

    # ---------------------------------------------------------
    # Verify
    # ---------------------------------------------------------

    def verify(self, receipts: List[AnchorReceipt]) -> bool:
        """
        Verify receipts across providers.

        Returns:
            True if >= minimum_success providers confirm on-chain validity.
        """

        if not receipts:
            return False

        success_count = 0

        for receipt in receipts:

            # Find matching provider by network
            matching_provider = next(
                (
                    provider
                    for provider in self.providers
                    if provider.network_id() == receipt.network
                ),
                None,
            )

            if not matching_provider:
                continue

            try:
                if matching_provider.verify_on_chain(receipt):
                    success_count += 1
            except Exception:
                continue

        return success_count >= self.minimum_success
