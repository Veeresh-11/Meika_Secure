# app/security/evidence/memory/tier.py

from enum import Enum

class EvidenceTier(str, Enum):
    """
    Track C — Evidence lifecycle tiers.

    Tiers NEVER affect hash, order, or meaning.
    They only affect storage and availability.
    """
    HOT = "hot"        # recent, fast access
    WARM = "warm"      # replicated, slower
    COLD = "cold"      # archive
    FROZEN = "frozen"  # legal hold / immutable forever
