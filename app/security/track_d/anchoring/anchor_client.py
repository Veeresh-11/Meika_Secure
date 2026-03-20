from __future__ import annotations

from abc import ABC, abstractmethod
from .anchor_receipt import AnchorReceipt


class AnchorClient(ABC):

    @abstractmethod
    def anchor(self, root_hash: str) -> AnchorReceipt:
        pass

    @abstractmethod
    def verify(self, receipt: AnchorReceipt) -> bool:
        pass
