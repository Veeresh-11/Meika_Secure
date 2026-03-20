from __future__ import annotations
from abc import ABC, abstractmethod
from ..anchor_receipt import AnchorReceipt


class BaseAnchorProvider(ABC):

    @abstractmethod
    def network_id(self) -> str:
        pass

    @abstractmethod
    def submit_root(self, root_hash: str) -> AnchorReceipt:
        pass

    @abstractmethod
    def verify_on_chain(self, receipt: AnchorReceipt) -> bool:
        pass
