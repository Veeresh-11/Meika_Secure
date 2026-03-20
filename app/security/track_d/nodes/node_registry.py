"""
TRACK D — Node Registry
"""

from __future__ import annotations

from typing import Dict

from .node_identity import NodeIdentity


class NodeRegistry:

    def __init__(self):
        self._nodes: Dict[str, NodeIdentity] = {}

    # ---------------------------------------------
    # Register Node
    # ---------------------------------------------

    def register(self, node: NodeIdentity):

        if node.node_id in self._nodes:
            raise ValueError("Duplicate node")

        self._nodes[node.node_id] = node

    # ---------------------------------------------
    # Basic Getter
    # ---------------------------------------------

    def get(self, node_id: str) -> NodeIdentity:
        if node_id not in self._nodes:
            raise ValueError("Unknown node")
        return self._nodes[node_id]

    # ---------------------------------------------
    # Consensus Getter
    # ---------------------------------------------

    def get_node(self, node_id: str) -> NodeIdentity:
        return self.get(node_id)

    # ---------------------------------------------
    # Active Node Getter
    # ---------------------------------------------

    def get_active(self, node_id: str, at_timestamp: str) -> NodeIdentity:

        node = self.get(node_id)

        node.validate_active(at_timestamp)

        return node
