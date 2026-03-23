from app.security.policy.loader import load_policy
from app.security.policy.engine import PolicyEngine
from app.security.pipeline import SecurityPipeline

from app.security.graph.relationship_graph import RelationshipGraph
from app.security.graph.storage.memory_store import MemoryTupleStore
from app.security.graph.storage.cache import TupleCache

from app.security.track_d.signing.ed25519_local import Ed25519LocalSigner


def build_pipeline():

    # -------------------------------------------------
    # Policy
    # -------------------------------------------------

    policy = load_policy("policies/authentication_policy.yaml")

    # -------------------------------------------------
    # Graph Authorization
    # -------------------------------------------------

    backend = MemoryTupleStore()
    cache = TupleCache(backend)

    cache.add("alice", "edit", "document:123")
    cache.add("document:123", "parent", "project:A")

    graph = RelationshipGraph(cache)

    policy_engine = PolicyEngine(policy, graph=graph)

    # -------------------------------------------------
    # Kernel
    # -------------------------------------------------

    kernel = SecurityPipeline()

    kernel.policy_evaluator = policy_engine.evaluate
    kernel.graph = graph
    # -------------------------------------------------
    # Optional signer for authorization receipts
    # -------------------------------------------------

    kernel.signer = Ed25519LocalSigner()

    return kernel