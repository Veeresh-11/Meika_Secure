# app/security/conftest.py

"""
Global pytest fixtures for Meika Security Kernel.

TRACK A:
- Deterministic kernel fixtures
- Stable allow / deny contexts

TRACK B:
- Evidence-enforced kernel
- Append-only evidence store ownership

TRACK C:
- Evidence memory fixtures
- Replay, retention, and tier-independence validation
"""
import os
import pytest
from app.security.pipeline import SecureIDKernel
from app.security.context import SecurityContext
from app.security.evidence.store import InMemoryEvidenceStore
from app.security.evidence_orchestrator import EvidenceEnforcedPipeline
from app.security.evidence.postgres_store import PostgresEvidenceStore
# -------------------------------------------------
# TRACK A — CORE KERNEL FIXTURES
# -------------------------------------------------

@pytest.fixture
def kernel():
    """
    Track A kernel fixture.

    - Deterministic
    - No external dependencies
    - Evidence store owned internally
    """
    return SecureIDKernel()


@pytest.fixture
def allow_context():
    """
    Canonical allow context.

    Used by Track A decision determinism tests.
    """
    return SecurityContext.fake_allow_context()


@pytest.fixture
def deny_context():
    """
    Canonical deny context.

    Used by Track A denial invariants.
    """
    return SecurityContext.fake_deny_context()


# -------------------------------------------------
# TRACK B — EVIDENCE-ENFORCED KERNEL
# -------------------------------------------------

@pytest.fixture
def kernel_with_store():
    """
    Track B / C kernel with explicit evidence store.

    This allows:
    - Evidence inspection
    - Chain replay
    - Retention tests

    WITHOUT violating kernel purity.
    """
    store = InMemoryEvidenceStore()
    return SecureIDKernel(evidence_store=store)


@pytest.fixture
def evidence_store(kernel_with_store):
    """
    Access to the kernel-owned evidence store.

    Read-only usage ONLY.
    """
    return kernel_with_store.evidence_store


# -------------------------------------------------
# TRACK C — EVIDENCE MEMORY FIXTURES
# -------------------------------------------------

@pytest.fixture
def evidence_chain(kernel_with_store):
    """
    Canonical VALID evidence chain.

    Properties:
    - Append-only
    - Strictly ordered
    - Cryptographically linked

    Used for:
    - Replay validation
    - Chain integrity checks
    - Tier independence tests
    """
    ctx = kernel_with_store._default_context()

    # Generate a valid chain
    kernel_with_store.evaluate(ctx)
    kernel_with_store.evaluate(ctx)
    kernel_with_store.evaluate(ctx)

    store = kernel_with_store.evidence_store
    return [store.get(h) for h in store.hashes()]


@pytest.fixture
def evidence_record(kernel_with_store):
    """
    Single immutable evidence record.

    Used by:
    - Retention tests
    - Mutation resistance checks
    """
    ctx = kernel_with_store._default_context()
    decision = kernel_with_store.evaluate(ctx)

    store = kernel_with_store.evidence_store
    return store.get(decision.evidence_hash)


POSTGRES_DSN = os.getenv("POSTGRES_DSN")


@pytest.fixture
def postgres_kernel():
    if not POSTGRES_DSN:
        pytest.skip("Postgres DSN not configured")
    # ✅ Import ONLY when needed    
    import psycopg2
    store = PostgresEvidenceStore(POSTGRES_DSN)

    return SecureIDKernel(evidence_store=store)
