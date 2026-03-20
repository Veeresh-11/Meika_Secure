Track C — Evidence Memory Test Matrix
A. Structural Integrity
Test	Description
C-01	Genesis hash correctness
C-02	Sequence monotonicity
C-03	previous_hash correctness
C-04	No fork detection
C-05	Missing record detection
B. Tier Safety
Test	Description
C-06	HOT → WARM transition
C-07	WARM → COLD transition
C-08	Tier migration preserves hash
C-09	Read-only enforcement
C-10	Cold tier offline replay
C. Replay & Audit
Test	Description
C-11	Full replay from genesis
C-12	Partial replay by range
C-13	Deterministic replay
C-14	Replay without runtime context
C-15	Offline verification
D. Failure Semantics
Test	Description
C-16	Missing record fails audit
C-17	Corrupt record detection
C-18	Storage outage isolation
C-19	Retention misconfiguration
C-20	Illegal mutation detection
E. Compliance Mapping
Framework	Controls
SOC2 Type II	CC7.2, CC7.4, CC7.5
ISO 27001	A.12.4, A.18.1
NIST 800-53	AU-3, AU-6, AU-9
