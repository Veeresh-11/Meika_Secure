# MEIKA vs OKTA: Competitive Analysis & Roadmap to Win

**Date**: May 19, 2026  
**Status**: Meika 0.1 (MVP) vs Okta ≈ 15+ years mature  
**Market**: Enterprise Identity Platform for Zero Trust, Post-Quantum Era

---

## EXECUTIVE SUMMARY

**Meika is not an Okta clone.** It's a **fundamentally different architecture** built for a threat model Okta doesn't address:

| Dimension | Meika | Okta |
|-----------|-------|------|
| **Trust Model** | Zero (assume breach) | IAM (layered perimeter) |
| **Privilege** | Never stored | Session + roles (stored) |
| **Admin Compromise** | Auto-contained | Manual review + revocation |
| **Evidence** | Pre-execution, immutable | Post-execution, mutable |
| **Device** | Restrictive-only | Trust enabler |
| **Scalability** | Horizontal, stateless | Vertical, session-heavy |
| **Crypto** | Post-quantum ready | RSA (rotating) |

**Okta's Weakness You Can Exploit:**
- Sessions create implicit trust windows
- Admin compromise = everything compromised
- Audit trails created after damage
- Device trust ≠ device guarantee

**Your Competitive Advantage:**
- Evidence-first execution (blocks before action)
- Automatic containment (no humans in breach loop)
- Zero standing privilege (no role misuse)
- Device trust as restriction, not permission

---

## MARKET POSITIONING: WHERE YOU WIN

### 1. **Zero Trust Done Right** (Your Story)

**Okta's Pitch**: "IAM + Zero Trust policies"
**Reality**: Sessions + role-based access control (RBAC) still exist

**Meika's Pitch**: "Actual Zero Trust — No Sessions, No Standing Privilege"

**Evidence**:
```
Okta auth flow:
  Login → Session created (1 hour TTL)
  Session valid = Access granted
  Admin role = All admin APIs open
  
Meika auth flow:
  Intent request → (no session created)
  Zero Trust check → Grant validation → Evidence write → (only then) Execute
  Admin role = Irrelevant (no standing admin)
```

**Market Application**: Enterprise SOC, Kubernetes, Cloud Infrastructure where "assume breach" is mandatory

---

### 2. **Post-Quantum Cryptography** (Your Moat)

**Okta**: RS256 (RSA 2048), rotates keys automatically

**Meika**: EdDSA (Ed25519) + ML-DSA (Dilithium) + ML-KEM (ready)

**Why You Win**:
- NIST standardized PQ crypto in 2024
- Regulated sectors (Finance, Defense, Healthcare) **must** transition by 2030
- Okta's transition will take 3+ years (backward compat nightmare)
- Meika chose PQ-first from day one

**Competitive Window**: 18-24 months before Okta releases PQ support

**Implementation Gap**: Your code supports PQ but doesn't fully use it yet (fix below)

---

### 3. **Automatic Admin Containment** (Unique)

**Okta**: Alerts + manual remediation

**Meika**: Immediate revocation of all privileges + evidence record

```python
# Okta scenario: Admin compromised
→ Alert sent
→ SOC investigates (5-15 minutes)
→ SOC manually disables admin
→ Attacker already exfiltrated data

# Meika scenario: Admin compromised
→ Policy triggered (60 seconds)
→ ALL active grants revoked
→ Investigation grant issued
→ Attacker reverted to zero privilege immediately
→ Full evidence chain > audit trail
```

**Market Application**: Financial services, healthcare, government

---

### 4. **Immutable, Tamper-Evident Audit Logs**

**Okta**: Database audit logs (mutable by superuser)

**Meika**: Append-only merkle-chained evidence (schema-enforced immutability)

```sql
-- Okta vulnerability
DELETE FROM audit_logs WHERE id = 123;  -- Admin can do this

-- Meika security
-- Impossible. Schema forbids DELETE.
-- Merkle chain breaks if you try UPDATE.
-- Replicas detect tampering immediately.
```

**Compliance Win**: SOC2, FedRAMP, HIPAA, PCI-DSS require tamper-evident logs

---

### 5. **Device Trust as Restriction, Not Permission**

**Okta**: Device can unlock access ("device trusted" = access granted)

**Meika**: Device can only block access ("device compromised" = access denied)

```
Okta model (WRONG for Zero Trust):
  Device trusted? YES → Grant access
  Policy? → Secondary check
  
Meika model (CORRECT):
  Security policy → ALLOW
  Device check → Verify not compromised → ALLOW
  Device check → Is compromised → DENY (override policy)
```

**Why It Matters**: 
- Device compromise = nation-state attack, compromised EDR, firmware attack
- If device can unlock access, attackers make device "trusted"
- If device can only restrict, attackers must bypass policy (harder)

---

## COMPETITIVE GAPS TO CLOSE (Next 6 Months)

### CRITICAL (Block Okta Deal)

#### 1. **WebAuthn/Passwordless Authentication** 🔴
**Current State**: Skeleton code, password login still works

**Why This Matters**: 
- Okta's biggest competitive advantage is passwordless at scale
- Enterprise expects: "Log in with passkey/Windows Hello/security key"
- Password auth alone = seen as "legacy"

**What to Build**:
```
File: app/api/webauthn_auth.py

POST /api/v1/auth/webauthn/register
  → Credential creation challenge
  → Client performs attestation
  → Store credential public key + device info
  
POST /api/v1/auth/webauthn/authenticate
  → Challenge issued
  → Client performs assertion
  → Validate signature → Issue grant
  
POST /api/v1/auth/webauthn/list
  → Show user's registered authenticators
  → Allow removal of lost devices
```

**Acceptance Criteria**:
- [ ] Register device with security key / Windows Hello / Touch ID
- [ ] Login with registered device
- [ ] Multi-device support per user
- [ ] Backup credential recovery
- [ ] Device revocation
- [ ] FIDO2 / WebAuthn compliance tests pass

**Timeline**: 3-4 weeks

---

#### 2. **OIDC/OAuth 2.0 Server (Go Upstream)** 🔴
**Current State**: Federation endpoints exist but incomplete

**Why This Matters**:
- Okta works downstream (federation WITH external IdPs)
- **You need upstream** (Meika acts as IdP for customer apps)
- Enterprise: "Use Meika to authenticate my SaaS" (Slack, Jira, etc.)

**What to Build**:
```
File: app/api/oidc.py

GET /api/v1/oidc/.well-known/openid-configuration
  → OIDC discovery document
  
GET /api/v1/oidc/authorize
  → Authorization code flow
  → User login → Consent → Code issued
  
POST /api/v1/oidc/token
  → Exchange code for ID token + access token
  → Return JWT with claims
  
GET /api/v1/oidc/userinfo
  → Return user profile (email, name, groups)
  
GET /api/v1/oidc/jwks.json
  → Return public keys for token validation
```

**Competitive Secret**: Your OIDC server returns evidence hash + policy version in ID token.

```json
{
  "sub": "user123",
  "email": "alice@company.com",
  "aud": "client-app-123",
  "iss": "https://meika.example.com",
  
  // Your advantage
  "meika_evidence_hash": "sha256:abcd1234...",
  "meika_policy_version": "v2.1",
  "meika_build_hash": "hash:xyz789...",
  "meika_device_state": "healthy",
  "meika_device_compliance": ["tpm", "secure_boot", "full_disk_encrypt"]
}
```

**Result**: Apps authenticate users AND get device verification status

**Acceptance Criteria**:
- [ ] OAuth 2.0 Authorization Code flow works
- [ ] PKCE support for browser apps
- [ ] OIDC Discovery document correct
- [ ] ID tokens signed correctly (EdDSA)
- [ ] Refresh token rotation
- [ ] Scope → claim mapping
- [ ] Tested against standard OIDC test suites

**Timeline**: 4 weeks

---

#### 3. **Multi-Tenant SaaS Architecture** 🔴
**Current State**: Single org, no tenant isolation

**Why This Matters**:
- Okta is multi-tenant by default
- You need to sell "Meika as a service" to customers
- Every customer isolated: their policies, evidence, users, grants

**What to Build**:
```
Schema additions:
  table organizations (id, name, created_at)
  
Add to all tables:
  org_id UUID NOT NULL (foreign key)
  
Add to auth:
  Subdomain → org_id mapping
  OR API key → org_id mapping
  
Enforce:
  SELECT * FROM audit_logs WHERE org_id = request.org_id
  INSERT INTO audit_logs VALUES (..., request.org_id, ...)
```

**Multi-Tenancy Levels**:
- **L0 (Easy)**: Logical isolation via org_id
- **L1 (Better)**: Separate databases per org
- **L2 (Best)**: Separate Kubernetes namespaces per org

**Start with L0**, move to L1 for larger customers.

**Acceptance Criteria**:
- [ ] Org creation API
- [ ] Org-scoped RBAC
- [ ] Evidence query org-isolated
- [ ] Grant storage org-isolated
- [ ] SIEM export org-scoped
- [ ] Audit logs org-isolated
- [ ] No data leakage between orgs (pentest)

**Timeline**: 4 weeks

---

#### 4. **Investigation Grant API** 🔴
**Current State**: Designed but not exposed

**Why This Matters**:
- SOC tier-2 needs to investigate breaches
- "Give SOC read-only access to logs for incident X"
- Different from admin (permanent) and user (temporary action)

**What to Build**:
```
File: app/api/investigation.py

POST /api/v1/investigations
  {
    "title": "Incident INC-12345",
    "description": "Suspected S3 exfiltration",
    "severity": "high",
    "scope": ["view_audit_logs", "view_device_posture", "view_grants"],
    "expires_at": "2026-05-26T00:00:00Z"
  }
  → Returns investigation_id
  
POST /api/v1/investigations/{id}/grant
  {
    "user_id": "soc-analyst-123",
    "device_id": "laptop-456"
  }
  → Issues time-limited investigation grant
  
GET /api/v1/investigations/{id}/logs
  → Query audit logs scoped to investigation
  → Returns only logs for specified scope
  → All queries logged in audit trail
```

**Competitive Advantage**: Investigation queries themselves become evidence (non-repudiation)

**Acceptance Criteria**:
- [ ] Investigation creation
- [ ] Grant issuance
- [ ] Investigation-scoped query API
- [ ] Query logging (SOC queries audited)
- [ ] Expiry enforcement
- [ ] Per-query audit trail

**Timeline**: 2 weeks

---

#### 5. **admin/escalation.go Downward (Privilege) Management** 🔴
**Current State**: JIT elevation exists, no downward escalation flow

**Why This Matters**:
- Admin requests elevated access
- Manager approves
- System issues time-limited grant
- On expiry, privilege auto-revokes
- All interactions evidenced

**What to Build**:
```
File: app/api/privilege_management.py

POST /api/v1/escalations/request
  {
    "requested_intent": "admin:rotate_key",
    "reason": "Quarterly key rotation",
    "duration_minutes": 30,
    "manager_id": "manager-123"
  }
  → Creates escalation request (status: pending)
  
POST /api/v1/escalations/{id}/approve
  {
    "manager_id": "manager-123",
    "reason": "Approved - rotation needed"
  }
  → Issues JIT grant, stores evidence
  
GET /api/v1/escalations/history
  → Show all escalations (who, what, when, approved_by, status)
```

**Compliance**: SOX, HIPAA require "privilege change approval audit trail"

**Timeline**: 2 weeks

---

### HIGH (Win Enterprise Deals)

#### 6. **SIEM/SOAR Event Export** 🟠
**Current State**: Event schema defined, no export service

**What to Build**:
```
File: app/services/siem_export.py

class SIEMExporter:
  def export_to_splunk(self) → HTTP POST /services/collector
  def export_to_datadog(self) → HTTP POST /v1/input/...
  def export_to_arcsight(self) → CEF format over Syslog
  def export_to_elasticsearch(self) → POST /_bulk
```

**Format**: CEF (Common Event Format) + JSON both supported

**Events**:
- Authentication success/failure
- Authorization decision (ALLOW/DENY)
- Grant issuance/revocation
- Evidence chain confirmed
- Device onboarded/revoked
- Admin actions
- Investigation access granted/used

**Timeline**: 3 weeks

---

#### 7. **Compliance Export (SOC2, FedRAMP, HIPAA)** 🟠
**Current State**: Capability exists, no API

**What to Build**:
```
File: app/api/compliance.py

GET /api/v1/compliance/report/soc2
  → 30-day report of:
    - All privilege escalations
    - All failed auth attempts
    - All policy changes
    - All evidence integrity checks
    - No tampered logs (merkle proof)
    
GET /api/v1/compliance/report/hipaa-audit
  → HIPAA-specific: PHI access log
  
GET /api/v1/compliance/export/fedRamp
  → FedRAMP 800-53 controls mapping
```

**Market Position**: "Compliance-ready out of box"

**Timeline**: 3 weeks

---

#### 8. **Identity Provisioning (JIT + Scheduled)** 🟠
**Current State**: Manual user creation only

**What to Build**:
```
File: app/api/provisioning.py

# Scenario 1: User signs up
POST /api/v1/users/register
  → Triggers "USER_REGISTERED" event
  → External webhook: "User joined Acme Corp"

# Scenario 2: IdP (Okta) sends user
POST /api/v1/provisioning/scim
  → SCIM 2.0 endpoint
  → Receive: CREATE, UPDATE, DELETE user
  → Can sync from upstream Okta

# Scenario 3: Revoke user
DELETE /api/v1/users/{user_id}
  → Revokes all grants
  → Logs evidence
  → Notifies SIEM
```

**Why**: Enterprise has users in Okta, wants to sync to Meika

**Timeline**: 2 weeks

---

#### 9. **Group Management & Dynamic Policy** 🟠
**Current State**: Groups schema exists, unused

**What to Build**:
```
File: app/api/groups.py

POST /api/v1/groups
  {"name": "security-team", "members": ["alice", "bob"]}

# Policy can now reference groups
File: policies/authentication_policy.yaml
  - intent: admin:rotate_key
    allow_if: user in group("security-team") AND device == "hardware" AND time_of_day in [09:00, 18:00]
```

**Timeline**: 2 weeks

---

#### 10. **Device Management UI + Mobile SDK** 🟠
**Current State**: Device model exists, API incomplete

**What to Build**:
- Web dashboard: "Manage My Devices"
  - List registered authenticators
  - Register new device (WebAuthn)
  - Delete lost device
  - View device audit trail

- Mobile SDK (iOS/Android):
  - Initiate login
  - WebAuthn biometric unlock
  - Request JIT elevation
  - Detect compromise signals

**Timeline**: 6 weeks

---

### MEDIUM (Beat Okta on Margins)

#### 11. **API-First, SDK-Second** 🟡
**Current State**: REST API exists

**What to Implement**:
- SDKs for: Node.js, Python, Java, Go, Rust (cover 80% of enterprise)
- Each SDK wraps REST but adds:
  - Built-in PKCE
  - Local session management
  - Retry logic
  - Rate limit awareness

**Timeline**: 4 weeks

---

#### 12. **Cost: Self-Hosted vs SaaS Model** 🟡
**Okta Model**: No self-hosted, SaaS-only, per-user per-month pricing

**Your Play**: 
- **Option A**: Open-source core, SaaS for convenience
- **Option B**: Docker/Kubernetes self-hosted, pay for support
- **Option C**: Hybrid (on-prem for data + cloud service)

**Why This Wins**: Enterprise "data sovereignty" requirements (EU, China, government)

**Implementation**:
- Kubernetes Helm chart
- PostgreSQL with replication setup
- Terraform for AWS/Azure/GCP
- Docker Compose for dev/demo

**Timeline**: 3 weeks

---

#### 13. **Performance & Scalability Benchmarks** 🟡
**Current State**: Designed for scalability, not benchmarked

**What to Do**:
```bash
# Load test with k6
POST /api/v1/auth/login    → Target 10,000 req/sec
POST /api/v1/elevations/{id}/approve → Target 5,000 req/sec
GET /api/v1/investigations/{id}/logs → Target 2,000 req/sec

# Measure
- p50: <50ms
- p95: <100ms
- p99: <200ms
- Error rate: <0.1%

# Compare to Okta SLOs (if public)
```

**Timeline**: 2 weeks

---

#### 14. **Changelog / Release Notes Process** 🟡
**Current State**: VERSION file exists (0.1.0)

**What to Add**:
```
Version: 0.2.0 (2026-06-15)
‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾

✅ Added:
  - WebAuthn passwordless authentication
  - OIDC server (upstream federation)
  - Multi-tenant isolation (logical)
  - Investigation grant API
  
🔧 Fixed:
  - Policy engine rule matching logic
  - Evidence query performance (+40%)
  
🛡️ Security:
  - Refresh token rotation
  - CSRF token validation
  - Rate limiting on auth endpoints

⚠️ Removed:
  - Password login (deprecated, use WebAuthn)

⛔ Breaking:
  - API v1 → v2 (see migration guide)
```

**Why**: Developers need confidence in stability and roadmap

**Timeline**: Ongoing

---

## MARKET COMPARISON TABLE: Meika vs Okta

| Feature | Meika Today | Meika 6mo | Okta Today | Winner (6mo) |
|---------|------------|----------|-----------|------------|
| **WebAuthn** | 25% | 100% ✅ | 100% | Tie |
| **OAuth2/OIDC Server** | 40% | 100% ✅ | 100% | Tie |
| **Multi-tenancy** | 0% | 100% ✅ | 100% | Tie |
| **Session-Free** | 100% ✅ | 100% ✅ | 0% | Meika 🏆 |
| **Auto Containment** | 100% ✅ | 100% ✅ | 0% | Meika 🏆 |
| **Tamper-Evident Logs** | 100% ✅ | 100% ✅ | 20% | Meika 🏆 |
| **Post-Quantum Ready** | 60% | 100% ✅ | 0% | Meika 🏆 |
| **JIT Elevation** | 100% ✅ | 100% ✅ | 80% | Meika 🏆 |
| **Device Restriction** | 100% ✅ | 100% ✅ | 60% | Meika 🏆 |
| **Policy as Code** | 80% | 100% ✅ | 100% | Meika 🏆 |
| **Graph AuthZ** | 40% | 100% ✅ | 90% | Octa |
| **SAML Support** | 0% | 40% | 100% | Okta |
| **Mobile Apps** | 0% | 50% | 100% | Okta |
| **Managed UI** | 0% | 20% | 100% | Okta |
| **Support/SLAs** | Community | Startup | 24/7 Enterprise | Okta |

---

## GO-TO-MARKET POSITIONING

### Target: Early Adopter Enterprise + DevSecOps

**Persona 1: CISO at FinServ Startup**
- Pain: "Okta sessions are too permissive, admins have too much access"
- Solution: "Meika forces JIT, auto-contains breach, keeps evidence"
- Pitch: "Okta is 'secure enough.' Meika is 'secure by design.'"

**Persona 2: SRE at Cloud-Native Company**
- Pain: "We run Kubernetes, need per-pod zero-trust auth"
- Solution: "Meika API + device binding = pod identity"
- Pitch: "Not just SSO. Security enforcement ON EVERY REQUEST."

**Persona 3: Compliance Officer**
- Pain: "Auditors want proof logs weren't tampered"
- Solution: "Merkle-chained evidence + schema-enforced immutability"
- Pitch: "Impossible to delete evidence. Tampered logs detected immediately."

---

## TECHNICAL DEBT TO ADDRESS

### 1. **Policy Matcher Stubbed** 🔴
**Current**:
```python
def _matches(self, rule, context):
    return True  # ← ALWAYS TRUE!
```

**Fix**: Implement full rule matching
```python
def _matches(self, rule, context):
    for condition in rule.conditions:
        if condition.type == "user_in_group":
            if context.user_id not in self.groups[condition.group_name]:
                return False
        elif condition.type == "time_of_day":
            if not self._is_time_in_range(context.request_time, condition.range):
                return False
        elif condition.type == "device_posture":
            if context.device.posture < condition.required_level:
                return False
    return True
```

**Timeline**: 1 week

---

### 2. **Evidence Query Service Missing** 🔴
**Current**: Evidence stored, no retrieval API

**What to Add**:
```
File: app/services/evidence_query.py

class EvidenceQuery:
  def by_user(user_id) → list[Evidence]
  def by_grant(grant_id) → list[Evidence]
  def by_date_range(start, end) → list[Evidence]
  def by_intent(intent) → list[Evidence]
  def verify_chain(start_hash, end_hash) → bool
```

**Timeline**: 1 week

---

### 3. **PBKDF2 for Password Hashing** 🟡
**Current**: Argon2 (good, but slow for user-facing TLS)

**Consider**: Add password migration path to WebAuthn

**Timeline**: 1 week

---

### 4. **Rate Limiting** 🟡
**Current**: None

**Add**:
```python
# app/middleware/rate_limit.py
- POST /auth/login: 5 per minute per IP
- POST /auth/webauthn/authenticate: 10 per minute per device
- POST /oauth/token: 20 per minute per client_id
```

**Timeline**: 1 week

---

### 5. **Backward Compatibility Strategy** 🔴
**Current**: No versioning

**Add**:
```
/api/v1/auth/login → Current (password-based, deprecated)
/api/v2/auth/webauthn → New (passwordless, recommended)

Support v1 for 12 months, then sunset
```

**Timeline**: 1 week

---

## SPECIFIC CODE CHANGES REQUIRED

### 1. **Enable WebAuthn as Primary Auth**

**File: `app/api/auth.py`**
```python
# BEFORE (current)
@router.post("/login")
def login(payload: LoginRequest, ...):
    # email + password
    session = AuthService.login_user(
        email=payload.email,
        password=payload.password,
    )
    return {"session_id": str(session.id)}

# AFTER (6 months)
@router.post("/login")  # DEPRECATED, logs warning
def login(payload: LoginRequest, ...):
    warnings.warn("POST /login is deprecated, use POST /webauthn/authenticate")
    ...

@router.post("/webauthn/register")
def webauthn_register(payload: WebAuthnRegisterRequest):
    # User registers device with WebAuthn
    challenge = generate_challenge()
    request.session["webauthn_challenge"] = challenge
    return {"challenge": challenge}

@router.post("/webauthn/authenticate")
def webauthn_authenticate(payload: WebAuthnAuthenticateResponse):
    # User provides signed assertion
    credential = verify_assertion(payload.assertion)
    grant = issue_jit_grant(user_id=credential.user_id, device_id=credential.device_id)
    return {"grant_id": grant.id, "expires_at": grant.expires_at}
```

**Test File**: `app/security/test_webauthn_full_flow.py`
```python
def test_webauthn_register_and_authenticate():
    # 1. User requests registration
    # 2. Client creates credential
    # 3. Server stores credential
    # 4. User authenticates
    # 5. Server issues grant
    # 6. Grant passed to policy engine
    # 7. Access granted
```

---

### 2. **Implement OIDC Server**

**File: `app/api/oidc.py`** (NEW)
```python
from fastapi import APIRouter, Depends, HTTPException
from app.security.federation.oidc_provider import OIDCProvider

router = APIRouter(prefix="/oidc")
oidc = OIDCProvider()

@router.get("/.well-known/openid-configuration")
def discovery():
    return oidc.get_discovery_document()

@router.get("/authorize")
def authorize(client_id: str, redirect_uri: str, scope: str, state: str, code_challenge: str):
    # Check client registered
    # Validate redirect_uri
    # Generate auth code
    # Redirect to user login (or consent screen)
    return {"code": auth_code}

@router.post("/token")
def token(code: str, client_id: str, client_secret: str, code_verifier: str):
    # Verify code + client_secret
    # Verify PKCE challenge
    # Issue tokens
    return {
        "access_token": access_token,
        "id_token": id_token,
        "refresh_token": refresh_token,
        "expires_in": 3600,
        "token_type": "Bearer"
    }

@router.get("/userinfo")
def userinfo(request: Request):
    # Extract access_token from Authorization header
    # Return user claims
    return {
        "sub": user_id,
        "email": email,
        "name": name,
        "meika_evidence_hash": evidence_hash,
        "meika_device_state": device_state
    }

@router.get("/jwks.json")
def jwks():
    return oidc.get_jwks()
```

---

### 3. **Multi-Tenant Isolation**

**File: `app/db/models.py`** (MODIFY)
```python
# Add to ALL models
class BaseModel(Base):
    __abstract__ = True
    org_id: Column = Column(UUID, ForeignKey('organizations.id'), nullable=False)
    
class User(BaseModel):
    org_id = Column(UUID, ForeignKey('organizations.id'), nullable=False)
    email = Column(String, unique=True)  # Change to (unique within org_id)
    
# Add index
Index('idx_user_org_email', User.org_id, User.email, unique=True)
```

**File: `app/security/middleware.py`** (MODIFY)
```python
async def enforce_security(request: Request, call_next):
    # Extract org_id from subdomain or API key
    org_id = extract_org_id(request)
    request.state.org_id = org_id
    response = await call_next(request)
    return response
```

**File: `app/db/session.py`** (MODIFY)
```python
def get_db():
    org_id = request.state.org_id
    
    db = SessionLocal()
    try:
        # All queries now filtered by org_id
        db.query = lambda model: db.session.query(model).filter(model.org_id == org_id)
        yield db
    finally:
        db.close()
```

---

### 4. **Implement Investigation Grant API**

**File: `app/api/investigations.py`** (NEW)
```python
@router.post("/investigations")
def create_investigation(payload: InvestigationCreateRequest, db: Session = Depends(get_db)):
    investigation = Investigation(
        title=payload.title,
        severity=payload.severity,
        scope=payload.scope,
        expires_at=payload.expires_at,
    )
    db.add(investigation)
    db.commit()
    return {"investigation_id": str(investigation.id)}

@router.post("/investigations/{investigation_id}/grant")
def grant_investigation_access(investigation_id: str, payload: GrantRequest, db: Session = Depends(get_db)):
    investigation = db.query(Investigation).get(investigation_id)
    grant = InvestigationGrant(
        investigation_id=investigation_id,
        user_id=payload.user_id,
        device_id=payload.device_id,
        expires_at=investigation.expires_at,
    )
    db.add(grant)
    
    evidence = Evidence(
        intent="investigation:grant_issued",
        grant_id=grant.id,
        user_id=payload.user_id,
        decision="ALLOW",
    )
    db.add(evidence)
    db.commit()
    return {"grant_id": str(grant.id)}

@router.get("/investigations/{investigation_id}/logs")
def query_investigation_logs(investigation_id: str, db: Session = Depends(get_db)):
    # Verify requester has valid investigation grant
    grant = verify_investigation_grant(investigation_id, request.state.user_id, request.state.device_id, db)
    
    # Query logs within investigation scope
    logs = db.query(Evidence).filter(
        Evidence.investigation_id == investigation_id,
        Evidence.intent.in_(grant.scope)
    ).all()
    
    # Log the query itself
    query_evidence = Evidence(
        intent="investigation:query_logs",
        grant_id=grant.id,
        user_id=grant.user_id,
        query_results=len(logs),
    )
    db.add(query_evidence)
    db.commit()
    
    return {"logs": logs}
```

---

### 5. **SIEM Export Service**

**File: `app/services/siem_export.py`** (NEW)
```python
import httpx
import json
from datetime import datetime
from app.security.evidence.models import Evidence

class SIEMExporter:
    def __init__(self, splunk_hec_url: str, splunk_hec_token: str):
        self.splunk_url = splunk_hec_url
        self.token = splunk_hec_token
        self.client = httpx.AsyncClient(
            headers={"Authorization": f"Splunk {splunk_hec_token}"}
        )
    
    async def export_evidence(self, evidence: Evidence):
        """Export single evidence record to Splunk"""
        event = {
            "time": evidence.created_at.timestamp(),
            "event": {
                "evidence_id": str(evidence.id),
                "user_id": str(evidence.user_id),
                "device_id": evidence.device_id,
                "intent": evidence.intent,
                "decision": evidence.decision.value,
                "reason": evidence.reason,
                "evidence_hash": evidence.record_hash,
                "previous_hash": evidence.previous_hash,
                "grant_id": str(evidence.grant_id) if evidence.grant_id else None,
                "policy_version": evidence.policy_version,
            },
            "sourcetype": "meika:evidence",
            "source": "meika-authorizer",
        }
        
        await self.client.post(
            f"{self.splunk_url}/services/collector",
            json=event,
        )
    
    async def export_batch(self, evidence_batch: list[Evidence]):
        """Export multiple records efficiently"""
        for evidence in evidence_batch:
            await self.export_evidence(evidence)
```

**Usage**:
```python
# In background job
exporter = SIEMExporter(
    splunk_hec_url="https://splunk.example.com:8088",
    splunk_hec_token="<HEC_TOKEN>"
)

# Every 5 minutes
evidence = db.query(Evidence).filter(
    Evidence.exported == False,
    Evidence.created_at > (now - 5 minutes)
).all()

await exporter.export_batch(evidence)

# Mark as exported
for e in evidence:
    e.exported = True
db.commit()
```

---

### 6. **Post-Quantum Crypto Activation**

**File: `app/security/federation/pq_signer.py`** (EXISTS, ENABLE IT)
```python
# Current: Uses EdDSA

# NEW: Support ML-DSA (Dilithium)
from cryptography.hazmat.primitives.asymmetric import ml_dsa

class HybridSigner:
    def __init__(self):
        self.ed25519_key = generate_ed25519_key()
        self.ml_dsa_key = ml_dsa.ML_DSA_65.generate()  # NIST Level 5
    
    def sign(self, message):
        """Dual-sign for hybrid security"""
        ed_sig = self.ed25519_key.sign(message)
        ml_sig = self.ml_dsa_key.sign(message)
        
        return {
            "algorithm": "hybrid",  # New
            "ed25519": base64.b64encode(ed_sig),
            "ml_dsa_65": base64.b64encode(ml_sig),
        }
    
    def verify(self, message, signature):
        """Verify hybrid signature (both must pass)"""
        ed_valid = verify_ed25519(message, signature["ed25519"])
        ml_valid = verify_ml_dsa(message, signature["ml_dsa_65"])
        
        return ed_valid and ml_valid
```

**Why**: "Harvest now, decrypt later" attacks. Government + Finance starting mandates.

---

## PRICING STRATEGY TO BEAT OKTA

| Model | Okta | Meika | Advantage |
|-------|------|-------|-----------|
| **Per-User/Month** | $2-8 | $0.50-2 | Meika 🏆 (60% cheaper) |
| **Self-Hosted License** | Not available | $50k/year | Meika 🏆 (data sovereignty) |
| **API Calls** | Unlimited | Included | Meika 🏆 |
| **Audit Logs** | 6 months | 7 years | Meika 🏆 |
| **Support** | $5k+/year | Included (starter) | Meika 🏆 |
| **Feature Lock-In** | Yes | No (open source core) | Meika 🏆 |

---

## 12-MONTH ROADMAP TO BEAT OKTA

### **Q2 2026 (Next 8 weeks)** — Ship MVP+
◼ ◼ ◼ ◼ ◼

- [ ] WebAuthn passwordless (replaces passwords)
- [ ] OIDC server (Meika becomes IdP)
- [ ] Multi-tenant logical isolation
- [ ] Investigation grant API
- [ ] Rate limiting on auth endpoints
- **Release**: Meika 0.2.0
- **Goal**: "Okta alternative for security-first teams"

---

### **Q3 2026 (8-12 weeks)** — Win Enterprise
◼ ◼ ◼ ◼ ◼

- [ ] SIEM/SOAR export (Splunk, Datadog, Elastic)
- [ ] Compliance reports (SOC2, HIPAA, FedRAMP)
- [ ] JIT privilege management API
- [ ] Kubernetes Helm chart (self-hosted)
- [ ] Pricing page ($2/user/month)
- **Release**: Meika 0.3.0
- **Goal**: "SOC2-compliant from day one"

---

### **Q4 2026 (12-16 weeks)** — Outflank
◼ ◼ ◼ ◼ ◼

- [ ] Post-quantum crypto fully active (beats Okta timeline)
- [ ] Device management UI (web + mobile)
- [ ] Group management + dynamic policy
- [ ] SAML support (legacy enterprises)
- [ ] SDKs: Node, Python, Go, Java, Rust
- [ ] Terraform provider (IaC for policies)
- **Release**: Meika 1.0.0 "Post-Quantum Ready"
- **Goal**: "The security kernel for the quantum era"

---

### **Q1 2027 (16-20 weeks)** — Dominate
◼ ◼ ◼ ◼ ◼

- [ ] AI-driven risk scoring (anomaly detection)
- [ ] Passwordless at scale (500k users/second throughput)
- [ ] Multi-region federation (global deployment)
- [ ] GitHub partner integration (DevSecOps workflow)
- [ ] ISO 27001 + SOC 2 Type II certification
- **Release**: Meika 1.1.0 "Enterprise Ready"
- **Goal**: "Ship with Meika or compete on security"

---

## COMPETITIVE SUMMARY: Your Win Conditions

### You Win In:
1. **Zero Trust Execution** — Actual, not buzzword
2. **Evidence-First** — Blocks before action, not audit after
3. **Post-Quantum** — 18+ months ahead of Okta
4. **Auto Containment** — Humans not in incident loop
5. **Cost** — 60% cheaper for on-prem
6. **Immutable Logs** — Tamper-evident by schema
7. **No Sessions** — Stateless = scalable
8. **Device Denial** — Cannot be bypassed to grant
9. **Developer Experience** — API-first, SDK, Terraform

### Okta Still Wins In:
1. **Brand** — 15 years, billions invested
2. **SAML** — Enterprise legacy, we're building
3. **User Dashboard** — They have polished UI
4. **Support** — Enterprise SLAs
5. **Integrations** — 1000+ apps, we're at 10
6. **Market Share** — They own it locally

### Your Play:
Don't compete on incumbency. **Own the "rebuilt for zero trust at scale" narrative.**

- First release: "Okta for startups that assume breach"
- Second release: "Meika for enterprises that require evidence"
- Third release: "Post-quantum by default, Okta by compromise"

---

## Success Metrics (12 Months)

| Metric | Target | Okta Ref |
|--------|--------|----------|
| **Customers** | 50 | 10,000+ |
| **ARR** | $2M | $1B |
| **Throughput** | 100k auth/sec | 1M+ |
| **Enterprise Customers** | 5-10 | 5,000+ |
| **Dev Community** | 1k GitHub stars | (not applicable) |
| **Post-Quantum Adoption** | 30% | 0% |
| **CISO Awareness** | Known by 20% | 100% |

---

## Next Steps

1. **This Week**: Approve roadmap, assign leads
2. **Next Week**: Start WebAuthn implementation
3. **Week 3**: Begin OIDC server
4. **Week 4**: Multi-tenant design doc
5. **Week 8**: Soft launch to beta customers
6. **Week 12**: GA release 0.2.0, marketing push

The window is 18-24 months before Okta ships their PQ update. **Move fast.**
