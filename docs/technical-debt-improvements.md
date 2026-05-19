# MEIKA TECHNICAL DEBT & ARCHITECTURAL IMPROVEMENTS

**Prepared for**: Engineering leadership  
**Priority**: Critical path to production  
**Timeline**: 12-16 weeks

---

## CRITICAL BLOCKING ISSUES

### 1. **Policy Engine Rule Matcher is Stubbed** ⛔

**Location**: `app/security/policy/engine.py` line ~150

**Current Code**:
```python
def _matches(self, rule: PolicyRule, context: SecurityContext) -> bool:
    return True  # ← ALWAYS MATCHES!
```

**Impact**: 
- All policies effectively "allow" everything
- Zero Trust guarantees broken
- Cannot differentiate between users/groups
- Investigation grants not scoped

**Fix** (2-3 days):
```python
def _matches(self, rule: PolicyRule, context: SecurityContext) -> bool:
    """Evaluate all conditions in rule"""
    
    for condition in rule.conditions:
        result = self._evaluate_condition(condition, context)
        
        if rule.logic == "all" and not result:  # AND logic
            return False
        elif rule.logic == "any" and result:   # OR logic (short circuit)
            return True
    
    # all conditions passed if logic=all, or none passed if logic=any
    return rule.logic == "all"

def _evaluate_condition(self, condition: Condition, context: SecurityContext) -> bool:
    if condition.type == "user":
        return context.principal_id == condition.value
    
    elif condition.type == "user_in_group":
        return context.principal_id in self.group_service.get_members(condition.group)
    
    elif condition.type == "device_posture":
        required = condition.required_level  # "low", "medium", "high", "veryhigh"
        actual = self._device_posture_to_level(context.device.posture)
        return posture_level(actual) >= posture_level(required)
    
    elif condition.type == "time_of_day":
        current_hour = context.request_time.hour
        start, end = condition.range  # e.g., (9, 18)
        return start <= current_hour < end
    
    elif condition.type == "geo_location":
        return context.ip_address_geo in condition.allowed_countries
    
    elif condition.type == "device_type":
        return context.device.type in condition.allowed_types  # ["mobile", "laptop"]
    
    elif condition.type == "mfa_age":
        mfa_time = context.device.last_mfa_time
        max_age = condition.max_hours  # hours
        return (now() - mfa_time) < timedelta(hours=max_age)
    
    else:
        raise ValueError(f"Unknown condition type: {condition.type}")
```

**Test**:
```python
def test_policy_rule_matching():
    rule = PolicyRule(
        conditions=[
            Condition(type="user_in_group", group="security-team"),
            Condition(type="device_posture", required_level="high"),
            Condition(type="time_of_day", range=(9, 18)),
        ],
        logic="all"
    )
    
    context = SecurityContext(
        principal_id="alice",
        device=DeviceContext(posture="compliant_and_updated"),
        request_time=datetime(2026, 5, 19, 10, 0)  # 10am
    )
    
    # Should match if alice in security-team, device healthy, during work hours
    assert engine._matches(rule, context) == True
```

---

### 2. **Password Login Should NOT Exist** ⛔

**Problem**: Whitepaper says "password-only forbidden" but code still accepts passwords

**Current Flow**:
```
POST /api/v1/auth/login
  {email: "alice@acme.com", password: "..."}
  ↓
  Authenticate with AuthService.login_user(email, password)
  ↓
  Create session token
```

**Why This Breaks Zero Trust**:
1. Passwords phishable
2. No hardware binding
3. Okta rejects this architecture
4. Users expect passwordless

**Fix** (1 week):

**Step 1**: Deprecate password login
```python
@router.post("/login", deprecated=True)
async def login_deprecated(payload: LoginRequest):
    warnings.warn("POST /login deprecated, use POST /webauthn/authenticate")
    # Still works but logs deprecation event
    logger.warning(f"Deprecated password auth used by {payload.email}")
    return {...}
```

**Step 2**: Implement WebAuthn as primary
```python
@router.post("/webauthn/register")
async def webauthn_register(
    user_id: str,
    device_name: str,  # "Alice's MacBook"
    db: Session = Depends(get_db)
):
    """Phase 1: Generate challenge for credential creation"""
    challenge = secrets.token_urlsafe(32)
    
    registration_session = WebAuthnRegistrationSession(
        user_id=user_id,
        challenge=challenge,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.add(registration_session)
    db.commit()
    
    return JSONResponse({
        "challenge": base64.b64encode(challenge.encode()).decode(),
        "rp": {
            "name": "Meika",
            "id": "meika.example.com"
        },
        "user": {
            "id": base64.b64encode(user_id.encode()).decode(),
            "name": email,
            "displayName": "Alice at ACME"
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},    # ES256
            {"type": "public-key", "alg": -8},    # EdDSA
        ],
        "timeout": 60000,
        "attestation": "direct",
    })

@router.post("/webauthn/register/verify")
async def webauthn_register_verify(
    payload: WebAuthnAttestationResponse,
    db: Session = Depends(get_db)
):
    """Phase 2: Verify and store credential"""
    
    # Validate attestation object
    attestation = verify_attestation(
        attestation_object=payload.attestation_object,
        client_data=payload.client_data,
        challenge=payload.challenge,
    )
    
    credential = WebAuthnCredential(
        user_id=payload.user_id,
        credential_id=attestation.credential_id,
        public_key=attestation.public_key,
        device_name=payload.device_name,
        transports=payload.transports,  # ["usb", "nfc", ...]
        created_at=datetime.utcnow(),
        last_used=None,
        verified=True,
    )
    db.add(credential)
    db.commit()
    
    return {
        "credential_id": str(credential.id),
        "status": "registered"
    }
```

**Step 3**: Authenticate with WebAuthn
```python
@router.post("/webauthn/authenticate")
async def webauthn_authenticate_init(email: str, db: Session = Depends(get_db)):
    """Phase 1: Initiate authentication"""
    user = db.query(User).filter_by(email=email).first()
    if not user:
        raise HTTPException(status_code=404)
    
    credentials = db.query(WebAuthnCredential).filter_by(user_id=user.id).all()
    
    challenge = secrets.token_urlsafe(32)
    auth_session = WebAuthnAuthSession(
        user_id=user.id,
        challenge=challenge,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db.add(auth_session)
    db.commit()
    
    return {
        "challenge": base64.b64encode(challenge.encode()).decode(),
        "allowCredentials": [
            {
                "type": "public-key",
                "id": base64.b64encode(c.credential_id).decode(),
                "transports": c.transports,
            }
            for c in credentials
        ],
        "timeout": 60000,
        "userVerification": "required",
    }

@router.post("/webauthn/authenticate/verify")
async def webauthn_authenticate_verify(
    payload: WebAuthnAssertionResponse,
    db: Session = Depends(get_db)
):
    """Phase 2: Verify assertion, issue grant"""
    
    # Find credential
    credential = db.query(WebAuthnCredential).filter_by(
        credential_id=payload.credential_id
    ).first()
    if not credential:
        raise HTTPException(status_code=401)
    
    # Verify signature
    if not verify_assertion(
        public_key=credential.public_key,
        assertion=payload.assertion,
        challenge=payload.challenge,
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Build security context (NO PASSWORD)
    security_ctx = SecurityContext(
        principal_id=credential.user_id,
        authenticated=True,
        intent="user.authenticate",
        device=DeviceContext(
            device_id=payload.device_id,
            registered=device_registry.is_registered(payload.device_id, credential.user_id),
            posture=posture_evaluator.evaluate(payload.device_signals),
        ),
    )
    
    # Run zero-trust pipeline
    decision = pipeline.evaluate(security_ctx)
    if decision.outcome != "ALLOW":
        raise HTTPException(status_code=403, detail=decision.reason)
    
    # Issue JIT grant (NO SESSION)
    grant = JITGrant(
        user_id=credential.user_id,
        device_id=payload.device_id,
        intent="user.authenticated",
        expires_at=datetime.utcnow() + timedelta(hours=8),
        evidence_hash=decision.evidence_hash,
    )
    db.add(grant)
    
    # Create evidence record
    evidence = Evidence(
        intent="auth.webauthn_success",
        grant_id=grant.id,
        principal_id=credential.user_id,
        device_id=payload.device_id,
        decision="ALLOW",
        evidence_hash=hashlib.sha256(...).hexdigest(),
        previous_hash=last_evidence_hash,
    )
    db.add(evidence)
    db.commit()
    
    # Return grant (not session!)
    return {
        "grant_id": str(grant.id),
        "expires_at": grant.expires_at,
        "device_compliant": security_ctx.device.posture in ["compliant", "hardened"],
    }
```

---

### 3. **MultiTenant Isolation Not Implemented** ⛔

**Problem**: Single org only, cannot sell SaaS

**Current State**:
```
Database:
  users (id, email, ...)  ← No org_id
  devices (id, user_id, ...) ← No org_id
```

**What It Should Be**:
```
Database:
  organizations (id, name, domain, created_at)
  users (id, org_id, email, ...) ← ORG_ID!
  devices (id, org_id, user_id, ...) ← ORG_ID!
  grants (id, org_id, user_id, ...) ← ORG_ID!
```

**Fix** (3-4 days):

**Schema**:
```sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW(),
    max_users INTEGER DEFAULT 1000,
    subscription_tier VARCHAR(50),  -- "free", "pro", "enterprise"
);

-- All existing tables add org_id
ALTER TABLE users ADD COLUMN org_id UUID NOT NULL;
ALTER TABLE devices ADD COLUMN org_id UUID NOT NULL;
ALTER TABLE grants ADD COLUMN org_id UUID NOT NULL;
ALTER TABLE evidence ADD COLUMN org_id UUID NOT NULL;

-- Foreign key
ALTER TABLE users ADD CONSTRAINT fk_users_org 
  FOREIGN KEY (org_id) REFERENCES organizations(id);
```

**Extract Org from Request**:
```python
# app/middleware/tenant.py
async def tenant_middleware(request: Request, call_next):
    # Option 1: Subdomain
    # meika.acme.com/... → org_id = acme
    
    # Option 2: Path prefix
    # /api/v1/orgs/acme-corp/users → org_id = acme-corp
    
    # Option 3: API Key
    # Bearer eyJhbGc... decode → org_id
    
    org_id = extract_org_id(request)
    request.state.org_id = org_id
    
    response = await call_next(request)
    return response
```

**Query Filtering**:
```python
# app/security/middleware.py - MODIFY
async def get_security_context(request: Request, db: Session) -> SecurityContext:
    org_id = request.state.org_id
    principal_id = request.state.principal_id
    
    # Check principal belongs to org
    user = db.query(User).filter(
        User.id == principal_id,
        User.org_id == org_id  # ← CRITICAL!
    ).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    return SecurityContext(...)
```

---

### 4. **Investigation Grant API Missing** ⛔

**Problem**: Designed in docs/policies but no REST API

**Solution** (see code section above)

---

### 5. **SIEM Export Not Implemented** ⛔

**Problem**: Cannot send events to Splunk/Datadog for compliance

**Solution** (see code section above, 2-3 days)

---

## HIGH PRIORITY TECHNICAL IMPROVEMENTS

### 6. **Add Rate Limiting**

**Location**: `app/middleware/rate_limit.py` (NEW)

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/v1/auth/login")
@limiter.limit("5/minute")
async def login(...):
    ...

@app.post("/api/v1/elevations/{id}/approve")
@limiter.limit("20/minute")
async def approve_elevation(...):
    ...

@app.post("/api/v1/oauth/token")
@limiter.limit("30/minute")
async def token_exchange(...):
    ...
```

**Why**: Prevent brute force on auth endpoints

---

### 7. **Evidence Query Service**

**Location**: `app/services/evidence_query.py` (NEW)

```python
class EvidenceQueryService:
    def query_by_user(self, user_id: str, org_id: str, limit: int = 1000) -> list[Evidence]:
        return db.query(Evidence).filter(
            Evidence.principal_id == user_id,
            Evidence.org_id == org_id,
        ).order_by(Evidence.sequence_number.desc()).limit(limit).all()
    
    def query_by_grant(self, grant_id: str, org_id: str) -> list[Evidence]:
        return db.query(Evidence).filter(
            Evidence.grant_id == grant_id,
            Evidence.org_id == org_id,
        ).all()
    
    def query_by_date_range(self, start: datetime, end: datetime, org_id: str):
        return db.query(Evidence).filter(
            Evidence.created_at >= start,
            Evidence.created_at <= end,
            Evidence.org_id == org_id,
        ).all()
    
    def verify_merkle_chain(self, start_hash: str, end_hash: str) -> bool:
        """Verify chain is unbroken from start to end"""
        records = db.query(Evidence).filter(
            Evidence.record_hash >= start_hash,
            Evidence.record_hash <= end_hash,
        ).order_by(Evidence.sequence_number).all()
        
        for i in range(1, len(records)):
            if records[i].previous_hash != records[i-1].record_hash:
                return False  # Chain broken!
        
        return True
```

---

### 8. **Improve Device Attestation**

**Current**: Schema exists, no active attestation verification

**Needed**:
```python
# app/security/device/attestation.py
class AttestationVerifier:
    def verify_tpm_quote(self, quote: bytes, pcr_values: dict) -> bool:
        """Verify TPM attestation"""
        # Check PCR values match expected (OS not modified)
    
    def verify_fido2_attestation(self, attestation: bytes) -> bool:
        """Verify FIDO2 device attestation"""
        # Check device is approved type (Yubico, SoloKey, etc.)
    
    def check_secure_boot(self, reported_state: bool) -> bool:
        """Verify Secure Boot enabled"""
```

---

### 9. **Implement Grant Graph**

**Current**: Optional graph authorization, rarely tested

**Do**: Make it required for admin intent, not optional

```python
# app/security/authz/grant_graph.py
class GrantGraph:
    def can_escalate_to(self, user_id: str, intent: str) -> bool:
        """
        Query: Does user have path to this intent?
        
        Example:
          user="alice" → admin_escalation_request → security-manager → approves
          → user gets grant for intent="admin:rotate_key"
        """
```

---

### 10. **Add Comprehensive Logging**

**Current**: Structlog used but inconsistent

**Do**: Every major decision logs:
```python
logger.info(
    "grant_verified",
    grant_id=grant.id,
    user_id=grant.user_id,
    intent=grant.intent,
    expires_at=grant.expires_at,
    is_valid=is_valid,
)

logger.warning(
    "grant_revoked",
    grant_id=grant.id,
    reason="admin_containment",
)
```

---

## DATABASE SCHEMA UPDATES

**File**: `migrations/004_multitenant_org_isolation.sql`

```sql
-- Create organization table
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    subscription_tier VARCHAR(50) DEFAULT 'free',
    max_users INTEGER DEFAULT 1000,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add org_id to all existing tables
ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS org_id UUID;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS org_id UUID;

-- Add constraints
ALTER TABLE users ADD CONSTRAINT fk_users_org 
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

ALTER TABLE evidence ADD CONSTRAINT fk_evidence_org
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;

-- Add indexes for multi-tenant queries
CREATE INDEX idx_users_org_id ON users(org_id);
CREATE INDEX idx_devices_org_id ON devices(org_id);
CREATE INDEX idx_grants_org_id ON grants(org_id);
CREATE INDEX idx_evidence_org_id ON evidence(org_id);
CREATE INDEX idx_evidence_org_date ON evidence(org_id, created_at DESC);

-- Unique constraint per org
CREATE UNIQUE INDEX idx_users_org_email ON users(org_id, email);
```

---

## ARCHITECTURE IMPROVEMENTS

### **Current Request Flow** (Session-Based):
```
POST /api/v1/auth/login
  → AuthService.login_user(email, password)
  → Session created (expires_in: 1 hour)
  → Client stores session_id
  
GET /api/v1/protected
  Authorization: Bearer session_id_xyz
  → Middleware checks session valid
  → If valid, execute
```

**Problem**: Session = implicit trust window (1 hour can be abused)

### **New Request Flow** (Intent-Based):
```
POST /api/v1/webauthn/authenticate
  → User proves device ownership
  → JIT Grant issued (time-bounded, scope-bounded)
  → Client stores grant_id
  
GET /api/v1/protected
  X-Grant-ID: grant_xyz
  → Middleware checks grant valid
  → Re-evaluates policy
  → If valid, execute + evidence recorded
```

**Advantage**: Grant can be immediately revoked, no window

---

## TESTING STRATEGY

### **Unit Tests** (By Feature)
```
test_webauthn_*                           60 tests
test_oidc_*                               40 tests
test_multitenant_isolation                30 tests
test_investigation_grant_*                25 tests
test_siem_export_*                        20 tests
test_rate_limiting_*                      15 tests
─────────────────────────────────────────────────
Total: ~190 tests
```

### **Integration Tests**
```
test_end_to_end_webauthn_to_policy        5 tests
test_multitenant_data_isolation           5 tests
test_siem_export_flow                     3 tests
─────────────────────────────────────────────────
Total: ~13 tests
```

### **Load Tests** (k6)
```
Scenario 1: Registration surge (deployment day)
  - 500 users registering concurrently
  - Target: p99 < 200ms
  - Error rate: < 0.1%

Scenario 2: Authentication peak (login page)
  - 10,000 users authenticating concurrently
  - Target: throughput = 5,000 req/sec
  - Error rate: < 0.01%

Scenario 3: JIT elevation
  - 100 admins requesting elevation
  - 100 managers approving
  - Target: < 500ms end-to-end
```

---

## TIMELINE TO PRODUCTION

| Week | Task | Owner | Status |
|------|------|-------|--------|
| 1-2 | Fix policy matcher | Core | 🔴 |
| 2-3 | WebAuthn auth | Security | 🔴 |
| 3-4 | Multi-tenant schema | DB | 🔴 |
| 4-5 | OIDC server | Federation | 🔴 |
| 5-6 | Investigation API | Security | 🔴 |
| 6-7 | SIEM export | Observability | 🔴 |
| 7-8 | Rate limiting | Platform | 🔴 |
| 8-9 | Load testing | DevOps | 🔴 |
| 9-10 | Documentation | Tech Writer | 🔴 |
| 10-11 | Beta launch | Product | 🔴 |
| 11-12 | GA preparation | All | 🔴 |

---

## Risk Mitigation

### Risk 1: WebAuthn Compatibility
**Mitigation**: Support both EdDSA and ES256, test on all major browsers

### Risk 2: Multi-tenant Data Leakage
**Mitigation**: Penetration test every org_id check, deny by default access model

### Risk 3: OIDC Token Security
**Mitigation**: Sign with hybrid EdDSA + ML-DSA, validate on every use

### Risk 4: SIEM Integration Uptime
**Mitigation**: Queue events locally if export fails, retry exponentially

---

## Success Criteria

- [ ] All 292 tests passing
- [ ] WebAuthn works on Chrome, Safari, Firefox, Edge
- [ ] Multi-tenant tests show zero cross-org data leakage
- [ ] OIDC Discovery passes OAuth2.io compliance tests
- [ ] Investigation queries audit themselves without infinite loop
- [ ] Load tests: 5,000 auth/sec, p99 < 100ms
- [ ] Documentation complete and reviewed
- [ ] Security audit passed
