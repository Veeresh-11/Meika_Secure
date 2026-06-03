# MEIKA IMPLEMENTATION GUIDE - Code-Level Recommendations

## Strategic Context: Why These Features Matter (Against Okta's Weaknesses)

Every feature below directly counters a fundamental Okta limitation:

| Feature | Okta's Weakness | Meika's Advantage | Regulatory/Market Impact |
|---------|---|---|---|
| **Multi-tenancy** | Complex, costly, operational complexity | Designed from day 1, clean isolation | Enables SaaS model Okta struggles with |
| **Admin console** | 200+ pages, steep learning curve, $millions PS | Ops-focused, 80% simpler | Enterprises choose simpler alternative |
| **Passwordless/WebAuthn** | Falls back to weak password auth | Passwordless-first, FIDO2 mandatory | Security-conscious enterprises demand FIDO2 |
| **Post-quantum crypto** | RSA-only, 3+ year migration needed, no plan | ML-DSA ready now, no technical debt | Finance/Defense **must be PQ by 2030** (Okta cannot) |
| **Investigation/immutable audit** | Mutable logs, superuser can delete | Schema-enforced append-only, tamper-evident | Compliance-by-architecture vs. controls-heavy Okta |
| **JIT grants** | Standing admin privileges (always-on) | Time-bound only, automatic revocation | Insider threat prevention Okta lacks |
| **Stateless architecture** | Session bottleneck, scales vertically | Stateless, scales horizontally | 40-60% cost reduction for large enterprises |
| **Automatic containment** | Manual SOC review (5-15 minutes) | Deterministic policy (<60 seconds) | Breach response that humans cannot match |

**Strategic Advantage**: You're not building to match Okta. You're building to **dominate the segments Okta's architecture cannot serve**.

---

## Quick Start: What to Build First

This guide shows **exactly what code needs to be written** with file locations and code examples.

---

## 1. MULTI-TENANCY (START HERE)

### Step 1a: Database Schema Changes

**File**: `app/db/models/user.py`

```python
# Current:
class User(Base):
    __tablename__ = "users"
    id: str = Column(String, primary_key=True)
    email: str = Column(String, unique=True, index=True)
    display_name: str = Column(String, nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)

# Required:
class User(Base):
    __tablename__ = "users"
    id: str = Column(String, primary_key=True)
    tenant_id: str = Column(String, ForeignKey("organizations.id"), index=True)  # ← NEW
    email: str = Column(String, index=True)  # ← Remove unique=True, add tenant_id index
    display_name: str = Column(String, nullable=True)
    status: str = Column(String, default="active")  # ← NEW: active, suspended, deprovisioned
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    source: str = Column(String, default="local")  # ← NEW: local, okta, entra, ldap
    external_id: str = Column(String, nullable=True)  # ← NEW: for directory sync
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'email', name='uq_tenant_email'),  # ← Unique per tenant
    )
```

**File**: `app/db/models/organization.py` (NEW FILE)

```python
from sqlalchemy import Column, String, DateTime, Boolean
from app.db.base import Base
from datetime import datetime

class Organization(Base):
    __tablename__ = "organizations"
    id: str = Column(String, primary_key=True, default=lambda: str(uuid4()))
    name: str = Column(String, index=True)
    domain: str = Column(String, unique=True, index=True, nullable=True)  # For org discovery
    admin_user_ids: str = Column(String)  # JSON array of admin IDs
    billing_plan: str = Column(String, default="free")  # free, starter, pro, enterprise
    status: str = Column(String, default="active")  # active, suspended, canceled
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    updated_at: datetime = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

**File**: `migrations/004_add_multi_tenancy.sql`

```sql
-- Add tenant_id to existing tables
ALTER TABLE users ADD COLUMN tenant_id VARCHAR NOT NULL DEFAULT 'legacy';
ALTER TABLE credentials ADD COLUMN tenant_id VARCHAR NOT NULL DEFAULT 'legacy';
ALTER TABLE sessions ADD COLUMN tenant_id VARCHAR NOT NULL DEFAULT 'legacy';
ALTER TABLE audit_logs ADD COLUMN tenant_id VARCHAR NOT NULL DEFAULT 'legacy';
ALTER TABLE grants ADD COLUMN tenant_id VARCHAR NOT NULL DEFAULT 'legacy';
ALTER TABLE evidence_records ADD COLUMN tenant_id VARCHAR NOT NULL DEFAULT 'legacy';
ALTER TABLE devices ADD COLUMN tenant_id VARCHAR NOT NULL DEFAULT 'legacy';

-- Create organizations table
CREATE TABLE organizations (
    id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    domain VARCHAR UNIQUE,
    admin_user_ids TEXT,
    billing_plan VARCHAR DEFAULT 'free',
    status VARCHAR DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Add foreign keys
ALTER TABLE users ADD CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES organizations(id);
ALTER TABLE credentials ADD CONSTRAINT fk_creds_tenant FOREIGN KEY (tenant_id) REFERENCES organizations(id);

-- Create unique constraint (email unique per tenant)
ALTER TABLE users DROP CONSTRAINT users_email_key;
ALTER TABLE users ADD CONSTRAINT uq_tenant_email UNIQUE(tenant_id, email);

-- Create indices for performance
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_credentials_tenant_id ON credentials(tenant_id);
CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_grants_tenant_id ON grants(tenant_id);
CREATE INDEX idx_evidence_tenant_id ON evidence_records(tenant_id);
```

### Step 1b: Middleware to Extract Tenant Context

**File**: `app/security/tenant_middleware.py` (NEW FILE)

```python
from typing import Optional
from fastapi import Request, HTTPException
from app.db.session import SessionLocal
from app.db.models.organization import Organization
import jwt

class TenantContext:
    def __init__(self, tenant_id: str, user_id: str):
        self.tenant_id = tenant_id
        self.user_id = user_id

async def extract_tenant_context(request: Request) -> TenantContext:
    """
    Extract tenant context from:
    1. JWT claims (tenant_id)
    2. Host header (subdomain = org.meika.com)
    3. Header (X-Tenant-ID)
    """
    
    # Priority 1: JWT token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            tenant_id = payload.get("tenant_id")
            user_id = payload.get("sub")
            if tenant_id and user_id:
                return TenantContext(tenant_id, user_id)
        except:
            pass
    
    # Priority 2: Host header (subdomain)
    host = request.headers.get("host", "")
    if "." in host:
        subdomain = host.split(".")[0]
        if subdomain not in ["localhost", "www", "api", "admin"]:
            db = SessionLocal()
            org = db.query(Organization).filter_by(domain=subdomain).first()
            if org:
                return TenantContext(org.id, "unknown")
    
    # Priority 3: Custom header
    tenant_id = request.headers.get("X-Tenant-ID")
    user_id = request.headers.get("X-User-ID")
    if tenant_id and user_id:
        return TenantContext(tenant_id, user_id)
    
    raise HTTPException(status_code=401, detail="Tenant context not found")
```

### Step 1c: Thread Tenant Through Queries

**File**: `app/services/auth_service.py` (Modified)

```python
# Current:
def login_user(self, email: str, password: str, device_id: str):
    user = self.db.query(User).filter_by(email=email).first()

# Required:
def login_user(self, email: str, password: str, device_id: str, tenant_id: str):
    user = self.db.query(User).filter_by(
        email=email,
        tenant_id=tenant_id,  # ← Add tenant filter
        status="active"  # ← Add status check
    ).first()
```

**Pattern**: Add `tenant_id` parameter to ALL database queries. Example:

```python
# ❌ Wrong (leaks data across tenants)
user = db.query(User).filter(User.email == email).first()

# ✅ Correct (tenant-isolated)
user = db.query(User).filter(
    (User.email == email) & (User.tenant_id == tenant_id)
).first()
```

---

## 2. ADMIN CONSOLE UI (NEXT PRIORITY)

### Step 2a: Backend Admin API Endpoints

**File**: `app/api/admin.py` (NEW FILE)

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.session import SessionLocal
from app.db.models.user import User
from app.security.tenant_middleware import extract_tenant_context, TenantContext

router = APIRouter(prefix="/admin", tags=["admin"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==================== USER MANAGEMENT ====================

class UserResponse(BaseModel):
    id: str
    email: str
    display_name: str
    status: str
    created_at: str

@router.get("/users", response_model=list[UserResponse])
async def list_users(
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context),
    limit: int = 50,
    offset: int = 0
):
    """List all users in tenant"""
    users = db.query(User).filter(
        User.tenant_id == tenant_context.tenant_id
    ).limit(limit).offset(offset).all()
    return users

@router.post("/users/{user_id}/suspend")
async def suspend_user(
    user_id: str,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Suspend a user (revoke all grants, disable login)"""
    user = db.query(User).filter(
        (User.id == user_id) & (User.tenant_id == tenant_context.tenant_id)
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.status = "suspended"
    db.commit()
    
    # TODO: Trigger containment engine to revoke all grants
    return {"status": "suspended"}

@router.post("/users/{user_id}/reset-password")
async def reset_password(
    user_id: str,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Send password reset email"""
    user = db.query(User).filter(
        (User.id == user_id) & (User.tenant_id == tenant_context.tenant_id)
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # TODO: Generate reset token, send email
    return {"reset_email_sent": True}

# ==================== DEVICE MANAGEMENT ====================

@router.get("/devices")
async def list_devices(
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context),
    limit: int = 50
):
    """List all devices in tenant"""
    from app.db.models.device import Device
    devices = db.query(Device).filter(
        Device.tenant_id == tenant_context.tenant_id
    ).limit(limit).all()
    return devices

@router.post("/devices/{device_id}/revoke")
async def revoke_device(
    device_id: str,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Revoke a device (prevent any future access)"""
    from app.db.models.device import Device
    device = db.query(Device).filter(
        (Device.device_id == device_id) & (Device.tenant_id == tenant_context.tenant_id)
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    device.status = "revoked"
    db.commit()
    
    # TODO: Trigger containment to revoke associated grants
    return {"status": "revoked"}

# ==================== AUDIT LOGS ====================

@router.get("/audit/logs")
async def list_audit_logs(
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context),
    user_id: str = None,
    action: str = None,
    limit: int = 100
):
    """Query audit logs with filtering"""
    from app.db.models.audit import AuditLog
    query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_context.tenant_id)
    
    if user_id:
        query = query.filter(AuditLog.actor == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
    
    logs = query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    return logs

@router.post("/audit/logs/export")
async def export_audit_logs(
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context),
    format: str = "json"  # json or csv
):
    """Export audit logs"""
    import csv
    import json
    from io import StringIO
    
    logs = db.query(AuditLog).filter(
        AuditLog.tenant_id == tenant_context.tenant_id
    ).all()
    
    if format == "csv":
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "actor", "action", "resource", "ip"])
        for log in logs:
            writer.writerow([log.created_at, log.actor, log.action, log.resource, log.ip])
        return {"csv": output.getvalue()}
    else:
        return {"json": [log.to_dict() for log in logs]}
```

### Step 2b: Register Admin Router in main.py

**File**: `app/main.py` (Modified)

```python
from app.api.admin import router as admin_router

# Add after other routers
app.include_router(admin_router, prefix="/api/v1")
```

### Step 2c: Frontend Components (React Example)

**File**: `frontend/src/pages/Admin/UserManagement.tsx` (NEW FILE)

```tsx
import React, { useState, useEffect } from 'react';
import { api } from '../../api/client';

interface User {
  id: string;
  email: string;
  display_name: string;
  status: string;
  created_at: string;
}

export const UserManagement: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const response = await api.get('/api/v1/admin/users');
      setUsers(response.data);
    } catch (error) {
      console.error('Failed to load users:', error);
    }
    setLoading(false);
  };

  const suspendUser = async (userId: string) => {
    try {
      await api.post(`/api/v1/admin/users/${userId}/suspend`);
      loadUsers();
    } catch (error) {
      console.error('Failed to suspend user:', error);
    }
  };

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-4">User Management</h1>
      {loading ? (
        <p>Loading...</p>
      ) : (
        <table className="w-full border">
          <thead>
            <tr className="bg-gray-100">
              <th className="p-2">Email</th>
              <th className="p-2">Status</th>
              <th className="p-2">Created</th>
              <th className="p-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} className="border-t">
                <td className="p-2">{user.email}</td>
                <td className="p-2">{user.status}</td>
                <td className="p-2">{new Date(user.created_at).toLocaleDateString()}</td>
                <td className="p-2">
                  {user.status !== 'suspended' && (
                    <button
                      onClick={() => suspendUser(user.id)}
                      className="text-red-600 hover:text-red-800"
                    >
                      Suspend
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};
```

---

## 3. WEBAUTHN API EXPOSURE

### Step 3a: Create WebAuthn Database Schema

**File**: `migrations/005_add_webauthn.sql`

```sql
CREATE TABLE webauthn_credentials (
    id VARCHAR PRIMARY KEY,
    tenant_id VARCHAR NOT NULL,
    user_id VARCHAR NOT NULL,
    device_id VARCHAR NOT NULL,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count INTEGER DEFAULT 0,
    hardware_backed BOOLEAN DEFAULT FALSE,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (tenant_id) REFERENCES organizations(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(tenant_id, user_id, credential_id)
);

CREATE TABLE webauthn_challenges (
    id VARCHAR PRIMARY KEY,
    tenant_id VARCHAR NOT NULL,
    user_id VARCHAR NOT NULL,
    challenge VARCHAR NOT NULL,
    type VARCHAR NOT NULL,  -- 'registration' or 'authentication'
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (tenant_id) REFERENCES organizations(id)
);

CREATE TABLE backup_codes (
    id VARCHAR PRIMARY KEY,
    tenant_id VARCHAR NOT NULL,
    user_id VARCHAR NOT NULL,
    code_hash VARCHAR NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (tenant_id) REFERENCES organizations(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Step 3b: Register WebAuthn Routes in main.py

**File**: `app/main.py` (Modified)

```python
from app.security.webauthn.routes import router as webauthn_router

# Add after other routers
app.include_router(webauthn_router, prefix="/api/v1/auth/webauthn")
```

### Step 3c: Update WebAuthn Routes to Use Database

**File**: `app/security/webauthn/routes.py` (Modified)

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.security.webauthn.challenge import generate_challenge
from app.security.webauthn.attestation import verify_attestation
from app.db.models.webauthn import WebAuthnChallenge, WebAuthnCredential, BackupCode
from app.security.tenant_middleware import extract_tenant_context, TenantContext
import uuid
from datetime import datetime, timedelta

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register/start")
async def webauthn_register_start(
    email: str,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Start WebAuthn registration"""
    challenge = generate_challenge()
    
    # Store challenge in DB
    challenge_record = WebAuthnChallenge(
        id=str(uuid.uuid4()),
        tenant_id=tenant_context.tenant_id,
        user_id=email,  # temp: will be user_id after lookup
        challenge=challenge,
        type="registration",
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.add(challenge_record)
    db.commit()
    
    return {
        "challenge": challenge,
        "rp": {
            "name": "Meika",
            "id": "meika.local"  # Should be domain
        },
        "user": {
            "id": email,
            "name": email,
            "displayName": email
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},  # ES256
            {"type": "public-key", "alg": -257}  # RS256
        ],
        "timeout": 60000,
        "attestation": "direct"
    }

@router.post("/register/finish")
async def webauthn_register_finish(
    email: str,
    attestation: dict,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Finish WebAuthn registration"""
    # Verify attestation
    result = verify_attestation(attestation, "challenge_here")  # TODO: get challenge
    
    # Store credential
    cred = WebAuthnCredential(
        id=str(uuid.uuid4()),
        tenant_id=tenant_context.tenant_id,
        user_id=email,
        device_id=attestation.get("device_id"),
        credential_id=attestation.get("id"),
        public_key=result["public_key"],
        hardware_backed=result.get("hardware_backed", False),
        sign_count=0
    )
    db.add(cred)
    
    # Generate backup codes
    backup_codes = [str(uuid.uuid4())[:8].upper() for _ in range(10)]
    for code in backup_codes:
        backup = BackupCode(
            id=str(uuid.uuid4()),
            tenant_id=tenant_context.tenant_id,
            user_id=email,
            code_hash=code  # TODO: hash this
        )
        db.add(backup)
    
    db.commit()
    
    return {
        "success": True,
        "backup_codes": backup_codes  # Show once, user must save
    }

@router.post("/authenticate/start")
async def webauthn_authenticate_start(
    email: str,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Start WebAuthn authentication"""
    challenge = generate_challenge()
    
    challenge_record = WebAuthnChallenge(
        id=str(uuid.uuid4()),
        tenant_id=tenant_context.tenant_id,
        user_id=email,
        challenge=challenge,
        type="authentication",
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.add(challenge_record)
    db.commit()
    
    # Get user's credentials
    from app.db.models.user import User
    user = db.query(User).filter_by(email=email, tenant_id=tenant_context.tenant_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    credentials = db.query(WebAuthnCredential).filter_by(
        user_id=user.id,
        revoked=False
    ).all()
    
    return {
        "challenge": challenge,
        "allowCredentials": [
            {"type": "public-key", "id": cred.credential_id} 
            for cred in credentials
        ],
        "timeout": 60000,
        "userVerification": "preferred"
    }

@router.post("/authenticate/finish")
async def webauthn_authenticate_finish(
    email: str,
    assertion: dict,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Finish WebAuthn authentication"""
    from app.db.models.user import User
    from app.security.webauthn.assertion import verify_assertion
    
    user = db.query(User).filter_by(email=email, tenant_id=tenant_context.tenant_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    cred = db.query(WebAuthnCredential).filter_by(
        credential_id=assertion.get("id"),
        user_id=user.id
    ).first()
    if not cred:
        raise HTTPException(status_code=401, detail="Credential not found")
    
    # Verify assertion
    verify_assertion(assertion, cred)
    db.commit()
    
    # Issue token (call existing federation service)
    from app.security.federation.service import FederationService
    federation = FederationService(None, None)
    token = federation.issue_token(...)  # TODO: build context
    
    return {"token": token}
```

---

## 4. INVESTIGATION ACCESS WORKFLOW

### Step 4a: Database Schema

**File**: `migrations/006_add_investigation.sql`

```sql
CREATE TABLE investigation_requests (
    id VARCHAR PRIMARY KEY,
    tenant_id VARCHAR NOT NULL,
    user_id VARCHAR NOT NULL,
    incident_id VARCHAR NOT NULL,
    justification TEXT NOT NULL,
    scope TEXT,  -- JSON: which tables/date ranges
    requested_at TIMESTAMP DEFAULT NOW(),
    approved_by VARCHAR,
    approved_at TIMESTAMP,
    denied_by VARCHAR,
    denied_at TIMESTAMP,
    denial_reason TEXT,
    status VARCHAR DEFAULT 'pending',  -- pending, approved, denied
    FOREIGN KEY (tenant_id) REFERENCES organizations(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE investigation_grants (
    id VARCHAR PRIMARY KEY,
    tenant_id VARCHAR NOT NULL,
    request_id VARCHAR NOT NULL,
    user_id VARCHAR NOT NULL,
    incident_id VARCHAR NOT NULL,
    issued_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    max_queries INTEGER DEFAULT 1000,
    queries_used INTEGER DEFAULT 0,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES organizations(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (request_id) REFERENCES investigation_requests(id)
);

CREATE TABLE investigation_access_logs (
    id VARCHAR PRIMARY KEY,
    tenant_id VARCHAR NOT NULL,
    grant_id VARCHAR NOT NULL,
    query VARCHAR NOT NULL,
    results_returned INTEGER,
    accessed_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (tenant_id) REFERENCES organizations(id),
    FOREIGN KEY (grant_id) REFERENCES investigation_grants(id)
);
```

### Step 4b: API Endpoints

**File**: `app/api/investigation.py` (NEW FILE)

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timedelta
from app.db.session import SessionLocal
from app.security.tenant_middleware import extract_tenant_context, TenantContext
import uuid

router = APIRouter(prefix="/investigation-access", tags=["investigation"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class InvestigationAccessRequest(BaseModel):
    incident_id: str
    justification: str
    scope: dict  # {"tables": ["users", "audit_logs"], "date_range": "7d"}

class ApprovalRequest(BaseModel):
    expires_in_hours: int = 4
    max_queries: int = 1000

@router.post("/request")
async def request_investigation_access(
    req: InvestigationAccessRequest,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Request access for incident investigation"""
    from app.db.models.investigation import InvestigationRequest
    
    request_record = InvestigationRequest(
        id=str(uuid.uuid4()),
        tenant_id=tenant_context.tenant_id,
        user_id=tenant_context.user_id,
        incident_id=req.incident_id,
        justification=req.justification,
        scope=json.dumps(req.scope),
        status="pending"
    )
    db.add(request_record)
    db.commit()
    
    # TODO: Notify approvers (SOAR event)
    
    return {
        "request_id": request_record.id,
        "status": "pending",
        "created_at": request_record.requested_at
    }

@router.get("/pending")
async def list_pending_requests(
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """List pending requests for current user to approve"""
    from app.db.models.investigation import InvestigationRequest
    
    # TODO: Check if user has approver role
    requests = db.query(InvestigationRequest).filter(
        (InvestigationRequest.tenant_id == tenant_context.tenant_id) &
        (InvestigationRequest.status == "pending")
    ).all()
    
    return requests

@router.post("/{request_id}/approve")
async def approve_investigation(
    request_id: str,
    approval: ApprovalRequest,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Approve access request"""
    from app.db.models.investigation import (
        InvestigationRequest, InvestigationGrant
    )
    
    request = db.query(InvestigationRequest).filter_by(id=request_id).first()
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    
    # Issue grant
    grant = InvestigationGrant(
        id=str(uuid.uuid4()),
        tenant_id=request.tenant_id,
        request_id=request.id,
        user_id=request.user_id,
        incident_id=request.incident_id,
        expires_at=datetime.utcnow() + timedelta(hours=approval.expires_in_hours),
        max_queries=approval.max_queries
    )
    db.add(grant)
    
    request.status = "approved"
    request.approved_by = tenant_context.user_id
    request.approved_at = datetime.utcnow()
    
    db.commit()
    
    return {
        "grant_id": grant.id,
        "expires_at": grant.expires_at,
        "max_queries": grant.max_queries
    }

@router.post("/{request_id}/deny")
async def deny_investigation(
    request_id: str,
    reason: str,
    db: Session = Depends(get_db),
    tenant_context: TenantContext = Depends(extract_tenant_context)
):
    """Deny access request"""
    from app.db.models.investigation import InvestigationRequest
    
    request = db.query(InvestigationRequest).filter_by(id=request_id).first()
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    
    request.status = "denied"
    request.denied_by = tenant_context.user_id
    request.denied_at = datetime.utcnow()
    request.denial_reason = reason
    
    db.commit()
    
    return {"status": "denied"}
```

---

## 5. RATE LIMITING (Quick Win)

**File**: `app/middleware/rate_limit.py` (NEW FILE)

```python
from fastapi import Request, HTTPException
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = asyncio.Lock()
    
    async def check_rate_limit(
        self,
        key: str,
        max_requests: int = 5,
        window_seconds: int = 900  # 15 minutes
    ) -> bool:
        """
        Check if request is within rate limit.
        Returns True if allowed, False if rate limited.
        """
        async with self.lock:
            now = datetime.utcnow()
            window_start = now - timedelta(seconds=window_seconds)
            
            # Clean old requests
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if req_time > window_start
            ]
            
            # Check limit
            if len(self.requests[key]) >= max_requests:
                return False
            
            # Add current request
            self.requests[key].append(now)
            return True

rate_limiter = RateLimiter()

async def rate_limit_middleware(request: Request, call_next):
    """
    Apply rate limiting based on route and IP.
    """
    path = request.url.path
    ip = request.client.host if request.client else "unknown"
    
    # Route-specific limits
    limits = {
        "/api/v1/auth/login": (5, 900),  # 5 per 15 min
        "/api/v1/auth/register": (10, 3600),  # 10 per hour
        "/api/v1/grants/request": (10, 3600),  # 10 per hour
    }
    
    if path in limits:
        max_req, window = limits[path]
        key = f"{path}:{ip}"
        
        allowed = await rate_limiter.check_rate_limit(key, max_req, window)
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many requests")
    
    response = await call_next(request)
    
    # Add rate limit headers
    if path in limits:
        response.headers["X-RateLimit-Limit"] = str(limits[path][0])
        response.headers["X-RateLimit-Remaining"] = str(
            limits[path][0] - len(rate_limiter.requests[key])
        )
    
    return response
```

**File**: `app/main.py` (Add middleware)

```python
from app.middleware.rate_limit import rate_limit_middleware

app.middleware("http")(rate_limit_middleware)
```

---

## SUMMARY: Implementation Priority

| Task | Effort | Impact | Priority |
|------|--------|--------|----------|
| Multi-tenancy schema | 40h | 🔴 Blocking | 1 |
| Tenant middleware | 20h | 🔴 Blocking | 2 |
| Thread tenant through code | 100h | 🔴 Blocking | 3 |
| Admin API endpoints | 80h | 🔴 Blocking | 4 |
| Admin UI (React) | 100h | 🔴 Blocking | 5 |
| WebAuthn DB + routes | 40h | 🔴 Blocking | 6 |
| Investigation access API | 60h | 🟠 High | 7 |
| Rate limiting | 30h | 🟠 High | 8 |

**Total**: 470 hours / 6 weeks with 2 engineers

This gets you to MVP SaaS launch.
