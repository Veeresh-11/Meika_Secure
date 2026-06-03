# MEIKA ENGINEERING ROADMAP
## 90-Day Sprint: Competitive Parity + Differentiation

**Prepared for**: Engineering Leadership  
**Timeline**: May 20, 2026 → Aug 20, 2026  
**Goal**: Ship production-ready offering with competitive advantages

---

## SPRINT 1: CRITICAL FIXES (Days 1-14)

### P0.1: Post-Quantum Signatures Active
**File**: `app/security/federation/jwt_builder.py`  
**Effort**: 3-5 days  
**Blocker**: Cannot market to defense/regulated sectors without this

```python
# CURRENT (BROKEN)
signing_algorithm = "RS256"  # RSA only

# FIXED
if os.getenv("PQ_SIGNING_ENABLED", "true") == "true":
    # Production: ML-DSA signatures
    from cryptography.hazmat.primitives.asymmetric import ml_dsa
    signer = ml_dsa.MLDSAPrivateKey.from_private_bytes(key_material)
    signature = signer.sign(message)
    algorithm = "DILITHIUM-3"  # NIST standard post-quantum
else:
    # Fallback: RSA (for backward compat)
    signature = rsa_sign(message)
    algorithm = "RS256"

# In JWT header:
jwt_header = {
    "alg": algorithm,  # Could be "DILITHIUM-3" or "RS256"
    "typ": "JWT",
    "x5c": [...],  # Certificate chain
}
```

**Tests**:
- [ ] ML-DSA signature generated correctly
- [ ] Token with ML-DSA signature verifies
- [ ] Backward compat: fallback to RS256 works
- [ ] Policy control: `PQ_SIGNING_ENABLED=false` uses RS256
- [ ] Defense customer scenario: Okta can't do this, Meika ships it

**Acceptance**: Ship with PQ signing **active by default**, RS256 as fallback

---

### P0.2: Policy Rule Matcher Implementation
**File**: `app/security/policy/engine.py` line ~150  
**Effort**: 1 week  
**Blocker**: Entire policy system is broken (always returns True)

```python
# CURRENT (SECURITY HOLE)
def _matches(self, rule: PolicyRule, context: SecurityContext) -> bool:
    return True  # ← EVERYTHING ALLOWED

# FIXED
def _matches(self, rule: PolicyRule, context: SecurityContext) -> bool:
    """Evaluate policy rule conditions against context"""
    
    for condition in rule.conditions:
        if not self._evaluate_condition(condition, context):
            if rule.logic == "all":  # AND logic
                return False
        else:
            if rule.logic == "any":  # OR logic
                return True
    
    return rule.logic == "all"

def _evaluate_condition(
    self, 
    condition: PolicyCondition, 
    context: SecurityContext
) -> bool:
    """Evaluate single condition"""
    
    if condition.type == "user":
        return context.principal_id == condition.value
    
    elif condition.type == "group":
        return context.principal_id in self.group_service.get_members(condition.value)
    
    elif condition.type == "device_posture":
        actual_level = self._posture_to_level(context.device.posture)
        required_level = self._posture_to_level(condition.required_level)
        return actual_level >= required_level  # >= because higher is better
    
    elif condition.type == "mfa_age_hours":
        age_hours = (now() - context.device.last_mfa_time).total_seconds() / 3600
        return age_hours <= condition.max_hours
    
    elif condition.type == "time_of_day":
        current_hour = context.request_time.hour
        start, end = condition.range  # e.g., (9, 18)
        return start <= current_hour < end
    
    elif condition.type == "location":
        return context.request_geo in condition.allowed_geos
    
    else:
        raise ValueError(f"Unknown condition: {condition.type}")
```

**Tests**:
- [ ] AND logic works (all conditions must pass)
- [ ] OR logic works (any condition can pass)
- [ ] User matching works
- [ ] Group matching works
- [ ] Device posture correctly blocks low-trust device
- [ ] MFA age gates access properly
- [ ] Time-of-day works
- [ ] Location works
- [ ] Integration: Grant scoping respects policy

**Acceptance**: DENY policy actually denies, ALLOW policy actually evaluates conditions

---

### P0.3: Deprecate Password Authentication
**Files**: `app/api/auth.py`, `app/main.py`  
**Effort**: 3 days  
**Blocker**: Violates architectural principle "no passwords"

```python
# app/api/auth.py

@router.post("/login", deprecated=True, tags=["Deprecated"])
async def login_deprecated(request: LoginRequest):
    """
    DEPRECATED: Use POST /webauthn/authenticate instead
    
    This endpoint is provided for backward compatibility only.
    All future authentication must use WebAuthn / passwordless.
    """
    
    logger.warning(f"DEPRECATED: Password login used by {request.email}")
    
    # Still works, but log the deprecation event
    evidence = await evidence_writer.write_deprecation_event(
        principal_id=request.email,
        event="password_auth_used",
        severity="WARNING",
        detail="POST /login is deprecated. Use WebAuthn."
    )
    
    # Process normally
    user = await authenticate_user(request.email, request.password)
    context = SecurityContext(principal_id=user.id, ...)
    grant = await grants_service.create_grant(context)
    
    return TokenResponse(...)

# app/api/webauthn.py

@router.post("/webauthn/authenticate")
async def webauthn_authenticate(
    credential_id: str,
    assertion_json: str,  # Serialized WebAuthn assertion
):
    """
    List 1: Authenticate with WebAuthn credential
    
    This is the ONLY supported authentication method for new implementations.
    Password login is available for backward compatibility only.
    """
    
    # Verify WebAuthn assertion
    assertion = WebAuthnAssertion.from_json(assertion_json)
    credential = await db.get_webauthn_credential(credential_id)
    
    # Validate signature
    try:
        credential.verify_assertion(assertion)
    except InvalidSignature:
        raise AuthenticationFailedError()
    
    # Grant created (no session)
    user = await db.get_user(credential.user_id)
    context = SecurityContext(principal_id=user.id, device_id=credential.device_id)
    grant = await grants_service.create_grant(context)
    
    return AuthenticationResponse(grant_token=grant.token, ...)
```

**Configuration**:
```yaml
# config.yaml
auth:
  passwordless_only: false  # Allow both for compatibility
  password_deprecated: true  # Log deprecation warnings
  
# Future (Q3 2026):
# auth:
#   passwordless_only: true  # BLOCK password auth entirely
```

**Tests**:
- [ ] Password login still works but logs deprecation
- [ ] WebAuthn login creates grant (no session)
- [ ] Deprecation events appear in evidence log
- [ ] Dashboard shows login method breakdown

---

## SPRINT 2: PRODUCTION READINESS (Days 15-35)

### P1.1: WebAuthn Authentication (Complete Implementation)
**Files**: `app/api/webauthn.py`, `app/security/webauthn/*`  
**Effort**: 3-4 weeks  
**Blocker**: Can't ship to enterprise without passwordless

#### Phase 1: Registration (Week 1)

```python
# POST /api/v1/auth/webauthn/register/start

async def webauthn_register_start(
    user_id: str,
    device_name: str,  # "Alice's MacBook"
):
    """Initiate WebAuthn credential registration"""
    
    # Generate challenge
    challenge = secrets.token_urlsafe(32)
    
    # Store registration session
    session = WebAuthnRegistrationSession(
        user_id=user_id,
        challenge=challenge,
        device_name=device_name,
        created_at=now(),
        expires_at=now() + timedelta(minutes=10),
    )
    await db.add(session)
    
    # Return registration options
    return {
        "challenge": challenge,
        "rp": {
            "id": "meika.example.com",
            "name": "Meika Authenticator"
        },
        "user": {
            "id": user_id,
            "name": user_id,
            "displayName": await db.get_user(user_id).full_name
        },
        "timeout": 60000,
        "attestation": "direct",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",  # Preferred: platform (Windows Hello, Touch ID)
            "userVerification": "required",
        },
        "pubKeyCredParams": [
            {"alg": -7, "type": "public-key"}  # ES256
        ]
    }

# POST /api/v1/auth/webauthn/register/complete

async def webauthn_register_complete(
    user_id: str,
    credential_response: dict,  # Client response with attestation
):
    """Complete WebAuthn credential registration"""
    
    # Get registration session
    session = await db.get_webauthn_registration_session(user_id)
    if not session or session.expires_at < now():
        raise RegistrationExpiredError()
    
    # Verify attestation
    try:
        credential_data = verify_registration_response(
            credential=credential_response,
            expected_challenge=session.challenge,
            expected_origin="https://meika.example.com",
            expected_rp_id="meika.example.com",
        )
    except VerificationError as e:
        logger.warning(f"WebAuthn attestation failed for {user_id}: {e}")
        raise RegistrationFailedError()
    
    # Store credential
    credential = WebAuthnCredential(
        user_id=user_id,
        device_id=credential_data.credential_id,
        device_name=session.device_name,
        public_key=credential_data.credential_public_key.export(),
        counter=credential_data.sign_count,
        created_at=now(),
    )
    await db.add(credential)
    
    # Write evidence
    await evidence_writer.write(
        principal_id=user_id,
        action="webauthn_credential_registered",
        resource=f"credential:{credential_data.credential_id}",
        result="success",
    )
    
    return {"credential_id": credential_data.credential_id}
```

#### Phase 2: Authentication (Week 1-2)

```python
# POST /api/v1/auth/webauthn/authenticate/start

async def webauthn_authenticate_start(
    credential_id: str,
):
    """Initiate WebAuthn authentication"""
    
    # Get credential to find user
    credential = await db.get_webauthn_credential(credential_id)
    if not credential:
        raise CredentialNotFoundError()
    
    # Generate challenge
    challenge = secrets.token_urlsafe(32)
    
    # Store auth session
    session = WebAuthnAuthenticationSession(
        credential_id=credential_id,
        user_id=credential.user_id,
        challenge=challenge,
        created_at=now(),
        expires_at=now() + timedelta(minutes=5),
    )
    await db.add(session)
    
    return {
        "challenge": challenge,
        "timeout": 60000,
        "rpId": "meika.example.com",
        "allowCredentials": [
            {
                "id": credential.device_id,
                "type": "public-key"
            }
        ]
    }

# POST /api/v1/auth/webauthn/authenticate/complete

async def webauthn_authenticate_complete(
    credential_id: str,
    assertion_response: dict,  # Client response with assertion
):
    """Complete WebAuthn authentication"""
    
    # Get auth session
    session = await db.get_webauthn_authentication_session(credential_id)
    if not session or session.expires_at < now():
        raise AuthenticationExpiredError()
    
    credential = await db.get_webauthn_credential(credential_id)
    
    # Verify assertion
    try:
        verify_authentication_response(
            credential=assertion_response,
            expected_challenge=session.challenge,
            expected_origin="https://meika.example.com",
            expected_rp_id="meika.example.com",
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.counter,
        )
    except VerificationError as e:
        logger.warning(f"WebAuthn assertion failed: {e}")
        
        # Write failed attempt
        await evidence_writer.write(
            principal_id=credential.user_id,
            action="webauthn_authentication_failed",
            resource=f"credential:{credential_id}",
            result="failure",
            reason=str(e),
        )
        
        raise AuthenticationFailedError()
    
    # Create JIT grant (no session)
    context = SecurityContext(
        principal_id=credential.user_id,
        device_id=credential.device_id,
        authentication_method="webauthn",
        authenticated=True,
    )
    
    grant = await grants_service.create_grant(
        context=context,
        ttl_minutes=60,
        scope=["api", "admin"],
    )
    
    # Write success
    await evidence_writer.write(
        principal_id=credential.user_id,
        action="webauthn_authentication_success",
        resource=f"credential:{credential_id}",
        result="success",
        grant_id=grant.id,
    )
    
    return {
        "grant_id": grant.id,
        "access_token": grant.create_jwt(),
        "token_type": "Bearer",
        "expires_in": grant.ttl_seconds,
    }
```

**Acceptance Criteria**:
- [ ] Register security KEY works
- [ ] Register Windows Hello works
- [ ] Register Touch ID works
- [ ] Login returns grant token (not session)
- [ ] FIDO2 compliance tests pass
- [ ] Multi-device support works
- [ ] Passwordless-only mode can be enabled
- [ ] Evidence log shows all auth events

---

### P1.2: OIDC/OAuth2 Provider Server
**Files**: `app/api/oauth2.py`, `app/security/federation/oidc.py`  
**Effort**: 2-3 weeks  
**Blocker**: Can't work downstream with SaaS apps

```python
# GET /.well-known/openid-configuration
# (Standard OIDC metadata endpoint)

async def openid_configuration():
    return {
        "issuer": "https://meika.example.com",
        "authorization_endpoint": "https://meika.example.com/oauth2/authorize",
        "token_endpoint": "https://meika.example.com/oauth2/token",
        "userinfo_endpoint": "https://meika.example.com/oauth2/userinfo",
        "jwks_uri": "https://meika.example.com/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email", "device"],  # device = unique to Meika
        "response_types_supported": ["code", "id_token", "token"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "subject_types_supported": ["public"],
    }

# POST /oauth2/authorize
# (Authorization code flow)

async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str,  # "code"
    scope: str,  # "openid profile email"
    state: str,
):
    """OAuth2 authorization endpoint"""
    
    # Validate request
    client = await db.get_oauth2_client(client_id)
    if not client:
        raise UnknownClientError()
    
    if redirect_uri not in client.allowed_redirect_uris:
        raise InvalidRedirectURIError()
    
    # TODO: Render user consent screen if needed
    # For MVP, auto-approve if user authenticated + client trusted
    
    # Check if user is authenticated (already has grant)
    grant = get_current_grant_from_header()  # From Authorization header
    if not grant or grant.is_expired():
        # Redirect to login
        return RedirectResponse(
            url=f"/api/v1/auth/webauthn/authenticate/start?client_id={client_id}&state={state}",
            status_code=307
        )
    
    # Generate authorization code
    auth_code = AuthorizationCode(
        client_id=client_id,
        user_id=grant.principal_id,
        redirect_uri=redirect_uri,
        scope=scope,
        code=secrets.token_urlsafe(32),
        created_at=now(),
        expires_at=now() + timedelta(minutes=10),
    )
    await db.add(auth_code)
    
    # Redirect with code
    return RedirectResponse(
        url=f"{redirect_uri}?code={auth_code.code}&state={state}",
        status_code=307
    )

# POST /oauth2/token
# (Code exchanged for tokens)

async def token(
    grant_type: str,  # "authorization_code"
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
):
    """OAuth2 token endpoint"""
    
    # Validate client
    client = await db.get_oauth2_client(client_id)
    if not client or client.secret != client_secret:
        raise InvalidClientError()
    
    # Get authorization code
    auth_code = await db.get_authorization_code(code)
    if not auth_code or auth_code.is_expired():
        raise InvalidGrantError()
    
    # Verify code belongs to client and redirect_uri
    if auth_code.client_id != client_id or auth_code.redirect_uri != redirect_uri:
        raise InvalidGrantError()
    
    # Get user (to include in ID token)
    user = await db.get_user(auth_code.user_id)
    
    # Get device (to include device posture in token - UNIQUE TO MEIKA)
    device = await db.get_device(auth_code.device_id)
    
    # Create ID token (contains user info)
    id_token_payload = {
        "iss": "https://meika.example.com",
        "sub": user.id,
        "aud": client_id,
        "iat": int(now().timestamp()),
        "exp": int((now() + timedelta(hours=1)).timestamp()),
        "name": user.full_name,
        "email": user.email,
        "email_verified": True,
        # UNIQUE TO MEIKA: device posture in token
        "device_posture": device.posture,
        "device_trusted": device.is_trusted,
    }
    
    id_token_jwt = create_jwt(
        payload=id_token_payload,
        private_key=os.getenv("JWT_SIGNING_KEY"),
        algorithm="DILITHIUM-3" if PQ_ENABLED else "RS256",
    )
    
    # Create access token
    access_token_jwt = create_jwt(
        payload={
            "iss": "https://meika.example.com",
            "sub": user.id,
            "aud": client_id,
            "scope": auth_code.scope,
            "iat": int(now().timestamp()),
            "exp": int((now() + timedelta(hours=1)).timestamp()),
        },
        private_key=os.getenv("JWT_SIGNING_KEY"),
        algorithm="DILITHIUM-3" if PQ_ENABLED else "RS256",
    )
    
    # Delete authorization code (one-time use)
    await db.delete(auth_code)
    
    return {
        "access_token": access_token_jwt,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token_jwt,
    }

# GET /oauth2/userinfo
# (Get authenticated user info)

async def userinfo(
    authorization: str  # Bearer token
):
    """OAuth2 userinfo endpoint"""
    
    # Verify access token
    access_token = authorization.replace("Bearer ", "")
    payload = verify_jwt(access_token)
    
    user = await db.get_user(payload["sub"])
    device = await db.get_device(payload.get("device_id"))
    
    return {
        "sub": user.id,
        "name": user.full_name,
        "email": user.email,
        "device_posture": device.posture if device else None,
    }

# GET /.well-known/jwks.json
# (Public keys for token verification)

async def jwks():
    """OIDC JWKS endpoint"""
    
    keys = []
    
    # Post-quantum key (if enabled)
    if PQ_ENABLED:
        keys.append({
            "kty": "OKP",
            "crv": "ML-DSA",
            "alg": "DILITHIUM-3",
            "use": "sig",
            "kid": "pq-2026-01",
            "x": base64.urlsafe_b64encode(pq_public_key).decode(),
        })
    
    # RSA key (always present for backward compat)
    keys.append({
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": "rsa-2026-01",
        "n": base64.urlsafe_b64encode(rsa_modulus).decode(),
        "e": "AQAB",
    })
    
    return {"keys": keys}
```

**Acceptance Criteria**:
- [ ] OIDC discovery endpoint works
- [ ] OAuth2 authorization code flow works
- [ ] Token endpoint issues ID + access tokens
- [ ] Userinfo endpoint works
- [ ] JWKS endpoint exposes keys
- [ ] Device posture included in ID token (differentiator)
- [ ] Post-quantum keys in JWKS (differentiator)
- [ ] Okta client can be swapped for Meika client (backward compat)

---

## SPRINT 3: COMPETITIVE DIFFERENTIATION (Days 36-60)

### P2.1: Hardware Key Support
**Effort**: 3 weeks  
**Differentiator**: "More secure than Okta"

- FIDO2 security keys (YubiKey, Titan)
- Hardware-backed key storage
- Attestation verification

---

### P2.2: Kubernetes RBAC Integration
**Effort**: 2 weeks  
**Differentiator**: "Cloud-native-first"

- Kubernetes ServiceAccount binding
- Pod identity authentication
- RBAC proof-of-concept

---

### P2.3: Admin Dashboard V1
**Effort**: 3-4 weeks  
**Business requirement**: Enterprises need visibility

- User management
- Device registry
- Policy list + edit
- Grant audit trail
- Real-time decision log

---

## SUCCESS METRICS

### By End of Sprint 1 (Aug 6)
- [ ] Post-quantum signatures shipping
- [ ] Policy engine working
- [ ] WebAuthn beta
- [ ] OIDC beta
- [ ] 1-2 pilot customers onboarding

### By End of Sprint 2 (Aug 20)
- [ ] WebAuthn production (all platforms)
- [ ] OAuth2 production
- [ ] 3-5 pilot customers live
- [ ] Reference architecture (Kubernetes)
- [ ] Case study: DevSecOps team

### By End of Sprint 3 (Sept 2)
- [ ] Hardware key support
- [ ] Admin dashboard v1
- [ ] 10-15 pilot customers
- [ ] Security-first vertical (finance or defense) initial traction
- [ ] $100k ARR pipeline

---

## RISK MITIGATION

### Risk: WebAuthn complexity
- **Mitigation**: Use webauthn-py library, extensive test coverage
- **Fallback**: Passwordless beta only for early adopters

### Risk: OIDC spec compliance
- **Mitigation**: Use python-oauth2 library, test with real clients (Okta, Auth0)
- **Fallback**: MVP supports core flows only, extensions later

### Risk: Post-quantum transition complexity
- **Mitigation**: Hybrid mode (PQ + RSA) from day one
- **Fallback**: Can revert to RS256 if PQ adoption slower than expected

---

## CONCLUSION

This roadmap gets Meika from "architecture prototype" to "credible production alternative" in 90 days.

The key is to ship your unfair advantages (PQ, automatic containment, evidence-first) while building table-stakes features (WebAuthn, OIDC, dashboard).

You're not trying to beat Okta at their game. You're playing a different game where Zero Trust actually matters.

Now ship it.
