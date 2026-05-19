# Okta Integration Analysis & Implementation Roadmap

**Prepared**: May 19, 2026  
**Status**: ✅ All tests passing (292 passed, 2 skipped)

---

## Executive Summary

Meika Secure ID has a **foundation for external identity integration** via OIDC, but lacks **complete Okta-specific integration**. The system currently:

✅ **Has**:
- OIDC discovery document
- External identity assertion schema
- Federation service with EdDSA signing
- Principle: "Authenticate users, don't grant access"
- Post-authentication zero-trust evaluation

❌ **Missing**:
- Okta OAuth 2.0 Authorization Code flow implementation
- Okta JWKS validation & key rotation
- PKCE support (security best practice)  
- Refresh token handling
- Scope-to-permission mapping
- Okta API integration for user provisioning
- Multi-tenant Okta org support

---

## Current Architecture vs. Okta Requirements

### Meika's Current Flow

```
User → POST /api/v1/auth/login
        (email, password, device_id, device_signals)
        ↓
        Device Context Evaluation
        ↓
        Security Pipeline (Zero Trust)
        ↓
        FederationService issues EdDSA JWT
        ↓
        Token returned to client
```

**Problem**: This is a **direct authentication flow**, not an **external IdP flow**.

### Okta's Authorization Code Flow (Recommended)

```
User → Browser redirects to 
        https://yourOktaDomain/oauth2/v1/authorize?
        client_id=...&response_type=code&
        scope=openid&redirect_uri=...
        ↓
        Okta Sign-In Page (MFA, passwordless, etc.)
        ↓
        User authenticates & provides consent
        ↓
        Okta returns authorization code to callback URI
        ↓
        Backend exchanges code + client_secret 
        for access_token + id_token + refresh_token
        ↓
        Backend validates tokens via JWKS
        ↓
        Backend creates local session
```

---

## Comparison Matrix

| Aspect | Meika Current | Okta Standard | Gap |
|--------|---------------|--------------|----|
| **Auth Method** | Direct password | OAuth 2.0 + MFA | Need OAuth adapter |
| **Token Signing** | EdDSA (post-quantum) | RS256 (RSA) | Need hybrid support |
| **Token Validation** | In-kernel | JWKS + key rotation | Need JWKS client |
| **Refresh Tokens** | Not implemented | Yes, 90-day default | Need refresh flow |
| **PKCE** | Not implemented | Recommended for SPAs | Need PKCE support |
| **Scopes** | Custom (meika-specific) | Standard OIDC scopes | Need scope mapping |
| **MFA** | Device posture signals | Okta MFA (app, SMS, TOTP) | Need MFA orchestration |
| **User Provisioning** | Manual or AuthService | Okta API | Need provisioning integration |
| **Multi-tenancy** | Single org | Per-org auth servers | Need org isolation |
| **Key Rotation** | Manual | Automatic (45-90 days) | Need rotation handler |

---

## What Needs to Be Done

### Phase 1: OAuth 2.0 Authorization Code Flow (HIGH PRIORITY)

#### 1.1 Add OAuth Endpoints
**Files to create**:
- `app/api/oauth.py` - OAuth 2.0 endpoints
- `app/security/federation/okta_client.py` - Okta client library
- `app/security/federation/pkce.py` - PKCE support

**Endpoints**:
```python
# Initiate OAuth flow
GET /api/v1/oauth/authorize
    Parameters: client_id, redirect_uri, scope, state, code_challenge, code_challenge_method

# OAuth callback (handles Okta redirect)
GET /api/v1/oauth/callback
    Parameters: code, state

# Token exchange endpoint
POST /api/v1/oauth/token
    Body: {code, client_id, client_secret, redirect_uri, code_verifier}
```

#### 1.2 Implement PKCE
**File**: `app/security/federation/pkce.py`
```python
class PKCEGenerator:
    def generate_code_verifier() -> str
    def generate_code_challenge(verifier: str) -> tuple[str, str]
    def verify_challenge(verifier: str, challenge: str) -> bool
```

**Why**: Browser-based apps can't securely store client_secret. PKCE replaces it with a verifier.

#### 1.3 Create Okta Client Adapter
**File**: `app/security/federation/okta_client.py`

```python
class OktaClient:
    def __init__(self, domain: str, client_id: str, client_secret: str):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.jwks_cache = JWKSCache()
    
    def get_authorization_url(
        self, 
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str
    ) -> str
    
    def exchange_code_for_tokens(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str
    ) -> dict  # {access_token, id_token, refresh_token, expires_in}
    
    def get_userinfo(self, access_token: str) -> dict
    
    def validate_id_token(self, id_token: str) -> dict  # decoded token
```

#### 1.4 JWKS Fetching & Caching
**File**: `app/security/federation/jwks.py`

```python
class JWKSCache:
    """
    Per Okta best practices:
    - Cache keys regularly (e.g., daily)
    - Validate just-in-time if kid not in cache
    - Refresh on validation failure
    """
    def get_jwks(self) -> list[dict]
    def get_key_by_kid(self, kid: str) -> dict
    def refresh(self) -> None
    def is_stale(self) -> bool
```

**Key Rotation Strategy**:
```
1. Background job: Fetch JWKS daily
2. JIT validation: On key miss, fetch fresh JWKS
3. Exponential backoff: If fetch fails
4. TTL: Cache for 24 hours or on key miss
```

---

### Phase 2: External Identity Assertion Integration (MEDIUM PRIORITY)

#### 2.1 Map Okta Claims to Meika AssertionContext
**File**: `app/security/federation/okta_assertion.py`

```python
def okta_id_token_to_assertion(id_token: dict) -> ExternalIdentityAssertion:
    """
    Map Okta ID token claims to Meika ExternalIdentityAssertion.
    
    Okta claims → Meika fields:
    - iss → issuer
    - sub → subject
    - auth_time → auth_time
    - amr[0] → auth_method (map: "pwd" → "password", ["oka"] → "okta_mfa")
    """
    return ExternalIdentityAssertion(
        issuer=id_token["iss"],
        subject=id_token["sub"],
        auth_time=datetime.fromtimestamp(id_token["auth_time"]),
        auth_method=map_amr_to_method(id_token.get("amr", [])),
        assertion_id=id_token["jti"],
        issued_at=datetime.fromtimestamp(id_token["iat"]),
        expires_at=datetime.fromtimestamp(id_token["exp"]),
    )
```

#### 2.2 Okta MFA Method Mapping
**File**: `app/security/federation/okta_mfa_mapping.py`

**Map Okta `amr` (Authentication Methods Reference) to Meika levels**:
```
Okta amr values          →  Meika trust level
═══════════════════════════════════════════════
["pwd"]                  →  "password_only" (medium)
["pwd", "mfa"]           →  "mfa" (high)
["otp"]                  →  "otp" (medium)
["mfa"]                  →  "okta_adaptive_mfa" (high)
["okta"]                 →  "okta_native_sso" (veryhigh)
["swk"]                  →  "software_key" (medium)
["hwk"]                  →  "hardware_key" (veryhigh)
```

---

### Phase 3: Refresh Token Handling (MEDIUM PRIORITY)

#### 3.1 Refresh Token Storage
**File Migration**: Add to `migrations/003_okta_refresh_tokens.sql`

```sql
CREATE TABLE okta_refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    refresh_token BYTEA NOT NULL,  -- encrypted
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    INDEX(user_id, expires_at)
);
```

#### 3.2 Silently Refresh Access Tokens
**File**: `app/security/federation/refresh_service.py`

```python
class RefreshService:
    async def refresh_access_token(
        self, 
        user_id: str, 
        refresh_token: str
    ) -> dict:  # {new_access_token, new_refresh_token, expires_in}
        """Call Okta /token endpoint with grant_type=refresh_token"""
```

**When to refresh**:
- Before token expires (e.g., 5 min TTL warning)
- On demand if validation fails
- Never pass expired token to resource

---

### Phase 4: Multi-Tenant Okta Support (LOWER PRIORITY)

#### 4.1 Okta Organization Mapping
**File**: `app/security/federation/okta_org_registry.py`

```python
class OktaOrgRegistry:
    """
    Store per-organization Okta credentials.
    
    Use case: ISV platform with customer Okta orgs
    """
    def register_okta_org(
        self,
        org_id: str,
        okta_domain: str,
        client_id: str,
        client_secret: str
    )
    
    def get_okta_client(self, org_id: str) -> OktaClient
```

#### 4.2 Dynamic Authorization Server Selection
```python
# In oauth.py
client = okta_registry.get_okta_client(org_id)
auth_url = client.get_authorization_url(...)
```

---

### Phase 5: Scope-to-Permission Mapping (MEDIUM PRIORITY)

#### 5.1 Okta Scope → Meika Intent Mapping
**File**: `app/security/federation/scope_mapping.py`

```python
OKTA_SCOPE_MAPPING = {
    "openid": MeikaIntent.USER_IDENTITY,
    "profile": MeikaIntent.USER_PROFILE,
    "email": MeikaIntent.USER_EMAIL,
    "offline_access": MeikaIntent.REFRESH_TOKEN_GRANT,
    
    # Custom scopes
    "meika:device_trust": MeikaIntent.DEVICE_TRUST_CHECK,
    "meika:jit_elevation": MeikaIntent.JIT_ELEVATION,
}

def scope_string_to_intents(scope: str) -> list[MeikaIntent]:
    """Parse scope string into Meika intent list"""
```

---

### Phase 6: Test Coverage & Documentation (HIGH PRIORITY)

#### 6.1 Integration Tests
**File**: `app/security/test_okta_integration.py`

```python
def test_okta_authorization_code_flow():
    """1. Get auth code"""
    """2. Exchange code for tokens"""
    """3. Validate ID token"""
    """4. Map to external assertion"""
    """5. Run zero-trust policy"""

def test_okta_refresh_token_flow():
    """1. Refresh access token"""
    """2. Validate new access token"""

def test_okta_jwks_key_rotation():
    """1. Cache initial JWKS"""
    """2. Rotate keys externally"""
    """3. JIT fetch detects new key"""
    """4. Old kid returns 401"""

def test_okta_mfa_method_mapping():
    """Verify amr → trust_level mapping"""
```

#### 6.2 Configuration
**File**: `.env.okta.example`

```env
# Okta Configuration
OKTA_DOMAIN=dev-12345678.okta.com
OKTA_CLIENT_ID=0oabucvyc38HLL1ef0h7
OKTA_CLIENT_SECRET=xxxxx_keep_secret_xxxxx
OKTA_REDIRECT_URI=https://yourapp.example.com/api/v1/oauth/callback

# Optional: Multi-tenant mode
OKTA_ORG_REGISTRY_ENABLED=false
```

#### 6.3 Documentation
**File**: `docs/okta-setup.md`
- Step-by-step Okta admin console setup
- Authorization server creation
- Scope definition
- Client app registration
- Custom claims configuration

---

## Implementation Priority & Timeline

| Phase | Priority | Est. Effort | Tasks | Risk |
|-------|----------|------------|-------|------|
| 1 | **HIGH** | 3-4 weeks | OAuth endpoints, PKCE, JWKS | HIGH (core) |
| 2 | **HIGH** | 1-2 weeks | Assertion mapping, MFA | MEDIUM |
| 3 | **MEDIUM** | 1 week | Refresh tokens | LOW |
| 4 | **LOWER** | 2 weeks | Multi-tenant | MEDIUM |
| 5 | **MEDIUM** | 1 week | Scope mapping | LOW |
| 6 | **HIGH** | 2 weeks | Tests, docs | LOW |

**Total**: ~9-13 weeks for full Okta integration

---

## Critical Path (MVP - 4 weeks)

To get **Okta OAuth working** with Meika zero-trust in 4 weeks:

1. **Week 1**: OAuth 2.0 endpoints + PKCE
2. **Week 2**: JWKS validation + key rotation
3. **Week 3**: Assertions + zero-trust pipeline integration
4. **Week 4**: Integration tests + Okta setup guide

**Result**: Users login via Okta, get assertions, pass through Meika zero-trust.

---

## Security Considerations

### 1. Client Secret Protection
- **Store in**: Vault (HashiCorp) or secure config mgmt
- **Never**: Commit to git, log, send to client
- **Rotate**: Every 90 days

### 2. Authorization Code Security
- **PKCE required** for browser apps (no client_secret available)
- **State parameter** mandatory to prevent CSRF
- **Valid for** 300 seconds (Okta default)

### 3. Token Validation
- **Fetch JWKS daily** in background
- **JIT refresh** if kid not found
- **Validate `iss`, `aud`, `exp`** on every token
- **No token reuse** (check `jti` against revocation list)

### 4. Refresh Token Rotation
- **Encrypt at rest** (BYOE - bring your own encryption)
- **Rotate on use** (get new refresh token on refresh)
- **Invalidate** if not used for 7 days

### 5. Multi-Tenant Isolation
- **Validate org_id matches token issuer**
- **Partition refresh token storage** by org_id
- **Scope JWKS cache** per org

---

## Testing Checklist Before Production

- [ ] Authorization code generation (`state`, `code_challenge`)
- [ ] Code exchange with PKCE verification
- [ ] ID token validation against live JWKS
- [ ] JWKS cache refresh on key rotation
- [ ] Refresh token exchange (new tokens issued)
- [ ] Token expiration handling
- [ ] Invalid amr → proper trust level mapping
- [ ] Assertion integration with zero-trust pipeline
- [ ] Multi-tenant org isolation
- [ ] User provisioning (if using Okta API)
- [ ] Email verification flow
- [ ] MFA enforcement (if configured in policy)
- [ ] Rate limiting on /oauth/token (prevent brute force)

---

## References

- [Okta OIDC & OAuth 2.0 Overview](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview/)
- [Okta Authorization Code Flow](https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html)
- [JWT Best Practices RFC 8725](https://tools.ietf.org/html/rfc8725)

---

## Questions & Next Steps

1. **Should we use PKCE** even for confidential backends?
   - **Yes** (defense in depth)

2. **Should we support both Okta + local auth?**
   - **Yes** (dual-path with org-level toggle)

3. **When to require MFA?**
   - **Configurable per policy** (sensitive operations)

4. **Should we support passwordless (WebAuthn)?**
   - **Yes** but secondary (Okta handles primary auth)
