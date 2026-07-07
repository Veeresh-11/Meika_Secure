CREATE TABLE identity.grants
(
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL
        REFERENCES identity.users(id),

    session_id UUID NOT NULL
        REFERENCES identity.sessions(id),

    credential_id UUID NOT NULL
        REFERENCES identity.webauthn_credentials(id),

    grant_type TEXT NOT NULL,

    risk_level TEXT NOT NULL DEFAULT 'LOW',

    guardian_state TEXT NOT NULL DEFAULT 'UNMONITORED',

    jwt_id TEXT NOT NULL UNIQUE,

    device_id UUID,

    ip_address TEXT,

    issued_at TIMESTAMP NOT NULL,

    expires_at TIMESTAMP NOT NULL,

    revoked BOOLEAN NOT NULL DEFAULT FALSE,

    revoked_at TIMESTAMP,

    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_grants_user
ON identity.grants(user_id);

CREATE INDEX idx_grants_session
ON identity.grants(session_id);

CREATE INDEX idx_grants_jti
ON identity.grants(jwt_id);

CREATE INDEX idx_grants_active
ON identity.grants(revoked, expires_at);