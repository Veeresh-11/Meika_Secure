CREATE TABLE identity.webauthn_challenges
(
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL
        REFERENCES identity.users(id),

    challenge TEXT NOT NULL UNIQUE,

    purpose TEXT NOT NULL,

    used BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMP NOT NULL DEFAULT now(),

    expires_at TIMESTAMP NOT NULL
);

CREATE TABLE identity.webauthn_credentials
(
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL
        REFERENCES identity.users(id),

    credential_id TEXT UNIQUE NOT NULL,

    public_key TEXT NOT NULL,

    sign_count INTEGER NOT NULL DEFAULT 0,

    hardware_backed BOOLEAN DEFAULT TRUE,

    attestation_verified BOOLEAN DEFAULT TRUE,

    attestation_type TEXT NOT NULL,

    revoked BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP DEFAULT now(),

    last_used_at TIMESTAMP DEFAULT now()
);