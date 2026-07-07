ALTER TABLE identity.sessions
ADD COLUMN grant_type TEXT NOT NULL DEFAULT 'access';

ALTER TABLE identity.sessions
ADD COLUMN jwt_id UUID UNIQUE;

UPDATE identity.sessions
SET jwt_id = gen_random_uuid()
WHERE jwt_id IS NULL;

ALTER TABLE identity.sessions
ALTER COLUMN jwt_id SET NOT NULL;

ALTER TABLE identity.sessions
ADD COLUMN created_by TEXT NOT NULL DEFAULT 'webauthn';