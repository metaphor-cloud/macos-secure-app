-- App Attest enrolment: one row per key a signed-in person enrolled.
-- key_id is Apple's key id (base64 SHA-256 of the public key) and the primary
-- key, so one key can never belong to two people. sub is the identity
-- provider subject the key is bound to; the gate admits a request only when
-- the bearer token's sub is this one. counter is the highest assertion
-- counter accepted, bumped with a conditional UPDATE so concurrent copies of
-- one assertion cannot both pass. A key is active while revoked_at is NULL.
-- There is no pending state: enrolment is automatic for someone who signs in
-- through SSO with MFA.
CREATE TABLE app_keys (
  key_id TEXT PRIMARY KEY,
  sub TEXT NOT NULL,
  -- At enrolment, for the device list and the audit trail.
  email TEXT NOT NULL,
  -- Team ID, a period, and the signing identifier: the string whose SHA-256
  -- is the RP ID hash.
  app_id TEXT NOT NULL,
  device_label TEXT NOT NULL CHECK (length(device_label) BETWEEN 1 AND 64),
  -- The credential certificate's SubjectPublicKeyInfo, base64 DER.
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  -- From the attestation's AAGUID.
  environment TEXT NOT NULL CHECK (environment IN ('production', 'development')),
  -- apple_validation_category_01 and apple_bundle_version_01, NULL when the
  -- attestation carried none.
  validation_category INTEGER,
  bundle_version TEXT,
  -- Apple's receipt from the attestation, base64. Stored, not verified.
  receipt TEXT,
  -- MFA evidence from the ID token at enrolment. mfa_required is whether the
  -- Worker demanded it (ATTEST_MFA); acr, amr (JSON array) and auth_time are
  -- what the token said, NULL when it said nothing.
  mfa_required INTEGER NOT NULL CHECK (mfa_required IN (0, 1)),
  mfa_acr TEXT,
  mfa_amr TEXT,
  mfa_auth_time INTEGER,
  -- The session challenge the next signed request must carry, and the one
  -- before it. Epoch milliseconds. Kept in D1 rather than KV so a rotation is
  -- seen at once everywhere.
  session_challenge TEXT,
  session_challenge_expires_at INTEGER,
  previous_session_challenge TEXT,
  previous_session_challenge_expires_at INTEGER,
  enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT,
  revoked_reason TEXT
);
CREATE INDEX app_keys_sub ON app_keys (sub);

-- Single-use enrolment challenges, bound to the person who asked. Consumed
-- with DELETE ... RETURNING. expires_at is epoch milliseconds.
CREATE TABLE attest_challenges (
  challenge TEXT PRIMARY KEY,
  sub TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX attest_challenges_expires_at ON attest_challenges (expires_at);

-- Append-only trail of enrolments, revocations, refused enrolments and
-- counter races. Never holds attestation, assertion, receipt or token bytes;
-- key_ref is the first 12 characters of the key id. Per-request refusals by
-- the gate are structured log lines, not rows, so refused traffic cannot turn
-- into D1 writes.
CREATE TABLE attest_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL DEFAULT (datetime('now')),
  event TEXT NOT NULL,
  sub TEXT,
  actor TEXT,
  key_ref TEXT,
  reason TEXT,
  path TEXT
);
CREATE INDEX attest_events_at ON attest_events (at);
