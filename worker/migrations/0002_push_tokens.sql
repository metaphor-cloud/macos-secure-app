-- One APNs device token per enrolled device, keyed on its App Attest key so a
-- device holds at most one token and revoking the key removes it. sub and
-- email are the person the key belongs to. token is unique: a token that
-- moves to a new key on the same Mac leaves the old row behind.
-- apns_environment is the APNs host the token works on: development builds
-- get sandbox tokens.
CREATE TABLE push_tokens (
  key_id TEXT PRIMARY KEY REFERENCES app_keys(key_id),
  token TEXT NOT NULL UNIQUE,
  sub TEXT NOT NULL,
  email TEXT NOT NULL,
  apns_environment TEXT NOT NULL CHECK (apns_environment IN ('production', 'development')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX push_tokens_sub ON push_tokens (sub);
