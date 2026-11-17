-- jWallet Lite initial schema.
-- Money is stored as INTEGER paise (₹1 = 100 paise); never floats.
-- Timestamps are ISO-8601 UTC strings (Date#toISOString), which sort correctly as text.

CREATE TABLE users (
  id                  TEXT PRIMARY KEY,               -- internal UUIDv7
  public_id           TEXT NOT NULL UNIQUE,           -- e.g. USR10001
  name                TEXT NOT NULL,
  email               TEXT NOT NULL UNIQUE,           -- stored lowercase
  password_hash       TEXT NOT NULL,                  -- argon2id
  status              TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'LOCKED', 'FROZEN')),
  failed_login_count  INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
  login_locked_until  TEXT,
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);

CREATE TABLE wallets (
  id             TEXT PRIMARY KEY,
  public_id      TEXT NOT NULL UNIQUE,                -- e.g. WALLET10001
  user_id        TEXT NOT NULL UNIQUE REFERENCES users (id),
  currency       TEXT NOT NULL DEFAULT 'INR',
  balance_paise  INTEGER NOT NULL CHECK (balance_paise >= 0),
  account_last4  TEXT NOT NULL CHECK (length(account_last4) = 4),
  status         TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'FROZEN')),
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);

CREATE TABLE transactions (
  id                          TEXT PRIMARY KEY,
  reference                   TEXT NOT NULL UNIQUE,   -- public TXN reference
  wallet_id                   TEXT NOT NULL REFERENCES wallets (id),
  user_id                     TEXT NOT NULL REFERENCES users (id),
  type                        TEXT NOT NULL CHECK (type IN ('CREDIT', 'DEBIT')),
  amount_paise                INTEGER NOT NULL CHECK (amount_paise > 0),
  currency                    TEXT NOT NULL DEFAULT 'INR',
  counterparty_name           TEXT NOT NULL,
  counterparty_mobile_enc     TEXT,                   -- AES-256-GCM encrypted
  counterparty_mobile_masked  TEXT,
  remarks                     TEXT,
  status                      TEXT NOT NULL CHECK (status IN ('SUCCESS', 'FAILED', 'PENDING')),
  balance_after_paise         INTEGER,
  approval_method             TEXT CHECK (approval_method IN ('BIOMETRIC', 'PIN')),
  idempotency_key             TEXT,
  created_at                  TEXT NOT NULL
);
CREATE INDEX idx_transactions_user_created ON transactions (user_id, created_at DESC);
CREATE INDEX idx_transactions_user_type ON transactions (user_id, type);

CREATE TABLE transaction_pins (
  user_id       TEXT PRIMARY KEY REFERENCES users (id),
  pin_hash      TEXT NOT NULL,                        -- argon2id
  failed_count  INTEGER NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
  locked_until  TEXT,
  set_at        TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE TABLE devices (
  id                     TEXT PRIMARY KEY,
  user_id                TEXT NOT NULL REFERENCES users (id),
  device_id              TEXT NOT NULL,               -- client-generated UUID
  device_public_key      TEXT,                        -- base64 DER SPKI, P-256 (non-biometric key)
  biometric_public_key   TEXT,                        -- base64 DER SPKI, P-256 (biometric-bound key)
  biometric_enrolled_at  TEXT,
  created_at             TEXT NOT NULL,
  last_seen_at           TEXT NOT NULL,
  revoked_at             TEXT,
  UNIQUE (user_id, device_id)
);

CREATE TABLE sessions (
  id                  TEXT PRIMARY KEY,               -- `sid` claim in the access token
  user_id             TEXT NOT NULL REFERENCES users (id),
  device_id           TEXT,                           -- client device UUID, if supplied
  refresh_token_hash  TEXT NOT NULL UNIQUE,           -- SHA-256 of the refresh token
  family_id           TEXT NOT NULL,                  -- rotation family (reuse detection)
  password_auth_at    TEXT NOT NULL,                  -- last password login (fresh-auth checks)
  expires_at          TEXT NOT NULL,
  revoked_at          TEXT,
  revoke_reason       TEXT,
  ip                  TEXT,
  user_agent          TEXT,
  created_at          TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions (user_id);

CREATE TABLE transfer_challenges (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users (id),
  session_id    TEXT NOT NULL REFERENCES sessions (id),
  nonce         TEXT NOT NULL,
  payload_hash  TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  used_at       TEXT,
  created_at    TEXT NOT NULL
);

CREATE TABLE idempotency_keys (
  user_id          TEXT NOT NULL REFERENCES users (id),
  key              TEXT NOT NULL,
  request_hash     TEXT NOT NULL,
  response_status  INTEGER NOT NULL,
  response_body    TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  PRIMARY KEY (user_id, key)
);

CREATE TABLE request_nonces (
  nonce       TEXT PRIMARY KEY,
  expires_at  TEXT NOT NULL
);

CREATE TABLE audit_log (
  id          TEXT PRIMARY KEY,
  user_id     TEXT,
  action      TEXT NOT NULL,
  ip          TEXT,
  device_id   TEXT,
  request_id  TEXT,
  metadata    TEXT,                                   -- JSON; never contains secrets
  created_at  TEXT NOT NULL
);
CREATE INDEX idx_audit_user_created ON audit_log (user_id, created_at);
